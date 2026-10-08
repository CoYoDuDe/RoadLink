"""Source-scoped AP routing; a missing WireGuard link never selects main."""
import ipaddress
import json
from pathlib import Path
from storage import load_json, write_json

TABLE = '51900'
PRIORITY = '21900'
TAG = 'roadlink-ap-route-owned'
AP = 'aproadlink'
VPN = 'wgroadlink'
PRIVATE = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
           '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
           '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
           '224.0.0.0/4', '240.0.0.0/4')


def plan(subnet, vpn, firewall=None):
    network = ipaddress.ip_network(subnet)
    address = ipaddress.ip_interface(vpn['address'])
    dns = ipaddress.ip_address(vpn['dns'])
    if (network.version != 4 or network.prefixlen != 24 or not network.is_private
            or address.version != 4 or address.network.prefixlen != 32
            or not address.ip.is_private or dns.version != 4
            or not (dns.is_global or any(dns in ipaddress.ip_network(net)
                    for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')))
            or dns.is_multicast or dns.is_reserved
            or network.overlaps(address.network) or dns in network):
        raise ValueError('Invalid or overlapping AP/VPN addressing')
    result = {'subnet': str(network), 'address': str(address.ip), 'dns': str(dns)}
    if firewall is not None:
        from firewall_config import validate
        result['firewall'] = validate(firewall)
    # Android strict Private DNS keeps the public hostname for TLS verification.
    # Only DNSmith's own public endpoint maps to its isolated in-tunnel resolver.
    from dns_config import PUBLIC_DNSMITH
    if (str(dns) == '10.8.0.1' and vpn.get('endpoint') == PUBLIC_DNSMITH
            and vpn.get('port', 51820) == 51820):
        result['dnsmith_dot_alias'] = PUBLIC_DNSMITH
    return result


def rules(config):
    from firewall_rules import rules as custom_rules
    custom = list(custom_rules(config['firewall'], config['subnet'], VPN, TAG)) if 'firewall' in config else []
    tag = ['-m', 'comment', '--comment', TAG]
    # Rules are inserted at position 1 in this order, so terminal allowances
    # remain below private-destination and DNS restrictions.
    yield ('filter', 'FORWARD', ['-i', AP, '-s', config['subnet'], '-o', VPN] + tag + ['-j', 'ACCEPT'])
    yield ('filter', 'FORWARD', ['-i', VPN, '-o', AP, '-d', config['subnet'],
           '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED'] + tag + ['-j', 'ACCEPT'])
    yield from custom
    for destination in PRIVATE:
        yield ('filter', 'FORWARD', ['-i', AP, '-d', destination] + tag + ['-j', 'DROP'])
    for protocol in ('tcp', 'udp'):
        yield ('filter', 'FORWARD', ['-i', AP, '-p', protocol, '--dport', '853'] + tag + ['-j', 'DROP'])
        yield ('filter', 'FORWARD', ['-i', AP, '-s', config['subnet'], '-o', VPN,
               '-d', config['dns'], '-p', protocol, '--dport', '53'] + tag + ['-j', 'ACCEPT'])
        yield ('nat', 'PREROUTING', ['-i', AP, '-s', config['subnet'], '-p', protocol,
               '--dport', '53'] + tag + ['-j', 'DNAT', '--to-destination', config['dns']])
    if 'dnsmith_dot_alias' in config:
        from dns_config import PUBLIC_DNSMITH
        if config['dnsmith_dot_alias'] != PUBLIC_DNSMITH or config['dns'] != '10.8.0.1':
            raise ValueError('Invalid DNSmith encrypted DNS alias')
        yield ('filter', 'FORWARD', ['-i', AP, '-s', config['subnet'], '-o', VPN,
               '-d', config['dns'], '-p', 'tcp', '--dport', '853'] + tag + ['-j', 'ACCEPT'])
        yield ('nat', 'PREROUTING', ['-i', AP, '-s', config['subnet'],
               '-d', config['dnsmith_dot_alias'], '-p', 'tcp', '--dport', '853'] +
               tag + ['-j', 'DNAT', '--to-destination', config['dns'] + ':853'])
    yield ('nat', 'POSTROUTING', ['-s', config['subnet'], '-o', VPN] + tag +
           ['-j', 'SNAT', '--to-source', config['address']])
    yield ('mangle', 'FORWARD', ['-i', AP, '-o', VPN, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN'] +
           tag + ['-j', 'TCPMSS', '--clamp-mss-to-pmtu'])


def rule_command(action, rule):
    table, chain, args = rule
    return ['iptables', '-w', '3', '-t', table, action, chain] + (['1'] if action == '-I' else []) + args


def start(root, config, command):
    # Validate the complete ruleset before creating any routing journal.
    # An invalid client after a subnet change must leave no uncleanable entry.
    planned_rules = list(rules(config))
    if (PRIORITY + ':' in command(['ip', 'rule', 'show']).stdout
            or command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout.strip()):
        raise RuntimeError('AP routing priority/table already occupied')
    before = Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
    write_json(root / 'routing.json', {'config': config, 'forward_before': before})
    # The journal precedes all mutations. Independent AP cleanup owns them.
    command(['ip', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', TABLE])
    command(['ip', 'rule', 'add', 'priority', PRIORITY, 'iif', AP, 'lookup', TABLE])
    for rule in planned_rules:
        command(rule_command('-I', rule))
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
    reconcile(command)


def vpn_interface_ready():
    device = Path('/sys/class/net/' + VPN)
    try:
        alias = (device / 'ifalias').read_text().strip()
        if alias != 'roadlink-vpn-owned':
            raise RuntimeError('Foreign VPN interface; AP remains blocked')
        return bool(int((device / 'flags').read_text().strip(), 16) & 1)
    except FileNotFoundError:
        return False


def route_entries(command):
    result = command(['ip', '-j', '-4', 'route', 'show', 'table', TABLE], check=False)
    if result.returncode and 'FIB table does not exist' not in (result.stderr or ''):
        raise RuntimeError('Cannot inspect AP route ownership')
    entries = json.loads(result.stdout or '[]')
    if not isinstance(entries, list): raise RuntimeError('Invalid AP route inventory')
    for entry in entries:
        if not isinstance(entry, dict): raise RuntimeError('Invalid AP route entry')
        if set(entry) - {'dst', 'dev', 'scope', 'metric', 'flags', 'type', 'protocol'}:
            raise RuntimeError('Foreign AP route retained')
        common = (entry.get('dst') == 'default' and entry.get('protocol', 'boot') == 'boot'
                  and entry.get('flags', []) in ([], ['linkdown']))
        fallback = (common and entry.get('type') == 'unreachable' and entry.get('metric') == 32767
                    and 'dev' not in entry and 'scope' not in entry)
        active = (common and entry.get('type', 'unicast') == 'unicast' and entry.get('metric') == 10
                  and entry.get('dev') == VPN and entry.get('scope', 'link') == 'link')
        if not (fallback or active): raise RuntimeError('Foreign AP route retained')
    if len(entries) != len({entry.get('metric') for entry in entries}):
        raise RuntimeError('Ambiguous AP route ownership')
    return entries


def policy_entries(command, allow_detached=False):
    result = command(['ip', '-j', '-4', 'rule', 'show'])
    rows = json.loads(result.stdout)
    if not isinstance(rows, list): raise RuntimeError('Invalid AP policy inventory')
    selected = [row for row in rows if row.get('priority') == int(PRIORITY)]
    keys = {'priority', 'src', 'table', 'iif'}
    def expected_keys(row):
        # Kernel marks an exact iif rule detached after AP teardown.
        return (set(row) == keys or allow_detached and set(row) == keys | {'iif_detached'}
                and row['iif_detached'] is None)
    if len(selected) > 1 or any(not expected_keys(row)
            or row.get('src') != 'all' or str(row.get('table')) != TABLE or row.get('iif') != AP
            for row in selected):
        raise RuntimeError('Foreign AP policy retained')
    return selected


def reconcile(command):
    entries = route_entries(command)
    if sum(entry.get('type') == 'unreachable' for entry in entries) != 1:
        raise RuntimeError('AP unreachable fallback changed externally')
    if not policy_entries(command):
        raise RuntimeError('AP policy changed externally')
    # Add never replaces another default. Missing WireGuard retains unreachable.
    if vpn_interface_ready() and not any(entry.get('metric') == 10 for entry in entries):
        result = command(['ip', '-4', 'route', 'add', 'default', 'dev', VPN,
                          'metric', '10', 'table', TABLE], check=False)
        if result.returncode and vpn_interface_ready():
            raise RuntimeError('AP VPN route installation failed')
        if not result.returncode:
            route_entries(command)


def cleanup(root, command):
    state = load_json(root / 'routing.json', {})
    if not state:
        return []
    errors = []
    # Caller has already removed the AP interface. Remove allowances before
    # policy/NAT, while the base AP drops are still installed.
    for rule in reversed(list(rules(state['config']))):
        command(rule_command('-D', rule), check=False)
        if command(rule_command('-C', rule), check=False).returncode == 0:
            errors.append('AP routed firewall cleanup incomplete')
    # Revoke permissions even if a foreign route/rule blocks ownership checks.
    try:
        policies = policy_entries(command, allow_detached=True)
        if policies:
            command(['ip', '-4', 'rule', 'del', 'priority', PRIORITY, 'from', 'all',
                     'iif', AP, 'lookup', TABLE], check=False)
        if policy_entries(command, allow_detached=True): raise RuntimeError('AP policy cleanup incomplete')
    except Exception as exc:
        errors.append(str(exc))
    try:
        entries = route_entries(command)
        # Keep the unreachable fallback while an ambiguous selector remains.
        if not errors:
            for entry in entries:
                args = ['ip', '-4', 'route', 'del']
                if entry.get('type') == 'unreachable': args += ['unreachable']
                args += ['default', 'metric', str(entry['metric']), 'table', TABLE]
                if entry.get('dev'): args += ['dev', entry['dev']]
                command(args, check=False)
            if route_entries(command): raise RuntimeError('AP route cleanup incomplete')
    except Exception as exc:
        errors.append(str(exc))
    if not errors and state['forward_before'] == '0':
        if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1':
            Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    return errors
