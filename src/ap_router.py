"""Source-scoped AP routing; a missing WireGuard link never selects main."""
import ipaddress
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


def plan(subnet, vpn):
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
    return {'subnet': str(network), 'address': str(address.ip), 'dns': str(dns)}


def rules(config):
    tag = ['-m', 'comment', '--comment', TAG]
    # Rules are inserted at position 1 in this order, so terminal allowances
    # remain below private-destination and DNS restrictions.
    yield ('filter', 'FORWARD', ['-i', AP, '-s', config['subnet'], '-o', VPN] + tag + ['-j', 'ACCEPT'])
    yield ('filter', 'FORWARD', ['-i', VPN, '-o', AP, '-d', config['subnet'],
           '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED'] + tag + ['-j', 'ACCEPT'])
    for destination in PRIVATE:
        yield ('filter', 'FORWARD', ['-i', AP, '-d', destination] + tag + ['-j', 'DROP'])
    for protocol in ('tcp', 'udp'):
        yield ('filter', 'FORWARD', ['-i', AP, '-p', protocol, '--dport', '853'] + tag + ['-j', 'DROP'])
        yield ('filter', 'FORWARD', ['-i', AP, '-s', config['subnet'], '-o', VPN,
               '-d', config['dns'], '-p', protocol, '--dport', '53'] + tag + ['-j', 'ACCEPT'])
        yield ('nat', 'PREROUTING', ['-i', AP, '-s', config['subnet'], '-p', protocol,
               '--dport', '53'] + tag + ['-j', 'DNAT', '--to-destination', config['dns']])
    yield ('nat', 'POSTROUTING', ['-s', config['subnet'], '-o', VPN] + tag +
           ['-j', 'SNAT', '--to-source', config['address']])
    yield ('mangle', 'FORWARD', ['-i', AP, '-o', VPN, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN'] +
           tag + ['-j', 'TCPMSS', '--clamp-mss-to-pmtu'])


def rule_command(action, rule):
    table, chain, args = rule
    return ['iptables', '-w', '3', '-t', table, action, chain] + (['1'] if action == '-I' else []) + args


def start(root, config, command):
    if (PRIORITY + ':' in command(['ip', 'rule', 'show']).stdout
            or command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout.strip()):
        raise RuntimeError('AP routing priority/table already occupied')
    before = Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
    write_json(root / 'routing.json', {'config': config, 'forward_before': before})
    # The journal precedes all mutations. Independent AP cleanup owns them.
    command(['ip', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', TABLE])
    command(['ip', 'rule', 'add', 'priority', PRIORITY, 'iif', AP, 'lookup', TABLE])
    for rule in rules(config):
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


def reconcile(command):
    # Kernel removal of WireGuard also removes this route; unreachable remains.
    if vpn_interface_ready():
        current = command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout
        if 'default dev ' + VPN + ' ' not in current:
            result = command(['ip', 'route', 'replace', 'default', 'dev', VPN,
                              'metric', '10', 'table', TABLE], check=False)
            if result.returncode and vpn_interface_ready():
                raise RuntimeError('AP VPN route installation failed')
            # If the VPN disappeared or went down meanwhile, retain the
            # unreachable route and retry next tick without restarting AP.


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
    command(['ip', 'rule', 'del', 'priority', PRIORITY, 'iif', AP, 'lookup', TABLE], check=False)
    command(['ip', 'route', 'del', 'default', 'metric', '10', 'table', TABLE], check=False)
    command(['ip', 'route', 'del', 'unreachable', 'default', 'metric', '32767', 'table', TABLE], check=False)
    if PRIORITY + ':' in command(['ip', 'rule', 'show']).stdout:
        errors.append('AP policy cleanup incomplete')
    if command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout.strip():
        errors.append('AP route cleanup incomplete')
    if not errors and state['forward_before'] == '0':
        if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1':
            Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    return errors
