"""Plans for the isolated WLAN uplink: only marked WireGuard crosses the host.

These builders do not mutate networking. The WAN ownership controller must
install drops before raising interfaces, journal all mutations, and remove
the link before removing rules. Native host routes and DNS stay untouched.
"""
import ipaddress

HOST = 'rlwanhost'
PEER = 'rlwanpeer'
RADIO = 'disabledrlwan'
MARK = '0x524c'
TAG = 'roadlink-wan-bridge-owned'


def bootstrap_rules():
    """No host bridge: only DHCP and two certificate-validated HTTPS services."""
    from enrollment import ADDRESS
    tag = ['-m', 'comment', '--comment', TAG]
    for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
        yield ('filter', chain, tag + ['-j', 'DROP'])
    for chain in ('INPUT', 'OUTPUT'):
        yield ('filter', chain, ['-i' if chain == 'INPUT' else '-o', 'lo'] + tag + ['-j', 'ACCEPT'])
    yield ('filter', 'OUTPUT', ['-o', RADIO, '-p', 'udp', '--sport', '68', '--dport', '67'] + tag + ['-j', 'ACCEPT'])
    yield ('filter', 'INPUT', ['-i', RADIO, '-p', 'udp', '--sport', '67', '--dport', '68'] + tag + ['-j', 'ACCEPT'])
    for address in (ADDRESS, '1.1.1.1'):
        yield ('filter', 'OUTPUT', ['-o', RADIO, '-d', address, '-p', 'tcp', '--dport', '443'] + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'INPUT', ['-i', RADIO, '-s', address, '-p', 'tcp', '--sport', '443',
               '-m', 'conntrack', '--ctstate', 'ESTABLISHED'] + tag + ['-j', 'ACCEPT'])


def plan(endpoint, port, subnet='172.27.250.0/30'):
    endpoint = ipaddress.IPv4Address(endpoint)
    network = ipaddress.IPv4Network(subnet)
    private = any(network.subnet_of(ipaddress.IPv4Network(block))
                  for block in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if (not endpoint.is_global or type(port) is not int or not 1 <= port <= 65535
            or network.prefixlen != 30 or not private):
        raise ValueError('Public VPN endpoint and private /30 required')
    return {'endpoint': str(endpoint), 'port': str(port), 'subnet': str(network),
            'host': str(network.network_address + 1),
            'peer': str(network.network_address + 2)}


def rules(config, scope):
    """Yield insertion order for iptables -I CHAIN 1 (last rule wins priority).

    IPv6 rules are separate and never have allowances. Interface names are
    fixed; source/destination validation is mandatory before use.
    """
    config = plan(config['endpoint'], int(config['port']), config['subnet'])
    tag = ['-m', 'comment', '--comment', TAG]
    endpoint, port = config['endpoint'], config['port']
    established = ['-m', 'conntrack', '--ctstate', 'ESTABLISHED']
    if scope == 'host':
        for chain, direction in (('INPUT', '-i'), ('OUTPUT', '-o'),
                                 ('FORWARD', '-i'), ('FORWARD', '-o')):
            yield ('filter', chain, [direction, HOST] + tag + ['-j', 'DROP'])
        yield ('filter', 'OUTPUT', ['-o', HOST, '-s', config['host'], '-d', endpoint,
               '-p', 'udp', '--dport', port, '-m', 'mark', '--mark', MARK + '/0xffffffff']
               + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'INPUT', ['-i', HOST, '-d', config['host'], '-s', endpoint,
               '-p', 'udp', '--sport', port] + established + tag + ['-j', 'ACCEPT'])
    elif scope == 'wan':
        # This namespace is exclusively owned; drop all unsolicited input,
        # local output and forwarding, including traffic using other devices.
        for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
            yield ('filter', chain, tag + ['-j', 'DROP'])
        for chain in ('INPUT', 'OUTPUT'):
            yield ('filter', chain, ['-i' if chain == 'INPUT' else '-o', 'lo'] + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'OUTPUT', ['-o', RADIO, '-p', 'udp', '--sport', '68', '--dport', '67']
               + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'INPUT', ['-i', RADIO, '-p', 'udp', '--sport', '67', '--dport', '68']
               + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'OUTPUT', ['-o', RADIO, '-d', '1.1.1.1', '-p', 'tcp', '--dport', '443']
               + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'INPUT', ['-i', RADIO, '-s', '1.1.1.1', '-p', 'tcp', '--sport', '443']
               + established + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'FORWARD', ['-i', PEER, '-o', RADIO, '-s', config['host'],
               '-d', endpoint, '-p', 'udp', '--dport', port] + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'FORWARD', ['-i', RADIO, '-o', PEER, '-d', config['host'],
               '-s', endpoint, '-p', 'udp', '--sport', port] + established + tag + ['-j', 'ACCEPT'])
        yield ('nat', 'POSTROUTING', ['-o', RADIO, '-s', config['host'], '-d', endpoint,
               '-p', 'udp', '--dport', port] + tag + ['-j', 'MASQUERADE'])
    else:
        raise ValueError('Unknown firewall scope')


def ipv6_rules(scope):
    tag = ['-m', 'comment', '--comment', TAG]
    if scope == 'host':
        for chain, direction in (('INPUT', '-i'), ('OUTPUT', '-o'),
                                 ('FORWARD', '-i'), ('FORWARD', '-o')):
            yield ('filter', chain, [direction, HOST] + tag + ['-j', 'DROP'])
    elif scope == 'wan':
        for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
            yield ('filter', chain, tag + ['-j', 'DROP'])
    else:
        raise ValueError('Unknown firewall scope')
