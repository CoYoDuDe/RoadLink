"""Plans for one selected portal client across a dedicated, guarded transit link.

This module never mutates networking. The session controller must own both
namespaces/interfaces, install drops before allowances, journal changes, provide
portal-only DNS filtering, and remove the session on lease/association changes.
"""
import ipaddress
from capport import allowed_address
from portal_clients import mac

AP = 'aproadlink'
HOST = 'rlportalhost'
PEER = 'rlportalpeer'
RADIO = 'disabledrlwan'
TAG = 'roadlink-portal-client-owned'
TABLE = '51930'
PRIORITY = '21760'
MARK = '0x524f/0xffffffff'
DNS_PORT = '5354'


def plan(subnet, client, lease, endpoints, resolver, transit='172.27.249.0/30'):
    vehicle, bridge = ipaddress.IPv4Network(subnet), ipaddress.IPv4Network(transit)
    private = tuple(map(ipaddress.IPv4Network, ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')))
    address, external = ipaddress.IPv4Address(client['ip']), ipaddress.IPv4Interface(lease['address'])
    if (vehicle.prefixlen != 24 or not any(vehicle.subnet_of(block) for block in private)
            or bridge.prefixlen != 30 or not any(bridge.subnet_of(block) for block in private)
            or bridge.overlaps(vehicle) or bridge.overlaps(external.network) or vehicle.overlaps(external.network)
            or address not in vehicle or address in (vehicle.network_address, vehicle.broadcast_address, vehicle[1])):
        raise ValueError('Portal client and transit addressing must be separate')
    client_mac = mac(client['mac'])
    resolver = str(ipaddress.IPv4Address(resolver))
    dns = ipaddress.IPv4Address(resolver)
    if (dns == external.ip or dns.is_unspecified or dns.is_multicast or dns.is_loopback or dns.is_link_local
            or dns.is_reserved or dns in bridge or dns in vehicle
            or not (dns.is_global or dns in external.network)):
        raise ValueError('Invalid external portal DNS')
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 32: raise ValueError('Bounded portal targets required')
    targets = set()
    for item in endpoints:
        target = str(ipaddress.IPv4Address(item['address']))
        port = item['port']
        if type(port) is not int or not 1 <= port <= 65535 or port in (22, 53, 853):
            raise ValueError('Portal target must be an approved web port')
        if not allowed_address(target, lease, str(vehicle), str(bridge)):
            raise ValueError('Protected portal target')
        targets.add((target, port))
    return {'subnet': str(vehicle), 'client': str(address), 'mac': client_mac, 'lease': dict(lease),
            'resolver': resolver, 'transit': str(bridge), 'host': str(bridge[1]), 'peer': str(bridge[2]),
            'endpoints': [{'address': value, 'port': port} for value, port in sorted(targets)]}


def canonical(config):
    return plan(config['subnet'], {'ip': config['client'], 'mac': config['mac']}, config['lease'],
                config['endpoints'], config['resolver'], config['transit'])


def targets(config):
    # Client DNS never crosses this transit link. The selected client uses a
    # local, allowlisted DNS broker; WAN-side resolution uses portal_access.
    for item in config['endpoints']: yield item['address'], item['port'], 'tcp'


def routes(config):
    config = canonical(config)
    yield ['ip', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', TABLE]
    for destination in sorted({value for value, _, _ in targets(config)}):
        yield ['ip', 'route', 'add', destination+'/32', 'via', config['peer'], 'dev', HOST, 'onlink', 'table', TABLE]
    yield ['ip', 'rule', 'add', 'priority', PRIORITY, 'iif', AP, 'from', config['client']+'/32',
           'fwmark', MARK, 'lookup', TABLE]


def rules(config, scope):
    """Insertion order for iptables -I CHAIN 1. IPv6 has no allowance."""
    config = canonical(config)
    tag = ['-m', 'comment', '--comment', TAG]
    if scope == 'host':
        for chain, direction in (('INPUT', '-i'), ('OUTPUT', '-o'), ('FORWARD', '-i'), ('FORWARD', '-o')):
            yield ('filter', chain, [direction, HOST]+tag+['-j', 'DROP'])
        # The selected client's other routed traffic is quarantined; AP-local
        # console traffic uses INPUT and retains the existing management rules.
        yield ('filter', 'FORWARD', ['-i', AP, '-s', config['client']]+tag+['-j', 'DROP'])
        selected = ['-i', AP, '-s', config['client'], '-m', 'mac', '--mac-source', config['mac']]
        gateway = str(ipaddress.IPv4Network(config['subnet'])[1])
        for protocol in ('udp', 'tcp'):
            yield ('nat', 'PREROUTING', selected+['-p', protocol, '--dport', '53']+tag+
                   ['-j', 'DNAT', '--to-destination', gateway+':'+DNS_PORT])
            yield ('filter', 'INPUT', selected+['-d', gateway, '-p', protocol, '--dport', DNS_PORT]+tag+['-j', 'ACCEPT'])
            yield ('filter', 'OUTPUT', ['-o', AP, '-s', gateway, '-d', config['client'],
                   '-p', protocol, '--sport', DNS_PORT, '-m', 'conntrack', '--ctstate', 'ESTABLISHED']+tag+['-j', 'ACCEPT'])
        for destination, port, protocol in targets(config):
            traffic = ['-d', destination, '-p', protocol, '--dport', str(port)]
            yield ('mangle', 'PREROUTING', selected+traffic+tag+['-j', 'MARK', '--set-xmark', MARK])
            yield ('filter', 'FORWARD', selected+['-o', HOST]+traffic+
                   ['-m', 'mark', '--mark', MARK]+tag+['-j', 'ACCEPT'])
            yield ('filter', 'FORWARD', ['-i', HOST, '-o', AP, '-d', config['client'], '-s', destination,
                   '-p', protocol, '--sport', str(port), '-m', 'conntrack', '--ctstate', 'ESTABLISHED']+tag+['-j', 'ACCEPT'])
            yield ('nat', 'POSTROUTING', ['-o', HOST, '-s', config['client']]+traffic+tag+
                   ['-j', 'SNAT', '--to-source', config['host']])
    elif scope == 'wan':
        for chain, direction in (('INPUT', '-i'), ('OUTPUT', '-o'), ('FORWARD', '-i'), ('FORWARD', '-o')):
            yield ('filter', chain, [direction, PEER]+tag+['-j', 'DROP'])
        for destination, port, protocol in targets(config):
            traffic = ['-d', destination, '-p', protocol, '--dport', str(port)]
            yield ('filter', 'FORWARD', ['-i', PEER, '-o', RADIO, '-s', config['host']]+traffic+tag+['-j', 'ACCEPT'])
            yield ('filter', 'FORWARD', ['-i', RADIO, '-o', PEER, '-d', config['host'], '-s', destination,
                   '-p', protocol, '--sport', str(port), '-m', 'conntrack', '--ctstate', 'ESTABLISHED']+tag+['-j', 'ACCEPT'])
            yield ('nat', 'POSTROUTING', ['-o', RADIO, '-s', config['host']]+traffic+tag+['-j', 'MASQUERADE'])
    else: raise ValueError('Unknown portal routing scope')


def ipv6_rules(scope):
    device = HOST if scope == 'host' else PEER if scope == 'wan' else None
    if device is None: raise ValueError('Unknown portal routing scope')
    for chain, direction in (('INPUT', '-i'), ('OUTPUT', '-o'), ('FORWARD', '-i'), ('FORWARD', '-o')):
        yield ('filter', chain, [direction, device, '-m', 'comment', '--comment', TAG, '-j', 'DROP'])
