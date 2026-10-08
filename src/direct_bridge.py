"""Isolated WiFi bridge plans for explicit direct mode.

The host bridge never permits forwarding itself. A separate checked-path
controller places scoped vehicle permits above its terminal drops. Removing
those permits therefore blocks the vehicle again even while WiFi stays up.
"""
import ipaddress
from ap_router import PRIVATE
from dns_config import public_address
from direct_router import MARK
from wan_bridge import HOST, PEER, RADIO, TAG, ipv6_rules


def plan(subnet, dns, secondary=''):
    network = ipaddress.IPv4Network(subnet)
    private = any(network.subnet_of(ipaddress.IPv4Network(block))
                  for block in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if network.prefixlen != 30 or not private:
        raise ValueError('A private WiFi transit /30 is required')
    dns = public_address(dns)
    secondary = public_address(secondary) if secondary else ''
    if secondary == dns:
        raise ValueError('Direct DNS addresses must differ')
    return {'transport': 'direct', 'subnet': str(network), 'host': str(network[1]),
            'peer': str(network[2]), 'dns': dns, 'dns_secondary': secondary}


def rules(config, scope):
    config = plan(config['subnet'], config['dns'], config.get('dns_secondary', ''))
    tag = ['-m', 'comment', '--comment', TAG]
    established = ['-m', 'conntrack', '--ctstate', 'ESTABLISHED']
    resolvers = [config['dns']] + ([config['dns_secondary']] if config['dns_secondary'] else [])
    if scope == 'host':
        for chain, direction in (('INPUT', '-i'), ('OUTPUT', '-o'),
                                 ('FORWARD', '-i'), ('FORWARD', '-o')):
            yield ('filter', chain, [direction, HOST] + tag + ['-j', 'DROP'])
        for destination in dict.fromkeys(resolvers + ['1.1.1.1']):
            ports = [('udp', '53'), ('tcp', '53')] if destination in resolvers else []
            if destination == '1.1.1.1':
                ports += [('tcp', '443')]
            for protocol, port in ports:
                yield ('filter', 'OUTPUT', ['-o', HOST, '-s', config['host'], '-d', destination,
                       '-p', protocol, '--dport', port, '-m', 'mark', '--mark', MARK + '/0xffffffff']
                       + tag + ['-j', 'ACCEPT'])
                yield ('filter', 'INPUT', ['-i', HOST, '-d', config['host'], '-s', destination,
                       '-p', protocol, '--sport', port] + established + tag + ['-j', 'ACCEPT'])
    elif scope == 'wan':
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
        outward = ['-i', PEER, '-o', RADIO, '-s', config['host']]
        yield ('filter', 'FORWARD', outward + tag + ['-j', 'ACCEPT'])
        yield ('filter', 'FORWARD', ['-i', RADIO, '-o', PEER, '-d', config['host']]
               + established + tag + ['-j', 'ACCEPT'])
        for destination in PRIVATE:
            yield ('filter', 'FORWARD', ['-i', PEER, '-d', destination] + tag + ['-j', 'DROP'])
        for protocol in ('udp', 'tcp'):
            for port in ('53', '853'):
                yield ('filter', 'FORWARD', ['-i', PEER, '-p', protocol, '--dport', port]
                       + tag + ['-j', 'DROP'])
            for destination in resolvers:
                yield ('filter', 'FORWARD', outward + ['-d', destination, '-p', protocol, '--dport', '53']
                       + tag + ['-j', 'ACCEPT'])
        yield ('nat', 'POSTROUTING', ['-o', RADIO, '-s', config['host']] + tag + ['-j', 'MASQUERADE'])
    else:
        raise ValueError('Unknown direct bridge scope')
