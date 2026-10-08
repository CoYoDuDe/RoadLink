"""Outbound-only rules inserted BELOW immutable isolation and DNS protections.

Callers must insert these after their broad outbound allowance and before all
protected destination/DNS rules using -I FORWARD 1. Rules never affect INPUT,
OUTPUT, reverse direction, NAT, policy routing or IPv6. Existing runtime guards
must journal the entire config before applying it and own exact cleanup.
"""
import ipaddress
import re
from firewall_config import validate


def rules(policy, subnet, uplink, tag):
    policy = validate(policy)
    network = ipaddress.IPv4Network(subnet, strict=True)
    if (network.prefixlen != 24 or not any(network.subnet_of(ipaddress.IPv4Network(n))
            for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
            or not isinstance(uplink, str) or not re.fullmatch('[A-Za-z0-9_.:-]{1,15}', uplink)
            or uplink == 'lo' or uplink.startswith('ap')
            or tag not in ('roadlink-ap-route-owned', 'roadlink-direct-owned')):
        raise ValueError('Invalid guarded firewall scope')
    # Validate ALL enabled clients before yielding any mutation command.
    for item in policy['rules']:
        if item['enabled'] and item['source']:
            source = ipaddress.IPv4Address(item['source'])
            if source not in network or source in (network.network_address, network[1], network.broadcast_address):
                raise ValueError('Firewall client is outside the current vehicle network')
    outgoing = ['-i', 'aproadlink', '-s', str(network), '-o', uplink]
    marker = ['-m', 'comment', '--comment', tag]
    if policy['default'] == 'block':
        yield ('filter', 'FORWARD', outgoing + marker + ['-j', 'DROP'])
    # Reverse insertion preserves the GUI list's first matching rule.
    for item in reversed(policy['rules']):
        if not item['enabled']:
            continue
        args = ['-i', 'aproadlink', '-s', item['source'] or str(network), '-o', uplink]
        if item['destination']:
            args += ['-d', item['destination']]
        if item['protocol'] != 'any':
            args += ['-p', item['protocol']]
        if item['port']:
            args += ['--dport', str(item['port'])]
        yield ('filter', 'FORWARD', args + marker + ['-j', 'ACCEPT' if item['action'] == 'allow' else 'DROP'])
