"""Plans for explicit direct Internet. No mutations or implicit VPN fallback.

A guarded controller must own these rules and the dedicated unreachable route,
check hardware/bridge ownership, and publish a matching health generation.
The daemon launches this controller only after explicit transport selection.
"""
import hashlib
import ipaddress
import json
import re
from ap_router import PRIVATE, rule_command
from dns_config import public_address
from wan_bridge import HOST

AP = 'aproadlink'
TAG = 'roadlink-direct-owned'
TABLE = '51920'
AP_TABLE = '51921'
MARK = '0x524d'
PROBE_PRIORITY = '21810'
AP_PRIORITY = '21820'


def usable_address(value):
    if not isinstance(value, str):
        raise ValueError('Uplink address must be an IPv4 string')
    address = ipaddress.IPv4Address(value)
    private = any(address in ipaddress.IPv4Network(block)
                  for block in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'))
    if ((not private and not address.is_global) or address.is_multicast
            or address.is_reserved):
        raise ValueError('Invalid direct uplink address')
    return str(address)


def plan(subnet, route, dns):
    network = ipaddress.IPv4Network(subnet)
    private = any(network.subnet_of(ipaddress.IPv4Network(block))
                  for block in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if network.prefixlen != 24 or not private:
        raise ValueError('A private vehicle /24 is required')
    if (not isinstance(route, dict) or route.get('kind') not in ('ethernet', 'wifi')
            or not isinstance(route.get('dev'), str)
            or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', route['dev'])
            or route['dev'] == 'lo' or route['dev'].startswith(('ap', 'wg'))
            or (route['kind'] == 'wifi') != (route['dev'] == HOST)):
        raise ValueError('Invalid direct uplink interface')
    source = usable_address(route['source'])
    gateway = usable_address(route['gateway']) if route.get('gateway') else ''
    if (ipaddress.IPv4Address(source) in network
            or gateway and (ipaddress.IPv4Address(gateway) in network or gateway == source)):
        raise ValueError('Direct uplink overlaps the vehicle network')
    return {'subnet': str(network), 'dev': route['dev'], 'source': source,
            'gateway': gateway, 'kind': route['kind'], 'dns': public_address(dns)}


def generation(config):
    """Full route and resolver identity; status from a previous path is stale."""
    config = plan(config['subnet'], config, config['dns'])
    encoded = json.dumps(config, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def ready(config, status):
    return bool(config and status.get('state') == 'READY'
                and status.get('internet') is True and status.get('dns_ready') is True
                and status.get('generation') == generation(config))


def routes(config):
    """Install policy before permissions; keep unreachable throughout changes."""
    config = plan(config['subnet'], config, config['dns'])
    yield ['ip', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', TABLE]
    yield ['ip', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', AP_TABLE]
    yield ['ip', 'rule', 'add', 'priority', PROBE_PRIORITY, 'fwmark', MARK + '/0xffffffff', 'lookup', TABLE]
    yield ['ip', 'rule', 'add', 'priority', AP_PRIORITY, 'iif', AP, 'lookup', AP_TABLE]
    route = ['ip', 'route', 'replace', 'default', 'table', TABLE, 'metric', '10',
             'dev', config['dev'], 'src', config['source']]
    if config['gateway']:
        route += ['via', config['gateway'], 'onlink']
    yield route
    yield [AP_TABLE if value == TABLE else value for value in route]


def rules(config):
    """iptables -I CHAIN 1 insertion order. Existing AP local rules stay intact."""
    config = plan(config['subnet'], config, config['dns'])
    tag = ['-m', 'comment', '--comment', TAG]
    outgoing = ['-i', AP, '-s', config['subnet'], '-o', config['dev']]
    # The controller adds allowances only for a checked path. These explicit
    # terminal drops also protect devices with native FORWARD policy ACCEPT.
    yield ('filter', 'FORWARD', ['-i', AP] + tag + ['-j', 'DROP'])
    yield ('filter', 'FORWARD', ['-o', AP] + tag + ['-j', 'DROP'])
    yield ('filter', 'FORWARD', outgoing + tag + ['-j', 'ACCEPT'])
    yield ('filter', 'FORWARD', ['-i', config['dev'], '-o', AP, '-d', config['subnet'],
           '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED'] + tag + ['-j', 'ACCEPT'])
    for destination in PRIVATE:
        yield ('filter', 'FORWARD', ['-i', AP, '-d', destination] + tag + ['-j', 'DROP'])
    for protocol in ('udp', 'tcp'):
        yield ('filter', 'FORWARD', ['-i', AP, '-p', protocol, '--dport', '853'] + tag + ['-j', 'DROP'])
        yield ('nat', 'PREROUTING', ['-i', AP, '-s', config['subnet'], '-p', protocol,
               '--dport', '53'] + tag + ['-j', 'DNAT', '--to-destination', config['dns']])
    yield ('nat', 'POSTROUTING', ['-s', config['subnet'], '-o', config['dev']] + tag +
           ['-j', 'SNAT', '--to-source', config['source']])
    yield ('mangle', 'FORWARD', outgoing + ['-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN'] +
           tag + ['-j', 'TCPMSS', '--clamp-mss-to-pmtu'])


def ipv6_rules():
    tag = ['-m', 'comment', '--comment', TAG]
    for chain, direction in (('FORWARD', '-i'), ('FORWARD', '-o'), ('INPUT', '-i'), ('OUTPUT', '-o')):
        yield ('filter', chain, [direction, AP] + tag + ['-j', 'DROP'])
