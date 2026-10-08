#!/usr/bin/env python3
"""DHCP event hook: only the owned network namespace, never host DNS/routes."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
from storage import write_json, load_json
import wan_lease

ROOT = Path('/run/roadlink-wan')
INTERFACE = 'disabledrlwan'
NS = 'roadlink-wan'


def lease(environ):
    address = ipaddress.IPv4Interface(environ['ip'] + '/' + environ['subnet'])
    if (address.ip.is_unspecified or address.ip.is_multicast or address.ip.is_loopback
            or address.network.prefixlen not in range(1, 31)
            or address.ip in (address.network.network_address, address.network.broadcast_address)):
        raise ValueError('Invalid DHCP lease')
    routers = environ.get('router', '').split()
    gateway = ipaddress.IPv4Address(routers[0]) if routers else None
    if gateway is not None and (gateway not in address.network or gateway == address.ip
            or gateway in (address.network.network_address, address.network.broadcast_address)):
        raise ValueError('DHCP gateway outside leased network')
    return {'address': str(address), 'gateway': str(gateway) if gateway else ''}


def main():
    from ap_runtime import alive, token
    # A netns handle and /proc/net/ns inode must identify the exact namespace.
    if (os.stat('/proc/self/ns/net').st_ino != os.stat('/run/netns/' + NS).st_ino
            or os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino
            or os.environ.get('interface') != INTERFACE):
        raise RuntimeError('Refusing DHCP changes outside the owned WAN namespace')
    def authorize():
        if (ROOT / 'stop').exists() or (ROOT / 'cleaning').exists():
            raise RuntimeError('DHCP owner is stopping')
        state = load_json(ROOT / 'state.json', {})
        connection = load_json(ROOT / 'connection.json', {})
        if not wan_lease.owned(connection, load_json(ROOT / 'dhcp.json', {}),
                load_json(ROOT / 'controller.json', {}), load_json(ROOT / 'guard.json', {}),
                state, alive, parent=os.getppid()):
            raise RuntimeError('DHCP connection ownership changed')
        ns = os.stat('/proc/self/ns/net')
        if (ns.st_ino, ns.st_dev) != (state.get('namespace_inode'), state.get('namespace_device')):
            raise RuntimeError('DHCP namespace identity changed')
        links = json.loads(subprocess.run(['ip', '-j', 'link', 'show', 'dev', INTERFACE],
            check=True, capture_output=True, timeout=5).stdout)
        if len(links) != 1 or links[0].get('ifindex') != state.get('ifindex'):
            raise RuntimeError('DHCP radio identity changed')
        return connection
    binding = authorize()
    write_json(ROOT / 'dhcp_hook.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    authorize()
    event = sys.argv[1]
    def command(args):
        if authorize() != binding: raise RuntimeError('DHCP binding changed')
        result = subprocess.run(args, check=True, capture_output=True, timeout=5)
        authorize()
        return result
    if event == 'deconfig':
        command(['ip', '-4', 'addr', 'flush', 'dev', INTERFACE])
        # A new namespace may have no main FIB yet. Query all existing tables
        # before flushing rather than treating its absence as a hook failure.
        routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout or b'[]')
        if any(route.get('dev') == INTERFACE for route in routes):
            command(['ip', '-4', 'route', 'flush', 'dev', INTERFACE])
        write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
        write_json(ROOT / 'portal-hints.json', {})
    elif event in ('bound', 'renew'):
        value = lease(os.environ)
        bridge = load_json(ROOT / 'state.json', {}).get('bridge')
        if bridge and ipaddress.IPv4Interface(value['address']).network.overlaps(ipaddress.IPv4Network(bridge['subnet'])):
            raise ValueError('DHCP lease overlaps the private transit link')
        command(['ip', '-4', 'addr', 'flush', 'dev', INTERFACE])
        command(['ip', 'addr', 'add', value['address'], 'dev', INTERFACE])
        command(['ip', '-4', 'route', 'flush', 'default'])
        if value['gateway']:
            command(['ip', 'route', 'add', 'default', 'via', value['gateway'], 'dev', INTERFACE])
        if authorize() != binding: raise RuntimeError('DHCP binding changed')
        write_json(ROOT / 'lease.json', dict(value, state='LEASED', connection=binding))
        # Hint capture grants no DNS access or Internet/portal authorization.
        write_json(ROOT / 'portal-hints.json', dict(wan_lease.hints(os.environ),
                   connection=binding, lease=value))
    # Ignore offered hostname, NTP and classless routes. Offered DNS is private
    # portal metadata only; host resolver and routing are never accessed here.


if __name__ == '__main__':
    main()
