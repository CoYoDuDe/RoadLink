#!/usr/bin/env python3
"""DHCP event hook: only the owned network namespace, never host DNS/routes."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
from storage import write_json, load_json

ROOT = Path('/run/roadlink-wan')
INTERFACE = 'disabledrlwan'


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
    # A netns handle and /proc/net/ns inode must identify the exact namespace.
    if (os.stat('/proc/self/ns/net').st_ino != os.stat('/run/netns/roadlink-wan').st_ino
            or os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino
            or os.environ.get('interface') != INTERFACE):
        raise RuntimeError('Refusing DHCP changes outside the owned WAN namespace')
    event = sys.argv[1]
    def command(args):
        return subprocess.run(args, check=True, capture_output=True, timeout=5)
    if event == 'deconfig':
        command(['ip', '-4', 'addr', 'flush', 'dev', INTERFACE])
        # A new namespace may have no main FIB yet. Query all existing tables
        # before flushing rather than treating its absence as a hook failure.
        routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout or b'[]')
        if any(route.get('dev') == INTERFACE for route in routes):
            command(['ip', '-4', 'route', 'flush', 'dev', INTERFACE])
        write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
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
        write_json(ROOT / 'lease.json', dict(value, state='LEASED'))
    # Ignore offered DNS, hostname, NTP and classless routes. Host resolver and
    # host routing are never accessed by this hook.


if __name__ == '__main__':
    main()
