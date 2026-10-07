"""Validated device-local VPN settings. Endpoint bootstrap needs no WAN DNS."""
import ipaddress
from pathlib import Path
from storage import load_json, write_json
from wireguard import validate_key

CONFIG = Path('/data/setupOptions/RoadLink/wireguard/config.json')


def validate(value):
    if not isinstance(value, dict) or type(value.get('enabled')) is not bool:
        raise ValueError('VPN enabled must be boolean')
    endpoint = ipaddress.IPv4Address(value['endpoint'])
    if not endpoint.is_global:
        raise ValueError('VPN endpoint must be a public IPv4 address')
    port = value.get('port', 51820)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid VPN endpoint port')
    address = ipaddress.IPv4Interface(value['address'])
    private = any(address.ip in ipaddress.IPv4Network(net)
                  for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if address.network.prefixlen != 32 or not private:
        raise ValueError('A single IPv4 client address is required')
    dns = ipaddress.IPv4Address(value['dns'])
    if dns.is_multicast or dns.is_unspecified or dns == address.ip:
        raise ValueError('Invalid VPN DNS address')
    mtu = value.get('mtu', 1380)
    if type(mtu) is not int or not 1280 <= mtu <= 1420:
        raise ValueError('VPN MTU must be 1280 to 1420')
    return {'enabled': value['enabled'], 'endpoint': str(endpoint), 'port': port,
            'public_key': validate_key(value['public_key']), 'address': str(address),
            'dns': str(dns), 'mtu': mtu}


def read(path=CONFIG):
    value = load_json(path)
    return validate(value) if value is not None else None


def save(value, path=CONFIG):
    write_json(path, validate(value))
