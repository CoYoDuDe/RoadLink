"""Validated device-local VPN settings. Endpoint bootstrap needs no WAN DNS."""
import ipaddress
import os
from contextlib import contextmanager
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
    dns_private = any(dns in ipaddress.IPv4Network(net)
                      for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if not (dns.is_global or dns_private) or dns == address.ip:
        raise ValueError('Invalid VPN DNS address')
    mtu = value.get('mtu', 1380)
    if type(mtu) is not int or not 1280 <= mtu <= 1420:
        raise ValueError('VPN MTU must be 1280 to 1420')
    result = {'enabled': value['enabled'], 'endpoint': str(endpoint), 'port': port,
            'public_key': validate_key(value['public_key']), 'address': str(address),
            'dns': str(dns), 'mtu': mtu}
    if 'provider' in value:
        if value['provider'] not in ('dnsmith', 'custom'):
            raise ValueError('Invalid VPN provider')
        result['provider'] = value['provider']
    return result


def read(path=CONFIG):
    if Path(path) == CONFIG:
        from vpn_providers import current
        return current()
    value = load_json(path)
    return validate(value) if value is not None else None


def configured(path=CONFIG):
    if Path(path) == CONFIG:
        from vpn_providers import state
        value = state()
        return value['selected'] in value['profiles']
    return Path(path).exists()


def enrollment_allowed():
    from vpn_providers import selected
    return selected() == 'dnsmith' and not configured()


@contextmanager
def locked(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Refusing a symlink VPN configuration')
    if os.name != 'posix':
        yield
        return
    import fcntl
    fd = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as stream:
        os.fchmod(stream.fileno(), 0o600)
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield


def save(value, path=CONFIG):
    config = validate(value)
    if Path(path) == CONFIG:
        from vpn_providers import STORE, save_profile, selected
        if STORE.exists():
            if not save_profile(dict(config, provider=config.get('provider', selected()))):
                raise ValueError('VPN provider is not selected')
            return
    with locked(path):
        write_json(path, config)


def install_if_missing(value, path=CONFIG, permitted=lambda: True):
    """A delayed enrollment response must never overwrite user configuration."""
    config = validate(value)
    if Path(path) == CONFIG:
        from vpn_providers import save_profile
        return save_profile(config, only_missing=True, permitted=permitted)
    with locked(path):
        if Path(path).exists() or not permitted():
            return False
        write_json(path, config)
        return True
