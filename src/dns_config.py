"""Independent DNS choice. Stored VPN profiles keep their original resolver."""
import ipaddress
from pathlib import Path
from storage import load_json, write_json
from vpn_config import locked

CONFIG = Path('/data/setupOptions/RoadLink/dns.json')
DEFAULT = {'dnsmith': True, 'primary': '', 'secondary': ''}
PUBLIC_DNSMITH = '82.165.141.247'


def public_address(value):
    if not isinstance(value, str):
        raise ValueError('DNS must be an IPv4 address')
    address = ipaddress.IPv4Address(value.strip())
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError('Custom DNS must be a public IPv4 address')
    return str(address)


def validate(value):
    if (not isinstance(value, dict) or set(value) != set(DEFAULT)
            or type(value['dnsmith']) is not bool):
        raise ValueError('Invalid DNS settings')
    result = {'dnsmith': value['dnsmith']}
    for name in ('primary', 'secondary'):
        if not isinstance(value[name], str):
            raise ValueError('Invalid DNS field')
        result[name] = public_address(value[name]) if value[name].strip() else ''
    if not result['dnsmith'] and not result['primary']:
        raise ValueError('Primary DNS required')
    if result['secondary'] and result['secondary'] == result['primary']:
        raise ValueError('DNS addresses must differ')
    return result


def read(path=CONFIG):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Refusing a symlink DNS configuration')
    return validate(load_json(path, dict(DEFAULT)))


def save(value, path=CONFIG):
    value = validate(value)
    with locked(path):
        write_json(path, value)


def effective(vpn, provider, settings):
    """Resolve an immutable view; never save DNS overrides into a VPN slot."""
    settings = validate(settings)
    if vpn is None:
        return None
    if provider not in ('dnsmith', 'custom'):
        raise ValueError('Invalid VPN provider')
    result = dict(vpn)
    result.pop('dns_secondary', None)
    if settings['dnsmith']:
        # A manually entered DNSmith tunnel still reaches the private resolver.
        # Its public address is not a permitted DNS destination inside wg0.
        dnsmith_tunnel = (vpn.get('endpoint') == PUBLIC_DNSMITH
                          and vpn.get('port', 51820) == 51820
                          and vpn.get('dns') == '10.8.0.1')
        result['dns'] = vpn['dns'] if provider == 'dnsmith' or dnsmith_tunnel else PUBLIC_DNSMITH
    else:
        result['dns'] = settings['primary']
        if settings['secondary']:
            result['dns_secondary'] = settings['secondary']
    return result


def ready(vpn, status):
    """Only accept resolver evidence from this active VPN configuration."""
    return bool(vpn and status.get('state') == 'READY' and status.get('dns_ready') is True
                and status.get('internet') is True and status.get('address') == vpn['address']
                and status.get('endpoint') == vpn['endpoint']
                and status.get('dns') in (vpn['dns'], vpn.get('dns_secondary'))
                and bool(status.get('dns')))


def routed(vpn, status):
    if vpn is None:
        return None
    return dict(vpn, dns=status['dns']) if ready(vpn, status) else dict(vpn)
