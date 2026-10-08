"""Explicit transport choice, independent of retained VPN provider profiles.

The direct runtime is integrated separately; this store alone never enables
forwarding or modifies native management routing.
"""
from pathlib import Path
from storage import load_json, write_json
from vpn_config import locked
from dns_config import PUBLIC_DNSMITH, validate as validate_dns

CONFIG = Path('/data/setupOptions/RoadLink/transport.json')
DEFAULT = {'vpn_required': True}


def validate(value):
    if (not isinstance(value, dict) or set(value) != set(DEFAULT)
            or type(value['vpn_required']) is not bool):
        raise ValueError('Invalid transport configuration')
    return dict(value)


def read(path=CONFIG):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Refusing a symlink transport configuration')
    return validate(load_json(path, dict(DEFAULT)))


def save(value, path=CONFIG):
    value = validate(value)
    with locked(path):
        write_json(path, value)


def direct_dns(settings):
    """Public DNSmith is reachable without a VPN; its private resolver is not."""
    settings = validate_dns(settings)
    result = {'dns': PUBLIC_DNSMITH if settings['dnsmith'] else settings['primary']}
    if not settings['dnsmith'] and settings['secondary']:
        result['dns_secondary'] = settings['secondary']
    return result
