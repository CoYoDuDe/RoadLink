"""Device-local provider slots; a selection never destroys the other VPN."""
from pathlib import Path
from storage import load_json, write_json

STORE = Path('/data/setupOptions/RoadLink/wireguard/providers.json')
NAMES = ('dnsmith', 'custom')


def legacy_provider(config):
    return config.get('provider', 'dnsmith' if config.get('endpoint') == '82.165.141.247'
                      and config.get('dns') == '10.8.0.1' else 'custom')


def state(store=STORE, legacy=None):
    from vpn_config import CONFIG, validate
    if Path(store).is_symlink() or Path(store).parent.is_symlink():
        raise ValueError('Refusing a symlink provider store')
    value = load_json(store)
    if value is None:
        config = load_json(CONFIG if legacy is None else legacy)
        if config is None:
            return {'selected': 'dnsmith', 'profiles': {}}
        config = validate(config)
        provider = legacy_provider(config)
        return {'selected': provider, 'profiles': {provider: config}}
    if (not isinstance(value, dict) or value.get('selected') not in NAMES
            or not isinstance(value.get('profiles'), dict)
            or any(name not in NAMES for name in value['profiles'])):
        raise ValueError('Invalid VPN provider storage')
    profiles = {}
    for name, config in value['profiles'].items():
        config = validate(config)
        if config.get('provider', name) != name:
            raise ValueError('VPN provider mismatch')
        profiles[name] = config
    return {'selected': value['selected'], 'profiles': profiles}


def selected(store=STORE, legacy=None):
    return state(store, legacy)['selected']


def current(store=STORE, legacy=None):
    value = state(store, legacy)
    return value['profiles'].get(value['selected'])


def select(name, store=STORE, legacy=None):
    from vpn_config import CONFIG, locked
    if name not in NAMES:
        raise ValueError('Invalid VPN provider')
    with locked(CONFIG if legacy is None else legacy):
        value = state(store, legacy)
        value['selected'] = name
        write_json(store, value)


def save_profile(config, store=STORE, legacy=None, only_missing=False, permitted=lambda: True, activate=False):
    from vpn_config import CONFIG, locked, validate
    config = validate(config)
    name = config.get('provider')
    if name not in NAMES:
        raise ValueError('VPN provider required')
    with locked(CONFIG if legacy is None else legacy):
        value = state(store, legacy)
        if (value['selected'] != name and not activate) or (only_missing and name in value['profiles']) or not permitted():
            return False
        if activate:
            value['selected'] = name
        value['profiles'][name] = config
        write_json(store, value)
        return True
