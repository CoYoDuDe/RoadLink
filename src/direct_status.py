"""Fresh direct-path proof shared by the AP, WLAN learner and GUI.

Status alone cannot authorize a path: both controllers and guards must still
own the exact AP and, for WiFi, the exact associated profile and bridge.
"""
import math
from pathlib import Path
import time
from storage import load_json
from transport_config import direct_dns
import direct_router

ROOT = Path('/run/roadlink-direct')
AP_ROOT = Path('/run/roadlink-ap')
WAN_ROOT = Path('/run/roadlink-wan')


def owners(root):
    return [load_json(Path(root) / (name + '.json'), {})
            for name in ('controller', 'guard')]


def identity(values):
    return [[item.get('pid'), item.get('start')] for item in values]


def verified(status, subnet, settings, ap, wan, wan_state, now):
    try:
        checked = status['checked_at']
        if (type(checked) not in (int, float) or not math.isfinite(checked)
                or not 0 <= now - checked <= 30):
            return None
        config = status['config']
        config = direct_router.plan(config['subnet'], config, config['dns'])
        resolvers = direct_dns(settings)
        allowed = {resolvers['dns'], resolvers.get('dns_secondary', '')}
        if (not direct_router.ready(config, status) or config['subnet'] != subnet
                or status.get('dns') != config['dns'] or config['dns'] not in allowed
                or status.get('ap_owners') != identity(ap)
                or status.get('wan') != config['kind']):
            return None
        if config['kind'] == 'wifi':
            bridge = wan_state.get('bridge') or {}
            if (status.get('wan_owners') != identity(wan)
                    or wan_state.get('state') != 'LEASED'
                    or not wan_state.get('profile_id')
                    or status.get('wifi_profile_id') != wan_state['profile_id']
                    or not wan_state.get('connection_id') or not wan_state.get('lease')
                    or status.get('wifi_connection_id') != wan_state['connection_id']
                    or status.get('wifi_lease') != wan_state['lease']
                    or bridge.get('transport') != 'direct'
                    or config['source'] != bridge.get('host')
                    or config['gateway'] != bridge.get('peer')):
                return None
        return config
    except (ValueError, TypeError, KeyError, OverflowError):
        return None


def current(subnet, settings, alive, root=ROOT, ap_root=AP_ROOT, wan_root=WAN_ROOT):
    root, ap_root, wan_root = map(Path, (root, ap_root, wan_root))
    values = owners(root)
    ap, wan = owners(ap_root), owners(wan_root)
    status = load_json(root / 'status.json', {})
    wan_state = load_json(wan_root / 'status.json', {})
    config = verified(status, subnet, settings, ap, wan, wan_state, time.monotonic())
    from firewall_guard import matches
    if config and not matches(config):
        return None
    required = [(root, values), (ap_root, ap)]
    if config and config['kind'] == 'wifi':
        required.append((wan_root, wan))
    for folder, before in required:
        if (folder.is_symlink() or not all(alive(item) for item in before)
                or owners(folder) != before
                or any((folder / name).exists() for name in ('stop', 'cleaning'))):
            return None
    if config and config['kind'] == 'wifi':
        after = load_json(wan_root / 'status.json', {})
        if any(after.get(key) != wan_state.get(key) for key in ('state', 'profile_id', 'connection_id', 'lease', 'bridge')):
            return None
    return config
