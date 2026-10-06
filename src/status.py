"""Read-only live status. Link carrier is deliberately not Internet health."""
import json
import time
from hardware import inspect_interfaces, command


def snapshot():
    devices = inspect_interfaces()
    try:
        routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'default']) or '[]')
    except (ValueError, TypeError):
        routes = []
    defaults = sorted(routes, key=lambda r: r.get('metric', 0))
    return {
        'schema': 1, 'timestamp': int(time.time()), 'mode': 'MONITOR_ONLY',
        'controller_enabled': False, 'privacy_enforced': False,
        'vpn_enforced': False, 'internet_verified': False,
        'default_interface': defaults[0].get('dev', '') if defaults else '',
        'interfaces': devices,
    }


def role_text(state, role):
    matches = [d for d in state['interfaces'] if d['suggested_role'] == role + '_candidate']
    if not matches:
        return 'Nicht erkannt'
    if len(matches) != 1:
        return 'Mehrere Geraete: Auswahl erforderlich'
    dev = matches[0]
    return '{} ({}, {})'.format(dev['interface'], dev['driver'], dev['operstate'])
