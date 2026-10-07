"""WireGuard-only outer routing, owned and cleaned by the VPN guard."""
import ipaddress
import json
import re
from pathlib import Path
from storage import load_json, write_json
from wan_bridge import HOST, MARK

TABLE = '51910'
PRIORITY = '21790'


def start(root, config, command):
    if (PRIORITY + ':' in command(['ip', 'rule', 'show']).stdout
            or command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout.strip()):
        raise RuntimeError('Transport policy table/priority already occupied')
    # Guard removes this only after removing the WireGuard interface.
    write_json(root / 'transport.json', {'endpoint': config['endpoint']})
    command(['ip', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', TABLE])
    command(['ip', 'rule', 'add', 'priority', PRIORITY, 'fwmark', MARK + '/0xffffffff', 'lookup', TABLE])


def ethernet(config, command):
    from hardware import inspect_interfaces
    result = command(['ip', '-j', '-4', 'route', 'get', config['endpoint']], check=False)
    items = json.loads(result.stdout or '[]')
    if not items: return None
    route = items[0]
    dev = route.get('dev', '')
    if not any(d['interface'] == dev and d['suggested_role'] == 'ethernet_candidate'
               for d in inspect_interfaces()): return None
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', dev): return None
    source = str(ipaddress.IPv4Address(route['prefsrc']))
    gateway = str(ipaddress.IPv4Address(route['gateway'])) if route.get('gateway') else ''
    return {'dev': dev, 'source': source, 'gateway': gateway}


def wifi(state):
    device = Path('/sys/class/net') / HOST
    if (state.get('state') != 'LEASED' or not state.get('bridge')
            or not device.exists() or (device / 'ifalias').read_text().strip() != 'roadlink-wan-bridge-owned'):
        return None
    bridge = state['bridge']
    return {'dev': HOST, 'source': str(ipaddress.IPv4Address(bridge['host'])),
            'gateway': str(ipaddress.IPv4Address(bridge['peer']))}


def select(config, route, command):
    destination = str(ipaddress.IPv4Address(config['endpoint'])) + '/32'
    if route:
        args = ['ip', 'route', 'replace', destination, 'table', TABLE, 'metric', '10',
                'dev', route['dev'], 'src', route['source']]
        if route['gateway']: args += ['via', route['gateway'], 'onlink']
        command(args)
    else:
        command(['ip', 'route', 'del', destination, 'table', TABLE, 'metric', '10'], check=False)


def cleanup(root, command):
    state = load_json(root / 'transport.json', {})
    if not state: return []
    command(['ip', 'rule', 'del', 'priority', PRIORITY, 'fwmark', MARK + '/0xffffffff', 'lookup', TABLE], check=False)
    command(['ip', 'route', 'del', state['endpoint'] + '/32', 'table', TABLE, 'metric', '10'], check=False)
    command(['ip', 'route', 'del', 'unreachable', 'default', 'metric', '32767', 'table', TABLE], check=False)
    if (PRIORITY + ':' in command(['ip', 'rule', 'show']).stdout
            or command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout.strip()):
        return ['Transport policy cleanup incomplete']
    return []
