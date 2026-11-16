"""Journal the AP parent and virtual interface before physical mutations."""
import json
from pathlib import Path
import secrets
import sys
import time
from storage import load_json, write_json
from runtime_lock import ParentNameOccupied

PARENT = 'disabledrlap'
AP = 'aproadlink'
TAG = 'roadlink-ap-owned'
SINGLE = {'parent': PARENT, 'ap': AP, 'journal': 'radio.json'}
# Dual-band: two radios become isolated ports of a bridge named AP.
DUAL = ({'parent': PARENT, 'ap': 'aprl24', 'journal': 'radio.json'},
        {'parent': 'disabledrlap5', 'ap': 'aprl5', 'journal': 'radio5.json'})


def links(command):
    return json.loads(command(['ip', '-j', 'link', 'show']).stdout)


def phy(name):
    return (Path('/sys/class/net') / name / 'phy80211').resolve().name


def plan(root, device, capabilities, command, names=SINGLE):
    if not capabilities.get('known') or not capabilities.get('ap'):
        raise ValueError('Selected radio does not advertise AP support')
    current = links(command)
    if any(item['ifname'] in (names['parent'], names['ap']) for item in current):
        raise RuntimeError('AP interface names are occupied')
    parent = next(item for item in current if item['ifname'] == device['interface'])
    addresses = json.loads(command(['ip', '-j', '-4', 'addr', 'show', 'dev', device['interface']]).stdout)
    if any(item.get('addr_info') for item in addresses):
        raise RuntimeError('Selected AP parent has native IPv4 configuration')
    on_phy = [item for item in current if phy(item['ifname']) == capabilities['phy']]
    if len(on_phy) != 1:
        raise RuntimeError('Selected AP radio has other virtual interfaces')
    if 'Connected to' in command(['iw', 'dev', device['interface'], 'link']).stdout:
        raise RuntimeError('Selected AP radio is connected natively')
    temporary = 'aprl' + secrets.token_hex(5)
    if any(item['ifname'] == temporary for item in current):
        raise RuntimeError('AP creation name occupied')
    state = {'parent': dict(device, phy=capabilities['phy'], ifindex=parent['ifindex'],
                            up='UP' in parent['flags'], alias=parent.get('ifalias', ''),
                            ipv6=Path('/proc/sys/net/ipv6/conf/' + device['interface'] + '/disable_ipv6').read_text()),
             'creation': temporary, 'ap_ifindex': None}
    state['names'] = dict(names)
    write_json(Path(root) / names['journal'], state)
    return state


def names_of(state):
    """Journals written before dual-band support carry no names: single radio."""
    names = state.get('names') or SINGLE
    if names not in (SINGLE, *DUAL):
        raise RuntimeError('Unknown AP radio names in ownership journal')
    return names


def release_supplicant(original, parent_name=PARENT):
    import dbus
    bus = dbus.SystemBus()
    manager = bus.get_object('fi.w1.wpa_supplicant1', '/fi/w1/wpa_supplicant1')
    for attempt in range(30):
        paths = dbus.Interface(manager, 'org.freedesktop.DBus.Properties').Get('fi.w1.wpa_supplicant1', 'Interfaces')
        owned = []
        for path in paths:
            try:
                value = dbus.Interface(bus.get_object('fi.w1.wpa_supplicant1', path), 'org.freedesktop.DBus.Properties').Get('fi.w1.wpa_supplicant1.Interface', 'Ifname')
                if str(value) in (original, parent_name): owned.append(path)
            except dbus.DBusException:
                pass
        if not owned: return
        if attempt == 10:
            for path in owned: dbus.Interface(manager, 'fi.w1.wpa_supplicant1').RemoveInterface(path)
        time.sleep(.1)
    raise RuntimeError('Native supplicant did not release the AP parent')


def acquire(root, state, command):
    parent = state['parent']
    names = names_of(state)
    command(['ip', 'link', 'set', parent['interface'], 'down'])
    command(['ip', 'link', 'set', parent['interface'], 'name', names['parent']])
    command(['ip', 'link', 'set', names['parent'], 'alias', TAG])
    command(['sysctl', '-qw', 'net.ipv6.conf.' + names['parent'] + '.disable_ipv6=1'])
    command([sys.executable, __file__, 'release-supplicant', parent['interface'], names['parent']])
    command(['iw', 'dev', names['parent'], 'interface', 'add', state['creation'], 'type', '__ap'])
    created = next(item for item in links(command) if item['ifname'] == state['creation'])
    state['ap_ifindex'] = created['ifindex']
    write_json(Path(root) / names['journal'], state)
    command(['ip', 'link', 'set', state['creation'], 'alias', TAG])
    command(['ip', 'link', 'set', state['creation'], 'name', names['ap']])


def owned_virtual(item, state):
    if phy(item['ifname']) != state['parent']['phy']:
        return False
    if item['ifname'] == state['creation']:
        return item.get('ifalias', '') in ('', TAG) and (state['ap_ifindex'] is None or item['ifindex'] == state['ap_ifindex'])
    return (item['ifname'] == names_of(state)['ap'] and item['ifindex'] == state['ap_ifindex']
            and item.get('ifalias') == TAG)


def remove_virtual(root, command, journal='radio.json'):
    state = load_json(Path(root) / journal, {})
    if not state:
        raise RuntimeError('Missing AP ownership journal')
    ap = names_of(state)['ap']
    for item in links(command):
        if item['ifname'] in (ap, state['creation']):
            if not owned_virtual(item, state):
                raise RuntimeError('Foreign AP interface; retained for inspection')
            command(['iw', 'dev', item['ifname'], 'del'])
    if any(item['ifname'] in (ap, state['creation']) for item in links(command)):
        raise RuntimeError('Owned AP interface removal incomplete')


def restore_parent(root, command, journal='radio.json'):
    state = load_json(Path(root) / journal)
    parent, parent_name = state['parent'], names_of(state)['parent']
    current = links(command)
    item = next((item for item in current if item['ifindex'] == parent['ifindex']), None)
    if item is None:
        return  # An unplugged radio is never replaced by another device's name.
    name = item['ifname']
    if (name not in (parent['interface'], parent_name) or phy(name) != parent['phy']
            or item.get('ifalias', '') not in (parent['alias'], TAG)):
        raise RuntimeError('AP parent ownership changed; restoration refused')
    if name != parent['interface'] and any(item['ifname'] == parent['interface'] for item in current):
        raise ParentNameOccupied('Original AP parent name occupied; original guard retains ownership')
    command(['ip', 'link', 'set', name, 'down'])
    command(['ip', 'link', 'set', name, 'address', parent['mac']])
    command(['ip', 'link', 'set', name, 'alias', parent['alias']])
    if name != parent['interface']:
        command(['ip', 'link', 'set', name, 'name', parent['interface']])
    command(['sysctl', '-qw', 'net.ipv6.conf.' + parent['interface'] + '.disable_ipv6=' + parent['ipv6'].strip()])
    if parent['up']: command(['ip', 'link', 'set', parent['interface'], 'up'])


if __name__ == '__main__':
    if len(sys.argv) not in (3, 4) or sys.argv[1] != 'release-supplicant':
        raise ValueError('Unknown AP radio action')
    if len(sys.argv) == 4 and sys.argv[3] not in (PARENT, DUAL[1]['parent']):
        raise ValueError('Unknown AP parent name')
    release_supplicant(sys.argv[2], *sys.argv[3:])
