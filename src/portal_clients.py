"""Select only an unambiguous, current DHCP client authenticated on the vehicle AP."""
import hashlib
import ipaddress
import math
import re
from pathlib import Path


def mac(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('Invalid vehicle client MAC')
    value = value.lower()
    if int(value[:2], 16) & 1 or value == '00:00:00:00:00:00':
        raise ValueError('Vehicle client MAC must be unicast')
    return value


def stations(text):
    if not isinstance(text, str) or len(text.encode()) > 65536: raise ValueError('AP station response too large')
    values, current = set(), None
    for line in text.splitlines():
        if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', line):
            current = mac(line)
        elif line.startswith('flags=') and current:
            if all(flag in line for flag in ('[AUTH]', '[ASSOC]', '[AUTHORIZED]')): values.add(current)
    return values


def clients(text, subnet, authenticated, now):
    if not isinstance(text, str) or len(text.encode()) > 65536 or len(text.splitlines()) > 256:
        raise ValueError('Vehicle lease response too large')
    if not math.isfinite(now): raise ValueError('Invalid clock')
    network = ipaddress.IPv4Network(subnet)
    if network.prefixlen != 24 or not network.is_private: raise ValueError('Invalid vehicle subnet')
    authenticated = {mac(value) for value in authenticated}
    result, seen_ips, seen_macs = [], set(), set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 5: raise ValueError('Malformed vehicle DHCP lease')
        expires, hardware, address, name, _ = fields
        if not expires.isascii() or not expires.isdecimal() or len(expires) > 12: raise ValueError('Invalid DHCP expiry')
        expires = int(expires)
        if expires <= now: continue
        hardware, address = mac(hardware), ipaddress.IPv4Address(address)
        if hardware not in authenticated: continue
        if address not in network or address in (network.network_address, network.broadcast_address, network[1]):
            raise ValueError('Client outside vehicle DHCP network')
        if str(address) in seen_ips or hardware in seen_macs: raise ValueError('Ambiguous vehicle client identity')
        seen_ips.add(str(address)); seen_macs.add(hardware)
        name = name if name != '*' and re.fullmatch(r'[A-Za-z0-9_.-]{1,63}', name) else ''
        result.append({'id': hashlib.sha256((hardware+'|'+str(address)).encode()).hexdigest()[:24],
                       'ip': str(address), 'mac': hardware, 'name': name, 'expires': expires})
    return sorted(result, key=lambda item: (item['name'], ipaddress.IPv4Address(item['ip'])))


def select(identifier, available):
    matches = [value for value in available if value['id'] == identifier]
    if len(matches) != 1: raise ValueError('Portal login device is absent or ambiguous')
    return dict(matches[0])


def inventory(root, read, is_alive, query, lease_text, now):
    """Read-only snapshot; reject AP restarts during station/lease collection."""
    root = Path(root)
    controller, guard = read(root/'controller.json', {}), read(root/'guard.json', {})
    radio, status = read(root/'radio.json', {}), read(root/'status.json', {})
    if (not all(is_alive(value) for value in (controller, guard))
            or status.get('state') not in ('LAN_ONLY', 'VPN_INTERNET', 'DIRECT_INTERNET')
            or type(radio.get('ap_ifindex')) is not int or radio['ap_ifindex'] <= 0):
        raise ValueError('Vehicle WLAN is unavailable')
    links = query('links')
    if (len(links) != 1 or links[0].get('ifindex') != radio['ap_ifindex']
            or links[0].get('ifname') != 'aproadlink' or links[0].get('ifalias') != 'roadlink-ap-owned'):
        raise ValueError('Vehicle WLAN interface ownership changed')
    network = str(ipaddress.IPv4Network(status['address']+'/24', strict=False))
    values = clients(lease_text(), network, stations(query('stations')), now)
    if (read(root/'controller.json', {}) != controller or read(root/'guard.json', {}) != guard
            or read(root/'radio.json', {}) != radio
            or read(root/'status.json', {}).get('address') != status['address']
            or query('links') != links or not all(is_alive(value) for value in (controller, guard))):
        raise ValueError('Vehicle WLAN changed during client collection')
    return {'controller': controller, 'guard': guard, 'ifindex': radio['ap_ifindex'],
            'subnet': network, 'clients': values}


def available():
    import json
    import subprocess
    import time
    from ap_runtime import alive
    from storage import load_json
    root = Path('/run/roadlink-ap')
    if (root/'stop').exists() or (root/'cleaning').exists(): raise ValueError('Vehicle WLAN is stopping')
    def query(kind):
        args = (['ip', '-j', 'link', 'show', 'dev', 'aproadlink'] if kind == 'links' else
                ['hostapd_cli', '-p', str(root/'control'), '-i', 'aproadlink', 'all_sta'])
        result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=3)
        return json.loads(result.stdout) if kind == 'links' else result.stdout
    def leases():
        with (root/'leases').open() as stream: return stream.read(65537)
    result = inventory(root, load_json, alive, query, leases, time.time())
    if (root/'stop').exists() or (root/'cleaning').exists(): raise ValueError('Vehicle WLAN is stopping')
    return result
