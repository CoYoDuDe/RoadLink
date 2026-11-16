"""Vehicle WLAN devices in the Venus menu: list with IP, block and unblock.

Rows come from hostapd (associated stations) and dnsmasq leases. Blocking is
persistent (blocked-clients.json) and applied at runtime through hostapd's
deny ACL plus a deauthentication, so no AP restart is needed. The AP runtime
loads the same list into deny_mac_file at every start.

Note: a repeater using MAC translation presents per-device proxy MACs; a
block then applies to the MAC the AP actually sees.
"""
import json
import os
import re
import subprocess
import time
from pathlib import Path

BLOCKED = Path('/data/setupOptions/RoadLink/blocked-clients.json')
CONTROL = Path('/run/roadlink-ap/control')
LEASES = Path('/run/roadlink-ap/leases')
INTERFACE = 'aproadlink'  # single radio; dual-band uses one hostapd per bridge port
SLOTS = 16
MAC = re.compile(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}')
NAME = re.compile(r'[A-Za-z0-9 ._+-]{1,40}')


def read_blocked(path=BLOCKED):
    try:
        data = json.loads(Path(path).read_text())
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise ValueError('Invalid blocked client list')
    result = {}
    for mac, name in data.items():
        if isinstance(mac, str) and MAC.fullmatch(mac) and isinstance(name, str) and len(name) <= 40:
            result[mac] = name
    return result


def write_blocked(value, path=BLOCKED):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing symlink blocked client list')
    temporary = path.with_name(path.name + '.new')
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(json.dumps(dict(sorted(value.items()))))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(temporary), str(path))


def deny_file_text(blocked):
    return ''.join(mac + '\n' for mac in sorted(blocked))


def parse_stations(text):
    """hostapd_cli all_sta: MAC line followed by key=value lines."""
    stations, current = {}, None
    for line in text.splitlines():
        line = line.strip()
        if MAC.fullmatch(line.lower()):
            current = stations.setdefault(line.lower(), {})
        elif current is not None and '=' in line:
            key, value = line.split('=', 1)
            current[key] = value
    return stations


def parse_leases(text):
    leases = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and MAC.fullmatch(parts[1].lower()):
            name = parts[3] if parts[3] != '*' and NAME.fullmatch(parts[3]) else ''
            leases[parts[1].lower()] = {'ip': parts[2], 'name': name}
    return leases


def rows(stations, leases, blocked):
    macs = list(stations) + [m for m in leases if m not in stations] + [m for m in blocked if m not in stations and m not in leases]
    result = []
    for mac in macs:
        lease = leases.get(mac, {})
        station = stations.get(mac, {})
        signal = station.get('signal')
        name = lease.get('name') or blocked.get(mac) or ''
        result.append({'mac': mac, 'name': name, 'ip': lease.get('ip', ''),
                       'online': mac in stations, 'blocked': mac in blocked,
                       'signal': int(signal) if signal and re.fullmatch(r'-?\d{1,3}', signal) else None,
                       'connected': int(station['connected_time']) if station.get('connected_time', '').isdigit() else None})
    # Online first, then blocked, then by name/MAC; stable for the menu.
    result.sort(key=lambda r: (not r['online'], not r['blocked'], r['name'] or '~', r['mac']))
    return result[:SLOTS]


def title(row):
    label = row['name'] or row['mac']
    parts = [label]
    if row['ip'] and row['online']:
        parts.append(row['ip'])
    if row['blocked']:
        parts.append('gesperrt')
    elif not row['online']:
        parts.append('offline')
    return ' – '.join(parts)


def interfaces(control=CONTROL):
    """hostapd creates one control socket per AP interface it serves."""
    try:
        names = sorted(item.name for item in Path(control).iterdir() if item.is_socket())
    except OSError:
        return []
    return [name for name in names if name in ('aproadlink', 'aprl24', 'aprl5')]


def hostapd(args, control=CONTROL, interface=INTERFACE):
    return subprocess.run(['hostapd_cli', '-p', str(control), '-i', interface, *args],
                          capture_output=True, text=True, timeout=3)


class Clients:
    def __init__(self, service, blocked_path=BLOCKED, control=CONTROL, leases=LEASES, run=None, clock=time.monotonic):
        self.service, self.path, self.control, self.leases = service, Path(blocked_path), Path(control), Path(leases)
        self.run = run or (lambda args: self._all(args))
        self.clock, self.next = clock, 0
        self.macs = [''] * SLOTS
        service.add_path('/Clients/Count', 0)
        service.add_path('/Clients/Status', '')
        for i in range(SLOTS):
            for key, value in (('Mac', ''), ('Name', ''), ('Ip', ''), ('Title', ''), ('Online', 0),
                               ('Signal', ''), ('Connected', '')):
                service.add_path('/Clients/{}/{}'.format(i, key), value)
            service.add_path('/Clients/{}/Blocked'.format(i), 0, writeable=True,
                             onchangecallback=lambda path, value, i=i: self.block(i, value))

    def _all(self, args):
        """Run a hostapd_cli command on every active AP interface; merge outputs."""
        outputs, code = [], 1
        for name in interfaces(self.control) or [INTERFACE]:
            result = hostapd(args, self.control, name)
            outputs.append(result.stdout)
            code = min(code, result.returncode)
        return subprocess.CompletedProcess(args, code, ''.join(outputs), '')

    def update(self, force=False):
        if not force and self.clock() < self.next:
            return
        self.next = self.clock() + 5
        try:
            blocked = read_blocked(self.path)
        except (ValueError, OSError):
            blocked = {}
        stations = {}
        if self.control.exists():
            try:
                result = self.run(['all_sta'])
                if result.returncode == 0:
                    stations = parse_stations(result.stdout)
            except (OSError, subprocess.SubprocessError):
                pass
        try:
            leases = parse_leases(self.leases.read_text())
        except OSError:
            leases = {}
        current = rows(stations, leases, blocked)
        self.service['/Clients/Count'] = sum(1 for r in current if r['online'])
        for i in range(SLOTS):
            row = current[i] if i < len(current) else None
            self.macs[i] = row['mac'] if row else ''
            prefix = '/Clients/{}/'.format(i)
            self.service[prefix + 'Mac'] = row['mac'] if row else ''
            self.service[prefix + 'Name'] = row['name'] if row else ''
            self.service[prefix + 'Ip'] = row['ip'] if row else ''
            self.service[prefix + 'Title'] = title(row) if row else ''
            self.service[prefix + 'Online'] = int(row['online']) if row else 0
            self.service[prefix + 'Blocked'] = int(row['blocked']) if row else 0
            self.service[prefix + 'Signal'] = '{} dBm'.format(row['signal']) if row and row['signal'] is not None else ''
            self.service[prefix + 'Connected'] = ('{} min'.format(row['connected'] // 60)
                                                 if row and row['connected'] is not None else '')

    def block(self, index, value):
        mac = self.macs[index] if 0 <= index < SLOTS else ''
        if not mac or value not in (0, 1, True, False):
            return False
        try:
            blocked = read_blocked(self.path)
            if value:
                blocked[mac] = self.service['/Clients/{}/Name'.format(index)] or ''
            else:
                blocked.pop(mac, None)
            write_blocked(blocked, self.path)
        except (ValueError, OSError):
            self.service['/Clients/Status'] = 'Sperrliste nicht gespeichert'
            return False
        if self.control.exists():
            try:
                if value:
                    self.run(['deny_acl', 'ADD_MAC', mac])
                    self.run(['deauthenticate', mac])
                else:
                    self.run(['deny_acl', 'DEL_MAC', mac])
            except (OSError, subprocess.SubprocessError):
                pass  # persisted; applied at the next AP start at the latest
        self.service['/Clients/Status'] = ('{} gesperrt' if value else '{} freigegeben').format(
            self.service['/Clients/{}/Name'.format(index)] or mac)
        self.next = 0
        return True
