"""Private WLAN profiles; public metadata never contains credentials."""
import hashlib
import secrets
import os
from contextlib import contextmanager
from pathlib import Path
from storage import load_json, write_json
from privacy import profile_mac


class Profiles:
    def __init__(self, path='/data/setupOptions/RoadLink/wifi-profiles.json'):
        self.path = Path(path)
        self.data = load_json(self.path, {'schema': 1, 'seed': secrets.token_hex(32), 'profiles': {}})
        if self.data.get('schema') != 1:
            raise ValueError('Unsupported WLAN profile schema')

    @contextmanager
    def mutation(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = self.path.with_name(self.path.name + '.lock')
        fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            if os.name == 'posix':
                import fcntl
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
            self.data = load_json(self.path, self.data)
            if self.data.get('schema') != 1: raise ValueError('Unsupported WLAN profile schema')
            yield
        finally:
            os.close(fd)

    def save(self, ssid, security, password='', priority=50, autoconnect=False, edit_id=None, last_resort=None):
        with self.mutation():
            return self._save(ssid, security, password, priority, autoconnect, edit_id, last_resort)

    def _save(self, ssid, security, password='', priority=50, autoconnect=False, edit_id=None, last_resort=None):
        if not isinstance(ssid, str) or not 1 <= len(ssid.encode('utf-8')) <= 32 or '\x00' in ssid:
            raise ValueError('SSID must contain 1 to 32 UTF-8 bytes')
        if security not in ('psk', 'open'):
            raise ValueError('Unsupported WLAN security')
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 100:
            raise ValueError('Priority must be 0 to 100')
        if type(autoconnect) is not bool:
            raise ValueError('Autoconnect must be boolean')
        if last_resort is not None and type(last_resort) is not bool:
            raise ValueError('Last resort must be boolean')
        identifier = hashlib.sha256((security + '\x00' + ssid).encode()).hexdigest()[:24]
        if edit_id is not None:
            if edit_id not in self.data['profiles']:
                raise ValueError('Unknown WLAN profile')
            if any(p['ssid'] == ssid and p['security'] == security and key != edit_id
                   for key, p in self.data['profiles'].items()):
                raise ValueError('WLAN profile already exists')
            identifier = edit_id
        existing = self.data['profiles'].get(identifier, {})
        if last_resort is None: last_resort = existing.get('last_resort', False)
        password = password or existing.get('password', '')
        if security == 'psk' and not (8 <= len(password) <= 63 and all(32 <= ord(c) <= 126 for c in password)):
            raise ValueError('Password must contain 8 to 63 printable ASCII characters')
        value = {'id': identifier, 'ssid': ssid, 'security': security, 'password': password if security == 'psk' else '',
                 'priority': priority, 'autoconnect': autoconnect, 'last_resort': last_resort, 'vpn_required': True,
                 'mac': profile_mac(bytes.fromhex(self.data['seed']), identifier)}
        candidate = dict(self.data['profiles'])
        candidate[identifier] = value
        updated = dict(self.data, profiles=candidate)
        write_json(self.path, updated)
        self.data = updated
        return identifier

    def metadata(self):
        return [{k: v for k, v in p.items() if k != 'password'}
                for p in sorted(self.data['profiles'].values(), key=lambda p: (p.get('last_resort', False), -p['priority'], p['ssid']))]

    def remember_open(self, ssid):
        with self.mutation():
            if any(p['ssid'] == ssid for p in self.data['profiles'].values()):
                return None  # Never override a concurrent user choice/security.
            return self._save(ssid, 'open', priority=50, autoconnect=True)

    def forget(self, identifier):
        with self.mutation():
            return self._forget(identifier)

    def _forget(self, identifier):
        if identifier not in self.data['profiles']:
            raise ValueError('Unknown WLAN profile')
        candidate = dict(self.data['profiles'])
        del candidate[identifier]
        updated = dict(self.data, profiles=candidate)
        write_json(self.path, updated)
        self.data = updated
