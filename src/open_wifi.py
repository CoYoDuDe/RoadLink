"""Bounded candidate selection; discovery never saves or trusts a network."""
import hashlib
from privacy import profile_mac


class Candidates:
    def __init__(self, data, enabled=False):
        self.profiles = list(data['profiles'].values())
        self.seed = bytes.fromhex(data['seed'])
        self.enabled = bool(enabled)
        self.blocked, self.failures = {}, {}

    def reject(self, identifier, now):
        count = min(self.failures.get(identifier, 0) + 1, 5)
        self.failures[identifier] = count
        self.blocked[identifier] = now + min(900, 60 * 2 ** (count - 1))

    def select(self, scan, wall_time, now):
        choices = sorted((p for p in self.profiles if p['autoconnect']),
                         key=lambda p: (-p['priority'], p['ssid']))
        if self.enabled and scan.get('state') == 'COMPLETE' and 0 <= wall_time - scan.get('timestamp', 0) <= 180:
            # Disabled saved networks and encrypted networks may not reappear
            # as anonymous open candidates, including security downgrades.
            known = {p['ssid'] for p in self.profiles}
            for network in sorted(scan.get('networks', []), key=lambda n: (-n['signal'], n['ssid']))[:80]:
                if network['security'] != 'open' or network['ssid'] in known:
                    continue
                ssid = network['ssid']
                identifier = hashlib.sha256(('open\0' + ssid).encode()).hexdigest()[:24]
                choices.append({'id': identifier, 'ssid': ssid, 'security': 'open', 'password': '',
                                'priority': 0, 'autoconnect': True, 'vpn_required': True,
                                'mac': profile_mac(self.seed, identifier), 'discovered': True})
        return next((p for p in choices if now >= self.blocked.get(p['id'], 0)), None)
