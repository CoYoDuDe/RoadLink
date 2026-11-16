"""Bounded candidate selection; discovery never saves or trusts a network."""
import hashlib
from privacy import profile_mac
from wifi_quality import ranking,history


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

    def replacement(self, current, state, scan, wall_time, now, allow_last_resort):
        """Choose an admitted visible reserve only for an unconnected attempt."""
        if (not self.enabled or not allow_last_resort or not current
                or current.get('last_resort') or state != 'CONNECTING'
                or scan.get('state') != 'COMPLETE'
                or not 0 <= wall_time - scan.get('timestamp', 0) <= 180):
            return None
        chosen = self.select(scan, wall_time, now, allow_last_resort=True)
        return chosen if chosen and chosen.get('last_resort') and chosen['id'] != current['id'] else None

    def select(self, scan, wall_time, now, allow_last_resort=True):
        # Require current radio evidence before trying saved profiles when
        # automatic discovery is enabled; a failed fresh scan still permits
        # hidden saved SSIDs as the bounded fallback.
        if self.enabled and (scan.get('state') not in ('COMPLETE', 'FAILED')
                             or not 0 <= wall_time - scan.get('timestamp', 0) <= 180):
            return None
        preferred = sorted((p for p in self.profiles if p['autoconnect'] and not p.get('last_resort', False)),
                           key=lambda p: ranking(p, wall_time))
        fallback = sorted((p for p in self.profiles if p['autoconnect'] and p.get('last_resort', False)),
                          key=lambda p: ranking(p, wall_time))
        fresh = 0 <= wall_time - scan.get('timestamp', 0) <= 180
        signals = {(n.get('ssid'), n.get('security')): n.get('signal')
                   for n in scan.get('networks', [])} if fresh and scan.get('state') == 'COMPLETE' else {}
        visible = set(signals)
        seen = lambda p: (p.get('ssid'), p.get('security')) in visible
        if self.enabled and fresh and scan.get('state') == 'COMPLETE':
            preferred = [p for p in preferred if seen(p)]
            fallback = [p for p in fallback if seen(p)]
        choices = list(preferred)
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
        # With auto-open enabled, search once before using last-resort WLANs.
        if allow_last_resort and (not self.enabled or (fresh and scan.get('state') in ('COMPLETE', 'FAILED'))):
            if fresh and scan.get('state') == 'COMPLETE':
                if any(seen(p) for p in fallback):
                    reserve_signal = max((signals[(p['ssid'],p['security'])] for p in fallback if seen(p)
                                          and type(signals[(p['ssid'],p['security'])]) is int),default=-1000)
                    def weak_failed(p):
                        signal = signals.get((p.get('ssid'),p.get('security')))
                        quality = history(p.get('quality'),wall_time)
                        return bool(type(signal) is int and signal <= -85
                                    and reserve_signal >= signal + 3 and reserve_signal >= -87
                                    and quality and quality['successes'] == 0 and quality['failures'] >= 3)
                    choices = ([p for p in preferred if seen(p) and not weak_failed(p)] + choices[len(preferred):]
                               + [p for p in fallback if seen(p)]
                               + [p for p in preferred if weak_failed(p)])
                else:
                    choices += fallback
            else:
                choices += fallback
        return next((p for p in choices if now >= self.blocked.get(p['id'], 0)), None)
