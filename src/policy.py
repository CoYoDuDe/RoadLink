"""Deterministic WAN policy. Network mutations belong to a separate backend."""
from dataclasses import dataclass

MODES = {'AUTO', 'PREFER_STARLINK', 'PREFER_WIFI', 'BEST_CONNECTION', 'STARLINK_ONLY', 'WIFI_ONLY'}
STATES = {'DISCONNECTED', 'LINK_ONLY', 'CONNECTING', 'CAPTIVE_PORTAL', 'DEGRADED', 'ONLINE', 'FAILED'}


@dataclass(frozen=True)
class Link:
    state: str
    score: int = 0
    trusted: bool = False
    vpn_ready: bool = False

    def usable(self, kind):
        if self.state not in STATES or not 0 <= self.score <= 100:
            raise ValueError('Invalid link health')
        return self.state in ('ONLINE', 'DEGRADED') and (kind != 'wifi' or self.trusted or self.vpn_ready)


class Selector:
    def __init__(self, failures=3, recoveries=3, cooldown=30, failback=60, margin=15):
        if failures < 1 or recoveries < 1 or min(cooldown, failback, margin) < 0:
            raise ValueError('Invalid hysteresis settings')
        self.failures, self.recoveries = failures, recoveries
        self.cooldown, self.failback, self.margin = cooldown, failback, margin
        self.active = None
        self.last_switch = float('-inf')
        self.good = {'ethernet': 0, 'wifi': 0}
        self.bad = {'ethernet': 0, 'wifi': 0}
        self.good_since = {'ethernet': None, 'wifi': None}

    def choose(self, mode, ethernet, wifi, now):
        if mode not in MODES:
            raise ValueError('Unknown WAN mode')
        links = {'ethernet': ethernet, 'wifi': wifi}
        allowed = {'ethernet', 'wifi'}
        if mode == 'STARLINK_ONLY': allowed = {'ethernet'}
        if mode == 'WIFI_ONLY': allowed = {'wifi'}
        usable = {key: key in allowed and link.usable(key) for key, link in links.items()}
        for key, healthy in usable.items():
            if healthy:
                self.good[key] += 1
                self.bad[key] = 0
                if self.good_since[key] is None: self.good_since[key] = now
            else:
                self.bad[key] += 1
                self.good[key] = 0
                self.good_since[key] = None
        # Revoked trust or lost VPN is never subject to a failover grace period.
        if self.active == 'wifi' and not (wifi.trusted or wifi.vpn_ready):
            self.active = None
        if self.active not in allowed:
            self.active = None
        candidates = [key for key in allowed if usable[key] and self.good[key] >= self.recoveries]
        preferred = 'wifi' if mode in ('PREFER_WIFI', 'WIFI_ONLY') else 'ethernet'
        if mode == 'BEST_CONNECTION' and candidates:
            preferred = max(sorted(candidates), key=lambda key: links[key].score)
        candidate = preferred if preferred in candidates else next(iter(sorted(candidates)), None)
        active_failed = self.active is not None and self.bad[self.active] >= self.failures
        if active_failed:
            self.active = None
        if self.active is None:
            if candidate:
                self.active, self.last_switch = candidate, now
            return self.active
        if not candidate or candidate == self.active or not usable[self.active]:
            return self.active
        if now - self.last_switch < self.cooldown or now - self.good_since[candidate] < self.failback:
            return self.active
        if mode == 'BEST_CONNECTION' and links[candidate].score < links[self.active].score + self.margin:
            return self.active
        self.active, self.last_switch = candidate, now
        return self.active
