"""Local connection history; never grants trust or changes manual priority."""
import math

MAX_AGE = 30 * 86400
FIELDS = {'successes', 'failures', 'latency_ms', 'checked_at'}


def history(value, now):
    if type(value) is not dict or set(value) != FIELDS:
        return None
    for field in ('successes', 'failures'):
        if type(value[field]) is not int or not 0 <= value[field] <= 100000:
            return None
    latency = value['latency_ms']
    checked = value['checked_at']
    if (latency is not None and (type(latency) is not int or not 0 <= latency <= 120000)
            or type(checked) not in (int, float) or not math.isfinite(checked)
            or type(now) not in (int, float) or not math.isfinite(now)
            or not 0 <= now - checked <= MAX_AGE):
        return None
    return dict(value)


def ranking(profile, now):
    value = history(profile.get('quality'), now)
    # Equal prior for unknown networks; one result cannot dominate history.
    reliability = ((value['successes'] + 2) / (value['successes'] + value['failures'] + 4)
                   if value else .5)
    latency = value['latency_ms'] if value else None
    return (-profile['priority'], -reliability,
            latency if latency is not None else 120001, profile['ssid'])


def update(previous, success, latency, now):
    if (type(success) is not bool or type(now) not in (int, float)
            or not math.isfinite(now) or now < 0
            or latency is not None and (type(latency) is not int or not 0 <= latency <= 120000)):
        raise ValueError('Invalid WLAN quality sample')
    value = history(previous, now) or dict(successes=0, failures=0, latency_ms=None, checked_at=now)
    field = 'successes' if success else 'failures'
    value[field] = min(100000, value[field] + 1)
    if success and latency is not None:
        value['latency_ms'] = (latency if value['latency_ms'] is None
                               else round((3 * value['latency_ms'] + latency) / 4))
    value['checked_at'] = now
    return value


def description(profile, now):
    value = history(profile.get('quality'), now)
    if not value:
        return 'Noch keine aktuelle Verbindungsprüfung'
    text = '{} erfolgreich, {} fehlgeschlagen'.format(value['successes'], value['failures'])
    if value['latency_ms'] is not None:
        text += '; HTTPS-Prüfung {} ms'.format(value['latency_ms'])
    return text


class Recorder:
    """At most one result per attempt/type; five minutes between disk writes.

Success requires thirty continuous seconds of independent Internet/DNS proof.
Callers must supply association-bound proof, not merely an IP or link state.
"""
    def __init__(self):
        self.attempt = None
        self.since = None
        self.recorded = set()
        self.writes = {}

    def consider(self, store, profile, attempt, proven, healthy, latency, failed, now, wall):
        identity = (profile['id'], attempt)
        if identity != self.attempt:
            self.attempt, self.since, self.recorded = identity, None, set()
        if proven and healthy:
            if self.since is None:
                self.since = now
        else:
            self.since = None
        result = False if failed else True if self.since is not None and now - self.since >= 30 else None
        if result is None or result in self.recorded:
            return False
        self.recorded.add(result)
        if now - self.writes.get(profile['id'], float('-inf')) < 300:
            return False
        try:
            saved = store.record_quality(profile, result, latency if result else None, wall)
        except (ValueError, OSError):
            return False  # Optional history must not interrupt a working WAN.
        if saved:
            self.writes.pop(profile['id'], None)
            self.writes[profile['id']] = now
            while len(self.writes) > 256:
                self.writes.pop(next(iter(self.writes)))
        return saved
