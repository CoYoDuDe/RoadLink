"""Connection-bound portal evidence and a finite manual-login waiting window."""
import hashlib
import json
import math

CAPTIVE = ('CAPTIVE', 'LEGACY_CAPTIVE', 'POSSIBLE_CAPTIVE')


def combine(metadata, legacy):
    result = dict(legacy or {'state': 'INCONCLUSIVE'})
    result['signals'] = {'api_captive': metadata.get('captive') if metadata else None,
                         'http': (legacy or {}).get('state', 'UNAVAILABLE')}
    if metadata is not None:
        result['metadata'] = metadata
        if metadata['captive']:
            result['state'] = 'CAPTIVE'
            if metadata.get('user_portal_url'): result['url'] = metadata['user_portal_url']
        elif result['state'] in CAPTIVE:
            result['state'] = 'POSSIBLE_CAPTIVE'  # Contradiction requires manual inspection.
        else:
            result['state'] = 'UNRESTRICTED_HINT'
    return result


def hint_hash(hints):
    return hashlib.sha256(json.dumps(hints, sort_keys=True).encode()).hexdigest()


def current(result, binding, lease, hints, now):
    if not isinstance(result, dict) or not binding: return None
    stamp = result.get('checked_at')
    if (type(stamp) not in (int, float) or not math.isfinite(stamp) or not 0 <= now-stamp <= 65
            or result.get('connection') != binding
            or result.get('lease') != {key: lease.get(key, '') for key in ('address', 'gateway')}
            or result.get('hint_hash') != hint_hash(hints)):
        return None
    return result


class Wait:
    def __init__(self):
        self.binding = None
        self.started = None

    def allow(self, binding, result, now, proven=False):
        if binding != self.binding:
            self.binding, self.started = binding, None
        if proven or not binding:
            self.started = None
            return False
        if not result or result.get('state') not in CAPTIVE: return False
        if self.started is None: self.started = now
        # Repeated portal responses must not reset a never-ending captive wait.
        return 0 <= now-self.started < 900
