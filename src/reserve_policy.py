"""Last-resort WLANs wait while the effective Ethernet path is healthy."""
import math
from policy import MODES


class Gate:
    def __init__(self, started, grace=15):
        self.started, self.grace = started, grace

    def allow(self, mode, status, live, now):
        if mode not in MODES or mode == 'STARLINK_ONLY':
            return False
        if mode == 'WIFI_ONLY':
            return True
        checked = status.get('checked_at')
        fresh = (type(checked) in (int, float) and math.isfinite(checked)
                 and 0 <= now - checked <= 30)
        if live and fresh:
            if status.get('penalties', {}).get('ethernet') is True:
                return True
            healthy = status.get('health', {}).get('ethernet', {}).get('healthy')
            if type(healthy) is bool:
                return not healthy
        # Allow bootstrap if no path controller can establish fresh evidence.
        # The grace period prevents association before its first Ethernet probe.
        return now - self.started >= self.grace
