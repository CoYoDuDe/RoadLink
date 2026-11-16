"""Decide when both radios may serve the vehicle WLAN (dual-band).

Dual-band uses every radio for the AP, so no radio is left for external
WLANs. It is therefore only active while the wired uplink (Ethernet/Starlink)
is proven healthy, with hysteresis: dual after 120 s healthy, back to a
single AP after 60 s unhealthy, which frees the second radio for WAN WLANs.
Unknown health (e.g. during a VPN restart) never flips the decision.
"""
import json
import subprocess
import time
from pathlib import Path

import ap_tuning

ENTER_SECONDS = 120
REENTER_SECONDS = 900  # after a fallback: avoid flapping (each switch drops the WLAN ~1 min)
LEAVE_SECONDS = 60
RADIO_CACHE_SECONDS = 30


def uplink_health(vpn_state, use_vpn, sysfs=Path('/sys/class/net')):
    """True/False when known, None when unknown."""
    if use_vpn:
        value = (vpn_state or {}).get('health', {}).get('ethernet', {}).get('healthy')
        return value if type(value) is bool else None
    try:
        return (sysfs / 'eth0' / 'carrier').read_text().strip() == '1'
    except OSError:
        return None


def radio_count(run=subprocess.run):
    """Wireless PHYs in the main and the WAN namespace (the WAN radio lives there)."""
    count = 0
    for prefix in ([], ['ip', 'netns', 'exec', 'roadlink-wan']):
        try:
            result = run(prefix + ['ls', '/sys/class/ieee80211'], capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            count += len([name for name in result.stdout.split() if name.startswith('phy')])
    return count


class Decision:
    def __init__(self, clock=time.monotonic, read=ap_tuning.read,
                 failed=lambda settings: ap_tuning.failed_before(settings, ignore_running=True),
                 radios=radio_count):
        self.clock, self.read, self.failed, self.radios = clock, read, failed, radios
        self.active = False
        self.ok_since = self.bad_since = None
        self.radio_cache = (None, -1e9)
        self.reason = ''
        self.fell_back = False

    def _radios(self):
        value, at = self.radio_cache
        if self.clock() - at > RADIO_CACHE_SECONDS:
            value = self.radios()
            self.radio_cache = (value, self.clock())
        return value

    def update(self, vpn_state, use_vpn):
        now = self.clock()
        health = uplink_health(vpn_state, use_vpn)
        if health is True:
            self.bad_since = None
            self.ok_since = self.ok_since or now
        elif health is False:
            self.ok_since = None
            self.bad_since = self.bad_since or now
        try:
            settings = self.read()
            wanted = settings['band'] == 'both'
            failed = wanted and self.failed(settings)
        except (ValueError, OSError):
            wanted, failed = False, False
        if not wanted:
            self.active, self.reason = False, 'single'
        elif failed:
            self.active, self.reason = False, 'failed'
        elif (self._radios() or 0) < 2:
            self.active, self.reason = False, 'one_radio'
        elif self.active and self.bad_since is not None and now - self.bad_since >= LEAVE_SECONDS:
            self.active, self.reason, self.fell_back = False, 'uplink_down', True
        elif (not self.active and self.ok_since is not None
              and now - self.ok_since >= (REENTER_SECONDS if self.fell_back else ENTER_SECONDS)):
            self.active, self.reason = True, 'dual'
        elif not self.active and self.reason != 'uplink_down':
            self.reason = 'waiting'
        return self.active

    def text(self):
        if self.active:
            return 'Beide Funkmodule (2,4 + 5 GHz)'
        return {'single': 'Ein Funkmodul',
                'failed': 'Ein Funkmodul (Dual-Start fehlgeschlagen)',
                'one_radio': 'Ein Funkmodul (zweites Funkmodul fehlt)',
                'uplink_down': 'Ein Funkmodul (Starlink/Ethernet gestoert, zweites fuer externe WLANs)',
                'waiting': 'Ein Funkmodul (wartet auf stabilen Starlink/Ethernet)',
                'dual': 'Ein Funkmodul'}.get(self.reason, 'Ein Funkmodul')
