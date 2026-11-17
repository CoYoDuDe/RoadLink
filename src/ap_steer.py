"""Band steering for the dual-band vehicle WLAN (same SSID on aprl24 and aprl5).

Venus OS hostapd is built without WNM, so a polite BSS-transition request is
not available. This uses the classic legacy method instead: a client that is
on 2.4 GHz, reports 5 GHz operating classes, has a strong signal and is idle
(or has just joined) is denied on 2.4 GHz only and disconnected there; with
the same SSID it rejoins on 5 GHz within seconds.

Safety:
- At most one client is steered at a time.
- If it does not appear on 5 GHz within GRACE seconds, the 2.4 GHz deny is
  lifted and the client is left alone for BACKOFF.
- A client that falls back to 2.4 GHz on its own soon after a steer is also
  left alone for BACKOFF (5 GHz is evidently too weak where it is).
- Owner-blocked clients are never touched, and their deny is never removed.
- Pending denies are persisted and lifted after a daemon restart.
- /data/setupOptions/RoadLink/NO_BAND_STEERING disables it.
"""
import json
import logging
import os
from pathlib import Path

STATE = Path('/run/roadlink-ap/steer.json')
DISABLE = Path('/data/setupOptions/RoadLink/NO_BAND_STEERING')
LOW, HIGH = 'aprl24', 'aprl5'
MIN_SIGNAL = -62          # dBm on 2.4 GHz; the 5 GHz cell is smaller
JOIN_WINDOW = 20          # s: a fresh 2.4 GHz join is steered at once
IDLE_SECONDS = 30         # s of low traffic before an established client is steered
IDLE_BYTES_PER_SECOND = 32000  # ~250 kbit/s both directions together
GRACE = 20                # s to appear on 5 GHz before the deny is lifted
BACKOFF = 6 * 3600        # s to leave a client alone after a failed/undone steer
FALLBACK_WINDOW = 1800    # s: back on 2.4 GHz within this after success = undone


def five_ghz_capable(station):
    """True if Supported Operating Classes list a 5 GHz class (115-127)."""
    raw = station.get('supp_op_classes', '')
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        return False
    classes = []
    for value in data[1:]:  # first octet is the current class
        if value in (0, 130):  # zero / current-class-extension delimiters
            break
        classes.append(value)
    return any(115 <= value <= 127 for value in classes)


def _int(station, key):
    value = station.get(key, '')
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class Steerer:
    def __init__(self, run, clock, state=STATE, disable=DISABLE):
        """run(interface, args) -> stdout text; clock() -> monotonic seconds."""
        self.run, self.clock = run, clock
        self.state, self.disable = Path(state), Path(disable)
        self.pending = None      # {'mac', 'since'}
        self.backoff = {}        # mac -> until
        self.steered = {}        # mac -> time of successful steer
        self.traffic = {}        # mac -> (time, bytes, idle_since)
        self._recover()

    # persistence -------------------------------------------------------
    def _save(self):
        try:
            tmp = self.state.with_name(self.state.name + '.new')
            tmp.write_text(json.dumps({'pending': self.pending['mac'] if self.pending else ''}))
            os.replace(str(tmp), str(self.state))
        except OSError:
            pass

    def _recover(self):
        try:
            mac = json.loads(self.state.read_text()).get('pending', '')
        except (OSError, ValueError, AttributeError):
            return
        if isinstance(mac, str) and mac:
            self.pending = {'mac': mac, 'since': self.clock() - GRACE}  # lifted on next tick

    # main --------------------------------------------------------------
    def tick(self, interfaces, low, high, blocked):
        """low/high: parsed all_sta dicts of aprl24/aprl5; blocked: owner block list."""
        now = self.clock()
        if self.pending:
            mac = self.pending['mac']
            if mac in high:
                self._release(mac, blocked)
                self.steered[mac] = now
                logging.info('Band steering: %s now on 5 GHz', mac)
            elif now - self.pending['since'] >= GRACE:
                self._release(mac, blocked)
                self.backoff[mac] = now + BACKOFF
                logging.info('Band steering: %s did not join 5 GHz; left on 2.4 GHz', mac)
            return
        if self.disable.exists() or LOW not in interfaces or HIGH not in interfaces:
            self.traffic.clear()
            return
        for mac in list(self.steered):
            if mac in low and now - self.steered[mac] <= FALLBACK_WINDOW:
                self.backoff[mac] = now + BACKOFF
                del self.steered[mac]
                logging.info('Band steering: %s returned to 2.4 GHz; not steered for now', mac)
            elif now - self.steered[mac] > FALLBACK_WINDOW:
                del self.steered[mac]
        for mac, station in sorted(low.items()):
            if self._eligible(mac, station, now, blocked):
                self._steer(mac, now)
                return
        for mac in list(self.traffic):
            if mac not in low:
                del self.traffic[mac]

    def _eligible(self, mac, station, now, blocked):
        total = (_int(station, 'rx_bytes') or 0) + (_int(station, 'tx_bytes') or 0)
        last = self.traffic.get(mac)
        idle_since = None
        if last is not None and now > last[0]:
            rate = (total - last[1]) / (now - last[0])
            idle_since = (last[2] or last[0]) if 0 <= rate < IDLE_BYTES_PER_SECOND else None
        self.traffic[mac] = (now, total, idle_since)
        signal = _int(station, 'signal')
        connected = _int(station, 'connected_time')
        if (mac in blocked or now < self.backoff.get(mac, 0) or mac in self.steered
                or signal is None or signal < MIN_SIGNAL or not five_ghz_capable(station)
                or connected is None):
            return False
        return connected <= JOIN_WINDOW or (idle_since is not None and now - idle_since >= IDLE_SECONDS)

    def _steer(self, mac, now):
        self.pending = {'mac': mac, 'since': now}
        self._save()
        self.run(LOW, ['deny_acl', 'ADD_MAC', mac])
        self.run(LOW, ['deauthenticate', mac])
        self.traffic.pop(mac, None)
        logging.info('Band steering: moving %s from 2.4 GHz to 5 GHz', mac)

    def _release(self, mac, blocked):
        if mac not in blocked:
            self.run(LOW, ['deny_acl', 'DEL_MAC', mac])
        self.pending = None
        self._save()
