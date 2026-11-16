"""Quarantine a wedged USB radio instead of letting it stall every network change.

Observed 2026-11-16: mt76x2u repeatedly logged "MAC RX failed to stop"; each
`ip link set` on that radio blocked the kernel's network lock for seconds, so
AP, VPN and cleanup commands on other interfaces timed out and the vehicle
WLAN went down in a restart loop. A radio with repeated driver stop failures
is now excluded from role resolution until it is re-plugged (new USB device
number) or the Pi reboots (/run is volatile).
"""
import json
import re
import subprocess
import time
from pathlib import Path

QUARANTINE = Path('/run/roadlink-radio-quarantine.json')
PATTERN = re.compile(r'^\[\s*(\d+\.\d+)\]\s+mt76x2u (\d+-[\d.]+):1\.0: MAC RX failed to stop\s*$')
WINDOW = 120.0
THRESHOLD = 2
SCAN_INTERVAL = 20.0
USB = Path('/sys/bus/usb/devices')


def _devnum(port, usb=USB):
    try:
        return (usb / port / 'devnum').read_text().strip()
    except OSError:
        return None


def load(path=QUARANTINE):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def active(path=QUARANTINE, usb=USB):
    """Quarantined USB ports whose device was not re-plugged since."""
    result = {}
    for port, entry in load(path).items():
        if isinstance(entry, dict) and entry.get('devnum') == _devnum(port, usb) and entry.get('devnum'):
            result[port] = entry
    return result


def identity_port(identity):
    match = re.fullmatch(r'usb:[0-9a-f]{4}:[0-9a-f]{4}:(\d+-[\d.]+)', identity or '')
    return match.group(1) if match else None


def quarantined(identity, path=QUARANTINE, usb=USB):
    port = identity_port(identity)
    return bool(port and port in active(path, usb))


def failures(dmesg_text, now, window=WINDOW, after=None):
    """Per USB port, driver stop failures within the window ending at `now` (kernel seconds).

    `after` maps a port to the kernel time of its last quarantine: older messages
    belong to the previous (re-plugged) device and must not count again.
    """
    after = after or {}
    counts = {}
    for line in dmesg_text.splitlines():
        match = PATTERN.match(line.strip())
        if not match:
            continue
        stamp, port = float(match.group(1)), match.group(2)
        if now - stamp <= window and stamp > after.get(port, -1.0):
            counts[port] = counts.get(port, 0) + 1
    return counts


def uptime():
    return float(Path('/proc/uptime').read_text().split()[0])


class Monitor:
    def __init__(self, run=subprocess.run, path=QUARANTINE, usb=USB, clock=time.monotonic, now=uptime):
        self.run, self.path, self.usb, self.clock, self.now = run, Path(path), Path(usb), clock, now
        self.next = 0.0

    def scan(self):
        """Rate-limited; returns True when a new port was quarantined."""
        if self.clock() < self.next:
            return False
        self.next = self.clock() + SCAN_INTERVAL
        try:
            text = self.run(['dmesg'], capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return False
        current = load(self.path)
        added = False
        now = self.now()
        after = {port: entry.get('kernel_at', -1.0) for port, entry in current.items() if isinstance(entry, dict)}
        for port, count in failures(text, now, after=after).items():
            devnum = _devnum(port, self.usb)
            if count >= THRESHOLD and devnum and current.get(port, {}).get('devnum') != devnum:
                current[port] = {'devnum': devnum, 'reason': 'MAC RX failed to stop', 'count': count,
                                 'at': time.time(), 'kernel_at': now}
                added = True
        if added:
            tmp = self.path.with_name(self.path.name + '.new')
            tmp.write_text(json.dumps(current, sort_keys=True))
            tmp.replace(self.path)
        return added

    def generation(self):
        return tuple(sorted(active(self.path, self.usb)))

    def text(self):
        ports = active(self.path, self.usb)
        if not ports:
            return 'Funkmodule in Ordnung'
        return 'USB-WLAN blockiert (Treiberfehler) - bitte abziehen und neu einstecken'
