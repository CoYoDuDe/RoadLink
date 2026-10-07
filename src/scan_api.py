"""Native passive-scan requests and sanitized metadata; no shell in the GUI."""
import json
import secrets
import time
from pathlib import Path
from gi.repository import GLib
from storage import load_json, write_json
from ap_runtime import alive
from secret_item import SecretItem

ROOT = Path('/run/roadlink-wan')


def results():
    scan = load_json(ROOT / 'scan.json', {})
    if (scan.get('request') != load_json(ROOT / 'scan-request.json', {}).get('request')
            or not alive(load_json(ROOT / 'guard.json', {}))): return []
    if scan.get('state') != 'COMPLETE' or not 0 <= time.time() - scan.get('timestamp', 0) <= 180: return []
    return scan.get('networks', [])


def install(service):
    service.add_path('/Wifi/Scan/Results', '[]')
    service.add_path('/Wifi/Scan/Status', 'USB-WLAN-Reserve aktivieren')
    service.add_path('/Wifi/Scan/Time', 0)
    service.add_path('/Wifi/Scan/Count', 0)
    pending = ['', 0, None]
    def request(path, value):
        if value != 'scan': return False
        guard_info = load_json(ROOT / 'guard.json', {})
        if (not alive(guard_info) or not ROOT.exists()
                or (ROOT / 'stop').exists() or (ROOT / 'cleaning').exists()):
            service['/Wifi/Scan/Status'] = 'USB-WLAN-Reserve zuerst aktivieren'; return False
        if pending[0] and time.monotonic() - pending[1] < 140:
            scan = load_json(ROOT / 'scan.json', {})
            if scan.get('request') != pending[0] or scan.get('state') not in ('COMPLETE', 'FAILED'):
                return False
        pending[:] = [secrets.token_hex(12), time.monotonic(), guard_info]
        write_json(ROOT / 'scan-request.json', {'request': pending[0]})
        service['/Wifi/Scan/Results'] = '[]'
        service['/Wifi/Scan/Status'] = 'Suche angefordert'
        return True
    service.add_path('/Wifi/Scan/Request', '', writeable=True, itemtype=SecretItem, onchangecallback=request)
    def refresh():
        guard_info = load_json(ROOT / 'guard.json', {})
        guard = alive(guard_info)
        if pending[0] and (not guard or guard_info != pending[2]): pending[:] = ['', 0, None]
        scan = load_json(ROOT / 'scan.json', {}) if guard else {}
        service['/Wifi/Scan/Results'] = json.dumps(results() if guard else [], ensure_ascii=False)
        service['/Wifi/Scan/Count'] = len(results()) if guard else 0
        service['/Wifi/Scan/Time'] = int(scan.get('timestamp', 0))
        service['/Wifi/Scan/Status'] = {'WAITING': 'Wartet auf freien Funk', 'SCANNING': 'Passive Suche laeuft',
             'COMPLETE': 'Suche abgeschlossen', 'FAILED': 'Suche fehlgeschlagen; erneut versuchen'}.get(
             scan.get('state'), 'Bereit zur Suche' if guard else 'USB-WLAN-Reserve aktivieren')
        if guard and pending[0] and scan.get('request') != pending[0]:
            service['/Wifi/Scan/Status'] = 'Suche angefordert'
        if scan.get('state') == 'COMPLETE' and time.time() - scan.get('timestamp', 0) > 180:
            service['/Wifi/Scan/Status'] = 'Ergebnisse abgelaufen; erneut suchen'
        if pending[0] and time.monotonic() - pending[1] >= 140 and scan.get('state') not in ('COMPLETE', 'FAILED'):
            service['/Wifi/Scan/Status'] = 'Suche abgebrochen; erneut versuchen'
        return True
    GLib.timeout_add_seconds(1, refresh)
