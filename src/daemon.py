#!/usr/bin/env python3
"""RoadLink status service and isolated local AP controller."""
import logging
import sys
import os
import signal
import subprocess
from pathlib import Path

for directory in ('/opt/victronenergy/dbus-systemcalc-py/ext/velib_python',
                  '/opt/victronenergy/velib_python'):
    if (Path(directory) / 'vedbus.py').exists():
        sys.path.insert(0, directory)
        break

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
from vedbus import VeDbusService
from settingsdevice import SettingsDevice
from status import snapshot, role_text
from storage import load_json, write_json
from ap_config import hostapd
from secret_item import SecretItem
from ap_runtime import ROOT as AP_ROOT, SECRET as AP_SECRET, token, alive
from wifi import networks
from profile_api import install as install_profile_api


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    settings = SettingsDevice(bus, {
        'ap_enabled': ['/Settings/RoadLink/AP/Enabled', 0, 0, 1],
        'ap_ssid': ['/Settings/RoadLink/AP/SSID', 'breschdleng-roadlink', 0, 0],
    }, eventCallback=lambda *_: None)
    service = VeDbusService('com.coyodude.roadlink', bus=bus, register=False)
    for path, value in {
        '/Mgmt/ProcessName': __file__, '/Mgmt/ProcessVersion': '0.4',
        '/Mgmt/Connection': 'Local network controller', '/Connected': 1,
        '/Status': 'Nur Diagnose',
        '/Ethernet': '', '/WifiWan': '', '/VehicleAp': '', '/DefaultInterface': '',
        '/Security': 'Noch nicht aktiv', '/LastUpdate': 0,
        '/AP/Status': 'Aus', '/AP/Address': '',
        '/AP/PasswordStatus': 'Gesetzt' if AP_SECRET.exists() else 'Bitte festlegen',
        '/WifiWan/SSID': 'Nicht verbunden', '/WifiWan/State': 'Unbekannt',
        '/Wan/Active': '', '/Wan/Reason': 'Noch nicht aktiv',
        '/Wan/Health': 'Noch nicht geprueft',
        '/Wan/Acceleration': 'Keine Buendelung aktiv',
    }.items():
        service.add_path(path, value, writeable=False)

    def save_ap_password(path, password):
        try:
            hostapd('aproadlink', str(settings['ap_ssid']), password)
            write_json(AP_SECRET, {'password': password})
        except (ValueError, OSError):
            service['/AP/PasswordStatus'] = 'Fehler: 8-63 ASCII-Zeichen'
            return False
        service['/AP/PasswordStatus'] = 'Gespeichert'
        return True

    service.add_path('/AP/NewPassword', '', writeable=True,
                     onchangecallback=save_ap_password, itemtype=SecretItem)
    install_profile_api(service)
    service.register()
    worker = None
    signature = None
    failed = None

    def refresh():
        nonlocal worker, signature, failed
        try:
            state = snapshot()
            service['/Ethernet'] = role_text(state, 'ethernet')
            service['/WifiWan'] = role_text(state, 'wifi_wan')
            service['/VehicleAp'] = role_text(state, 'vehicle_ap')
            service['/DefaultInterface'] = state['default_interface'] or 'Keine'
            service['/LastUpdate'] = state['timestamp']
            service['/Wan/Active'] = ('Ethernet / Starlink' if any(d['interface'] == state['default_interface']
                and d['suggested_role'] == 'ethernet_candidate' for d in state['interfaces'])
                else state['default_interface'] or 'Keine Standardroute')
            radios = [d for d in state['interfaces'] if d['suggested_role'] == 'wifi_wan_candidate']
            if len(radios) == 1:
                wifi_available = True
                try:
                    wifi = networks(bus, radios[0]['interface'])
                except dbus.DBusException:
                    wifi = []
                    wifi_available = False
                current = next((n for n in wifi if n['state'] in ('ready', 'online')), None)
                service['/WifiWan/SSID'] = current['ssid'] if current else 'Nicht verbunden'
                service['/WifiWan/State'] = current['state'] if current else ('idle' if wifi_available else 'unavailable')
            else:
                service['/WifiWan/SSID'] = 'Nicht verfuegbar'
                service['/WifiWan/State'] = 'missing' if not radios else 'ambiguous'
            requested = (bool(settings['ap_enabled']), str(settings['ap_ssid']),
                         AP_SECRET.stat().st_mtime_ns if AP_SECRET.exists() else 0)
            if (Path('/data/setupOptions/RoadLink/SAFE_MODE').exists()):
                requested = (False, requested[1], requested[2])
            if requested != signature:
                failed = None
            if worker and worker.poll() is not None:
                if signature == requested and requested[0]:
                    failed = requested
                worker = None
            if worker and (not requested[0] or signature != requested):
                (AP_ROOT / 'stop').touch()
            elif not worker and not alive(load_json(AP_ROOT / 'guard.json', {})):
                signature = requested
                if requested[0] and failed != requested:
                    worker = subprocess.Popen([sys.executable, str(Path(__file__).with_name('ap_runtime.py')),
                                               'serve', requested[1], str(os.getpid()), token(os.getpid())])
            ap_state = load_json(AP_ROOT / 'status.json', {})
            service['/AP/Status'] = ('Fehler: Diagnose pruefen' if failed else
                ('Lokal, ohne Internet' if ap_state.get('state') == 'LAN_ONLY' else 'Startet') if worker
                else 'Aus')
            service['/AP/Address'] = ap_state.get('address', '') if worker else ''
            service['/Status'] = ('Lokales WLAN aktiv' if ap_state.get('state') == 'LAN_ONLY'
                                  else 'Fahrzeug-WLAN startet') if worker else 'Netzwerkdiagnose'
        except Exception:
            logging.exception('Status refresh failed')
        return True

    refresh()
    GLib.timeout_add_seconds(3, refresh)
    loop = GLib.MainLoop()
    signal.signal(signal.SIGTERM, lambda *_: loop.quit())
    try:
        loop.run()
    finally:
        if worker and worker.poll() is None:
            (AP_ROOT / 'stop').touch()
            try:
                worker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                worker.kill()  # independent guard performs cleanup


if __name__ == '__main__':
    main()
