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
from scan_api import install as install_scan_api
from vpn_config import read as vpn_config
from vpn_runtime import ROOT as VPN_ROOT
from wan_runtime import ROOT as WAN_ROOT
from wan_config import client_name


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    settings = SettingsDevice(bus, {
        'ap_enabled': ['/Settings/RoadLink/AP/Enabled', 0, 0, 1],
        'ap_ssid': ['/Settings/RoadLink/AP/SSID', 'RoadLink', 0, 0],
        'wan_enabled': ['/Settings/RoadLink/WifiWan/Enabled', 0, 0, 1],
        'client_name': ['/Settings/RoadLink/WifiWan/ClientName', '', 0, 0],
        'auto_open': ['/Settings/RoadLink/WifiWan/AutoOpen', 0, 0, 1],
        'wan_mode': ['/Settings/RoadLink/Wan/Mode', 'AUTO', 0, 0],
    }, eventCallback=lambda *_: None)
    service = VeDbusService('com.coyodude.roadlink', bus=bus, register=False)
    for path, value in {
        '/Mgmt/ProcessName': __file__, '/Mgmt/ProcessVersion': '0.16',
        '/Mgmt/Connection': 'Local network controller', '/Connected': 1,
        '/Status': 'Nur Diagnose',
        '/Ethernet': '', '/WifiWan': '', '/VehicleAp': '', '/DefaultInterface': '',
        '/Security': 'Noch nicht aktiv', '/LastUpdate': 0,
        '/AP/Status': 'Aus', '/AP/Address': '',
        '/AP/PasswordStatus': 'Gesetzt' if AP_SECRET.exists() else 'Bitte festlegen',
        '/WifiWan/SSID': 'Nicht verbunden', '/WifiWan/State': 'Unbekannt',
        '/WifiWan/StateText': 'Nicht verbunden',
        '/WifiWan/ClientNameStatus': ('Gesetzt'
                                    if settings['client_name'] else 'Leer: kein DHCP-Name'),
        '/Wan/Active': '', '/Wan/Reason': 'Noch nicht aktiv',
        '/Wan/Health': 'Noch nicht geprueft',
        '/Wan/Acceleration': 'Keine Buendelung aktiv',
        '/VPN/Status': 'Aus', '/VPN/DNS': 'Nicht geprueft',
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

    def save_client_name(path, value):
        try:
            settings['client_name'] = client_name(value)
        except (ValueError, TypeError, dbus.DBusException):
            service['/WifiWan/ClientNameStatus'] = 'Fehler: Name ungueltig'
            return False
        service['/WifiWan/ClientNameStatus'] = 'Gespeichert'
        return True

    service.add_path('/WifiWan/ClientName', str(settings['client_name']), writeable=True,
                     onchangecallback=save_client_name)
    install_profile_api(service)
    install_scan_api(service)
    service.register()
    worker = None
    signature = None
    failed = None
    vpn_worker = None
    vpn_signature = None
    vpn_retry_at = 0
    ap_retry_at = 0
    wan_worker = None
    wan_signature = None
    wan_retry_at = 0

    def refresh():
        nonlocal worker, signature, failed, vpn_worker, vpn_signature, vpn_retry_at, ap_retry_at
        nonlocal wan_worker, wan_signature, wan_retry_at
        try:
            import time
            vpn_invalid = False
            try:
                configuration = vpn_config()
            except (ValueError, KeyError, OSError):
                configuration, vpn_invalid = None, True
            vpn_requested = bool(configuration and configuration['enabled']
                and not Path('/data/setupOptions/RoadLink/SAFE_MODE').exists())
            vpn_current = repr(configuration) if vpn_requested else None
            profiles_path = Path('/data/setupOptions/RoadLink/wifi-profiles.json')
            wan_requested = bool(settings['wan_enabled'])
            hostname = client_name(str(settings['client_name']))
            service['/WifiWan/ClientName'] = hostname
            wan_current = (repr(configuration), profiles_path.stat().st_mtime_ns
                           if profiles_path.exists() else 0, hostname, bool(settings['auto_open'])) if wan_requested else None
            if wan_worker and wan_worker.poll() is not None:
                wan_worker = None
                wan_retry_at = time.monotonic() + 15
            if wan_worker and wan_current != wan_signature:
                (WAN_ROOT / 'stop').touch()
            elif (not wan_worker and wan_requested and time.monotonic() >= wan_retry_at
                  and not alive(load_json(WAN_ROOT / 'guard.json', {}))):
                if load_json(WAN_ROOT / 'result.json', {'cleaned': True}).get('cleaned'):
                    wan_signature = wan_current
                    wan_worker = subprocess.Popen([sys.executable,
                        str(Path(__file__).with_name('wan_runtime.py')), 'serve',
                        str(os.getpid()), token(os.getpid()), hostname, str(int(settings['auto_open']))])
            if vpn_worker and vpn_worker.poll() is not None:
                vpn_worker = None
                vpn_retry_at = time.monotonic() + 15
            if vpn_worker and vpn_current != vpn_signature:
                (VPN_ROOT / 'stop').touch()
            elif (not vpn_worker and vpn_requested and time.monotonic() >= vpn_retry_at
                  and not alive(load_json(VPN_ROOT / 'guard.json', {}))):
                result = load_json(VPN_ROOT / 'result.json', {'cleaned': True})
                if result.get('cleaned'):
                    vpn_signature = vpn_current
                    vpn_worker = subprocess.Popen([sys.executable,
                        str(Path(__file__).with_name('vpn_runtime.py')), 'serve',
                        str(os.getpid()), token(os.getpid())])
            vpn_state = load_json(VPN_ROOT / 'status.json', {})
            service['/VPN/Status'] = ('Konfiguration ungueltig' if vpn_invalid else
                'Tunnel und DNS bereit' if vpn_worker and vpn_state.get('state') == 'READY'
                else 'Verbindet' if vpn_worker else 'Fehler: Bereinigung pruefen'
                if vpn_state.get('state') == 'CLEANUP_FAILED' else 'Wartet' if vpn_requested else 'Aus')
            service['/VPN/DNS'] = 'DNSmith erreichbar' if vpn_worker and vpn_state.get('dns_ready') else 'Nicht bereit'
            service['/Security'] = 'AP nur lokal'
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
            wan_state = load_json(WAN_ROOT / 'status.json', {})
            if wan_worker and alive(load_json(WAN_ROOT / 'guard.json', {})):
                service['/WifiWan'] = 'Isolierter USB-Stick (' + wan_state.get('driver', 'startet') + ')'
                service['/WifiWan/SSID'] = wan_state.get('ssid') or ('Suchmodus, nicht verbunden'
                    if wan_state.get('state') == 'SCAN_ONLY' else 'Verbindet WLAN')
                service['/WifiWan/State'] = wan_state.get('state', 'STARTING')
                service['/Wan/Reason'] = ('WLAN als Reserve verbunden; VPN noch ueber Ethernet'
                    if wan_state.get('state') == 'LEASED' else 'WLANs werden gesucht oder geprueft')
            else:
                service['/Wan/Reason'] = ('WLAN-Bereinigung fehlgeschlagen' if wan_state.get('state') == 'CLEANUP_FAILED'
                    else 'WLAN-Reserve startet' if wan_requested else 'WLAN-Reserve ausgeschaltet')
            service['/WifiWan/StateText'] = {
                'LEASED': 'Verbunden', 'ASSOCIATED': 'Wartet auf IP-Adresse',
                'CONNECTING': 'Verbindet', 'STARTING': 'Startet', 'OFF': 'Aus',
                'SCAN_ONLY': 'Nur WLAN-Suche',
                'CLEANUP_FAILED': 'Bereinigung fehlgeschlagen', 'missing': 'Nicht erkannt',
                'ambiguous': 'Mehrere Funkmodule', 'idle': 'Nicht verbunden',
                'online': 'Verbunden', 'ready': 'Verbunden', 'unavailable': 'Nicht verfuegbar',
            }.get(str(service['/WifiWan/State']), 'Nicht verbunden')
            if 'wan' in vpn_state:
                active = vpn_state['wan']
                service['/Wan/Active'] = {'ethernet': 'Ethernet / Starlink', 'wifi': 'USB-WLAN'}.get(active, 'Kein geeigneter WAN-Pfad')
                service['/Wan/Reason'] = ('Ethernet-Tunnel nicht erreichbar, WLAN aktiv'
                    if active == 'wifi' and vpn_state.get('penalties', {}).get('ethernet') else
                    'Ethernet nicht erreichbar, WLAN aktiv' if active == 'wifi' and not vpn_state.get('health', {}).get('ethernet', {}).get('healthy') else
                    'VPN ueber bekanntes WLAN' if active == 'wifi' else 'VPN ueber Ethernet / Starlink'
                    if active == 'ethernet' else 'Wartet auf geeignete Verbindung')
                service['/Wan/Health'] = 'VPN-Internet und DNS geprueft' if vpn_state.get('internet') else 'VPN-Internet nicht bereit'
            requested = (bool(settings['ap_enabled']), str(settings['ap_ssid']),
                         AP_SECRET.stat().st_mtime_ns if AP_SECRET.exists() else 0,
                         repr(configuration))
            if (Path('/data/setupOptions/RoadLink/SAFE_MODE').exists()):
                requested = (False, *requested[1:])
            if requested != signature:
                failed = None
                ap_retry_at = 0
            if worker and worker.poll() is not None:
                if signature == requested and requested[0]:
                    failed = requested
                worker = None
                ap_retry_at = time.monotonic() + 15
            if worker and (not requested[0] or signature != requested):
                (AP_ROOT / 'stop').touch()
            elif not worker and not alive(load_json(AP_ROOT / 'guard.json', {})):
                signature = requested
                if requested[0] and time.monotonic() >= ap_retry_at:
                    failed = None
                    worker = subprocess.Popen([sys.executable, str(Path(__file__).with_name('ap_runtime.py')),
                                               'serve', requested[1], str(os.getpid()), token(os.getpid())])
            ap_state = load_json(AP_ROOT / 'status.json', {})
            internet = bool(worker and ap_state.get('internet')
                            and vpn_worker and vpn_state.get('state') == 'READY')
            service['/Security'] = 'AP ueber VPN, DNSmith' if internet else 'AP nur lokal'
            service['/AP/Status'] = ('Fehler: Diagnose pruefen' if failed else
                ('Internet ueber VPN' if internet else 'Lokal, ohne Internet'
                 if ap_state.get('state') in ('LAN_ONLY', 'VPN_INTERNET') else 'Startet') if worker
                else 'Aus')
            service['/AP/Address'] = ap_state.get('address', '') if worker else ''
            service['/Status'] = ('WLAN-Internet ueber VPN' if internet else
                                  'Lokales WLAN aktiv' if ap_state.get('state') in ('LAN_ONLY', 'VPN_INTERNET')
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
        if wan_worker and wan_worker.poll() is None:
            (WAN_ROOT / 'stop').touch()
            try:
                wan_worker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                wan_worker.kill()
        if vpn_worker and vpn_worker.poll() is None:
            (VPN_ROOT / 'stop').touch()
            try:
                vpn_worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                vpn_worker.kill()
        if worker and worker.poll() is None:
            (AP_ROOT / 'stop').touch()
            try:
                worker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                worker.kill()  # independent guard performs cleanup


if __name__ == '__main__':
    main()
