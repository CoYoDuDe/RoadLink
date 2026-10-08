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
from enrollment_runtime import ROOT as ENROLLMENT_ROOT
from vpn_config import configured as vpn_configured, enrollment_allowed
from vpn_providers import selected as vpn_provider
from vpn_provider_api import install as install_provider_api
from dns_config import read as dns_settings, routed as routed_dns, ready as dns_ready
from dns_api import install as install_dns_api
from enrollment_scheduler import EnrollmentSchedule
from transport_config import read as transport_settings, direct_dns
from transport_barrier import Barrier
from transport_runtime import clear as transport_clear
from transport_api import install as install_transport_api
from direct_status import ROOT as DIRECT_ROOT, current as direct_current
from ap_runtime import command
import radio_roles
from radio_api import install as install_radio_api
from runtime_lock import busy as runtime_locked
import ipaddress
import firewall_config


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    settings = SettingsDevice(bus, {
        'ap_enabled': ['/Settings/RoadLink/AP/Enabled', 0, 0, 1],
        'ap_ssid': ['/Settings/RoadLink/AP/SSID', 'RoadLink', 0, 0],
        'starlink_local': ['/Settings/RoadLink/Starlink/LocalAccess', 0, 0, 1],
        'wan_enabled': ['/Settings/RoadLink/WifiWan/Enabled', 0, 0, 1],
        'client_name': ['/Settings/RoadLink/WifiWan/ClientName', '', 0, 0],
        'auto_open': ['/Settings/RoadLink/WifiWan/AutoOpen', 0, 0, 1],
        'wan_mode': ['/Settings/RoadLink/Wan/Mode', 'AUTO', 0, 0],
        'auto_enroll': ['/Settings/RoadLink/VPN/AutoEnroll', 1, 0, 1],
    }, eventCallback=lambda *_: None)
    service = VeDbusService('com.coyodude.roadlink', bus=bus, register=False)
    for path, value in {
        '/Mgmt/ProcessName': __file__, '/Mgmt/ProcessVersion': '0.22',
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
        '/VPN/Enrollment': 'Noch nicht geprueft',
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
    install_provider_api(service)
    install_dns_api(service)
    install_transport_api(service)
    install_radio_api(service)
    from firewall_api import API as FirewallAPI
    firewall_api = FirewallAPI(service, itemtype=SecretItem)
    from portal_manager import Manager as PortalManager
    portal_manager=PortalManager(service,{'pid':os.getpid(),'start':token(os.getpid())},alive,SecretItem)
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
    enrollment_worker = None
    enrollment_schedule = EnrollmentSchedule()
    direct_worker = None
    direct_signature = None
    direct_retry_at = 0
    import portal_session_runtime
    roots = {'ap': AP_ROOT, 'vpn': VPN_ROOT, 'wan': WAN_ROOT, 'direct': DIRECT_ROOT,
             'portal': portal_session_runtime.ROOT}

    def stop_transport(name):
        root = roots[name]
        if root.is_symlink():
            raise ValueError('Unsafe transport runtime directory')
        if root.exists():
            (root / 'stop').touch()

    def transport_busy(name):
        if name=='portal': return portal_manager.busy()
        processes = {'ap': worker, 'vpn': vpn_worker, 'wan': wan_worker, 'direct': direct_worker}
        process = processes[name]
        root = roots[name]
        if process and process.poll() is None:
            return True
        if runtime_locked(root):
            return True
        if not root.exists():
            return False
        if any(alive(load_json(root / (item + '.json'), {})) for item in ('controller', 'guard')):
            return True
        return load_json(root / 'result.json', {}).get('cleaned') is not True

    barrier = Barrier(stop_transport, transport_busy, lambda: transport_clear(command))

    def refresh():
        nonlocal worker, signature, failed, vpn_worker, vpn_signature, vpn_retry_at, ap_retry_at
        nonlocal wan_worker, wan_signature, wan_retry_at
        nonlocal enrollment_worker
        nonlocal direct_worker, direct_signature, direct_retry_at
        try:
            import time
            firewall_api.update()
            safe_mode = Path('/data/setupOptions/RoadLink/SAFE_MODE').exists()
            try:
                role_config = radio_roles.read()
                radio_key = radio_roles.generation(role_config)
                # Policy edits use the same fully drained transport handover.
                # A malformed private policy selects off; never default allow.
                firewall = firewall_config.read()
                radio_key = (radio_key, firewall_config.generation(firewall))
                use_vpn = transport_settings()['vpn_required']
                wanted = 'off' if safe_mode else 'vpn' if use_vpn else 'direct'
            except (ValueError, OSError):
                use_vpn, wanted = True, 'off'
                role_config, radio_key = dict(radio_roles.DEFAULT), None
            switching = (barrier.phase is not None or barrier.current != wanted
                         or barrier.current_key != radio_key)
            if switching:
                portal_manager.update(False)
                if ENROLLMENT_ROOT.exists() and not ENROLLMENT_ROOT.is_symlink():
                    write_json(ENROLLMENT_ROOT / 'request.json', {'pid': os.getpid(),
                        'start': token(os.getpid()), 'enabled': False})
                if enrollment_worker and enrollment_worker.poll() is None:
                    enrollment_worker.terminate()
                    service['/Transport/Status'] = 'Wartet auf VPN-Einrichtung'
                    return True
            if not barrier.step(wanted, radio_key):
                service['/Transport/Status'] = 'Bereinigt bisherigen Modus'
                service['/Security'] = 'Moduswechsel; bisheriger Modus stoppt'
                service['/AP/Status'] = 'Moduswechsel'
                service['/DNS/Active'] = 'Nicht bereit'
                return True
            if switching:
                worker = vpn_worker = wan_worker = direct_worker = None
                signature = vpn_signature = wan_signature = direct_signature = None
                vpn_retry_at = wan_retry_at = ap_retry_at = direct_retry_at = 0
                failed = None
            service['/Transport/Status'] = {'vpn': 'VPN erforderlich',
                'direct': 'Direkt, ohne VPN', 'off': 'Angehalten; Einstellungen pruefen'}[wanted]
            vpn_invalid = False
            try:
                configuration = vpn_config() if use_vpn else None
            except (ValueError, KeyError, OSError):
                configuration, vpn_invalid = None, True
            vpn_requested = bool(wanted == 'vpn' and configuration and configuration['enabled']
                and not Path('/data/setupOptions/RoadLink/SAFE_MODE').exists())
            vpn_current = repr(configuration) if vpn_requested else None
            profiles_path = Path('/data/setupOptions/RoadLink/wifi-profiles.json')
            wan_requested = bool(settings['wan_enabled'] and wanted != 'off')
            hostname = client_name(str(settings['client_name']))
            service['/WifiWan/ClientName'] = hostname
            wan_current = (repr(configuration) if use_vpn else repr(direct_dns(dns_settings())),
                           use_vpn, profiles_path.stat().st_mtime_ns
                           if profiles_path.exists() else 0, hostname, bool(settings['auto_open']),
                           use_vpn and bool(settings['auto_enroll']) and enrollment_allowed()) if wan_requested else None
            if wan_worker and wan_worker.poll() is not None:
                wan_worker = None
                wan_retry_at = time.monotonic() + 15
            if wan_worker and wan_current != wan_signature:
                (WAN_ROOT / 'stop').touch()
            elif (not wan_worker and wan_requested and time.monotonic() >= wan_retry_at
                  and not runtime_locked(WAN_ROOT)
                  and not alive(load_json(WAN_ROOT / 'guard.json', {}))):
                if load_json(WAN_ROOT / 'result.json', {'cleaned': True}).get('cleaned'):
                    wan_signature = wan_current
                    wan_worker = subprocess.Popen([sys.executable,
                        str(Path(__file__).with_name('wan_runtime.py')), 'serve',
                        str(os.getpid()), token(os.getpid()), hostname, str(int(settings['auto_open'])),
                        str(int(use_vpn and bool(settings['auto_enroll']) and enrollment_allowed()
                                and not Path('/data/setupOptions/RoadLink/SAFE_MODE').exists())),
                        role_config['vehicle_ap'], role_config['usb_identity']])
            if vpn_worker and vpn_worker.poll() is not None:
                vpn_worker = None
                vpn_retry_at = time.monotonic() + 15
            if vpn_worker and vpn_current != vpn_signature:
                (VPN_ROOT / 'stop').touch()
            elif (not vpn_worker and vpn_requested and time.monotonic() >= vpn_retry_at
                  and not runtime_locked(VPN_ROOT)
                  and not alive(load_json(VPN_ROOT / 'guard.json', {}))):
                result = load_json(VPN_ROOT / 'result.json', {'cleaned': True})
                if result.get('cleaned'):
                    vpn_signature = vpn_current
                    vpn_worker = subprocess.Popen([sys.executable,
                        str(Path(__file__).with_name('vpn_runtime.py')), 'serve',
                        str(os.getpid()), token(os.getpid())])
            vpn_state = load_json(VPN_ROOT / 'status.json', {})
            direct_requested = wanted == 'direct'
            direct_current_signature = repr(direct_dns(dns_settings())) if direct_requested else None
            if direct_worker and direct_worker.poll() is not None:
                direct_worker = None
                direct_retry_at = time.monotonic() + 15
            if direct_worker and direct_current_signature != direct_signature:
                (DIRECT_ROOT / 'stop').touch()
            elif (not direct_worker and direct_requested and time.monotonic() >= direct_retry_at
                  and not runtime_locked(DIRECT_ROOT)
                  and not alive(load_json(DIRECT_ROOT / 'guard.json', {}))
                  and load_json(DIRECT_ROOT / 'result.json', {'cleaned': True}).get('cleaned')):
                direct_signature = direct_current_signature
                direct_worker = subprocess.Popen([sys.executable,
                    str(Path(__file__).with_name('direct_runtime.py')), 'serve',
                    str(os.getpid()), token(os.getpid())])
            direct_state = load_json(DIRECT_ROOT / 'status.json', {})
            service['/DNS/Provider'] = 'DNSmith' if dns_settings()['dnsmith'] else 'Eigener DNS'
            service['/DNS/Active'] = vpn_state['dns'] if vpn_worker and dns_ready(configuration, vpn_state) else 'Nicht bereit'
            service['/VPN/Status'] = ('Konfiguration ungueltig' if vpn_invalid else
                'Tunnel und DNS bereit' if vpn_worker and vpn_state.get('state') == 'READY'
                else 'Verbindet' if vpn_worker else 'Fehler: Bereinigung pruefen'
                if vpn_state.get('state') == 'CLEANUP_FAILED' else 'Wartet' if vpn_requested else 'Aus')
            service['/VPN/DNS'] = (('DNSmith erreichbar' if dns_settings()['dnsmith'] else 'Eigener DNS erreichbar')
                                  if vpn_worker and vpn_state.get('dns_ready') else 'Nicht bereit')
            service['/Security'] = 'AP nur lokal'
            state = snapshot()
            enrollment_requested = bool(use_vpn and wanted != 'off' and settings['auto_enroll'] and enrollment_allowed()
                and not Path('/data/setupOptions/RoadLink/SAFE_MODE').exists())
            if enrollment_requested or ENROLLMENT_ROOT.exists():
                if ENROLLMENT_ROOT.is_symlink():
                    raise ValueError('Invalid enrollment runtime directory')
                enrollment_request = {'pid': os.getpid(), 'start': token(os.getpid()), 'enabled': enrollment_requested}
                if load_json(ENROLLMENT_ROOT / 'request.json', {}) != enrollment_request:
                    write_json(ENROLLMENT_ROOT / 'request.json', enrollment_request)
            if enrollment_worker and enrollment_worker.poll() is not None:
                enrollment_worker = None
                enrollment_schedule.finished(time.monotonic())
            if enrollment_worker and not enrollment_requested:
                enrollment_worker.terminate()
            enrollment_interface = next((d['interface'] for d in state['interfaces']
                if d['interface'] == state['default_interface']
                and d['suggested_role'] in ('ethernet_candidate', 'vehicle_ap_candidate')), None)
            bootstrap_state = load_json(WAN_ROOT / 'status.json', {})
            bootstrap_ready = (bootstrap_state.get('bootstrap') is True and bootstrap_state.get('state') == 'LEASED'
                               and alive(load_json(WAN_ROOT / 'guard.json', {})))
            native_enrollment_interface = enrollment_interface
            retry_due = time.monotonic() >= enrollment_schedule.retry_at
            if enrollment_requested and not enrollment_worker:
                enrollment_interface = enrollment_schedule.choose(native_enrollment_interface, bootstrap_ready, time.monotonic())
            if enrollment_requested and not enrollment_worker and enrollment_interface:
                enrollment_schedule.started(enrollment_interface)
                enrollment_command = [sys.executable,
                    str(Path(__file__).with_name('enrollment_runtime.py')), str(os.getpid()),
                    token(os.getpid()), enrollment_interface]
                if enrollment_interface == 'disabledrlwan':
                    enrollment_command = ['ip', 'netns', 'exec', 'roadlink-wan', *enrollment_command]
                enrollment_worker = subprocess.Popen(enrollment_command)
            enrollment_state = load_json(ENROLLMENT_ROOT / 'status.json', {})
            service['/VPN/Enrollment'] = ('Im direkten Betrieb ausgeschaltet' if not use_vpn else
                'VPN-Einstellungen vorhanden' if vpn_configured() else
                'Eigenen VPN einrichten' if vpn_provider() == 'custom' else
                'Automatische Einrichtung ausgeschaltet' if not settings['auto_enroll'] else
                'Im Sicherheitsmodus angehalten' if Path('/data/setupOptions/RoadLink/SAFE_MODE').exists() else
                'Wartet auf Internetzugang' if not native_enrollment_interface and not bootstrap_ready else
                'Erneuter Versuch spaeter' if not enrollment_worker and not enrollment_interface else
                'Einrichtung unterbrochen; erneuter Versuch spaeter'
                if not enrollment_worker and not retry_due and enrollment_state.get('state') == 'REGISTERING' else
                enrollment_state.get('message', 'DNSmith.net wird eingerichtet')
                if enrollment_state.get('pid') == os.getpid() and enrollment_state.get('start') == token(os.getpid())
                else 'DNSmith.net wird eingerichtet')
            service['/Ethernet'] = role_text(state, 'ethernet')
            service['/WifiWan'] = role_text(state, 'wifi_wan', role_config)
            service['/VehicleAp'] = role_text(state, 'vehicle_ap', role_config)
            service['/Radio/VehicleAP'] = role_config['vehicle_ap']
            service['/Radio/WanRadio'] = 'USB-Stick' if role_config['vehicle_ap'] == 'internal' else 'Integriertes WLAN'
            service['/DefaultInterface'] = state['default_interface'] or 'Keine'
            service['/LastUpdate'] = state['timestamp']
            service['/Wan/Active'] = ('Ethernet / Starlink' if any(d['interface'] == state['default_interface']
                and d['suggested_role'] == 'ethernet_candidate' for d in state['interfaces'])
                else state['default_interface'] or 'Keine Standardroute')
            try:
                radios = [radio_roles.resolve(state['interfaces'], 'wifi_wan', role_config)]
            except ValueError:
                radios = []
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
                service['/WifiWan'] = service['/Radio/WanRadio'] + ' (' + wan_state.get('driver', 'startet') + ')'
                service['/WifiWan/SSID'] = wan_state.get('ssid') or ('Suchmodus, nicht verbunden'
                    if wan_state.get('state') == 'SCAN_ONLY' else 'Verbindet WLAN')
                service['/WifiWan/State'] = wan_state.get('state', 'STARTING')
                service['/Wan/Reason'] = ('WLAN als Reserve verbunden'
                    if wan_state.get('state') == 'LEASED' else 'WLANs werden gesucht oder geprueft')
            else:
                service['/Wan/Reason'] = ('WLAN-Bereinigung fehlgeschlagen' if wan_state.get('state') == 'CLEANUP_FAILED'
                    else 'WLAN-Reserve startet' if wan_requested else 'WLAN-Reserve ausgeschaltet')
            service['/WifiWan/StateText'] = {
                'LEASED': 'Verbunden', 'ASSOCIATED': 'Wartet auf IP-Adresse',
                'CONNECTING': 'Verbindet', 'STARTING': 'Startet', 'OFF': 'Aus',
                'SCAN_ONLY': ('Reserve wartet; WLAN-Suche' if wan_state.get('reserve_deferred') else 'Nur WLAN-Suche'),
                'CLEANUP_FAILED': 'Bereinigung fehlgeschlagen', 'missing': 'Nicht erkannt',
                'ambiguous': 'Mehrere Funkmodule', 'idle': 'Nicht verbunden',
                'online': 'Verbunden', 'ready': 'Verbunden', 'unavailable': 'Nicht verfuegbar',
            }.get(str(service['/WifiWan/State']), 'Nicht verbunden')
            path_state = vpn_state if use_vpn else direct_state
            service['/Wan/Health'] = 'Internet nicht bereit'
            if 'wan' in path_state:
                active = path_state['wan']
                service['/Wan/Active'] = {'ethernet': 'Ethernet / Starlink', 'wifi': service['/Radio/WanRadio']}.get(active, 'Kein geeigneter WAN-Pfad')
                service['/Wan/Reason'] = ('Direkt ueber WLAN' if not use_vpn and active == 'wifi' else
                    'Direkt ueber Ethernet / Starlink' if not use_vpn and active == 'ethernet' else
                    'Ethernet-Tunnel nicht erreichbar, WLAN aktiv'
                    if active == 'wifi' and vpn_state.get('penalties', {}).get('ethernet') else
                    'Ethernet nicht erreichbar, WLAN aktiv' if active == 'wifi' and not vpn_state.get('health', {}).get('ethernet', {}).get('healthy') else
                    'VPN ueber bekanntes WLAN' if active == 'wifi' else 'VPN ueber Ethernet / Starlink'
                    if active == 'ethernet' else 'Wartet auf geeignete Verbindung')
                service['/Wan/Health'] = (('VPN-Internet und DNS geprueft' if use_vpn else 'Internet und DNS geprueft')
                    if path_state.get('internet') else 'Internet nicht bereit')
            requested = (bool(settings['ap_enabled']), str(settings['ap_ssid']),
                         AP_SECRET.stat().st_mtime_ns if AP_SECRET.exists() else 0,
                         repr(routed_dns(configuration, vpn_state)) if use_vpn else 'direct', use_vpn,
                         bool(settings['starlink_local']))
            if wanted == 'off':
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
            elif not worker and not transport_busy('ap'):
                signature = requested
                if requested[0] and time.monotonic() >= ap_retry_at:
                    failed = None
                    worker = subprocess.Popen([sys.executable, str(Path(__file__).with_name('ap_runtime.py')),
                                               'serve', requested[1], str(os.getpid()), token(os.getpid()),
                                               role_config['vehicle_ap'], role_config['usb_identity'],
                                               '1' if requested[-1] else '0'])
            ap_state = load_json(AP_ROOT / 'status.json', {})
            internet = bool(worker and ap_state.get('internet')
                            and vpn_worker and vpn_state.get('state') == 'READY')
            if not use_vpn:
                subnet = str(ipaddress.IPv4Network(ap_state['address'] + '/24', strict=False)) if ap_state.get('address') else ''
                direct = direct_current(subnet, dns_settings(), alive)
                internet = bool(worker and ap_state.get('internet') and direct_worker and direct)
                service['/DNS/Active'] = direct['dns'] if direct else 'Nicht bereit'
                service['/Security'] = 'AP direkt, ohne VPN; getrenntes Fahrzeugnetz' if internet else 'AP nur lokal'
            service['/Security'] = ('AP ueber VPN, DNSmith' if dns_settings()['dnsmith']
                                   else 'AP ueber VPN, eigenen DNS') if internet and use_vpn else service['/Security']
            service['/AP/Status'] = ('Fehler: Diagnose pruefen' if failed else
                (('Internet ueber VPN' if use_vpn else 'Internet ohne VPN') if internet else 'Lokal, ohne Internet'
                 if ap_state.get('state') in ('LAN_ONLY', 'VPN_INTERNET', 'DIRECT_INTERNET') else 'Startet') if worker
                else 'Aus')
            service['/AP/Address'] = ap_state.get('address', '') if worker else ''
            service['/Status'] = (('WLAN-Internet ueber VPN' if use_vpn else 'WLAN-Internet ohne VPN') if internet else
                                  'Lokales WLAN aktiv' if ap_state.get('state') in ('LAN_ONLY', 'VPN_INTERNET', 'DIRECT_INTERNET')
                                  else 'Fahrzeug-WLAN startet') if worker else 'Netzwerkdiagnose'
            portal_manager.update(wanted!='off')
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
        portal_manager.cancel()
        if portal_manager.worker and portal_manager.worker.poll() is None:
            try:portal_manager.worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                portal_manager.worker.kill()
                portal_manager.worker.wait(timeout=3)
        portal_session_runtime.stop()
        if direct_worker and direct_worker.poll() is None:
            (DIRECT_ROOT / 'stop').touch()
            try:
                direct_worker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                direct_worker.kill()
        if ENROLLMENT_ROOT.exists() and not ENROLLMENT_ROOT.is_symlink():
            try:
                write_json(ENROLLMENT_ROOT / 'request.json', {'pid': os.getpid(), 'start': token(os.getpid()), 'enabled': False})
            except (OSError, ValueError):
                logging.warning('Could not revoke enrollment request file')
        if enrollment_worker and enrollment_worker.poll() is None:
            try:
                enrollment_worker.terminate()
            except ProcessLookupError:
                pass
            try:
                enrollment_worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                enrollment_worker.kill()
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
