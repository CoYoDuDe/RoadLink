#!/usr/bin/env python3
"""RoadLink status service; no network mutations in the monitor release."""
import logging
import sys
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
from status import snapshot, role_text


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    DBusGMainLoop(set_as_default=True)
    service = VeDbusService('com.coyodude.roadlink', bus=dbus.SystemBus(), register=False)
    for path, value in {
        '/Mgmt/ProcessName': __file__, '/Mgmt/ProcessVersion': '0.1',
        '/Mgmt/Connection': 'Local network monitor', '/Connected': 1,
        '/Status': 'Nur Diagnose',
        '/Ethernet': '', '/WifiWan': '', '/VehicleAp': '', '/DefaultInterface': '',
        '/Security': 'Noch nicht aktiv', '/LastUpdate': 0,
    }.items():
        service.add_path(path, value, writeable=False)
    service.register()

    def refresh():
        try:
            state = snapshot()
            service['/Ethernet'] = role_text(state, 'ethernet')
            service['/WifiWan'] = role_text(state, 'wifi_wan')
            service['/VehicleAp'] = role_text(state, 'vehicle_ap')
            service['/DefaultInterface'] = state['default_interface'] or 'Keine'
            service['/LastUpdate'] = state['timestamp']
        except Exception:
            logging.exception('Status refresh failed')
        return True

    refresh()
    GLib.timeout_add_seconds(10, refresh)
    GLib.MainLoop().run()


if __name__ == '__main__':
    main()
