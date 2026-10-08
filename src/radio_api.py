"""Vehicle radio choice; changing intent is drained by the daemon barrier."""
import radio_roles


def install(service):
    try:
        current = radio_roles.read()
        message = 'Funkzuordnung gespeichert'
    except (ValueError, OSError):
        current, message = dict(radio_roles.DEFAULT), 'Funkzuordnung ungueltig; neu waehlen'
    service.add_path('/Radio/EditStatus', message)
    service.add_path('/Radio/WanRadio', 'USB-Stick' if current['vehicle_ap'] == 'internal' else 'Integriertes WLAN')

    def choose(path, value):
        if value not in ('internal', 'usb'):
            return False
        try:
            try:
                settings = radio_roles.read()
            except ValueError:
                settings = dict(radio_roles.DEFAULT)
            radio_roles.save(dict(settings, vehicle_ap=value))
            service['/Radio/WanRadio'] = 'USB-Stick' if value == 'internal' else 'Integriertes WLAN'
            service['/Radio/EditStatus'] = 'Gespeichert; WLANs starten neu'
            return True
        except (ValueError, OSError):
            service['/Radio/EditStatus'] = 'Funkzuordnung nicht gespeichert'
            return False

    service.add_path('/Radio/VehicleAP', current['vehicle_ap'], writeable=True, onchangecallback=choose)
