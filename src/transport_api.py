"""Explicit VPN requirement; provider profiles are preserved when disabled."""
from transport_config import read, save


def install(service):
    try:
        current = read()
        message = 'VPN erforderlich' if current['vpn_required'] else 'Direkt, ohne VPN'
    except (ValueError, OSError):
        current, message = {'vpn_required': True}, 'Transport-Einstellungen pruefen'
    service.add_path('/Transport/Status', 'Noch nicht aktiv')
    service.add_path('/Transport/EditStatus', message)

    def choose(path, value):
        if value not in (0, 1):
            return False
        try:
            save({'vpn_required': bool(value)})
            service['/Transport/EditStatus'] = 'VPN erforderlich' if value else 'Direkt, ohne VPN'
            return True
        except (ValueError, OSError):
            service['/Transport/EditStatus'] = 'Auswahl fehlgeschlagen'
            return False
    service.add_path('/Transport/VPNRequired', int(current['vpn_required']), writeable=True,
                     onchangecallback=choose)
