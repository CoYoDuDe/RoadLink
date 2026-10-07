"""Native independent DNS settings; unsaved drafts never change routing."""
from dns_config import DEFAULT, read, save


def install(service):
    from secret_item import SecretItem
    try:
        settings = read()
        message = 'DNSmith aktiv' if settings['dnsmith'] else 'Eigener DNS aktiv'
    except (ValueError, OSError):
        settings, message = dict(DEFAULT), 'DNS-Einstellungen ungueltig'
    service.add_path('/DNS/Provider', 'DNSmith' if settings['dnsmith'] else 'Eigener DNS')
    service.add_path('/DNS/Active', 'Nicht bereit')
    service.add_path('/DNS/EditStatus', message)
    for name, field in [('Primary', 'primary'), ('Secondary', 'secondary')]:
        service.add_path('/DNS/' + name, settings[field], writeable=True)

    def choose(path, value):
        if value not in (0, 1):
            return False
        try:
            current = read()
            if value or current['primary']:
                save(dict(current, dnsmith=bool(value)))
                service['/DNS/EditStatus'] = 'DNSmith aktiv' if value else 'Eigener DNS aktiv'
            else:
                service['/DNS/EditStatus'] = 'DNS-Felder eingeben und speichern'
            return True
        except (ValueError, OSError):
            service['/DNS/EditStatus'] = 'DNS-Auswahl fehlgeschlagen'
            return False

    def apply(path, value):
        if value != 'save' or service['/DNS/UseDNSmith'] != 0:
            return False
        try:
            save({'dnsmith': False, 'primary': str(service['/DNS/Primary']),
                  'secondary': str(service['/DNS/Secondary'])})
            service['/DNS/EditStatus'] = 'Eigener DNS gespeichert'
            return True
        except (ValueError, OSError):
            service['/DNS/EditStatus'] = 'DNS-Adressen pruefen'
            return False
    service.add_path('/DNS/UseDNSmith', int(settings['dnsmith']), writeable=True, onchangecallback=choose)
    service.add_path('/DNS/Save', '', writeable=True, itemtype=SecretItem, onchangecallback=apply)
