"""Native GUI profile API. Password commands never publish their arguments."""
import json
import time
from profiles import Profiles
from secret_item import SecretItem
from gi.repository import GLib


def install(service):
    service.add_path('/Wifi/Profiles', '[]')
    service.add_path('/Wifi/EditStatus', 'VPN-Verbindung noch nicht aktiv')
    pending = ['', 0, None]
    editing = [None]

    def draft_changed(path, value):
        if path.endswith(('/SSID', '/Security')):
            pending[:] = ['', 0, None]
        return True

    for name, value in [('SSID', ''), ('Security', 'psk'), ('Priority', 50), ('AutoConnect', 0)]:
        service.add_path('/Wifi/Draft/' + name, value, writeable=True, onchangecallback=draft_changed)

    def expire():
        if pending[0] and time.monotonic() >= pending[1]:
            pending[:] = ['', 0, None]
        return True

    GLib.timeout_add_seconds(1, expire)

    def publish():
        service['/Wifi/Profiles'] = json.dumps(Profiles().metadata(), ensure_ascii=False)

    def edit(path, value):
        pending[:] = ['', 0, None]
        profile = {} if value == 'new' else Profiles().data['profiles'].get(value)
        editing[0] = None if value == 'new' else value
        if profile is None:
            editing[0] = None
            profile = {}
            service['/Wifi/EditStatus'] = 'Profil nicht gefunden'
        else:
            service['/Wifi/EditStatus'] = 'Neues WLAN' if value == 'new' else 'Passwort bleibt bei leerer Eingabe'
        for name, field, default in [('SSID', 'ssid', ''), ('Security', 'security', 'psk'),
                                     ('Priority', 'priority', 50), ('AutoConnect', 'autoconnect', False)]:
            service['/Wifi/Draft/' + name] = int(profile.get(field, default)) if name == 'AutoConnect' else profile.get(field, default)
        return bool(profile) or value == 'new'

    def password(path, value):
        if not 8 <= len(value) <= 63 or any(not 32 <= ord(c) <= 126 for c in value):
            service['/Wifi/EditStatus'] = 'Passwort: 8-63 ASCII-Zeichen'
            return False
        pending[:] = [value, time.monotonic() + 60,
                      (str(service['/Wifi/Draft/SSID']), str(service['/Wifi/Draft/Security']))]
        service['/Wifi/EditStatus'] = 'Passwort eingegeben; speichern'
        return True

    def save(path, value):
        if value != 'save':
            return False
        try:
            identity = (str(service['/Wifi/Draft/SSID']), str(service['/Wifi/Draft/Security']))
            password_value = pending[0] if time.monotonic() < pending[1] and pending[2] == identity else ''
            Profiles().save(str(service['/Wifi/Draft/SSID']), str(service['/Wifi/Draft/Security']),
                            password_value, int(service['/Wifi/Draft/Priority']),
                            bool(service['/Wifi/Draft/AutoConnect']), edit_id=editing[0])
            pending[:] = ['', 0, None]
            publish()
            service['/Wifi/EditStatus'] = 'Profil gespeichert'
            return True
        except (ValueError, OSError):
            service['/Wifi/EditStatus'] = 'SSID/Passwort/Prioritaet pruefen'
            return False

    def forget(path, value):
        try:
            Profiles().forget(value)
            publish()
            service['/Wifi/EditStatus'] = 'Profil entfernt'
            return True
        except (ValueError, OSError):
            service['/Wifi/EditStatus'] = 'Entfernen fehlgeschlagen'
            return False

    for path, callback in [('/Wifi/Draft/Password', password), ('/Wifi/Draft/Save', save),
                           ('/Wifi/Forget', forget), ('/Wifi/Edit', edit)]:
        service.add_path(path, '', writeable=True, itemtype=SecretItem, onchangecallback=callback)
    publish()
