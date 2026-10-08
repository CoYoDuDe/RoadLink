"""GUI switches for previously approved portals; callbacks queue disk writes."""
import json
from urllib.parse import urlsplit
from portal_known import KnownPortals


class API:
    def __init__(self, service, store=None):
        self.service = service
        self.store = store if store is not None else KnownPortals()
        self.pending = None
        self.known = set()
        self.paths = set()
        self.valid = False
        service.add_path('/Portal/Known/AutoAccept', 0, writeable=True,
                         onchangecallback=lambda path, value: self.queue(None, value))
        service.add_path('/Portal/Known/Profiles', '[]')
        service.add_path('/Portal/Known/Status', 'Noch nicht geprueft')
        self.publish()

    def queue(self, identifier, value):
        # No file lock, disk access, network or portal action in DBus callbacks.
        if (not self.valid or self.pending is not None or isinstance(value, bool)
                or not isinstance(value, int) or value not in (0, 1)
                or identifier is not None and identifier not in self.known):
            return False
        self.pending = (identifier, bool(value))
        self.service['/Portal/Known/Status'] = 'Einstellung wird gespeichert'
        return True

    def publish(self):
        try:
            data = self.store.read()
            profiles = [{'id': key, 'ssid': record['descriptor']['ssid'],
                'host': urlsplit(record['descriptor']['url']).hostname,
                'auto_accept': record['auto_accept'], 'last_success': record['last_success']}
                for key, record in sorted(data['profiles'].items())]
            self.known = set(data['profiles'])
            self.valid = True
            self.service['/Portal/Known/AutoAccept'] = int(data['auto_accept'])
            self.service['/Portal/Known/Profiles'] = json.dumps(profiles, ensure_ascii=False)
            if self.service['/Portal/Known/Status'] in ('Noch nicht geprueft',
                    'Portalprofile nicht lesbar; automatische Zustimmung gesperrt'):
                self.service['/Portal/Known/Status'] = 'Bereit' if profiles else 'Noch keine bestaetigten Portale'
            for identifier in self.known:
                path = '/Portal/Known/Profiles/' + identifier + '/AutoAccept'
                value = int(data['profiles'][identifier]['auto_accept'])
                if identifier not in self.paths:
                    self.service.add_path(path, value, writeable=True,
                        onchangecallback=lambda path, value, key=identifier: self.queue(key, value))
                    self.paths.add(identifier)
                else: self.service[path] = value
            for identifier in self.paths - self.known:
                self.service['/Portal/Known/Profiles/' + identifier + '/AutoAccept'] = 0
            return True
        except (ValueError, TypeError, KeyError, OSError):
            self.valid = False
            self.known = set()
            self.service['/Portal/Known/AutoAccept'] = 0
            self.service['/Portal/Known/Profiles'] = '[]'
            self.service['/Portal/Known/Status'] = 'Portalprofile nicht lesbar; automatische Zustimmung gesperrt'
            for identifier in self.paths:
                self.service['/Portal/Known/Profiles/' + identifier + '/AutoAccept'] = 0
            return False

    def update(self):
        command, self.pending = self.pending, None
        if command is not None:
            try:
                identifier, enabled = command
                self.store.set_auto_accept(enabled, identifier)
                self.service['/Portal/Known/Status'] = 'Gespeichert'
            except (ValueError, TypeError, KeyError, OSError):
                self.service['/Portal/Known/Status'] = 'Einstellung nicht gespeichert'
        self.publish()
