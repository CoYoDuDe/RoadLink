"""Native GUI commands, queued outside DBus callbacks and checked by revision."""
import copy
import ipaddress
import json
import re
from pathlib import Path
import firewall_config as config
from storage import load_json

PREFIX = '/Firewall/'
DRAFT = {'name': '', 'enabled': True, 'action': 'block', 'source': '',
         'destination': '', 'protocol': 'tcp', 'port': 0}


class API:
    def __init__(self, service, store=None, itemtype=None):
        self.service = service
        self.store = config.Store() if store is None else store
        self.pending = None
        self.editing = None
        self.base = None
        self.valid = False
        self.data = None
        service.add_path(PREFIX + 'Draft/Ready', 0)
        for name, value in [('Rules', '[]'), ('Revision', ''), ('Default', 'allow'),
                            ('Status', 'Noch nicht geprueft'), ('ApplyStatus', 'Noch nicht aktiv')]:
            service.add_path(PREFIX + name, value)
        for name, value in DRAFT.items():
            service.add_path(PREFIX + 'Draft/' + name.title(), int(value) if type(value) is bool else value,
                             writeable=True, onchangecallback=self.draft)
        for name, callback in [('Edit', self.edit), ('Save', self.save), ('Action', self.action)]:
            options = {'writeable': True, 'onchangecallback': callback}
            if itemtype is not None:
                options['itemtype'] = itemtype
            service.add_path(PREFIX + name, '', **options)
        self.publish()

    def draft(self, path, value):
        field = path.rsplit('/', 1)[-1].lower()
        if field not in DRAFT:
            return False
        if field == 'enabled':
            return not isinstance(value, bool) and isinstance(value, int) and value in (0, 1)
        if field == 'port':
            return (not isinstance(value, bool) and isinstance(value, (int, str))
                    and re.fullmatch('[0-9]{1,5}', str(value)) is not None and int(value) <= 65535)
        return isinstance(value, str) and len(value) <= 64 and '\x00' not in value

    def queue(self, command):
        if not self.valid or self.pending is not None:
            return False
        self.pending = copy.deepcopy(command)
        self.service[PREFIX + 'Status'] = 'Wird gespeichert'
        return True

    def edit(self, path, value):
        if not isinstance(value, str) or value != 'new' and not re.fullmatch('[0-9a-f]{16}', value):
            return False
        accepted = self.queue(('edit', value))
        if accepted:
            self.base = None
            self.service[PREFIX + 'Draft/Ready'] = 0
        return accepted

    def save(self, path, value):
        if value != 'save' or self.base is None:
            return False
        try:
            draft = {name: self.service[PREFIX + 'Draft/' + name.title()] for name in DRAFT}
            if not all(self.draft(PREFIX+'Draft/'+name.title(), value) for name, value in draft.items()):
                raise ValueError('Invalid draft')
            draft['enabled'] = bool(int(draft['enabled']))
            draft['port'] = int(draft['port'])
            # Complete validation before copying the draft into the command.
            config.rule(dict(draft, id=self.editing or '0'*16))
            return self.queue(('save', draft, self.base, self.editing))
        except (ValueError, TypeError, KeyError):
            self.service[PREFIX + 'Status'] = 'Name, Adressen und Port pruefen'
            return False

    def action(self, path, value):
        if not isinstance(value, str) or len(value) > 100:
            return False
        parts = value.split(':')
        if len(parts) != 3 or not re.fullmatch('[0-9a-f]{64}', parts[2]):
            return False
        operation, argument, revision = parts
        if (operation == 'default' and argument in ('allow', 'block') or
                operation in ('remove', 'up', 'down') and re.fullmatch('[0-9a-f]{16}', argument)):
            return self.queue((operation, argument, revision))
        return False

    def publish(self):
        try:
            self.data = config.read(self.store.path)
            self.valid = True
            self.service[PREFIX + 'Rules'] = json.dumps(self.data['rules'], ensure_ascii=False)
            self.service[PREFIX + 'Revision'] = config.generation(self.data)
            self.service[PREFIX + 'Default'] = self.data['default']
            if self.service[PREFIX + 'Status'] == 'Noch nicht geprueft':
                self.service[PREFIX + 'Status'] = 'Bereit'
            return True
        except (ValueError, TypeError, OSError):
            self.valid = False
            self.data = None
            self.service[PREFIX + 'Rules'] = '[]'
            self.service[PREFIX + 'Revision'] = ''
            self.service[PREFIX + 'Status'] = 'Regeln nicht lesbar; Internet wird gesperrt'
            self.service[PREFIX + 'ApplyStatus'] = 'Gesperrt'
            return False

    def apply_status(self):
        if not self.valid:
            return
        revision = config.generation(self.data)
        ap = load_json(Path('/run/roadlink-ap/status.json'), {})
        if ap.get('firewall_generation') == revision:
            # AP proof is sufficient for VPN rules only when its guard is live.
            from ap_runtime import alive
            owners = [load_json(Path('/run/roadlink-ap')/(name+'.json'), {}) for name in ('controller','guard')]
            if all(alive(owner) for owner in owners) and not any(
                    (Path('/run/roadlink-ap')/name).exists() for name in ('stop','cleaning')):
                if ap.get('state') == 'VPN_INTERNET':
                    self.service[PREFIX + 'ApplyStatus'] = 'Aktiv'
                    return
                if ap.get('state') == 'DIRECT_INTERNET':
                    from direct_status import current
                    from dns_config import read as dns_settings
                    subnet = str(ipaddress.IPv4Network(ap['address']+'/24', strict=False))
                    direct = current(subnet, dns_settings(), alive)
                    if direct and direct.get('firewall') == self.data:
                        self.service[PREFIX + 'ApplyStatus'] = 'Aktiv'
                        return
        self.service[PREFIX + 'ApplyStatus'] = 'Wartet auf sicheren Internetpfad'

    def update(self):
        command, self.pending = self.pending, None
        if command is not None:
            try:
                operation = command[0]
                if operation == 'edit':
                    self.editing = self.base = None
                    data = config.read(self.store.path)
                    identifier = command[1]
                    selected = DRAFT if identifier == 'new' else next(r for r in data['rules'] if r['id'] == identifier)
                    self.editing = None if identifier == 'new' else identifier
                    self.base = config.generation(data)
                    for name in DRAFT:
                        value = selected[name]
                        self.service[PREFIX + 'Draft/' + name.title()] = int(value) if type(value) is bool else value
                    self.service[PREFIX + 'Draft/Ready'] = 1
                    self.service[PREFIX + 'Status'] = 'Neue Regel' if identifier == 'new' else 'Regel bearbeiten'
                elif operation == 'save':
                    _, draft, revision, identifier = command
                    if draft['enabled'] and draft['source']:
                        # Catch a mistyped device address before restarting AP.
                        # Disabled rules may retain an old vehicle address.
                        ap = load_json(Path('/run/roadlink-ap/status.json'), {})
                        subnet = str(ipaddress.IPv4Network(ap['address']+'/24', strict=False))
                        from firewall_rules import rules
                        list(rules({'schema': 1, 'default': 'allow', 'rules': [
                            config.rule(dict(draft, id=identifier or '0'*16))]},
                            subnet, 'wgroadlink', 'roadlink-ap-route-owned'))
                    self.editing = self.store.save(draft, revision, identifier)
                    self.base = config.generation(config.read(self.store.path))
                    self.service[PREFIX + 'Status'] = 'Gespeichert; wird angewendet'
                elif operation == 'remove':
                    self.store.remove(command[1], command[2])
                    self.service[PREFIX + 'Status'] = 'Entfernt; wird angewendet'
                elif operation == 'default':
                    self.store.set_default(command[1], command[2])
                    self.service[PREFIX + 'Status'] = 'Gespeichert; wird angewendet'
                elif operation in ('up', 'down'):
                    data = config.read(self.store.path)
                    identifiers = [r['id'] for r in data['rules']]
                    index = identifiers.index(command[1])
                    target = index + (-1 if operation == 'up' else 1)
                    if not 0 <= target < len(identifiers):
                        raise ValueError('Rule is already at the boundary')
                    identifiers[index], identifiers[target] = identifiers[target], identifiers[index]
                    self.store.reorder(identifiers, command[2])
                    self.service[PREFIX + 'Status'] = 'Reihenfolge gespeichert; wird angewendet'
            except (ValueError, TypeError, KeyError, StopIteration, OSError):
                self.service[PREFIX + 'Status'] = 'Nicht gespeichert; Regeln neu oeffnen und Eingaben pruefen'
        self.publish()
        try:
            self.apply_status()
        except (ValueError, TypeError, KeyError, OSError):
            self.service[PREFIX + 'ApplyStatus'] = 'Noch nicht nachgewiesen'
