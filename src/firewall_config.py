"""Private, revision-checked firewall policy. System protections are not editable."""
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
from storage import load_json, write_json

PATH = Path('/data/setupOptions/RoadLink/firewall.json')
DEFAULT = {'schema': 1, 'default': 'allow', 'rules': []}


def rule(value):
    keys = {'id', 'name', 'enabled', 'action', 'source', 'destination', 'protocol', 'port'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('Invalid firewall rule fields')
    if not isinstance(value['id'], str) or not re.fullmatch('[0-9a-f]{16}', value['id']):
        raise ValueError('Invalid firewall rule identity')
    name = value['name']
    if not isinstance(name, str) or not 1 <= len(name) <= 48 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError('Invalid firewall rule name')
    if type(value['enabled']) is not bool or value['action'] not in ('allow', 'block'):
        raise ValueError('Invalid firewall action')
    if value['protocol'] not in ('any', 'tcp', 'udp'):
        raise ValueError('Invalid firewall protocol')
    port = value['port']
    if type(port) is not int or not 0 <= port <= 65535 or port and value['protocol'] == 'any':
        raise ValueError('Invalid firewall port')
    source, destination = value['source'], value['destination']
    if not isinstance(source, str) or not isinstance(destination, str):
        raise ValueError('Invalid firewall addresses')
    if source:
        address = ipaddress.IPv4Address(source)
        if not any(address in ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
            raise ValueError('A private vehicle client is required')
        source = str(address)
    if destination:
        network = ipaddress.IPv4Network(destination, strict=True)
        # A user allowance cannot describe any protected/special range.
        from ap_router import PRIVATE
        if (not network.network_address.is_global or not network.broadcast_address.is_global
                or any(network.overlaps(ipaddress.IPv4Network(n)) for n in PRIVATE)):
            raise ValueError('A public IPv4 destination is required')
        destination = str(network)
    return dict(value, source=source, destination=destination)


def validate(value):
    if (not isinstance(value, dict) or set(value) != {'schema', 'default', 'rules'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['default'] not in ('allow', 'block')
            or not isinstance(value['rules'], list) or len(value['rules']) > 32):
        raise ValueError('Invalid firewall policy')
    rules = [rule(r) for r in value['rules']]
    if len({r['id'] for r in rules}) != len(rules):
        raise ValueError('Duplicate firewall rule identity')
    return {'schema': 1, 'default': value['default'], 'rules': rules}


def read(path=PATH):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Firewall policy must not be a symlink')
    return validate(load_json(path, DEFAULT))


def generation(value):
    return hashlib.sha256(json.dumps(validate(value), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


class Store:
    def __init__(self, path=PATH):
        self.path = Path(path)

    @contextmanager
    def mutation(self, expected):
        if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
            raise ValueError('A policy revision is required')
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(str(self.path.with_name(self.path.name + '.lock')),
            os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            if os.name == 'posix':
                import fcntl
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            value = read(self.path)
            if generation(value) != expected:
                raise ValueError('Firewall policy changed; reload before editing')
            yield value
        finally:
            os.close(descriptor)

    def save(self, draft, expected, identifier=None):
        with self.mutation(expected) as value:
            if not isinstance(draft, dict) or 'id' in draft:
                raise ValueError('Invalid firewall draft')
            candidate = rule(dict(draft, id=identifier or secrets.token_hex(8)))
            rules = value['rules']
            if identifier is None:
                rules.append(candidate)
            else:
                indexes = [i for i, r in enumerate(rules) if r['id'] == identifier]
                if not indexes:
                    raise ValueError('Unknown firewall rule')
                rules[indexes[0]] = candidate
            write_json(self.path, validate(value))
            return candidate['id']

    def remove(self, identifier, expected):
        with self.mutation(expected) as value:
            if identifier not in {r['id'] for r in value['rules']}:
                raise ValueError('Unknown firewall rule')
            value['rules'] = [r for r in value['rules'] if r['id'] != identifier]
            write_json(self.path, value)

    def reorder(self, identifiers, expected):
        with self.mutation(expected) as value:
            if (not isinstance(identifiers, list) or any(not isinstance(i, str) for i in identifiers)
                    or len(identifiers) != len(set(identifiers))
                    or set(identifiers) != {r['id'] for r in value['rules']}):
                raise ValueError('Every rule must occur exactly once')
            indexed = {r['id']: r for r in value['rules']}
            value['rules'] = [indexed[i] for i in identifiers]
            write_json(self.path, value)

    def set_default(self, action, expected):
        with self.mutation(expected) as value:
            value['default'] = action
            write_json(self.path, validate(value))
