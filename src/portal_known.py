"""Private, explicitly approved portal identities; never submits a login.

Descriptors must come from a reviewed portal adapter, not arbitrary page claims.
Session tokens, form values, cookies and personal information are not stored.
An AUTO_ACCEPT_READY decision authorizes only the recorded free action; it is
not evidence of Internet access and does not authorize network exceptions.
"""
import hashlib
import json
import math
import os
import re
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
import capport
from storage import load_json, write_json

MANUAL = {'payment', 'card', 'purchase', 'phone', 'sms', 'mfa', 'captcha',
          'age', 'personal_data', 'newsletter', 'unknown'}
FREE = {'terms_checkbox', 'connect_button', 'free_session'}


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def text(value, limit):
    if (not isinstance(value, str) or not value or len(value.encode()) > limit
            or any(ord(c) < 32 and c not in '\n\r\t' for c in value)):
        raise ValueError('Invalid portal descriptor text')
    return unicodedata.normalize('NFC', value)


def address(value, private=False):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('Invalid portal radio identity')
    first = int(value[:2], 16)
    if first & 1 or value.lower() == '00:00:00:00:00:00' or (private and not first & 2):
        raise ValueError('Invalid portal radio identity')
    return value.lower()


def location(value):
    parts = urlsplit(capport.uri(value, legacy_http=True))
    if parts.query or parts.port in (22, 53, 853):
        raise ValueError('Portal patterns must omit session parameters')
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    authority = parts.hostname.lower().rstrip('.')
    if port != (443 if parts.scheme == 'https' else 80): authority += ':' + str(port)
    return parts.scheme + '://' + authority + (parts.path or '/')


def descriptor(value):
    keys = {'adapter', 'ssid', 'bssids', 'wan_mac', 'url', 'form_action', 'method',
            'fields', 'redirects', 'success_detection', 'structure', 'terms',
            'manual_reasons', 'action'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('Incomplete portal descriptor')
    bssids = value['bssids']
    if not isinstance(bssids, list) or not 1 <= len(bssids) <= 16:
        raise ValueError('Invalid BSSID group')
    bssids = sorted(address(v) for v in bssids)
    if len(set(bssids)) != len(bssids): raise ValueError('Duplicate BSSID')
    fields = value['fields']
    if not isinstance(fields, list) or not 1 <= len(fields) <= 32:
        raise ValueError('Invalid portal fields')
    normalized = []
    for field in fields:
        if (not isinstance(field, dict) or set(field) != {'name', 'type', 'required', 'role'}
                or type(field['required']) is not bool
                or field['role'] not in {'session', 'consent', 'submit'} | MANUAL):
            raise ValueError('Unsupported portal field')
        normalized.append(dict(field, name=text(field['name'], 128), type=text(field['type'], 32)))
    if len({f['name'] for f in normalized}) != len(normalized):
        raise ValueError('Ambiguous portal fields')
    reasons = value['manual_reasons']
    if not isinstance(reasons, list) or len(reasons) > len(MANUAL) or any(r not in MANUAL for r in reasons):
        raise ValueError('Unclassified portal requirements')
    reasons = sorted(set(reasons) | {f['role'] for f in normalized if f['role'] in MANUAL})
    redirects = value['redirects']
    if not isinstance(redirects, list) or len(redirects) > 5:
        raise ValueError('Invalid portal redirects')
    if value['method'] not in ('GET', 'POST') or value['action'] not in FREE:
        raise ValueError('Unapproved portal action')
    # Store only hashes of page structure and terms, never their raw contents.
    return {'adapter': text(value['adapter'], 64), 'ssid': text(value['ssid'], 32),
            'bssids': bssids, 'wan_mac': address(value['wan_mac'], private=True),
            'url': location(value['url']), 'form_action': location(value['form_action']),
            'method': value['method'], 'fields': normalized,
            'redirects': [location(v) for v in redirects],
            'success_detection': text(value['success_detection'], 64),
            'structure_hash': digest(text(value['structure'], 65536)),
            'terms_hash': digest(' '.join(text(value['terms'], 131072).split())),
            'manual_reasons': reasons, 'action': value['action']}


def profile_id(snapshot):
    return digest({k: snapshot[k] for k in ('ssid', 'bssids', 'wan_mac', 'url')})[:24]


def stored_snapshot(snapshot):
    if not isinstance(snapshot, dict): raise ValueError('Invalid saved portal descriptor')
    candidate = dict(snapshot)
    hashes = {}
    for key in ('structure_hash', 'terms_hash'):
        hashes[key] = candidate.pop(key, None)
        if not isinstance(hashes[key], str) or not re.fullmatch(r'[0-9a-f]{64}', hashes[key]):
            raise ValueError('Invalid saved portal fingerprint')
    candidate.update(structure='stored', terms='stored')
    normalized = descriptor(candidate)
    normalized.update(hashes)
    if normalized != snapshot: raise ValueError('Noncanonical saved portal descriptor')
    return normalized


class KnownPortals:
    def __init__(self, path='/data/setupOptions/RoadLink/known-portals.json'):
        self.path = Path(path)

    def read(self):
        if self.path.is_symlink(): raise ValueError('Portal store must not be a symlink')
        if self.path.exists() and self.path.stat().st_size > 524288:
            raise ValueError('Portal store too large')
        data = load_json(self.path, {'schema': 1, 'auto_accept': True, 'profiles': {}})
        if (not isinstance(data, dict) or set(data) != {'schema', 'auto_accept', 'profiles'}
                or type(data['schema']) is not int or data['schema'] != 1
                or type(data['auto_accept']) is not bool
                or not isinstance(data['profiles'], dict) or len(data['profiles']) > 64):
            raise ValueError('Invalid portal store')
        for identifier, record in data['profiles'].items():
            if (not re.fullmatch(r'[0-9a-f]{24}', identifier)
                    or not isinstance(record, dict)
                    or set(record) != {'descriptor', 'fingerprint', 'auto_accept', 'last_success'}
                    or not isinstance(record['fingerprint'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', record['fingerprint'])
                    or type(record['auto_accept']) is not bool
                    or type(record['last_success']) not in (int, float)
                    or not math.isfinite(record['last_success']) or record['last_success'] <= 0):
                raise ValueError('Invalid known portal record')
            snapshot = stored_snapshot(record['descriptor'])
            if (snapshot['manual_reasons'] or profile_id(snapshot) != identifier
                    or digest(snapshot) != record['fingerprint']):
                raise ValueError('Inconsistent known portal record')
        return data

    @contextmanager
    def mutation(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path.with_name(self.path.name + '.lock'),
                     os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            if os.name == 'posix':
                import fcntl
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield self.read()
        finally: os.close(fd)

    def remember(self, observed, proof, now, approved_free=False, current_connection=None):
        snapshot = descriptor(observed)
        fingerprint = digest(snapshot)
        if (approved_free is not True or snapshot['manual_reasons']
                or not isinstance(proof, dict)
                or set(proof) != {'fingerprint', 'manual_success', 'internet_proven', 'checked_at', 'connection_id', 'bssid'}
                or not isinstance(current_connection, str)
                or not re.fullmatch(r'[0-9a-f]{24}', current_connection)
                or proof['connection_id'] != current_connection
                or proof['bssid'] not in snapshot['bssids']
                or proof['fingerprint'] != fingerprint or proof['manual_success'] is not True
                or proof['internet_proven'] is not True
                or any(type(v) not in (int, float) or not math.isfinite(v)
                       for v in (now, proof['checked_at']))
                or now <= 0 or not 0 <= now-proof['checked_at'] <= 30):
            raise ValueError('Fresh explicit manual success required')
        identifier = profile_id(snapshot)
        with self.mutation() as data:
            if identifier not in data['profiles'] and len(data['profiles']) >= 64:
                raise ValueError('Known portal limit reached')
            old = data['profiles'].get(identifier, {})
            data['profiles'][identifier] = {'descriptor': snapshot, 'fingerprint': fingerprint,
                'auto_accept': old.get('auto_accept', True), 'last_success': now}
            if len(json.dumps(data, ensure_ascii=False).encode()) > 524288:
                raise ValueError('Known portal store limit reached')
            write_json(self.path, data)
        return identifier

    def set_auto_accept(self, enabled, identifier=None):
        if type(enabled) is not bool: raise ValueError('Boolean portal switch required')
        with self.mutation() as data:
            if identifier is None: data['auto_accept'] = enabled
            else:
                if identifier not in data['profiles']: raise ValueError('Unknown portal')
                data['profiles'][identifier]['auto_accept'] = enabled
            write_json(self.path, data)

    def decision(self, observed):
        snapshot = descriptor(observed)
        data = self.read()
        record = data['profiles'].get(profile_id(snapshot))
        if snapshot['manual_reasons']: return 'MANUAL_REVIEW_REQUIRED'
        if record is None: return 'MANUAL_REVIEW_REQUIRED'
        if record['fingerprint'] != digest(snapshot): return 'PORTAL_CHANGED'
        if not data['auto_accept'] or not record['auto_accept']: return 'AUTO_ACCEPT_DISABLED'
        return 'AUTO_ACCEPT_READY'

    def metadata(self):
        return [{'id': identifier, 'ssid': record['descriptor']['ssid'],
                 'host': urlsplit(record['descriptor']['url']).hostname,
                 'auto_accept': record['auto_accept'], 'last_success': record['last_success']}
                for identifier, record in sorted(self.read()['profiles'].items())]
