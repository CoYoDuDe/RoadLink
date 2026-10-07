"""Bounded DNSmith enrollment transport. Only the public key leaves the Pi."""
import ipaddress
import json
import socket
import ssl
import time
from enrollment_crypto import challenge_fields, proof
from vpn_config import validate
from wireguard import validate_key

HOST = 'dnsmith.net'
ADDRESS = '82.165.141.247'
PATHS = ('/api/roadlink/challenge', '/api/roadlink/enroll')
MAX_BODY = 16384


class EnrollmentError(ValueError):
    """Safe user-facing error; contains neither response body nor credentials."""


def decode_response(raw):
    try:
        header, body = raw.split(b'\r\n\r\n', 1)
        if len(header) > 8192 or len(body) > MAX_BODY:
            raise ValueError()
        lines = header.split(b'\r\n')
        status = lines[0].split(b' ')
        if len(status) < 2 or status[0] not in (b'HTTP/1.0', b'HTTP/1.1'):
            raise ValueError()
        code = int(status[1])
        fields = {}
        for line in lines[1:]:
            name, value = line.split(b':', 1)
            name = name.lower()
            critical = (b'content-length', b'transfer-encoding', b'content-type', b'content-encoding')
            if (not name or name.strip() != name or (name in critical and name in fields)):
                raise ValueError()
            if name not in fields:
                fields[name] = value.strip()
        if b'transfer-encoding' in fields:
            raise ValueError()
        if b'content-length' in fields and int(fields[b'content-length']) != len(body):
            raise ValueError()
        if code != 200:
            reason = {429: 'Zu viele Anfragen; später erneut versuchen',
                      503: 'DNSmith-Einrichtung derzeit nicht verfügbar'}.get(code, 'DNSmith-Anmeldung abgewiesen')
            raise EnrollmentError(reason)
        if fields.get(b'content-type', b'').split(b';', 1)[0].strip().lower() != b'application/json':
            raise ValueError()
        value = json.loads(body.decode('utf-8'))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except EnrollmentError:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise EnrollmentError('Ungültige Antwort von DNSmith') from None


def post(path, value, interface=None, source=None):
    if path not in PATHS:
        raise EnrollmentError('Ungültiger Anmeldungspfad')
    body = json.dumps(value, separators=(',', ':')).encode('utf-8')
    if len(body) > 2048:
        raise EnrollmentError('Anmeldedaten zu groß')
    # The server's root broker can spend up to 30s activating a peer; the
    # HTTPS proxy waits 35s. Enrollment must outlive that bounded activation.
    deadline = time.monotonic() + (40 if path == PATHS[1] else 10)
    request = ('POST ' + path + ' HTTP/1.1\r\nHost: ' + HOST +
               '\r\nContent-Type: application/json\r\nAccept: application/json\r\n'
               'Connection: close\r\nContent-Length: ' + str(len(body)) + '\r\n\r\n').encode('ascii') + body
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            if source:
                sock.bind((str(ipaddress.IPv4Address(source)), 0))
            if interface:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b'\0')
            sock.connect((ADDRESS, 443))
            with ssl.create_default_context().wrap_socket(sock, server_hostname=HOST) as secure:
                secure.settimeout(max(.01, deadline - time.monotonic()))
                secure.sendall(request)
                raw = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    secure.settimeout(remaining)
                    part = secure.recv(4096)
                    if not part:
                        break
                    raw.extend(part)
                    if len(raw) > MAX_BODY + 8192 + 4:
                        raise EnrollmentError('Antwort von DNSmith zu groß')
        return decode_response(bytes(raw))
    except (OSError, ssl.SSLError):
        raise EnrollmentError('DNSmith-Anmeldung nicht erreichbar') from None


def enroll(private, public, interface=None, source=None, transport=post, prove=proof):
    public = validate_key(public)
    started = time.monotonic()
    challenge = transport(PATHS[0], {'version': 1, 'public_key': public}, interface, source)
    challenge_fields(challenge)
    signature = prove(private, public, challenge)
    if time.monotonic() - started >= challenge['expires_in']:
        raise EnrollmentError('DNSmith-Anmeldeprüfung abgelaufen')
    result = transport(PATHS[1], {'version': 1, 'challenge_id': challenge['challenge_id'],
                                'public_key': public, 'proof': signature}, interface, source)
    try:
        if type(result.get('version')) is not int or result['version'] != 1 or result.get('client_public_key') != public:
            raise ValueError()
        config = validate(result['config'])
        if not config['enabled'] or not any(ipaddress.IPv4Address(config['dns']) in ipaddress.IPv4Network(net)
                                           for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
            raise ValueError()
        config['provider'] = 'dnsmith'
        return config
    except (ValueError, KeyError, TypeError):
        raise EnrollmentError('Ungültige VPN-Einstellungen von DNSmith') from None
