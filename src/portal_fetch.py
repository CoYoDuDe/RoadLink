"""Pinned, interface-bound CAPPORT HTTPS; no cookies, credentials or native DNS."""
import ipaddress
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit
import capport
from portal_dns import remaining, resolve
from probe_binding import bind_path

MAX_BODY = 8192
MAX_WIRE = 32768


class Incomplete(ValueError):
    pass


def limits(body_limit, wire_limit):
    if (type(body_limit) is not int or type(wire_limit) is not int
            or not 1 <= body_limit <= 65536 or not body_limit + 4 <= wire_limit <= 98304):
        raise ValueError('Invalid portal response budgets')


def decode(raw, closed=False, *, body_limit=MAX_BODY, wire_limit=MAX_WIRE):
    limits(body_limit, wire_limit)
    if not isinstance(raw, bytes) or len(raw) > wire_limit: raise ValueError('Portal response too large')
    marker = raw.find(b'\r\n\r\n')
    if marker < 0:
        if len(raw) > 8192 or closed: raise ValueError('Invalid portal headers')
        raise Incomplete()
    if marker > 8192: raise ValueError('Portal headers too large')
    lines = raw[:marker].split(b'\r\n')
    match = re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?', lines[0])
    if not match or len(lines) > 65: raise ValueError('Invalid portal status')
    fields = {}
    for line in lines[1:]:
        if b':' not in line: raise ValueError('Invalid portal header')
        name, value = line.split(b':', 1)
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name): raise ValueError('Invalid header name')
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value): raise ValueError('Invalid header value')
        name = name.lower()
        if name in fields and name in (b'content-length', b'transfer-encoding', b'content-type', b'content-encoding', b'location'):
            raise ValueError('Ambiguous portal headers')
        fields.setdefault(name, value.strip())
    if fields.get(b'content-encoding', b'identity').lower() != b'identity':
        raise ValueError('Compressed portal response rejected')
    body = raw[marker+4:]
    length, transfer = fields.get(b'content-length'), fields.get(b'transfer-encoding')
    if length is not None and transfer is not None: raise ValueError('Ambiguous portal framing')
    if transfer is not None:
        if transfer.lower() != b'chunked': raise ValueError('Unsupported portal framing')
        decoded, offset = bytearray(), 0
        while True:
            end = body.find(b'\r\n', offset)
            if end < 0:
                if closed: raise ValueError('Incomplete chunk')
                raise Incomplete()
            line = body[offset:end]
            if len(line) > 128 or not re.fullmatch(rb'[0-9a-fA-F]{1,8}(?:;[\x20-\x7e]*)?', line):
                raise ValueError('Invalid chunk size')
            size = int(line.split(b';', 1)[0], 16)
            offset = end + 2
            if size == 0:
                if body[offset:offset+2] == b'\r\n': end = offset
                else: end = body.find(b'\r\n\r\n', offset)
                if end < 0:
                    if closed: raise ValueError('Incomplete chunk trailer')
                    raise Incomplete()
                # API trailers are unnecessary; refuse them instead of merging
                # content/security headers from a second interpretation.
                if end != offset or len(body) != offset+2: raise ValueError('Unexpected portal trailer/data')
                body = bytes(decoded)
                break
            if len(decoded) + size > body_limit: raise ValueError('Portal body too large')
            if len(body) < offset+size+2:
                if closed: raise ValueError('Incomplete chunk data')
                raise Incomplete()
            if body[offset+size:offset+size+2] != b'\r\n': raise ValueError('Invalid chunk ending')
            decoded.extend(body[offset:offset+size]); offset += size+2
    elif length is not None:
        if not re.fullmatch(rb'[0-9]{1,10}', length) or int(length) > body_limit: raise ValueError('Invalid portal length')
        if len(body) < int(length):
            if closed: raise ValueError('Incomplete portal body')
            raise Incomplete()
        if len(body) != int(length): raise ValueError('Trailing portal data')
    else:
        if len(body) > body_limit: raise ValueError('Portal body too large')
        if not closed: raise Incomplete()
    return {'status': int(match[1]), 'content_type': fields.get(b'content-type', b'').decode('ascii'),
            'location': fields.get(b'location', b'').decode('ascii'), 'body': body}


def request(url):
    capport.uri(url)
    parts = urlsplit(url)
    path = parts.path or '/'
    if parts.query: path += '?' + parts.query
    # Original authority is validated ASCII without credentials or fragments.
    return ('GET ' + path + ' HTTP/1.1\r\nHost: ' + parts.netloc + '\r\nAccept: ' + capport.MEDIA_TYPE
            + '\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii')


def receive(sock, check, deadline, *, body_limit=MAX_BODY, wire_limit=MAX_WIRE):
    limits(body_limit, wire_limit)
    raw = bytearray()
    while True:
        sock.settimeout(remaining(deadline, check))
        chunk = sock.recv(min(4096, wire_limit+1-len(raw)))
        raw.extend(chunk)
        try:
            value = decode(bytes(raw), closed=not chunk, body_limit=body_limit, wire_limit=wire_limit)
            check()
            return value
        except Incomplete:
            if not chunk: raise ValueError('Incomplete portal response')


def https(url, address, source, interface, mark, check, permit, deadline):
    parts = urlsplit(capport.uri(url))
    address = str(ipaddress.IPv4Address(address))
    port = parts.port or 443
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(remaining(deadline, check))
        bind_path(sock, source, interface, mark)
        with permit(sock, address, port, 'tcp'):
            sock.settimeout(remaining(deadline, check))
            sock.connect((address, port))  # Numeric pin; never getaddrinfo(hostname).
            check()
            with context.wrap_socket(sock, server_hostname=parts.hostname) as secure:
                secure.settimeout(remaining(deadline, check))
                secure.sendall(request(url))
                return receive(secure, check, deadline)


def fetch(url, lease, resolvers, vehicle_subnet, transit_subnet, interface, mark, check, permit, deadline):
    source = str(ipaddress.IPv4Interface(lease['address']).ip)
    for _ in range(3):
        parts = urlsplit(capport.uri(url))
        try: addresses = [str(ipaddress.IPv4Address(parts.hostname))]
        except ValueError:
            addresses = resolve(parts.hostname, resolvers, source, interface, mark, check, permit, deadline)['addresses']
        # Reject a mixed public/private answer rather than trying its private
        # addresses or silently accepting a rebinding response.
        if not all(capport.allowed_address(value, lease, vehicle_subnet, transit_subnet) for value in addresses):
            raise ValueError('Forbidden portal destination')
        value = None
        for address in addresses:
            check()
            try:
                value = https(url, address, source, interface, mark, check, permit, deadline)
                break
            except OSError:
                check()
        if value is None: raise ValueError('Portal HTTPS unavailable')
        if value['status'] in (301, 302, 303, 307, 308) and value['location']:
            url = capport.uri(urljoin(url, value['location']))
            continue
        if value['status'] != 200: raise ValueError('Portal API rejected request')
        return capport.response(value['body'], value['content_type'])
    raise ValueError('Too many portal redirects')
