"""Portal-only DNS: explicit resolver, bound sockets and bounded wire parsing.

The caller supplies a live connection check and a temporary socket permission.
No system resolver, search domain, cache, native route or address-family fallback.
"""
import ipaddress
import re
import secrets
import socket
import struct
import time
from probe_binding import bind_path

MAX_PACKET = 8192


class Truncated(ValueError):
    pass


def hostname(value):
    if not isinstance(value, str) or not value.isascii(): raise ValueError('Invalid DNS name')
    value = value.rstrip('.').lower()
    if not value or len(value) > 253 or not all(re.fullmatch(
            r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
        raise ValueError('Invalid DNS name')
    return value


def question(name, identifier):
    name = hostname(name)
    if type(identifier) is not int or not 0 <= identifier <= 65535: raise ValueError('Invalid query ID')
    labels = b''.join(bytes((len(label),)) + label.encode('ascii') for label in name.split('.')) + b'\x00'
    return struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', 1, 1)


def read_name(packet, offset):
    labels, seen, end, size = [], set(), None, 0
    while True:
        if offset in seen or offset >= len(packet) or len(seen) >= 128: raise ValueError('Invalid DNS compression')
        seen.add(offset)
        count = packet[offset]
        if count & 0xc0 == 0xc0:
            if offset + 1 >= len(packet): raise ValueError('Incomplete DNS pointer')
            target = ((count & 63) << 8) | packet[offset+1]
            if target < 12 or target >= offset: raise ValueError('Unsafe DNS pointer')
            if end is None: end = offset + 2
            offset = target
            continue
        if count & 0xc0: raise ValueError('Unsupported DNS label')
        offset += 1
        if count == 0: return '.'.join(labels).lower(), end if end is not None else offset
        if offset + count > len(packet): raise ValueError('Incomplete DNS label')
        label = packet[offset:offset+count].decode('ascii')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', label): raise ValueError('Invalid DNS label')
        labels.append(label)
        size += count + 1
        if size > 254: raise ValueError('DNS name too long')
        offset += count


def answer(packet, identifier, name):
    if not isinstance(packet, bytes) or not 12 <= len(packet) <= MAX_PACKET: raise ValueError('Invalid DNS packet size')
    ident, flags, questions, answers, authority, additional = struct.unpack('!6H', packet[:12])
    if (ident != identifier or not flags & 0x8000 or flags & 0x784f
            or questions != 1 or answers + authority + additional > 128):
        raise ValueError('Unrelated or failed DNS response')
    actual, offset = read_name(packet, 12)
    if actual != hostname(name) or packet[offset:offset+4] != struct.pack('!HH', 1, 1):
        raise ValueError('DNS question mismatch')
    offset += 4
    if flags & 0x0200: raise Truncated('Retry this resolver using TCP')
    records = []
    for index in range(answers + authority + additional):
        owner, offset = read_name(packet, offset)
        if offset + 10 > len(packet): raise ValueError('Incomplete DNS record')
        kind, family, ttl, size = struct.unpack('!HHIH', packet[offset:offset+10])
        offset += 10
        end = offset + size
        if end > len(packet): raise ValueError('Incomplete DNS data')
        if index < answers and family == 1 and kind in (1, 5):
            if kind == 1:
                if size != 4: raise ValueError('Invalid IPv4 DNS record')
                value = str(ipaddress.IPv4Address(packet[offset:end]))
            else:
                value, consumed = read_name(packet, offset)
                if consumed != end: raise ValueError('Invalid CNAME length')
                value = hostname(value)
            records.append((owner, kind, value, ttl))
        offset = end
    if offset != len(packet): raise ValueError('Trailing DNS data')
    current, visited, ttl = hostname(name), set(), 2**32-1
    for _ in range(9):
        if current in visited: raise ValueError('CNAME loop')
        visited.add(current)
        linked = [record for record in records if record[0] == current]
        aliases = {record[2] for record in linked if record[1] == 5}
        addresses = sorted({record[2] for record in linked if record[1] == 1})
        if len(aliases) > 1 or aliases and addresses: raise ValueError('Conflicting DNS answer')
        if linked: ttl = min(ttl, *(record[3] for record in linked))
        if addresses:
            if len(addresses) > 8: raise ValueError('Too many portal addresses')
            return {'addresses': addresses, 'ttl': ttl}
        if not aliases: raise ValueError('No linked IPv4 DNS answer')
        current = next(iter(aliases))
    raise ValueError('CNAME chain too long')


def remaining(deadline, check):
    check()
    value = deadline - time.monotonic()
    if value <= 0: raise TimeoutError('Portal request timed out')
    return min(2, value)


def exchange(request, resolver, source, interface, mark, check, permit, deadline, tcp=False):
    resolver = str(ipaddress.IPv4Address(resolver))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(remaining(deadline, check))
        bind_path(sock, source, interface, mark)
        # Permission is for this bound socket and must disappear on context exit.
        with permit(sock, resolver, 53, 'tcp' if tcp else 'udp'):
            sock.settimeout(remaining(deadline, check))
            sock.connect((resolver, 53))
            if not tcp:
                sock.send(request)
                sock.settimeout(remaining(deadline, check))
                result = sock.recv(MAX_PACKET + 1)
            else:
                sock.sendall(struct.pack('!H', len(request)) + request)
                def receive(size):
                    data = bytearray()
                    while len(data) < size:
                        sock.settimeout(remaining(deadline, check))
                        part = sock.recv(size - len(data))
                        if not part: raise ValueError('Incomplete DNS TCP response')
                        data.extend(part)
                    return bytes(data)
                size = struct.unpack('!H', receive(2))[0]
                if not 12 <= size <= MAX_PACKET: raise ValueError('DNS TCP response too large')
                result = receive(size)
            check()
            return result


def resolve(name, resolvers, source, interface, mark, check, permit, deadline):
    identifier = secrets.randbelow(65536)
    request = question(name, identifier)
    if not isinstance(resolvers, (list, tuple)) or not 1 <= len(resolvers) <= 4:
        raise ValueError('One to four explicit portal resolvers required')
    for resolver in resolvers:
        check()
        try:
            packet = exchange(request, resolver, source, interface, mark, check, permit, deadline)
            try: result = answer(packet, identifier, name)
            except Truncated:
                packet = exchange(request, resolver, source, interface, mark, check, permit, deadline, tcp=True)
                result = answer(packet, identifier, name)
            check()
            return result
        except (OSError, ValueError):
            check()  # Revocation is not permission to try another path.
    raise ValueError('Portal DNS unavailable')
