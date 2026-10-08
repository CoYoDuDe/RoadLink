"""DNS replies only for approved, fresh portal pins. No upstream queries here."""
import ipaddress
import math
import struct
from portal_dns import hostname, read_name


def answer(packet, pins, now):
    if not isinstance(packet, bytes) or not 12 <= len(packet) <= 512:
        raise ValueError('Invalid client DNS query size')
    identifier, flags, questions, answers, authority, additional = struct.unpack('!6H', packet[:12])
    if flags & 0xf840 or questions != 1 or answers or authority or additional > 1:
        raise ValueError('Unsupported client DNS query')
    name, offset = read_name(packet, 12)
    name = hostname(name)
    if offset+4 > len(packet): raise ValueError('Incomplete client DNS question')
    kind, family = struct.unpack('!HH', packet[offset:offset+4])
    end = offset+4
    # A single EDNS OPT record is accepted without forwarding options such as
    # client-subnet/cookies or identity data. No EDNS data enters the reply.
    if additional:
        owner, cursor = read_name(packet, end)
        if owner or cursor+10 > len(packet): raise ValueError('Invalid client EDNS')
        record_kind, _, _, size = struct.unpack('!HHIH', packet[cursor:cursor+10])
        if record_kind != 41 or cursor+10+size != len(packet): raise ValueError('Invalid client EDNS size')
    elif end != len(packet): raise ValueError('Trailing client DNS data')
    if family != 1: raise ValueError('Unsupported client DNS class')
    record = pins.get(name)
    valid = False
    if isinstance(record, dict):
        expires = record.get('expires')
        valid = type(expires) in (int, float) and math.isfinite(expires) and 0 < expires-now <= 60
    addresses = record.get('addresses', []) if valid else []
    if valid and (not isinstance(addresses, list) or not 1 <= len(addresses) <= 8):
        raise ValueError('Invalid approved portal pins')
    addresses = list(dict.fromkeys(str(ipaddress.IPv4Address(value)) for value in addresses))
    # Unknown/expired names get NXDOMAIN locally, not foreign DNS fallbacks.
    code = 0 if valid else 3
    replies = []
    if valid and kind == 1:
        original_ttl = record.get('ttl', 15)
        if type(original_ttl) is not int or original_ttl < 0: raise ValueError('Invalid approved DNS TTL')
        ttl = max(0, min(original_ttl, 15, int(record['expires']-now)))
        replies = [b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, ttl, 4)+ipaddress.IPv4Address(value).packed
                   for value in addresses]
    header = struct.pack('!6H', identifier, 0x8080 | (flags & 0x0100) | code, 1, len(replies), 0, 0)
    return header+packet[12:end]+b''.join(replies)
