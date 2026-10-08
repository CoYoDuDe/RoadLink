"""Bounded RFC 8910/8908 metadata; this module grants no network access.

API/user portal URLs require TLS. Legacy HTTP redirects use an explicit
separate path. The future isolated fetcher must also validate TLS, destination,
lease identity and connection generation before accepting this metadata.
"""
import ipaddress
import json
import re
from urllib.parse import urlsplit, unquote

UNRESTRICTED = 'urn:ietf:params:capport:unrestricted'
MEDIA_TYPE = 'application/captive+json'


def uri(value, limit=2048, legacy_http=False):
    if (not isinstance(value, str) or not value or len(value.encode('utf-8')) > limit
            or not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or '\\' in value or any(ord(c) < 32 or ord(c) == 127 for c in unquote(value))):
        raise ValueError('Invalid captive portal URI')
    parts = urlsplit(value)
    if (parts.scheme not in (('http', 'https') if legacy_http is True else ('https',))
            or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.fragment or '%' in parts.netloc):
        raise ValueError('Unsafe captive portal URI')
    host = parts.hostname
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label)
                                      for label in host.rstrip('.').split('.')):
            raise ValueError('Invalid portal hostname')
        # Reject noncanonical numeric IP spellings interpreted by some clients.
        if host.replace('.', '').isdigit() or host.lower().startswith('0x'):
            raise ValueError('Noncanonical numeric portal host')
    if parts.port is not None and not 1 <= parts.port <= 65535:
        raise ValueError('Invalid portal port')
    return value


def api_hint(value):
    if value == UNRESTRICTED:
        return value  # Hint only; HTTPS/DNS/VPN checks still decide readiness.
    return uri(value, limit=255)


def response(body, content_type):
    if not isinstance(content_type, str) or content_type.split(';', 1)[0].strip().lower() != MEDIA_TYPE:
        raise ValueError('Unexpected captive portal media type')
    if not isinstance(body, bytes) or len(body) > 8192:
        raise ValueError('Captive portal response too large')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('Duplicate captive portal key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('Nonstandard JSON constant')
    try:
        data = json.loads(body.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid_constant)
    except RecursionError as exc:
        raise ValueError('Captive portal JSON nesting too deep') from exc
    if not isinstance(data, dict) or type(data.get('captive')) is not bool:
        raise ValueError('Captive state must be boolean')
    result = {'captive': data['captive']}
    if 'user-portal-url' in data:
        result['user_portal_url'] = uri(data['user-portal-url'])
    if 'can-extend-session' in data:
        if type(data['can-extend-session']) is not bool: raise ValueError('Invalid session extension flag')
        result['can_extend_session'] = data['can-extend-session']
    for key in ('seconds-remaining', 'bytes-remaining'):
        if key in data:
            if type(data[key]) is not int or not 0 <= data[key] <= 2**63 - 1:
                raise ValueError('Invalid captive portal session limit')
            result[key.replace('-', '_')] = data[key]
    return result  # Unknown extension fields are deliberately ignored.


def allowed_address(value, lease, vehicle_subnet, transit_subnet):
    """Only public IPv4 or the exact leased gateway, never vehicle/transit ranges."""
    address = ipaddress.IPv4Address(value)
    source = ipaddress.IPv4Interface(lease['address'])
    gateway = ipaddress.IPv4Address(lease['gateway']) if lease.get('gateway') else None
    if (address.is_loopback or address.is_unspecified or address.is_multicast
            or address.is_link_local or address.is_reserved or address == source.ip
            or any(address in ipaddress.IPv4Network(subnet) for subnet in (vehicle_subnet, transit_subnet))):
        return False
    if gateway is not None and gateway not in source.network:
        raise ValueError('Portal lease gateway outside its network')
    return bool(address.is_global or gateway is not None and address == gateway)
