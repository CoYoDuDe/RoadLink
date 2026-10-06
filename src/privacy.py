"""Privacy primitives; these do not change live interfaces."""
import hashlib
import hmac
import re


def profile_mac(seed, profile_id):
    if not isinstance(seed, bytes) or len(seed) < 32:
        raise ValueError('A private random seed of at least 32 bytes is required')
    if not isinstance(profile_id, str) or not 1 <= len(profile_id) <= 128:
        raise ValueError('Invalid profile ID')
    digest = bytearray(hmac.new(seed, ('RoadLink WAN MAC v1:' + profile_id).encode(), hashlib.sha256).digest()[:6])
    digest[0] = (digest[0] | 2) & 0xfe  # Locally administered unicast address.
    return ':'.join('{:02x}'.format(value) for value in digest)


def validate_mac(value):
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
        raise ValueError('Invalid MAC address')
    raw = bytes.fromhex(value.replace(':', ''))
    if raw[0] & 1 or raw == bytes(6):
        raise ValueError('A unicast device MAC is required')
    return value.lower()
