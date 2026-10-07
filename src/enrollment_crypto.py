"""X25519 possession proof via OpenSSL; no private key in argv or disk copies."""
import base64
import hashlib
import hmac
import os
import re
import subprocess
from wireguard import validate_key


def shared_secret(private, public):
    private_raw = base64.b64decode(validate_key(private))
    public_raw = base64.b64decode(validate_key(public))
    if not hasattr(os, 'memfd_create'):
        raise RuntimeError('Anonymous key descriptors unavailable')
    handles = []
    try:
        for name, content in (
            ('roadlink-x25519-private', bytes.fromhex('302e020100300506032b656e04220420') + private_raw),
            ('roadlink-x25519-public', bytes.fromhex('302a300506032b656e032100') + public_raw),
        ):
            fd = os.memfd_create(name, os.MFD_CLOEXEC)
            handles.append(fd)
            os.write(fd, content)
            os.lseek(fd, 0, os.SEEK_SET)
        result = subprocess.run(['openssl', 'pkeyutl', '-derive', '-keyform', 'DER',
            '-inkey', '/proc/self/fd/' + str(handles[0]), '-peerform', 'DER',
            '-peerkey', '/proc/self/fd/' + str(handles[1])],
            pass_fds=tuple(handles), capture_output=True, timeout=5)
        if result.returncode or len(result.stdout) != 32 or result.stdout == bytes(32):
            raise ValueError('Enrollment key exchange rejected')
        return result.stdout
    finally:
        for fd in handles: os.close(fd)


def challenge_fields(challenge):
    if not isinstance(challenge, dict) or type(challenge.get('version')) is not int or challenge['version'] != 1:
        raise ValueError('Unsupported enrollment protocol')
    ident = challenge.get('challenge_id', '')
    if not isinstance(ident, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', ident):
        raise ValueError('Invalid enrollment challenge')
    expiry = challenge.get('expires_in')
    if type(expiry) is not int or not 1 <= expiry <= 300:
        raise ValueError('Invalid enrollment expiry')
    if not isinstance(challenge.get('nonce'), str) or not isinstance(challenge.get('server_key'), str):
        raise ValueError('Invalid enrollment keys')
    nonce = validate_key(challenge['nonce'])
    public = validate_key(challenge['server_key'])
    return ident, nonce, public


def proof(private, client_public, challenge):
    client_public = validate_key(client_public)
    ident, nonce, server_public = challenge_fields(challenge)
    shared = shared_secret(private, server_public)
    payload = ('RoadLink enrollment v1\n' + ident + '\n' + nonce + '\n' +
               client_public + '\n' + server_public).encode('utf-8')
    return base64.b64encode(hmac.new(shared, payload, hashlib.sha256).digest()).decode('ascii')
