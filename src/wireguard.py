"""Device-local WireGuard key provisioning; private keys never leave this API."""
import base64
import binascii
import os
from pathlib import Path
import subprocess
from storage import atomic_write

KEY = Path('/data/setupOptions/RoadLink/wireguard/client.key')


def validate_key(value):
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError, binascii.Error) as error:
        raise ValueError('Invalid WireGuard key') from error
    if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
        raise ValueError('Invalid WireGuard key')
    return value


def ensure_public_key(path=KEY):
    if os.geteuid() != 0:
        raise PermissionError('Root required')
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Refusing a symlink key path')
    import fcntl
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _ensure_locked(path)


def _ensure_locked(path):
    if not path.exists():
        private = subprocess.run(['wg', 'genkey'], check=True, capture_output=True,
                                 text=True, timeout=5).stdout.strip()
        validate_key(private)
        atomic_write(path, (private + '\n').encode())
    else:
        private = validate_key(path.read_text().strip())
        os.chmod(path, 0o600)
    public = subprocess.run(['wg', 'pubkey'], input=private + '\n', check=True,
                            capture_output=True, text=True, timeout=5).stdout.strip()
    return validate_key(public)
