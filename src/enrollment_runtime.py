"""One bounded enrollment attempt; never changes interfaces or existing VPNs."""
import os
from pathlib import Path
import stat
import sys
from enrollment import enroll, EnrollmentError
from storage import load_json, write_json
from vpn_config import CONFIG, install_if_missing, configured, enrollment_allowed
from wireguard import KEY, ensure_public_key, validate_key

ROOT = Path('/run/roadlink-enrollment')


def bootstrap_alive():
    try:
        root = Path('/run/roadlink-wan')
        owner = load_json(root / 'state.json', {})
        current = os.stat('/proc/self/ns/net')
        mounted = os.stat('/run/netns/roadlink-wan')
        guard = load_json(root / 'guard.json', {})
        controller = load_json(root / 'controller.json', {})
        status = load_json(root / 'status.json', {})
        return (current.st_ino == mounted.st_ino == owner.get('namespace_inode')
                and mounted.st_dev == owner.get('namespace_device')
                and identity_alive(guard['pid'], guard['start'])
                and identity_alive(controller['pid'], controller['start'])
                and status.get('bootstrap') is True and status.get('state') == 'LEASED'
                and not (root / 'stop').exists() and not (root / 'cleaning').exists())
    except (OSError, ValueError, KeyError):
        return False


def identity_alive(pid, start):
    try:
        fields = Path('/proc/{}/stat'.format(int(pid))).read_text().rsplit(')', 1)[1].split()
        return fields[0] != 'Z' and fields[19] == start
    except (OSError, ValueError, IndexError):
        return False


def local_keys(path=KEY):
    """Read only the root-private device key, with no symlink or type ambiguity."""
    public = ensure_public_key(path)
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 48:
            raise ValueError('Invalid device key permissions')
        private = validate_key(stream.read(48).strip())
    return private, public


def register(interface, permitted=lambda: True, path=CONFIG, keys=local_keys, request=enroll):
    if configured(path):
        return 'EXISTING'
    if not permitted():
        return 'CANCELLED'
    private, public = keys()
    config = request(private, public, interface)
    return 'READY' if install_if_missing(config, path, permitted=permitted) else (
        'EXISTING' if configured(path) else 'CANCELLED')


def main():
    import fcntl
    pid, start, interface = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    def permitted():
        request = load_json(ROOT / 'request.json', {})
        return (identity_alive(pid, start) and request.get('enabled') is True
                and enrollment_allowed()
                and request.get('pid') == pid and request.get('start') == start
                and (interface != 'disabledrlwan' or bootstrap_alive())
                and not Path('/data/setupOptions/RoadLink/SAFE_MODE').exists())
    if os.geteuid() != 0 or not permitted():
        return
    if ROOT.is_symlink():
        raise ValueError('Invalid enrollment runtime directory')
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    if interface == 'disabledrlwan':
        from ap_runtime import token
        write_json(Path('/run/roadlink-wan/enrollment.json'), {'pid': os.getpid(), 'start': token(os.getpid())})
    fd = os.open(str(ROOT / 'worker.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        def status(state, message):
            if permitted():
                write_json(ROOT / 'status.json', {'state': state, 'message': message, 'pid': pid, 'start': start,
                                                'interface': interface})
        status('REGISTERING', 'DNSmith.net wird eingerichtet')
        try:
            state = register(interface, permitted)
            status(state, {'READY': 'DNSmith.net eingerichtet', 'EXISTING': 'VPN-Einstellungen vorhanden',
                           'CANCELLED': 'Einrichtung abgebrochen'}[state])
        except EnrollmentError as error:
            status('RETRY', str(error))
        except Exception:
            status('RETRY', 'Einrichtung fehlgeschlagen; später erneut versuchen')


if __name__ == '__main__':
    main()
