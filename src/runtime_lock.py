"""A late-starting registered child must finish before its runtime is reused."""
import errno
import json
import os
from pathlib import Path
import stat


def busy(root):
    import fcntl
    path = Path(str(root) + '.lock')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Unsafe runtime lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EAGAIN, errno.EACCES): raise
            return True
        return False
    finally:
        os.close(fd)


def cleanup_ready(root):
    """Advisory start gate; the worker still acquires/revalidates its lock.

    Missing runtime means first start. An existing runtime needs an explicit
    cleanup receipt; a missing/invalid receipt must never cause a spawn loop.
    This function neither repairs a journal nor declares resources unowned.
    """
    root = Path(root)
    try:
        info = root.lstat()
    except FileNotFoundError:
        return True
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        return False
    directory = descriptor = None
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        held = os.fstat(directory)
        if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
            return False
        descriptor = os.open('result.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
        result = os.fstat(descriptor)
        if (not stat.S_ISREG(result.st_mode) or result.st_uid != os.geteuid()
                or result.st_mode & 0o022 or result.st_nlink != 1 or result.st_size > 65536):
            return False
        raw = os.read(descriptor, 65537)
        if len(raw) > 65536:
            return False
        value = json.loads(raw)
        named = os.stat('result.json', dir_fd=directory, follow_symlinks=False)
        current = root.lstat()
        return (isinstance(value, dict) and value.get('cleaned') is True
                and (result.st_dev, result.st_ino, result.st_size, result.st_mtime_ns)
                == (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns)
                and (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino))
    except (OSError, ValueError, TypeError):
        return False
    finally:
        if descriptor is not None: os.close(descriptor)
        if directory is not None: os.close(directory)


# Guard retry backport; caller supplies its original process identity API.
import fcntl
import time

def wait_stopped(identity, is_alive):
    """Sending a signal is insufficient evidence that mutation has stopped."""
    deadline = time.monotonic() + 3
    while is_alive(identity) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not is_alive(identity)

class ChildrenNotStopped(RuntimeError):
    """An exactly registered child has not completed its termination yet."""

class ParentNameOccupied(RuntimeError):
    """The owned radio is intact, but hotplug occupies its original name.

    Never rename the foreign device or select a different restoration name.
    The original cleanup guard must retain ownership until that name is free.
    """

def cleanup_with_retry(root, cleanup, owner, lock_fd, *, wait_for_controller=False, is_alive, start_token):
    """Keep the guard's lock across timeouts, child drain and name collisions.

    Only the same guard may retry its controller's cleanup. A command
    timeout comes from subprocess.run, which kills and reaps before raising.
    Incomplete ownership checks and other errors remain failures; they never
    manufacture a successful cleanup receipt.
    """
    import logging
    import subprocess
    from storage import load_json, write_json
    if type(wait_for_controller) is not bool:
        raise ValueError('Exact controller-drain policy required')

    class ControllerNotStopped(RuntimeError):
        """Guard has requested termination, but its controller still lives."""
    root = Path(root)
    initial = root.lstat()
    me = {'pid': os.getpid(), 'start': start_token(os.getpid())}
    attempts = 0
    first_failure = None

    def held(allow_running=False):
        current = root.lstat()
        descriptor = os.fstat(lock_fd)
        named = Path(str(root) + '.lock').lstat()
        if not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid() or current.st_mode & 63 or ((initial.st_dev, initial.st_ino) != (current.st_dev, current.st_ino)) or (not stat.S_ISREG(descriptor.st_mode)) or (descriptor.st_uid != os.geteuid()) or (descriptor.st_mode & 18) or (descriptor.st_nlink != 1) or stat.S_ISLNK(named.st_mode) or ((descriptor.st_dev, descriptor.st_ino) != (named.st_dev, named.st_ino)):
            raise RuntimeError('Cleanup runtime or lock identity changed')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not me['start'] or load_json(root / 'guard.json', {}) != me or load_json(root / 'controller.json', {}) != owner or (owner.get('pid') == me['pid']) or (not allow_running and is_alive(owner)):
            raise RuntimeError('Cleanup requires the original guard and stopped controller')
    while True:
        held(allow_running=wait_for_controller)
        try:
            if wait_for_controller and (not wait_stopped(owner, is_alive)):
                raise ControllerNotStopped('Original controller termination pending')
            held()
            cleanup()
        except (subprocess.TimeoutExpired, ChildrenNotStopped, ParentNameOccupied, ControllerNotStopped) as error:
            held(allow_running=isinstance(error, ControllerNotStopped))
            attempts += 1
            if first_failure is None:
                first_failure = time.monotonic()
            delay = (1, 5, 15, 30)[min(attempts - 1, 3)]
            kind = 'command_timeout' if isinstance(error, subprocess.TimeoutExpired) else 'controller_drain' if isinstance(error, ControllerNotStopped) else 'parent_name_busy' if isinstance(error, ParentNameOccupied) else 'child_drain'
            write_json(root / 'result.json', {'cleaned': False, 'errors': ['Cleanup pending; original guard retains lock']})
            status = load_json(root / 'status.json', {})
            write_json(root / 'status.json', dict(status, state='CLEANUP_FAILED', internet=False, dns_ready=False, retrying=True))
            write_json(root / 'cleanup-fault.json', {'kind': kind, 'attempts': attempts, 'first_checked_at': first_failure, 'checked_at': time.monotonic(), 'retry_after': delay, 'guard': me, 'owner': owner})
            logging.warning('Network cleanup %s; original guard retains lock (attempt %d)', kind, attempts)
            time.sleep(delay)
            continue
        held()
        return load_json(root / 'result.json', {})
