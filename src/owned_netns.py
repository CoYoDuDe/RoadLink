"""Journal namespace and placeholder identity before publishing a named mount."""
import ctypes
import os
from pathlib import Path
import signal
import secrets
import re
import stat
import time
from ap_runtime import alive, token
from storage import load_json, write_json

CLONE_NEWNET = 0x40000000
MS_BIND = 4096


def syscall(name, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    if getattr(libc, name)(*args) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def create(root, state, name, pulse):
    target = Path('/run/netns') / name
    if target.exists() or target.is_symlink():
        raise RuntimeError('Namespace name already occupied')
    parent = {'pid': os.getpid(), 'start': token(os.getpid())}
    pid = os.fork()
    if pid == 0:
        try:
            write_json(root / 'namespace_creator.json', {'pid': os.getpid(), 'start': token(os.getpid())})
            if not alive(parent) or (root / 'stop').exists() or (root / 'cleaning').exists():
                os._exit(0)
            syscall('unshare', CLONE_NEWNET)
            info = Path('/proc/self/ns/net').stat()
            write_json(root / 'namespace_ready.json', {'inode': info.st_ino, 'device': info.st_dev})
            while alive(parent) and not (root / 'stop').exists() and not (root / 'cleaning').exists():
                time.sleep(.1)
        finally:
            os._exit(0)
    fd = None
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            ready = load_json(root / 'namespace_ready.json', {})
            creator = load_json(root / 'namespace_creator.json', {})
            if ready and alive(creator): break
            if (root / 'stop').exists() or not alive(load_json(root / 'guard.json', {})):
                raise RuntimeError('Namespace guard unavailable')
            pulse()
            time.sleep(.05)
        else: raise RuntimeError('Namespace creator did not become ready')
        fd = os.open('/proc/{}/ns/net'.format(pid), os.O_RDONLY)
        info = os.fstat(fd)
        if (info.st_ino, info.st_dev) != (ready['inode'], ready['device']):
            raise RuntimeError('Namespace identity changed')
        target.parent.mkdir(exist_ok=True)
        placeholder = target.parent / ('.roadlink-' + secrets.token_hex(12))
        state['namespace_placeholder_name'] = placeholder.name
        write_json(root / 'state.json', state)
        placeholder_fd = os.open(placeholder, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(placeholder_fd)
        state.update(namespace_inode=info.st_ino, namespace_device=info.st_dev,
                     namespace_placeholder_inode=placeholder.stat().st_ino,
                     namespace_placeholder_device=placeholder.stat().st_dev)
        write_json(root / 'state.json', state)
        # A crash before link leaves no public name; after link, the already
        # journalled placeholder proves ownership; after mount, nsfs does.
        if (root / 'stop').exists() or not alive(load_json(root / 'guard.json', {})):
            raise RuntimeError('Namespace guard unavailable')
        os.link(placeholder, target)  # exclusive: never overwrite another name
        syscall('mount', ('/proc/self/fd/' + str(fd)).encode(), os.fsencode(target),
                None, ctypes.c_ulong(MS_BIND), None)
        if target.stat().st_ino != info.st_ino or target.stat().st_dev != info.st_dev:
            raise RuntimeError('Namespace mount identity mismatch')
        placeholder.unlink()
    finally:
        if fd is not None: os.close(fd)
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
        os.waitpid(pid, 0)


def remove_placeholder(state, name):
    target = Path('/run/netns') / name
    if target.is_symlink(): raise RuntimeError('Foreign namespace symlink')
    if target.exists():
        info = target.stat()
        if (info.st_ino, info.st_dev) == (state.get('namespace_placeholder_inode'),
                                           state.get('namespace_placeholder_device')):
            target.unlink()
    pending = state.get('namespace_placeholder_name', '')
    if not pending: return
    if not re.fullmatch(r'\.roadlink-[0-9a-f]{24}', pending):
        raise RuntimeError('Invalid namespace placeholder identity')
    placeholder = target.parent / pending
    if placeholder.exists() or placeholder.is_symlink():
        info = placeholder.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise RuntimeError('Foreign namespace placeholder')
        if state.get('namespace_placeholder_inode') and (info.st_ino, info.st_dev) != (
                state['namespace_placeholder_inode'], state['namespace_placeholder_device']):
            raise RuntimeError('Namespace placeholder was replaced')
        placeholder.unlink()
