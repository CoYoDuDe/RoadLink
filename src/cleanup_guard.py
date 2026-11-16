"""Exact original-owner, runtime-directory and inherited-flock fence."""
import os
from pathlib import Path
import select
import signal
import stat

from ap_runtime import token


def identity(info):
    return info.st_dev, info.st_ino


class CleanupGuard:
    def __init__(self, root, pid, start, lock_fd):
        self.root = Path(root)
        self.owner = {'pid': pid, 'start': start}
        self.me = {'pid': os.getpid(), 'start': token(os.getpid())}
        self.lock_fd = lock_fd
        self.ownerfd = self.rootfd = None
        try:
            if os.getppid() != pid or token(pid) != start:
                raise RuntimeError('Cleanup guard parent changed')
            self.ownerfd = os.pidfd_open(pid)
            if token(pid) != start:
                raise RuntimeError('Cleanup controller generation changed')
            self.rootfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.root_identity = identity(os.fstat(self.rootfd))
            self.lock_identity = identity(os.fstat(lock_fd))
            self.network = identity(os.stat('/proc/self/ns/net'))
            self.held()
        except BaseException:
            self.close()
            raise

    def held(self):
        root, lock = os.fstat(self.rootfd), os.fstat(self.lock_fd)
        named_root = self.root.lstat()
        named_lock = Path(str(self.root) + '.lock').lstat()
        if (os.getpid() != self.me['pid'] or token(os.getpid()) != self.me['start']
                or identity(root) != self.root_identity or identity(named_root) != self.root_identity
                or not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid() or root.st_mode & 0o077
                or not stat.S_ISDIR(named_root.st_mode) or named_root.st_mode & 0o077
                or identity(lock) != self.lock_identity or identity(named_lock) != self.lock_identity
                or not stat.S_ISREG(lock.st_mode) or lock.st_uid != os.geteuid()
                or lock.st_mode & 0o022 or lock.st_nlink != 1
                or identity(os.stat('/proc/self/ns/net')) != self.network):
            raise RuntimeError('Cleanup ownership changed')
        rows = Path('/proc/self/fdinfo', str(self.lock_fd)).read_text().splitlines()
        if not any(row.split()[2:5] == ['FLOCK', 'ADVISORY', 'WRITE']
                   for row in rows if row.startswith('lock:')):
            raise RuntimeError('Original cleanup lock is not held')

    def stop_controller(self):
        self.held()
        if not select.select([self.ownerfd], [], [], 0)[0]:
            try:
                signal.pidfd_send_signal(self.ownerfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        # A signal alone does not prove termination. Retain the original lock
        # while a kernel-blocked controller has not actually exited.
        while not select.select([self.ownerfd], [], [], 1)[0]:
            self.held()

    def stop_mutation(self, mutation):
        self.held()
        if not mutation or token(mutation['pid']) != mutation['start']:
            return
        try:
            descriptor = os.pidfd_open(mutation['pid'])
        except ProcessLookupError:
            return
        try:
            if token(mutation['pid']) != mutation['start']:
                return
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while not select.select([descriptor], [], [], 1)[0]:
                self.held()
        finally:
            os.close(descriptor)

    def close(self):
        for name in ('ownerfd', 'rootfd'):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)
