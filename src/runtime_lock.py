"""A late-starting registered child must finish before its runtime is reused."""
import errno
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
