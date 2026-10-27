"""Reading files an install can control, without ever blocking.

An install (or the code it runs) can leave anything at a path package-alert later
reads: a lock file it rewrote, a package's own manifest or source, a cache entry.
A FIFO there blocks a plain ``open()`` until something writes to it, so a scan, a
post-install check or the daemon would hang. These helpers open with
``O_NONBLOCK``, read only a regular file, and raise :class:`NotARegularFile` (an
``OSError``) for anything else, so a caller that already treats ``OSError`` as
"unreadable" needs no other change.
"""

from __future__ import annotations

import errno
import io
import os
import stat
from pathlib import Path
from typing import BinaryIO


class NotARegularFile(OSError):
    """The path names a FIFO, socket, device or directory, not a regular file."""


def open_regular(path: Path | str, *, follow_symlinks: bool = True) -> BinaryIO:
    """Open the regular file at *path* for binary reading.

    Raises NotARegularFile for anything else, and OSError as ``open()`` would. With
    *follow_symlinks* false, a symlink at *path* itself is refused (``ELOOP``).
    """
    flags = os.O_RDONLY | os.O_NONBLOCK | (0 if follow_symlinks else os.O_NOFOLLOW)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotARegularFile(errno.EINVAL, "not a regular file", str(path))
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_bytes(path: Path | str, *, follow_symlinks: bool = True) -> bytes:
    """``Path.read_bytes()`` for a regular file only (see open_regular())."""
    with open_regular(path, follow_symlinks=follow_symlinks) as f:
        return f.read()


def read_text(path: Path | str, *, errors: str = "strict", follow_symlinks: bool = True) -> str:
    """``Path.read_text()`` (UTF-8) for a regular file only (see open_regular()), with its
    universal newlines: ``\r\n`` and ``\r`` read as ``\n``, as line-based parsers expect."""
    with io.TextIOWrapper(open_regular(path, follow_symlinks=follow_symlinks), encoding="utf-8", errors=errors) as f:
        return f.read()
