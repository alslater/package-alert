"""What a directory is and holds, read without following links past it: shared by the sandbox
(backups, the post-run scan) and the tool fixers, which must not depend on each other."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def dir_identity(path: Path) -> tuple[str, int, int] | None:
    """(real path, device, inode) of the directory *path* names; None when it is not one."""
    real = os.path.realpath(path)
    try:
        st = os.lstat(real)
    except OSError:
        return None
    return (real, st.st_dev, st.st_ino) if stat.S_ISDIR(st.st_mode) else None


def entry_names(directory: Path) -> list[str] | None:
    """The entries of *directory*, sorted ([] when it does not exist), or None when unreadable."""
    try:
        return sorted(os.listdir(directory))
    except FileNotFoundError:
        return []
    except OSError:
        return None


def resolution(path: Path) -> tuple[list[Path], Path]:
    """(each link resolving *path* passes through, at its own real location; where it ends),
    as the kernel resolves it, a component at a time. OSError for a loop. A component the kernel
    cannot pass through (missing, not a directory, or one this user cannot search, with more to
    follow) ends it there, with
    the rest kept as written: ``x/missing/../y`` does not lead to ``x/y`` until ``missing`` is
    a directory, so it is not recorded as if it did."""
    current, pending, hops = Path("/"), list(reversed(Path(os.path.abspath(path)).parts[1:])), []
    while pending:
        name = pending.pop()
        if name in ("", "."):
            continue
        if name == "..":
            current = current.parent
            continue
        candidate = current / name
        if not candidate.is_symlink():
            if pending and not (candidate.is_dir() and os.access(candidate, os.X_OK)):
                return hops, candidate.joinpath(*reversed(pending))
            current = candidate
            continue
        hops.append(candidate)
        if len(hops) > 40:  # the kernel's own limit (MAXSYMLINKS)
            raise OSError(40, "too many levels of symbolic links")
        target = Path(os.readlink(candidate))
        if target.is_absolute():
            current = Path("/")
        pending.extend(reversed(target.parts[1:] if target.is_absolute() else target.parts))
    return hops, current
