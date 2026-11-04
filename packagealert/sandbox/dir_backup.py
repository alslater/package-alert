"""Full-fidelity backups of directories a sandboxed command recreates (a pipx app's venv).

The in-memory snapshot (backends/filesystem.py) keeps only the metadata of a file over its size
limit, so it cannot put back a venv holding a large binary. A directory the command deletes and
rebuilds is therefore copied whole beforehand, links kept as links, into a package-alert directory
no writable mount shows, with a digest of the copy; on rollback the copy replaces whatever the run
left, but only while it is exactly what was copied and the target's parent is the directory it was.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from packagealert.fs_identity import dir_identity, resolution

BACKUP_ROOT = Path.home() / ".cache" / "package-alert" / "run-backups"
# Free space kept beyond the copy itself.
_SPACE_MARGIN = 64 * 1024 * 1024


class BackupError(Exception):
    """A directory could not be backed up; the command must not run."""


@dataclass
class DirBackup:
    target: Path
    copy: Path
    """The backup directory; the copy is ``copy / "tree"``."""
    digest: str
    parent: tuple[str, int, int]
    keep: bool = False
    """Kept after the run: the restore failed, so the copy is the user's only good one."""
    outside: dict[str, tuple[tuple[str, ...], str, str]] = field(default_factory=dict)
    """Each link in the target (by its path relative to it) that passes through or ends in a
    writable path outside it: (each link it passes through, where it ends, a digest of what is
    there). The copy keeps only the link, so restore() checks these were left as they were."""
    writable: list[Path] = field(default_factory=list)
    """The resolved writable paths *outside* was judged against (track())."""


def tree_digest(root: Path) -> str:
    """A digest of everything under *root* (names, kinds, link targets, modes and contents),
    not following links. Each entry is hashed on its own, its fields length-prefixed, so no
    file's contents can stand for another entry."""

    def field(data: bytes) -> bytes:
        return len(data).to_bytes(8, "big") + data

    h = hashlib.sha256(os.lstat(root).st_mode.to_bytes(8, "big"))  # the root's own kind and mode
    for dirpath, dirnames, filenames in os.walk(root, onerror=_raise):
        dirnames.sort()
        for name in sorted([*dirnames, *filenames]):
            path = Path(dirpath) / name
            st = os.lstat(path)
            payload = hashlib.sha256()
            if stat.S_ISLNK(st.st_mode):
                payload.update(os.readlink(path).encode(errors="surrogateescape"))
            elif stat.S_ISREG(st.st_mode):
                payload.update(_file_digest(path).encode())
            entry = (field(str(path.relative_to(root)).encode(errors="surrogateescape"))
                     + st.st_mode.to_bytes(8, "big") + payload.digest())
            h.update(hashlib.sha256(entry).digest())
    return h.hexdigest()


def _raise(exc: OSError) -> None:
    """os.walk()'s onerror: a directory that cannot be listed is an error, not an empty one."""
    raise exc


def _field(data: str) -> bytes:
    raw = data.encode(errors="surrogateescape")
    return len(raw).to_bytes(8, "big") + raw


def _file_digest(path: Path | str) -> str:
    """A digest of the regular file *path*, opened without blocking or following a link (a FIFO
    or a link put in its place is no file to read); a description of what is there otherwise."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return f"unreadable ({exc.errno})"
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            return f"not a file ({stat.S_IFMT(st.st_mode):o})"
        h = hashlib.sha256()
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class _Outside:
    """Which paths are writable places outside the backed-up directory."""

    def __init__(self, target: Path, writable: list[Path]) -> None:
        self.target = Path(os.path.realpath(target))
        self.roots = [Path(os.path.realpath(w)) for w in writable]

    def __call__(self, p: Path) -> bool:
        return not p.is_relative_to(self.target) and any(p.is_relative_to(r) for r in self.roots)


def _referent_digest(path: Path, outside: _Outside, seen: set[Path]) -> str:
    """A digest of what *path* (where a link ends) holds: a file's contents, what else is there,
    or a directory's whole tree with, for each link in it, where that link leads and, when that
    is a writable place outside the target, what is there too (each place once: *seen*).
    OSError for a directory that cannot be listed or a link that cannot be resolved."""
    seen.add(path)
    if not (os.path.isdir(path) and not os.path.islink(path)):
        return _file_digest(path)
    h = hashlib.sha256(tree_digest(path).encode())
    for dirpath, dirnames, filenames in os.walk(path, onerror=_raise):
        dirnames.sort()
        for name in sorted([*dirnames, *filenames]):
            link = Path(dirpath) / name
            if not link.is_symlink():
                continue
            hops, end = resolution(link)
            h.update(_field(str(link.relative_to(path))) + b"".join(_field(str(p)) for p in (*hops, end)))
            if end not in seen and any(outside(p) for p in (*hops, end)):
                h.update(_referent_digest(end, outside, seen).encode())
    return h.hexdigest()


def _link_state(link: Path, outside: _Outside) -> tuple[tuple[str, ...], str, str]:
    """(each link *link* passes through, where it ends, a digest of what is there); OSError for a
    loop or a directory that cannot be listed."""
    hops, end = resolution(link)
    return tuple(str(h) for h in hops), str(end), _referent_digest(end, outside, set())


def _writable_referents(target: Path, writable: list[Path]) -> dict[str, tuple[tuple[str, ...], str, str]]:
    """The links in *target* that pass through or end in one of *writable* outside it
    (DirBackup.outside). OSError for a link that cannot be resolved (a loop) or a directory that
    cannot be listed."""
    outside = _Outside(target, writable)
    out: dict[str, tuple[tuple[str, ...], str, str]] = {}
    for dirpath, dirnames, filenames in os.walk(target, onerror=_raise):
        for name in (*dirnames, *filenames):
            link = Path(dirpath) / name
            if not link.is_symlink():
                continue
            hops, end = resolution(link)
            if any(outside(p) for p in (*hops, end)):
                out[str(link.relative_to(target))] = _link_state(link, outside)
    return out


def track(backup: DirBackup, writable: list[Path]) -> None:
    """Judge the backup's links against *writable*, every path the command may write (the final
    set, once the sandbox is assembled; make() takes the set known then). OSError as for
    _writable_referents()."""
    backup.outside = _writable_referents(backup.target, writable)
    backup.writable = list(writable)


def _size(root: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            st = os.lstat(Path(dirpath) / name)
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def special_file(target: Path) -> Path | None:
    """The first entry under the directory *target* that is not a regular file, directory or link
    (a FIFO, socket or device, which nothing pip installs), which a copy cannot take; None."""
    for dirpath, dirnames, filenames in os.walk(target):
        for name in (*dirnames, *filenames):
            mode = os.lstat(Path(dirpath) / name).st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                return Path(dirpath) / name
    return None


def special_file_message(path: Path) -> str:
    return (f"{path} is not a file, directory or link (a FIFO, socket or device, which nothing pip installs, "
            "so build code may have left it); remove it, then run the command again")


def space_needed(target: Path) -> int:
    """The free space a copy of the directory *target* needs: its regular files and a margin.
    OSError when it cannot be measured."""
    return _size(target) + _SPACE_MARGIN


def overlap(root: Path, writable: list[Path]) -> Path | None:
    """The first of *writable* that is, holds or lies in the backup root *root*, or None."""
    try:
        real_root = root.resolve(strict=False)
    except (OSError, RuntimeError):
        return root
    for w in writable:
        try:
            real_w = w.resolve(strict=False)
        except (OSError, RuntimeError):
            return w
        if real_root == real_w or real_root.is_relative_to(real_w) or real_w.is_relative_to(real_root):
            return w
    return None


def overlap_message(root: Path, path: Path) -> str:
    return (f"the backup directory {root} lies in {path}, which the sandbox makes writable, so the run could "
            "change the backup it would roll back to; if that is the working directory, run the command from "
            "another directory")


def make(target: Path, writable: list[Path], root: Path | None = None) -> DirBackup:
    """Copy the directory *target* whole into a fresh directory under *root* (BACKUP_ROOT).
    BackupError when *root* lies in one of the *writable* paths (the run could change the copy),
    when *target* is not a directory of its own, or when there is not room for the copy."""
    root = BACKUP_ROOT if root is None else root
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        real_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BackupError(f"cannot create the backup directory {root}: {exc}") from exc
    if (w := overlap(real_root, writable)) is not None:
        raise BackupError(overlap_message(root, w))
    parent = dir_identity(target.parent)
    if parent is None or target.is_symlink() or not target.is_dir():
        raise BackupError(f"{target} is not a directory of its own")
    try:
        if (odd := special_file(target)) is not None:
            raise BackupError(special_file_message(odd))
        need = space_needed(target)
        free = shutil.disk_usage(real_root).free
    except OSError as exc:
        raise BackupError(f"cannot measure {target} for its backup: {exc}") from exc
    if free < need:
        raise BackupError(f"not enough free space in {root} to back up {target}: needs {need // 2**20} MB, "
                          f"{free // 2**20} MB free")
    try:
        # A fresh directory of this call's own (mode 0700): a name the clock alone picks can be one
        # an earlier backup, kept after a failed restore, already has.
        copy = Path(tempfile.mkdtemp(prefix=f"{time.strftime('%Y%m%d-%H%M%S')}-", suffix=f"-{target.name}",
                                     dir=real_root))
    except OSError as exc:
        raise BackupError(f"cannot back up {target}: {exc}") from exc
    try:
        shutil.copytree(target, copy / "tree", symlinks=True)
        digest = tree_digest(copy / "tree")
        backup = DirBackup(target, copy, digest, parent)
        track(backup, writable)
    except BaseException as exc:
        # Interrupted or failed: no partial copy is left behind.
        shutil.rmtree(copy, ignore_errors=True)
        if isinstance(exc, OSError):
            raise BackupError(f"cannot back up {target}: {exc}") from exc
        raise
    return backup


def restore(backup: DirBackup) -> None:
    """Replace whatever is at the backup's target with the copy. OSError, touching nothing, when
    the target's parent is not the directory it was before the run (build code that could write
    beside it may have replaced it with a link) or the copy is not exactly what was made. OSError
    after the copy is put back when a link in it leads somewhere writable that the run changed
    (DirBackup.outside): the copy holds the link, not what it leads to."""
    if dir_identity(backup.target.parent) != backup.parent:
        raise OSError(f"{backup.target.parent} is not the directory it was before the run")
    if tree_digest(backup.copy / "tree") != backup.digest:
        raise OSError("the backup changed during the run")
    target = Path(backup.parent[0]) / backup.target.name
    if os.path.isdir(target) and not os.path.islink(target):
        shutil.rmtree(target)
    elif os.path.lexists(target):
        os.unlink(target)
    shutil.copytree(backup.copy / "tree", target, symlinks=True)
    changed = []
    outside = _Outside(target, backup.writable)
    for rel, state in backup.outside.items():
        try:
            if _link_state(target / rel, outside) != state:
                changed.append(rel)
        except OSError:
            changed.append(rel)
    if changed:
        raise OSError(f"{target} was put back, but {', '.join(changed)} links to a writable location that "
                      "changed during the run, which a backup of links cannot restore")


def discard(backup: DirBackup) -> None:
    shutil.rmtree(backup.copy, ignore_errors=True)
