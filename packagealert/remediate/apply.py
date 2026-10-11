"""``pa fix --apply``: write a verified plan's lock (and manifest) changes into the project."""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import errno
import logging
import os
import shutil
import stat
import tempfile
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, cast

from packagealert.remediate.adapter import ApplyRefused

if TYPE_CHECKING:
    from packagealert.remediate.adapter import TrialRunner
    from packagealert.remediate.planner import FixPlan

log = logging.getLogger(__name__)


def read_regular_file(path: Path) -> bytes | None:
    """*path*'s bytes when it is a regular file (never followed through a symlink), else None."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


def open_regular_beneath(root_fd: int, name: str) -> int | None:
    """A read-only descriptor for the regular file *name* beneath the directory *root_fd*, or None.

    Every component is opened relative to the one before it without following
    a symlink, so nothing outside *root_fd* is reached however the tree changes
    meanwhile; a symlink, a non-regular file, or a missing one gives None. *name*
    must be relative with no ``..`` part (``is_project_file_name``).
    """
    parts = Path(name).parts
    dir_fd = root_fd
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            if dir_fd != root_fd:
                os.close(dir_fd)
            dir_fd = nxt
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError:
        return None
    finally:
        if dir_fd != root_fd:
            os.close(dir_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None
    return fd


def read_regular_beneath(root: Path, name: str) -> bytes | None:
    """*name*'s bytes when it is a regular file beneath *root*, reached with no symlink (``open_regular_beneath``)."""
    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return None
    try:
        fd = open_regular_beneath(root_fd, name)
    finally:
        os.close(root_fd)
    if fd is None:
        return None
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


_TEMP_SUFFIX = ".pa-fix"
_live_temporaries: set[str] = set()
"""The names of the temporary files the write in progress has made in the project directory."""


def is_own_temporary(name: str) -> bool:
    """Whether *name* (a path relative to the project) is one of the temporary files the
    write in progress has made beside its targets: exactly those names, at the top level,
    and only until that write finishes, so a project file that merely looks like one (or
    one an interrupted run left behind) is never taken for it."""
    return "/" not in name and name in _live_temporaries


def _temporary_beside(target: Path) -> str:
    """A new, empty hidden file beside *target* (``.<name>.<random>.pa-fix``), recorded as
    the write's own; its path."""
    fd, path = tempfile.mkstemp(prefix=f".{target.name}.", suffix=_TEMP_SUFFIX, dir=target.parent)
    os.close(fd)
    _live_temporaries.add(Path(path).name)
    return path


APPLY_HOOKS = ("apply_files", "apply_steps", "written_files", "versions_in", "lockfile_name")


def can_apply(adapter: object) -> bool:
    """Whether *adapter* has every member ``apply_plan`` uses."""
    return all(hasattr(adapter, h) for h in APPLY_HOOKS)


def refusal(adapter: object, plan: FixPlan) -> str | None:
    """Why *plan* cannot be applied with *adapter* before anything runs, or None."""
    name = getattr(adapter, "name", "this")
    try:
        applicable = can_apply(adapter)
    except Exception as exc:
        log.warning("the %s adapter's apply members could not be read", name, exc_info=True)
        return f"the {name} adapter cannot apply fixes ({exc}); run the printed commands"
    if not applicable:
        return f"the {name} adapter cannot apply fixes; run the printed commands"
    if plan.verified_after is None:
        return "verification did not record what the fix leaves in the lock file; run the printed commands"
    return None


def checked_files(adapter: Any) -> tuple[str, ...]:
    """The files a snapshot records: ``written_files`` then any further ``stale_files`` (which default to them)."""
    written = tuple(adapter.written_files)
    stale = tuple(getattr(adapter, "stale_files", written))
    return tuple(dict.fromkeys((*written, *stale)))


def is_project_file_name(name: object) -> bool:
    """Whether *name* is a non-empty, relative file name with no ``..`` part and no NUL
    (which no path can hold: file I/O on it raises ValueError, not OSError)."""
    if not isinstance(name, str) or not name or "\0" in name:
        return False
    rel = Path(name)
    return not rel.is_absolute() and ".." not in rel.parts


@dataclass(frozen=True)
class Snapshot:
    files: dict[str, bytes | None]
    """Each checked file's bytes when planning started (None: absent or not a regular file)."""
    entries: dict[str, str | None] = field(default_factory=dict)
    """What each checked name was when it was not a regular file (``_entry()``):
    None when absent, so a name absent at planning must still be absent and a
    symlink must still point where it did."""
    inputs: dict[str, str] | None = None
    """Every file the re-resolve copies (the adapter's ``apply_files``), by
    ``_digest()``, when it was recorded; a digest rather than the bytes, since a
    git-tracked copy can hold thousands of files. The copy must then hold the
    same files, each unchanged."""
    root: tuple[int, int] | None = None
    """The project directory's (device, inode) when it was recorded: the apply writes only
    into that same directory."""


def copy_mode(st_mode: int) -> int:
    """The permission bits a scratch copy of a file with *st_mode* gets: its own, without
    set-id or sticky bits, and always readable and writable by the owner (the re-lock
    rewrites the copy). An executable build helper stays executable."""
    return (stat.S_IMODE(st_mode) & 0o777) | 0o600


def _digest(path: Path) -> str:
    """*path*'s SHA-256 and the mode a copy of it keeps (``copy_mode``) when it is a regular
    file (never through a symlink), else what it is (``_entry()``)."""
    import hashlib

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return f"entry {_entry(path)}"
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            return f"entry {_entry(path)}"
        return f"sha256 {hashlib.file_digest(fh, 'sha256').hexdigest()} mode {copy_mode(st.st_mode):o}"


def _entry(path: Path) -> str | None:
    """What *path* is when it is not a regular file read through ``read_regular_file``:
    None when absent or a readable regular file, else a symlink's target, the kind of
    entry, or that a regular file cannot be opened (never mistaken for an absent one)."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"unreadable ({exc.errno})"
    if stat.S_ISREG(st.st_mode):
        try:
            os.close(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK))
        except FileNotFoundError:
            return None
        except OSError as exc:
            return f"unreadable regular file ({exc.errno})"
        return None
    if stat.S_ISLNK(st.st_mode):
        try:
            return f"symlink to {os.readlink(path)}"
        except OSError as exc:
            return f"symlink ({exc.errno})"
    return f"mode {stat.S_IFMT(st.st_mode):o}"


def snapshot(project_dir: Path, names: Iterable[str], inputs: Iterable[str] | None = None) -> Snapshot:
    """*names*' bytes and entries, and, when given, a digest of every input the re-resolve copies."""
    names = list(names)
    return Snapshot({n: read_regular_file(project_dir / n) for n in names},
                    {n: _entry(project_dir / n) for n in names},
                    None if inputs is None else {n: _digest(project_dir / n) for n in inputs},
                    _dir_identity(project_dir))


def _dir_identity(path: Path | str) -> tuple[int, int] | None:
    """*path*'s (device, inode), or None when it cannot be read."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_dev, st.st_ino


def _unchanged(project: Path, name: str, snap: Snapshot) -> bool:
    """Whether *name* is now what *snap* recorded: the same bytes, or the same absent or
    non-regular entry; an input (whose digest also holds the mode a copy keeps), the same digest."""
    if snap.inputs is not None and name in snap.inputs and _digest(project / name) != snap.inputs[name]:
        return False
    if name not in snap.files and snap.inputs is not None and name in snap.inputs:
        return True
    return (read_regular_file(project / name) == snap.files.get(name)
            and _entry(project / name) == snap.entries.get(name))


def copy_is_snapshot(files: Iterable[str], snap: Snapshot) -> Callable[[Path], None]:
    """A first step for the re-resolve: refuse unless the scratch copy holds exactly what
    *snap* recorded for each of *files* (bytes, or an input's digest).

    The copy is taken from the live project, so a file changed only while it was
    being copied, and changed back before the later checks, would otherwise steer
    the re-resolve unseen. A file *snap* did not record cannot be checked, and refuses.
    """
    names = list(files)

    def check(copy: Path) -> None:
        for n in names:
            recorded = n in snap.files or (snap.inputs is not None and n in snap.inputs)
            same = (recorded
                    and (n not in snap.files or read_regular_file(copy / n) == snap.files[n])
                    and (snap.inputs is None or n not in snap.inputs or _digest(copy / n) == snap.inputs[n]))
            if not same:
                raise ApplyRefused("the project changed while pa fix was running; run it again")

    return check


@dataclass(frozen=True)
class VersionChange:
    package: str
    before: tuple[str, ...]
    after: tuple[str, ...]


@dataclass(frozen=True)
class ApplyResult:
    applied: bool
    reason: str | None = None
    written: tuple[str, ...] = ()
    backup: Path | None = None
    changes: tuple[VersionChange, ...] = ()
    interrupted: BaseException | None = None
    """A KeyboardInterrupt or cancellation that stopped the apply: before anything was
    written, during a write whose every file was put back, or during one that left a
    file it could not put back (with the backup); the caller reports the result and
    then re-raises it."""


def _last_line(text: str) -> str:
    return next((ln.strip() for ln in reversed(text.splitlines()) if ln.strip()), "")


def _fmt(versions: frozenset[str]) -> str:
    return ", ".join(sorted(versions)) or "none"


def _differences(expected: Mapping[str, frozenset[str]], actual: Mapping[str, frozenset[str]]) -> list[str]:
    out = []
    for name in sorted(expected.keys() | actual.keys()):
        e, a = expected.get(name, frozenset()), actual.get(name, frozenset())
        if e != a:
            out.append(f"{name}: verified {_fmt(e)}, re-resolved {_fmt(a)}")
    return out


def _changes(before: Mapping[str, frozenset[str]], after: Mapping[str, frozenset[str]]) -> tuple[VersionChange, ...]:
    return tuple(
        VersionChange(name, tuple(sorted(before.get(name, frozenset()))), tuple(sorted(after.get(name, frozenset()))))
        for name in sorted(before.keys() | after.keys())
        if before.get(name, frozenset()) != after.get(name, frozenset())
    )


def _backup(root: Path, originals: Mapping[str, bytes], stamp: str) -> Path:
    """Write *originals* to a new directory under *root* named *stamp* (suffixed when taken).

    If a file cannot be written, or the write is interrupted, the new directory
    is removed again before the error propagates: nothing has been applied, and
    a partial backup would only mislead.
    """
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    target, n = root / stamp, 0
    while True:
        try:
            target.mkdir(mode=0o700)
            break
        except FileExistsError:
            n += 1
            target = root / f"{stamp}-{n}"
    try:
        for name, data in originals.items():
            # A project-relative name can be nested; it keeps its path under the backup,
            # each level created private (mkdir's parents=True ignores the mode for them).
            level = target
            for part in Path(name).parent.parts:
                level = level / part
                level.mkdir(mode=0o700, exist_ok=True)
            (target / name).write_bytes(data)
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise
    return target


_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
_renameat2: Any = None


def _rename2(src: str | Path, dst: str | Path, flags: int) -> bool:
    """``renameat2(src, dst, flags)``: True when done, False when this system or filesystem
    does not support the flag (the caller then falls back). Raises OSError otherwise."""
    global _renameat2
    if _renameat2 is None:
        import ctypes

        try:
            fn = ctypes.CDLL(None, use_errno=True).renameat2
        except (OSError, AttributeError):
            _renameat2 = False
            return False
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        _renameat2 = fn
    if _renameat2 is False:
        return False
    import ctypes

    at_fdcwd = -100
    if _renameat2(at_fdcwd, os.fsencode(src), at_fdcwd, os.fsencode(dst), flags) == 0:
        return True
    err = ctypes.get_errno()
    if err in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
        return False
    raise OSError(err, os.strerror(err), str(dst))


class _NoAtomicRename(OSError):
    """The filesystem cannot rename atomically (no renameat2 exchange or no-replace), so a
    write could only check and then rename, which another writer could slip between."""

    def __init__(self, target: Path) -> None:
        super().__init__(f"the filesystem holding {target.name} cannot rename atomically "
                         "(renameat2 is unsupported); run the printed commands")


def _mode(path: Path | str) -> int | None:
    """*path*'s permission bits (never through a symlink), or None when it cannot be read."""
    try:
        return stat.S_IMODE(os.lstat(path).st_mode)
    except OSError:
        return None


def _swap_in(new: str, target: Path, expected: bytes | None, mode: int | None = None) -> None:
    """Put the file at *new* in place of *target*, atomically against whatever is at *target*.

    *expected* is what *target* must hold: its bytes, or None for "absent";
    *mode*, when given, the permission bits it must still have. The
    files are exchanged in one step and the displaced one is checked afterwards;
    when it is not *expected* (or has another mode), they are exchanged back (the other writer's file
    is kept) and ``_ProjectChanged`` is raised. An absent target is created
    without replacing anything that appeared meanwhile. After success *new*
    holds the displaced file (for the caller to remove). A filesystem without
    renameat2 raises ``_NoAtomicRename``: a check and a separate rename could
    overwrite a change landing between them.
    """
    if expected is None:
        try:
            if _rename2(new, target, _RENAME_NOREPLACE):
                return
        except FileExistsError:
            raise _ProjectChanged from None
        raise _NoAtomicRename(target)
    placing = read_regular_file(Path(new))
    if not _rename2(new, target, _RENAME_EXCHANGE):
        raise _NoAtomicRename(target)
    if read_regular_file(Path(new)) != expected or (mode is not None and _mode(new) != mode):
        _put_back(new, target, placing)
        raise _ProjectChanged


class _InterruptedUnrestored(OSError):
    """An interruption stopped the write, and the rollback could not put every file back.

    Raised in place of the interruption so the backup can still be reported;
    ``interruption`` is re-raised by the caller once it has.
    """

    def __init__(self, message: str, interruption: BaseException) -> None:
        super().__init__(message)
        self.interruption = interruption


class _InterruptedRestored(Exception):
    """An interruption stopped the write, and the rollback then put every file back.

    Raised in place of the interruption only once the rollback has finished, so
    the caller knows the project is as it was; ``interruption`` is re-raised by
    the caller once it has reported that. An interruption that reaches the caller
    any other way (during the rollback, or after every rename succeeded) leaves
    the project's state unknown.
    """

    def __init__(self, interruption: BaseException) -> None:
        super().__init__("interrupted while writing; every file was put back")
        self.interruption = interruption


class _DisplacedKept(OSError):
    """Another writer's file was displaced and could not be returned to its path; it is kept
    at ``path`` instead (never removed with the temporary files)."""

    def __init__(self, name: str, path: str) -> None:
        super().__init__(f"{name} changed while it was being replaced and could not be put back; "
                         f"that version is kept at {path}")
        self.path = path


def _put_back(displaced: str, target: Path, ours: bytes | None) -> None:
    """Return another writer's *displaced* file to *target* after an exchange found it there.

    *ours* is what this write had just put at *target*. Exchanged back when
    possible: what that exchange brings out must be *ours*, and anything else
    (a further writer's version, landing just before it) is kept rather than
    removed with the temporary files. Put back without replacing anything when
    the target has gone meanwhile. Whatever cannot go back, or came out instead
    of *ours*, is moved to a uniquely named file beside the target, never to be
    removed, and ``_DisplacedKept`` names it.
    """
    for flags in (_RENAME_EXCHANGE, _RENAME_NOREPLACE):
        try:
            if _rename2(displaced, target, flags):
                if flags == _RENAME_NOREPLACE or read_regular_file(Path(displaced)) == ours:
                    return
                break  # *displaced* now holds a further writer's version: keep it
        except OSError:
            log.warning("could not put %s back with renameat2 flags %d", target, flags, exc_info=True)
    _keep_aside(displaced, target)


def _keep_aside(displaced: str, target: Path) -> NoReturn:
    """Keep another writer's *displaced* file, which cannot go back to *target*, beside it
    under a visible, unique name that nothing removes; ``_DisplacedKept`` names where."""
    raise _DisplacedKept(target.name, _set_aside(displaced, target))


def _discard_temporary(tmp: str, target: Path, known: Iterable[bytes | None]) -> None:
    """Remove the temporary file *tmp* beside *target* while it holds content this write
    accounts for (*known*); anything else (a version an interrupted exchange displaced into
    it) is kept beside the target under a visible name instead."""
    if not os.path.lexists(tmp):
        return
    if read_regular_file(Path(tmp)) in tuple(known):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    else:
        log.warning("keeping a version of %s found while writing it at %s", target.name, _set_aside(tmp, target))


def _set_aside(displaced: str, target: Path) -> str:
    """Move *displaced* beside *target* under a visible, unique name (``<name>.kept-*``) that
    nothing removes; where it is (where it was, if it could not be moved)."""
    kept = None
    try:
        fd, kept = tempfile.mkstemp(prefix=f"{target.name}.kept-", dir=target.parent)
        os.close(fd)
        os.replace(displaced, kept)
    except OSError:
        if kept is not None:  # the name reserved for it, still empty
            with contextlib.suppress(OSError):
                os.unlink(kept)
        log.exception("could not keep the displaced %s aside; it is at %s", target, displaced)
        return displaced
    return kept


def _take_out(target: Path, expected: bytes, mode: int | None = None) -> None:
    """Remove *target*, a file this write created, only while it still holds *expected*
    (and, when given, still has permission bits *mode*).

    It is moved aside first (atomically, without replacing anything) and only
    removed once the moved file is confirmed to be *expected*; anything else is
    put back and ``_ProjectChanged`` is raised. A filesystem without renameat2
    raises ``_NoAtomicRename``.
    """
    aside = _temporary_beside(target)
    os.unlink(aside)
    if not _rename2(target, aside, _RENAME_NOREPLACE):
        raise _NoAtomicRename(target)
    if read_regular_file(Path(aside)) != expected or (mode is not None and _mode(aside) != mode):
        # Another writer's file: back to the target if nothing has replaced it meanwhile,
        # else kept beside it and named (never left under the hidden temporary name).
        try:
            if _rename2(aside, target, _RENAME_NOREPLACE):
                raise _ProjectChanged
        except OSError:
            log.warning("could not put %s back after a removal", target, exc_info=True)
        _keep_aside(aside, target)
    os.unlink(aside)


def _write_temp(target: Path, data: bytes, mode: int) -> str:
    """Write *data* to a new temporary file beside *target* with permission bits *mode*; return its path."""
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=_TEMP_SUFFIX, dir=target.parent)
    _live_temporaries.add(Path(tmp).name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return tmp


class _ProjectChanged(Exception):
    """A checked project file changed while the new files were being written."""


def _write_all(project: Path, files: Mapping[str, bytes], originals: Mapping[str, bytes | None],
               unchanged: Callable[[str], bool] | None = None, checked: Iterable[str] = (),
               same_inputs: Callable[[], bool] | None = None) -> None:
    """``_writing()``, forgetting the temporary files it made (``is_own_temporary``) once it ends."""
    before = set(_live_temporaries)
    try:
        _writing(project, files, originals, unchanged, checked, same_inputs)
    finally:
        _live_temporaries.intersection_update(before)


def _writing(project: Path, files: Mapping[str, bytes], originals: Mapping[str, bytes | None],
             unchanged: Callable[[str], bool] | None = None, checked: Iterable[str] = (),
             same_inputs: Callable[[], bool] | None = None) -> None:
    """Replace each of *files* atomically; if a later replace fails, put the earlier ones back.

    Every temporary file is written (keeping the original's permission bits)
    before any is renamed into place, so a failure while writing leaves the
    project untouched. Immediately before each rename, *unchanged* is asked
    about every name in *checked* (and in *files*) not renamed yet, and
    *same_inputs* whether the list of inputs is still the recorded one; every
    file already renamed must also still hold the bytes and the permission bits
    written here, and every file not renamed yet the permission bits its
    temporary file was given (the rename checks them too), so a chmod meanwhile
    is neither undone nor reported as applied. All of
    it is checked once more after the last rename. When any check fails, the renames
    already made are put back and ``_ProjectChanged`` is raised, so a change
    made while writing is never overwritten and never reported as applied. A target that exists but is not a regular file is
    refused. Rolling back replaces each file with its original through a
    temporary file (removed again if that replace fails), and removes a file
    that did not exist before, but only while the file still holds the bytes
    and mode written here: one rewritten or chmodded by someone else since is
    kept and reported as not restored. Raises OSError, naming any file that could not
    be put back.
    """
    if any(not is_project_file_name(n) or len(Path(n).parts) != 1 for n in files):
        raise ValueError(f"only files directly in {project} are written: {sorted(files)}")
    temps: list[tuple[str, str]] = []
    modes: dict[str, int] = {}
    given: dict[str, int] = {}
    kept_aside: set[str] = set()
    try:
        for name, data in files.items():
            target = project / name
            try:
                st = target.lstat()
            except FileNotFoundError:
                mode = 0o644
            else:
                if not stat.S_ISREG(st.st_mode):
                    raise OSError(f"{name} is not a regular file")
                mode = modes[name] = stat.S_IMODE(st.st_mode)
            given[name] = mode
            temps.append((name, _write_temp(target, data, mode)))
        watched = tuple(dict.fromkeys((*checked, *files)))
        done: list[str] = []
        # The file being swapped in: an interruption can land once its exchange is made but
        # before it is recorded in done, so the rollback checks it by its content.
        in_flight: str | None = None

        def ours_intact() -> bool:
            """Whether every file renamed so far still holds the bytes, and has the mode, written here."""
            return all(read_regular_file(project / d) == files[d] and _mode(project / d) == given[d]
                       for d in done)

        def still_as_planned() -> bool:
            """Every check at once: the renamed files still hold the bytes written here,
            every other checked file is unchanged, and the input list is the same."""
            return (ours_intact()
                    and all(_mode(project / n) == m for n, m in modes.items() if n not in done)
                    and (unchanged is None or all(unchanged(n) for n in watched if n not in done))
                    and (same_inputs is None or same_inputs()))

        try:
            for name, tmp in temps:
                if not still_as_planned():
                    raise _ProjectChanged
                # The rename itself checks the target too: a change landing after the
                # check above is swapped back rather than overwritten.
                in_flight = name
                try:
                    _swap_in(tmp, project / name, originals.get(name), modes.get(name))
                except _DisplacedKept as kept:
                    in_flight = None  # _swap_in dealt with what it displaced itself
                    kept_aside.add(kept.path)
                    raise
                except (_ProjectChanged, _NoAtomicRename):
                    in_flight = None  # nothing exchanged, or exchanged back by _swap_in itself
                    raise
                done.append(name)
                in_flight = None
            if not still_as_planned():
                raise _ProjectChanged
        except BaseException as exc:
            # Any stop between renames is undone first, a KeyboardInterrupt or a
            # cancelled task included; an interruption is then re-raised as it was.
            unrestored = []
            if in_flight is not None and in_flight not in done:
                target = project / in_flight
                if read_regular_file(target) == files[in_flight] and _mode(target) == given[in_flight]:
                    # Its exchange was made but what it displaced was never checked: a new
                    # file is removed like the rest, and a replaced one gets back exactly
                    # what was there (the snapshot's version or another writer's).
                    if originals.get(in_flight) is None:
                        done.append(in_flight)
                    else:
                        try:
                            _put_back(dict(temps)[in_flight], target, files[in_flight])
                        except _DisplacedKept as kept:
                            kept_aside.add(kept.path)
                            log.warning("not restoring %s: %s", in_flight, kept)
                            unrestored.append(f"{in_flight} (the version found there is kept at {kept.path})")
                elif read_regular_file(Path(dict(temps)[in_flight])) != files[in_flight]:
                    # Its temporary file no longer holds the new version, so the exchange was
                    # made, and the target has changed since: what to put back is unknown.
                    log.warning("not restoring %s: it changed while it was being written", in_flight)
                    unrestored.append(in_flight)
            for name in done:
                target = project / name
                original = originals.get(name)
                if read_regular_file(target) != files[name] or _mode(target) != given[name]:
                    # Rewritten or chmodded by someone else since it was renamed into place:
                    # theirs is kept, and it is reported as not restored (the backup holds the original).
                    log.warning("not restoring %s: it changed after it was written", name)
                    unrestored.append(name)
                    continue
                try:
                    if original is None:
                        _take_out(target, files[name], given[name])
                    else:
                        back = _write_temp(target, original, given[name])
                        try:
                            _swap_in(back, target, files[name], given[name])
                        except _DisplacedKept as kept:
                            kept_aside.add(kept.path)
                            raise
                        finally:
                            if back not in kept_aside:
                                # Unused, it holds the original; exchanged, what it displaced.
                                _discard_temporary(back, target, (original, files[name]))
                except _DisplacedKept as kept:
                    log.warning("not restoring %s: %s", name, kept)
                    unrestored.append(f"{name} (the version found there is kept at {kept.path})")
                except _ProjectChanged:
                    log.warning("not restoring %s: it changed after it was written", name)
                    unrestored.append(name)
                except OSError:
                    log.warning("could not restore %s after a failed write", name, exc_info=True)
                    unrestored.append(name)
            if unrestored and isinstance(exc, (OSError, _ProjectChanged)):
                what = "the project changed while pa fix was running" if isinstance(exc, _ProjectChanged) else exc
                raise OSError(f"{what}; {', '.join(unrestored)} could not be restored") from exc
            if unrestored:
                raise _InterruptedUnrestored(
                    f"interrupted while writing; {', '.join(unrestored)} could not be restored", exc) from exc
            if isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError)):
                raise _InterruptedRestored(exc) from exc
            raise
    finally:
        # A temporary file is removed only while it holds what this write can account for:
        # its new bytes, or the snapshot's original (which the backup holds too). Anything
        # else (another writer's version an interruption left there) is kept, visibly.
        for name, tmp in temps:
            if tmp not in kept_aside:
                _discard_temporary(tmp, project / name, (files[name], originals.get(name)))


async def apply_plan(adapter: Any, plan: FixPlan, run: TrialRunner, snap: Snapshot, backup_root: Path,
                     *, stamp: str | None = None) -> ApplyResult:
    """Re-resolve *plan* in a scratch copy and, when it leaves exactly the verified end state, write it.

    Nothing is written when the adapter cannot apply, verification recorded
    no end state, the re-resolve fails or differs, or any file *snap* recorded,
    or the adapter writes or checks (``stale_files``), changed since it was
    taken. Only ``written_files`` are written, each of which must lie directly
    in the project directory.
    """
    name = getattr(adapter, "name", "this")
    if why := refusal(adapter, plan):
        return ApplyResult(False, why)
    expected = plan.verified_after
    assert expected is not None
    project = run.project_dir
    try:
        lock_name = adapter.lockfile_name
        written = tuple(adapter.written_files)
        stale = tuple(getattr(adapter, "stale_files", written))
    except Exception as exc:
        log.warning("the %s adapter's lock file or written files could not be read", name, exc_info=True)
        return ApplyResult(False, f"the {name} adapter cannot apply fixes ({exc}); run the printed commands")
    # A written file lies directly in the project directory: creating its temporary file
    # (O_EXCL) and renaming it never follow a symlink in the last component, so nothing
    # inside the project (a symlinked or swapped-in directory) can redirect a write.
    bad = [n for n in (*written, *stale) if not is_project_file_name(n)]
    bad += [n for n in written if not bad and len(Path(n).parts) != 1]
    if bad:
        return ApplyResult(False, f"the {name} adapter gave an unusable file name ({bad[0]!r}); "
                                  "run the printed commands")
    original_lock = snap.files.get(lock_name)
    if original_lock is None:
        return ApplyResult(False, f"{lock_name} is not a regular file")
    try:
        files = adapter.apply_files(project)
        if snap.inputs is not None and set(files) != set(snap.inputs):
            return ApplyResult(False, "the project changed while pa fix was running; run it again")
        # A scratch copy holds regular files only: a symlinked (or otherwise non-regular)
        # input would be left out, and the re-resolve would run without it.
        for n in dict.fromkeys((*files, *stale)):
            if (entry := _entry(project / n)) is not None:
                if entry.startswith("unreadable"):
                    return ApplyResult(False, f"{n} cannot be read; run the printed commands")
                kind = "a symlink" if entry.startswith("symlink") else "not a regular file"
                return ApplyResult(False, f"{n} is {kind}, which a scratch copy cannot hold; "
                                          "run the printed commands")
        steps = list(adapter.apply_steps(plan))
        out = await run.in_copy(files, [copy_is_snapshot(files, snap), *steps], read_back=list(written))
    except (KeyboardInterrupt, asyncio.CancelledError) as exc:
        # Nothing is written yet; the caller reports that, then re-raises the interruption.
        return ApplyResult(False, "interrupted while re-resolving; nothing was written", interrupted=exc)
    except ApplyRefused as exc:
        return ApplyResult(False, str(exc))
    except Exception as exc:
        log.warning("re-resolving %s in an isolated copy failed", name, exc_info=True)
        return ApplyResult(False, f"re-resolving in an isolated copy failed: {exc}")
    commands = sum(1 for s in steps if not callable(s))
    failed = next((r for r in out.results if r.returncode != 0 or r.timed_out), None)
    if failed is not None or len(out.results) < commands:
        why = ("timed out" if failed is not None and failed.timed_out
               else (_last_line(failed.stderr) or f"exit status {failed.returncode}") if failed is not None
               else "did not finish")
        return ApplyResult(False, f"re-resolving in an isolated copy failed: {why}; run the printed commands")
    new_lock = out.files.get(lock_name)
    if new_lock is None:
        return ApplyResult(False, f"re-resolving in an isolated copy left no {lock_name}")
    try:
        actual = adapter.versions_in(new_lock)
        before = adapter.versions_in(original_lock)
    except Exception as exc:
        log.warning("the %s adapter could not read a lock file", name, exc_info=True)
        return ApplyResult(False, f"could not read the re-resolved {lock_name} ({exc})")
    if diff := _differences(expected, actual):
        shown = "; ".join(diff[:5]) + (f"; and {len(diff) - 5} more" if len(diff) > 5 else "")
        return ApplyResult(False, f"the re-resolve differed from the verification: {shown}")
    # The copy holds only some of the project's files: an adapter that can tell whether
    # one it leaves out matters (confirm_in_project) re-resolves the project itself,
    # read-only, and that must reach the same end state. Files the copy leaves out
    # (ones git ignores) are not in the snapshot, so they are judged as of this
    # re-resolve: a change to one after it is indistinguishable from a change just
    # after the write, and is left to the next lock (`uv sync --locked` refuses a
    # lock its metadata has moved past).
    confirm = getattr(adapter, "confirm_in_project", None)
    if callable(confirm):
        try:
            confirmed = await cast("Callable[..., Awaitable[Mapping[str, frozenset[str]] | None]]",
                                   confirm)(plan, run)
        except (KeyboardInterrupt, asyncio.CancelledError) as exc:
            return ApplyResult(False, "interrupted while re-resolving; nothing was written", interrupted=exc)
        except ApplyRefused as exc:
            return ApplyResult(False, str(exc))
        except Exception as exc:
            log.warning("re-resolving %s in the project itself failed", name, exc_info=True)
            return ApplyResult(False, f"could not re-resolve the project itself ({exc}); run the printed commands")
        if confirmed is not None and (diff := _differences(expected, confirmed)):
            shown = "; ".join(diff[:5]) + (f"; and {len(diff) - 5} more" if len(diff) > 5 else "")
            return ApplyResult(False, f"the project resolves differently from the copy of its files ({shown}): "
                                      "a file the copy leaves out, such as one git ignores, changes the result; "
                                      "run the printed commands")
    def same_inputs() -> bool:
        """Whether the adapter still lists exactly the recorded inputs: a newly tracked
        file (a new workspace member) changes what a re-resolve reads without changing
        any recorded file. True when no inputs were recorded."""
        if snap.inputs is None:
            return True
        try:
            listed = set(adapter.apply_files(project))
        except Exception:  # an input list that cannot be read again is not the same list
            log.warning("the %s adapter could not list the project's inputs again", name, exc_info=True)
            return False
        return listed == set(snap.inputs)

    # Everything from here on goes through one open descriptor for the project directory
    # (/proc/self/fd/N resolves through it whatever happens to the path meanwhile), which
    # must be the directory snapshotted, and the path must still name it at every check:
    # a directory renamed and replaced (by a symlink or a copy) cannot receive the write.
    try:
        root_fd = os.open(project, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return ApplyResult(False, "the project changed while pa fix was running; run it again")
    try:
        st = os.fstat(root_fd)
        identity = (st.st_dev, st.st_ino)
        base = Path(f"/proc/self/fd/{root_fd}")
        if not base.is_dir():
            return ApplyResult(False, "writing the project needs /proc, which is not mounted")

        def as_project_path(message: str) -> str:
            """*message* naming the project's own path rather than its descriptor."""
            return message.replace(str(base), str(project))

        def still_same() -> bool:
            """Whether the project path still names the directory written into, and the
            adapter still lists the recorded inputs."""
            return _dir_identity(project) == identity and same_inputs()

        if snap.root is not None and identity != snap.root:
            return ApplyResult(False, "the project changed while pa fix was running; run it again")
        if not still_same():
            return ApplyResult(False, "the project changed while pa fix was running; run it again")
        for n in dict.fromkeys((*snap.files, *written, *stale, *(snap.inputs or ()))):
            if not _unchanged(base, n, snap):
                return ApplyResult(False, "the project changed while pa fix was running; run it again")
        if any(snap.files.get(n) is None and os.path.lexists(base / n) for n in written):
            return ApplyResult(False, "a project file is not a regular file; run the printed commands")
        if any(out.files.get(n) is None and snap.files.get(n) is not None for n in written):
            return ApplyResult(False, "re-resolving in an isolated copy removed a project file")
        changed = {n: data for n in written if (data := out.files.get(n)) is not None and data != snap.files.get(n)}
        if not changed:
            return ApplyResult(False, "the re-resolve changed nothing")
        originals = {n: d for n in changed if (d := snap.files.get(n)) is not None}
        try:
            backup = _backup(backup_root, originals, stamp or datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
        except (KeyboardInterrupt, asyncio.CancelledError) as exc:
            # _backup removes its own partial directory; the project is untouched.
            return ApplyResult(False, "interrupted before anything was written; nothing was written",
                               interrupted=exc)
        except OSError as exc:
            return ApplyResult(False, f"could not save a backup in {backup_root} ({exc})")
        checked = tuple(dict.fromkeys((*snap.files, *written, *stale, *(snap.inputs or ()))))
        try:
            _write_all(base, changed, snap.files,
                       unchanged=lambda n: _unchanged(base, n, snap), checked=checked, same_inputs=still_same)
        except _ProjectChanged:
            shutil.rmtree(backup, ignore_errors=True)
            return ApplyResult(False, "the project changed while pa fix was running; run it again")
        except _InterruptedRestored as exc:
            # Every rename was undone: the project is as it was, and the backup is not needed.
            shutil.rmtree(backup, ignore_errors=True)
            return ApplyResult(False, str(exc), interrupted=exc.interruption)
        except (KeyboardInterrupt, asyncio.CancelledError) as exc:
            # Interrupted during the rollback, or after every rename succeeded: the new
            # files may be in place, so the originals' backup is kept.
            return ApplyResult(False, f"interrupted while writing; the project's files may have been changed, "
                                      f"and the originals are in {backup}", backup=backup, interrupted=exc)
        except _NoAtomicRename as exc:
            # Raised only with every rename undone (a rename that could not be undone is
            # reported as a failed write instead), so the project is as it was.
            shutil.rmtree(backup, ignore_errors=True)
            return ApplyResult(False, as_project_path(str(exc)))
        except _InterruptedUnrestored as exc:
            return ApplyResult(False, f"could not write the project's files ({as_project_path(str(exc))}); the originals are in {backup}",
                               backup=backup, interrupted=exc.interruption)
        except OSError as exc:
            return ApplyResult(False, f"could not write the project's files ({as_project_path(str(exc))}); the originals are in {backup}",
                               backup=backup)
        return ApplyResult(True, written=tuple(changed), backup=backup, changes=_changes(before, actual))
    finally:
        os.close(root_fd)
