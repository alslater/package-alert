from __future__ import annotations

import logging
import os
import shutil
import stat as _stat
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from packagealert.sandbox.backend import InstallSnapshot

log = logging.getLogger(__name__)

_10_MB = 10 * 1024 * 1024


class FileSystemSnapshot(InstallSnapshot):
    """InstallSnapshot produced by FileSystemBackend.

    Stores full file contents, symlink targets, directory paths, and large-file
    metadata. path_set() unions these to give the runner the pre-run path set for
    new-package detection.

    Large files (exceeding snapshot_file_size_limit) are not content-snapshotted,
    but their size and mtime_ns are recorded. On rollback, large files whose
    metadata changed are removed rather than left in a potentially-modified state.
    Content cannot be restored for these files.
    """

    def __init__(self, *, existed: bool) -> None:
        super().__init__(existed=existed)
        # If the install target root itself is a symlink, its target string is
        # stored here. When the target resolves inside the project, the real
        # directory is also walked and its contents stored in files/dirs/etc so
        # rollback can restore them. Restore recreates the symlink and then
        # restores the real directory's contents through it.
        self.root_symlink: str | None = None
        # Canonical resolved path of the real directory at snapshot time (set when
        # root_symlink is set). Used by restore to validate the target before walking,
        # avoiding traversal of a potentially-mutated symlink chain.
        self.root_symlink_resolved: Path | None = None
        # Whether the resolved symlink target directory existed at snapshot time.
        # False means the symlink was broken pre-run; if the target was created
        # during the run it must be removed on rollback to restore exact pre-run state.
        self.root_symlink_target_existed: bool = False
        # Mode of the install target root directory (0 if unknown/not a real dir).
        self.root_mode: int = 0
        # files: path → (content_bytes, st_mode)
        self.files: dict[Path, tuple[bytes, int]] = {}
        self.symlinks: dict[Path, str] = {}
        # dirs: path → st_mode
        self.dirs: dict[Path, int] = {}
        # large_files: path → (size_bytes, mtime_ns) at snapshot time
        self.large_files: dict[Path, tuple[int, int]] = {}

    def path_set(self) -> set[Path]:
        if not self.existed:
            return set()
        return set(self.files) | set(self.symlinks) | set(self.dirs) | set(self.large_files)

    def scan_root(self, target: Path) -> Path:
        if self.root_symlink is not None and self.root_symlink_resolved is not None:
            # Use the canonical path stored at snapshot time — do NOT re-resolve
            # the symlink target, since an install script may have replaced the real
            # directory with a symlink chain pointing outside the project.
            return self.root_symlink_resolved
        return target


class FileSystemBackend:
    def __init__(self, *, snapshot_file_size_limit: int = _10_MB) -> None:
        self._size_limit = snapshot_file_size_limit

    def absent_snapshot(self) -> FileSystemSnapshot:
        return FileSystemSnapshot(existed=False)

    def snapshot_install_target(self, path: Path, console: Console, project_root: Path | None = None) -> FileSystemSnapshot:
        # Use lstat() so we see the directory entry itself, not what a symlink points to.
        try:
            path.lstat()
        except FileNotFoundError:
            return self.absent_snapshot()

        snap = FileSystemSnapshot(existed=True)
        label = path.name

        if path.is_symlink():
            try:
                resolved = path.resolve()
            except OSError as exc:
                raise ValueError(
                    f"Install target {path} is a symlink that cannot be resolved: {exc}"
                ) from exc
            if project_root is not None and not resolved.is_relative_to(project_root.resolve()):
                raise ValueError(
                    f"Install target {path} is a symlink pointing outside the project "
                    f"({resolved}). Rollback cannot be guaranteed — remove the symlink "
                    f"or replace it with a real directory before running package-alert."
                )
            # Symlink must point to a directory — pointing to a file would cause
            # os.walk() to silently yield nothing and leave rollback broken.
            # Broken symlinks (resolved path absent) are allowed: they are recorded
            # by target string only and restore recreates the symlink as-is.
            if resolved.exists() and not resolved.is_dir():
                raise ValueError(
                    f"Install target {path} is a symlink pointing to a non-directory "
                    f"({resolved}). Only directory targets are supported."
                )
            # Record the symlink itself and the canonical resolved path so restore
            # can validate it hasn't been replaced by a different symlink chain.
            # Always record the resolved path when project_root is provided — even
            # if the target doesn't exist yet (e.g. directory created during the run)
            # so scan_root() returns the real directory path post-run rather than
            # falling back to the symlink path and triggering a SandboxScanError.
            snap.root_symlink = os.readlink(path)
            snap.root_symlink_resolved = resolved if (resolved.exists() or project_root is not None) else None
            snap.root_symlink_target_existed = resolved.exists()
            console.print(f"✓ Snapshotting {label} (symlink → {snap.root_symlink})", style="dim", markup=False)
            # Walk the resolved target and capture its root mode for rollback.
            if resolved.exists():
                try:
                    snap.root_mode = resolved.stat().st_mode
                except OSError:
                    log.debug("Cannot stat symlink target root %s — mode not recorded", resolved)
                self._walk(resolved, snap)
            file_count = len(snap.files) + len(snap.large_files)
            log.debug("Snapshot %s (via symlink): %d files", label, file_count)
            return snap

        if not path.is_dir():
            # A non-directory, non-symlink entry at the install target root is
            # unexpected. Snapshotting it as a directory tree would produce an
            # empty snapshot, and restore would incorrectly recreate it as a
            # directory — destroying the original file. Fail fast instead.
            raise ValueError(
                f"Install target {path} exists but is not a directory or symlink "
                f"(type: {path.stat().st_mode:#o}). Cannot snapshot."
            )

        try:
            snap.root_mode = path.stat().st_mode
        except OSError:
            log.debug("Cannot stat install target root %s — mode not recorded", path)

        t0 = time.monotonic()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(f"Snapshotting {label}...", total=None)
            self._walk(path, snap)

        elapsed = time.monotonic() - t0
        total_bytes = sum(len(content) for content, _mode in snap.files.values())
        mb = total_bytes / (1024 * 1024)
        file_count = len(snap.files) + len(snap.large_files)
        log.debug("Snapshot %s: %d files, %.1f MB in %.2fs", label, file_count, mb, elapsed)
        console.print(f"✓ Snapshotted {label} ({file_count:,} files, {mb:.0f} MB)", style="dim", markup=False)
        return snap

    def _walk(self, path: Path, snap: FileSystemSnapshot) -> None:
        def _onerror(err: OSError) -> None:
            # Raise so snapshot_install_target propagates the error and the runner
            # aborts rather than producing a silently incomplete snapshot.
            raise err

        for dirpath, dirnames, filenames in os.walk(path, followlinks=False, onerror=_onerror):
            dp = Path(dirpath)
            for dn in list(dirnames):
                full = dp / dn
                if full.is_symlink():
                    try:
                        snap.symlinks[full] = os.readlink(full)
                    except OSError:
                        # Record with empty target — path_set() will include it so
                        # restore won't treat it as added and delete it.
                        log.debug("Cannot readlink %s — recording path without target", full)
                        snap.symlinks[full] = ""
                    dirnames.remove(dn)  # don't descend into symlinked dirs
                else:
                    try:
                        snap.dirs[full] = full.stat().st_mode
                    except OSError:
                        log.debug("Cannot stat dir %s — mode unknown, chmod skipped on restore", full)
                        snap.dirs[full] = 0
            for fn in filenames:
                full = dp / fn
                if full.is_symlink():
                    try:
                        snap.symlinks[full] = os.readlink(full)
                    except OSError:
                        # Record with empty target — path_set() will include it so
                        # restore won't treat it as added and delete it.
                        log.debug("Cannot readlink %s — recording path without target", full)
                        snap.symlinks[full] = ""
                    continue
                try:
                    st = full.stat()
                    size = st.st_size
                except OSError:
                    # Cannot stat — record in large_files with zeroed metadata so
                    # path_set() includes it and restore won't delete the file.
                    log.debug("Cannot stat %s — recording path without metadata", full)
                    snap.large_files[full] = (0, 0)
                    continue
                if not _stat.S_ISREG(st.st_mode):
                    # Non-regular file (FIFO, socket, device node) — reading would
                    # block or behave unexpectedly. Record metadata only.
                    log.debug("Non-regular file, skipping content: %s", full)
                    snap.large_files[full] = (size, st.st_mtime_ns)
                    continue
                if size > self._size_limit:
                    log.debug("File size %d bytes exceeds limit %d, skipping content: %s", size, self._size_limit, full)
                    snap.large_files[full] = (size, st.st_mtime_ns)
                    continue
                try:
                    snap.files[full] = (full.read_bytes(), st.st_mode)
                except OSError:
                    # Content unreadable — record metadata only so restore won't
                    # treat the file as "added during the run" and delete it.
                    log.debug("Cannot read %s — recording metadata only", full)
                    snap.large_files[full] = (size, st.st_mtime_ns)

    def restore_install_target(self, path: Path, snap: InstallSnapshot, console: Console) -> bool:
        if not isinstance(snap, FileSystemSnapshot):
            raise TypeError(f"FileSystemBackend requires a FileSystemSnapshot, got {type(snap).__name__}")
        label = path.name

        failures: list[str] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(f"Restoring {label}...", total=None)
            self._restore(path, snap, failures)

        file_count = len(snap.files) + len(snap.large_files)
        if not failures:
            console.print(f"✓ Restored {label} ({file_count:,} files)", style="dim", markup=False)
            return True
        else:
            console.print(f"⚠ Restored {label} ({file_count:,} files) — {len(failures)} path(s) could not be fully restored:", style="yellow", markup=False)
            for msg in failures:
                console.print(f"  • {msg}", style="yellow", markup=False)
            return False

    def _restore(self, path: Path, snap: FileSystemSnapshot, failures: list[str]) -> None:
        """Restore install target. Appends human-readable failure messages to *failures*."""
        if not snap.existed:
            try:
                path.lstat()
            except FileNotFoundError:
                return  # already absent — nothing to do
            # Remove whatever was created at this path during the run, regardless
            # of type (directory, file, symlink, FIFO, socket, device node, …).
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)  # raises on failure — propagates to caller
            else:
                path.unlink()  # covers symlinks, files, FIFOs, sockets, devices
            return

        def warn(msg: str, *args: object) -> None:
            formatted = msg % args if args else msg
            failures.append(formatted)
            log.warning("%s", formatted)

        # Root was a symlink before the run — restore the symlink, then restore
        # the real directory contents through it (snapshot walked the target).
        if snap.root_symlink is not None:
            current_target = os.readlink(path) if path.is_symlink() else None
            if current_target != snap.root_symlink:
                # Remove whatever is there and recreate the symlink.
                try:
                    path.lstat()
                    if path.is_dir() and not path.is_symlink():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                except FileNotFoundError:
                    pass
                path.symlink_to(snap.root_symlink)
            # Restore the contents of the real directory the symlink points to.
            # Use the path stored at snapshot time — do NOT re-resolve the symlink
            # chain, since the sandbox may have replaced the target with a symlink
            # pointing outside the project.
            real_dir = snap.root_symlink_resolved
            if real_dir is None:
                # Target was absent at snapshot time (broken symlink) — nothing to restore.
                return
            if not snap.root_symlink_target_existed:
                # Resolved target did not exist pre-run — if the sandbox created it,
                # remove it to restore the exact pre-run (broken symlink) state.
                try:
                    real_dir.lstat()
                    if real_dir.is_dir() and not real_dir.is_symlink():
                        shutil.rmtree(real_dir)
                    else:
                        real_dir.unlink()
                except FileNotFoundError:
                    pass  # already absent — nothing to do
                except OSError:
                    warn("Cannot remove symlink target created during install: %s", real_dir)
                return
            # Validate that the stored path is still a real (non-symlink) directory.
            try:
                st = real_dir.lstat()
                entry_exists = True
            except OSError:
                entry_exists = False
                st = None

            if entry_exists and st is not None and _stat.S_ISLNK(st.st_mode):
                # Replaced by a symlink during the run — refuse to follow an
                # attacker-controlled chain. Remove the symlink and rebuild.
                try:
                    real_dir.unlink()
                except OSError:
                    warn("Cannot remove symlink that replaced real directory: %s", real_dir)
                    return
                _rebuild_from_snapshot(real_dir, snap, failures)
                return

            if not entry_exists or st is None or not _stat.S_ISDIR(st.st_mode):
                # Real directory was deleted or replaced by a non-directory entry.
                # Remove the impostor (if any) and rebuild from snapshot.
                if entry_exists:
                    try:
                        real_dir.unlink()
                    except OSError:
                        warn("Cannot remove entry that replaced real directory: %s", real_dir)
                        return
                _rebuild_from_snapshot(real_dir, snap, failures)
                return

            self._restore_dir_contents(real_dir, snap, warn)
            return

        # Guard: the install target root must be a real directory. If it is
        # absent or was replaced by any other entry type (symlink, regular file,
        # FIFO, socket, device node), os.walk() would silently yield nothing or
        # raise. Remove the impostor and rebuild from the snapshot instead.
        if not (path.is_dir() and not path.is_symlink()):
            # Root is absent, a symlink, or any non-directory entry type (regular
            # file, FIFO, socket, device). Remove it and rebuild from the snapshot.
            try:
                path.lstat()
                path.unlink()  # unlink works for all non-directory entry types
            except FileNotFoundError:
                pass  # already absent
            _rebuild_from_snapshot(path, snap, failures)
            return

        self._restore_dir_contents(path, snap, warn)

    def _restore_dir_contents(
        self,
        path: Path,
        snap: FileSystemSnapshot,
        warn: Callable[..., None],
    ) -> None:
        """Walk *path* and restore its contents to match *snap*."""
        # Build set of all paths known before the run
        known: set[Path] = snap.path_set()

        # Walk current state bottom-up, remove anything added during the run
        for dirpath, dirnames, filenames in os.walk(path, topdown=False, followlinks=False):
            dp = Path(dirpath)
            for fn in filenames:
                full = dp / fn
                if full in snap.large_files:
                    # Content was not snapshotted. Remove the file if it was replaced
                    # by a symlink, or if its size/mtime changed (indicating modification).
                    # Content cannot be restored, but leaving a modified or replaced
                    # large file in place is worse than leaving the path absent.
                    if full.is_symlink():
                        try:
                            full.unlink()
                        except OSError:
                            warn("Cannot remove symlink replacing large file: %s", full)
                        warn(
                            "Large file was replaced by a symlink during install and "
                            "cannot be restored (content was not snapshotted): %s", full
                        )
                    else:
                        orig_size, orig_mtime_ns = snap.large_files[full]
                        if orig_size == 0 and orig_mtime_ns == 0:
                            # stat() failed during snapshot — metadata unknown.
                            # Leave the file in place rather than incorrectly
                            # treating any real metadata as "changed".
                            continue
                        try:
                            st = full.stat()
                            changed = st.st_size != orig_size or st.st_mtime_ns != orig_mtime_ns
                        except OSError:
                            changed = True
                        if changed:
                            try:
                                full.unlink()
                            except OSError:
                                warn("Cannot remove modified large file: %s", full)
                            warn(
                                "Large file was modified during install and cannot be "
                                "restored (content was not snapshotted): %s", full
                            )
                    continue  # do not attempt content restore for large files
                if full not in known:
                    try:
                        full.unlink()
                    except OSError:
                        warn("Cannot remove added file: %s", full)
                elif full in snap.dirs:
                    # Path was a directory before the run but is now a regular file.
                    # Remove it so the recreate-dirs loop below can restore the directory.
                    try:
                        full.unlink()
                    except OSError:
                        warn("Cannot remove file replacing directory: %s", full)
                elif full in snap.files:
                    # Use lstat to detect if the file was replaced by a symlink
                    # during the run — read_bytes() would follow it unsafely.
                    file_content, file_mode = snap.files[full]
                    if full.is_symlink():
                        try:
                            full.unlink()
                        except OSError:
                            warn("Cannot remove symlink replacing file: %s", full)
                        try:
                            _atomic_write(full, file_content, file_mode)
                        except OSError:
                            warn("Cannot restore file (was symlink): %s", full)
                    else:
                        try:
                            current = full.read_bytes()
                        except OSError:
                            current = None
                        if current != file_content:
                            try:
                                _atomic_write(full, file_content, file_mode)
                            except OSError:
                                warn("Cannot restore modified file: %s", full)
                        else:
                            # Content unchanged — still restore mode in case it changed.
                            try:
                                if full.stat().st_mode & 0o7777 != file_mode & 0o7777:
                                    os.chmod(full, file_mode & 0o7777)
                            except OSError:
                                warn("Cannot restore mode for: %s", full)
            for dn in dirnames:
                full = dp / dn
                if full.is_symlink():
                    current_target = None
                    try:
                        current_target = os.readlink(full)
                    except OSError:
                        pass
                    if full not in snap.symlinks:
                        try:
                            full.unlink()
                        except OSError:
                            warn("Cannot remove added symlink: %s", full)
                    elif current_target != snap.symlinks[full]:
                        try:
                            full.unlink()
                            full.symlink_to(snap.symlinks[full])
                        except OSError:
                            warn("Cannot restore symlink: %s", full)
                elif full not in known or full in snap.large_files:
                    # Remove directories that are either new (not in known) or
                    # replaced a pre-existing large file (in snap.large_files):
                    # a directory at a large-file path is always an impostor.
                    try:
                        shutil.rmtree(full)
                    except OSError:
                        warn("Cannot remove added dir: %s", full)
                    if full in snap.large_files:
                        warn(
                            "Large file was replaced by a directory during install "
                            "and cannot be restored (content was not snapshotted): %s", full
                        )

        # Restore file symlinks
        for p, target in snap.symlinks.items():
            if not target:
                # Empty target means readlink() failed during snapshot — we can't
                # restore the original target, so leave the path as-is.
                continue
            if p.is_symlink():
                try:
                    if os.readlink(p) != target:
                        p.unlink()
                        p.symlink_to(target)
                except OSError:
                    warn("Cannot restore symlink: %s", p)
            else:
                # Path is either absent or was replaced by a regular file/directory.
                # Remove whatever is there, then recreate the symlink.
                try:
                    if p.is_dir():
                        shutil.rmtree(p)
                    elif p.exists():
                        p.unlink()
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.symlink_to(target)
                except OSError:
                    warn("Cannot recreate symlink: %s", p)

        # Recreate deleted or replaced regular files.
        # A file may have been replaced by a symlink or directory during the run;
        # remove whatever is there before writing atomically.
        for p, (content, mode) in snap.files.items():
            if p.is_symlink() or p.is_dir() or not p.exists():
                try:
                    if p.is_dir():
                        shutil.rmtree(p)
                    elif p.is_symlink():
                        p.unlink()
                    p.parent.mkdir(parents=True, exist_ok=True)
                    _atomic_write(p, content, mode)
                except OSError:
                    warn("Cannot recreate file: %s", p)

        # Recreate deleted directories and restore their modes.
        for p, mode in snap.dirs.items():
            if not p.exists():
                try:
                    p.mkdir(parents=True, exist_ok=True)
                    if mode:
                        os.chmod(p, mode & 0o7777)
                except OSError:
                    warn("Cannot recreate deleted dir: %s", p)
            elif mode:
                try:
                    if p.stat().st_mode & 0o7777 != mode & 0o7777:
                        os.chmod(p, mode & 0o7777)
                except OSError:
                    warn("Cannot restore mode for dir: %s", p)

        # Large files that were deleted during the run: warn, cannot restore.
        for p in snap.large_files:
            if not p.exists() and not p.is_symlink():
                warn(
                    "Large file was deleted during install and cannot be restored "
                    "(content was not snapshotted): %s", p
                )

        # Restore root directory mode last (after all content is in place).
        if snap.root_mode:
            try:
                if path.stat().st_mode & 0o7777 != snap.root_mode & 0o7777:
                    os.chmod(path, snap.root_mode & 0o7777)
            except OSError:
                warn("Cannot restore mode for install target root: %s", path)



def _rebuild_from_snapshot(
    root: Path,
    snap: FileSystemSnapshot,
    failures: list[str],
) -> None:
    """Recreate a directory tree entirely from snapshot content.

    Used when the install target root was replaced by an impostor (symlink or
    regular file) during the run and has already been unlinked by the caller.
    Appends user-visible failure messages to *failures*.
    """
    def _warn(msg: str, *args: object) -> None:
        formatted = msg % args if args else msg
        failures.append(formatted)
        log.warning("%s", formatted)

    # Raise on failure: if the root cannot be recreated, none of the contents
    # can be restored either. Propagate so the caller surfaces a rollback error.
    root.mkdir(parents=True, exist_ok=True)
    if snap.root_mode:
        try:
            os.chmod(root, snap.root_mode & 0o7777)
        except OSError:
            _warn("Cannot restore mode for install target root: %s", root)
    for p, mode in snap.dirs.items():
        try:
            p.mkdir(parents=True, exist_ok=True)
            if mode:
                os.chmod(p, mode & 0o7777)
        except OSError:
            _warn("Cannot recreate dir: %s", p)
    for p, target in snap.symlinks.items():
        if not target:
            continue
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.symlink_to(target)
        except OSError:
            _warn("Cannot recreate symlink: %s", p)
    for p, (content, mode) in snap.files.items():
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(p, content, mode)
        except OSError:
            _warn("Cannot recreate file: %s", p)
    for p in snap.large_files:
        _warn("Large file cannot be restored (content was not snapshotted): %s", p)


def _atomic_write(path: Path, content: bytes, mode: int | None = None) -> None:
    fd, tmp_str = tempfile.mkstemp(dir=path.parent, prefix=".pa-restore-")
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "wb") as fobj:
            fd = -1  # fdopen takes ownership; don't close twice
            fobj.write(content)
        if mode is not None:
            os.chmod(tmp, mode & 0o7777)
        tmp.rename(path)
    except Exception:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    finally:
        tmp.unlink(missing_ok=True)
