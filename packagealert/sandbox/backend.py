from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Protocol

from rich.console import Console


class InstallSnapshot(ABC):
    """Base class for install target snapshots.

    Each backend returns a subclass from snapshot_install_target(). The runner
    calls path_set() to determine which paths existed before the run, allowing
    each backend to implement diffing in whatever way suits it — for example,
    reading field dicts for the filesystem backend, or wrapping an overlayfs
    upper-layer reference for a copy-on-write backend.
    """

    def __init__(self, *, existed: bool) -> None:
        self.existed = existed

    @abstractmethod
    def path_set(self) -> set[Path]:
        """Return the set of paths that existed before the run.

        Must return an empty set when existed is False, regardless of any
        other state the snapshot holds.
        """

    def scan_root(self, target: Path) -> Path:
        """Return the path to walk for post-run new-package detection.

        Normally returns *target* unchanged. Backends that snapshot through a
        symlink (e.g. FileSystemBackend when the target is an in-project
        symlink) should return the resolved real directory so the post-run
        walk uses the same path namespace as path_set().
        """
        return target


class SandboxBackend(Protocol):
    def snapshot_install_target(self, path: Path, console: Console, project_root: Path | None = None) -> InstallSnapshot:
        """Snapshot the install target at *path* and return its state.

        *project_root* is the project directory (cwd). Backends use it to
        enforce containment: if *path* is a symlink whose resolved target lies
        outside *project_root*, the snapshot must raise ValueError so the runner
        can abort rather than silently skip rollback for that target.
        """
        ...

    def restore_install_target(self, path: Path, snap: InstallSnapshot, console: Console) -> bool:
        """Restore the install target at *path* to the state captured in *snap*.

        Returns True if the target was fully restored, False if any path-level
        failures occurred (content printed to console; rollback was partial).
        """
        ...

    def absent_snapshot(self) -> InstallSnapshot:
        """Return a snapshot representing a target that did not exist before the run.

        Used when a scan target is discovered post-run (e.g. a venv created from
        scratch by `uv sync`). On rollback, the backend will remove the entire target.
        """
        ...
