"""Package-manager adapters for `pa fix`, and finding the one a project uses.

A language plugin supplies adapters through an optional ``fix_adapters()``
method (see the comment in languages/base.py). Everything outside an adapter —
planning, verification, output — is shared by every manager.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

if TYPE_CHECKING:
    from packagealert.languages.base import PackageSpec
    from packagealert.remediate.graph import DependencyGraph
    from packagealert.remediate.planner import FixPlan

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Change:
    action: str
    package: str
    old: str | None
    new: str | None
    fork_versions: tuple[str, ...] = ()
    """Every version locked after the change, when there are several (marker forks)."""


@dataclass(frozen=True)
class Blocker:
    parent: str
    constraint: str


@dataclass(frozen=True)
class Yank:
    package: str
    version: str
    reason: str | None = None


@dataclass(frozen=True)
class TrialResult:
    status: str
    changes: tuple[Change, ...] = ()
    blocker: Blocker | None = None
    detail: str = ""
    yanked: tuple[Yank, ...] = ()
    """Yanked versions in the trial's resolution, whether or not it changed them."""


RunFn = Callable[[list[str]], Awaitable[tuple[int, str]]]
"""Run a command in the read-only sandbox in the project directory: (returncode, stdout)."""


@dataclass(frozen=True)
class SyncSelection:
    flags: tuple[str, ...] = ()
    """Extra arguments for the printed sync command."""
    warning: str | None = None
    """Shown when the sync command could not be made to match the installed environment."""


class LockfileError(Exception):
    """A lock file exists but cannot be used; the message says why."""


class FixAdapter(Protocol):
    """One package manager's part of `pa fix`.

    ``cadences(names)`` is optional: an async method returning each package's
    release cadence (``"every-release"``, ``"calendar"`` or None) to label
    held major upgrades. Without it no label is shown.

    ``sync_selection(project_dir, run)`` is also optional: an async method
    returning a ``SyncSelection`` for the printed sync command, so that it keeps
    what the project's environment has installed.

    Every command an adapter runs (trials, exports) goes through
    ``SandboxRunner.run_captured()``, which runs a command only when the
    language plugin that owns it answers True from its optional
    ``is_read_only_command(argv)`` hook; a plugin supplying an adapter declares
    its read-only commands there.
    """

    name: str
    ecosystem: str
    lockfile_name: str

    def find_lockfile(self, root: Path) -> Path | None: ...
    def load_graph(self, lockfile: Path) -> DependencyGraph: ...
    def locked_packages(self, lockfile: Path) -> list[PackageSpec]: ...
    def commands(
        self, plan: FixPlan, project_dir: Path | None = None, sync_flags: tuple[str, ...] = (),
    ) -> list[list[str]]:
        """The commands that apply *plan*; with *project_dir*, they run there from any directory."""
        ...
    def trial_argv(self, pins: list[tuple[str, str]], float_packages: Iterable[str] = ()) -> list[str]: ...
    def parse_trial(
        self, returncode: int, stderr: str, *, timed_out: bool = False, pinned: dict[str, str] | None = None,
    ) -> TrialResult: ...


_ATTRIBUTES = ("name", "ecosystem", "lockfile_name")
_OPERATIONS = ("find_lockfile", "load_graph", "locked_packages", "commands", "trial_argv", "parse_trial")


@dataclass(frozen=True)
class Discovery:
    matches: list[tuple[FixAdapter, Path]]
    """Every adapter that found a lock file in the project, with that file."""
    supported: list[str]
    """The lock file names of every usable adapter, for messages."""


def _label(obj: object) -> str:
    """*obj*'s ``name`` for log messages, or "?" — even when reading it raises."""
    try:
        return str(getattr(obj, "name", "?"))
    except Exception:  # noqa: BLE001 - a plugin property may raise anything
        return "?"


def _adapters_of(lang: object) -> list[Any]:
    hook = getattr(lang, "fix_adapters", None)
    if not callable(hook):
        return []
    adapters = hook()
    if not isinstance(adapters, list):
        raise TypeError(f"fix_adapters() returned {type(adapters).__name__}, not a list")
    return list(adapters)


def discover(root: Path, languages: Iterable[object] | None = None) -> Discovery:
    """Ask every language (default: the registry) which adapters find a lock file in *root*.

    A plugin or adapter that raises or returns the wrong shape is logged and
    skipped; the others are still discovered.
    """
    if languages is None:
        from packagealert.languages import registry

        registry.load()
        languages = registry.all_languages()
    matches: list[tuple[FixAdapter, Path]] = []
    supported: list[str] = []
    for lang in languages:
        lang_name = _label(lang)
        try:
            adapters = _adapters_of(lang)
        except Exception:
            log.warning("fix_adapters() failed for lang=%s — skipping", lang_name, exc_info=True)
            continue
        for adapter in adapters:
            try:
                missing = [m for m in _ATTRIBUTES if not hasattr(adapter, m)]
                missing += [m for m in _OPERATIONS if not callable(getattr(adapter, m, None))]
                if missing:
                    raise TypeError(f"missing or not callable: {', '.join(missing)}")
                for attr in _ATTRIBUTES:
                    value = getattr(adapter, attr)
                    if not isinstance(value, str) or not value:
                        raise TypeError(f"{attr} is {value!r}, not a non-empty string")
                label = adapter.lockfile_name
                lockfile = adapter.find_lockfile(root)
                if lockfile is not None and not isinstance(lockfile, Path):
                    raise TypeError(f"find_lockfile() returned {type(lockfile).__name__}")
            except Exception:
                log.warning("Unusable fix adapter %s from lang=%s — skipping",
                            _label(adapter), lang_name, exc_info=True)
                continue
            supported.append(label)
            if lockfile is not None:
                matches.append((cast("FixAdapter", adapter), lockfile))
    return Discovery(matches=matches, supported=supported)
