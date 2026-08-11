"""Per-project default options for ``pa run``.

A ``.pa-run.toml`` file in or above a project directory can supply defaults
for the following ``pa run`` options:

- ``flags`` — comma-separated ``namespace:capability`` tokens (same syntax as ``--flags``)
- ``env`` — list of environment variable names to pass through (same syntax as ``--env``)
- ``no_network`` — boolean, equivalent to ``--no-network``
- ``allow_external_lockfiles`` — boolean, equivalent to ``--allow-external-lockfiles``

Options from the file are merged with ``PA_RUN_OPTS`` and explicit CLI flags
using these rules: boolean options are OR-ed across all three sources — once
set to ``true`` in any source they cannot be unset by another.  ``flags`` is
unioned across all three sources.  ``env`` is unioned between ``.pa-run.toml``
and CLI only — ``PA_RUN_OPTS`` does not support ``--env``.

Discovery algorithm
-------------------
Starting from *cwd*, walk up the directory tree.  The first
``.pa-run.toml`` found (closest to *cwd*) wins; its path is reported so
the source is always transparent.

Two stopping rules apply:

1. **Home directory ceiling** — the walk never goes above ``$HOME``
   (inclusive).  A ``~/.pa-run.toml`` acts as a user-wide default for
   projects under ``$HOME``.

2. **VCS root boundary** — if *cwd* is outside ``$HOME``, the walk stops
   at the first VCS root (``.git`` or ``.hg``) it encounters, or at the
   filesystem root if no VCS marker is found.  There is no trusted
   user-level config above a repo that lives outside the home directory.
   When *cwd* is under ``$HOME``, VCS roots are **not** stopping points —
   they only determine trust (see :class:`ProjectRunConfig.trusted`).

File format
-----------
Standard TOML.  All keys are optional::

    # .pa-run.toml
    flags = "python:ssh-keys"          # merged with --flags
    env   = ["MY_TOKEN", "REGISTRY"]  # merged with --env
    no_network             = false
    allow_external_lockfiles = false

Keys that are absent or ``false`` have no effect.  Boolean keys are only
applied when set to ``true``.
"""
from __future__ import annotations

import logging
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_CONFIG_FILENAME = ".pa-run.toml"
_VCS_MARKERS = frozenset({".git", ".hg"})


def _is_world_writable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
        if (mode & 0o002) == 0:
            return False
        # Sticky-bit directories (e.g. /tmp, mode 01777) restrict deletion to
        # the owner, so they are not meaningfully open for tampering.
        return not (stat.S_ISDIR(mode) and (mode & 0o1000))
    except OSError:
        return True


def _is_inside_vcs_root(config_dir: Path, home: Path) -> bool:
    """Return True if *config_dir* is at or inside a VCS root between it and *home*.

    Scans from *config_dir* up to *home* (inclusive) for VCS markers.  A config
    file whose directory (or any ancestor up to home) is a VCS root is considered
    to be inside a project repository rather than the user's personal space.
    """
    current = config_dir
    while True:
        if any((current / m).exists() for m in _VCS_MARKERS):
            return True
        if current == home:
            break
        if current.parent == current:
            break
        current = current.parent
    return False


def _path_is_trusted(file: Path, home: Path) -> str | None:
    """Return None if the path is trusted, or a human-readable reason string if not.

    Checks the file itself and every parent directory up to *home* (or the
    filesystem root if *file* is not under *home*) for world-writable permissions,
    excluding sticky-bit directories.
    """
    if _is_world_writable(file):
        return "file is world-writable"
    current = file.parent
    while True:
        if _is_world_writable(current):
            return f"{current}: directory is world-writable"
        if current == home:
            break
        if current.parent == current:
            break
        current = current.parent
    return None


@dataclass
class ProjectRunConfig:
    """Parsed content of a ``.pa-run.toml`` file."""

    source: Path
    """Absolute path to the ``.pa-run.toml`` file that was loaded."""

    flags: str = ""
    """Comma-separated ``namespace:capability`` tokens (same syntax as ``--flags``)."""

    env: list[str] = field(default_factory=list)
    """Extra environment variable names to pass through (same syntax as ``--env``)."""

    no_network: bool = False
    """If ``true``, block outbound network access (same as ``--no-network``)."""

    allow_external_lockfiles: bool = False
    """If ``true``, disable symlink containment checks (same as ``--allow-external-lockfiles``)."""

    trusted: bool = True
    """``True`` if the file is under ``$HOME``, not inside a VCS root, and no path component is world-writable."""


def find_project_run_config(cwd: Path) -> ProjectRunConfig | None:
    """Search for a ``.pa-run.toml`` starting at *cwd* and walking up.

    Returns the parsed :class:`ProjectRunConfig` for the first file found, or
    ``None`` if no file exists within the search boundary.

    See module docstring for the exact stopping rules.
    """
    home = Path.home().resolve(strict=False)
    # Resolve to eliminate symlinks / relative components before comparing.
    try:
        start = cwd.resolve(strict=True)
    except OSError:
        start = cwd.resolve(strict=False)

    # Only walk past a VCS root when $HOME is an ancestor of cwd — i.e. the
    # project is under the home directory.  Outside $HOME there is no trusted
    # user-level config to reach, so the walk stops at the VCS boundary.
    try:
        start.relative_to(home)
        under_home = True
    except ValueError:
        under_home = False

    current = start
    while True:
        candidate = current / _CONFIG_FILENAME
        if candidate.is_symlink():
            log.warning("%s: is a symlink — skipping (symlinked configs are not loaded)", candidate)
        elif candidate.is_file():
            vcs_trusted = under_home and not _is_inside_vcs_root(current, home)
            perm_reason = _path_is_trusted(candidate, home)
            trusted = vcs_trusted and perm_reason is None
            if perm_reason is not None:
                log.warning(
                    "%s: %s — treating as untrusted (env vars will require sandbox.project_env_allowlist)",
                    candidate,
                    perm_reason,
                )
            return _load(candidate, trusted=trusted)

        at_home = current == home
        at_fs_root = current.parent == current
        at_vcs_root = any((current / m).exists() for m in _VCS_MARKERS)

        if at_home or at_fs_root or (at_vcs_root and not under_home):
            return None

        current = current.parent


def _load(path: Path, *, trusted: bool = True) -> ProjectRunConfig:
    """Parse *path* as TOML and return a :class:`ProjectRunConfig`."""
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProjectRunConfigError(path, str(exc)) from exc

    unknown = set(data) - {"flags", "env", "no_network", "allow_external_lockfiles"}
    if unknown:
        raise ProjectRunConfigError(
            path,
            f"unknown key(s): {', '.join(sorted(unknown))}. "
            f"Valid keys: flags, env, no_network, allow_external_lockfiles",
        )

    def _str(key: str) -> str:
        v = data.get(key, "")
        if not isinstance(v, str):
            raise ProjectRunConfigError(path, f"{key!r} must be a string")
        return v

    def _strlist(key: str) -> list[str]:
        v = data.get(key, [])
        if isinstance(v, str):
            return [v]
        if not isinstance(v, list) or not all(isinstance(i, str) for i in v):
            raise ProjectRunConfigError(path, f"{key!r} must be a string or list of strings")
        return list(v)

    def _bool(key: str) -> bool:
        v = data.get(key, False)
        if not isinstance(v, bool):
            raise ProjectRunConfigError(path, f"{key!r} must be a boolean (true/false)")
        return v

    return ProjectRunConfig(
        source=path.resolve(),
        flags=_str("flags"),
        env=_strlist("env"),
        no_network=_bool("no_network"),
        allow_external_lockfiles=_bool("allow_external_lockfiles"),
        trusted=trusted,
    )


class ProjectRunConfigError(Exception):
    """Raised when a ``.pa-run.toml`` cannot be parsed."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"{path}: {detail}")
