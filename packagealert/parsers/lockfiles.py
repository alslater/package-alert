from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_DISTINFO_RE = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")


@dataclass
class LockedPackage:
    name: str
    version: str | None  # None = unpinned
    ecosystem: str
    is_dev: bool | None = None  # True/False = dev/prod known; None = unknown (format lacks the concept, or source data was unavailable)


@dataclass
class ProjectScan:
    sources: list[str]  # human-readable descriptions of what was found
    pinned: list[LockedPackage]
    unpinned: list[LockedPackage]
    dev_undetectable: list[str] = field(default_factory=list)  # sources where dev/prod couldn't be distinguished


def scan_lockfiles(paths: list[Path], *, prod_only: bool = False) -> ProjectScan:
    """Parse each path in *paths* directly via its owning language module.

    Unlike scan_project(), this does not apply first-match-per-language logic —
    every supplied path is parsed regardless of whether a higher-priority lock
    file for the same language also exists.  Used when specific lock files are
    known to have changed and must all be scanned.
    """
    from packagealert.languages import registry as lang_registry
    lang_registry.load()
    pinned: list[LockedPackage] = []
    unpinned: list[LockedPackage] = []
    sources: list[str] = []
    dev_undetectable: list[str] = []

    for path in paths:
        if not path.exists():
            continue
        lang = lang_registry.for_lockfile(path)
        if lang is None:
            continue
        try:
            specs = lang.parse_lockfile(path)
        except Exception:
            log.warning(
                "parse_lockfile raised unexpectedly for lang=%s path=%s — skipping",
                getattr(lang, "name", "?"), path, exc_info=True,
            )
            continue
        if not specs:
            continue
        if prod_only:
            if any(s.is_dev is None for s in specs):
                dev_undetectable.append(path.name)
            specs = [s for s in specs if s.is_dev is not True]
        sources.append(f"{lang.name} ({path.name})")
        for spec in specs:
            pkg = LockedPackage(name=spec.name, version=spec.version, ecosystem=spec.ecosystem.lower(), is_dev=spec.is_dev)
            if spec.version:
                pinned.append(pkg)
            else:
                unpinned.append(pkg)

    return ProjectScan(sources=sources, pinned=pinned, unpinned=unpinned, dev_undetectable=dev_undetectable)


def scan_project(root: Path, *, prod_only: bool = False) -> ProjectScan:
    from packagealert.languages import registry as lang_registry
    lang_registry.load()
    pinned: list[LockedPackage] = []
    unpinned: list[LockedPackage] = []
    sources: list[str] = []
    dev_undetectable: list[str] = []

    for lang in lang_registry.all_languages():
        try:
            patterns = lang.lockfile_patterns()
        except Exception:
            log.warning(
                "lockfile_patterns raised unexpectedly for lang=%s — skipping language",
                getattr(lang, "name", "?"), exc_info=True,
            )
            continue
        for pattern in patterns:
            lock_path = root / pattern
            if not lock_path.exists():
                continue
            try:
                specs = lang.parse_lockfile(lock_path)
            except Exception:
                log.warning(
                    "parse_lockfile raised unexpectedly for lang=%s path=%s — skipping pattern",
                    getattr(lang, "name", "?"), lock_path, exc_info=True,
                )
                continue
            if not specs:
                # File exists but yielded nothing — may be an unsupported format
                # or a genuinely empty lock file. Try the next pattern rather than
                # treating this as a successful match and skipping higher-quality
                # lock files that may also be present.
                continue
            if prod_only:
                if any(s.is_dev is None for s in specs):
                    dev_undetectable.append(pattern)
                specs = [s for s in specs if s.is_dev is not True]
                if not specs:
                    # All packages were dev-only — this is still a successful match.
                    # Record the source and stop; don't fall through to a lower-priority
                    # lockfile that might include packages from a different source.
                    sources.append(f"{lang.name} ({pattern})")
                    break
            for spec in specs:
                pkg = LockedPackage(name=spec.name, version=spec.version, ecosystem=spec.ecosystem.lower(), is_dev=spec.is_dev)
                if spec.version:
                    pinned.append(pkg)
                else:
                    unpinned.append(pkg)
            sources.append(f"{lang.name} ({pattern})")
            break  # first pattern that yielded packages wins

    return ProjectScan(sources=sources, pinned=pinned, unpinned=unpinned, dev_undetectable=dev_undetectable)


_PINNED_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)")
_UNPINNED_RE = re.compile(r"^([A-Za-z0-9_.-]+)")
# Scp-style VCS ref: git@host:path (colon not slash after hostname).
_SCP_VCS_RE = re.compile(r"^git@[^/:]+:[^/]")


def scan_installed(root: Path) -> ProjectScan:
    """Scan venv/.venv site-packages and node_modules for installed packages."""
    from packagealert.languages import registry as lang_registry
    lang_registry.load()
    pinned: list[LockedPackage] = []
    sources: list[str] = []

    for lang in lang_registry.all_languages():
        try:
            pkgs = lang.detect_installed_packages(root)
        except Exception:
            log.warning(
                "detect_installed_packages raised unexpectedly for lang=%s root=%s — skipping",
                getattr(lang, "name", "?"), root, exc_info=True,
            )
            continue
        if pkgs:
            for pkg in pkgs:
                if pkg.version:
                    pinned.append(LockedPackage(name=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem.lower()))
            sources.append(f"{lang.name} (installed)")

    return ProjectScan(sources=sources, pinned=pinned, unpinned=[])


_PROJECT_MARKERS = frozenset({
    "pyproject.toml", "setup.py", "setup.cfg",
    "requirements.txt", "Pipfile", "uv.lock",
    "package.json", "composer.json", "Cargo.toml",
    ".git",
})


def _find_project_root(start: Path) -> Path:
    """Walk up from *start* to find the nearest directory containing a project
    marker file.  Returns *start* itself if no marker is found before the
    filesystem root, which is safe — it simply means includes must stay within
    the starting directory.
    """
    current = start.resolve()
    while True:
        if any((current / marker).exists() for marker in _PROJECT_MARKERS):
            return current
        parent = current.parent
        if parent == current:
            return start.resolve()
        current = parent


def _req_include(line: str) -> str | None:
    """Return the included path if *line* is a -r/--requirement directive, else None."""
    if line.startswith("--requirement="):
        return line[len("--requirement="):]
    if line.startswith("--requirement "):
        return line[len("--requirement "):].lstrip()
    if line.startswith("-r") and len(line) > 2 and not line[2:].startswith("-"):
        return line[2:].lstrip()
    if line.startswith("-r "):
        return line[3:].lstrip()
    return None


# PEP 751's exact naming rule: ``pylock.toml`` itself, or ``pylock.<name>.toml``
# where <name> is non-empty and dot-free (distinguishes purpose-specific
# lockfiles like ``pylock.dev.toml`` from an unrelated file that merely ends
# in .toml, e.g. a requirements file someone named ``requirements.toml`` —
# `-r`/`--requirement` places no restriction on the file's extension or name).
_PYLOCK_NAME_RE = re.compile(r"^pylock(\.[^.]+)?\.toml$")


def _is_pylock_filename(name: str) -> bool:
    return bool(_PYLOCK_NAME_RE.match(name))


class _TargetVersionUnknown:
    """Sentinel: a target environment was selected (VIRTUAL_ENV/CONDA_PREFIX
    set, or a .venv found) but its Python version could not be read.

    Distinct from returning ``None`` (no target environment applies at all —
    safe to fall back to evaluating markers against package-alert's own
    interpreter, the closest available approximation). Here a target was
    positively identified, so falling back to package-alert's own
    interpreter would silently substitute an unrelated Python version — no
    better than a coin flip on whether a `python_version`/
    `python_full_version` marker happens to agree with the real target. The
    caller must not supply *any* version override in this case, and must
    treat a marker that references either variable as unresolvable (fail
    open, keep the package) rather than let it evaluate against the wrong
    interpreter.
    """


_TARGET_VERSION_UNKNOWN = _TargetVersionUnknown()

# Marker grammar identifiers for the two PEP 508 version-comparison
# variables. Checked against the marker string with quoted segments
# stripped first, so a marker like `sys_platform == 'python_version'` (the
# variable name only coincidentally appearing inside a string literal) is
# correctly NOT treated as version-dependent.
_VERSION_MARKER_VAR_RE = re.compile(r"\bpython_version\b|\bpython_full_version\b")
_QUOTED_RE = re.compile(r"'[^']*'|\"[^\"]*\"")


def _marker_references_python_version(marker: str) -> bool:
    return bool(_VERSION_MARKER_VAR_RE.search(_QUOTED_RE.sub("", marker)))


def _read_pyvenv_python_version(venv_root: Path) -> str | None:
    """Read the Python version a venv was created for, from its pyvenv.cfg.

    Static (no interpreter execution, matching THREAT_MODEL.md's "No code
    execution" property): the venv's own creation-time metadata already
    records this. Key name differs by creator — stdlib `venv` writes
    ``version`` (full, e.g. "3.14.3"); `uv venv` writes ``version_info``
    (short, e.g. "3.12"). Either is accepted; malformed/missing content
    returns None. The caller (`_discover_target_python_version`) treats
    that as "target selected but version unknown", not "no target" — see
    `_TARGET_VERSION_UNKNOWN`.
    """
    cfg = venv_root / "pyvenv.cfg"
    try:
        text = cfg.read_text(errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if key in ("version", "version_info"):
            value = value.strip()
            if value:
                return value
    return None


def _read_conda_python_version(env_root: Path) -> str | None:
    """Read the Python version of a conda/mamba environment, from its own metadata.

    Verified empirically against a real conda-compatible environment
    (`micromamba create -p ./env python=3.11`): unlike a venv, a conda
    environment has no `pyvenv.cfg` at all — its installed-package records
    live under `conda-meta/<name>-<version>-<build>.json`, one file per
    package. `python-3.11.15-h8ab3286_2_cpython.json` has top-level `name`
    and `version` fields. The filename alone is not a safe match: real
    conda-forge packages such as `python-dateutil` or `python-json-logger`
    also produce `conda-meta/python-*.json` files, so every candidate is
    opened and its `"name"` field is checked for the exact string
    ``"python"`` before trusting its `"version"`.
    """
    import json

    meta_dir = env_root / "conda-meta"
    try:
        candidates = list(meta_dir.glob("python-*.json"))
    except OSError:
        return None
    for candidate in candidates:
        try:
            data = json.loads(candidate.read_text(errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("name") != "python":
            continue
        version = data.get("version")
        if isinstance(version, str) and version:
            return version
    return None


def _discover_target_python_version(cwd: Path) -> str | _TargetVersionUnknown | None:
    """Best-effort match of uv/pip's own bare-invocation interpreter discovery.

    A bare `uv pip sync`/`uv pip install` (no --python/--python-version
    flag) does not target package-alert's own running interpreter — uv
    documents and this was verified empirically (`uv pip sync -v`, DEBUG
    "Searching for default Python interpreter in virtual environments") to
    resolve, in order: the `VIRTUAL_ENV` environment variable, then
    `CONDA_PREFIX`, then a `.venv` directory found by walking up from *cwd*.
    Only the version actually matters for marker evaluation
    (`python_version`/`python_full_version`), so this reads it statically
    rather than resolving/invoking the interpreter.

    `VIRTUAL_ENV` and `CONDA_PREFIX` are each read with the metadata format
    that actually matches what sets them: `VIRTUAL_ENV` names a venv
    (`pyvenv.cfg`); `CONDA_PREFIX` names a conda/mamba environment
    (`conda-meta/python-*.json` — conda environments routinely have no
    `pyvenv.cfg` at all, verified against a real `micromamba`-created
    environment).

    Three-way return, not two: a target can be *positively selected*
    (`VIRTUAL_ENV`/`CONDA_PREFIX` set, or a `.venv` directory found) with
    its version still unreadable (corrupted/unusually-packaged
    environment). That is not the same as *no target applying at all* —
    conflating the two by returning `None` for both would let the caller
    fall back to evaluating markers against package-alert's own
    interpreter, an arbitrary, unrelated Python version with no better than
    coincidental odds of matching the real target. So once a target is
    selected, its outcome is terminal in both directions: a version return
    stops here, and an unreadable one returns `_TARGET_VERSION_UNKNOWN`
    (not `None`) rather than falling through to a lower-priority location —
    uv itself does not fall back once it has committed to an environment
    (uv's own docs), and neither should this. Plain `None` is reserved for
    the genuine absence of any target: neither env var set, and no `.venv`
    found anywhere walking up from *cwd* — which also covers plain `pip`
    (no venv/conda discovery of its own).
    """
    import os

    virtual_env = os.environ.get("VIRTUAL_ENV")
    if virtual_env:
        version = _read_pyvenv_python_version(Path(virtual_env))
        return version if version is not None else _TARGET_VERSION_UNKNOWN

    conda_prefix = os.environ.get("CONDA_PREFIX")
    if conda_prefix:
        version = _read_conda_python_version(Path(conda_prefix))
        return version if version is not None else _TARGET_VERSION_UNKNOWN

    current = cwd.resolve()
    while True:
        venv_dir = current / ".venv"
        if venv_dir.is_dir():
            # A .venv directory here IS the target (uv doesn't keep
            # searching parents for a different one once it finds one) —
            # so an unreadable pyvenv.cfg is terminal too, not "not found."
            version = _read_pyvenv_python_version(venv_dir)
            return version if version is not None else _TARGET_VERSION_UNKNOWN
        parent = current.parent
        if parent == current:
            return None
        current = parent


def _collect_pylock_packages(
    path: Path, *, cwd: Path | None = None, is_system_python_target: bool = False
) -> tuple[list[LockedPackage], list[LockedPackage]]:
    """Parse a PEP 751 pylock.toml file (e.g. ``pylock.toml``, ``pylock.dev.toml``).

    Structurally unrelated to requirements.txt — a line-oriented read of a
    pylock.toml (as `collect_requirements_packages` does) matches TOML syntax
    like ``name = "requests"`` against the same regexes used for requirements
    lines, producing bogus packages literally named "name"/"version" while
    never surfacing the real ones. See PEP 751 for the schema:
    https://packaging.python.org/en/latest/specifications/pylock-toml/

    Honours ``packages.marker``: PEP 751's installation algorithm requires
    "If packages.marker is specified, check if it is satisfied; if it
    isn't, skip to the next package." A universal (multi-platform) pylock
    routinely contains mutually-exclusive platform variants of the same or
    different packages (e.g. a Windows-only package alongside its Linux
    counterparts) — evaluating every entry unconditionally would gate a
    package that uv/pip will never actually install on this environment.

    Evaluated against the *target* environment, not necessarily
    package-alert's own running interpreter: a bare `uv pip sync`/`uv pip
    install` (no --python/--python-version flag) does not target
    package-alert's interpreter — it targets whatever `VIRTUAL_ENV`/
    `CONDA_PREFIX` names, or a `.venv` found by walking up from *cwd*
    (verified empirically via `uv pip sync -v`'s own DEBUG output; see
    `_discover_target_python_version`). If package-alert runs under a
    different Python than that target — the common case whenever a
    project's `.venv` pins a version other than package-alert's own — a
    marker like `python_version == '3.12'` must be evaluated against the
    *target's* version, or a real dependency the sync installs gets
    silently excluded from every gate. Only the version is overridden
    (`python_version`/`python_full_version`, read statically from the
    target's own metadata — no interpreter execution); *cwd* is optional
    and omitting it (or a target genuinely not applying at all) falls back
    to evaluating against package-alert's own interpreter, matching the
    prior, narrower behaviour.

    A target can also be *positively selected* (`VIRTUAL_ENV`/
    `CONDA_PREFIX` set, or a `.venv` found) with its version unreadable
    (see `_discover_target_python_version`'s three-way return and
    `_TARGET_VERSION_UNKNOWN`). That is not treated the same as no target
    applying: falling back to package-alert's own interpreter there would
    silently compare against an unrelated Python version with no better
    than coincidental odds of being right. Instead, any marker referencing
    `python_version`/`python_full_version` (`_marker_references_python_version`,
    quote-stripped so a string literal that merely contains the substring
    isn't mistaken for the variable) fails open in this case — retained
    rather than excluded on a guess — while markers that don't reference
    either variable (platform, extras, dependency-group markers) are still
    evaluated normally.

    *is_system_python_target=True* (the caller's `uv pip sync`/`uv pip
    install --system` or UV_SYSTEM_PYTHON) short-circuits straight to this
    same target-unknown, fail-open treatment, skipping VIRTUAL_ENV/
    CONDA_PREFIX/`.venv` discovery entirely — `--system` switches uv's own
    interpreter discovery to a PATH-walk/managed-installation search that
    explicitly ignores any active venv (verified empirically), so applying
    VIRTUAL_ENV-based discovery here would evaluate markers against an
    environment uv was never going to use for this invocation.

    `--python-platform`/an explicit `--python <path>` override are
    separate, still-undocumented-and-unfixed gaps — see THREAT_MODEL.md's
    Out of Scope.

    An unparseable or unresolvable marker fails open (kept, not skipped) so
    a malformed pylock still gets the package scanned rather than silently
    ignored — covers all three of Marker.evaluate()'s documented raises:
    InvalidMarker (construction-time syntax error), UndefinedEnvironmentName
    (references an environment variable this evaluation doesn't provide),
    and UndefinedComparison (parses fine but applies an operator to values
    it can't compare, e.g. `python_version ~= 'dog'` — ~= requires a valid
    version on both sides). Letting any of these three propagate would
    abort the whole pylock scan instead of failing open on the one bad
    entry.

    Evaluated with context="lock_file" (packaging>=25 — see pyproject.toml's
    floor), which PEP 751 requires: a marker can reference the `extra`/
    `dependency_groups` variables (PEP 751's own extension covering
    packages.marker's use of dependency-group selection), and per the
    spec's install algorithm these default to the empty set unless the
    installing command selects specific extras/groups, OR — for
    dependency_groups specifically — unless the pylock's own top-level
    `default-groups` key names groups to install by default even on a bare
    sync/install. PEP 751: "dependency_groups SHOULD be the set created
    from default-groups by default." A package marked e.g. `marker =
    "'runtime' in dependency_groups"` is meant to represent what a bare
    install pulls in implicitly (the key's own doc: "meant to be used in
    situations where packages.marker necessitates such a group to exist") —
    seeding dependency_groups from default-groups here (still ∅ if the key
    is absent, its own spec default) is what makes a bare `uv pip sync
    pylock.toml` see it, without needing any --group flag from the
    invocation. Evaluating with the default "metadata" context instead
    leaves `extra`/`dependency_groups` undefined, so any such marker raises
    UndefinedEnvironmentName and gets caught by the fail-open fallback
    below — incorrectly retaining a package the extras default (empty set)
    would exclude, and which `uv pip sync`'s own `--extra`/`--group`
    selection (not yet threaded through this parser — see the module's
    callers) would need to explicitly opt into.
    """
    import tomllib

    from packaging.markers import (
        InvalidMarker,
        Marker,
        UndefinedComparison,
        UndefinedEnvironmentName,
    )

    pinned: list[LockedPackage] = []
    unpinned: list[LockedPackage] = []
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return pinned, unpinned

    default_groups = data.get("default-groups")
    marker_environment: dict[str, object] = (
        {"dependency_groups": frozenset(default_groups)}
        if isinstance(default_groups, list) and all(isinstance(g, str) for g in default_groups)
        else {}
    )

    target_version_unknown = False
    if is_system_python_target:
        # `uv pip sync`/`uv pip install --system` (or UV_SYSTEM_PYTHON)
        # switches uv's interpreter discovery to ignore any active
        # VIRTUAL_ENV/CONDA_PREFIX entirely (verified empirically — see
        # ParsedInstall.is_system_python_target's docstring) in favour of a
        # PATH-walk/managed-installation search this module does not
        # attempt to reproduce. Applying VIRTUAL_ENV/CONDA_PREFIX-based
        # discovery here would evaluate markers against an environment uv
        # was never going to use, so treat the target version as unknown
        # and fail open on version-dependent markers instead of guessing.
        target_version_unknown = True
    elif cwd is not None:
        target_python_version = _discover_target_python_version(cwd)
        if isinstance(target_python_version, str):
            marker_environment["python_full_version"] = target_python_version
            # python_version is the major.minor pair only — derive it rather
            # than trust a pyvenv.cfg that already recorded the short form
            # (uv's version_info) at face value for both keys.
            parts = target_python_version.split(".")
            marker_environment["python_version"] = ".".join(parts[:2])
        elif target_python_version is _TARGET_VERSION_UNKNOWN:
            # A target was positively selected (VIRTUAL_ENV/CONDA_PREFIX set,
            # or a .venv found) but its version couldn't be read. Evaluating
            # a python_version/python_full_version marker here would compare
            # against package-alert's own interpreter — an arbitrary,
            # unrelated Python version — so any such marker must fail open
            # instead (see the loop below).
            target_version_unknown = True

    for entry in data.get("packages", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            continue
        marker = entry.get("marker")
        if isinstance(marker, str) and marker:
            if target_version_unknown and _marker_references_python_version(marker):
                pass  # target's version unknown: fail open, don't guess
            else:
                try:
                    if not Marker(marker).evaluate(marker_environment, context="lock_file"):
                        continue
                except (InvalidMarker, UndefinedEnvironmentName, UndefinedComparison):
                    pass  # malformed/unresolvable marker: fail open, still scan the package
        version = entry.get("version")
        if isinstance(version, str) and version:
            pinned.append(LockedPackage(name=name, version=version, ecosystem="pypi"))
        else:
            # A pylock.toml entry can be VCS/directory/archive-sourced with no
            # PyPI version string — same "no fixed version" concept as an
            # unpinned requirements.txt line.
            unpinned.append(LockedPackage(name=name, version=None, ecosystem="pypi"))
    return pinned, unpinned


def collect_requirements_packages(
    path: Path,
    visited: set[Path] | None = None,
    allowed_root: Path | None = None,
    *,
    is_system_python_target: bool = False,
) -> tuple[list[LockedPackage], list[LockedPackage]]:
    """Parse *path* and all transitively included requirement files.

    Returns ``(pinned, unpinned)`` combining results from all included files.
    *visited* prevents re-processing files and breaks cycles.

    *allowed_root* constrains recursive includes: any -r path that resolves
    outside this directory is silently skipped.  Callers should pass the
    project root (e.g. cwd) so that monorepo patterns like
    ``requirements/base.txt`` including ``../root.txt`` work, while traversal
    to ``../../../../etc/passwd`` is blocked.  Defaults to the parent of the
    initial *path* when not provided.

    *is_system_python_target* should be the invoking command's
    `ParsedInstall.is_system_python_target` (`uv pip sync`/`uv pip install
    --system` or UV_SYSTEM_PYTHON) — forwarded to `_collect_pylock_packages`
    so it never applies VIRTUAL_ENV/CONDA_PREFIX-based version discovery
    when uv itself would ignore an active venv for this invocation.

    A filename matching PEP 751's pylock.toml convention (``pylock.toml`` or
    ``pylock.<name>.toml`` — uv's own `pip sync`/`pip install` accept such a
    file wherever a requirements.txt is accepted) is delegated to
    `_collect_pylock_packages` instead of being read as requirements.txt —
    the two formats are structurally unrelated and parsing one as the other
    silently drops every real package (see `_collect_pylock_packages`'s
    docstring). Matched by filename, not merely a ``.toml`` suffix: `-r`/
    `--requirement` places no restriction on the requirements file's name or
    extension, so an unrelated file that happens to end in .toml (e.g.
    ``requirements.toml``) must still be read as requirements.txt. Not
    itself recursive (a pylock.toml has no -r-style include directive), so
    *visited*/*allowed_root* don't apply to it.
    """
    if visited is None:
        visited = set()
    path = path.resolve()
    if allowed_root is None:
        allowed_root = _find_project_root(path.parent)
    if path in visited:
        return [], []
    visited.add(path)

    if _is_pylock_filename(path.name):
        return _collect_pylock_packages(
            path, cwd=allowed_root, is_system_python_target=is_system_python_target
        )

    pinned: list[LockedPackage] = []
    unpinned: list[LockedPackage] = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return pinned, unpinned

    for raw in lines:
        line = raw.split("#")[0].strip()
        if not line:
            continue
        include = _req_include(line)
        if include:
            if Path(include).is_absolute():
                continue
            ref_path = (path.parent / include).resolve()
            if not ref_path.is_relative_to(allowed_root):
                continue
            p, u = collect_requirements_packages(
                ref_path, visited, allowed_root, is_system_python_target=is_system_python_target
            )
            pinned.extend(p)
            unpinned.extend(u)
            continue
        if line.startswith("-"):
            continue
        # Skip local paths (./pkg, ../pkg, /abs/path), VCS URLs — scheme-based
        # (git+https://, git+ssh://, etc.) and scp-style (git@host:path).
        # _UNPINNED_RE would otherwise extract "git" or "." as a package name.
        if line.startswith((".", "/", "git+", "hg+", "svn+", "bzr+")) or "://" in line or _SCP_VCS_RE.match(line):
            continue
        m = _PINNED_RE.match(line)
        if m:
            pinned.append(LockedPackage(name=m.group(1), version=m.group(2), ecosystem="pypi"))
            continue
        m = _UNPINNED_RE.match(line)
        if m:
            unpinned.append(LockedPackage(name=m.group(1), version=None, ecosystem="pypi"))
    return pinned, unpinned
