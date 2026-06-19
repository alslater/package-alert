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


def collect_requirements_packages(
    path: Path,
    visited: set[Path] | None = None,
    allowed_root: Path | None = None,
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
    """
    if visited is None:
        visited = set()
    path = path.resolve()
    if allowed_root is None:
        allowed_root = _find_project_root(path.parent)
    if path in visited:
        return [], []
    visited.add(path)

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
            p, u = collect_requirements_packages(ref_path, visited, allowed_root)
            pinned.extend(p)
            unpinned.extend(u)
            continue
        if line.startswith("-"):
            continue
        # Skip local paths (./pkg, ../pkg, /abs/path), VCS URLs — scheme-based
        # (git+https://, git+ssh://, etc.) and scp-style (git@host:path).
        # _UNPINNED_RE would otherwise extract "git" or "." as a package name.
        if line.startswith((".", "/")) or "://" in line or line.startswith(("git+", "hg+", "svn+", "bzr+")) or _SCP_VCS_RE.match(line):
            continue
        m = _PINNED_RE.match(line)
        if m:
            pinned.append(LockedPackage(name=m.group(1), version=m.group(2), ecosystem="pypi"))
            continue
        m = _UNPINNED_RE.match(line)
        if m:
            unpinned.append(LockedPackage(name=m.group(1), version=None, ecosystem="pypi"))
    return pinned, unpinned
