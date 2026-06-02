from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

_NORMALISE_RE = re.compile(r"[-_.]+")
MAX_TOP_PACKAGES = 500


def normalise_package_name(name: str) -> str:
    """Normalise a package name: lowercase and collapse runs of [-_.] to a single hyphen."""
    return _NORMALISE_RE.sub("-", name).lower()

if TYPE_CHECKING:
    import httpx
    from packagealert.heuristics.base import AbstractHeuristic

CURRENT_CONTRACT_VERSION = 1

# Describes a package being requested or installed (from CLI args or lock files).
@dataclass
class PackageSpec:
    name: str
    version: str | None
    ecosystem: str


# Describes a package that has been observed (from a cache file or installed environment).
@dataclass
class PackageMetadata:
    name: str
    version: str | None
    ecosystem: str
    extras: dict[str, str] = field(default_factory=dict)


@dataclass
class SandboxPaths:
    read_only: list[Path] = field(default_factory=list)
    writable: list[Path] = field(default_factory=list)
    hidden: list[Path] = field(default_factory=list)


@dataclass
class Snapshot:
    data: dict[str, str]  # path -> metadata fingerprint


@dataclass
class ProcessInstall:
    """Result of parsing a process invocation.

    ``manager`` is the canonical name used for lockfile lookup (e.g. ``"pip"``,
    ``"uv-lock"``, ``"npm"``, ``"composer"``).  ``defer_to_lockfile`` signals that
    the monitor should wait for the process to exit and then read the lock file
    rather than acting on ``packages`` immediately.  ``venv_exe`` is the path to
    the Python interpreter when the invocation was inside a venv.

    ``lockfile_hint`` is an optional relative path (e.g. ``"Pipfile.lock"``) that
    the monitor should try *before* falling back to the full ``lockfile_patterns()``
    list.  Set this when the manager always writes a specific lockfile so the monitor
    does not accidentally pick up an unrelated lock file that happens to appear first
    in the priority list (e.g. a ``uv.lock`` in a repo that also uses pipenv).
    """

    manager: str
    packages: list[PackageSpec]
    defer_to_lockfile: bool = False
    venv_exe: str | None = None
    lockfile_hint: str | None = None
    req_files: list[str] = field(default_factory=list)
    global_install: bool = False


@runtime_checkable
class LanguageBase(Protocol):
    name: str
    ecosystems: list[str]
    process_names: list[str]
    contract_version: int
    author: str
    repository: str

    def parse_process_install(self, args: list[str]) -> ProcessInstall | None:
        """Parse a process invocation.  Return None if the args are not recognised."""
        ...
    def parse_package_spec(self, raw: str) -> tuple[str, str | None]:
        """Parse a raw command-line package token into (normalised_name, version_or_None).

        Used to convert tokens like ``requests==2.31.0`` or ``lodash@4.17.21`` into
        structured form for OSV queries and PackageSpec construction.  Version is None
        for unpinned specs; name is ``""`` if the token should be ignored (local paths,
        VCS URLs, etc.).  The default implementation returns the raw token with no version,
        which is safe but loses version information — override for precise behaviour.
        """
        return raw, None
    def serialise_package_spec(self, name: str, version: str | None) -> str:
        """Serialise (name, version) back to the string format this language's
        parse_package_spec() expects.  Must round-trip correctly:
        ``parse_package_spec(serialise_package_spec(n, v)) == (n, v)``.

        The default uses ``name==version`` (PEP 508 exact pin), which is correct
        for PyPI.  Override for ecosystems that use a different separator.
        """
        return f"{name}=={version}" if version else name
    def parse_lockfile(self, path: Path) -> list[PackageSpec]: ...
    def inspect_package(self, path: Path) -> PackageMetadata | None:
        """Inspect a downloaded package artifact (wheel, tarball, etc). Return None if the format is not supported."""
        ...
    def cache_paths(self) -> list[Path]: ...
    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        """Classify a file or directory created in a watched cache or site-packages dir. Return None if not a recognisable package artifact."""
        ...
    def cache_file_globs(self) -> list[str]:
        """Glob patterns (relative to each cache_paths() root) for artifacts that
        classify_cache_file() can recognise.  scan-cache uses these instead of
        rglob('*') to avoid enumerating the entire cache tree.  Return ['**/*'] to
        fall back to full traversal (not recommended for large caches)."""
        ...
    def heuristics(self) -> list[AbstractHeuristic]: ...
    def lockfile_patterns(self) -> list[str]: ...
    def detect_installed_packages(self, root: Path) -> list[PackageMetadata]: ...
    def sandbox_paths(self) -> SandboxPaths: ...
    def sandbox_env(self) -> list[str]:
        """Environment variable names that should be forwarded into the sandbox.

        Return names only — the sandbox runner reads their values from the live
        environment.  Names that are absent from the environment are silently
        ignored.  The runner merges results from all loaded language modules with
        its own common allowlist.
        """
        ...
    def top_packages_url(self) -> str | None:
        """URL to fetch a ranked list of top packages for this ecosystem.
        Return None if no dynamic source is available for this language."""
        ...
    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        """Fetch a ranked list of top packages from ``url`` using ``client``.

        Each registry has its own response shape and pagination strategy, so
        this method must be implemented by each language module.  Return a list
        of normalised names (lowercase, hyphens only — use ``normalise_package_name``),
        capped at ``MAX_TOP_PACKAGES`` entries, or None on failure.
        """
        ...
    def top_packages_fallback(self) -> list[str]:
        """Static baseline used when the cache is empty and fetch has failed.
        Names must be pre-normalised: lowercase, hyphens only (no underscores or dots)."""
        ...
    def publication_date_url(self, name: str, version: str) -> str | None:
        return None

    def package_manager_names(self) -> list[str]:
        """Executable names that are pure package managers (pip, npm, uv, etc.).

        Used by setup-shell and setup-project to determine which binaries to shim
        and which shell functions to generate. Must NOT include runtime interpreters
        (python, node, php) — those are handled separately via interpreter_names().
        """
        return []

    def interpreter_names(self) -> list[str]:
        """Runtime interpreter names (python, python3, node, php, etc.) that may
        invoke package managers via `-m pip` style invocations.

        setup-project writes a special shim for these that only intercepts package
        manager sub-invocations and passes everything else through unchanged.
        """
        return []

    def snapshot(self, install_root: Path) -> Snapshot: ...
    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]: ...


__all__ = [
    "CURRENT_CONTRACT_VERSION",
    "MAX_TOP_PACKAGES",
    "normalise_package_name",
    "PackageSpec",
    "PackageMetadata",
    "SandboxPaths",
    "Snapshot",
    "ProcessInstall",
    "LanguageBase",
]
