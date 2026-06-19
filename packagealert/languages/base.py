from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

_NORMALISE_RE = re.compile(r"[-_.]+")
MAX_TOP_PACKAGES = 500


def normalise_package_name(name: str) -> str:
    """Normalise a package name: lowercase and collapse runs of [-_.] to a single hyphen."""
    return _NORMALISE_RE.sub("-", name).lower()

if TYPE_CHECKING:
    import httpx
    from packagealert.heuristics.base import AbstractHeuristic

CURRENT_CONTRACT_VERSION = 3

# Describes a package being requested or installed (from CLI args or lock files).
@dataclass
class PackageSpec:
    name: str
    version: str | None
    ecosystem: str
    is_dev: bool | None = None  # True/False = dev/prod known; None = unknown (format lacks the concept, or source data was unavailable)


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
class SandboxTargets:
    """Returned by resolve_sandbox_targets() for a package-install run."""
    scan_targets: list[Path] = field(default_factory=list)
    write_dirs: list[Path] = field(default_factory=list)
    # Paths to snapshot+restore for rollback but NOT scanned for new packages.
    # Use for writable paths that must be rolled back (e.g. entry-point dirs)
    # but that don't contain package metadata.
    snapshot_only_dirs: list[Path] = field(default_factory=list)
    # User-visible warnings to print to the console (bold yellow). Use for
    # conditions that degrade scan coverage or rollback completeness.
    warnings: list[str] = field(default_factory=list)


@dataclass
class ShellEnvironment:
    """Returned by shell_environment() for an interactive shell session."""
    scan_targets: list[Path] = field(default_factory=list)
    write_dirs: list[Path] = field(default_factory=list)
    env_updates: dict[str, str] = field(default_factory=dict)
    path_prepends: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # User-visible warnings to print to the console (bold yellow).
    warnings: list[str] = field(default_factory=list)


class SandboxEnvError(Exception):
    """Raised by prepare_sandbox_env() to block the run with a user-visible message.

    The runner catches this, prints the message with markup=False, and returns 1.
    Use this instead of out-of-band env key sentinels.
    """


class SandboxScanError(Exception):
    """Raised by _collect_new_packages() when a scan target cannot be safely walked.

    The runner catches this, treats it as a scan failure (triggers rollback and
    returns 1) rather than silently skipping detection, so malicious installs
    cannot evade post-install scanning by replacing a scan root with a symlink.
    """


@dataclass
class PreRunResult:
    """Returned by pre_run_check()."""
    ok: bool
    message: str = ""
    required_flag: str = ""


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
    suggested_env: dict[str, str] = field(default_factory=dict)
    # Extra home-directory paths this install will write to (e.g. tool venv dirs,
    # entry-point dirs). The runner snapshots and restores these for rollback.
    extra_write_home_dirs: list[Path] = field(default_factory=list)
    # Name of the target environment receiving the packages when it differs from
    # packages[0] (e.g. pipx inject httpie httpx → target_env_name="httpie").
    # None means the environment name is derived from packages[0] as normal.
    target_env_name: str | None = None


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

    def popularity_ecosystem(self) -> str | None:
        return None

    def prepare_sandbox_argv(self, argv: list[str], cwd: Path) -> list[str]:
        """Pre-process argv before it is passed to the sandbox.

        Called by the sandbox runner just before build_cmd. Language modules can
        override to canonicalise arguments that the sandbox requires in a different
        form (e.g. resolving relative paths to absolute). Default returns argv unchanged.
        """
        return argv

    def sandbox_extra_ro_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        """Return additional paths to expose read-only inside the sandbox.

        Called with the prepared argv (after prepare_sandbox_argv) and cwd. Use this
        to expose paths referenced by argv that lie outside the project root and
        would otherwise be hidden by the home tmpfs (e.g. local editable installs).
        Default returns an empty list.
        """
        return []

    def sandbox_extra_write_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        """Return additional paths to bind writable inside the sandbox.

        Called with the prepared argv (after prepare_sandbox_argv) and cwd. Use this
        to expose paths that the install process must write to (e.g. editable install
        source directories where egg-info or build artifacts are written).
        Default returns an empty list.
        """
        return []

    def post_run_scan_targets(self, parsed: Any, cwd: Path) -> list[Path]:
        """Return scan targets that may have been created during the sandbox run.

        Called after the sandbox exits when no scan targets were detected before
        the run (e.g. a package manager that creates its install directory from
        scratch). Return paths to scan for newly installed packages. The runner
        also uses the first returned path to identify the rollback root — the
        language module should order paths from outermost (rollback root) to
        innermost (scan target), or return a single path if they are the same.
        Default returns an empty list.

        The *parsed* argument is a ``ParsedInstall`` from
        ``packagealert.parsers.process_args``. It has the same ``manager``,
        ``ecosystem``, ``venv_exe``, and ``lockfile_hint`` fields as
        ``ProcessInstall``, plus ``packages: list[str]``, ``req_files``,
        ``global_install``, and ``suggested_env``.
        """
        return []

    def pre_run_check(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str] = frozenset(),
    ) -> PreRunResult:
        """Return PreRunResult(ok=True) to allow, or (ok=False, message, required_flag) to block.

        *flags* contains only this module's flags (namespace already stripped by the runner).
        Default returns PreRunResult(ok=True).

        *parsed* is ``None`` when this plugin's namespace has active flags but its
        ecosystem is not the primary one for the current install (e.g. ``--flags
        python:ssh-keys`` during ``npm install``). Guard any access with
        ``if parsed is not None``.
        """
        return PreRunResult(ok=True)

    def configure_sandbox(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
        home_ro: list[Path],
        sandbox_env: dict[str, str],
    ) -> None:
        """Adjust sandbox mounts and env based on granted flags.

        Mutates *home_ro* and *sandbox_env* in-place to expose paths or inject
        environment variables. *targets* is read-only context (scan and write
        dirs already resolved and snapshotted); mutations to it are ignored.
        Called after pre_run_check passes in run mode. In shell mode it is
        called without a preceding pre_run_check. Default is a no-op.

        *parsed* is ``None`` in two situations: shell mode (``package-alert shell``),
        and when this plugin's namespace has active flags but its ecosystem is not
        the primary one for the current install (e.g. ``--flags python:ssh-keys``
        during ``npm install`` calls the Python plugin with ``parsed=None``).
        Always guard access with ``if parsed is not None``.
        """

    def resolve_sandbox_targets(
        self,
        parsed: Any,
        cwd: Path,
    ) -> SandboxTargets:
        """Return scan targets and extra writable dirs for this install.

        Called after cwd is appended to write_dirs. Replaces the per-ecosystem
        if/elif branches in the runner's _resolve_targets. Default returns
        empty SandboxTargets.

        The *parsed* argument is a ``ParsedInstall`` (see
        ``post_run_scan_targets`` for field details).
        """
        return SandboxTargets()

    def prepare_sandbox_env(
        self,
        parsed: Any,
        cwd: Path,
        env: dict[str, str],
    ) -> list[Path]:
        """Mutate *env* to add language-specific variables (e.g. VIRTUAL_ENV, PATH).

        Returns additional paths to bind writable inside the sandbox (e.g. the
        venv root for pip, so entry-point scripts in venv/bin/ are writable).
        Default returns an empty list.

        The *parsed* argument is a ``ParsedInstall`` (see
        ``post_run_scan_targets`` for field details).
        """
        return []

    def shell_environment(self, cwd: Path) -> ShellEnvironment:
        """Return the shell session environment for this language.

        Called at the start of _run_shell. Results from all registered language
        modules are merged. Default returns empty ShellEnvironment.
        """
        return ShellEnvironment()

    def detect_new_packages(
        self,
        new_paths: set[Path],
        walk_root: Path,
    ) -> list[PackageSpec]:
        """Return packages that appeared in *new_paths* since the pre-run snapshot.

        Called after the sandbox exits with the set of paths that appeared under
        the install target (new_paths = post_run_paths - pre_run_paths). *walk_root*
        is the directory that was walked (equals the scan target, or the resolved
        real directory when the scan target is an in-project symlink).

        Return PackageSpec objects for each newly installed package. Results from
        all registered language modules are merged and deduplicated by the runner.
        Default returns an empty list.
        """
        return []

    def home_ro_paths(self) -> list[Path]:
        """Return paths under $HOME to expose read-only inside the sandbox.

        Called once at sandbox setup. Results from all registered language modules
        are merged with the runner's common allowlist. Use this to expose package
        manager configuration files that your ecosystem reads at install time
        (e.g. ~/.config/pip, ~/.npmrc). Only return paths that actually exist.
        Default returns an empty list.
        """
        return []

    def resolve_package_dir(self, package_name: str, project_path: Path | None, site_packages_dir: Path | None) -> Path | None:
        """Return the on-disk directory for an installed package, or None if not resolvable.

        Called by the daemon after a process-monitor event to locate the extracted
        package directory so file-content heuristics can be run against it.

        *project_path* is the cwd of the install process (e.g. the project root
        for npm/composer, or None if unknown). *site_packages_dir* is the active
        venv's site-packages directory (PyPI only, None for other ecosystems).

        Default returns None — language modules that support file-content heuristics
        should override this.
        """
        return None

    def latest_version_url(self, name: str) -> str | None:
        """Return a registry API URL that resolves the latest published version of
        a package. The response is parsed by latest_version_parse().

        Return None if this ecosystem does not support latest-version resolution.
        """
        return None

    def latest_version_parse(self, data: dict, name: str) -> str | None:
        """Extract the latest version string from a registry API response.

        Called with the parsed JSON body from latest_version_url(). Return None
        if the version cannot be determined from the response.
        """
        return None

    def package_manager_names(self) -> list[str]:
        """Executable names that are pure package managers (pip, npm, uv, etc.).

        Used by setup-shell to generate shell functions. Must NOT include runtime
        interpreters (python, node, php) — those are handled separately via
        interpreter_names().
        """
        return []

    def project_shim_names(self) -> list[str]:
        """Subset of package_manager_names() to shim inside .venv/bin/ and
        node_modules/.bin/. Defaults to package_manager_names().

        Override to exclude tools that manage the venv itself (e.g. uv) or that
        install a versioned copy of themselves into the venv — shimming those can
        cause version mismatches or recursive invocation issues.
        """
        return self.package_manager_names()

    def interpreter_names(self) -> list[str]:
        """Runtime interpreter names (python, python3, node, php, etc.) that may
        invoke package managers via `-m pip` style invocations.

        setup-project writes a special shim for these that only intercepts package
        manager sub-invocations and passes everything else through unchanged.
        """
        return []

    def interpreter_shim_script(self, real: Path, pa: Path) -> str | None:
        """Return a complete sh(1) shim script for a runtime interpreter, or None.

        Called by setup-project when writing an interpreter shim for any name
        returned by interpreter_names(). The script must either exec *pa* (to
        route through package-alert), exec *real* (to bypass it), or exit with
        a non-zero status for guard failures such as a missing or inconsistent
        *real* binary. It must not return silently without taking one of these
        three actions.

        Return None to use the default plain passthrough shim (exec pa run "$0"
        "$@" for every invocation). Only override when the interpreter supports
        a sub-command style that needs selective interception — e.g. Python's
        `-m pip`, Ruby's `-S gem`, etc.

        The script must include the package-alert fingerprint and version marker
        so staleness detection works:

            from packagealert.cli.setup_cmd import PA_FINGERPRINT, PA_SHIM_VERSION_MARKER
        """
        return None

    def project_bin_dirs(self, root: Path) -> list[Path]:
        """Return bin/ directories within root that contain this language's package
        manager binaries, suitable for shimming by setup-project.

        The default implementation returns an empty list — override in each
        language module to detect the actual install locations (e.g. venv bin dirs
        for Python, node_modules/.bin for Node).
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
    "PreRunResult",
    "SandboxPaths",
    "SandboxEnvError",
    "SandboxTargets",
    "ShellEnvironment",
    "Snapshot",
    "ProcessInstall",
    "LanguageBase",
]
