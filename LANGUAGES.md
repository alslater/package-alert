# Language Module Guide

package-alert supports multiple package ecosystems through **language modules** — self-contained Python classes that implement the `LanguageBase` contract. This guide covers the contract, how to write an in-tree module, and how to publish an external plugin.

---

## The `LanguageBase` Contract

All language modules must satisfy the `LanguageBase` protocol defined in [`packagealert/languages/base.py`](packagealert/languages/base.py).

### Ecosystems are registry-driven

Whatever a module declares in `ecosystems` becomes a first-class ecosystem across the whole pipeline — events, risk scoring, typosquat detection and the `pa run` gates. `normalise_ecosystem()` and `PackageEvent.ecosystem` resolve their vocabulary from the registry, so a plugin does **not** need to be added to any core list.

Two rules apply:

- **Matching is case-insensitive; the declared spelling is canonical.** Declaring `["crates.io"]` means `"Crates.IO"` and `"crates.io"` both resolve to `crates.io`, and that is the form stored on events and used as a cache key. Cache keys are canonicalised inside `OsvCache` rather than by its callers — there are a dozen readers and writers across the daemon, scheduler, sandbox runner and CLI, and `parsers/lockfiles.py` lowercases every ecosystem it parses, so a caller-side rule would leave `scan-project` writing `nuget` rows that `clear-cache --ecosystem NuGet` could not find.
- **Built-ins cannot be redefined.** `pypi`, `npm` and `packagist` keep their canonical lowercase form even if a plugin declares a different casing.

An ecosystem that *no* registered module claims is still rejected — that indicates a typo or a plugin that failed to load, not a supported state.

> Before this was registry-driven, `PackageEvent.ecosystem` was a closed `Literal["pypi", "npm", "packagist"]`. A plugin's ecosystem parsed and scanned correctly but could never be risk-scored: every scoring entry point funnels through `normalise_ecosystem` into a `PackageEvent`, so those packages were counted as scoring failures.

### Contract Version

Each module declares `contract_version: int` — a **fixed declaration of the highest contract version this module fully implements**, checked by the registry at registration time. The current value lives in [`base.py`](packagealert/languages/base.py); the [changelog](#contract-version-changelog) at the bottom of this file records what each version added.

In-tree modules ([`python.py`](packagealert/languages/python.py), [`node.py`](packagealert/languages/node.py), [`php.py`](packagealert/languages/php.py)) import `CURRENT_CONTRACT_VERSION` and assign it directly, because they are released in lockstep with the same version of package-alert that defines the constant — a contract bump and the work to implement it land in the same PR. **External plugins must not do this.** They are packaged, versioned and released independently, so an external plugin's `contract_version` must be a hardcoded integer literal matching the highest version it has actually implemented and verified — not an import of `CURRENT_CONTRACT_VERSION`. If it auto-tracks the constant, upgrading package-alert alone (without also upgrading the plugin) silently re-evaluates the plugin's declared version upward, falsely claiming compliance with hooks the plugin was never updated to implement — bypassing both the deprecation warning and the shim/adapter safety net a correctly-lower declaration would otherwise trigger, since the registry only shims/adapts a plugin declaring a version *below* the one that changed (see the table below: "Equal to current" gets no adaptation at all). When a module is registered the registry checks this value:

| Declared version | Behaviour |
|-----------------|-----------|
| Equal to current | Registered normally. |
| Older than current | Warning logged. Call sites use `getattr`/`callable` guards before invoking optional methods, so plugins that don't implement them continue to work. For methods that require a non-trivial default (not just "skip if absent"), a shim entry should be added to `_VERSION_SHIMS` in `registry.py` — the shim is injected onto the plugin instance at registration time. Note: `LanguageBase` is a `Protocol`, so its method bodies are **not** automatically inherited by plugins that duck-type it rather than subclassing it. |
| Newer than current | Warning logged; registered, but newer methods will not be called by this version of package-alert. |
| Absent | Treated as version 1; warning logged. |

When you add a new method to the contract: increment `CURRENT_CONTRACT_VERSION`, add a safe-default entry to `_VERSION_SHIMS` in [`registry.py`](packagealert/languages/registry.py), and document the change in the changelog at the bottom of this file.

---

### Supporting Types

All types are defined in [`packagealert/languages/base.py`](packagealert/languages/base.py).

```python
@dataclass
class PackageSpec:
    name: str
    version: str | None   # None = unpinned or unknown
    ecosystem: str        # OSV ecosystem string: "PyPI", "npm", "Packagist"

@dataclass
class PackageMetadata:
    name: str
    version: str | None
    ecosystem: str
    extras: dict[str, str] = field(default_factory=dict)

@dataclass
class ProcessInstall:
    manager: str                  # canonical name used for lockfile lookup
    packages: list[PackageSpec]   # empty when defer_to_lockfile is True
    defer_to_lockfile: bool = False
    venv_exe: str | None = None   # absolute path to interpreter, for site-packages discovery

@dataclass
class SandboxPaths:
    read_only: list[Path] = field(default_factory=list)  # bind-mounted read-only
    writable: list[Path]  = field(default_factory=list)  # package manager writes here
    hidden:   list[Path]  = field(default_factory=list)  # shadowed by a tmpfs

@dataclass
class Snapshot:
    data: dict[str, str]   # path → fingerprint; format is opaque and language-defined

@dataclass
class PreRunResult:
    ok: bool               # True = allow the run; False = block it
    message: str = ""      # user-visible error message (printed in bold red when ok=False)
    required_flag: str = "" # the flag the user should pass to unblock (e.g. "python:ssh-keys");
                            # informational only — the runner does not re-prompt automatically
```

---

### Contract Methods

#### Method Reference

| Signature | Required | Description |
|-----------|----------|-------------|
| `popularity_ecosystem() -> str | None` | Optional | Return the deps.dev system name for this ecosystem (e.g. `"PYPI"`, `"NPM"`), or `None` if unsupported. Used by `PopularityClient` to look up adoption metrics for risk score dampening. Third-party plugins implement this to participate in popularity dampening without patching core. Defaults to `None`. |

#### Full Protocol Definition

```python
class LanguageBase(Protocol):
    # ── Identity ──────────────────────────────────────────────────────────
    name: str                  # unique slug, e.g. "python", "node", "php"
    ecosystems: list[str]      # OSV ecosystem strings, e.g. ["PyPI"]
    process_names: list[str]   # process basenames to watch, e.g. ["pip", "pip3", "uv"]
    contract_version: int

    # ── Process monitoring ─────────────────────────────────────────────────
    def parse_process_install(self, args: list[str]) -> ProcessInstall | None:
        """Parse a process argv.  Return None if the command is not recognised.

        Set defer_to_lockfile=True when the package manager writes a lock file
        (e.g. npm install, composer require, pipenv install) — the monitor will
        wait for the process to exit and then call parse_lockfile() instead of
        acting on packages immediately.

        Set venv_exe to the absolute interpreter path when the invocation is
        inside a venv so the monitor can derive the correct site-packages dir.
        """

    # ── Lock file parsing ──────────────────────────────────────────────────
    def parse_lockfile(self, path: Path) -> list[PackageSpec]:
        """Parse a lock file and return all pinned packages.  Return [] on error."""

    def lockfile_patterns(self) -> list[str]:
        """Lock file basenames to look for under a project root, in priority order."""

    # ── Artifact inspection ────────────────────────────────────────────────
    def inspect_package(self, path: Path) -> PackageMetadata | None:
        """Inspect a downloaded package artifact (wheel, tarball, etc.).
        Return None if the format is not supported by this language module."""

    # ── Cache monitoring ───────────────────────────────────────────────────
    def cache_paths(self) -> list[Path]:
        """Filesystem paths that watchdog should monitor for new package artifacts."""

    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        """Classify a file/directory created in a watched path.
        Return None if it is not a recognisable package artifact."""

    # ── Heuristic risk scoring ─────────────────────────────────────────────
    def heuristics(self) -> list[AbstractHeuristic]:
        """Heuristic instances to run against downloaded package directories.
        Return [] if this language module has no heuristics."""

    def resolve_package_dir(
        self,
        package_name: str,
        project_path: Path | None,
        site_packages_dir: Path | None,
        version: str | None = None,
    ) -> list[Path]:
        """Return every on-disk directory this distribution owns, or [] if none resolvable.

        Called by the daemon after a process-monitor event, and by
        ``--scan-installed``, to locate the extracted package directory(ies) so
        file-content heuristics can be run against them. Only called for
        ``source="process"`` events — cache-monitor events fire while the tarball
        is still in the download cache, before extraction.

        Returns a *list* — plural — because a single directory is not always a
        distribution's whole footprint. A PEP 420 implicit namespace package
        distribution (``google-auth``) installs into more than one subdirectory
        (``google/auth/``, ``google/oauth2/``) of a top-level directory
        (``google/``) it does not exclusively own — sibling distributions
        (``google-cloud-storage``) install into other subdirectories of the same
        shared root, with no file at the shared level to mark it as shared.
        Returning that shared root hands source-code heuristics every sibling
        distribution's files too, misattributing one distribution's signals to
        another. Every directory in the returned list must therefore actually
        belong to *this* distribution and no other's.

        *project_path* is the cwd of the install process (the project root for
        npm/composer installs, or None if unknown). *site_packages_dir* is the
        active venv's site-packages directory (set for PyPI events when detectable,
        None otherwise).

        *version*, when given, must be matched as well as the name — return ``[]``
        rather than a name-only match if that version is not present. A caller may
        search several environments (``scan-project --scan-installed`` aggregates
        every venv it finds) and two of them can hold different versions of one
        package; matching on name alone returns whichever was searched first, so
        heuristics inspect the wrong source tree and a malicious version can be
        scored against a benign one. Accept the parameter even where your layout
        cannot hold two versions at one path, so the signature matches the contract
        version you declare.

        Typical implementations:
        - npm: ``return [project_path / "node_modules" / package_name]`` (one
          version per path, so *version* needs no check; ``[]`` if it doesn't exist)
        - PyPI: find the ``.dist-info`` dir whose name **and version** match, read
          ``RECORD``/``top_level.txt``, return every importable directory this
          distribution's own files occupy — never a shared namespace root another
          distribution also installs into
        - Packagist: ``return [project_path / "vendor" / Path(package_name)]`` (one
          version per path)

        Return ``[]`` if no directory can be determined. Default returns ``[]``."""

    def resolve_package_dir_manifest_warning(
        self,
        package_name: str,
        project_path: Path | None,
        site_packages_dir: Path | None,
        version: str | None = None,
    ) -> str | None:
        """Return a risk-signal warning if this distribution's install manifest
        could not be fully trusted while resolving its package directory.

        Called with the same arguments as ``resolve_package_dir``, immediately
        after it, on the matched distribution. Exists because
        ``resolve_package_dir`` correctly refusing to guess a directory for an
        unverifiable manifest (e.g. PyPI's RECORD present but unparseable) is,
        on its own, indistinguishable from an ordinary "nothing to scan here" —
        silently downgrading a manifest a legitimate build tool essentially
        never produces to a clean scan. Implement this whenever your
        ``resolve_package_dir`` consults a manifest file that could plausibly be
        corrupted or crafted — most in-tree implementations have no such file
        (npm/Composer resolve a direct, unambiguous path with nothing to parse)
        and correctly return ``None`` unconditionally.

        Return ``None`` when the manifest was absent, empty, or fully trusted —
        including when this hook is simply not overridden. Default returns
        ``None``."""

    # ── Installed-package scanning ─────────────────────────────────────────
    def detect_installed_packages(self, root: Path) -> list[PackageMetadata]:
        """Enumerate packages installed in the environment rooted at root.
        May call subprocesses or walk the filesystem.  Must return [] on any error."""

    # ── Sandbox ────────────────────────────────────────────────────────────
    def sandbox_paths(self) -> SandboxPaths:
        """Bubblewrap mount configuration for this language's package manager."""

    def sandbox_env(self) -> list[str]:
        """Environment variable *names* to forward into the sandbox for this language.

        Return names only — the sandbox runner reads their values from the live
        environment at run time.  Names absent from the environment are silently
        ignored.  The runner merges results from all loaded language modules with
        a common allowlist (PATH, HOME, proxy vars, SSL vars, etc.).

        Include all variables your package manager may read, e.g. registry URLs,
        cache directories, version manager roots, and auth tokens."""

    # ── Top packages ───────────────────────────────────────────────────────
    def top_packages_url(self) -> str | None:
        """URL to fetch a ranked list of top packages for this ecosystem.

        Return a URL to a JSON file containing top-N packages by download count
        (or similar metric). Used by TopPackagesCache to refresh weekly.
        Return None if no dynamic source is available for this language."""

    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        """Fetch and parse top packages from url using the provided HTTP client.

        Called by TopPackagesCache with the URL returned by top_packages_url().
        Implement your registry's pagination and response format here.
        Return a list of normalised names (use normalise_package_name()), or None on failure.

        Use MAX_TOP_PACKAGES as the cap. Both helpers are exported from
        packagealert.languages.base."""

    def top_packages_fallback(self) -> list[str]:
        """Static baseline list of well-known packages used as a fallback.

        Used when the cache is empty and the live fetch has failed. Names must
        be pre-normalised: lowercase, hyphens only (no underscores or dots)."""

    # ── Publication date & latest version (cooldown policy) ──────────────
    def publication_date_url(self, name: str, version: str) -> str | None:
        """Registry API URL to fetch when this package version was first published.

        Return None to opt out of cooldown enforcement for this ecosystem.
        Default implementation returns None."""

    def publication_date_parse(self, data: object, version: str | None) -> float | None:
        """Extract a Unix publication timestamp from the publication_date_url() reply.

        *data* is typed ``object``, not ``dict``: a JSON document's root is not
        always an object — RubyGems' versions.json, for one, returns a JSON
        array. Narrow with ``isinstance`` before indexing/iterating.

        Implement this whenever you implement publication_date_url: without it the
        cooldown policy cannot determine a package's age, so it fails open and never
        blocks or prompts however recently the package was published.
        Default implementation returns None."""

    def osv_ecosystem(self) -> str | None:
        """The ecosystem name OSV.dev uses, e.g. "PyPI", "npm", "Packagist".

        Used to match advisory entries when extracting fixed versions. Without it
        the raw ecosystem string is used as a best-effort fallback, so upgrade
        advice may be missing. Default implementation returns None."""

    def normalise_name(self, name: str) -> str:
        """Normalise a package name for equality comparison against advisories.

        The registry's own casing and separator rules decide whether two names are
        the same package. PyPI collapses runs of ``[-_.]`` per PEP 503; most
        ecosystems only lowercase, which is the default.

        Implement this if your registry treats separators as interchangeable. When
        this hook is missing or raises, core falls back to lowercase-only for every
        ecosystem except PyPI — deliberately, because folding two distinct names
        together would make a typosquat an exact corpus match and report it as clean.
        A missing equivalence is visible (a distance-1 finding for two spellings of one
        package); a wrongly-merged pair is silent."""

    def latest_version_url(self, name: str) -> str | None:
        """Registry API URL that resolves the latest published version of a package.

        Used for unpinned installs (e.g. `pip install requests`) to determine the
        version that will be installed before running the cooldown check. Return None
        to skip version resolution for unpinned installs in this ecosystem.
        Default implementation returns None."""

    def latest_version_parse(self, data: object, name: str) -> str | None:
        """Extract the latest version string from the response of latest_version_url().

        *data* is typed ``object``, not ``dict``, for the same reason as
        publication_date_parse: a JSON document's root is not always an
        object. Narrow with ``isinstance`` before indexing/iterating.

        Return None if the version cannot be determined. Called with the parsed JSON
        body and the package name. Default implementation returns None."""

    # ── Sandbox argv preprocessing ─────────────────────────────────────────
    def prepare_sandbox_argv(self, argv: list[str], cwd: Path) -> list[str]:
        """Pre-process argv before it is passed to the sandbox.

        Override to canonicalise arguments the sandbox requires in a specific form,
        e.g. resolving relative paths to absolute (pip editable installs).
        Default returns argv unchanged."""

    def sandbox_extra_ro_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        """Additional paths to expose read-only inside the sandbox.

        Called with the prepared argv (after prepare_sandbox_argv). Override to expose
        paths referenced by argv that lie outside the project root and would otherwise
        be hidden by the home tmpfs.
        Default returns []."""

    def sandbox_extra_write_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        """Additional paths to bind writable inside the sandbox.

        Called with the prepared argv (after prepare_sandbox_argv). Override to expose
        paths the install process must write to, e.g. editable install source directories
        where egg-info or build artifacts are written.
        Default returns []."""

    def post_run_scan_targets(self, parsed: Any, cwd: Path) -> list[Path]:
        """Install targets that may have been created during the sandbox run.

        Called after the sandbox exits, but only when no scan targets were detected
        before the run (i.e. the install directory did not exist yet). Use this to
        handle package managers that create their install directory from scratch
        (e.g. uv creating .venv on first sync).

        *parsed* is a ``ParsedInstall`` from ``packagealert.parsers.process_args``
        (not ``ProcessInstall``). Useful fields: ``manager`` (str), ``ecosystem``
        (str), ``packages`` (list[str]), ``venv_exe`` (str | None),
        ``req_files`` (list[str]), ``lockfile_hint`` (str | None),
        ``global_install`` (bool).

        Return a list of paths ordered from outermost to innermost:
        - The first path is the **rollback root** — removed entirely on rollback.
        - The last path is the **scan target** — diffed for new packages.

        If the rollback root and scan target are the same, return a single-element list.
        Return [] if no targets were created (the default).

        Example for a fresh Python venv:
            return [Path(cwd / ".venv"), Path(cwd / ".venv/lib/python3.12/site-packages")]
        """
        return []

    def pre_run_check(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str] = frozenset(),
    ) -> PreRunResult:
        """Return a PreRunResult indicating whether to allow or block the run.

        Called before the sandbox runs. When ok=False the runner prints
        message with markup=False and exits 1. Use embedded newlines in
        message for multi-line output (e.g. to include a remediation hint).
        Default returns PreRunResult(ok=True).

        *flags* is the set of capability names for this module, with the
        namespace prefix already stripped by the runner (e.g. if the user
        passes ``--flags python:ssh-keys``, the Python module receives
        ``frozenset({"ssh-keys"})``).

        *parsed* is a ``ParsedInstall`` when this is the primary ecosystem
        language, or ``None`` when invoked for a cross-namespace flag (e.g.
        ``--flags python:ssh-keys`` during ``npm install``). Always guard
        access with ``if parsed is not None``.

        **Legacy plugins:** if your plugin still declares ``expose_ssh_keys``
        as a positional parameter, the runner detects this via
        ``inspect.signature`` and passes ``False``. This is safe because
        ``expose_ssh_keys`` was only ever declared by plugins because the old
        ``LanguageBase`` had it — no third-party plugin ever read or acted on
        the value. The runner emits a ``DeprecationWarning`` on load. Remove
        ``expose_ssh_keys`` from your signature and use ``flags`` instead."""

    def configure_sandbox(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
        home_ro: list[Path],
        sandbox_env: dict[str, str],
    ) -> None:
        """Mutate sandbox configuration in-place based on active flags.

        Called after pre_run_check passes, before the sandbox is built.
        Override to expose additional paths or inject environment variables
        when specific capability flags are active. *flags* contains only the
        stripped capability names for this module (e.g. ``"ssh-keys"``, not
        ``"python:ssh-keys"``).

        *parsed* is ``None`` in two situations: shell mode
        (``package-alert shell`` / ``package-alert run bash``), and when this
        plugin's namespace has active flags but its ecosystem is not the primary
        one for the current install (e.g. ``--flags python:ssh-keys`` during
        ``npm install`` invokes the Python plugin with ``parsed=None``). Always
        guard access with ``if parsed is not None``.

        *targets* — read-only context: the SandboxTargets already resolved and
        snapshotted by resolve_sandbox_targets. Mutations are ignored.
        *home_ro* — list of home-directory paths to expose read-only; append
        to this list to re-expose paths hidden by the home tmpfs.
        *sandbox_env* — environment dict forwarded into the sandbox; mutate
        in-place to inject variables.

        Default is a no-op."""

    def configure_sandbox_writable(
        self,
        parsed: ParsedCommand | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
    ) -> list[tuple[Path, Path]]:
        """Return `(src, dest)` pairs for writable bind mounts.

        Each *src* is a temporary directory you create; *dest* is where it is
        mounted inside the sandbox at the real path of the resource you are
        snapshotting. The runner owns cleanup of *src* after the sandbox exits
        — do not delete it yourself.

        Use this when a flag needs a resource to be writable inside the sandbox
        but the real resource must not be modified (e.g. a credential store that
        requires a write lock to read). Create a temp dir with
        ``tempfile.mkdtemp()``, copy the resource into it with
        ``shutil.copytree``, and return the pair.

        *parsed* is ``None`` in shell mode and for cross-namespace flags —
        guard with ``if parsed is not None`` if you need it.

        **Example (uv credentials snapshot):**

        ```python
        def configure_sandbox_writable(self, parsed, cwd, flags, targets):
            if "uv-auth" not in flags:
                return []
            creds_dir = self._uv_credentials_dir()
            if not creds_dir.exists():
                return []
            tmp = Path(tempfile.mkdtemp(prefix="pa-uv-auth-"))
            shutil.copytree(creds_dir, tmp, dirs_exist_ok=True)
            return [(tmp, creds_dir)]
        ```

        Default returns ``[]``."""

    def resolve_sandbox_targets(self, parsed: Any, cwd: Path) -> SandboxTargets:
        """Return scan targets and extra writable dirs for this install.

        Replaces the per-ecosystem if/elif branches that previously lived in the
        runner. scan_targets are diffed for new packages; write_dirs are bound
        writable inside the sandbox. Default returns empty SandboxTargets.

        *parsed* is a ``ParsedInstall`` — see ``post_run_scan_targets`` for
        the available fields.

        **Surfacing warnings to the user:** if something goes wrong that degrades
        scan coverage or rollback completeness (e.g. a configuration file cannot
        be parsed, an expected directory is missing), add a human-readable message
        to ``SandboxTargets.warnings``. The runner prints each entry to the
        terminal in bold yellow immediately after calling this hook, regardless of
        log level. Always combine with ``log.warning()`` so the message also
        appears in the log file."""
        return SandboxTargets()

    def prepare_sandbox_env(self, parsed: Any, cwd: Path, env: dict[str, str]) -> list[Path]:
        """Mutate *env* in-place and return additional write dirs.

        Called just before build_cmd. Use to inject language-specific variables
        (e.g. VIRTUAL_ENV, PATH prepends). Returned paths are bound writable
        inside the sandbox. Default returns [].

        *parsed* is a ``ParsedInstall`` — see ``post_run_scan_targets`` for
        the available fields.

        **Blocking the run:** raise ``SandboxEnvError`` with a user-visible message
        to abort the run (e.g. no virtualenv found). The runner prints the message
        and exits 1. Do not use ``pre_run_check`` for conditions that are only
        detectable after env setup."""
        return []

    def shell_environment(self, cwd: Path) -> ShellEnvironment:
        """Return the shell session environment for this language.

        Called at the start of an interactive shell session. Results from all
        registered language modules are merged by the runner. Default returns
        empty ShellEnvironment.

        **Surfacing warnings to the user:** add messages to
        ``ShellEnvironment.warnings`` for conditions that degrade scan or rollback
        coverage. The runner prints them to the terminal in bold yellow. See
        ``resolve_sandbox_targets`` for the same pattern."""
        return ShellEnvironment()

    def package_manager_names(self) -> list[str]:
        """Pure package manager binary names (pip, npm, uv, composer, …).

        Used by `setup shell` to generate shell functions and by `setup project`
        to write plain pass-through shims. Must NOT include runtime interpreters
        (python, node, php) — those are handled by interpreter_names().
        Default implementation returns []."""

    def interpreter_names(self) -> list[str]:
        """Runtime interpreter names (python, python3, node, php, …).

        `setup project` installs a shim for each name returned here. The shim
        script is provided by interpreter_shim_script() — if that returns None
        a plain passthrough shim is used instead.
        Default implementation returns []."""

    def interpreter_shim_script(self, real: Path, pa: Path) -> str | None:
        """Return a complete sh(1) shim script for a runtime interpreter, or None.

        Called by `setup project` when writing an interpreter shim. *real* is
        the Path to the renamed original binary (e.g. ``python3.__pa_real``).
        *pa* is the Path to the package-alert executable.

        The script must either exec *pa* (to route through package-alert), exec
        *real* (to bypass it), or exit with a non-zero status for guard failures
        (e.g. *real* is missing or the install is in an inconsistent state). It
        must not return silently without taking one of these three actions.

        The script must also include the package-alert fingerprint and version
        marker so staleness detection works:

            from packagealert.cli.setup_cmd import PA_FINGERPRINT, PA_SHIM_VERSION_MARKER

        Return None to use the default plain passthrough shim, which routes all
        invocations through `pa run`. Only override when the interpreter supports
        a sub-command style that needs selective routing — e.g. Python's `-m pip`,
        or a future Ruby plugin intercepting `-S gem`.
        Default implementation returns None."""

    # ── Snapshots ──────────────────────────────────────────────────────────
    def snapshot(self, install_root: Path) -> Snapshot:
        """Capture installed-package state before an install runs."""

    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]:
        """Diff two snapshots and return packages that appeared in after but not before."""
```

#### `configure_sandbox_writable` (optional, contract v4)

```python
def configure_sandbox_writable(
    self,
    parsed: ParsedCommand | None,
    cwd: Path,
    flags: frozenset[str],
    targets: SandboxTargets,
) -> list[tuple[Path, Path]]:
```

Return `(src, dest)` pairs for writable bind mounts. Each *src* is a temporary directory you create; *dest* is where it is mounted inside the sandbox at the real path of the resource you are snapshotting. The runner owns cleanup of *src* after the sandbox exits — do not delete it yourself.

Use this when a flag needs a resource to be writable inside the sandbox but the real resource must not be modified (e.g. a credential store that requires a write lock to read). Create a temp dir with `tempfile.mkdtemp()`, copy the resource into it with `shutil.copytree`, and return the pair.

*parsed* is `None` in shell mode and for cross-namespace flags — guard with `if parsed is not None` if you need it.

Default returns `[]`.

**Example (uv credentials snapshot):**

```python
def configure_sandbox_writable(self, parsed, cwd, flags, targets):
    if "uv-auth" not in flags:
        return []
    creds_dir = Path.home() / ".local" / "share" / "uv" / "credentials"
    if not creds_dir.exists():
        return []
    tmp = Path(tempfile.mkdtemp(prefix="pa-uv-auth-"))
    shutil.copytree(creds_dir, tmp, dirs_exist_ok=True)
    return [(tmp, creds_dir)]
```

---

## Writing an In-Tree Module

In-tree modules live in [`packagealert/languages/`](packagealert/languages/). Use [`python.py`](packagealert/languages/python.py) as the reference implementation.

1. Create `packagealert/languages/<name>.py` implementing all contract methods.
2. Set `contract_version = CURRENT_CONTRACT_VERSION`.
3. Register it in `registry.load()` in [`registry.py`](packagealert/languages/registry.py).
4. Write tests in `tests/unit/languages/test_<name>.py` covering every method.

---

## Writing an External Plugin

External plugins are auto-discovered at startup via Python entry points.

See [Contract Version](#contract-version) above: unlike in-tree modules, an external
plugin must declare `contract_version` as a fixed integer literal matching what it has
actually implemented, not `CURRENT_CONTRACT_VERSION`.

### 1. Implement the contract

```python
# my_ruby_plugin.py
from pathlib import Path
from typing import Any
import httpx
from packagealert.languages.base import (
    MAX_TOP_PACKAGES,
    PackageMetadata,
    PackageSpec,
    PreRunResult,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
    normalise_package_name,
)


class RubyLanguage:
    name = "ruby"
    ecosystems = ["RubyGems"]
    process_names = ["gem", "bundle", "bundler"]
    # A hardcoded literal — the highest contract version this plugin has
    # actually implemented and verified, NOT an import of
    # CURRENT_CONTRACT_VERSION. This plugin is released independently of
    # package-alert, so nothing keeps its declared version in sync with a
    # future contract bump; only bump this by hand once you've implemented
    # whatever that version adds.
    contract_version = 5

    def parse_process_install(self, args: list[str]) -> ProcessInstall | None:
        return None  # implement me

    def parse_lockfile(self, path: Path) -> list[PackageSpec]:
        return []

    def inspect_package(self, path: Path) -> PackageMetadata | None:
        return None

    def cache_paths(self) -> list[Path]:
        return []

    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        return None

    def heuristics(self):
        return []

    def lockfile_patterns(self) -> list[str]:
        return ["Gemfile.lock"]

    def detect_installed_packages(self, root: Path) -> list[PackageMetadata]:
        return []

    def sandbox_paths(self) -> SandboxPaths:
        return SandboxPaths()

    def sandbox_env(self) -> list[str]:
        return [
            "GEM_HOME", "GEM_PATH",
            "BUNDLE_PATH", "BUNDLE_WITHOUT",
            "RUBYGEMS_HOST",
        ]

    def top_packages_url(self) -> str | None:
        return "https://rubygems.org/api/v1/downloads.json"  # implement me

    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        resp = await client.get(url)
        resp.raise_for_status()
        # Adapt to your registry's actual response shape:
        gems = resp.json()  # e.g. [{"name": "rails", ...}, ...]
        return [normalise_package_name(g["name"]) for g in gems[:MAX_TOP_PACKAGES]]

    def top_packages_fallback(self) -> list[str]:
        return ["rails", "sinatra", "devise", "pundit", "rspec"]

    def publication_date_url(self, name: str, version: str) -> str | None:
        # Return the registry API URL for the publication date of this version.
        # Used by the cooldown policy. Return None to opt out.
        return f"https://rubygems.org/api/v1/versions/{name}.json"  # implement me

    def publication_date_parse(self, data: object, version: str | None) -> float | None:
        # Parse the response from publication_date_url() into a Unix timestamp.
        # RubyGems' versions.json returns a JSON array at the root (not an
        # object), which is exactly why this hook is typed `object` rather
        # than `dict` — narrow with isinstance before use, as here.
        for entry in data if isinstance(data, list) else []:
            if entry.get("number") == version:
                created_at = entry.get("created_at")
                if created_at:
                    from datetime import datetime
                    return datetime.fromisoformat(created_at).timestamp()
        return None

    def osv_ecosystem(self) -> str | None:
        return "RubyGems"

    def normalise_name(self, name: str) -> str:
        return name.lower()

    def package_manager_names(self) -> list[str]:
        # Binaries to wrap as shell functions and shim in project bin dirs.
        return ["gem", "bundle", "bundler"]

    def project_shim_names(self) -> list[str]:
        # Subset of package_manager_names() to shim in project bin dirs.
        # Exclude tools that manage global state or self-update.
        return ["bundle", "bundler"]

    def interpreter_names(self) -> list[str]:
        # Runtime interpreter names that may invoke package managers indirectly.
        # Ruby has no standard -m style invocation, so this is empty.
        return []

    def project_bin_dirs(self, root: Path) -> list[Path]:
        # Return bin/ directories within root that contain this language's tools.
        p = root / "vendor" / "bundle" / "bin"
        return [p] if p.is_dir() else []

    def latest_version_url(self, name: str) -> str | None:
        return f"https://rubygems.org/api/v2/rubygems/{name}/versions/latest.json"

    def latest_version_parse(self, data: object, name: str) -> str | None:
        # Adapt to your registry's actual response shape. Narrow first: data
        # is `object`, not `dict` — this endpoint happens to return a JSON
        # object, but the contract does not guarantee that for every registry.
        if not isinstance(data, dict):
            return None
        return data.get("version") or None

    def prepare_sandbox_argv(self, argv: list[str], cwd: Path) -> list[str]:
        # Override if any arguments need canonicalisation before entering the sandbox.
        return argv

    def sandbox_extra_ro_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    def sandbox_extra_write_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    def pre_run_check(self, parsed: Any, cwd: Path, flags: frozenset[str] = frozenset()) -> PreRunResult:
        # parsed is a ParsedInstall (not ProcessInstall) — see contract docs for fields.
        # Return PreRunResult(ok=False, message=...) to block, or PreRunResult(ok=True) to allow.
        # flags contains namespace-stripped capability names (e.g. "ssh-keys", not "ruby:ssh-keys").
        return PreRunResult(ok=True)

    def resolve_sandbox_targets(self, parsed: Any, cwd: Path) -> SandboxTargets:
        # parsed is a ParsedInstall — see contract docs for fields.
        # Return scan targets and writable dirs for this ecosystem's install.
        return SandboxTargets()

    def prepare_sandbox_env(self, parsed: Any, cwd: Path, env: dict[str, str]) -> list[Path]:
        # parsed is a ParsedInstall — see contract docs for fields.
        # Mutate env in-place; return extra paths to bind writable.
        return []

    def shell_environment(self, cwd: Path) -> ShellEnvironment:
        # Return shell session environment for interactive shells.
        return ShellEnvironment()

    def post_run_scan_targets(self, parsed: Any, cwd: Path) -> list[Path]:
        # parsed is a ParsedInstall — see contract docs for fields.
        # Override if the package manager creates its install directory during the run.
        # Return [install_root, scan_target] so rollback removes the whole tree and
        # new-package detection diffs the right subdirectory.
        return []

    def resolve_package_dir(
        self,
        package_name: str,
        project_path: Path | None,
        site_packages_dir: Path | None,
        version: str | None = None,
    ) -> list[Path]:
        # Return every directory where package_name was extracted after install,
        # so the daemon can run file-content heuristics against them.
        # Return [] if no directory can be determined for this ecosystem.
        #
        # Accept `version` even if you do not use it, so the signature matches the
        # contract version you declare. Bundler installs one version per gem at a
        # given path, so the name alone identifies the tree here — but a layout
        # where two environments can hold different versions of one package must
        # match it, or heuristics inspect the wrong source.
        if project_path is None:
            return []
        return [project_path / "vendor" / "bundle" / "ruby" / package_name]  # example

    def resolve_package_dir_manifest_warning(
        self,
        package_name: str,
        project_path: Path | None,
        site_packages_dir: Path | None,
        version: str | None = None,
    ) -> str | None:
        # Bundler resolves a direct, unambiguous path above with no manifest
        # file to parse — nothing here can be corrupted the way PyPI's RECORD
        # can, so there is nothing to warn about. Override this only if your
        # resolve_package_dir consults a manifest that could plausibly be
        # crafted or corrupted to evade heuristics.
        return None

    def snapshot(self, install_root: Path) -> Snapshot:
        return Snapshot({})

    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]:
        return []
```

### 2. Declare the entry point

In your package's `pyproject.toml`:

```toml
[project.entry-points."package_alert.languages"]
ruby = "my_ruby_plugin:RubyLanguage"
```

### 3. Install and verify

```bash
uv add my-ruby-plugin      # or: pip install my-ruby-plugin
package-alert config-show     # "ruby" should appear in loaded languages
```

---

## Example plugin: Rust / Cargo *(incomplete)*

[`examples/package-alert-rust/`](examples/package-alert-rust/) is a working but
incomplete language plugin for the Rust ecosystem (Cargo / crates.io). It is
provided as a reference implementation and a starting point — not for production use.

### What works

| Mechanism | Status |
|-----------|--------|
| Entry-point wiring | ✅ loads correctly; visible in `package-alert languages list` |
| `scan-project` | ✅ parses `Cargo.lock` and returns all crates with versions |
| Process detection | ✅ recognises `cargo add` (defers to lockfile) and `cargo install` |
| `scan-cache` | ✅ walks `~/.cargo/registry/src` via `Cargo.toml` pattern |
| Typosquatting baseline | ✅ fetches top-100 crates from crates.io API; has static fallback |
| Snapshot diffing | ✅ diffs `Cargo.lock` before and after an install |

### Known gaps

- **`detect_installed_packages()`** returns nothing — needs to parse `~/.cargo/.crates.toml`
- **`classify_cache_file()` can false-positive** on workspace members and path-dependency `Cargo.toml` files that are not registry crates
- **No heuristics** — `build.rs` (Rust build scripts) are the primary supply-chain attack surface and are not yet flagged
- **Version specifiers not parsed** — `cargo add serde@1.0` and `cargo install ripgrep --version 14.0` are silently dropped
- **No tests**

### Install and test manually

```bash
# Install into the package-alert dev environment
pip install -e examples/package-alert-rust
# or with uv:
uv pip install -e examples/package-alert-rust
```

**Verify it loaded:**

```bash
package-alert languages list        # should include a "rust" row
package-alert languages info rust   # shows ecosystems, process names, lockfile patterns
```

**Test `scan-project`:**

```bash
cd /path/to/a/rust/project   # must have Cargo.lock
package-alert scan-project
```

Expected: crates listed under `cargo (Cargo.lock)`.

**Test process monitoring** (daemon must be running):

```bash
package-alert daemon &
cd /path/to/a/rust/project
cargo add serde
```

Expected: daemon log shows `Tracking cargo install pid=<N>`, then scans `Cargo.lock` on exit.

**Test typosquatting detection:**

```bash
package-alert query serd --ecosystem crates.io
```

Expected: `typosquat` signal in the risk report (close match to `serde`).

**Uninstall:**

```bash
pip uninstall package-alert-rust
```

---

## Surfacing Errors and Warnings to the User

package-alert routes plugin output to the terminal in three ways. Choose the right one based on severity and timing.

### 1. Block the run with an error — `pre_run_check`

Return a `PreRunResult(ok=False, message=...)` from `pre_run_check()`. The runner prints `message` in **bold red** and exits 1 before the sandbox starts. Use for hard pre-conditions that cannot be satisfied (e.g. wrong virtualenv active, a required capability flag is missing).

If blocking because a specific flag is needed, populate `required_flag` with the flag name (e.g. `"python:ssh-keys"`) — this is included in diagnostics.

```python
from packagealert.languages.base import PreRunResult

def pre_run_check(self, parsed, cwd, flags=frozenset()):
    if "ssh-keys" not in flags:
        return PreRunResult(
            ok=False,
            message="✗ Cannot proceed: SSH keys required.\nFix: re-run with --flags python:ssh-keys.",
            required_flag="python:ssh-keys",
        )
    return PreRunResult(ok=True)
```

> **Legacy plugins**: older contract v1/v2 plugins may declare `expose_ssh_keys` as a positional parameter. The runner detects this via `inspect.signature` and passes it accordingly, but emits a `DeprecationWarning` on load. Remove `expose_ssh_keys` from your signature and use `flags` instead.

### 2. Block sandbox env setup — `SandboxEnvError`

Raise `SandboxEnvError` from `prepare_sandbox_env()` when a condition is only detectable after env setup (e.g. no virtualenv found for bare `pip install`). The runner prints the message in **bold red** and exits 1.

```python
from packagealert.languages.base import SandboxEnvError

def prepare_sandbox_env(self, parsed, cwd, env):
    if not can_proceed:
        raise SandboxEnvError("✗ <reason>.\n<how to fix>.")
    return []
```

### 3. Warn about degraded coverage — `warnings` field

Add strings to `SandboxTargets.warnings` (from `resolve_sandbox_targets`) or `ShellEnvironment.warnings` (from `shell_environment`) when something goes wrong that reduces scan or rollback coverage but should not abort the run. The runner prints each message in **bold yellow** immediately after the hook returns, regardless of log level.

Always pair with `log.warning()` so the message also appears in the log file.

```python
def resolve_sandbox_targets(self, parsed, cwd):
    targets = SandboxTargets()
    if problem_detected:
        msg = "⚠ <what failed> — <what won't work as a result>."
        log.warning(msg)
        targets.warnings.append(msg)
    return targets
```

### What NOT to use

- `log.warning()` alone — only visible if the user sets an appropriate log level with `-v`.
- `log.debug()` — invisible to users entirely; reserve for internal diagnostic detail.
- Printing to stdout directly — bypasses Rich formatting and may not flush correctly.

---

## Contract Version Changelog

| Version | What changed |
|---------|-------------|
| 1 | Initial contract. All methods listed above. `publication_date_url`, `package_manager_names`, `interpreter_names`, `latest_version_url`, `latest_version_parse`, `prepare_sandbox_argv`, `sandbox_extra_ro_paths`, `sandbox_extra_write_paths`, and `post_run_scan_targets` added as optional methods with default no-op implementations (no version bump required). |
| 2 | `SandboxTargets` and `ShellEnvironment` dataclasses added. `pre_run_check`, `resolve_sandbox_targets`, `prepare_sandbox_env`, `shell_environment`, `resolve_package_dir`, and `interpreter_shim_script` added as optional hooks with default no-op implementations (no version bump required for existing plugins). `interpreter_shim_script(real, pa)` lets language modules supply their own interpreter shim script; the default returns None (plain passthrough shim). |
| 3 | Added `popularity_ecosystem() -> str | None` optional hook. Plugins returning `None` (the default) are unaffected; implement to enable popularity dampening for your ecosystem. Added `PreRunResult` dataclass (`ok`, `message`, `required_flag`). `pre_run_check` now accepts a `flags: frozenset[str]` parameter and returns `PreRunResult` instead of `str | None`; the `expose_ssh_keys: bool` parameter is deprecated. Added `configure_sandbox(parsed, cwd, flags, targets, home_ro, sandbox_env) -> None` hook for flag-driven sandbox configuration; default is a no-op. |
| 4 | Added optional `configure_sandbox_writable(parsed, cwd, flags, targets) -> list[tuple[Path, Path]]` hook. Default returns `[]`. Runner collects `(src, dest)` pairs from all active language modules, binds them writably into the sandbox, and deletes *src* in a `finally` block after the sandbox exits. Use for resources that require write access inside the sandbox but must not be modified on the host (snapshot pattern). |
| 5 | Moved ecosystem-specific registry-response parsing out of core modules and onto the contract, so adding a language no longer requires editing core code. Added three optional hooks: `publication_date_parse(data, version) -> float \| None` (parses the reply from `publication_date_url()`; **without it the cooldown policy cannot determine package age and fails open, never blocking or prompting**), `osv_ecosystem() -> str \| None` (the name OSV.dev uses, e.g. `"PyPI"`; without it advisory matching falls back to the raw ecosystem string and upgrade advice may be empty), and `normalise_name(name) -> str` (name-equality rules for advisory matching; defaults to lowercasing, PyPI overrides with PEP 503 collapsing). Plugins declaring v4 or earlier receive shims reproducing their previous behaviour exactly, so no plugin breaks — but implementing `publication_date_parse` is strongly recommended if you implement `publication_date_url`. Also added an optional 4th parameter to `resolve_package_dir`: `version: str \| None = None`. Declare it however you like — `version=None`, `*, version=None`, or absorb it with `**kwargs`; callers inspect the signature and pass it by keyword unless only positional passing is possible (positional-only parameters or a bare `*args`). Whether you *use* it depends on your install layout: one directory per package name (npm's `node_modules`, Composer's `vendor/`) needs no version check, since a second version cannot occupy the same path; layouts where several environments under one project can each hold a different version (Python venvs) must match it. Accept the parameter either way, so the signature matches the contract you declare. When given it **must** be matched as well as the name: a caller may search several environments — `scan-project --scan-installed` aggregates packages across every venv it finds — and two of them can hold different versions of the same package. Matching on name alone returned whichever environment was searched first, so heuristics inspected the wrong source tree and a malicious version was scored against a benign one. Return `[]` rather than a name-only match when the requested version is absent. No shim is required for the `version` parameter itself: callers inspect the signature and omit the argument for plugins that predate it, preserving the previous name-only behaviour. **`resolve_package_dir`'s return type is `list[Path]`, not `Path \| None`** — `[]` replaces `None` as the "not resolvable" case. A single directory is not always a distribution's whole footprint: a PEP 420 namespace package (`google-auth`) can own more than one subdirectory (`google/auth/`, `google/oauth2/`) of a shared root it does not exclusively own, and returning that shared root hands heuristics every sibling distribution's files too. Every directory returned must belong to *this* distribution and no other's. Unlike the parameter addition, this **does** require a shim: a plugin declaring contract version 4 or earlier whose `resolve_package_dir` still returns a bare `Path` or `None` is adapted automatically — its return value is wrapped (`None` → `[]`, `Path` → `[Path]`) by calling through to the plugin's real implementation, so the plugin's own resolution logic still runs and only the return shape changes. A plugin declaring `contract_version = 5` (or a later value, once one exists) must implement `list[Path]`/`[]` itself; the adapter only covers plugins declaring a version below the one at which this changed. Also added an optional fourth hook, `resolve_package_dir_manifest_warning(package_name, project_path, site_packages_dir, version=None) -> str \| None`, called alongside `resolve_package_dir` on the matched distribution: without it, `resolve_package_dir` correctly refusing to guess a directory for a manifest it cannot trust (e.g. PyPI's RECORD present but unparseable — a shape a legitimate build tool essentially never produces) is indistinguishable from an ordinary clean scan, silently downgrading a probable evasion attempt to "nothing to report." A non-`None` return becomes an undampened `unverifiable_manifest` risk signal. Plugins declaring v4 or earlier are shimmed to return `None` unconditionally; most in-tree implementations (npm, Composer) have no manifest file to distrust and also return `None` unconditionally by design, not merely by the shim. |
