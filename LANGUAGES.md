# Language Module Guide

package-alert supports multiple package ecosystems through **language modules** — self-contained Python classes that implement the `LanguageBase` contract. This guide covers the contract, how to write an in-tree module, and how to publish an external plugin.

---

## The `LanguageBase` Contract

All language modules must satisfy the `LanguageBase` protocol defined in [`packagealert/languages/base.py`](packagealert/languages/base.py).

### Contract Version

Each module declares `contract_version: int` set to `CURRENT_CONTRACT_VERSION` (currently `1`). When a module is registered the registry checks this value:

| Declared version | Behaviour |
|-----------------|-----------|
| Equal to current | Registered normally. |
| Older than current | Warning logged; safe no-op shims applied for missing methods. Module remains functional. |
| Newer than current | Warning logged; registered, but newer methods will not be called by this version of package-alert. |
| Absent | Treated as version 1 (current); warning logged. |

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
```

---

### Contract Methods

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

    def latest_version_url(self, name: str) -> str | None:
        """Registry API URL that resolves the latest published version of a package.

        Used for unpinned installs (e.g. `pip install requests`) to determine the
        version that will be installed before running the cooldown check. Return None
        to skip version resolution for unpinned installs in this ecosystem.
        Default implementation returns None."""

    def latest_version_parse(self, data: dict, name: str) -> str | None:
        """Extract the latest version string from the response of latest_version_url().

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

    def package_manager_names(self) -> list[str]:
        """Pure package manager binary names (pip, npm, uv, composer, …).

        Used by `setup shell` to generate shell functions and by `setup project`
        to write plain pass-through shims. Must NOT include runtime interpreters
        (python, node, php) — those are handled by interpreter_names().
        Default implementation returns []."""

    def interpreter_names(self) -> list[str]:
        """Runtime interpreter names (python, python3, node, php, …).

        `setup project` writes a special shim for these that intercepts
        `-m pip`-style invocations and routes them through package-alert,
        while passing all other arguments straight to the real interpreter.
        Default implementation returns []."""

    # ── Snapshots ──────────────────────────────────────────────────────────
    def snapshot(self, install_root: Path) -> Snapshot:
        """Capture installed-package state before an install runs."""

    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]:
        """Diff two snapshots and return packages that appeared in after but not before."""
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

### 1. Implement the contract

```python
# my_ruby_plugin.py
from pathlib import Path
import httpx
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    MAX_TOP_PACKAGES,
    PackageMetadata,
    PackageSpec,
    ProcessInstall,
    SandboxPaths,
    Snapshot,
    normalise_package_name,
)


class RubyLanguage:
    name = "ruby"
    ecosystems = ["RubyGems"]
    process_names = ["gem", "bundle", "bundler"]
    contract_version = CURRENT_CONTRACT_VERSION

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

    def latest_version_parse(self, data: dict, name: str) -> str | None:
        # Adapt to your registry's actual response shape.
        return data.get("version") or None

    def prepare_sandbox_argv(self, argv: list[str], cwd: Path) -> list[str]:
        # Override if any arguments need canonicalisation before entering the sandbox.
        return argv

    def sandbox_extra_ro_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    def sandbox_extra_write_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

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

## Contract Version Changelog

| Version | What changed |
|---------|-------------|
| 1 | Initial contract. All methods listed above. `publication_date_url`, `package_manager_names`, `interpreter_names`, `latest_version_url`, `latest_version_parse`, `prepare_sandbox_argv`, `sandbox_extra_ro_paths`, and `sandbox_extra_write_paths` added as optional methods with default no-op implementations (no version bump required). |
