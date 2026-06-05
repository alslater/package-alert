"""Incomplete example package-alert language plugin for Rust / Cargo / crates.io."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import httpx

from typing import Any

from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    MAX_TOP_PACKAGES,
    PackageMetadata,
    PackageSpec,
    ProcessInstall,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
    normalise_package_name,
)
from packagealert.heuristics.base import AbstractHeuristic

log = logging.getLogger(__name__)


def _parse_cargo_lock(path: Path) -> list[PackageSpec]:
    """Parse Cargo.lock (TOML v3 format) into PackageSpec objects."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            log.warning("tomllib/tomli not available; cannot parse Cargo.lock")
            return []
    try:
        data = tomllib.loads(path.read_text())
    except Exception:
        log.debug("Failed to parse Cargo.lock at %s", path)
        return []
    result = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version") or None
        if name:
            result.append(PackageSpec(name=name, version=version, ecosystem="crates.io"))
    return result


class CargoLanguage:
    """package-alert language plugin for Rust / Cargo / crates.io."""

    name = "rust"
    ecosystems = ["crates.io"]
    process_names = ["cargo"]
    contract_version = CURRENT_CONTRACT_VERSION
    author = "package-alert contributors"
    repository = "https://github.com/package-alert/package-alert-rust"

    # ------------------------------------------------------------------
    # Process monitoring
    # ------------------------------------------------------------------

    def parse_package_spec(self, raw: str) -> tuple[str, str | None]:
        # Cargo specs: name or name@version (exact) or name@^semver (range → None)
        name, _, ver = raw.partition("@")
        name = name.strip()
        import re
        version = ver.strip() if ver and re.match(r"^\d+\.\d+\.\d+", ver.strip()) else None
        return name, version

    def serialise_package_spec(self, name: str, version: str | None) -> str:
        return f"{name}@{version}" if version else name

    def parse_process_install(self, args: list[str]) -> ProcessInstall | None:
        """Detect `cargo add <crate>` and `cargo install <crate>` invocations."""
        if not args:
            return None
        exe = args[0].rsplit("/", 1)[-1]
        if exe != "cargo":
            return None
        if len(args) < 2:
            return None
        subcmd = args[1]

        if subcmd == "add":
            # cargo add serde serde_json  (skip flags)
            packages = [
                PackageSpec(name=a, version=None, ecosystem="crates.io")
                for a in args[2:]
                if not a.startswith("-")
            ]
            return ProcessInstall(
                manager="cargo",
                packages=packages,
                defer_to_lockfile=True,
            )

        if subcmd == "install":
            # cargo install ripgrep  (name only — no lockfile)
            packages = [
                PackageSpec(name=a, version=None, ecosystem="crates.io")
                for a in args[2:]
                if not a.startswith("-")
            ]
            return ProcessInstall(manager="cargo", packages=packages)

        return None

    # ------------------------------------------------------------------
    # Lockfile
    # ------------------------------------------------------------------

    def parse_lockfile(self, path: Path) -> list[PackageSpec]:
        if path.name != "Cargo.lock":
            return []
        return _parse_cargo_lock(path)

    def lockfile_patterns(self) -> list[str]:
        return ["Cargo.lock"]

    # ------------------------------------------------------------------
    # Package artifact inspection
    # ------------------------------------------------------------------

    def inspect_package(self, path: Path) -> PackageMetadata | None:
        return None

    # ------------------------------------------------------------------
    # Cache paths / classification
    # ------------------------------------------------------------------

    def cache_paths(self) -> list[Path]:
        # Cargo stores downloaded crates under ~/.cargo/registry
        return [Path.home() / ".cargo" / "registry" / "src"]

    def cache_file_globs(self) -> list[str]:
        # Each crate is unpacked into a directory named <crate>-<version>
        return ["**/Cargo.toml"]

    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        # A Cargo.toml directly inside a <crate>-<version> directory
        if path.name != "Cargo.toml":
            return None
        # Parent dir name is typically "<crate>-<version>"
        m = re.match(r"^(.+)-(\d[\d.]*)$", path.parent.name)
        if not m:
            return None
        return PackageMetadata(
            name=m.group(1),
            version=m.group(2),
            ecosystem="crates.io",
        )

    # ------------------------------------------------------------------
    # Installed packages
    # ------------------------------------------------------------------

    def detect_installed_packages(self, root: Path) -> list[PackageMetadata]:
        # Installed crate binaries live in ~/.cargo/bin — there's no
        # machine-readable index there, so we return nothing here.
        return []

    # ------------------------------------------------------------------
    # Heuristics
    # ------------------------------------------------------------------

    def heuristics(self) -> list[AbstractHeuristic]:
        return []

    # ------------------------------------------------------------------
    # Sandbox
    # ------------------------------------------------------------------

    def sandbox_paths(self) -> SandboxPaths:
        home = Path.home()
        return SandboxPaths(
            read_only=[home / ".cargo" / "config.toml"],
            writable=[home / ".cargo" / "registry"],
            hidden=[home / ".ssh", home / ".aws"],
        )

    def sandbox_env(self) -> list[str]:
        return ["CARGO_HOME", "CARGO_REGISTRY_TOKEN", "RUSTUP_HOME"]

    # ------------------------------------------------------------------
    # Shadow tools (setup shell / setup project)
    # ------------------------------------------------------------------

    def package_manager_names(self) -> list[str]:
        # Binaries to include in the shell function wrapper and project shims.
        return ["cargo"]

    def project_shim_names(self) -> list[str]:
        # cargo is a global tool, not installed into a project-local bin/ —
        # shimming it at the project level doesn't make sense.
        return []

    def interpreter_names(self) -> list[str]:
        # Rust has no interpreter that invokes cargo via -m style.
        return []

    def project_bin_dirs(self, root: Path) -> list[Path]:
        # Cargo does not create a project-local bin/ that needs shimming.
        return []

    def publication_date_url(self, name: str, version: str) -> str | None:
        return f"https://crates.io/api/v1/crates/{name}/{version}"

    def latest_version_url(self, name: str) -> str | None:
        return f"https://crates.io/api/v1/crates/{name}"

    def latest_version_parse(self, data: dict, name: str) -> str | None:
        # crates.io returns the newest version in crate.newest_version
        return data.get("crate", {}).get("newest_version") or None

    def prepare_sandbox_argv(self, argv: list[str], cwd: Path) -> list[str]:
        # No Cargo-specific argv canonicalisation needed.
        return argv

    def sandbox_extra_ro_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    def sandbox_extra_write_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    # ------------------------------------------------------------------
    # Sandbox hooks (contract version 2)
    # ------------------------------------------------------------------

    def pre_run_check(self, parsed: Any, cwd: Path, expose_ssh_keys: bool) -> str | None:
        # No pre-run checks needed for Cargo.
        return None

    def resolve_sandbox_targets(self, parsed: Any, cwd: Path) -> SandboxTargets:
        targets = SandboxTargets()
        # Cargo.lock lives under cwd; target/ is the build dir (not a package install target).
        # No additional scan targets beyond what the runner picks up from lockfile diffing.
        cargo_cache = Path.home() / ".cargo" / "registry"
        if cargo_cache.exists():
            targets.write_dirs.append(cargo_cache)
        return targets

    def prepare_sandbox_env(self, parsed: Any, cwd: Path, env: dict[str, str]) -> list[Path]:
        # No environment variables need to be injected beyond sandbox_env() names.
        return []

    def shell_environment(self, cwd: Path) -> ShellEnvironment:
        result = ShellEnvironment()
        cargo_cache = Path.home() / ".cargo" / "registry"
        if cargo_cache.exists():
            result.write_dirs.append(cargo_cache)
        return result

    def home_ro_paths(self) -> list[Path]:
        candidates = [
            Path.home() / ".cargo" / "config.toml",
            Path.home() / ".cargo" / "credentials.toml",
        ]
        return [p for p in candidates if p.exists()]

    def detect_new_packages(self, new_paths: set[Path], walk_root: Path) -> list[PackageSpec]:
        # Cargo does not install into a flat directory that _collect_new_packages
        # can diff — new packages are detected via Cargo.lock diffing instead.
        return []

    # ------------------------------------------------------------------
    # Top packages (typosquat baseline)
    # ------------------------------------------------------------------

    def top_packages_url(self) -> str | None:
        return "https://crates.io/api/v1/crates?sort=downloads&per_page=100"

    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        packages: list[str] = []
        next_url: str | None = url
        while next_url and len(packages) < MAX_TOP_PACKAGES:
            resp = await client.get(next_url, headers={"User-Agent": "package-alert"})
            resp.raise_for_status()
            data = resp.json()
            for crate in data.get("crates", []):
                packages.append(normalise_package_name(crate["id"]))
                if len(packages) >= MAX_TOP_PACKAGES:
                    break
            meta = data.get("meta", {})
            next_url = meta.get("next_page")
        return packages if packages else None

    def top_packages_fallback(self) -> list[str]:
        return [
            "serde", "serde-json", "tokio", "rand", "clap", "log",
            "anyhow", "thiserror", "reqwest", "hyper", "axum", "actix-web",
            "rayon", "regex", "chrono", "uuid", "tracing", "futures",
            "bytes", "once-cell", "lazy-static", "itertools", "indexmap",
            "parking-lot", "crossbeam", "dashmap", "num-traits", "num-derive",
        ]

    # ------------------------------------------------------------------
    # Snapshot / post-install detection
    # ------------------------------------------------------------------

    def snapshot(self, install_root: Path) -> Snapshot:
        lock = install_root / "Cargo.lock"
        if not lock.exists():
            return Snapshot(data={})
        data: dict[str, str] = {}
        for spec in _parse_cargo_lock(lock):
            data[spec.name] = spec.version or ""
        return Snapshot(data=data)

    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]:
        new_names = set(after.data) - set(before.data)
        return [
            PackageSpec(name=name, version=after.data[name] or None, ecosystem="crates.io")
            for name in new_names
        ]
