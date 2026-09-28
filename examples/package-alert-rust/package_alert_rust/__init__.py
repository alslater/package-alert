"""Incomplete example package-alert language plugin for Rust / Cargo / crates.io."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, ClassVar

import httpx

from packagealert.heuristics.base import AbstractHeuristic
from packagealert.languages.base import (
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
    except Exception:  # noqa: BLE001 — malformed/unreadable lockfile, best-effort parse
        log.debug("Failed to parse Cargo.lock at %s", path)
        return []
    result = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version") or None
        if name:
            result.append(PackageSpec(name=name, version=version, ecosystem="crates.io"))
    return result


# Options that consume the next argument (`<VALUE>` in `cargo <cmd> --help`).
# cargo's global options may appear before the subcommand or after it.
# Audited against: cargo 1.97.1 `cargo --help` / `cargo add --help` /
# `cargo install --help`, plus the hidden `--vers` alias from cargo's source
# (src/bin/cargo/commands/install.rs) — help output does not list aliases.
_CARGO_GLOBAL_VALUE_FLAGS = frozenset({"--explain", "--color", "-C", "--config", "-Z"})
_CARGO_ADD_VALUE_FLAGS = _CARGO_GLOBAL_VALUE_FLAGS | frozenset({
    "-F", "--features", "--rename", "-m", "--manifest-path", "--path", "--base",
    "--git", "--branch", "--tag", "--rev", "--registry", "--target",
})
_CARGO_INSTALL_VALUE_FLAGS = _CARGO_GLOBAL_VALUE_FLAGS | frozenset({
    "--version", "--vers", "--index", "--registry", "--git", "--branch", "--tag",
    "--rev", "--path", "--root", "--message-format", "-F", "--features", "-j",
    "--jobs", "--profile", "--target-dir",
})
# OPTIONAL values (`[<VALUE>]`): clap consumes the next argument for these
# only when it does not start with `-`.
_CARGO_ADD_OPTIONAL_VALUE_FLAGS = frozenset({"-p", "--package"})
_CARGO_INSTALL_OPTIONAL_VALUE_FLAGS = frozenset({"--bin", "--example", "--target"})


def _consumes(flag: str, nxt: str | None, value_flags: frozenset[str], optional: frozenset[str]) -> bool:
    if flag in value_flags:
        return True
    return flag in optional and nxt is not None and not nxt.startswith("-")


def _skip_options(args: list[str], value_flags: frozenset[str], optional: frozenset[str]) -> int:
    """Index of the first argument that is neither an option nor its value."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        nxt = args[i + 1] if i + 1 < len(args) else None
        i += 2 if _consumes(args[i], nxt, value_flags, optional) else 1
    return i


def _positionals(args: list[str], value_flags: frozenset[str], optional: frozenset[str]) -> list[str]:
    """Positional arguments, skipping options and the values they consume."""
    result: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            result.extend(args[i + 1:])
            break
        if arg.startswith("-"):
            nxt = args[i + 1] if i + 1 < len(args) else None
            i += 2 if _consumes(arg, nxt, value_flags, optional) else 1
            continue
        result.append(arg)
        i += 1
    return result


def _option_value(args: list[str], names: frozenset[str]) -> str | None:
    """The value of the last of `names` (`--opt X`, `--opt=X` or `-CX`)."""
    value: str | None = None
    for i, arg in enumerate(args):
        if arg == "--":
            break
        if arg in names and i + 1 < len(args):
            value = args[i + 1]
            continue
        for name in names:
            if name.startswith("--") and arg.startswith(name + "="):
                value = arg[len(name) + 1:]
            elif len(name) == 2 and arg.startswith(name) and len(arg) > 2:
                value = arg[2:]
    return value


class CargoLanguage:
    """package-alert language plugin for Rust / Cargo / crates.io."""

    name = "rust"
    ecosystems: ClassVar[list[str]] = ["crates.io"]
    process_names: ClassVar[list[str]] = ["cargo"]
    # Pinned to the highest contract version this plugin actually implements —
    # NOT CURRENT_CONTRACT_VERSION. This plugin predates v5 (resolve_package_dir
    # here still returns Path | None, not list[Path], and it implements none of
    # publication_date_parse/osv_ecosystem/normalise_name), so declaring v5 would
    # falsely claim full compliance: the registry only shims/adapts a plugin
    # declaring a version *below* the one that changed, so an equal-to-current
    # declaration gets no protection at all. Bump this only after actually
    # implementing whatever a future contract version adds.
    contract_version = 4
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
        """Detect `cargo add <crate>` and `cargo install <crate>` invocations.

        Applies the rules in LANGUAGES.md, "Parsing process arguments"; the two
        most important:

        1. Find the subcommand behind any options that precede it. Returning
           None means "not an install" — the sandbox runner then executes the
           command directly with no sandbox and no pre-flight — so
           `cargo -q install x` must not be misread just because `-q` came first.
        2. Never read an option's VALUE as a package: `cargo add serde
           --features derive` adds `serde`, not a crate called `derive`.
        """
        if not args:
            return None
        exe = args[0].rsplit("/", 1)[-1]
        if exe != "cargo":
            return None
        rest = args[1:]
        # rustup's toolchain selector (`cargo +nightly install x`) is consumed
        # by the rustup proxy before cargo sees its arguments.
        if rest and rest[0].startswith("+"):
            rest = rest[1:]
        i = _skip_options(rest, _CARGO_GLOBAL_VALUE_FLAGS, frozenset())
        if i >= len(rest):
            return None
        subcmd, tail = rest[i], rest[i + 1:]
        # `-C <dir>` changes the directory cargo runs in; `--manifest-path`
        # names the Cargo.toml to act on. Report both so package-alert scans
        # the right project (see ProcessInstall.working_dir / project_dir).
        working_dir = _option_value(rest, frozenset({"-C"}))
        manifest = _option_value(tail, frozenset({"-m", "--manifest-path"}))
        project_dir = str(Path(manifest).parent) if manifest else None

        if subcmd == "add":
            # cargo add serde serde_json
            # Positionals are specs, not bare names (`serde@1.0.38`): split
            # each one, or the name keeps its `@version` and is not a valid
            # crate name at all.
            packages = [
                PackageSpec(name=name, version=version, ecosystem="crates.io")
                for name, version in (
                    self.parse_package_spec(a)
                    for a in _positionals(tail, _CARGO_ADD_VALUE_FLAGS, _CARGO_ADD_OPTIONAL_VALUE_FLAGS)
                )
            ]
            return ProcessInstall(
                manager="cargo",
                packages=packages,
                defer_to_lockfile=True,
                working_dir=working_dir,
                project_dir=project_dir,
            )

        if subcmd == "install":
            # cargo install ripgrep  /  cargo install --version 14.1.0 ripgrep
            specs = [
                self.parse_package_spec(a)
                for a in _positionals(tail, _CARGO_INSTALL_VALUE_FLAGS, _CARGO_INSTALL_OPTIONAL_VALUE_FLAGS)
            ]
            # `--version` applies only when exactly one crate is named; a spec's
            # own `@version` takes precedence over it.
            # A requirement (`--version '^14.0'`) pins nothing: run it through
            # the same exact-version check as a positional `crate@version`.
            raw_flag_version = _option_value(tail, frozenset({"--version", "--vers"}))
            flag_version = (
                self.parse_package_spec(f"_@{raw_flag_version}")[1] if raw_flag_version else None
            )
            packages = [
                PackageSpec(
                    name=name,
                    version=version or (flag_version if len(specs) == 1 else None),
                    ecosystem="crates.io",
                )
                for name, version in specs
            ]
            # `cargo install` puts binaries in ~/.cargo/bin (or `--root`), not in
            # a project: a global install (rule 5) — checked in pre-flight but
            # not sandboxed, and with no project lock file to read back.
            return ProcessInstall(
                manager="cargo",
                packages=packages,
                global_install=True,
                working_dir=working_dir,
            )

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

    def interpreter_shim_script(self, real: Path, pa: Path) -> str | None:
        # No custom shim needed — cargo is always invoked directly.
        return None

    def project_bin_dirs(self, root: Path) -> list[Path]:
        # Cargo does not create a project-local bin/ that needs shimming.
        return []

    def publication_date_url(self, name: str, version: str) -> str | None:
        return f"https://crates.io/api/v1/crates/{name}/{version}"

    def resolve_package_dir(self, package_name: str, project_path: Path | None, site_packages_dir: Path | None) -> Path | None:
        # Cargo extracts crates into ~/.cargo/registry/src/<hash>/<name>-<version>/
        # but the daemon doesn't have the version at this call site, so we can't
        # reconstruct the exact path. Return None — Rust heuristics are not yet
        # implemented anyway.
        return None

    def latest_version_url(self, name: str) -> str | None:
        return f"https://crates.io/api/v1/crates/{name}"

    def latest_version_parse(self, data: object, name: str) -> str | None:
        # crates.io returns the newest version in crate.newest_version
        if not isinstance(data, dict):
            return None
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
