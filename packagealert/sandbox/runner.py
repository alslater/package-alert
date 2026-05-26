from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from packagealert.parsers.process_args import (
    ParsedInstall,
    derive_site_packages,
    parse_composer_args,
    parse_npm_args,
    parse_package_spec,
    parse_pip_args,
    parse_pipenv_args,
    parse_uv_args,
)
from packagealert.sandbox.bwrap import available as bwrap_available
from packagealert.sandbox.bwrap import build_cmd

if TYPE_CHECKING:
    from packagealert.config import AppConfig

log = logging.getLogger(__name__)

_PARSERS = [parse_pip_args, parse_uv_args, parse_pipenv_args, parse_npm_args, parse_composer_args]
_DISTINFO_RE = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")

_SHELL_NAMES: frozenset[str] = frozenset({
    "bash", "zsh", "sh", "fish", "dash", "ksh", "csh", "tcsh",
})

# RC files to re-expose inside the home tmpfs so the shell initialises properly.
_SHELL_RC_FILES: dict[str, list[str]] = {
    "bash": [".bashrc", ".bash_profile", ".profile", ".bash_aliases"],
    "sh":   [".profile"],
    "zsh":  [".zshenv", ".zprofile", ".zshrc", ".zlogin"],
    "fish": [".config/fish/config.fish", ".config/fish"],
    "ksh":  [".kshrc", ".profile"],
    "csh":  [".cshrc", ".login"],
    "tcsh": [".tcshrc", ".cshrc", ".login"],
    "dash": [".profile"],
}

# Minimal environment allowlist: names always forwarded into the sandbox when present.
_SANDBOX_ENV: frozenset[str] = frozenset({
    # Core POSIX
    "PATH", "HOME", "USER", "LOGNAME", "SHELL",
    # Locale / terminal
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "LC_COLLATE", "LC_NUMERIC", "LC_TIME", "LC_MONETARY", "LC_PAPER",
    "TERM", "COLORTERM",
    # Python / pip / uv / pyenv
    "VIRTUAL_ENV", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE",
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST", "PIP_CERT",
    "UV_INDEX_URL", "UV_INDEX", "UV_CACHE_DIR", "UV_PYTHON",
    "UV_PROJECT_ENVIRONMENT", "UV_SYSTEM_PYTHON",
    "PYENV_ROOT", "PYENV_VERSION", "PYENV_VERSION_FILE",
    # npm / Node / nvm
    "NPM_CONFIG_REGISTRY", "NPM_CONFIG_CACHE", "NODE_PATH", "NODE_ENV",
    "NVM_DIR", "NVM_BIN",
    # pipenv behaviour flags
    "PIPENV_VENV_IN_PROJECT", "PIPENV_IGNORE_VIRTUALENVS", "PIPENV_VERBOSITY",
    "WORKON_HOME",
    # pip behaviour flags
    "PIP_REQUIRE_VIRTUALENV",
    # Composer / PHP
    "COMPOSER_HOME", "COMPOSER_CACHE_DIR", "COMPOSER_MIRROR",
    # Network proxies (package managers respect these)
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
    # SSL / TLS
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    # Git (uv may invoke git for VCS deps; GIT_SSH_COMMAND set by --expose-ssh-keys)
    "GIT_CONFIG_GLOBAL", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_SSH_COMMAND",
})


@dataclass
class _Context:
    argv: list[str]
    parsed: ParsedInstall | None
    cwd: Path
    # Directories that must be writable inside the sandbox (superset of scan_targets)
    write_dirs: list[Path] = field(default_factory=list)
    # Directories to snapshot before and diff after to detect new packages
    scan_targets: list[Path] = field(default_factory=list)


class SandboxRunner:
    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg
        self._console = Console()

    async def run(self, argv: list[str], *, allow_network: bool = True, extra_env: list[str] | None = None, expose_ssh_keys: bool = False) -> int:
        if not bwrap_available():
            self._console.print("[red]bwrap not found. Install bubblewrap to use 'package-alert run'.[/red]")
            self._console.print("[dim]  Ubuntu/Debian: sudo apt install bubblewrap[/dim]")
            self._console.print("[dim]  Fedora/RHEL:   sudo dnf install bubblewrap[/dim]")
            self._console.print("[dim]  Arch:          sudo pacman -S bubblewrap[/dim]")
            return 1

        cwd = Path.cwd()

        if expose_ssh_keys:
            from rich.prompt import Confirm
            self._console.print(
                "[yellow]⚠  --expose-ssh-keys: your ~/.ssh directory will be mounted "
                "read-only inside the sandbox.[/yellow]"
            )
            self._console.print(
                "[dim]Install-time scripts will be able to read your private keys "
                "and SSH config. Only proceed if you trust the packages being installed.[/dim]"
            )
            if not Confirm.ask("Continue with SSH keys exposed?", default=False):
                return 1

        if argv and Path(argv[0]).name in _SHELL_NAMES:
            return await self._run_shell(argv, cwd=cwd, allow_network=allow_network, extra_env=extra_env, expose_ssh_keys=expose_ssh_keys)

        parsed = _try_parse(argv)
        ctx = _Context(argv=argv, parsed=parsed, cwd=cwd)

        self._console.print(f"\n[bold]Sandbox:[/bold] {' '.join(argv)}")

        if not self._check_venv_scope(parsed, cwd):
            return 1

        if _has_ssh_vcs_deps(parsed, cwd) and not expose_ssh_keys:
            self._console.print("[yellow]⚠ This install includes SSH VCS dependencies.[/yellow]")
            self._console.print("[dim]SSH keys are not exposed in the sandbox by default.[/dim]")
            self._console.print("[dim]Re-run with --expose-ssh-keys to allow SSH key access:[/dim]")
            self._console.print(f"[dim]  package-alert run --expose-ssh-keys {shlex.join(argv)}[/dim]")
            return 1

        if not await self._preflight(ctx):
            return 1

        _resolve_targets(ctx)

        targets_label = ", ".join(str(t) for t in ctx.scan_targets) or "none detected"
        self._console.print(f"[dim]Scan targets: {targets_label}[/dim]")
        network_label = "allowed" if allow_network else "blocked"
        self._console.print(f"[dim]Running in sandbox (network: {network_label})...[/dim]\n")

        # Snapshot scan targets and lock files before execution
        snapshots = {t: _snapshot(t) for t in ctx.scan_targets if t.exists()}
        lock_snapshots = _snapshot_lock_files(cwd)

        combined_extra = list(self._cfg.sandbox.extra_env)
        if extra_env:
            combined_extra.extend(extra_env)
        sandbox_env = _build_sandbox_env(combined_extra)

        # For pip/pipenv: resolve which venv to use and give it an explicit
        # writable bind mount.  The cwd write bind alone is not reliable for
        # deep nested paths inside the home tmpfs; an explicit --bind for the
        # venv root ensures pip can write to both site-packages AND venv/bin/
        # (needed for console scripts like entry points).
        if parsed and parsed.manager in ("pip", "pipenv"):
            if "VIRTUAL_ENV" in sandbox_env:
                venv_path: Path | None = Path(sandbox_env["VIRTUAL_ENV"])
            elif parsed.manager == "pip":
                # Auto-detect project venv for bare pip, which cannot create its own.
                venv_path = _find_venv_root(ctx.scan_targets)
                if venv_path:
                    sandbox_env["VIRTUAL_ENV"] = str(venv_path)
                    self._console.print(f"[dim]No active virtualenv — using detected project venv: {venv_path}[/dim]")
                else:
                    self._console.print("[bold red]✗ Blocked — no virtualenv found for this project.[/bold red]")
                    self._console.print("[dim]Create one first:  python -m venv .venv  &&  source .venv/bin/activate[/dim]")
                    self._console.print("[dim]Or use uv:         package-alert run uv sync[/dim]")
                    return 1
            else:
                # pipenv manages its own virtualenv; don't inject VIRTUAL_ENV.
                venv_path = None
            if venv_path and venv_path.exists():
                # Prepend venv/bin to PATH so the sandbox resolves `pip` to the
                # venv's own pip.  System pip runs under system Python where
                # sys.prefix == sys.base_prefix, causing it to ignore VIRTUAL_ENV
                # and fall back to a user install even when VIRTUAL_ENV is set.
                venv_bin = str(venv_path / "bin")
                sandbox_env["PATH"] = f"{venv_bin}:{sandbox_env.get('PATH', '')}"
                if venv_path not in ctx.write_dirs:
                    ctx.write_dirs.append(venv_path)

        # home_ro: paths under cwd are already covered by the cwd write bind —
        # a more-specific ro-bind on any of them would silently shadow it.
        home_ro = [p for p in _home_ro_dirs() if not p.is_relative_to(ctx.cwd)]
        if expose_ssh_keys:
            ssh_dir = Path.home() / ".ssh"
            if ssh_dir.exists():
                home_ro.append(ssh_dir)
            # Bypass system SSH config (which may have broken permissions on
            # some systemd setups) and use only the user's ~/.ssh/config.
            ssh_config = ssh_dir / "config"
            if ssh_config.exists():
                sandbox_env["GIT_SSH_COMMAND"] = f"ssh -F {shlex.quote(str(ssh_config))}"
            else:
                sandbox_env["GIT_SSH_COMMAND"] = "ssh -F /dev/null"

        extra_tmpfs = list(self._cfg.sandbox.extra_tmpfs)
        if not self._check_extra_tmpfs(extra_tmpfs):
            return 1

        result = subprocess.run(build_cmd(
            argv, ctx.write_dirs,
            allow_network=allow_network,
            env=sandbox_env,
            home_ro_dirs=home_ro,
            extra_tmpfs=extra_tmpfs,
        ))
        print()

        if result.returncode != 0:
            self._console.print(f"[yellow]Command exited with code {result.returncode}[/yellow]")
            return result.returncode

        if not await self._scan_updated_lock_files(cwd, lock_snapshots):
            _restore_lock_files(lock_snapshots, cwd, self._console)
            return 1

        # Re-detect scan targets that may have been created by the install
        # (e.g. uv sync creating .venv from scratch)
        if parsed and parsed.ecosystem == "pypi" and not ctx.scan_targets:
            site_pkgs = _find_site_packages(parsed, cwd)
            if site_pkgs and site_pkgs.exists():
                ctx.scan_targets.append(site_pkgs)

        ecosystem = parsed.ecosystem if parsed else None
        new_pkgs = _collect_new_packages(ctx.scan_targets, snapshots, ecosystem)

        if new_pkgs:
            self._console.print(f"[dim]Post-install scan: {len(new_pkgs)} new package(s)...[/dim]")
            if not await self._post_scan(new_pkgs):
                _restore_lock_files(lock_snapshots, cwd, self._console)
                return 1
        else:
            self._console.print("[dim]Post-install scan: no new packages detected[/dim]")

        return 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_venv_scope(self, parsed: ParsedInstall | None, cwd: Path) -> bool:
        """Return False (and print an error) if VIRTUAL_ENV belongs to a different project."""
        if parsed is None or parsed.manager not in ("pip", "pipenv"):
            return True
        virtual_env = os.environ.get("VIRTUAL_ENV")
        if not virtual_env:
            return True
        venv_path = Path(virtual_env)
        # Inside the project tree — always fine.
        if venv_path.is_relative_to(cwd):
            return True
        # pipenv stores managed venvs outside the project by default; allow any
        # path under its venvs directory unless PIPENV_VENV_IN_PROJECT forces
        # them in-project (in which case an outside path would be foreign).
        if parsed.manager == "pipenv" and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
            if venv_path.is_relative_to(_pipenv_venv_dir()):
                return True
        self._console.print("[bold red]✗ Blocked — VIRTUAL_ENV points to a virtualenv outside this project:[/bold red]")
        self._console.print(f"  [red]VIRTUAL_ENV = {virtual_env}[/red]")
        self._console.print(f"  [dim]Project     = {cwd}[/dim]")
        self._console.print("[dim]Run 'deactivate' before using package-alert run, or cd to the project that owns this virtualenv.[/dim]")
        return False

    def _check_extra_tmpfs(self, paths: list[Path]) -> bool:
        """Return False (and print an error) if any configured extra_tmpfs path does not exist.

        bwrap cannot create a missing mount point under the read-only root bind,
        so a non-existent path causes the entire sandbox to abort silently.
        """
        ok = True
        for p in paths:
            if not p.exists():
                self._console.print(f"[bold red]✗ sandbox.extra_tmpfs path does not exist: {p}[/bold red]")
                self._console.print("[dim]Remove or correct the path in your config file (sandbox.extra_tmpfs).[/dim]")
                ok = False
        return ok

    async def _run_shell(
        self,
        argv: list[str],
        *,
        cwd: Path,
        allow_network: bool,
        extra_env: list[str] | None,
        expose_ssh_keys: bool = False,
    ) -> int:
        """Run an interactive shell inside the sandbox with the project environment set up.

        Performs a pre-flight check against all project lock files before opening
        the shell, and a post-exit scan to catch any packages installed during
        the session.
        """
        shell_name = Path(argv[0]).name
        self._console.print(f"\n[bold]Sandbox shell:[/bold] {' '.join(argv)}")

        combined_extra = list(self._cfg.sandbox.extra_env)
        if extra_env:
            combined_extra.extend(extra_env)
        sandbox_env = _build_sandbox_env(combined_extra)

        write_dirs: list[Path] = [cwd]
        scan_targets: list[Path] = []
        notes: list[str] = []

        # Python venv — prefer .venv over venv
        venv_path: Path | None = None
        for name in (".venv", "venv"):
            candidate = cwd / name
            if (candidate / "pyvenv.cfg").exists():
                venv_path = candidate
                break

        if venv_path:
            sandbox_env["VIRTUAL_ENV"] = str(venv_path)
            sandbox_env["PATH"] = f"{venv_path / 'bin'}:{sandbox_env.get('PATH', '')}"
            write_dirs.append(venv_path)
            notes.append(f"venv: {venv_path.name}")
            lib_dir = venv_path / "lib"
            if lib_dir.exists():
                sp_candidates = sorted(lib_dir.glob("python*/site-packages"))
                if sp_candidates:
                    scan_targets.append(sp_candidates[0])

        # Node.js — prepend node_modules/.bin if present, scan node_modules
        nm_bin = cwd / "node_modules" / ".bin"
        if nm_bin.is_dir():
            sandbox_env["PATH"] = f"{nm_bin}:{sandbox_env.get('PATH', '')}"
            notes.append("node_modules/.bin in PATH")
        if (cwd / "package.json").exists():
            scan_targets.append(cwd / "node_modules")

        # Composer/PHP
        if (cwd / "composer.json").exists():
            scan_targets.append(cwd / "vendor")

        # pipenv-managed virtualenvs dir (outside the project unless PIPENV_VENV_IN_PROJECT)
        if (cwd / "Pipfile").exists() and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
            pipenv_dir = _pipenv_venv_dir()
            pipenv_dir.mkdir(parents=True, exist_ok=True)
            write_dirs.append(pipenv_dir)
            notes.append(f"pipenv venvs: {pipenv_dir}")

        # Writable package-manager caches so installs work from within the shell
        for cache_path in [
            Path.home() / ".cache" / "pip",
            Path.home() / ".cache" / "uv",
            Path.home() / ".npm",
            Path.home() / ".config" / "composer",
        ]:
            if cache_path.exists():
                write_dirs.append(cache_path)

        if notes:
            self._console.print(f"[dim]Environment: {', '.join(notes)}[/dim]")

        # Pre-flight: scan all project lock files for known-malicious packages
        if not await self._preflight_shell(cwd):
            return 1

        # Snapshot install targets and lock files before the shell session opens
        snapshots = {t: _snapshot(t) for t in scan_targets if t.exists()}
        lock_snapshots = _snapshot_lock_files(cwd)

        network_label = "allowed" if allow_network else "blocked"
        self._console.print(f"[dim]Running sandboxed shell (network: {network_label})...[/dim]")
        self._console.print("[dim]Type 'exit' or press Ctrl-D to leave the sandbox.[/dim]\n")

        # RC files so the shell initialises properly (aliases, prompt, etc.)
        home = Path.home()
        rc_paths = [
            home / rc
            for rc in _SHELL_RC_FILES.get(shell_name, [])
            if (home / rc).exists()
        ]
        git_cfg = home / ".gitconfig"
        if git_cfg.exists():
            rc_paths.append(git_cfg)

        home_ro = [
            p for p in _home_ro_dirs() + rc_paths
            if not p.is_relative_to(cwd)
        ]
        if expose_ssh_keys:
            ssh_dir = Path.home() / ".ssh"
            if ssh_dir.exists():
                home_ro.append(ssh_dir)
            ssh_config = ssh_dir / "config"
            if ssh_config.exists():
                sandbox_env["GIT_SSH_COMMAND"] = f"ssh -F {shlex.quote(str(ssh_config))}"
            else:
                sandbox_env["GIT_SSH_COMMAND"] = "ssh -F /dev/null"

        extra_tmpfs = list(self._cfg.sandbox.extra_tmpfs)
        if not self._check_extra_tmpfs(extra_tmpfs):
            return 1

        result = subprocess.run(build_cmd(
            argv, write_dirs,
            allow_network=allow_network,
            env=sandbox_env,
            home_ro_dirs=home_ro,
            extra_tmpfs=extra_tmpfs,
        ))
        print()

        # Post-exit: scan changed lock files, then any newly installed packages
        if not await self._scan_updated_lock_files(cwd, lock_snapshots):
            _restore_lock_files(lock_snapshots, cwd, self._console)
            return 1

        new_pkgs = _collect_new_packages(scan_targets, snapshots, None)
        if new_pkgs:
            self._console.print(f"[dim]Post-shell scan: {len(new_pkgs)} new package(s)...[/dim]")
            if not await self._post_scan(new_pkgs):
                _restore_lock_files(lock_snapshots, cwd, self._console)
                return 1
        else:
            self._console.print("[dim]Post-shell scan: no new packages detected[/dim]")

        return result.returncode

    async def _preflight_shell(self, cwd: Path) -> bool:
        """Pre-flight OSV check for shell sessions: scans all project lock files."""
        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient
        from packagealert.parsers.lockfiles import scan_project
        from packagealert.storage.db import open_db

        scan = scan_project(cwd)
        queries = [(p.ecosystem, p.name, p.version) for p in scan.pinned]

        if not queries:
            self._console.print("[dim]Pre-flight: no lock files found[/dim]")
            return True

        sources = ", ".join(scan.sources) if scan.sources else "no lock file"
        self._console.print(f"[dim]Pre-flight check: {len(queries)} packages ({sources})...[/dim]")

        db = await open_db()
        client = OsvClient(self._cfg.osv)
        cache = OsvCache(db, self._cfg.osv)
        malicious: list[tuple[str, str]] = []

        try:
            for i in range(0, len(queries), 50):
                batch = queries[i:i + 50]
                cached_results, uncached = [], []
                for q in batch:
                    r = await cache.get(*q)
                    if r is not None:
                        cached_results.append(r)
                    else:
                        uncached.append(q)
                fresh = []
                if uncached:
                    fresh = await client.batch_query(uncached)
                    for q, r in zip(uncached, fresh):
                        if r:
                            await cache.set(*q, r)
                for r in cached_results + fresh:
                    if r and r.has_malicious:
                        adv_id = next((a.id for a in r.advisories if a.is_malicious), "?")
                        malicious.append((r.package_name, adv_id))
        finally:
            await client.aclose()
            await db.close()

        if malicious:
            self._console.print(f"[bold red]✗ Blocked — {len(malicious)} malicious package(s) in lock files:[/bold red]")
            for name, adv_id in malicious:
                self._console.print(f"  [red]• {name}  ({adv_id})[/red]")
            return False

        self._console.print("[green]✓ Pre-flight: no known advisories[/green]")
        return True

    async def _preflight(self, ctx: _Context) -> bool:
        """Query OSV for what's about to be installed. Return False to block."""
        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient
        from packagealert.parsers.lockfiles import scan_project
        from packagealert.storage.db import open_db

        parsed = ctx.parsed

        if parsed is None:
            self._console.print("[dim]Pre-flight: unrecognised command, skipping OSV check[/dim]")
            return True

        queries: list[tuple[str, str, str | None]] = []

        source_parts: list[str] = []

        if parsed.packages:
            # Explicit packages on the command line — normalise specs first
            for raw in parsed.packages:
                name, version = parse_package_spec(raw, parsed.ecosystem)
                if name:
                    queries.append((parsed.ecosystem, name, version))
            source_parts.append(f"{len(queries)} explicit package(s)")

        if parsed.req_files:
            # -r / --requirement files — parse each one recursively (follows includes)
            from packagealert.parsers.lockfiles import collect_requirements_packages
            visited: set[Path] = set()
            file_sources: list[str] = []
            before = len(queries)
            for rf in parsed.req_files:
                req_path = ctx.cwd / rf
                if req_path.exists():
                    pinned, unpinned = collect_requirements_packages(req_path, visited)
                    queries.extend((p.ecosystem, p.name, p.version) for p in pinned)
                    queries.extend((p.ecosystem, p.name, None) for p in unpinned)
                    file_sources.append(rf)
            added = len(queries) - before
            source_parts.append(
                f"{added} packages ({', '.join(file_sources) or 'no packages found'})"
            )

        if not parsed.packages and not parsed.req_files:
            # Lock-file install — read lockfile for exact versions
            scan = scan_project(ctx.cwd)
            queries = [
                (p.ecosystem, p.name, p.version)
                for p in scan.pinned
                if p.ecosystem == parsed.ecosystem
            ]
            lock_sources = ", ".join(scan.sources) if scan.sources else "no lock file found"
            source_parts.append(f"{len(queries)} packages ({lock_sources})")

        source = "; ".join(source_parts)

        if not queries:
            self._console.print("[dim]Pre-flight: nothing to check[/dim]")
            return True

        self._console.print(f"[dim]Pre-flight check: {source}...[/dim]")

        db = await open_db()
        client = OsvClient(self._cfg.osv)
        cache = OsvCache(db, self._cfg.osv)
        malicious: list[tuple[str, str]] = []

        try:
            for i in range(0, len(queries), 50):
                batch = queries[i : i + 50]
                cached_results, uncached = [], []
                for q in batch:
                    r = await cache.get(*q)
                    if r is not None:
                        cached_results.append(r)
                    else:
                        uncached.append(q)
                fresh = []
                if uncached:
                    fresh = await client.batch_query(uncached)
                    for q, r in zip(uncached, fresh):
                        if r:
                            await cache.set(*q, r)
                for r in cached_results + fresh:
                    if r and r.has_malicious:
                        adv_id = next((a.id for a in r.advisories if a.is_malicious), "?")
                        malicious.append((r.package_name, adv_id))
        finally:
            await client.aclose()
            await db.close()

        if malicious:
            self._console.print(f"[bold red]✗ Blocked — {len(malicious)} malicious package(s):[/bold red]")
            for name, adv_id in malicious:
                self._console.print(f"  [red]• {name}  ({adv_id})[/red]")
            return False

        self._console.print("[green]✓ Pre-flight: no known advisories[/green]")
        return True

    async def _scan_updated_lock_files(self, cwd: Path, lock_snapshots: dict[Path, bytes | None]) -> bool:
        """Scan any lock files that changed during the sandbox run for malicious packages.

        Uses the OSV cache for packages that haven't changed (fast) and queries
        fresh for anything new, so this is cheap when only a few packages were added.
        Returns False if a malicious package is found.
        """
        scannable = {cwd / name for name in _SCANNABLE_LOCK_FILES}
        changed = []
        for p, before in lock_snapshots.items():
            if p not in scannable:
                continue
            if before is None:
                # File was absent before the run; if it exists now it was created.
                if p.exists():
                    changed.append(p)
            else:
                try:
                    if p.read_bytes() != before:
                        changed.append(p)
                except OSError:
                    log.warning("Could not read lock file after sandbox run: %s", p)
                    changed.append(p)  # treat as changed — err on the side of caution
        if not changed:
            return True

        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient
        from packagealert.parsers.lockfiles import scan_project
        from packagealert.storage.db import open_db

        scan = scan_project(cwd)
        queries = [(p.ecosystem, p.name, p.version) for p in scan.pinned]
        if not queries:
            return True

        changed_names = ", ".join(p.name for p in changed)
        self._console.print(
            f"[dim]Lock file scan: {len(queries)} packages ({changed_names} updated)...[/dim]"
        )

        db = await open_db()
        client = OsvClient(self._cfg.osv)
        cache = OsvCache(db, self._cfg.osv)
        malicious: list[tuple[str, str]] = []

        try:
            for i in range(0, len(queries), 50):
                batch = queries[i : i + 50]
                cached_results, uncached = [], []
                for q in batch:
                    r = await cache.get(*q)
                    if r is not None:
                        cached_results.append(r)
                    else:
                        uncached.append(q)
                fresh = []
                if uncached:
                    fresh = await client.batch_query(uncached)
                    for q, r in zip(uncached, fresh):
                        if r:
                            await cache.set(*q, r)
                for r in cached_results + fresh:
                    if r and r.has_malicious:
                        adv_id = next((a.id for a in r.advisories if a.is_malicious), "?")
                        malicious.append((r.package_name, adv_id))
        finally:
            await client.aclose()
            await db.close()

        if malicious:
            self._console.print(
                f"[bold red]✗ Malicious package(s) found in updated lock file(s):[/bold red]"
            )
            for name, adv_id in malicious:
                self._console.print(f"  [red]• {name}  ({adv_id})[/red]")
            return False

        self._console.print("[green]✓ Lock file scan: clean[/green]")
        return True

    async def _post_scan(self, packages: list[tuple[str, str, str | None]]) -> bool:
        """OSV-check newly installed packages. Return False if anything is malicious."""
        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient
        from packagealert.storage.db import open_db

        db = await open_db()
        client = OsvClient(self._cfg.osv)
        cache = OsvCache(db, self._cfg.osv)
        malicious: list[tuple[str, str]] = []

        try:
            for i in range(0, len(packages), 50):
                batch = packages[i : i + 50]
                results = await client.batch_query(batch)
                for q, r in zip(batch, results):
                    if r:
                        await cache.set(*q, r)
                    if r and r.has_malicious:
                        adv_id = next((a.id for a in r.advisories if a.is_malicious), "?")
                        malicious.append((r.package_name, adv_id))
        finally:
            await client.aclose()
            await db.close()

        if malicious:
            self._console.print(f"[bold red]✗ Post-install: {len(malicious)} malicious package(s) detected:[/bold red]")
            for name, adv_id in malicious:
                self._console.print(f"  [red]• {name}  ({adv_id})[/red]")
            self._console.print(
                "[yellow]Packages were written to disk inside the sandbox write targets. "
                "Remove them manually to clean up.[/yellow]"
            )
            return False

        self._console.print("[green]✓ Post-install: clean[/green]")
        return True


# ---------------------------------------------------------------------------
# Module-level helpers (kept outside the class for testability)
# ---------------------------------------------------------------------------

# Matches scp-style git@host:path — colon (not slash) after hostname distinguishes
# this from HTTPS URLs like git+https://git@host/path which are NOT SSH.
_SCP_SSH_RE = re.compile(r"git@[^/:]+:[^/]")


def _is_ssh_vcs_url(s: str) -> bool:
    """Return True if *s* contains any SSH-based Git URL pattern.

    Covers:
    - git+ssh://  (pip/uv requirements, explicit packages)
    - ssh://      (Pipfile.lock "git" field)
    - git@host:path  (scp-style: pip, Pipfile.lock, bare requirements)

    Note: git+https://git@host/path is NOT SSH — the slash after hostname
    distinguishes it from scp-style which uses a colon.
    """
    return (
        "git+ssh://" in s
        or "ssh://" in s
        or bool(_SCP_SSH_RE.search(s))
    )


def _req_file_has_ssh(path: Path, visited: set[Path]) -> bool:
    """Recursively scan a requirements file for SSH VCS URLs.

    Follows -r / --requirement include directives, resolving paths relative to
    the directory of the including file.  *visited* prevents infinite loops.
    """
    path = path.resolve()
    if path in visited:
        return False
    visited.add(path)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return False
    from packagealert.parsers.lockfiles import _req_include
    base = path.parent
    for line in lines:
        # Strip inline comments: everything from the first unquoted # onward.
        # Requirements files don't support quoting, so a simple split is correct.
        line = line.split("#")[0].strip()
        if not line:
            continue
        # Check this line for an SSH VCS URL before inspecting it as an include.
        if _is_ssh_vcs_url(line):
            return True
        include = _req_include(line)
        if include:
            if _req_file_has_ssh(base / include, visited):
                return True
    return False


def _has_ssh_vcs_deps(parsed: ParsedInstall | None, cwd: Path) -> bool:
    """Return True if the install involves SSH-authenticated Git VCS dependencies.

    Checks explicit packages on the command line, and for lock-file installs
    scans Pipfile.lock (pipenv) or requirements*.txt (pip) for SSH VCS URLs.
    Both URL-style (git+ssh://, ssh://) and scp-style (git@host:org/repo)
    patterns are detected.  Nested pip -r includes are followed recursively.
    """
    if parsed is None:
        return False
    if any(_is_ssh_vcs_url(p) for p in parsed.packages):
        return True
    if parsed.manager == "pipenv":
        candidates: list[Path] = [cwd / "Pipfile.lock"]
        for path in candidates:
            try:
                if _is_ssh_vcs_url(path.read_text(errors="replace")):
                    return True
            except OSError:
                pass
    elif parsed.manager in ("pip", "uv"):
        if parsed.req_files:
            roots = [cwd / f for f in parsed.req_files]
        elif not parsed.packages:
            # Bare install with no explicit packages or -r flags — treat as
            # a lock-file-style install and scan requirements*.txt in the project.
            roots = sorted(cwd.glob("requirements*.txt"))
        else:
            # Explicit packages were given; their URLs were already checked above.
            roots = []
        visited: set[Path] = set()
        for root in roots:
            if _req_file_has_ssh(root, visited):
                return True
    return False


def _find_venv_root(scan_targets: list[Path]) -> Path | None:
    """Return the virtualenv root inferred from the first pypi scan target.

    site-packages sits at <venv>/lib/pythonX.Y/site-packages, so the venv
    root is three levels up.  We confirm with pyvenv.cfg before returning.
    """
    for target in scan_targets:
        candidate = target.parent.parent.parent
        if (candidate / "pyvenv.cfg").exists():
            return candidate
    return None


def _home_ro_dirs() -> list[Path]:
    """Return home-directory paths that package managers need read-only access to.

    The home directory is hidden with a tmpfs; only these paths are re-exposed
    so that SSH keys, cloud credentials, and secrets in other directories are
    not readable by install-time scripts.
    """
    home = Path.home()
    candidates: list[Path] = [
        # pyenv-managed Python installations (respects PYENV_ROOT override)
        Path(os.environ.get("PYENV_ROOT", home / ".pyenv")),
        # nvm-managed Node installations (respects NVM_DIR override)
        Path(os.environ.get("NVM_DIR", home / ".nvm")),
        # uv-managed Python installations and tool environments
        home / ".local" / "share" / "uv",
        # User-local binaries: uv, pip-installed scripts, etc.
        home / ".local" / "bin",
        # pipx-managed tool environments — shebangs in ~/.local/bin/* may point here
        home / ".local" / "pipx",
        # pip configuration (index URLs, proxy, trusted hosts)
        home / ".config" / "pip",
        home / ".pip",                          # legacy pip config location
        # uv configuration
        home / ".config" / "uv",
        # npm registry / auth config
        home / ".npmrc",
    ]
    return [p for p in candidates if p.exists()]


def _build_sandbox_env(extra: list[str]) -> dict[str, str]:
    """Return a filtered copy of os.environ containing only the sandbox allowlist plus *extra*."""
    allowed = _SANDBOX_ENV | set(extra)
    return {k: v for k, v in os.environ.items() if k in allowed}


def _try_parse(argv: list[str]) -> ParsedInstall | None:
    for parser in _PARSERS:
        result = parser(argv)
        if result is not None:
            return result
    return None


def _find_site_packages(parsed: ParsedInstall | None, cwd: Path) -> Path | None:
    """Return the site-packages directory that will be written by this install."""
    if parsed is None:
        return None

    # 1. Derived from the executable path (e.g. /path/to/venv/bin/pip)
    if parsed.venv_exe:
        sp = derive_site_packages(parsed.venv_exe)
        if sp and sp.exists():
            return sp

    # 2. Active virtualenv — only reliable for pip/pipenv; uv ignores VIRTUAL_ENV
    #    and always writes to the project-local .venv regardless of activation state.
    if parsed.manager in ("pip", "pipenv"):
        venv_env = os.environ.get("VIRTUAL_ENV")
        if venv_env:
            candidates = sorted(Path(venv_env).glob("lib/python*/site-packages"))
            if candidates:
                return candidates[0]

    # 3. pipenv-managed venv under WORKON_HOME (outside the project by default)
    if parsed.manager == "pipenv" and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
        pipenv_venv = _find_pipenv_venv(cwd)
        if pipenv_venv:
            candidates = sorted(pipenv_venv.glob("lib/python*/site-packages"))
            if candidates:
                return candidates[0]

    # 4. .venv / venv inside the project (uv default, pipenv with PIPENV_VENV_IN_PROJECT)
    for name in (".venv", "venv"):
        candidates = sorted((cwd / name).glob("lib/python*/site-packages"))
        if candidates:
            return candidates[0]

    return None


def _find_pipenv_venv(cwd: Path) -> Path | None:
    """Return the pipenv-managed virtualenv root for the project at *cwd*, or None.

    Runs `pipenv --venv` outside the sandbox to resolve the path, which works
    for both pre-existing venvs (pre-install snapshot) and freshly-created ones
    (post-install scan).  Returns None if pipenv is not installed or the venv
    does not exist yet (e.g. before the first `pipenv sync`).
    """
    try:
        result = subprocess.run(
            ["pipenv", "--venv"],
            capture_output=True, text=True, cwd=cwd,
        )
        if result.returncode == 0:
            venv = Path(result.stdout.strip())
            if venv.exists():
                return venv
    except FileNotFoundError:
        pass
    return None


def _pipenv_venv_dir() -> Path:
    """Return the directory where pipenv stores its managed virtualenvs.

    Respects WORKON_HOME; falls back to ~/.local/share/virtualenvs (the pipenv
    default on Linux).  When PIPENV_VENV_IN_PROJECT is set the venv lives
    inside the project directory instead and this directory is not needed.
    """
    workon = os.environ.get("WORKON_HOME")
    return Path(workon) if workon else Path.home() / ".local" / "share" / "virtualenvs"


def _resolve_targets(ctx: _Context) -> None:
    """Populate ctx.write_dirs and ctx.scan_targets from the parsed command."""
    parsed = ctx.parsed
    cwd = ctx.cwd

    # The project directory is always writable (lock-file updates, project files)
    ctx.write_dirs.append(cwd)

    if parsed is None:
        return

    eco = parsed.ecosystem

    if eco == "pypi":
        site_pkgs = _find_site_packages(parsed, cwd)
        if site_pkgs:
            ctx.scan_targets.append(site_pkgs)
            # Only add as a separate write mount if site-packages is outside cwd
            try:
                site_pkgs.relative_to(cwd)
            except ValueError:
                ctx.write_dirs.append(site_pkgs)
        else:
            log.warning("Could not detect site-packages directory; Python packages will not be scanned")
        # Cache dirs — writable so pip/uv can store wheels, but we don't scan them
        for cache in [Path.home() / ".cache" / "pip", Path.home() / ".cache" / "uv"]:
            if cache.exists():
                ctx.write_dirs.append(cache)
        # pipenv stores its managed venvs outside the project unless
        # PIPENV_VENV_IN_PROJECT is set — make that directory writable, creating
        # it if necessary so pipenv can write there on a fresh install.
        if parsed.manager == "pipenv" and not os.environ.get("PIPENV_VENV_IN_PROJECT"):
            venv_dir = _pipenv_venv_dir()
            venv_dir.mkdir(parents=True, exist_ok=True)
            ctx.write_dirs.append(venv_dir)
            # If the venv already exists, add its site-packages as a scan target
            # so the pre-install snapshot captures current state.  Fresh installs
            # produce an empty snapshot here; the post-install fallback below
            # then finds the newly-created venv and diffs against empty.
            if not ctx.scan_targets:
                pipenv_venv = _find_pipenv_venv(cwd)
                if pipenv_venv:
                    sp_candidates = sorted(pipenv_venv.glob("lib/python*/site-packages"))
                    if sp_candidates:
                        ctx.scan_targets.append(sp_candidates[0])

    elif eco == "npm":
        # node_modules lives under cwd, so it's already covered by the cwd bind
        ctx.scan_targets.append(cwd / "node_modules")
        npm_cache = Path.home() / ".npm"
        if npm_cache.exists():
            ctx.write_dirs.append(npm_cache)

    elif eco == "packagist":
        # vendor lives under cwd
        ctx.scan_targets.append(cwd / "vendor")
        composer_home = Path.home() / ".config" / "composer"
        if composer_home.exists():
            ctx.write_dirs.append(composer_home)


# Lock files to snapshot and restore if a malicious package is detected.
_RESTORABLE_LOCK_FILES = [
    "Pipfile.lock",
    "uv.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
]

# Subset of the above that scan_project() can actually parse. Used to decide
# whether to trigger an OSV scan after a sandbox run. yarn.lock and
# pnpm-lock.yaml are intentionally excluded until parser support is added.
_SCANNABLE_LOCK_FILES = [
    "Pipfile.lock",
    "uv.lock",
    "package-lock.json",
    "composer.lock",
]


def _snapshot_lock_files(cwd: Path) -> dict[Path, bytes | None]:
    """Snapshot all known restorable lock files under *cwd*.

    Files that exist are recorded with their contents; files that are absent
    are recorded with ``None`` so that ``_restore_lock_files`` knows to delete
    them if they were created during the sandbox run.
    """
    result: dict[Path, bytes | None] = {}
    for name in _RESTORABLE_LOCK_FILES:
        p = cwd / name
        if p.exists():
            try:
                result[p] = p.read_bytes()
            except OSError:
                result[p] = None
        else:
            result[p] = None
    return result


def _restore_lock_files(
    snapshots: dict[Path, bytes | None], cwd: Path, console: Console
) -> None:
    project_root = cwd.resolve()
    restored = []
    for path, content in snapshots.items():
        try:
            resolved = path.resolve()
        except OSError:
            log.warning("Cannot resolve path during lock file restore, skipping: %s", path)
            continue
        if not resolved.is_relative_to(project_root):
            log.warning(
                "Lock file path resolves outside project directory, skipping restore: %s -> %s",
                path,
                resolved,
            )
            continue
        try:
            if content is None:
                if path.exists():
                    path.unlink()
                    restored.append(path.name)
            else:
                path.write_bytes(content)
                restored.append(path.name)
        except OSError:
            log.warning("Failed to restore lock file: %s", path)
    if restored:
        console.print(f"[yellow]Restored lock file(s) to pre-install state: {', '.join(restored)}[/yellow]")


def _snapshot(path: Path) -> set[Path]:
    """Return the set of all paths currently under *path*."""
    try:
        return set(path.rglob("*"))
    except (PermissionError, FileNotFoundError):
        return set()


def _collect_new_packages(
    scan_targets: list[Path],
    snapshots: dict[Path, set[Path]],
    ecosystem: str | None,
) -> list[tuple[str, str, str | None]]:
    """Return (ecosystem, name, version) tuples for packages that appeared since the snapshot."""
    new: list[tuple[str, str, str | None]] = []
    for target in scan_targets:
        if not target.exists():
            continue
        before = snapshots.get(target, set())
        new_paths = set(target.rglob("*")) - before
        if ecosystem in ("pypi", None):
            new.extend(_new_python_packages(new_paths))
        if ecosystem in ("npm", None):
            new.extend(_new_npm_packages(new_paths, target))
        if ecosystem in ("packagist", None):
            new.extend(_new_composer_packages(new_paths, target))
    # Deduplicate preserving order
    seen: set[tuple[str, str, str | None]] = set()
    result = []
    for pkg in new:
        if pkg not in seen:
            seen.add(pkg)
            result.append(pkg)
    return result


def _new_python_packages(new_paths: set[Path]) -> list[tuple[str, str, str | None]]:
    results = []
    for p in new_paths:
        if p.is_dir():
            m = _DISTINFO_RE.match(p.name)
            if m:
                name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
                results.append(("pypi", name, m.group(2)))
    return results


def _new_npm_packages(new_paths: set[Path], node_modules: Path) -> list[tuple[str, str, str | None]]:
    results = []
    for p in new_paths:
        if p.name != "package.json":
            continue
        try:
            rel = p.relative_to(node_modules)
        except ValueError:
            continue
        # Regular pkg: pkg/package.json (2 parts)
        # Scoped pkg:  @scope/pkg/package.json (3 parts)
        if len(rel.parts) not in (2, 3):
            continue
        try:
            data = json.loads(p.read_text())
            name = data.get("name")
            version = data.get("version")
            if name:
                results.append(("npm", name, version))
        except Exception:
            pass
    return results


def _new_composer_packages(new_paths: set[Path], vendor: Path) -> list[tuple[str, str, str | None]]:
    results = []
    for p in new_paths:
        if p.name != "composer.json":
            continue
        try:
            rel = p.relative_to(vendor)
        except ValueError:
            continue
        # vendor/vendor_name/package_name/composer.json = 3 parts
        if len(rel.parts) != 3:
            continue
        try:
            data = json.loads(p.read_text())
            name = data.get("name", "")
            version = data.get("version", "").lstrip("v") or None
            if name and "/" in name:
                results.append(("packagist", name, version))
        except Exception:
            pass
    return results
