from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, replace as dataclass_replace
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from packagealert.languages import registry as lang_registry
from packagealert.languages.base import PackageSpec
from packagealert.parsers.process_args import (
    ParsedInstall,
    derive_site_packages,
    parse_package_spec,
)
from packagealert.sandbox.bwrap import available as bwrap_available
from packagealert.sandbox.bwrap import build_cmd
from packagealert.storage.db import (
    get_cooldown_cleared_at,
    get_publication_date,
    open_db,
    store_cooldown_cleared,
    store_publication_date,
)

if TYPE_CHECKING:
    from packagealert.config import AppConfig

log = logging.getLogger(__name__)
_DISTINFO_RE = re.compile(r"^(.+)-(\d[^-]*)\.dist-info$")
_PA_REAL_SUFFIX = ".__pa_real"

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

# Environment variable names that are always forwarded into the sandbox regardless
# of which package manager is being used.  Language-specific names are contributed
# at runtime by each language module via LanguageBase.sandbox_env().
_SANDBOX_ENV_COMMON: frozenset[str] = frozenset({
    # Core POSIX
    "PATH", "HOME", "USER", "LOGNAME", "SHELL",
    # Locale / terminal
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "LC_COLLATE", "LC_NUMERIC", "LC_TIME", "LC_MONETARY", "LC_PAPER",
    "TERM", "COLORTERM",
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
        lang_registry.load()

    async def run(self, argv: list[str], *, allow_network: bool = True, extra_env: list[str] | None = None, expose_ssh_keys: bool = False, allow_developer_packages: bool = False, no_change: bool = False) -> int:
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
            return await self._run_shell(argv, cwd=cwd, allow_network=allow_network, extra_env=extra_env, expose_ssh_keys=expose_ssh_keys, allow_developer_packages=allow_developer_packages, no_change=no_change)

        parsed = _try_parse(argv)

        # Apply any environment variables suggested by the language module (e.g.
        # VIRTUAL_ENV derived from a venv shim path in python.py).
        if parsed is not None:
            for key, value in parsed.suggested_env.items():
                os.environ.setdefault(key, value)

        if parsed is None:
            # Unrecognised command (e.g. bare `pip`, `npm --version`) — nothing to
            # sandbox or scan, so exec the real binary directly.
            real_argv = _resolve_real_binary(argv)
            # Guard against infinite recursion: if the binary we are about to exec
            # is a package-alert shim without a .__pa_real sibling (inconsistent
            # state), exec'ing it would call back into us. Check the fingerprint.
            tool_path = shutil.which(real_argv[0])
            if tool_path:
                real_sibling = Path(tool_path).parent / f"{Path(tool_path).name}{_PA_REAL_SUFFIX}"
                if not real_sibling.exists():
                    try:
                        content = Path(tool_path).read_text(errors="strict")
                        if "# __pa_shim__" in content:
                            self._console.print(
                                f"[red]✗ {argv[0]} is a package-alert shim but "
                                f"{argv[0]}{_PA_REAL_SUFFIX} is missing — infinite recursion prevented.[/red]"
                            )
                            self._console.print(
                                f"[dim]Run 'package-alert setup project --uninstall' "
                                f"and reinstall the package manager.[/dim]"
                            )
                            return 1
                    except (UnicodeDecodeError, OSError):
                        pass  # ELF binary — safe to exec
            try:
                os.execvp(real_argv[0], real_argv)
            except FileNotFoundError:
                self._console.print(f"[red]✗ Command not found: {real_argv[0]}[/red]")
                return 127
            return 0  # unreachable; satisfies type checker

        ctx = _Context(argv=argv, parsed=parsed, cwd=cwd)

        # Show the interception banner only when invoked through a shim or shell
        # function — when the user types `package-alert run ...` directly they
        # already know we're running.
        real_argv = _resolve_real_binary(argv)
        via_project_shim = real_argv is not argv
        via_shim = via_project_shim or bool(os.environ.get("_PA_VIA_SHELL"))
        is_global = parsed.global_install

        if via_shim:
            self._console.print(r"[bold cyan]\[package-alert][/bold cyan] " + " ".join(argv))
        if is_global:
            self._console.print("[dim]Global install: pre-flight check only (not sandboxed)[/dim]")
        elif not via_shim:
            self._console.print(f"\n[bold]Sandbox:[/bold] {' '.join(argv)}")

        if not self._check_venv_scope(parsed, cwd):
            return 1

        if _has_ssh_vcs_deps(parsed, cwd) and not expose_ssh_keys:
            self._console.print("[yellow]⚠ This install includes SSH VCS dependencies.[/yellow]")
            self._console.print("[dim]SSH keys are not exposed in the sandbox by default.[/dim]")
            self._console.print("[dim]Re-run with --expose-ssh-keys to allow SSH key access:[/dim]")
            self._console.print(f"[dim]  package-alert run --expose-ssh-keys {shlex.join(argv)}[/dim]")
            return 1

        cooldown_result = await self._cooldown_check(ctx)
        if cooldown_result is False:
            return 1
        pending_clears: list[tuple[str, str, str]] = cooldown_result  # type: ignore[assignment]

        if not await self._preflight(ctx, allow_developer_packages=allow_developer_packages):
            return 1

        if is_global:
            real_argv = _resolve_real_binary(argv)
            try:
                os.execvp(real_argv[0], real_argv)
            except FileNotFoundError:
                self._console.print(f"[red]✗ Command not found: {real_argv[0]}[/red]")
                return 127
            return 0  # unreachable

        _resolve_targets(ctx)

        targets_label = ", ".join(str(t) for t in ctx.scan_targets) or "none detected"
        self._console.print(f"[dim]Scan targets: {targets_label}[/dim]")
        network_label = "allowed" if allow_network else "blocked"
        if no_change:
            self._console.print("[dim]Mode: dry run (--no-change) — lock files will be restored after the run[/dim]")
        self._console.print(f"[dim]Running in sandbox (network: {network_label})...[/dim]\n")

        # Snapshot scan targets and lock files before execution
        snapshots = {t: _snapshot(t) for t in ctx.scan_targets if t.exists()}
        lock_snapshots = _snapshot_lock_files(cwd, allow_developer_packages=allow_developer_packages)

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

        home_ro.extend(self._cfg.sandbox.extra_ro_paths)

        argv = _resolve_real_binary(argv)
        if ctx.parsed is not None:
            lang = lang_registry.for_ecosystem(ctx.parsed.ecosystem)
            if lang is not None:
                prepare_fn = getattr(lang, "prepare_sandbox_argv", None)
                if callable(prepare_fn):
                    argv = prepare_fn(argv, cwd)
                extra_ro_fn = getattr(lang, "sandbox_extra_ro_paths", None)
                if callable(extra_ro_fn):
                    home_ro.extend(extra_ro_fn(argv, cwd))
                extra_write_fn = getattr(lang, "sandbox_extra_write_paths", None)
                if callable(extra_write_fn):
                    ctx.write_dirs.extend(extra_write_fn(argv, cwd))
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
            # A failing install can still write or modify lock files, so run the
            # lock-file scan and restore unconditionally — exiting non-zero must
            # not be a way to evade the check.
            scan_ok = await self._scan_updated_lock_files(cwd, lock_snapshots, allow_developer_packages=allow_developer_packages)
            if no_change:
                _restore_lock_files(lock_snapshots, cwd, self._console)
            elif not scan_ok:
                _restore_lock_files(lock_snapshots, cwd, self._console)
                return 1
            return result.returncode if scan_ok else 1

        scan_ok = await self._scan_updated_lock_files(cwd, lock_snapshots, allow_developer_packages=allow_developer_packages)
        if no_change:
            _restore_lock_files(lock_snapshots, cwd, self._console)
        elif not scan_ok:
            _restore_lock_files(lock_snapshots, cwd, self._console)
            return 1
        if not scan_ok:
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
            post_ok = await self._post_scan(new_pkgs)
            if not post_ok:
                if not no_change:
                    _restore_lock_files(lock_snapshots, cwd, self._console)
                return 1
        else:
            self._console.print("[dim]Post-install scan: no new packages detected[/dim]")

        if pending_clears:
            db = await open_db()
            try:
                for eco, pkg_name, ver in pending_clears:
                    await store_cooldown_cleared(db, ecosystem=eco, package=pkg_name, version=ver)
            finally:
                await db.close()

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

    async def _cooldown_check(self, ctx: _Context) -> list[tuple[str, str, str]] | bool:
        """Check cooldown policy. Returns False if blocked, or a list of
        (ecosystem, name, version) tuples for packages the user confirmed at the
        prompt — to be written to cooldown_cleared after a successful install.
        An empty list means allowed with no prompts."""
        import sys
        import time as _time

        from packagealert.sandbox.cooldown import decide_with_cleared, fetch_latest_version, fetch_publication_date

        if ctx.parsed is None or not ctx.parsed.packages:
            return []

        cfg = self._cfg.sandbox.cooldown
        is_tty = sys.stdin.isatty()
        db = await open_db()

        from packagealert.heuristics.top_packages import TopPackagesCache
        from packagealert.heuristics.typosquat import TyposquatDetector
        from packagealert.languages.base import PackageSpec
        from packagealert.parsers.process_args import parse_package_spec
        top_cache = TopPackagesCache(db, self._cfg.heuristics)
        detector = TyposquatDetector(top_cache)

        blocked: list = []
        pending_clears: list[tuple[str, str, str]] = []
        warned: list = []

        try:
            for pkg_str in ctx.parsed.packages:
                ecosystem = ctx.parsed.ecosystem.lower()
                name, version = parse_package_spec(pkg_str, ecosystem)
                if not name:
                    continue  # VCS URL, local path, editable install — not a registry package
                if not version:
                    lang_for_latest = lang_registry.for_ecosystem(ecosystem)
                    if lang_for_latest is not None:
                        latest_url_fn = getattr(lang_for_latest, "latest_version_url", None)
                        if callable(latest_url_fn):
                            latest_url = latest_url_fn(name)
                            if latest_url is not None:
                                version = await fetch_latest_version(latest_url, lang_for_latest, name)
                                if version:
                                    self._console.print(f"[dim]Resolving latest version: {name}=={version}[/dim]")
                    if not version:
                        self._console.print(
                            f"[dim]Cooldown skipped for {name} (unpinned — version unknown until install)[/dim]"
                        )
                        continue

                pkg = PackageSpec(name=name, version=version, ecosystem=ecosystem)

                lang = lang_registry.for_ecosystem(ecosystem)
                if lang is None:
                    continue
                url = lang.publication_date_url(pkg.name, pkg.version)
                if url is None:
                    # Ecosystem has not opted into cooldown — skip entirely.
                    # The typosquat check is also skipped: without a publication
                    # date there is no age to enforce a cooldown period against,
                    # so a decision cannot be made.
                    continue

                cached = await get_publication_date(db, ecosystem=ecosystem, package=name, version=version)
                if cached == "miss":
                    fetched = await fetch_publication_date(url, ecosystem=ecosystem, version=version)
                    if isinstance(fetched, float):
                        await store_publication_date(db, ecosystem=ecosystem, package=name, version=version, published_at=fetched)
                    elif fetched == "not_found":
                        await store_publication_date(db, ecosystem=ecosystem, package=name, version=version, published_at=None)
                    pub_ts = fetched if isinstance(fetched, float) else None
                elif cached == "not_found":
                    pub_ts = None
                else:
                    pub_ts = cached  # float

                age_days = (_time.time() - pub_ts) / 86400 if isinstance(pub_ts, float) else None
                cleared_at = await get_cooldown_cleared_at(db, ecosystem=ecosystem, package=name, version=version)

                typo = await detector.analyze(name, ecosystem)
                risk_score = typo.score

                decision = decide_with_cleared(
                    pkg,
                    age_days=age_days,
                    risk_score=risk_score,
                    cfg=cfg,
                    is_tty=is_tty,
                    cleared_at=cleared_at,
                )

                if typo.is_typosquat and typo.closest_match:
                    decision = dataclass_replace(
                        decision,
                        reason=f"{decision.reason}; possible typosquat of '{typo.closest_match}' (distance {typo.distance})",
                    )

                if decision.action == "block":
                    blocked.append(decision)
                elif decision.action == "warn":
                    warned.append(decision)
                elif decision.action == "prompt":
                    from rich.prompt import Confirm
                    self._console.print(f"[yellow]  {pkg.name}=={pkg.version}: {decision.reason}[/yellow]")
                    if not Confirm.ask("Install anyway?", default=False):
                        blocked.append(decision)
                    else:
                        pending_clears.append((ecosystem, name, version))
        finally:
            await db.close()

        for d in warned:
            self._console.print(f"[yellow]  {d.package.name}=={d.package.version}: {d.reason}[/yellow]")

        if blocked:
            for d in blocked:
                self._console.print(f"[red]✗ {d.package.name}=={d.package.version}: {d.reason}[/red]")
                eco_flag = f" --ecosystem {d.package.ecosystem}" if d.package.ecosystem.lower() != "pypi" else ""
                self._console.print(f"[dim]  To pre-clear: package-alert cooldown allow {d.package.name} {d.package.version}{eco_flag}[/dim]")
            return False

        return pending_clears

    async def _run_shell(
        self,
        argv: list[str],
        *,
        cwd: Path,
        allow_network: bool,
        extra_env: list[str] | None,
        expose_ssh_keys: bool = False,
        allow_developer_packages: bool = False,
        no_change: bool = False,
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
        if not await self._preflight_shell(cwd, allow_developer_packages=allow_developer_packages):
            return 1

        # Snapshot install targets and lock files before the shell session opens
        snapshots = {t: _snapshot(t) for t in scan_targets if t.exists()}
        lock_snapshots = _snapshot_lock_files(cwd, allow_developer_packages=allow_developer_packages)

        network_label = "allowed" if allow_network else "blocked"
        if no_change:
            self._console.print("[dim]Mode: dry run (--no-change) — lock files will be restored after the session[/dim]")
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

        home_ro.extend(self._cfg.sandbox.extra_ro_paths)

        result = subprocess.run(build_cmd(
            argv, write_dirs,
            allow_network=allow_network,
            env=sandbox_env,
            home_ro_dirs=home_ro,
            extra_tmpfs=extra_tmpfs,
        ))
        print()

        # Post-exit: scan changed lock files, then any newly installed packages
        scan_ok = await self._scan_updated_lock_files(cwd, lock_snapshots, allow_developer_packages=allow_developer_packages)
        if no_change:
            _restore_lock_files(lock_snapshots, cwd, self._console)
        elif not scan_ok:
            _restore_lock_files(lock_snapshots, cwd, self._console)
            return 1
        if not scan_ok:
            return 1

        new_pkgs = _collect_new_packages(scan_targets, snapshots, None)
        if new_pkgs:
            self._console.print(f"[dim]Post-shell scan: {len(new_pkgs)} new package(s)...[/dim]")
            post_ok = await self._post_scan(new_pkgs)
            if not post_ok:
                if not no_change:
                    _restore_lock_files(lock_snapshots, cwd, self._console)
                return 1
        else:
            self._console.print("[dim]Post-shell scan: no new packages detected[/dim]")

        return result.returncode

    async def _preflight_shell(self, cwd: Path, *, allow_developer_packages: bool = False) -> bool:
        """Pre-flight OSV check for shell sessions: scans all project lock files."""
        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient
        from packagealert.parsers.lockfiles import scan_project
        from packagealert.storage.db import open_db

        if not allow_developer_packages:
            offender = _assert_scannable_lock_files_contained(cwd)
            if offender is not None:
                self._console.print(
                    f"[bold red]✗ Lock file {offender} resolves outside the project directory "
                    f"— refusing pre-flight scan. Pass --allow-developer-packages to override.[/bold red]"
                )
                log.warning(
                    "Lock file resolves outside project root, refusing pre-flight scan: %s",
                    cwd / offender,
                )
                return False

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

    async def _preflight(self, ctx: _Context, *, allow_developer_packages: bool = False) -> bool:
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
                    pinned, unpinned = collect_requirements_packages(req_path, visited, ctx.cwd)
                    queries.extend((p.ecosystem, p.name, p.version) for p in pinned)
                    queries.extend((p.ecosystem, p.name, None) for p in unpinned)
                    file_sources.append(rf)
            added = len(queries) - before
            source_parts.append(
                f"{added} packages ({', '.join(file_sources) or 'no packages found'})"
            )

        if not parsed.packages and not parsed.req_files:
            # Lock-file install — read lockfile for exact versions.
            # Enforce containment before scan_project() follows any symlinks.
            if not allow_developer_packages:
                bad = _assert_scannable_lock_files_contained(ctx.cwd)
                if bad is not None:
                    self._console.print(
                        f"[bold red]✗ Blocked — lock file '{bad}' resolves outside the project "
                        f"directory. Use --allow-developer-packages to override.[/bold red]"
                    )
                    return False
            if parsed.lockfile_hint:
                # Use the hinted lockfile directly so we scan the right file in
                # repos with multiple lockfiles for the same ecosystem (e.g. a
                # repo with both package-lock.json and yarn.lock).
                from packagealert.parsers.lockfiles import scan_lockfiles
                hint_path = ctx.cwd / parsed.lockfile_hint
                if hint_path.exists():
                    scan = scan_lockfiles([hint_path])
                    # If the hint file exists but parsed to nothing, fall back so
                    # we don't silently skip the pre-flight check.
                    if not scan.pinned and not scan.unpinned:
                        scan = scan_project(ctx.cwd)
                else:
                    # Hint file absent — fall back to full project scan so we
                    # don't miss an existing lockfile for the same ecosystem.
                    scan = scan_project(ctx.cwd)
            else:
                scan = scan_project(ctx.cwd)
            queries = (
                [(p.ecosystem, p.name, p.version) for p in scan.pinned if p.ecosystem == parsed.ecosystem]
                + [(p.ecosystem, p.name, None) for p in scan.unpinned if p.ecosystem == parsed.ecosystem]
            )
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

    async def _scan_updated_lock_files(
        self,
        cwd: Path,
        lock_snapshots: dict[Path, bytes | None | _LockUnreadable],
        *,
        allow_developer_packages: bool = False,
    ) -> bool:
        """Scan any lock files that changed during the sandbox run for malicious packages.

        Uses the OSV cache for packages that haven't changed (fast) and queries
        fresh for anything new, so this is cheap when only a few packages were added.
        Returns False if a malicious package is found.
        """
        scannable = {cwd / name for name in _scannable_lock_files()}
        changed = []
        for p, before in lock_snapshots.items():
            if p not in scannable:
                continue
            if isinstance(before, _LockUnreadable):
                # Pre-run state was unknown; treat as changed — err on the side of caution.
                changed.append(p)
            elif before is None:
                # File was absent before the run; if any directory entry exists now
                # (including broken symlinks) it was created during the run.
                if p.exists() or p.is_symlink():
                    changed.append(p)
            else:
                # Before reading, verify the path hasn't been replaced by an
                # external symlink during the sandbox run.  p.read_bytes() follows
                # symlinks, so an attacker-placed symlink would otherwise let the
                # sandbox read arbitrary files outside the project.
                if not allow_developer_packages and p.is_symlink():
                    try:
                        resolved = p.resolve()
                    except OSError:
                        resolved = None
                    if resolved is None or not resolved.is_relative_to(cwd.resolve()):
                        log.warning(
                            "Lock file replaced by external symlink during sandbox run, "
                            "treating as changed without reading: %s",
                            p,
                        )
                        changed.append(p)
                        continue
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
        from packagealert.parsers.lockfiles import scan_lockfiles
        from packagealert.storage.db import open_db

        # Enforce symlink containment before reading any changed lock file.
        if not allow_developer_packages:
            offender = _assert_scannable_lock_files_contained(cwd)
            if offender is not None:
                self._console.print(
                    f"[bold red]✗ Lock file {offender} resolves outside the project directory "
                    f"— refusing to scan. Pass --allow-developer-packages to override.[/bold red]"
                )
                log.warning(
                    "Lock file resolves outside project root, refusing scan: %s",
                    cwd / offender,
                )
                return False

        # Parse exactly the files that changed rather than calling scan_project(),
        # which applies first-match-per-language logic and would skip a changed
        # yarn.lock if package-lock.json also exists in the same project.
        scan = scan_lockfiles(changed)
        if not scan.pinned and not scan.unpinned:
            changed_names = ", ".join(p.name for p in changed)
            self._console.print(
                f"[bold red]✗ Lock file(s) changed ({changed_names}) but no packages could be parsed "
                f"— file may be corrupt or empty. Blocking as a precaution.[/bold red]"
            )
            log.warning(
                "Changed lock file(s) yielded no parseable packages; failing safe: %s",
                changed_names,
            )
            return False
        queries = (
            [(p.ecosystem, p.name, p.version) for p in scan.pinned]
            + [(p.ecosystem, p.name, None) for p in scan.unpinned]
        )

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
        # PIPX_HOME defaults differ by install method: ~/.local/pipx or ~/.local/share/pipx
        Path(os.environ.get("PIPX_HOME", home / ".local" / "pipx")).expanduser(),
        home / ".local" / "share" / "pipx",
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
    """Return a filtered copy of os.environ containing only the sandbox allowlist plus *extra*.

    The allowlist is the union of the common names, names contributed by every
    loaded language module via ``sandbox_env()``, and any caller-supplied *extra*
    names (from config or CLI flags).
    """
    lang_env: set[str] = set()
    for lang in lang_registry.all_languages():
        try:
            lang_env.update(lang.sandbox_env())
        except Exception:
            log.warning(
                "sandbox_env() raised unexpectedly for lang=%s — skipping its env contributions",
                getattr(lang, "name", "?"), exc_info=True,
            )
    allowed = _SANDBOX_ENV_COMMON | lang_env | set(extra)
    return {k: v for k, v in os.environ.items() if k in allowed}


def _serialise_package_spec(p: PackageSpec) -> str:
    """Serialise a PackageSpec back to the string format its language module expects.

    Delegates to the language module's serialise_package_spec() so the result
    round-trips correctly through parse_package_spec() for every ecosystem,
    including external plugins.  Falls back to ``name==version`` when no module
    is registered for the ecosystem — the name is always preserved, but the
    version may not survive the round-trip through parse_package_spec() if the
    calling code later re-parses the string.  OSV queries will still run against
    the name but without a pinned version.
    """
    lang = lang_registry.for_ecosystem(p.ecosystem)
    if lang is not None:
        try:
            return lang.serialise_package_spec(p.name, p.version)
        except Exception:
            log.warning(
                "serialise_package_spec raised unexpectedly for lang=%s spec=%r — falling back",
                getattr(lang, "name", "?"), p, exc_info=True,
            )
    return f"{p.name}=={p.version}" if p.version else p.name


def _try_parse(argv: list[str]) -> ParsedInstall | None:
    """Return a ParsedInstall for *argv*, or None if the command is unrecognised.

    Delegates to the language module's parse_process_install() and adapts the
    result to ParsedInstall so the sandbox runner can work with a single type.
    """
    if not argv:
        return None
    # Unpack a packed argv[0] (Node.js packs "npm install react" into a single
    # string with empty trailing slots).  Only trigger when all remaining slots
    # are empty so we don't corrupt legitimate paths that contain spaces.
    if " " in argv[0] and not any(argv[1:]):
        import shlex
        try:
            argv = shlex.split(argv[0])
        except ValueError:
            argv = argv[0].split()
    cmd = re.split(r"[/\\]", argv[0])[-1]
    lang = lang_registry.for_process(cmd)
    if lang is None:
        return None
    try:
        pi = lang.parse_process_install(argv)
    except Exception:
        log.warning(
            "parse_process_install raised unexpectedly for lang=%s argv=%r",
            getattr(lang, "name", "?"), argv, exc_info=True,
        )
        return None
    if pi is None:
        return None
    # Derive a single ecosystem string from the first package, or from the
    # language's primary ecosystem.
    ecosystem = (
        pi.packages[0].ecosystem.lower()
        if pi.packages
        else (lang.ecosystems[0].lower() if lang.ecosystems else "unknown")
    )
    return ParsedInstall(
        manager=pi.manager,
        packages=[_serialise_package_spec(p) for p in pi.packages],
        ecosystem=ecosystem,
        venv_exe=pi.venv_exe,
        req_files=pi.req_files,
        lockfile_hint=pi.lockfile_hint,
        global_install=pi.global_install,
        suggested_env=pi.suggested_env,
    )



def _resolve_real_binary(argv: list[str]) -> list[str]:
    """Replace argv[0] with its .__pa_real original if a shim is installed."""
    if not argv:
        return argv
    # If argv[0] is a full path (from a shim passing $0), use it directly.
    # Otherwise fall back to shutil.which for bare tool names.
    p = Path(argv[0])
    tool_path = str(p) if p.is_absolute() else shutil.which(argv[0])
    if tool_path is None:
        return argv
    real = Path(tool_path).parent / f"{Path(tool_path).name}{_PA_REAL_SUFFIX}"
    if real.exists():
        return [str(real)] + argv[1:]
    return argv


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


class _LockUnreadable:
    """Sentinel: lock file existed at snapshot time but its content could not be read
    (e.g. permission denied, symlink outside project root).  On restore this entry is
    skipped — we neither overwrite nor delete — to avoid data loss."""
    __slots__ = ()
    def __repr__(self) -> str:
        return "<LockUnreadable>"

_LOCK_UNREADABLE = _LockUnreadable()

def _restorable_lock_files() -> list[str]:
    """All lock/manifest file patterns to snapshot, restore, and check for containment.

    Includes every pattern advertised by language modules via lockfile_patterns(),
    including subdirectory variants (e.g. requirements/base.txt), so that
    _assert_scannable_lock_files_contained() covers exactly the same set that
    scan_project() will try to read.
    """
    lang_registry.load()
    seen: set[str] = set()
    result: list[str] = []
    for lang in lang_registry.all_languages():
        try:
            patterns = lang.lockfile_patterns()
        except Exception:
            log.warning(
                "lockfile_patterns raised unexpectedly for lang=%s — skipping language",
                getattr(lang, "name", "?"), exc_info=True,
            )
            continue
        for name in patterns:
            if name not in seen:
                seen.add(name)
                result.append(name)
    return result


def _scannable_lock_files() -> list[str]:
    """Lock file patterns that scan_project() may read — identical to restorable set."""
    return _restorable_lock_files()


def _assert_scannable_lock_files_contained(cwd: Path) -> str | None:
    """Check every existing scannable lock file in *cwd* resolves within the project.

    Returns the name of the first offending file, or ``None`` if all are safe.
    Used by both pre-flight and post-run scans before calling ``scan_project()``,
    which follows symlinks unconditionally via ``read_text()``.
    """
    project_root = cwd.resolve()
    for name in _scannable_lock_files():
        p = cwd / name
        if not p.exists() and not p.is_symlink():
            continue
        try:
            resolved = p.resolve()
        except OSError:
            return name
        if not resolved.is_relative_to(project_root):
            return name
    return None


def _snapshot_lock_files(
    cwd: Path, *, allow_developer_packages: bool = False
) -> dict[Path, bytes | None | _LockUnreadable]:
    """Snapshot all known restorable lock files under *cwd*.

    Return values per entry:
    - ``bytes``            — file existed and was readable; content stored.
    - ``None``             — file was genuinely absent (no directory entry at all);
                             restore should delete it if created during the run.
    - ``_LOCK_UNREADABLE`` — file had a directory entry (regular file, symlink, etc.)
                             but content could not be read (broken symlink, permission
                             error, or target outside project root); restore skips it
                             to avoid data loss.

    Symlinks whose resolved target lies outside *cwd* are recorded as
    ``_LOCK_UNREADABLE`` unless *allow_developer_packages* is True, which relaxes
    the check for monorepo / editable-install setups where lock files may
    legitimately live elsewhere.
    """
    project_root = cwd.resolve()
    result: dict[Path, bytes | None | _LockUnreadable] = {}
    for name in _restorable_lock_files():
        p = cwd / name
        # Use lstat() rather than exists() so that a broken symlink (inode present
        # but target missing) is treated as _LOCK_UNREADABLE rather than None.
        # FileNotFoundError from lstat() means the path truly does not exist.
        try:
            p.lstat()
        except FileNotFoundError:
            result[p] = None
            continue
        except OSError:
            # Other lstat failures (e.g. permission on parent dir) — treat as
            # unreadable rather than absent to avoid accidental deletion on restore.
            log.warning("Cannot stat lock file, skipping snapshot: %s", p)
            result[p] = _LOCK_UNREADABLE
            continue
        # Path has a directory entry (file, symlink, etc.).  Apply the containment
        # check before reading so we never follow external symlinks.
        if not allow_developer_packages:
            try:
                resolved = p.resolve()
            except OSError:
                log.warning("Cannot resolve lock file path, skipping snapshot: %s", p)
                result[p] = _LOCK_UNREADABLE
                continue
            if not resolved.is_relative_to(project_root):
                log.warning(
                    "Lock file resolves outside project directory, skipping snapshot: %s -> %s",
                    p,
                    resolved,
                )
                result[p] = _LOCK_UNREADABLE
                continue
        try:
            result[p] = p.read_bytes()
        except OSError:
            result[p] = _LOCK_UNREADABLE
    return result


def _restore_lock_files(
    snapshots: dict[Path, bytes | None | _LockUnreadable],
    cwd: Path,
    console: Console,
) -> None:
    # Check the *parent directory* (not the resolved symlink target) to decide
    # whether it is safe to operate on this path.  unlink() and rename() act on
    # the directory entry itself without following symlinks, so a containment
    # check on the parent is both necessary and sufficient.  This check is
    # unconditional because it guards the host filesystem, not the sandboxed
    # package manager — allow_developer_packages does not apply.
    project_root = cwd.resolve()
    restored = []
    for path, content in snapshots.items():
        if isinstance(content, _LockUnreadable):
            # Pre-run state was unknown; skip to avoid accidental data loss.
            continue
        try:
            parent_resolved = path.parent.resolve()
        except OSError:
            log.warning("Cannot resolve parent directory during lock file restore, skipping: %s", path)
            continue
        if not parent_resolved.is_relative_to(project_root):
            log.warning(
                "Lock file parent directory resolves outside project, skipping restore: %s",
                path,
            )
            continue
        try:
            if content is None:
                # Was absent pre-run; remove whatever appeared, including symlinks
                # and directories.  lstat() detects broken symlinks that exists()
                # would miss.  If the sandbox created a directory at this path
                # (e.g. an attacker replacing a lock file with a directory to
                # frustrate restore), unlink() would raise IsADirectoryError so we
                # fall back to rmtree().  These are known lock-file paths that must
                # be regular files, so removing any unexpected directory is correct.
                try:
                    path.lstat()
                    try:
                        path.unlink()
                    except IsADirectoryError:
                        shutil.rmtree(path)
                    restored.append(path.name)
                except FileNotFoundError:
                    pass
            else:
                # Write to a securely-created temp file in the same directory,
                # then atomically rename into place.  mkstemp() uses O_CREAT|O_EXCL
                # so it never follows an existing symlink.  rename() replaces the
                # destination directory entry without following symlinks, so an
                # attacker-placed symlink at `path` is overwritten by a regular file
                # rather than the content going to the symlink's target.
                fd, tmp_str = tempfile.mkstemp(dir=path.parent, prefix=".pa-restore-")
                tmp = Path(tmp_str)
                try:
                    # os.fdopen takes ownership of fd; the context manager flushes
                    # and closes it, guaranteeing all bytes are written (no partial
                    # write) before we rename into place.
                    with os.fdopen(fd, "wb") as fobj:
                        fobj.write(content)
                    tmp.rename(path)
                    restored.append(path.name)
                finally:
                    tmp.unlink(missing_ok=True)
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
