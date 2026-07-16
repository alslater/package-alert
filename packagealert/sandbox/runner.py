from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, replace as dataclass_replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console

from packagealert.languages import registry as lang_registry
from packagealert.languages.base import PackageSpec, SandboxEnvError, SandboxScanError, SandboxTargets
from packagealert.parsers.process_args import (
    ParsedInstall,
    parse_package_spec,
)
from packagealert.sandbox.backend import InstallSnapshot, SandboxBackend
from packagealert.sandbox.backends.registry import build_backend
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
    # Directories to snapshot+restore for rollback but not scanned for new packages
    snapshot_only_dirs: list[Path] = field(default_factory=list)


class SandboxRunner:
    def __init__(self, cfg: AppConfig) -> None:
        self._cfg = cfg
        self._console = Console()
        lang_registry.load()
        self._backend: SandboxBackend = build_backend(cfg.sandbox)

    async def run(self, argv: list[str], *, allow_network: bool = True, extra_env: list[str] | None = None, flags: dict[str, frozenset[str]] | None = None, allow_external_lockfiles: bool = False, no_change: bool = False) -> int:
        if not bwrap_available():
            self._console.print("[red]bwrap not found. Install bubblewrap to use 'package-alert run'.[/red]")
            self._console.print("[dim]  Ubuntu/Debian: sudo apt install bubblewrap[/dim]")
            self._console.print("[dim]  Fedora/RHEL:   sudo dnf install bubblewrap[/dim]")
            self._console.print("[dim]  Arch:          sudo pacman -S bubblewrap[/dim]")
            return 1

        if flags is None:
            flags = {}

        cwd = Path.cwd()

        if argv and Path(argv[0]).name in _SHELL_NAMES:
            return await self._run_shell(argv, cwd=cwd, allow_network=allow_network, extra_env=extra_env, flags=flags, allow_external_lockfiles=allow_external_lockfiles, no_change=no_change)

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
                # Resolve symlinks first — python3 -> python means __pa_real
                # lives next to python, not python3. Fall back to the unresolved
                # path if resolve() fails (permission error, broken symlink, etc.)
                try:
                    tool_resolved = Path(tool_path).resolve()
                except OSError:
                    tool_resolved = Path(tool_path)
                real_sibling = tool_resolved.parent / f"{tool_resolved.name}{_PA_REAL_SUFFIX}"
                if not real_sibling.exists():
                    try:
                        content = Path(tool_path).read_text(errors="strict")
                        if "# __pa_shim__" in content:
                            self._console.print(
                                f"[red]✗ {tool_resolved} is a package-alert shim but "
                                f"{real_sibling} is missing — infinite recursion prevented.[/red]"
                            )
                            self._console.print(
                                "[dim]Run 'package-alert setup project --uninstall' "
                                "and reinstall the tool.[/dim]"
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

        import inspect as _inspect
        from packagealert.languages.base import PreRunResult as _PreRunResult

        def _run_pre_check(lang, parsed_arg, lang_flags):
            """Invoke pre_run_check on *lang*, handling legacy signatures.

            *parsed_arg* is None when the language is not the primary ecosystem
            (mirrors configure_sandbox behaviour for cross-namespace flags).
            Returns 1 if the check blocked, 0 to continue.
            """
            pre_check_fn = getattr(lang, "pre_run_check", None)
            if not callable(pre_check_fn):
                return 0
            _lang_name = getattr(lang, "name", "?")
            try:
                _sig = _inspect.signature(pre_check_fn)
                _params = _sig.parameters
                _has_flags_param = "flags" in _params or any(
                    p.kind == _inspect.Parameter.VAR_KEYWORD
                    for p in _params.values()
                )
                # expose_ssh_keys was in the old LanguageBase signature, so any
                # plugin overriding pre_run_check before contract v3 will have it.
                # Only Python ever acted on it — and the built-in Python plugin is
                # already on v3, so this path is only hit by third-party legacy
                # plugins that never used the value. Always pass False.
                _has_legacy_expose = "expose_ssh_keys" in _params
            except (ValueError, TypeError):
                _has_flags_param = True
                _has_legacy_expose = False
            try:
                if _has_legacy_expose:
                    # expose_ssh_keys is always False here. The parameter existed in the
                    # old LanguageBase signature so every pre-v3 plugin declared it, but
                    # only the built-in Python plugin ever read it — and that plugin is
                    # already on contract v3 (no expose_ssh_keys in its signature), so
                    # it will never reach this branch. No third-party plugin shipped that
                    # acted on this value; passing False is safe and correct.
                    if _has_flags_param:
                        result = pre_check_fn(parsed_arg, cwd, False, flags=lang_flags)
                    else:
                        result = pre_check_fn(parsed_arg, cwd, False)
                elif _has_flags_param:
                    result = pre_check_fn(parsed_arg, cwd, flags=lang_flags)
                else:
                    result = pre_check_fn(parsed_arg, cwd)
            except Exception:
                log.warning("pre_run_check raised for lang=%s — skipping",
                            _lang_name, exc_info=True)
                result = None
            if isinstance(result, str):
                # Legacy v1/v2 contract: non-empty string = error message (block);
                # empty string or None = allow. Truthy non-string = block (old sentinel).
                if result:
                    result = _PreRunResult(ok=False, message=result)
                else:
                    result = _PreRunResult(ok=True)
            elif result is None:
                result = _PreRunResult(ok=True)
            elif not isinstance(result, _PreRunResult):
                # Any other truthy value was a legacy block sentinel; falsy = allow.
                if result:
                    log.warning(
                        "pre_run_check for lang=%s returned unexpected truthy type %s — blocking",
                        _lang_name, type(result).__name__,
                    )
                    result = _PreRunResult(ok=False, message="Run blocked by language plugin.")
                else:
                    log.warning(
                        "pre_run_check for lang=%s returned unexpected falsy type %s — allowing",
                        _lang_name, type(result).__name__,
                    )
                    result = _PreRunResult(ok=True)
            if not result.ok:
                self._console.print(result.message, style="bold red", markup=False)
                if result.required_flag:
                    self._console.print(
                        f"Re-run with --flags {result.required_flag} to grant this capability.",
                        style="dim",
                        markup=False,
                    )
                return 1
            return 0

        # Run pre_run_check for the primary ecosystem language.
        _primary_lang_name: str | None = None
        if parsed is not None:
            lang = lang_registry.for_ecosystem(parsed.ecosystem)
            if lang is not None:
                _primary_lang_name = getattr(lang, "name", None)
                lang_flags = flags.get(_primary_lang_name or "", frozenset())
                if _run_pre_check(lang, parsed, lang_flags):
                    return 1

        # Also run pre_run_check for any other flagged namespace so that e.g.
        # --flags python:ssh-keys during `npm install` still triggers the Python
        # confirmation prompt before configure_sandbox mounts ~/.ssh.
        for _ns, _ns_flags in flags.items():
            if not _ns_flags:
                continue
            _lang = lang_registry.get(_ns)
            if _lang is None:
                continue
            if getattr(_lang, "name", _ns) == _primary_lang_name:
                continue  # already handled above
            if _run_pre_check(_lang, None, _ns_flags):
                return 1

        cooldown_result = await self._cooldown_check(ctx)
        if cooldown_result is False:
            return 1
        pending_clears: list[tuple[str, str, str]] = cooldown_result  # type: ignore[assignment]

        if not await self._preflight(ctx, allow_external_lockfiles=allow_external_lockfiles):
            return 1

        if is_global:
            real_argv = _resolve_real_binary(argv)
            try:
                os.execvp(real_argv[0], real_argv)
            except FileNotFoundError:
                self._console.print(f"[red]✗ Command not found: {real_argv[0]}[/red]")
                return 127
            return 0  # unreachable

        _resolve_targets(ctx, self._console)

        targets_label = ", ".join(str(t) for t in ctx.scan_targets) or "none detected"
        self._console.print(f"[dim]Scan targets: {targets_label}[/dim]")
        network_label = "allowed" if allow_network else "blocked"
        if no_change:
            self._console.print("[dim]Mode: dry run (--no-change) — lock files and install targets will be restored after the run[/dim]")
        self._console.print(f"[dim]Running in sandbox (network: {network_label})...[/dim]\n")

        # Snapshot scan targets and lock files before execution.
        # Abort if any snapshot fails — rollback guarantees depend on having one.
        snapshots: dict[Path, InstallSnapshot] = {}
        for _t in ctx.scan_targets:
            try:
                snapshots[_t] = self._backend.snapshot_install_target(_t, self._console, cwd)
            except Exception as exc:
                self._console.print(f"✗ Cannot snapshot install target {_t}: {exc}", style="bold red", markup=False)
                self._console.print("Aborting — rollback cannot be guaranteed without a snapshot.", style="dim")
                return 1
        for _t in ctx.snapshot_only_dirs:
            if _t not in snapshots:
                try:
                    # Use $HOME as the containment root for home-local dirs (e.g. pipx/uv
                    # tool venvs under ~/.local/share/) so that symlinks relocated elsewhere
                    # under $HOME are accepted.  Dirs under cwd keep the tighter cwd root.
                    _home = Path.home()
                    _snap_root = _home if _t.is_relative_to(_home) else cwd
                    snapshots[_t] = self._backend.snapshot_install_target(_t, self._console, _snap_root)
                except Exception as exc:
                    self._console.print(f"✗ Cannot snapshot rollback target {_t}: {exc}", style="bold red", markup=False)
                    self._console.print("Aborting — rollback cannot be guaranteed without a snapshot.", style="dim")
                    return 1
        lock_snapshots = _snapshot_lock_files(cwd, allow_external_lockfiles=allow_external_lockfiles)

        combined_extra = list(self._cfg.sandbox.extra_env)
        if extra_env:
            combined_extra.extend(extra_env)
        sandbox_env = _build_sandbox_env(combined_extra)

        if parsed is not None:
            lang = lang_registry.for_ecosystem(parsed.ecosystem)
            if lang is not None:
                prepare_env_fn = getattr(lang, "prepare_sandbox_env", None)
                if callable(prepare_env_fn):
                    try:
                        extra_write = prepare_env_fn(parsed, cwd, sandbox_env)
                    except SandboxEnvError as exc:
                        self._console.print(str(exc), style="bold red", markup=False)
                        return 1
                    except Exception:
                        log.warning("prepare_sandbox_env raised for lang=%s — skipping",
                                    getattr(lang, "name", "?"), exc_info=True)
                        extra_write = []
                    else:
                        for p in extra_write:
                            if p not in ctx.write_dirs:
                                ctx.write_dirs.append(p)
                            # Snapshot extra writable paths so rollback covers them.
                            # These may be modified by the sandbox (e.g. venv/bin/)
                            # but are not in ctx.scan_targets, so without a snapshot
                            # they would not be restored on rollback.
                            if p not in snapshots:
                                try:
                                    snapshots[p] = self._backend.snapshot_install_target(
                                        p, self._console, cwd
                                    )
                                except Exception as exc:
                                    self._console.print(
                                        f"✗ Cannot snapshot extra write target {p}: {exc}",
                                        style="bold red", markup=False,
                                    )
                                    self._console.print(
                                        "Aborting — rollback cannot be guaranteed without a snapshot.",
                                        style="dim",
                                    )
                                    return 1

        # home_ro: paths under cwd are already covered by the cwd write bind —
        # a more-specific ro-bind on any of them would silently shadow it.
        home_ro = [p for p in _home_ro_dirs() if not p.is_relative_to(ctx.cwd)]

        _cs_targets = SandboxTargets(
            scan_targets=list(ctx.scan_targets),
            write_dirs=list(ctx.write_dirs),
        )
        _primary_lang_name: str | None = None
        if ctx.parsed is not None:
            lang_for_cs = lang_registry.for_ecosystem(ctx.parsed.ecosystem)
            if lang_for_cs is not None:
                configure_fn = getattr(lang_for_cs, "configure_sandbox", None)
                if callable(configure_fn):
                    _primary_lang_name = getattr(lang_for_cs, "name", None)
                    lang_flags_cs = flags.get(_primary_lang_name or "", frozenset())
                    try:
                        configure_fn(ctx.parsed, cwd, lang_flags_cs, _cs_targets, home_ro, sandbox_env)
                    except Exception:
                        log.warning("configure_sandbox raised for lang=%s — skipping",
                                    _primary_lang_name, exc_info=True)

        # Also invoke configure_sandbox for any other language namespace that has
        # active flags — so e.g. --flags python:ssh-keys mounts ~/.ssh even when
        # running npm install (node ecosystem, not python).
        for _ns, _ns_flags in flags.items():
            if not _ns_flags:
                continue
            _lang = lang_registry.get(_ns)
            if _lang is None:
                continue
            _ns_name = getattr(_lang, "name", _ns)
            if _ns_name == _primary_lang_name:
                continue  # already handled above
            _configure_fn = getattr(_lang, "configure_sandbox", None)
            if callable(_configure_fn):
                try:
                    _configure_fn(None, cwd, _ns_flags, _cs_targets, home_ro, sandbox_env)
                except Exception:
                    log.warning("configure_sandbox raised for lang=%s — skipping",
                                _ns_name, exc_info=True)

        # Collect writable bind pairs from configure_sandbox_writable.
        _parsed_by_lang = {_primary_lang_name: ctx.parsed} if _primary_lang_name and ctx.parsed else {}
        _writable_binds = self._collect_and_print_writable_binds(
            flags, cwd, _cs_targets, _parsed_by_lang,
        )

        try:
            extra_tmpfs = list(self._cfg.sandbox.extra_tmpfs)
            if not self._check_extra_tmpfs(extra_tmpfs):
                return 1

            home_ro.extend(self._cfg.sandbox.extra_ro_paths)

            argv = _resolve_real_binary(argv)
            if ctx.parsed is not None:
                lang = lang_registry.for_ecosystem(ctx.parsed.ecosystem)
                if lang is not None:
                    lang_name = getattr(lang, "name", "?")
                    prepare_fn = getattr(lang, "prepare_sandbox_argv", None)
                    if callable(prepare_fn):
                        try:
                            argv = prepare_fn(argv, cwd)
                        except Exception:
                            log.warning("prepare_sandbox_argv raised for lang=%s — using original argv", lang_name, exc_info=True)
                    editable_roots = self._cfg.sandbox.editable_roots
                    extra_ro_fn = getattr(lang, "sandbox_extra_ro_paths", None)
                    if callable(extra_ro_fn):
                        try:
                            for p in extra_ro_fn(argv, cwd):
                                if _is_safe_sandbox_path(p, editable_roots):
                                    home_ro.append(p.resolve())
                                else:
                                    log.warning("sandbox_extra_ro_paths: rejecting path %s from lang=%s", p, lang_name)
                                    self._print_editable_rejection(p, editable_roots)
                        except Exception:
                            log.warning("sandbox_extra_ro_paths raised for lang=%s — skipping", lang_name, exc_info=True)
                    extra_write_fn = getattr(lang, "sandbox_extra_write_paths", None)
                    if callable(extra_write_fn):
                        try:
                            for p in extra_write_fn(argv, cwd):
                                if _is_safe_sandbox_path(p, editable_roots):
                                    ctx.write_dirs.append(p.resolve())
                                else:
                                    log.warning("sandbox_extra_write_paths: rejecting path %s from lang=%s", p, lang_name)
                                    self._print_editable_rejection(p, editable_roots)
                        except Exception:
                            log.warning("sandbox_extra_write_paths raised for lang=%s — skipping", lang_name, exc_info=True)
            result = subprocess.run(build_cmd(
                argv, ctx.write_dirs,
                allow_network=allow_network,
                env=sandbox_env,
                home_ro_dirs=home_ro,
                extra_tmpfs=extra_tmpfs,
                post_ro_tmpfs=_post_ro_tmpfs_dirs(home_ro),
                writable_binds=_writable_binds,
            ))
        finally:
            _cleanup_writable_binds(_writable_binds)
        print()

        if result.returncode != 0:
            self._console.print(f"[yellow]Command exited with code {result.returncode}[/yellow]")
            # A failing install can still write or modify lock files, so run the
            # lock-file scan and restore unconditionally — exiting non-zero must
            # not be a way to evade the check.
            scan_ok = await self._scan_updated_lock_files(cwd, lock_snapshots, allow_external_lockfiles=allow_external_lockfiles)
            if no_change:
                _restore_lock_files(lock_snapshots, cwd, self._console)
                restore_ok = _restore_install_targets(self._backend, snapshots, self._console)
                return result.returncode if (scan_ok and restore_ok) else 1
            elif not scan_ok:
                _restore_lock_files(lock_snapshots, cwd, self._console)
                _restore_install_targets(self._backend, snapshots, self._console)
                return 1
            return result.returncode if scan_ok else 1

        scan_ok = await self._scan_updated_lock_files(cwd, lock_snapshots, allow_external_lockfiles=allow_external_lockfiles)
        if not no_change:
            if not scan_ok:
                _restore_lock_files(lock_snapshots, cwd, self._console)
                _restore_install_targets(self._backend, snapshots, self._console)
                return 1

        if not scan_ok:
            # no_change=True: lock file scan failed — restore everything and exit.
            _restore_lock_files(lock_snapshots, cwd, self._console)
            _restore_install_targets(self._backend, snapshots, self._console)
            return 1

        # Re-detect scan targets that may have been created during the run
        # (e.g. uv sync creating .venv from scratch). Delegate to the language
        # module so the logic stays out of the runner.
        if parsed and not ctx.scan_targets:
            lang = lang_registry.for_ecosystem(parsed.ecosystem)
            if lang is not None:
                post_run_fn = getattr(lang, "post_run_scan_targets", None)
                if callable(post_run_fn):
                    try:
                        targets = post_run_fn(parsed, cwd)
                    except Exception:
                        log.warning(
                            "post_run_scan_targets raised for lang=%s — skipping",
                            getattr(lang, "name", "?"), exc_info=True,
                        )
                        targets = []
                    if targets:
                        # First path is the rollback root (e.g. venv root),
                        # last path is the scan target (e.g. site-packages).
                        rollback_root = targets[0]
                        scan_target = targets[-1]
                        if scan_target.exists():
                            ctx.scan_targets.append(scan_target)
                            snapshots[rollback_root] = self._backend.absent_snapshot()

        ecosystem = parsed.ecosystem if parsed else None
        try:
            new_pkgs = _collect_new_packages(
                ctx.scan_targets,
                snapshots,
                ecosystem,
            )
        except SandboxScanError as exc:
            self._console.print(str(exc), style="bold red", markup=False)
            _restore_lock_files(lock_snapshots, cwd, self._console)
            _restore_install_targets(self._backend, snapshots, self._console)
            return 1

        if new_pkgs:
            self._console.print(f"[dim]Post-install scan: {len(new_pkgs)} new package(s)...[/dim]")
            post_ok = await self._post_scan(new_pkgs)
            if not post_ok:
                _restore_lock_files(lock_snapshots, cwd, self._console)
                _restore_install_targets(self._backend, snapshots, self._console)
                return 1
        else:
            self._console.print("[dim]Post-install scan: no new packages detected[/dim]")

        # --no-change: restore lock files and install targets after all checks pass.
        if no_change:
            _restore_lock_files(lock_snapshots, cwd, self._console)
            restore_ok = _restore_install_targets(self._backend, snapshots, self._console)
            if not restore_ok:
                return 1

        if pending_clears:
            db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))
            try:
                for eco, pkg_name, ver in pending_clears:
                    await store_cooldown_cleared(db, ecosystem=eco, package=pkg_name, version=ver)
            finally:
                await db.close()

        return 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _print_editable_rejection(self, p: Path, editable_roots: list[Path]) -> None:
        """Print a user-facing explanation for why an editable path was blocked."""
        try:
            resolved = p.resolve()
        except OSError:
            resolved = p
        # Check if it's a credential/system directory violation — including ancestors
        # (e.g. $HOME would expose ~/.ssh as a subdirectory of the bind mount).
        for cred in credential_dirs():
            if resolved == cred or resolved.is_relative_to(cred) or cred.is_relative_to(resolved):
                if cred.is_relative_to(resolved):
                    self._console.print(f"✗  Editable path blocked — would expose {cred.name} inside the sandbox: {p}", style="red bold", markup=False)
                else:
                    self._console.print(f"✗  Editable path blocked — credential directory: {p}", style="red bold", markup=False)
                self._console.print("  package-alert never exposes credential directories inside the sandbox.", style="dim")
                return
        for prefix in _UNSAFE_PREFIXES:
            if resolved == prefix or resolved.is_relative_to(prefix):
                self._console.print(f"✗  Editable path blocked — system directory: {p}", style="red bold", markup=False)
                return
        # editable_roots restriction
        self._console.print(f"⚠  Editable install blocked: {p}", style="yellow", markup=False)
        if not editable_roots:
            self._console.print("  Editable installs require sandbox.editable_roots to be configured.", style="dim")
            self._console.print("  Add to ~/.config/package-alert/config.toml:", style="dim")
            self._console.print("    [sandbox]", style="dim", markup=False)
            self._console.print(f'    editable_roots = ["{p.parent}"]', style="dim", markup=False)
        else:
            roots = ", ".join(f'"{r}"' for r in editable_roots)
            self._console.print(f"  Path is outside configured editable_roots: [{roots}]", style="dim", markup=False)
            self._console.print(f'  Add "{p.parent}" to sandbox.editable_roots to permit this install.', style="dim", markup=False)

    def _collect_and_print_writable_binds(
        self,
        flags_by_lang: dict[str, frozenset[str]],
        cwd: Path,
        targets: SandboxTargets,
        parsed_by_lang: dict[str, ParsedInstall | None],
    ) -> list[tuple[Path, Path]]:
        """Collect writable-bind pairs and print any security warnings via the runner console.

        Thin wrapper around :func:`_collect_writable_binds` that handles the
        warning-printing step so callers don't duplicate it.
        """
        pairs, warnings = _collect_writable_binds(
            lang_registry, flags_by_lang, cwd, targets, parsed_by_lang,
        )
        for msg in warnings:
            self._console.print(msg)
        return pairs

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
        db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))

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
                            try:
                                latest_url = latest_url_fn(name)
                            except Exception:
                                log.warning("latest_version_url raised for lang=%s pkg=%s — skipping", getattr(lang_for_latest, "name", "?"), name, exc_info=True)
                                latest_url = None
                            if latest_url is not None:
                                version = await fetch_latest_version(latest_url, lang_for_latest, name)
                                if version:
                                    self._console.print(f"[dim]Resolving latest version: {lang_for_latest.serialise_package_spec(name, version)}[/dim]")
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
        flags: dict[str, frozenset[str]] | None = None,
        allow_external_lockfiles: bool = False,
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

        # Propagate active flags into PA_RUN_OPTS so shim-invoked package managers
        # inside the shell inherit them (e.g. pipenv lock picking up python:ssh-keys).
        shell_flags = flags or {}
        if shell_flags:
            flags_str = ",".join(
                f"{ns}:{cap}"
                for ns, caps in sorted(shell_flags.items())
                for cap in sorted(caps)
            )
            existing_opts = sandbox_env.get("PA_RUN_OPTS", "").strip()
            sandbox_env["PA_RUN_OPTS"] = f"{existing_opts} --flags {shlex.quote(flags_str)}".strip()

        if "ssh-keys" in shell_flags.get("python", frozenset()):
            from rich.console import Console as _Console
            _ssh_dir = Path.home() / ".ssh"
            if _ssh_dir.exists():
                _Console(stderr=True).print(
                    "⚠  SSH keys (python:ssh-keys): ~/.ssh mounted read-only inside the sandbox.",
                    style="yellow",
                    markup=False,
                )
            else:
                _Console(stderr=True).print(
                    "⚠  SSH keys (python:ssh-keys): ~/.ssh not found — flag has no effect.",
                    style="yellow",
                    markup=False,
                )

        write_dirs: list[Path] = [cwd]
        scan_targets: list[Path] = []
        notes: list[str] = []

        for lang in lang_registry.all_languages():
            shell_env_fn = getattr(lang, "shell_environment", None)
            if callable(shell_env_fn):
                try:
                    lang_shell = shell_env_fn(cwd)
                except Exception:
                    log.warning("shell_environment raised for lang=%s — skipping",
                                getattr(lang, "name", "?"), exc_info=True)
                    continue
                write_dirs.extend(lang_shell.write_dirs)
                scan_targets.extend(lang_shell.scan_targets)
                for k, v in lang_shell.env_updates.items():
                    sandbox_env[k] = v
                for p in lang_shell.path_prepends:
                    sandbox_env["PATH"] = f"{p}:{sandbox_env.get('PATH', '')}"
                notes.extend(lang_shell.notes)
                for w in lang_shell.warnings:
                    self._console.print(w, style="bold yellow", markup=False)

        if notes:
            self._console.print(f"[dim]Environment: {', '.join(notes)}[/dim]")

        # Pre-flight: scan all project lock files for known-malicious packages
        if not await self._preflight_shell(cwd, allow_external_lockfiles=allow_external_lockfiles):
            return 1

        # Snapshot install targets and lock files before the shell session opens.
        # Abort if any snapshot fails — rollback guarantees depend on having one.
        # Also snapshot write dirs that are within the project so rollback covers
        # mutations outside the scan targets (e.g. new console scripts in venv/bin/).
        # Exclude cwd (covered by lock file restore) and paths outside the project
        # (e.g. package-manager caches) which are too large to snapshot usefully.
        targets_to_snapshot: list[Path] = list(scan_targets)
        for p in write_dirs:
            if p == cwd or p in targets_to_snapshot:
                continue
            if p.is_relative_to(cwd):
                targets_to_snapshot.append(p)

        snapshots: dict[Path, InstallSnapshot] = {}
        for _t in targets_to_snapshot:
            try:
                snapshots[_t] = self._backend.snapshot_install_target(_t, self._console, cwd)
            except Exception as exc:
                self._console.print(f"✗ Cannot snapshot install target {_t}: {exc}", style="bold red", markup=False)
                self._console.print("Aborting — rollback cannot be guaranteed without a snapshot.", style="dim")
                return 1
        lock_snapshots = _snapshot_lock_files(cwd, allow_external_lockfiles=allow_external_lockfiles)

        network_label = "allowed" if allow_network else "blocked"
        if no_change:
            self._console.print("[dim]Mode: dry run (--no-change) — lock files and install targets will be restored after the session[/dim]")
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
        shell_flags = flags or {}
        for lang in lang_registry.all_languages():
            lang_name_sh = getattr(lang, "name", "?")
            lang_flags_sh = shell_flags.get(lang_name_sh, frozenset())
            if not lang_flags_sh:
                continue
            configure_fn = getattr(lang, "configure_sandbox", None)
            if callable(configure_fn):
                _sh_targets = SandboxTargets(
                    scan_targets=list(scan_targets),
                    write_dirs=list(write_dirs),
                )
                try:
                    configure_fn(None, cwd, lang_flags_sh, _sh_targets, home_ro, sandbox_env)
                except Exception:
                    log.warning("configure_sandbox raised for lang=%s in shell mode — skipping",
                                lang_name_sh, exc_info=True)

        # Collect writable bind pairs from configure_sandbox_writable (shell mode).
        _wb_sh_targets = SandboxTargets(
            scan_targets=list(scan_targets),
            write_dirs=list(write_dirs),
        )
        _writable_binds = self._collect_and_print_writable_binds(
            shell_flags, cwd, _wb_sh_targets, {},
        )

        try:
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
                post_ro_tmpfs=_post_ro_tmpfs_dirs(home_ro),
                writable_binds=_writable_binds,
            ))
        finally:
            _cleanup_writable_binds(_writable_binds)
        print()

        # Post-exit: scan changed lock files, then any newly installed packages.
        # In --no-change mode, defer restore until after post-shell scanning so
        # new-package detection sees the actual installed state.
        scan_ok = await self._scan_updated_lock_files(cwd, lock_snapshots, allow_external_lockfiles=allow_external_lockfiles)
        if not no_change:
            if not scan_ok:
                _restore_lock_files(lock_snapshots, cwd, self._console)
                _restore_install_targets(self._backend, snapshots, self._console)
                return 1
        if not scan_ok:
            # no_change=True and lock file scan failed — restore and exit.
            _restore_lock_files(lock_snapshots, cwd, self._console)
            _restore_install_targets(self._backend, snapshots, self._console)
            return 1

        try:
            new_pkgs = _collect_new_packages(
                scan_targets,
                snapshots,
                None,
            )
        except SandboxScanError as exc:
            self._console.print(str(exc), style="bold red", markup=False)
            _restore_lock_files(lock_snapshots, cwd, self._console)
            _restore_install_targets(self._backend, snapshots, self._console)
            return 1

        if new_pkgs:
            self._console.print(f"[dim]Post-shell scan: {len(new_pkgs)} new package(s)...[/dim]")
            post_ok = await self._post_scan(new_pkgs)
            if not post_ok:
                _restore_lock_files(lock_snapshots, cwd, self._console)
                _restore_install_targets(self._backend, snapshots, self._console)
                return 1
        else:
            self._console.print("[dim]Post-shell scan: no new packages detected[/dim]")

        # --no-change: restore lock files and install targets after all checks pass.
        if no_change:
            _restore_lock_files(lock_snapshots, cwd, self._console)
            restore_ok = _restore_install_targets(self._backend, snapshots, self._console)
            if not restore_ok:
                return 1

        return result.returncode

    async def _preflight_shell(self, cwd: Path, *, allow_external_lockfiles: bool = False) -> bool:
        """Pre-flight OSV check for shell sessions: scans all project lock files."""
        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient
        from packagealert.parsers.lockfiles import scan_project
        from packagealert.storage.db import open_db

        if not allow_external_lockfiles:
            offender = _assert_scannable_lock_files_contained(cwd)
            if offender is not None:
                self._console.print(
                    f"[bold red]✗ Lock file {offender} resolves outside the project directory "
                    f"— refusing pre-flight scan. Pass --allow-external-lockfiles to override.[/bold red]"
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
        db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))
        client = OsvClient(self._cfg.osv)
        cache = OsvCache(db, self._cfg.osv)
        malicious: list[tuple[str, str]] = []

        status = self._console.status(f"[dim]Pre-flight: {len(queries)} packages ({sources})...[/dim]")
        status.start()
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
            status.stop()
            await client.aclose()
            await db.close()

        if malicious:
            self._console.print(f"[bold red]✗ Blocked — {len(malicious)} malicious package(s) in lock files:[/bold red]")
            for name, adv_id in malicious:
                self._console.print(f"  [red]• {name}  ({adv_id})[/red]")
            return False

        self._console.print("[green]✓ Pre-flight: no known advisories[/green]")
        return True

    async def _preflight(self, ctx: _Context, *, allow_external_lockfiles: bool = False) -> bool:
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
            if not allow_external_lockfiles:
                bad = _assert_scannable_lock_files_contained(ctx.cwd)
                if bad is not None:
                    self._console.print(
                        f"[bold red]✗ Blocked — lock file '{bad}' resolves outside the project "
                        f"directory. Use --allow-external-lockfiles to override.[/bold red]"
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

        db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))
        client = OsvClient(self._cfg.osv)
        cache = OsvCache(db, self._cfg.osv)
        malicious: list[tuple[str, str]] = []

        status = self._console.status(f"[dim]Pre-flight: {source}...[/dim]")
        status.start()
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
            status.stop()
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
        allow_external_lockfiles: bool = False,
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
                if not allow_external_lockfiles and p.is_symlink():
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
        if not allow_external_lockfiles:
            offender = _assert_scannable_lock_files_contained(cwd)
            if offender is not None:
                self._console.print(
                    f"[bold red]✗ Lock file {offender} resolves outside the project directory "
                    f"— refusing to scan. Pass --allow-external-lockfiles to override.[/bold red]"
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

        db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))
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
                "[bold red]✗ Malicious package(s) found in updated lock file(s):[/bold red]"
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

        db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))
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
            return False

        self._console.print("[green]✓ Post-install: clean[/green]")
        return True


# ---------------------------------------------------------------------------
# Module-level helpers (kept outside the class for testability)
# ---------------------------------------------------------------------------


def _home_ro_dirs() -> list[Path]:
    """Return home-directory paths that package managers need read-only access to.

    The home directory is hidden with a tmpfs; only these paths are re-exposed
    so that SSH keys, cloud credentials, and secrets in other directories are
    not readable by install-time scripts.

    Runtime tool paths (pyenv, nvm, uv, pipx, local bin) are listed here.
    Package-manager config paths (pip, npmrc, etc.) are contributed by each
    language module via the home_ro_paths() hook.
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
    ]
    result = [p for p in candidates if p.exists()]
    # Merge language-module config paths
    for lang in lang_registry.all_languages():
        home_ro_fn = getattr(lang, "home_ro_paths", None)
        if callable(home_ro_fn):
            try:
                result.extend(p for p in home_ro_fn() if p.exists() and p not in result)
            except Exception:
                log.warning("home_ro_paths raised for lang=%s — skipping",
                            getattr(lang, "name", "?"), exc_info=True)
    return result


def _post_ro_tmpfs_dirs(home_ro: list[Path]) -> list[Path]:
    """Return log subdirectories of ro-bound tool dirs that need a writable tmpfs overlay.

    Tools like pipx unconditionally try to delete old log files during startup,
    before executing any user command.  When their home directory is re-exposed
    read-only inside the sandbox, that cleanup fails with EROFS.  Overlaying the
    logs directory with a fresh tmpfs (after the ro-bind) makes it writable again
    without exposing it to the host.

    Only dirs that exist are returned — bwrap cannot create a missing mount point
    under the read-only root bind.

    Deduplication uses ``os.path.realpath`` (resolves symlinks in all components)
    so two ro_path entries that refer to the same filesystem location via different
    spellings or symlinked parents yield a single logs entry.
    """
    result: list[Path] = []
    seen: set[Path] = set()
    for ro_path in home_ro:
        logs = ro_path / "logs"
        if not logs.is_symlink() and logs.is_dir():
            key = Path(os.path.realpath(logs))
            if key not in seen:
                seen.add(key)
                result.append(logs)
    return result


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


_FLAG_TOKEN_RE = re.compile(r'^[a-z0-9_-]+$')


def _parse_flags(flags_str: str) -> dict[str, frozenset[str]]:
    """Parse a comma-separated flags string into a per-namespace dict.

    "python:ssh-keys,ruby:gem-credentials" ->
        {"python": frozenset({"ssh-keys"}), "ruby": frozenset({"gem-credentials"})}

    Entries without a colon are silently ignored. Namespace and capability tokens
    must match ``[a-z0-9_-]+``; invalid tokens (including uppercase) are silently
    dropped. Callers are responsible for producing user-facing diagnostics before
    calling this function.
    """
    result: dict[str, list[str]] = {}
    for token in flags_str.split(","):
        token = token.strip()
        if ":" not in token:
            continue
        namespace, _, capability = token.partition(":")
        namespace = namespace.strip()
        capability = capability.strip()
        if not namespace or not capability:
            continue
        if not _FLAG_TOKEN_RE.match(namespace) or not _FLAG_TOKEN_RE.match(capability):
            continue
        result.setdefault(namespace, []).append(capability)
    return {k: frozenset(v) for k, v in result.items()}


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
        extra_write_home_dirs=list(getattr(pi, "extra_write_home_dirs", [])),
        target_env_name=getattr(pi, "target_env_name", None),
    )



_UNSAFE_PREFIXES: tuple[Path, ...] = (
    Path("/etc"),
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
    Path("/boot"),
    Path("/sys"),
    Path("/proc"),
    Path("/dev"),
)

# Credential and secret directories inside $HOME that the sandbox deliberately
# hides. Plugin-supplied extra paths must not re-expose these.
def credential_dirs() -> tuple[Path, ...]:
    home = Path.home()
    return (
        home / ".ssh",
        home / ".aws",
        home / ".gnupg",
        home / ".config" / "gcloud",
        home / ".netrc",
        home / ".git-credentials",
        home / ".azure",
        home / ".kube",
        home / ".docker",
    )


def _collect_writable_binds(
    lang_registry: Any,
    flags_by_lang: dict[str, frozenset[str]],
    cwd: Path,
    targets: SandboxTargets,
    parsed_by_lang: dict[str, ParsedInstall | None],
) -> tuple[list[tuple[Path, Path]], list[str]]:
    """Collect (src, dest) writable-bind pairs and security warnings from all language modules.

    Returns ``(pairs, warnings)`` where *warnings* is a list of Rich markup
    strings to be printed by the caller via its console.  *parsed_by_lang* maps
    language name to the parsed command object for that language.  Languages
    absent from the mapping receive ``None`` (the correct value in shell mode
    and for cross-namespace calls).
    """
    result: list[tuple[Path, Path]] = []
    seen: set[tuple[Path, Path]] = set()
    warnings: list[str] = []
    for lang in lang_registry.all_languages():
        name = getattr(lang, "name", "?")
        lang_flags = flags_by_lang.get(name, frozenset())
        parsed = parsed_by_lang.get(name)
        fn = getattr(lang, "configure_sandbox_writable", None)
        if callable(fn):
            try:
                pairs = fn(parsed, cwd, lang_flags, targets)
            except Exception:
                log.warning(
                    "configure_sandbox_writable raised for lang=%s — skipping",
                    name,
                    exc_info=True,
                )
                continue
            if not isinstance(pairs, list):
                log.warning(
                    "configure_sandbox_writable lang=%s returned %s, expected list — skipping",
                    name, type(pairs).__name__,
                )
                continue
            valid_pairs: list[tuple[Path, Path]] = []
            for entry in pairs:
                if (
                    isinstance(entry, tuple)
                    and len(entry) == 2
                    and isinstance(entry[0], Path)
                    and isinstance(entry[1], Path)
                ):
                    if not entry[0].is_absolute():
                        log.warning(
                            "configure_sandbox_writable lang=%s: src is not absolute, skipping: %s",
                            name, entry[0],
                        )
                    elif not entry[1].is_absolute():
                        log.warning(
                            "configure_sandbox_writable lang=%s: dest is not absolute, skipping: %s",
                            name, entry[1],
                        )
                    elif not _is_safe_writable_bind_src(entry[0]):
                        log.warning(
                            "configure_sandbox_writable lang=%s: src failed safety checks "
                            "(must be a pa- prefixed directory under tempdir), skipping: %s",
                            name, entry[0],
                        )
                    elif not _is_safe_writable_bind_dest(entry[1], cwd):
                        log.warning(
                            "configure_sandbox_writable lang=%s: dest failed safety checks "
                            "(must be strictly under $HOME, not a credential dir, and not overlapping the project dir): %s",
                            name, entry[1],
                        )
                    else:
                        try:
                            norm_key = (entry[0].resolve(strict=False), entry[1].resolve(strict=False))
                        except (OSError, RuntimeError):
                            norm_key = entry
                        if norm_key in seen:
                            log.warning(
                                "configure_sandbox_writable lang=%s returned duplicate entry %r — skipping",
                                name, entry,
                            )
                        else:
                            seen.add(norm_key)
                            valid_pairs.append(entry)
                else:
                    log.warning(
                        "configure_sandbox_writable lang=%s returned invalid entry %r "
                        "(expected (Path, Path) tuple) — skipping entry",
                        name, entry,
                    )
            if valid_pairs:
                result.extend(valid_pairs)
                warn_fn = getattr(lang, "configure_sandbox_writable_warning", None)
                if callable(warn_fn):
                    try:
                        msg = warn_fn(parsed, cwd, lang_flags, targets)
                        if msg:
                            warnings.append(msg)
                    except Exception:
                        log.warning(
                            "configure_sandbox_writable_warning raised for lang=%s — skipping",
                            name,
                            exc_info=True,
                        )
    return result, warnings


def _cleanup_writable_binds(writable_binds: list[tuple[Path, Path]]) -> None:
    """Delete temp directories created by configure_sandbox_writable.

    Called in finally blocks to ensure cleanup regardless of how the run exits.
    Always resolves *src* before deletion so that a symlink returned by a plugin
    does not cause a silent leak (shutil.rmtree on a symlink removes the link
    but leaves the underlying directory intact).
    """
    for _wb_src, _ in writable_binds:
        try:
            if not os.path.lexists(_wb_src):
                continue
            if _wb_src.is_symlink() and not _wb_src.exists():
                # Dangling symlink — target was removed; unlink the stale entry.
                try:
                    _wb_src.unlink()
                except OSError:
                    pass
                continue
            try:
                resolved = _wb_src.resolve(strict=False)
            except (OSError, RuntimeError):
                log.warning(
                    "configure_sandbox_writable: could not resolve src %s, skipping cleanup",
                    _wb_src,
                )
                continue
            if _is_safe_writable_bind_src(resolved):
                shutil.rmtree(resolved, ignore_errors=True)
                if _wb_src.is_symlink() and _wb_src != resolved:
                    try:
                        _wb_src.unlink()
                    except OSError:
                        pass
            else:
                log.warning(
                    "configure_sandbox_writable: refusing to delete src %s — "
                    "failed safety checks (must be a pa- prefixed directory under tempdir)",
                    _wb_src,
                )
        except OSError:
            log.warning(
                "configure_sandbox_writable: unexpected OSError during cleanup of %s, skipping",
                _wb_src,
                exc_info=True,
            )


_PA_WRITABLE_BIND_PREFIX = "pa-"


def _is_safe_writable_bind_src(src: Path) -> bool:
    """Return True if *src* resolves to a directory that is safe to delete.

    Three guards must all pass:
    1. *src* resolves to a path strictly under the system temp directory.
    2. The resolved path's final component starts with ``pa-`` — the prefix
       used by all package-alert mkdtemp calls — so that arbitrary paths under
       /tmp created by other processes are never eligible for deletion.
    3. The resolved path is a directory (``resolved.is_dir()``).

    Note: *src* itself may be a symlink.  ``_cleanup_writable_binds`` always
    resolves *src* before calling ``shutil.rmtree`` so that the underlying
    directory is deleted rather than just the symlink.
    """
    try:
        resolved = src.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    try:
        tmp_root = Path(tempfile.gettempdir()).resolve()
    except (OSError, RuntimeError):
        return False
    if resolved == tmp_root or not resolved.is_relative_to(tmp_root):
        return False
    if not resolved.name.startswith(_PA_WRITABLE_BIND_PREFIX):
        return False
    return resolved.is_dir()


def _is_safe_writable_bind_dest(dest: Path, cwd: Path | None = None) -> bool:
    """Return True if *dest* is an acceptable writable-bind mount point.

    Writable binds overlay the sandbox's home tmpfs with credential or config
    directories.  To prevent plugins from punching writable holes into the
    read-only system filesystem or into arbitrary project paths, *dest* must:

    1. Be an absolute path.
    2. Resolve to a path strictly under the user's home directory — the only
       area where writable overlays are meaningful given the sandbox layout.
    3. Not be, be under, or be an ancestor of any entry in ``credential_dirs()``
       — overlaying a credential directory writably would re-expose secrets the
       sandbox deliberately hides.  Ancestor rejection (e.g. ``~/.config``)
       prevents writable overlays that would include a credential dir as a
       subdirectory.
    4. Not be, be under, or be an ancestor of *cwd* (the project directory) —
       writable_binds are applied after write_dirs in the bwrap command, so a
       plugin that targets the project tree could shadow it with a temp-dir
       overlay, bypassing lockfile scanning or restore on the host.

    Paths pointing to ``/``, ``/etc``, ``/usr``, the project directory,
    anywhere outside ``$HOME``, or any known credential directory are rejected.
    """
    if not dest.is_absolute():
        return False
    try:
        resolved = dest.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    home = Path.home().resolve()
    if resolved == home or not resolved.is_relative_to(home):
        return False
    for cred in credential_dirs():
        try:
            cred_resolved = cred.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if (
            resolved == cred_resolved
            or resolved.is_relative_to(cred_resolved)
            or cred_resolved.is_relative_to(resolved)
        ):
            return False
    if cwd is not None:
        try:
            cwd_resolved = cwd.resolve(strict=False)
        except (OSError, RuntimeError):
            cwd_resolved = None
        if cwd_resolved is not None and (
            resolved == cwd_resolved
            or resolved.is_relative_to(cwd_resolved)
            or cwd_resolved.is_relative_to(resolved)
        ):
            return False
    return True


def _is_safe_sandbox_path(p: Path, editable_roots: list[Path] | None = None) -> bool:
    """Return True if p is safe to bind into the sandbox as a writable or ro mount.

    Rejects the filesystem root, system directories, and credential directories
    inside $HOME that the sandbox deliberately hides. Callers log a warning and
    skip the path when this returns False.

    editable_roots is required: an empty list blocks all paths (fail closed).
    When non-empty, the path must be under one of those roots.
    """
    try:
        # strict=False so non-existent paths (e.g. pre-registered absent rollback
        # targets for fresh installs) are normalised rather than raising OSError.
        resolved = p.resolve(strict=False)
    except OSError:
        return False
    if resolved == Path("/"):
        return False
    for prefix in _UNSAFE_PREFIXES:
        if resolved == prefix or resolved.is_relative_to(prefix):
            return False
    for cred in credential_dirs():
        # Reject both the credential dir itself and any ancestor of it — mounting
        # a parent (e.g. $HOME or ~/.config) would re-expose the credential dir
        # as a subdirectory, defeating the sandbox's home tmpfs isolation.
        if resolved == cred or resolved.is_relative_to(cred) or cred.is_relative_to(resolved):
            return False
    # editable_roots must be explicitly configured — no roots means no editable installs allowed.
    # Treat individual root resolution failures as non-matches (fail closed).
    if not editable_roots:
        return False
    for root in editable_roots:
        try:
            if resolved.is_relative_to(root.resolve()):
                return True
        except OSError:
            pass
    return False


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
    # Resolve symlinks before constructing the .__pa_real sibling — a layout
    # like python3 -> python (shim) has python.__pa_real, not python3.__pa_real.
    # Fall back to the unresolved path if resolve() raises (broken symlink, etc.)
    try:
        tool_resolved = Path(tool_path).resolve()
    except OSError:
        tool_resolved = Path(tool_path)
    real = tool_resolved.parent / f"{tool_resolved.name}{_PA_REAL_SUFFIX}"
    if real.exists():
        return [str(real)] + argv[1:]
    return argv


def _resolve_targets(ctx: _Context, console: Console | None = None) -> None:
    """Populate ctx.write_dirs and ctx.scan_targets from the parsed command."""
    ctx.write_dirs.append(ctx.cwd)
    if ctx.parsed is None:
        return
    lang = lang_registry.for_ecosystem(ctx.parsed.ecosystem)
    if lang is None:
        return
    resolve_fn = getattr(lang, "resolve_sandbox_targets", None)
    if callable(resolve_fn):
        try:
            result = resolve_fn(ctx.parsed, ctx.cwd)
            # Validate ALL paths returned by the language plugin before accepting
            # them — a malicious or buggy plugin could otherwise cause the runner
            # to expose credential dirs, snapshot sensitive data, or bind-mount
            # locations outside the legitimate editable roots.
            _safe_roots = [ctx.cwd, Path.home()]
            _lang_name = getattr(lang, "name", "?")
            for p in result.scan_targets:
                if _is_safe_sandbox_path(p, editable_roots=_safe_roots):
                    ctx.scan_targets.append(p)
                else:
                    log.warning(
                        "_resolve_targets: dropping unsafe scan_target %r from lang=%s",
                        str(p), _lang_name,
                    )
                    if console is not None:
                        console.print(
                            f"⚠ Unsafe scan path blocked: {p}",
                            style="bold yellow", markup=False,
                        )
            for p in result.write_dirs:
                if _is_safe_sandbox_path(p, editable_roots=_safe_roots):
                    ctx.write_dirs.append(p)
                else:
                    log.warning(
                        "_resolve_targets: dropping unsafe write_dir %r from lang=%s",
                        str(p), _lang_name,
                    )
                    if console is not None:
                        console.print(
                            f"⚠ Unsafe write path blocked: {p}",
                            style="bold yellow", markup=False,
                        )
            for p in getattr(result, "snapshot_only_dirs", []):
                if _is_safe_sandbox_path(p, editable_roots=_safe_roots):
                    ctx.snapshot_only_dirs.append(p)
                else:
                    log.warning(
                        "_resolve_targets: dropping unsafe snapshot_only_dir %r from lang=%s",
                        str(p), _lang_name,
                    )
                    if console is not None:
                        console.print(
                            f"⚠ Unsafe snapshot path blocked: {p}",
                            style="bold yellow", markup=False,
                        )
            if console is not None:
                for w in result.warnings:
                    console.print(w, style="bold yellow", markup=False)
        except Exception:
            log.warning("resolve_sandbox_targets raised for lang=%s — skipping",
                        getattr(lang, "name", "?"), exc_info=True)


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
    cwd: Path, *, allow_external_lockfiles: bool = False
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
    ``_LOCK_UNREADABLE`` unless *allow_external_lockfiles* is True, which relaxes
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
        if not allow_external_lockfiles:
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


def _restore_install_targets(
    backend: SandboxBackend,
    snapshots: dict[Path, InstallSnapshot],
    console: Console,
) -> bool:
    """Restore all install targets. Returns True if all succeeded, False if any failed."""
    ok = True
    for path, snap in snapshots.items():
        try:
            target_ok = backend.restore_install_target(path, snap, console)
            if not target_ok:
                ok = False
        except Exception:
            log.warning("Failed to restore install target: %s", path, exc_info=True)
            console.print(f"✗ Failed to restore install target: {path}", style="bold red", markup=False)
            console.print("  The install target may be partially modified — inspect and clean up manually.", style="yellow")
            ok = False
    return ok


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
    # package manager — allow_external_lockfiles does not apply.
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
                        fd = -1  # fdopen takes ownership; don't close twice
                        fobj.write(content)
                    tmp.rename(path)
                    restored.append(path.name)
                except Exception:
                    if fd != -1:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    raise
                finally:
                    tmp.unlink(missing_ok=True)
        except OSError:
            log.warning("Failed to restore lock file: %s", path)
    if restored:
        console.print(f"[yellow]Restored lock file(s) to pre-install state: {', '.join(restored)}[/yellow]")






def _collect_new_packages(
    scan_targets: list[Path],
    snapshots: dict[Path, InstallSnapshot],
    ecosystem: str | None,
) -> list[tuple[str, str, str | None]]:
    """Return (ecosystem, name, version) tuples for packages that appeared since the snapshot."""
    new: list[tuple[str, str, str | None]] = []
    for target in scan_targets:
        snap = snapshots.get(target)
        before: set[Path] = snap.path_set() if snap is not None else set()
        # For symlink-root targets the snapshot walked the real directory, so
        # the before set uses real-dir paths. Walk the same real directory for
        # the after set so both sets are in the same namespace.
        walk_root = snap.scan_root(target) if snap is not None else target
        if not walk_root.exists():
            if snap is not None and snap.existed:
                # Exception: a broken symlink pre-run (root_symlink set, target absent)
                # legitimately produces a missing walk_root. If the install didn't create
                # the target either, this is a no-op — nothing was installed.
                was_broken_symlink = (
                    getattr(snap, "root_symlink", None) is not None
                    and not getattr(snap, "root_symlink_target_existed", True)
                )
                if not was_broken_symlink:
                    raise SandboxScanError(
                        f"Post-run scan target is missing after the install: {walk_root}\n"
                        "Cannot safely scan for new packages — treating as scan failure."
                    )
            continue
        # Guard: os.walk follows a symlink at the root even with followlinks=False.
        # If a sandboxed install replaced walk_root with a symlink, we would
        # traverse an attacker-controlled location. Refuse to walk symlink roots.
        if walk_root.is_symlink():
            raise SandboxScanError(
                f"Post-run scan target was replaced by a symlink during the install: {walk_root}\n"
                f"Cannot safely scan for new packages — treating as scan failure."
            )
        if not walk_root.is_dir():
            # A non-directory entry (file, FIFO, socket, etc.) at the scan root
            # causes os.walk() to yield nothing, silently bypassing detection.
            raise SandboxScanError(
                f"Post-run scan target is not a directory: {walk_root}\n"
                "Cannot safely scan for new packages — treating as scan failure."
            )
        # Use os.walk(followlinks=False) to match the snapshot's behaviour —
        # rglob() follows symlinks, which would cause false-positive new-package
        # detections for paths under symlinked subdirectories that the snapshot
        # intentionally skipped.
        after: set[Path] = set()

        def _scan_onerror(err: OSError) -> None:
            raise SandboxScanError(
                f"Post-run scan of {walk_root} failed: {err}\n"
                "Cannot safely detect new packages — treating as scan failure."
            )

        for dirpath, dirnames, filenames in os.walk(walk_root, followlinks=False, onerror=_scan_onerror):
            dp = Path(dirpath)
            for name in dirnames:
                after.add(dp / name)
            for name in filenames:
                after.add(dp / name)
        new_paths = after - before
        langs = (
            [lang_registry.for_ecosystem(ecosystem)]
            if ecosystem is not None
            else list(lang_registry.all_languages())
        )
        for lang in langs:
            if lang is None:
                continue
            detect_fn = getattr(lang, "detect_new_packages", None)
            if callable(detect_fn):
                try:
                    pkg_specs = detect_fn(new_paths, walk_root)
                    for ps in pkg_specs:
                        new.append((ps.ecosystem, ps.name, ps.version))
                except Exception:
                    log.warning("detect_new_packages raised for lang=%s — skipping",
                                getattr(lang, "name", "?"), exc_info=True)
    # Deduplicate preserving order
    seen: set[tuple[str, str, str | None]] = set()
    result = []
    for pkg in new:
        if pkg not in seen:
            seen.add(pkg)
            result.append(pkg)
    return result


