from __future__ import annotations

import contextlib
import enum
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from dataclasses import replace as dataclass_replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console

from packagealert.languages import registry as lang_registry
from packagealert.languages.base import (
    PackageSpec,
    SandboxEnvError,
    SandboxScanError,
    SandboxTargets,
)
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


class _GateResourcesUnavailable(enum.Enum):
    """Sentinel: gate resources could not be opened, so both gates must skip.

    Distinct from None, which on the gates' `res` parameter means "not supplied —
    open your own". Conflating the two made a locked DB be retried by every gate
    in turn: three connection attempts per run, each able to burn SQLite's lock
    timeout, for a subsystem that is purely advisory.

    A single-member Enum rather than a plain sentinel class so that
    ``res is GATE_RESOURCES_UNAVAILABLE`` narrows the union for a type checker. With
    an ordinary instance the guard is opaque, and every subsequent ``res.engine`` /
    ``res.db`` access reported an attribute error on the sentinel type — noise that
    hides real findings in the same file.
    """

    TOKEN = "GATE_RESOURCES_UNAVAILABLE"

    def __repr__(self) -> str:  # pragma: no cover — debugging aid
        return "GATE_RESOURCES_UNAVAILABLE"


GATE_RESOURCES_UNAVAILABLE = _GateResourcesUnavailable.TOKEN


@dataclass
class _GateResources:
    """State shared by the risk gate and the cooldown gate for one run.

    Both gates iterate the same package list and need the same DB connection,
    top-packages corpus, risk engine and typosquat detector. `detector` is the
    engine's own instance, and it memoises internally, so the O(corpus) typosquat
    scan runs once per distinct package name across both gates and the engine.
    """

    db: Any
    # engine/detector/pop_client are None when risk scoring is disabled: the
    # cooldown gate needs only `db`, so the engine and its httpx client are not
    # constructed at all in that case.
    engine: Any | None
    detector: Any | None
    pop_client: Any | None


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
            _lang_name = getattr(lang, "name", "?")
            try:
                pre_check_fn = getattr(lang, "pre_run_check", None)
                if not callable(pre_check_fn):
                    return 0
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

        # Both gates iterate the same package list and need the same DB, corpus,
        # engine and detector, so construct that state once and share it — but only
        # when a gate will actually use it. Constructing unconditionally would open
        # a DB connection and an httpx client for runs that skip both gates
        # entirely (no explicit packages, e.g. `pip install -r`), letting resource
        # initialisation fail an install that risk scoring does not even apply to.
        #
        # Never pass None here: on a gate's `res` parameter that means "not
        # supplied, open your own", so a failed or skipped open would be retried
        # once per gate. GATE_RESOURCES_UNAVAILABLE says "skip" and stays skipped.
        gate_res: _GateResources | _GateResourcesUnavailable = (
            await self._open_gate_resources()
            if self._gate_resources_needed(
                ctx, allow_external_lockfiles=allow_external_lockfiles
            )
            else GATE_RESOURCES_UNAVAILABLE
        )
        try:
            # Risk gate runs before cooldown: if a package is a typosquat, the user
            # should not be asked to answer a cooldown prompt about a package they
            # are then told is a typosquat.
            risk_result = await self._risk_check(
                ctx, res=gate_res, allow_external_lockfiles=allow_external_lockfiles
            )
            if risk_result is False:
                return 1
            risk_scores: dict[tuple[str, str], int] = risk_result  # type: ignore[assignment]

            cooldown_result = await self._cooldown_check(
                ctx,
                risk_scores=risk_scores,
                res=gate_res,
                allow_external_lockfiles=allow_external_lockfiles,
            )
            if cooldown_result is False:
                return 1
        finally:
            await self._close_gate_resources(gate_res)
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
            except Exception as exc:  # noqa: BLE001 — filesystem snapshot failure, abort with clear message
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
                except Exception as exc:  # noqa: BLE001 — filesystem snapshot failure, abort with clear message
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
                try:
                    prepare_env_fn = getattr(lang, "prepare_sandbox_env", None)
                except Exception:
                    log.warning("prepare_sandbox_env lookup raised for lang=%s — skipping",
                                getattr(lang, "name", "?"), exc_info=True)
                    prepare_env_fn = None
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
                                except Exception as exc:  # noqa: BLE001 — filesystem snapshot failure, abort with clear message
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
                _primary_lang_name = getattr(lang_for_cs, "name", None)
                try:
                    configure_fn = getattr(lang_for_cs, "configure_sandbox", None)
                    if callable(configure_fn):
                        lang_flags_cs = flags.get(_primary_lang_name or "", frozenset())
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
            try:
                _configure_fn = getattr(_lang, "configure_sandbox", None)
                if callable(_configure_fn):
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
                    try:
                        prepare_fn = getattr(lang, "prepare_sandbox_argv", None)
                        if callable(prepare_fn):
                            argv = prepare_fn(argv, cwd)
                    except Exception:
                        log.warning("prepare_sandbox_argv raised for lang=%s — using original argv", lang_name, exc_info=True)
                    editable_roots = self._cfg.sandbox.editable_roots
                    try:
                        extra_ro_fn = getattr(lang, "sandbox_extra_ro_paths", None)
                        if callable(extra_ro_fn):
                            for p in extra_ro_fn(argv, cwd):
                                if _is_safe_sandbox_path(p, editable_roots):
                                    home_ro.append(p.resolve())
                                else:
                                    log.warning("sandbox_extra_ro_paths: rejecting path %s from lang=%s", p, lang_name)
                                    self._print_editable_rejection(p, editable_roots)
                    except Exception:
                        log.warning("sandbox_extra_ro_paths raised for lang=%s — skipping", lang_name, exc_info=True)
                    try:
                        extra_write_fn = getattr(lang, "sandbox_extra_write_paths", None)
                        if callable(extra_write_fn):
                            for p in extra_write_fn(argv, cwd):
                                if _is_safe_sandbox_path(p, editable_roots):
                                    ctx.write_dirs.append(p.resolve())
                                else:
                                    log.warning("sandbox_extra_write_paths: rejecting path %s from lang=%s", p, lang_name)
                                    self._print_editable_rejection(p, editable_roots)
                    except Exception:
                        log.warning("sandbox_extra_write_paths raised for lang=%s — skipping", lang_name, exc_info=True)
            result = subprocess.run(build_cmd(  # noqa: ASYNC221 — single-shot CLI command, this blocking call is the program's main work
                argv, ctx.write_dirs,
                allow_network=allow_network,
                env=sandbox_env,
                home_ro_dirs=home_ro,
                extra_tmpfs=extra_tmpfs,
                post_ro_tmpfs=_post_ro_tmpfs_dirs(home_ro),
                writable_binds=_writable_binds,
            ), check=False)
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
        if not no_change and not scan_ok:
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
                try:
                    post_run_fn = getattr(lang, "post_run_scan_targets", None)
                    targets = post_run_fn(parsed, cwd) if callable(post_run_fn) else []
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

    def _gate_resources_needed(
        self, ctx: _Context, *, allow_external_lockfiles: bool = False
    ) -> bool:
        """True when either pre-flight gate will actually inspect a package.

        Both gates need a non-empty package set, and the risk gate additionally
        needs to be enabled. Checking this *before* _open_gate_resources() keeps a
        disabled or inapplicable run free of a DB connection and an httpx client:
        wasted work at best, and an installation that risk scoring does not even
        apply to must never fail during resource initialisation.

        The package set comes from `_resolve_query_packages`, not bare
        `ctx.parsed.packages`: `pip install -r requirements.txt` and a bare
        `npm install` both have `packages == []` but do have packages to
        gate. `npm uninstall` has the identical empty shape but correctly
        resolves to no packages — see `_resolve_query_packages`'s and
        `ParsedInstall.is_lockfile_install`'s docstrings.

        Note the cooldown gate has no `enabled` flag of its own, so resources are
        still required when only risk scoring is disabled.
        """
        # The cooldown gate has no enable flag, so a non-empty package set is
        # currently both necessary and sufficient. Should cooldown gain one, this
        # becomes `risk_enabled or cooldown_enabled`.
        if ctx.parsed is None:
            return False
        queries, _blocked_reason, _source = self._resolve_query_packages(
            ctx, allow_external_lockfiles=allow_external_lockfiles
        )
        return bool(queries)

    async def _open_gate_resources(self) -> _GateResources | _GateResourcesUnavailable:
        """Open the DB, engine, detector and typosquat cache shared by both gates.

        The risk gate and the cooldown gate run back-to-back over the same package
        list and need overlapping state: one DB connection, one TopPackagesCache
        (and therefore one top-packages fetch), one RiskEngine, and one
        TyposquatDetector. Constructing them once here — rather than per gate —
        also means the O(corpus) typosquat scan runs once per package instead of
        three times, since the detector memoises across both gates and the engine.

        Scaled to what is actually needed. The cooldown gate requires only the DB
        (for publication dates and clearances) plus a TyposquatDetector for its
        risk_score fallback — never the RiskEngine or its httpx PopularityClient.
        Disabling `sandbox.preflight_risk.enabled` (the pre-flight *gate*) must not
        also disable that fallback: it previously routed through the same flag as
        engine construction, so turning off pre-flight scoring alone forced
        `_typo_for` to return None, which zeroed cooldown's risk_score and could
        silently downgrade `on_new_medium_risk` ("prompt") to `on_new_low_risk`
        ("warn") for a real typosquat — weakening a gate the user never touched.
        `heuristics.enabled` is still the one flag that disables everything,
        including this fallback, since it is the global kill switch for
        heuristic-derived signals.

        Risk construction failures degrade rather than propagate: building the
        engine touches third-party plugin entry points (the popularity ecosystem
        map) and opens an httpx client, none of which should be able to abort an
        install. On failure the returned resources carry the DB alone, so the
        cooldown gate still runs and the risk gate reports no scores. Any client
        created before the failure is carried out for _close_gate_resources() to
        release, so a partial build cannot leak a socket.

        Returns GATE_RESOURCES_UNAVAILABLE when even the DB cannot be opened
        (read-only filesystem, SQLite lock timeout). Neither gate is load-bearing
        for the install itself, so both are skipped in that case rather than
        aborting the run — and the sentinel, rather than None, is what makes
        "skipped" stick: None on a gate's `res` parameter means "not supplied",
        which would have each gate retry the failing open in turn.

        The caller owns the lifecycle and must call _close_gate_resources().
        """
        try:
            db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))
        except Exception:
            log.warning(
                "Could not open the database — skipping risk and cooldown checks "
                "for this run", exc_info=True,
            )
            return GATE_RESOURCES_UNAVAILABLE
        if not self._cfg.heuristics.enabled:
            return _GateResources(db=db, engine=None, detector=None, pop_client=None)
        if not self._cfg.sandbox.preflight_risk.enabled:
            # The pre-flight gate is off, but cooldown's risk_score fallback still
            # needs a detector. Built directly rather than via _build_risk_engine, so
            # disabling the gate does not also construct the RiskEngine or its httpx
            # PopularityClient that only the gate needed.
            detector = await self._build_typosquat_detector(db)
            return _GateResources(db=db, engine=None, detector=detector, pop_client=None)
        try:
            engine, detector, pop_client = await self._build_risk_engine(db)
        except Exception:
            log.warning(
                "Could not construct the risk engine — continuing without risk "
                "scoring (cooldown checks still apply)", exc_info=True,
            )
            # _build_risk_engine closes its own PopularityClient before re-raising,
            # so nothing is left to release here beyond the DB the caller owns. Still
            # try for a bare detector so cooldown's fallback survives this failure too.
            detector = await self._build_typosquat_detector(db)
            return _GateResources(db=db, engine=None, detector=detector, pop_client=None)
        return _GateResources(db=db, engine=engine, detector=detector, pop_client=pop_client)

    async def _build_typosquat_detector(self, db: Any) -> Any | None:
        """Build a bare TyposquatDetector, with no RiskEngine or httpx client.

        Used when the pre-flight risk gate is off (or failed to construct) but
        cooldown still needs its risk_score fallback. Returns None on failure —
        cooldown's own fail-open in `_typo_for` already tolerates that.
        """
        try:
            from packagealert.heuristics.top_packages import TopPackagesCache
            from packagealert.heuristics.typosquat import TyposquatDetector

            top_cache = TopPackagesCache(db=db, cfg=self._cfg.heuristics)
            return TyposquatDetector(top_cache)
        except Exception:
            log.warning(
                "Could not construct a typosquat detector for cooldown's fallback "
                "score — cooldown will classify on age alone", exc_info=True,
            )
            return None

    async def _close_gate_resources(
        self, res: _GateResources | _GateResourcesUnavailable | None
    ) -> None:
        """Release shared gate resources. Safe to call once, in a finally block.

        Tolerates None and GATE_RESOURCES_UNAVAILABLE (nothing was opened in
        either case) and never raises: a teardown fault must not fail an install
        that has otherwise succeeded.
        """
        if res is None or res is GATE_RESOURCES_UNAVAILABLE:
            return
        try:
            if res.pop_client is not None:
                await res.pop_client.aclose()
        except Exception:
            log.warning("Closing the popularity client failed", exc_info=True)
        finally:
            with contextlib.suppress(Exception):
                await res.db.close()

    async def _typo_for(self, res: _GateResources, name: str, ecosystem: str) -> Any | None:
        """Typosquat-analyse *name* via the shared detector.

        The detector memoises internally, so repeat calls across the risk gate,
        the cooldown gate and RiskEngine.analyze() cost nothing. Returns None if
        the analysis failed, or if risk scoring is disabled and no detector was
        built — callers fail open rather than blocking an install because the
        corpus was unavailable.
        """
        if res.detector is None:
            return None
        try:
            return await res.detector.analyze(name, ecosystem)
        except Exception:
            log.warning("Typosquat check failed for %s — skipping", name, exc_info=True)
            return None

    async def _build_risk_engine(self, db: Any) -> tuple[Any, Any, Any]:
        """Construct a fully-wired RiskEngine sharing *db*.

        Mirrors the daemon's construction (daemon.py) so scores produced here are
        comparable with daemon scores. Returns (engine, detector, pop_client);
        the caller owns closing pop_client.

        If construction fails after the httpx PopularityClient exists, that client
        is closed here before re-raising — this function owns the ordering, so it
        owns the cleanup rather than leaving callers to guess what was built.
        """
        from packagealert.analyzers.risk import RiskEngine
        from packagealert.heuristics.top_packages import TopPackagesCache
        from packagealert.heuristics.typosquat import TyposquatDetector
        from packagealert.osv.popularity import PopularityCache, PopularityClient

        pop_client = PopularityClient(lang_registry.popularity_ecosystem_map())
        try:
            top_cache = TopPackagesCache(db=db, cfg=self._cfg.heuristics)
            engine = RiskEngine(
                self._cfg.heuristics,
                pop_client=pop_client,
                pop_cache=PopularityCache(db),
                top_packages_cache=top_cache,
                db=db,
                cooldown_period_days=self._cfg.sandbox.cooldown.period_days,
            )
        except Exception:
            with contextlib.suppress(Exception):
                await pop_client.aclose()
            raise
        # Reuse the engine's own detector rather than building a second one.
        # RiskEngine constructs a TyposquatDetector internally and calls it during
        # analyze(); a separate runner-level instance would run the O(corpus) scan
        # a second time for every package, which no amount of caching here can
        # deduplicate. getattr keeps this tolerant of the attribute being renamed.
        detector = getattr(engine, "_typosquat", None) or TyposquatDetector(top_cache)
        return engine, detector, pop_client

    async def _risk_check(
        self,
        ctx: _Context,
        *,
        res: _GateResources | _GateResourcesUnavailable | None = None,
        allow_external_lockfiles: bool = False,
    ) -> dict[tuple[str, str], int] | bool:
        """Evaluate typosquat + composite risk score for the packages about to be
        installed. Return False to block, else a (ecosystem, name) -> score map
        for _cooldown_check to reuse.

        Deliberately independent of _cooldown_check's skip conditions: a typosquat
        match is a function of the package name alone, so it must still be reported
        when the ecosystem has no publication-date endpoint or when an unpinned
        version cannot be resolved.

        The package set comes from `_resolve_query_packages`, matching the OSV
        pre-flight check's coverage: explicit CLI packages, `-r`/`--requirement`
        files, and bare package-manager lock-file installs (e.g. `npm install`
        with no explicit names) all contribute — not just `ctx.parsed.packages`,
        which is empty for the latter two and previously skipped this gate
        entirely despite the OSV pre-flight already covering the same install.

        *res* carries state shared with the cooldown gate. When omitted the method
        opens and closes its own, so it remains independently callable.
        """
        from packagealert.sandbox.preflight_risk import decide_risk
        from packagealert.scoring import score_packages

        cfg = self._cfg.sandbox.preflight_risk
        if not cfg.enabled or not self._cfg.heuristics.enabled:
            return {}
        if ctx.parsed is None:
            return {}
        queries, blocked_reason, _source = self._resolve_query_packages(
            ctx, allow_external_lockfiles=allow_external_lockfiles
        )
        if blocked_reason is not None:
            self._console.print(
                f"✗ Lock file {blocked_reason} resolves outside the project directory "
                f"— refusing risk scan. Pass --allow-external-lockfiles to override.",
                style="bold red",
                markup=False,
            )
            return False
        if not queries:
            return {}

        is_tty = sys.stdin.isatty()
        if res is GATE_RESOURCES_UNAVAILABLE:
            # Already known unavailable — do not retry the failing open.
            return {}
        owned = res is None
        if res is None:
            res = await self._open_gate_resources()
        if res is GATE_RESOURCES_UNAVAILABLE:
            # No DB: risk scoring is unavailable. Fail open.
            return {}
        engine = res.engine
        if engine is None:
            # Engine construction failed earlier; cooldown still runs, we do not.
            # Release anything this call opened before bailing.
            if owned:
                await self._close_gate_resources(res)
            return {}

        scores: dict[tuple[str, str], int] = {}
        blocked: list = []
        warned: list = []
        # Once any package is blocked, the whole check returns False regardless
        # of a later "prompt" decision's answer — skip the pointless Confirm.ask
        # once that outcome is already fixed, matching _cooldown_check.
        already_blocked = False

        try:
            # Scored concurrently (bounded by score_packages' own semaphore) rather
            # than one engine.analyze() await per package in sequence: each call can
            # hit deps.dev on a popularity-cache miss and read publication-date rows,
            # entirely independent work across packages that a sequential loop would
            # otherwise serialise. _risk_check_lockfiles already scores this way for
            # the same reason; this mirrors it rather than looping _score_one.
            keys = [(raw_ecosystem.lower(), name, version) for raw_ecosystem, name, version in queries]
            outcome = await score_packages(engine, keys)

            # Iterate in first-seen query order, not outcome.reports' dict
            # order: score_packages scores concurrently and inserts each
            # report as its own task completes (see scoring.py's `one()`),
            # so dict order is task-completion order — unrelated to, and
            # nondeterministic relative to, the order packages were listed
            # in. The already_blocked short-circuit below depends on a
            # stable, meaningful order: iterating completion order could see
            # a "prompt" decision before an earlier-listed package's "block"
            # simply because its network call happened to finish first,
            # making the short-circuit's effect a timing accident rather
            # than a property of the package list.
            #
            # dict.fromkeys(keys), not the raw keys list: score_packages
            # dedupes internally (its own _dedupe_keys), so a package repeated
            # on the CLI or across requirement files has exactly one entry in
            # outcome.reports. Iterating the raw (non-deduped) keys list would
            # process — and for a "prompt" decision, interactively re-ask
            # about — the same package once per repetition.
            for ecosystem, name, version in dict.fromkeys(keys):
                report = outcome.reports.get((ecosystem, name, version))
                if report is None:
                    continue
                pkg = PackageSpec(name=name, version=version, ecosystem=ecosystem)

                # Fail open on any scoring failure: a risk check must never block
                # an install because the network or the corpus was unavailable.
                typo = await self._typo_for(res, name, ecosystem)
                if typo is None:
                    continue

                scores[(ecosystem, name.lower())] = report.score

                decision = decide_risk(
                    pkg, report=report, typo=_reconcile_typo(typo, report), cfg=cfg, is_tty=is_tty
                )

                if decision.action == "block":
                    blocked.append(decision)
                    already_blocked = True
                elif decision.action == "warn":
                    warned.append(decision)
                elif decision.action == "prompt":
                    if already_blocked:
                        # Nothing this prompt could answer would change the
                        # outcome — an earlier package already forces a block.
                        blocked.append(decision)
                        continue
                    from rich.prompt import Confirm
                    self._console.print(
                        f"  {_spec_label(pkg)}: {decision.reason}", style="yellow", markup=False
                    )
                    if not Confirm.ask("Install anyway?", default=False):
                        blocked.append(decision)
                        already_blocked = True
        finally:
            if owned:
                await self._close_gate_resources(res)

        for d in warned:
            self._console.print(
                f"  ⚠ {_spec_label(d.package)}: {d.reason}", style="yellow", markup=False
            )

        if blocked:
            for d in blocked:
                self._console.print(
                    f"✗ {_spec_label(d.package)}: {d.reason}", style="red", markup=False
                )
            # markup=False: the config path contains brackets Rich would eat.
            self._console.print(
                "  Risk gating is configured in [sandbox.preflight_risk].",
                style="dim",
                markup=False,
            )
            return False

        return scores

    async def _risk_check_lockfiles(
        self, cwd: Path, *, allow_external_lockfiles: bool = False
    ) -> bool:
        """Risk-gate a project's lock-file package set. Return False to block.

        Used by the shell path, which has no explicit package list. The gate
        decision is the highest-ranked action across all scored packages, so a
        sandboxed interactive shell gets the same protection as a direct install.

        Lock file containment is enforced before anything is read. scan_project()
        follows symlinks unconditionally, and this path additionally sends every
        package name to deps.dev, so an unchecked external symlink would both read
        and exfiltrate a file outside the project.

        Reporting suppresses low-signal rows the same way scan-project does;
        suppression never affects enforcement, because a suppressed row cannot
        have reached risk_threshold in the first place.

        False positives here are handled by scoring, not by declining to enforce:
        RiskEngine reduces the typosquat score for packages with established
        adoption of their own, so an ordinary lock file of legitimate libraries
        resolves to warn (httpx2 scores 3, respx 14 — both below
        typosquat_min_score) and the shell starts.
        """
        from packagealert.parsers import lockfiles
        from packagealert.sandbox.preflight_risk import ACTION_RANK, decide_risk, worst
        from packagealert.scoring import score_packages

        cfg = self._cfg.sandbox.preflight_risk
        if not cfg.enabled or not self._cfg.heuristics.enabled:
            return True

        # Containment first: scan_project() below follows symlinks unconditionally,
        # and the scoring pass sends package names to deps.dev. Both must be gated
        # on the lock files actually belonging to this project.
        if not allow_external_lockfiles:
            offender = _assert_scannable_lock_files_contained(cwd)
            if offender is not None:
                self._console.print(
                    f"✗ Lock file {offender} resolves outside the project directory "
                    f"— refusing risk scan. Pass --allow-external-lockfiles to override.",
                    style="bold red",
                    markup=False,
                )
                log.warning(
                    "Lock file resolves outside project root, refusing risk scan: %s",
                    cwd / offender,
                )
                return False

        try:
            result = lockfiles.scan_project(cwd)
        except Exception:
            log.warning("Lock-file scan failed for risk check — skipping", exc_info=True)
            return True
        if not result.pinned:
            return True

        is_tty = sys.stdin.isatty()
        res = await self._open_gate_resources()
        if res is GATE_RESOURCES_UNAVAILABLE or res.engine is None:
            # No DB or no engine: nothing to score. Let the shell start.
            await self._close_gate_resources(res)
            return True

        decisions: list = []
        try:
            keys = [(p.ecosystem.lower(), p.name, p.version) for p in result.pinned]
            outcome = await score_packages(res.engine, keys)

            for (ecosystem, name, version), report in outcome.reports.items():
                typo = await self._typo_for(res, name, ecosystem)
                if typo is None:
                    continue
                decisions.append(
                    decide_risk(
                        PackageSpec(name=name, version=version, ecosystem=ecosystem),
                        report=report,
                        # Judge the engine-reduced score, as _risk_check does —
                        # the detector's raw score ignores adoption evidence.
                        typo=_reconcile_typo(typo, report),
                        cfg=cfg,
                        is_tty=is_tty,
                    )
                )
        finally:
            await self._close_gate_resources(res)

        flagged = [d for d in decisions if d.action != "allow"]
        if not flagged:
            return True

        # Highest-severity findings first, and the worst of them governs the gate.
        flagged.sort(key=lambda d: -ACTION_RANK[d.action])
        top = worst(flagged)
        assert top is not None  # flagged is non-empty

        blocking = top.action == "block"
        header_style = "bold red" if blocking else "yellow"
        marker = "✗" if blocking else "⚠"
        self._console.print(
            f"{marker} Risk signals in {len(flagged)} lock file dependenc"
            f"{'y' if len(flagged) == 1 else 'ies'}:",
            style=header_style,
            markup=False,
        )
        for d in flagged:
            self._console.print(
                f"  {_spec_label(d.package)}: {d.reason}",
                style="red" if d.action == "block" else "yellow",
                markup=False,
            )
        self._console.print(
            "  Run 'package-alert scan-project' for the full breakdown.",
            style="dim",
            markup=False,
        )

        if blocking:
            # markup=False: the config path contains brackets Rich would eat.
            self._console.print(
                "  Risk gating is configured in [sandbox.preflight_risk].",
                style="dim",
                markup=False,
            )
            return False
        if top.action == "prompt":
            from rich.prompt import Confirm
            return bool(Confirm.ask("Enter sandbox anyway?", default=False))
        return True

    async def _cooldown_check(
        self,
        ctx: _Context,
        *,
        risk_scores: dict[tuple[str, str], int] | None = None,
        res: _GateResources | _GateResourcesUnavailable | None = None,
        allow_external_lockfiles: bool = False,
    ) -> list[tuple[str, str, str]] | bool:
        """Check cooldown policy. Returns False if blocked, or a list of
        (ecosystem, name, version) tuples for packages the user confirmed at the
        prompt — to be written to cooldown_cleared after a successful install.
        An empty list means allowed with no prompts.

        *risk_scores* maps (ecosystem, lowercased name) to the composite
        RiskEngine score computed by _risk_check. When absent, the typosquat
        score is used instead, preserving the pre-risk-gate behaviour.

        The package set comes from `_resolve_query_packages`, the same as
        `_risk_check` — see that method's docstring for why bare
        `ctx.parsed.packages` under-covers `-r`/lock-file installs.

        *res* carries state shared with the risk gate — including memoised
        typosquat results, so the corpus scan is not repeated. When omitted the
        method opens and closes its own, so it remains independently callable."""
        import time as _time

        from packagealert.sandbox.cooldown import (
            decide_with_cleared,
            fetch_latest_version,
            fetch_publication_date,
        )

        if ctx.parsed is None:
            return []
        queries, blocked_reason, _source = self._resolve_query_packages(
            ctx, allow_external_lockfiles=allow_external_lockfiles
        )
        if blocked_reason is not None:
            self._console.print(
                f"✗ Lock file {blocked_reason} resolves outside the project directory "
                f"— refusing cooldown scan. Pass --allow-external-lockfiles to override.",
                style="bold red",
                markup=False,
            )
            return False
        if not queries:
            return []

        cfg = self._cfg.sandbox.cooldown
        is_tty = sys.stdin.isatty()
        if res is GATE_RESOURCES_UNAVAILABLE:
            # Already known unavailable — do not retry the failing open.
            return []
        owned = res is None
        if res is None:
            res = await self._open_gate_resources()
        if res is GATE_RESOURCES_UNAVAILABLE:
            # No DB means no publication dates and no clearances to consult.
            # Fail open rather than blocking on missing information.
            log.warning("Cooldown checks skipped: no database available")
            return []
        db = res.db

        from packagealert.languages.base import PackageSpec

        blocked: list = []
        pending_clears: list[tuple[str, str, str]] = []
        warned: list = []
        # Once any package is blocked, the whole check returns False regardless
        # of what happens to any later "prompt" decision — its answer can never
        # change the outcome. Publication-date/typosquat lookups still run for
        # every remaining package, so the user sees every blocking reason in one
        # pass, but the interactive Confirm.ask is skipped as pointless.
        already_blocked = False

        try:
            for raw_ecosystem, name, version in queries:
                ecosystem = raw_ecosystem.lower()
                if not version:
                    lang_for_latest = lang_registry.for_ecosystem(ecosystem)
                    if lang_for_latest is not None:
                        try:
                            latest_url_fn = getattr(lang_for_latest, "latest_version_url", None)
                            latest_url = latest_url_fn(name) if callable(latest_url_fn) else None
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

                # Reuses the risk gate's memoised result when the caller shared
                # resources, so the O(corpus) scan runs once per package. None when
                # risk scoring is disabled or the corpus was unavailable — cooldown
                # is an age policy and must still run without it, so this only
                # costs the typosquat detail in the reason string.
                typo = await self._typo_for(res, name, ecosystem)
                # Prefer the composite RiskEngine score computed by _risk_check;
                # fall back to the typosquat score, or 0 when neither is available.
                fallback = typo.score if typo is not None else 0
                risk_score = fallback
                if risk_scores is not None:
                    risk_score = risk_scores.get((ecosystem, name.lower()), fallback)

                decision = decide_with_cleared(
                    pkg,
                    age_days=age_days,
                    risk_score=risk_score,
                    cfg=cfg,
                    is_tty=is_tty,
                    cleared_at=cleared_at,
                )

                if typo is not None and typo.is_typosquat and typo.closest_match:
                    # Omit the distance when unknown rather than showing "None".
                    _dist = (
                        f" (distance {typo.distance})" if typo.distance is not None else ""
                    )
                    decision = dataclass_replace(
                        decision,
                        reason=(
                            f"{decision.reason}; possible typosquat of "
                            f"'{typo.closest_match}'{_dist}"
                        ),
                    )

                if decision.action == "block":
                    blocked.append(decision)
                    already_blocked = True
                elif decision.action == "warn":
                    warned.append(decision)
                elif decision.action == "prompt":
                    if already_blocked:
                        # Nothing this prompt could answer would change the
                        # outcome — an earlier package already forces a block.
                        blocked.append(decision)
                        continue
                    from rich.prompt import Confirm
                    self._console.print(f"[yellow]  {pkg.name}=={pkg.version}: {decision.reason}[/yellow]")
                    if not Confirm.ask("Install anyway?", default=False):
                        blocked.append(decision)
                        already_blocked = True
                    else:
                        pending_clears.append((ecosystem, name, version))
        finally:
            if owned:
                await self._close_gate_resources(res)

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
            try:
                shell_env_fn = getattr(lang, "shell_environment", None)
                if not callable(shell_env_fn):
                    continue
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
        if not await self._risk_check_lockfiles(
            cwd, allow_external_lockfiles=allow_external_lockfiles
        ):
            return 1
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
            except Exception as exc:  # noqa: BLE001 — filesystem snapshot failure, abort with clear message
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
            try:
                configure_fn = getattr(lang, "configure_sandbox", None)
                if callable(configure_fn):
                    _sh_targets = SandboxTargets(
                        scan_targets=list(scan_targets),
                        write_dirs=list(write_dirs),
                    )
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

            result = subprocess.run(build_cmd(  # noqa: ASYNC221 — single-shot CLI command, this blocking call is the program's main work
                argv, write_dirs,
                allow_network=allow_network,
                env=sandbox_env,
                home_ro_dirs=home_ro,
                extra_tmpfs=extra_tmpfs,
                post_ro_tmpfs=_post_ro_tmpfs_dirs(home_ro),
                writable_binds=_writable_binds,
            ), check=False)
        finally:
            _cleanup_writable_binds(_writable_binds)
        print()

        # Post-exit: scan changed lock files, then any newly installed packages.
        # In --no-change mode, defer restore until after post-shell scanning so
        # new-package detection sees the actual installed state.
        scan_ok = await self._scan_updated_lock_files(cwd, lock_snapshots, allow_external_lockfiles=allow_external_lockfiles)
        if not no_change and not scan_ok:
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

    def _resolve_query_packages(
        self, ctx: _Context, *, allow_external_lockfiles: bool = False
    ) -> tuple[list[tuple[str, str, str | None]], str | None, str]:
        """Build the (ecosystem, name, version) package set for *ctx*'s install.

        Shared by the OSV pre-flight check and the risk/cooldown gates so all
        three see the same install surface. Explicit CLI packages alone
        under-covers real `pa run` usage — `pip install -r requirements.txt`
        and a bare `npm install` (installing everything from an existing
        lock file) both have `parsed.packages == []`, and previously the risk
        and cooldown gates returned early there, running no typosquat or
        high-risk scoring at all for either surface despite the OSV
        pre-flight already expanding them.

        Returns `(queries, blocked_reason, source)`. *blocked_reason*, when not
        None, means an external (symlinked-outside-the-project) lock file was
        found and the caller must block the run rather than use *queries* —
        mirrors `_preflight`'s own containment check, required because
        `scan_project` follows symlinks unconditionally. *source* is a
        human-readable description of where *queries* came from, for status
        messages; it is `""` when *queries* is empty or the run was blocked.
        """
        from packagealert.parsers.lockfiles import scan_project

        parsed = ctx.parsed
        if parsed is None:
            return [], None, ""

        if not parsed.should_gate:
            # A report-only/check-only invocation (`npm install lodash
            # --dry-run`, `uv sync --check`, ...) installs nothing no matter
            # what packages/req_files/is_lockfile_install say — see
            # ParsedInstall.should_gate's own docstring. Must be checked
            # before packages/req_files below: an explicit-package dry-run
            # still has a non-empty `packages`, which would otherwise be
            # queried and could block a command that changes nothing.
            return [], None, ""

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
                    pinned, unpinned = collect_requirements_packages(
                        req_path, visited, ctx.cwd,
                        is_system_python_target=parsed.is_system_python_target,
                    )
                    queries.extend((p.ecosystem, p.name, p.version) for p in pinned)
                    queries.extend((p.ecosystem, p.name, None) for p in unpinned)
                    file_sources.append(rf)
            added = len(queries) - before
            source_parts.append(
                f"{added} packages ({', '.join(file_sources) or 'no packages found'})"
            )

        if not parsed.packages and not parsed.req_files and parsed.is_lockfile_install:
            # Lock-file install — read the lock file for exact versions.
            # `is_lockfile_install` is required here, not inferred from empty
            # packages/req_files: a removal (`npm uninstall`, `yarn/pnpm
            # remove`) or an unrelated non-install subcommand (`pipenv
            # shell`/`check`, `uv run`/`cache`) produces the identical empty
            # ParsedInstall shape but must NOT trigger a scan of the current
            # lock file — that would gate packages the command is not
            # installing at all, and could block a legitimate removal over a
            # risk signal on the very dependency being removed. See
            # ParsedInstall.is_lockfile_install's own docstring.
            #
            # Enforce containment before scan_project() follows any symlinks.
            if not allow_external_lockfiles:
                bad = _assert_scannable_lock_files_contained(ctx.cwd)
                if bad is not None:
                    return [], bad, ""
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

        return queries, None, "; ".join(source_parts)

    async def _preflight(self, ctx: _Context, *, allow_external_lockfiles: bool = False) -> bool:
        """Query OSV for what's about to be installed. Return False to block."""
        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient
        from packagealert.storage.db import open_db

        parsed = ctx.parsed

        if parsed is None:
            self._console.print("[dim]Pre-flight: unrecognised command, skipping OSV check[/dim]")
            return True

        if not parsed.should_gate:
            # A report-only/check-only invocation (`npm install lodash
            # --dry-run`, `uv sync --check`, ...) installs nothing no matter
            # what packages/req_files/is_lockfile_install say — see
            # ParsedInstall.should_gate's own docstring. Must be checked
            # before packages/req_files below: an explicit-package dry-run
            # still has a non-empty `packages`, which would otherwise be
            # queried and could block a command that changes nothing.
            self._console.print("[dim]Pre-flight: no-op/report-only command, skipping OSV check[/dim]")
            return True

        queries, blocked_reason, source = self._resolve_query_packages(
            ctx, allow_external_lockfiles=allow_external_lockfiles
        )
        if blocked_reason is not None:
            self._console.print(
                f"[bold red]✗ Blocked — lock file '{blocked_reason}' resolves outside the project "
                f"directory. Use --allow-external-lockfiles to override.[/bold red]"
            )
            return False

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

    async def _post_scan(self, packages: list[tuple[str, str, str | None, Path]]) -> bool:
        """OSV-check newly installed packages, then risk-score them.

        *packages* carries a fourth element — the scan root the package was
        detected under — which OSV does not need but the risk pass does.
        """
        from packagealert.osv.cache import OsvCache
        from packagealert.osv.client import OsvClient
        from packagealert.storage.db import open_db

        db = await open_db(enabled_plugins=set(self._cfg.plugins.enabled))
        client = OsvClient(self._cfg.osv)
        cache = OsvCache(db, self._cfg.osv)
        malicious: list[tuple[str, str]] = []

        # OSV queries are (ecosystem, name, version) only.
        osv_queries = [(eco, name, ver) for eco, name, ver, _root in packages]

        try:
            for i in range(0, len(osv_queries), 50):
                batch = osv_queries[i : i + 50]
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

        self._console.print("[green]✓ Post-install: no known advisories[/green]")
        return await self._post_scan_risk(packages)

    async def _post_scan_risk(self, packages: list[tuple[str, str, str | None, Path]]) -> bool:
        """Score newly installed packages with full source-code signals.

        This is the only point in the run flow where an extracted package tree
        exists, so install-script / eval / embedded-binary signals can fire here
        but not at pre-flight. Returning False triggers the caller's rollback.
        """
        from packagealert.analyzers.risk import UNVERIFIABLE_MANIFEST_SIGNAL
        from packagealert.models.events import normalise_ecosystem
        from packagealert.sandbox.escalation import escalate_if_prompt
        from packagealert.scoring import score_packages

        cfg = self._cfg.sandbox.preflight_risk
        if not cfg.enabled or not self._cfg.heuristics.enabled:
            return True

        # Own resources: this runs after the install, long after the pre-flight
        # gates have released theirs.
        res = await self._open_gate_resources()
        if res is GATE_RESOURCES_UNAVAILABLE or res.engine is None:
            # Risk scoring is unavailable. The OSV post-install check has already
            # passed, so keep the install rather than rolling back a good one over
            # a scoring-setup failure.
            log.warning("Post-install risk scoring skipped: risk engine unavailable")
            await self._close_gate_resources(res)
            return True
        engine = res.engine

        flagged: list[tuple[str, str | None, int, list[str]]] = []
        try:
            # Scored concurrently via score_packages (bounded by its own semaphore)
            # rather than one engine.analyze() await per package in sequence — each
            # call can hit deps.dev on a popularity-cache miss and read
            # publication-date rows, entirely independent work across packages that
            # a sequential loop would otherwise serialise. Mirrors _risk_check and
            # _risk_check_lockfiles, which already score this way for the same
            # reason.
            #
            # *packages* can carry the same (ecosystem, name, version) more than
            # once with different scan_roots — a monorepo install can place the
            # same dependency under more than one node_modules/site-packages tree
            # in a single run — so score_packages' plain (ecosystem, name,
            # version) dedup cannot see the distinct copies on its own. The
            # resolver below groups every scan_root for a given key into its own
            # candidate group, exactly like _installed_dir_resolver in cli/app.py,
            # so score_packages scores each copy independently and keeps the
            # highest-scoring report — a compromised copy under a second scan_root
            # cannot hide behind a clean copy under the first.
            #
            # Keyed by the *canonical* ecosystem, not the raw string _try_parse
            # produced (which always lowercases — see _try_parse's own comment):
            # score_packages.one() normalises each key's ecosystem before calling
            # resolve_dirs/resolve_manifest_warning, so a plugin declaring
            # "NuGet" would otherwise be looked up here as "NuGet" against a
            # dict built with "nuget". That mismatch does not raise all the way
            # out — score_packages' own resolver wrapper catches it and quietly
            # degrades to metadata-only scoring — so every source-code signal
            # (install-script, eval, embedded-binary, unverifiable-manifest) for
            # a mixed-case plugin ecosystem went silently missing. Normalising
            # here, once, keeps this dict's keys identical to what score_packages
            # will actually look up with.
            roots_by_key: dict[tuple[str, str, str | None], list[Path]] = {}
            for raw_ecosystem, name, version, scan_root in packages:
                try:
                    ecosystem = normalise_ecosystem(raw_ecosystem)
                except ValueError:
                    ecosystem = raw_ecosystem.lower()
                roots_by_key.setdefault((ecosystem, name, version), []).append(scan_root)

            manifest_warnings: dict[tuple[str, str, str | None], str | None] = {}

            def resolve_dirs(
                ecosystem: str, name: str, version: str | None
            ) -> list[list[Path]]:
                groups: list[list[Path]] = []
                warning: str | None = None
                for scan_root in roots_by_key[(ecosystem, name, version)]:
                    # project_path is deliberately left to the scan_root.parent
                    # fallback: a post-install scan target may be a venv elsewhere
                    # or a monorepo subdirectory, so there is no single project
                    # root to pass. The fallback is correct for the Node targets
                    # that need it.
                    resolved, env_warning = _resolve_installed_dir(
                        ecosystem, name, Path.cwd(), scan_root, version=version
                    )
                    if not resolved:
                        log.debug(
                            "No package directory resolved for %s/%s under %s — "
                            "source-code signals unavailable",
                            ecosystem, name, scan_root,
                        )
                    if resolved:
                        groups.append(resolved)
                    # First non-None warning across scan_roots wins — a corrupt
                    # manifest anywhere is worth surfacing, and nothing
                    # distinguishes which scan_root's warning matters more.
                    if warning is None and env_warning:
                        warning = env_warning
                manifest_warnings[(ecosystem, name, version)] = warning
                return groups

            def resolve_manifest_warning(
                ecosystem: str, name: str, version: str | None
            ) -> str | None:
                return manifest_warnings.get((ecosystem, name, version))

            keys = list(roots_by_key.keys())
            outcome = await score_packages(
                engine, keys,
                package_dir_resolver=resolve_dirs,
                manifest_warning_resolver=resolve_manifest_warning,
            )

            for (ecosystem, name, version), report in outcome.reports.items():
                # unverifiable_manifest fires independently of the aggregate
                # threshold: it typically arrives alone at score 20 (a corrupt
                # manifest means no directories were resolved, so no other
                # source-code heuristic ran), which never reaches
                # post_install_threshold's default of 30 on its own — silently
                # keeping an install whose own manifest could not be verified,
                # despite it being exactly the kind of signal that should never
                # go unreported. Mirrors preflight_risk.decide_risk's
                # independent typosquat/high-risk gating rather than folding
                # every signal into one combined score.
                has_manifest_warning = any(
                    s.name == UNVERIFIABLE_MANIFEST_SIGNAL for s in report.signals
                )
                if report.score >= cfg.post_install_threshold or has_manifest_warning:
                    flagged.append(
                        (name, version, report.score, [s.name for s in report.signals])
                    )
        finally:
            await self._close_gate_resources(res)

        if not flagged:
            return True

        # Resolve the configured action. on_post_install_risk accepts the full
        # CooldownAction literal, so all four values must be honoured — treating
        # anything that is not "block" as "warn" would silently downgrade a
        # configured "prompt" and never escalate it in CI.
        action = cfg.on_post_install_risk
        if action == "allow":
            # A genuine no-op: report nothing and keep the install.
            return True
        # Nobody can answer in CI or under a coding agent, so fall back to the
        # configured escalation rather than hanging or silently keeping a
        # package that tripped the threshold — shared with the pre-flight
        # gate and cooldown, which apply the identical substep.
        action = escalate_if_prompt(
            action, is_tty=sys.stdin.isatty(), non_interactive_escalation=cfg.non_interactive_escalation
        )
        if action == "allow":
            return True

        blocking = action == "block"
        style = "bold red" if blocking else "bold yellow"
        marker = "✗" if blocking else "⚠"
        self._console.print(
            f"{marker} Post-install: {len(flagged)} package(s) flagged "
            f"(risk threshold {cfg.post_install_threshold}, or an unverifiable manifest):",
            style=style,
            markup=False,
        )
        for name, version, score, signals in flagged:
            label = f"{name}=={version}" if version else name
            self._console.print(
                f"  • {label}  score {score}  [{', '.join(signals)}]",
                style="red" if blocking else "yellow",
                markup=False,
            )

        if blocking:
            return False
        if action == "prompt":
            from rich.prompt import Confirm
            # The packages are already extracted; declining rolls the install back
            # through the caller's snapshot restore.
            return bool(Confirm.ask("Keep these packages installed?", default=False))
        return True


# ---------------------------------------------------------------------------
# Module-level helpers (kept outside the class for testability)
# ---------------------------------------------------------------------------


def _reconcile_typo(typo: Any, report: Any) -> Any:
    """Return *typo* with its score replaced by the engine's reduced value.

    TyposquatDetector reports the raw name-similarity score. RiskEngine then
    reduces it for packages with established adoption of their own and for
    version-suffix variants, and that reduced value is what the gate must judge —
    otherwise the reductions never reach the decision. Reading it back off the
    report keeps the reduction logic in one place (the engine) rather than
    duplicating it here.
    """
    if not getattr(typo, "is_typosquat", False):
        return typo
    signal = next((s for s in getattr(report, "signals", []) if s.name == "typosquat"), None)
    if signal is None or signal.score == typo.score:
        return typo
    return dataclass_replace(typo, score=signal.score)


def _version_passing_style(method: Any) -> str:
    """How to pass `version` to *method*: "keyword", "positional", or "none".

    resolve_package_dir gained `version` in contract v5; plugins written against an
    earlier version take three arguments. Inspecting the signature keeps a genuine
    TypeError from inside a plugin distinguishable from an arity mismatch.

    The distinction between "keyword" and "positional" matters: a hook declared
    `(..., *, version=None)` or `(..., **kwargs)` accepts the argument only by
    name, and passing it positionally raises TypeError — which the caller's broad
    except would swallow, silently disabling every source-code heuristic for a
    perfectly valid plugin. Only positional-only parameters and bare `*args`
    require positional passing.
    """
    import inspect

    try:
        sig = inspect.signature(method)
    except (TypeError, ValueError):
        return "none"

    accepts_var_positional = False
    for param in sig.parameters.values():
        if param.kind is param.VAR_KEYWORD:
            # **kwargs — name it explicitly.
            return "keyword"
        if param.kind is param.VAR_POSITIONAL:
            # *args cannot be addressed by name; remember and keep looking, in case
            # a keyword-only `version` follows (def f(*args, version=None)).
            accepts_var_positional = True
            continue
        if param.name != "version":
            continue
        if param.kind is param.POSITIONAL_ONLY:
            return "positional"
        # POSITIONAL_OR_KEYWORD and KEYWORD_ONLY both accept the name.
        return "keyword"
    return "positional" if accepts_var_positional else "none"


def call_resolve_package_dir(
    method: Any,
    name: str,
    project_path: Path | None,
    site_packages_dir: Path | None,
    *,
    version: str | None = None,
) -> list[Path]:
    """Invoke a language module's resolve_package_dir, adapting to its signature.

    Shared by the sandbox runner and the daemon so the argument-passing rules are
    defined once. Exceptions propagate — each caller logs and degrades in its own
    way. See _version_passing_style for why the style must be inspected.

    Returns every directory the distribution owns (see LanguageBase.resolve_package_dir
    for why this is a list rather than a single Path — a namespace-package
    distribution can own more than one non-adjacent subdirectory of a shared root).
    The registry's contract-v5 adapter guarantees *method* itself already returns
    list[Path] regardless of the plugin's declared contract version, so no
    adaptation happens here.
    """
    args: tuple = (name, project_path, site_packages_dir)
    kwargs: dict[str, Any] = {}
    if version is not None:
        style = _version_passing_style(method)
        if style == "keyword":
            kwargs["version"] = version
        elif style == "positional":
            args = (name, project_path, site_packages_dir, version)
    return method(*args, **kwargs)


def _resolve_installed_dir(
    ecosystem: str,
    name: str,
    cwd: Path,
    scan_root: Path | None = None,
    *,
    project_path: Path | None = None,
    version: str | None = None,
) -> tuple[list[Path], str | None]:
    """Resolve an installed package's directories via its language module,
    alongside any manifest-integrity warning for it (see
    LanguageBase.resolve_package_dir_manifest_warning).

    Mirrors daemon._resolve_package_dir, including the defensive hook guard: a
    third-party plugin raising here must not fail the post-install scan.

    Both location hints are passed because ecosystems need different ones and the
    runner should not encode that mapping: PythonLanguage requires
    site_packages_dir (and returns [] without it, which previously disabled all
    Python source heuristics post-install), while NodeLanguage requires
    project_path and ignores site_packages_dir.

    *scan_root* is the directory whose walk detected the package — site-packages
    for Python, node_modules for Node — and is forwarded as site_packages_dir.

    *project_path* should be passed explicitly whenever the caller knows it. When
    omitted it falls back to `scan_root.parent`, then to *cwd*. That inference is
    only correct when the scan root IS node_modules (parent = project root), which
    holds for the post-install scan's Node targets but **not** for a venv
    site-packages, whose parent is `lib/pythonX.Y`. The fallback is retained
    because it is right for that original caller and harmless elsewhere —
    PythonLanguage.resolve_package_dir ignores project_path entirely — but callers
    that know the real project root should say so rather than rely on the shape of
    the scan root matching their ecosystem.

    Returns every directory this one environment's resolution owns — e.g. both
    `google/auth` and `google/oauth2` for a namespace-package distribution — never
    the shared namespace root, which sibling distributions also install into.
    """
    if project_path is None:
        project_path = scan_root.parent if scan_root is not None else cwd
    # for_ecosystem() returns None on an unloaded registry, which would silently
    # disable every source-code signal. SandboxRunner.__init__ already loads it,
    # but this is a module-level helper and must not depend on that. Idempotent.
    lang_registry.load()
    lang = lang_registry.for_ecosystem(ecosystem)
    if lang is None:
        return [], None
    dirs: list[Path] = []
    # Pass the version so a caller searching several environments cannot be handed
    # a different version's source tree. Older plugins predate the parameter, so
    # check the signature rather than catching TypeError — that would also swallow
    # a genuine TypeError raised from inside the plugin's own body. Pass by keyword
    # unless the signature can only take it positionally: `(..., *, version=None)`
    # and `(..., **kwargs)` both reject a 4th positional argument.
    try:
        method = getattr(lang, "resolve_package_dir", None)
        if callable(method):
            dirs = call_resolve_package_dir(
                method, name, project_path, scan_root, version=version
            )
    except Exception:
        log.warning(
            "resolve_package_dir raised for lang=%s pkg=%s — skipping",
            getattr(lang, "name", "?"), name, exc_info=True,
        )

    warning: str | None = None
    try:
        warning_fn = getattr(lang, "resolve_package_dir_manifest_warning", None)
        if callable(warning_fn):
            warning = warning_fn(name, project_path, scan_root, version=version)
    except Exception:
        log.warning(
            "resolve_package_dir_manifest_warning raised for lang=%s pkg=%s — skipping",
            getattr(lang, "name", "?"), name, exc_info=True,
        )

    return dirs, warning


def _spec_label(pkg: object) -> str:
    """Render a PackageSpec as name==version for display.

    Markup-unsafe by design: package names are registry-supplied and may contain
    brackets, so callers must pass this to Console.print with markup=False.
    """
    version = getattr(pkg, "version", None)
    name = getattr(pkg, "name", "?")
    return f"{name}=={version}" if version else f"{name} (unpinned)"


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
        try:
            home_ro_fn = getattr(lang, "home_ro_paths", None)
            if callable(home_ro_fn):
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
        # getattr default False (not True): a third-party plugin predating
        # this field must not have every empty-packages command
        # (uninstalls included) silently start scanning its lock file just
        # because the attribute happens to be absent.
        is_lockfile_install=getattr(pi, "is_lockfile_install", False),
        # getattr default True (gate normally): a third-party plugin
        # predating this field has no way to signal "report-only, nothing
        # to gate" and should keep today's behaviour of being gated as usual.
        should_gate=getattr(pi, "should_gate", True),
        # getattr default False: a third-party plugin predating this field
        # has no way to signal system-Python targeting, so assume the
        # ordinary venv-discovery path still applies.
        is_system_python_target=getattr(pi, "is_system_python_target", False),
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
        _not_called = object()
        pairs: object = _not_called
        try:
            fn = getattr(lang, "configure_sandbox_writable", None)
            if callable(fn):
                pairs = fn(parsed, cwd, lang_flags, targets)
        except Exception:
            log.warning(
                "configure_sandbox_writable raised for lang=%s — skipping",
                name,
                exc_info=True,
            )
            pairs = _not_called
        if pairs is not _not_called:
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
                try:
                    warn_fn = getattr(lang, "configure_sandbox_writable_warning", None)
                    if callable(warn_fn):
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
    try:
        resolve_fn = getattr(lang, "resolve_sandbox_targets", None)
        if callable(resolve_fn):
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
) -> list[tuple[str, str, str | None, Path]]:
    """Return (ecosystem, name, version, scan_root) for packages that appeared
    since the snapshot.

    *scan_root* is the directory whose walk detected the package — site-packages
    for Python, node_modules for Node. It is retained because post-install source
    heuristics need it to locate the extracted package on disk
    (_resolve_installed_dir); without it, PythonLanguage.resolve_package_dir
    returns None and every source-code signal is unreachable.
    """
    new: list[tuple[str, str, str | None, Path]] = []
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

        def _scan_onerror(err: OSError, walk_root: Path = walk_root) -> None:
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
            try:
                detect_fn = getattr(lang, "detect_new_packages", None)
                if callable(detect_fn):
                    pkg_specs = detect_fn(new_paths, walk_root)
                    for ps in pkg_specs:
                        new.append((ps.ecosystem, ps.name, ps.version, walk_root))
            except Exception:
                log.warning("detect_new_packages raised for lang=%s — skipping",
                            getattr(lang, "name", "?"), exc_info=True)
    # Deduplicate preserving order, keyed on the full tuple including scan_root.
    # The same (ecosystem, name, version) installed under two distinct scan
    # roots is two separate on-disk copies — e.g. a project venv and a nested
    # tool's own venv both pulling in the same version — and each is scored
    # independently by _post_scan_risk via _resolve_installed_dir(..., scan_root,
    # ...). Keying on identity alone (dropping scan_root) collapsed those into
    # one entry, silently skipping every copy after the first: a compromised
    # second copy would never be inspected. Keying on the full tuple still
    # collapses true duplicates — the same package detected twice under the
    # same scan_root, e.g. by more than one language plugin's detect_new_packages.
    seen: set[tuple[str, str, str | None, Path]] = set()
    result = []
    for pkg in new:
        if pkg not in seen:
            seen.add(pkg)
            result.append(pkg)
    return result


