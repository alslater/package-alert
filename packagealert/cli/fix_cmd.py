"""`pa fix`: plan the upgrade commands that remove known vulnerabilities."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import re
import shlex
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, cast

import typer
from rich.console import Console

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from packagealert.remediate.adapter import RunFn, Yank
    from packagealert.remediate.planner import FixPlan

# pa fix discovers its package-manager adapter through the language registry
# (remediate.adapter.discover); the registry and adapters are imported inside
# _run_fix so `pa` stays as fast to start as before.

_CI_VARIABLES = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "TF_BUILD")
_BACKUP_ROOT = Path.home() / ".cache" / "package-alert" / "fix-backups"


@dataclasses.dataclass(frozen=True)
class ApplyOptions:
    mode: str
    """``sync`` or ``lock-only``."""
    yes: bool
    interactive: bool


def _interactive() -> bool:
    import sys

    return sys.stdin.isatty() and sys.stdout.isatty()


def _apply_mode(lock_only: bool, sync: bool, *, interactive: bool, env: Mapping[str, str]) -> str:
    """``sync`` at a terminal outside CI, ``lock-only`` otherwise; either flag decides outright."""
    if lock_only:
        return "lock-only"
    if sync:
        return "sync"
    in_ci = any(env.get(v, "").strip().lower() not in ("", "0", "false") for v in _CI_VARIABLES)
    return "sync" if interactive and not in_ci else "lock-only"


@contextlib.contextmanager
def _stdout_to_stderr():
    """Point file descriptor 1 at stderr while a child process runs, so JSON on stdout stays pure."""
    import os
    import sys

    sys.stdout.flush()
    saved = os.dup(1)
    try:
        os.dup2(2, 1)
        yield
    finally:
        sys.stdout.flush()
        os.dup2(saved, 1)
        os.close(saved)


def fix(
    path: Path = typer.Argument(Path("."), help="Project directory (must contain a supported lock file, such as uv.lock)."),
    allow_major: list[str] = typer.Option(
        [], "--allow-major", metavar="PKG|all",
        help="Plan fixes that need a new major version of PKG (repeatable, comma-separated), or of every package with 'all'.",
    ),
    allow_cooldown: bool = typer.Option(False, "--allow-cooldown", help="Plan fixes whose version is still inside the cooldown period."),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format: text, json."),
    no_verify: bool = typer.Option(False, "--no-verify", help="Print the plan without trial-resolving it (not verified; exits 1)."),
    allow_project_env: bool = typer.Option(
        False, "--allow-project-env",
        help="Bypass the sandbox.project_env_allowlist check for env vars from .pa-run.toml. "
             "Use when you trust the repository's .pa-run.toml env entries for this run only.",
    ),
    apply: bool = typer.Option(False, "--apply", help="Apply the verified plan: update the lock file (and npm's package.json), then sync the environment when run at a terminal."),
    lock_only: bool = typer.Option(False, "--lock-only", help="With --apply: update only the lock and manifest; never install or sync."),
    sync: bool = typer.Option(False, "--sync", help="With --apply: sync the environment afterwards, even when not at a terminal."),
    yes: bool = typer.Option(False, "--yes", "-y", help="With --apply: apply without asking."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config TOML file."),
):
    """Plan upgrade commands that fix vulnerable packages. Prints the commands; with --apply, applies the verified plan."""
    from packagealert.cli.app import _load, console

    if fmt not in ("text", "json"):
        console.print("--format must be one of: text, json", style="red", markup=False)
        raise typer.Exit(2)
    try:
        cli_allow_major = _parse_allow_major(allow_major)
    except ValueError as exc:
        console.print(str(exc), style="red", markup=False)
        raise typer.Exit(2) from None
    for message, bad in (
        ("--lock-only and --sync cannot be used together", lock_only and sync),
        ("--lock-only, --sync and --yes need --apply", (lock_only or sync or yes) and not apply),
        ("--apply needs the plan verified: drop --no-verify", apply and no_verify),
        ("--format json with --apply needs --yes at a terminal (it cannot prompt)",
         apply and fmt == "json" and not yes and _interactive()),
    ):
        if bad:
            console.print(message, style="red", markup=False)
            raise typer.Exit(2)
    import os
    interactive = _interactive()
    apply_options = (ApplyOptions(_apply_mode(lock_only, sync, interactive=interactive, env=os.environ),
                                  yes=yes, interactive=interactive) if apply else None)
    cfg, _ = _load(config)
    code = asyncio.run(_run_fix(cfg, path.resolve(), allow_major=cli_allow_major,
                                allow_cooldown=allow_cooldown, fmt=fmt,
                                verify=not no_verify,
                                allow_project_env=allow_project_env,
                                apply=apply_options))
    raise typer.Exit(code)


_PACKAGE_NAME_RE = re.compile(r"(@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")


def _parse_allow_major(values: list[str]) -> frozenset[str]:
    """Package names from repeated/comma-separated values, ``all`` as ``"*"``.

    Raises ValueError (with the message to show) for a value that names nothing
    or is not a package name, such as a path.
    """
    from packagealert.cli.run_settings import split_package_names

    names: set[str] = set()
    for value in values:
        parts = [p.strip() for p in value.split(",") if p.strip()]
        if not parts:
            raise ValueError("--allow-major needs a package name or 'all'")
        for part in parts:
            if part.lower() not in ("all", "*") and not _PACKAGE_NAME_RE.fullmatch(part):
                raise ValueError(
                    f"--allow-major needs a package name or 'all' (got {part!r} — a path goes before "
                    f"or after the options, not as this option's value)")
        names |= {"*" if n == "all" else n for n in split_package_names(parts)}
    return frozenset(names)


class _Spinner:
    """A transient one-line spinner that leaves sys.stdout and sys.stderr alone.

    Rich's console.status() redirects sys.stdout into its display while it runs
    on a terminal, which would draw a JSON plan on stderr instead of writing it
    to stdout (`pa fix --format json > plan.json`).
    """

    def __init__(self, console, message: str) -> None:
        from rich.live import Live
        from rich.spinner import Spinner

        self._spinner = Spinner("dots", text=message)
        self._live = Live(self._spinner, console=console, transient=True, refresh_per_second=12.5,
                          redirect_stdout=False, redirect_stderr=False)

    def start(self) -> None:
        self._live.start()

    def update(self, message: str) -> None:
        self._spinner.update(text=message)

    def stop(self) -> None:
        self._live.stop()


async def _run_fix(cfg, root: Path, *, allow_major: frozenset[str], allow_cooldown: bool, fmt: str,
                    verify: bool = True, allow_project_env: bool = False,
                    apply: ApplyOptions | None = None) -> int:
    from packagealert.cli import app as app_module

    out = app_module.console
    # JSON mode keeps stdout pure JSON: every notice goes to stderr.
    console = Console(stderr=True) if fmt == "json" else out
    # One spinner line naming the current step. Rich draws nothing when the
    # console is not a terminal, so piped output and logs stay clean.
    status = _Spinner(console, "Finding the lock file…")
    status.start()

    @contextlib.contextmanager
    def paused():
        """Stop the spinner while something may prompt on the terminal."""
        status.stop()
        try:
            yield
        finally:
            status.start()

    try:
        return await _plan_and_report(cfg, root, allow_major=allow_major, allow_cooldown=allow_cooldown, fmt=fmt,
                                      verify=verify, allow_project_env=allow_project_env, apply=apply,
                                      out=out, console=console, say=status.update, pause=paused)
    finally:
        status.stop()


async def _plan_and_report(cfg, root: Path, *, allow_major: frozenset[str], allow_cooldown: bool, fmt: str,
                           verify: bool, allow_project_env: bool, out, console,
                           say: Callable[[str], object],
                           pause: Callable[[], contextlib.AbstractContextManager[None]],
                           apply: ApplyOptions | None = None) -> int:
    from packagealert.cli import app as app_module
    from packagealert.cli.run_settings import (
        ProjectRunSettings,
        RunSettingsError,
        resolve_project_run_settings,
        split_package_names,
    )
    from packagealert.models.events import normalise_package_name_for
    from packagealert.osv.remediation import group_findings
    from packagealert.remediate import planner
    from packagealert.remediate.adapter import (
        LockfileError,
        SyncSelection,
        Yank,
        discover,
    )
    from packagealert.remediate.graph import DependencyGraph
    from packagealert.storage.db import open_db

    found = discover(root)
    if not found.matches:
        supported = ", ".join(dict.fromkeys(found.supported)) or "no lock files (no adapters are installed)"
        console.print(f"No supported lock file in {root}: pa fix supports {supported}.", style="red", markup=False)
        return 2
    if len(found.matches) > 1:
        names = ", ".join(lf.name for _, lf in found.matches)
        console.print(f"Several lock files in {root} ({names}): pa fix cannot tell which package manager to use.",
                  style="red", markup=False)
        return 2
    adapter, lockfile = found.matches[0]
    snap = None
    if apply is not None:
        from packagealert.remediate import apply as apply_module
        try:
            names = (apply_module.checked_files(adapter) if hasattr(adapter, "written_files")
                     else (lockfile.name,))
            if not names or not all(apply_module.is_project_file_name(n) for n in names):
                raise TypeError(f"written_files/stale_files are {names!r}, not project file names")
        except Exception:  # noqa: BLE001 - an adapter bug must not become a traceback
            app_module.log.warning("The %s adapter failed to list the files it writes and checks", adapter.name,
                                   exc_info=True)
            names = (lockfile.name,)
        # Every file the re-resolve will copy, by digest, so a changed source or workspace
        # member is caught too. A list that cannot be read now is recorded as empty: the
        # apply then refuses rather than skip the check (a deterministic refusal, such as
        # a project outside git, is given again by apply_files itself, first).
        inputs: list[str] | None = None
        list_inputs = getattr(adapter, "apply_files", None)
        if callable(list_inputs):
            try:
                listed = list_inputs(lockfile.parent)
                if not (isinstance(listed, list)
                        and all(isinstance(n, str) and apply_module.is_project_file_name(n) for n in listed)):
                    raise TypeError(f"apply_files returned {listed!r}, not a list of project file names")
                inputs = [str(n) for n in listed]
            except Exception:  # noqa: BLE001 - an adapter refusal or bug must not become a traceback
                app_module.log.warning("The %s adapter could not list the files it copies", adapter.name,
                                       exc_info=True)
                inputs = []
        snap = apply_module.snapshot(lockfile.parent, names, inputs=inputs)
    say(f"Reading {lockfile.name}…")
    try:
        graph = adapter.load_graph(lockfile)
        packages = adapter.locked_packages(lockfile)
        if not isinstance(graph, DependencyGraph) or not isinstance(packages, list):
            raise TypeError(f"returned {type(graph).__name__} and {type(packages).__name__}, "
                            "not a DependencyGraph and a list")
        for p in packages:
            if not _is_package_spec(p):
                raise TypeError(f"locked_packages() returned {p!r}, not a PackageSpec")
    except LockfileError as exc:
        console.print(f"Cannot use {lockfile.name}: {exc}", style="red", markup=False)
        return 2
    except Exception as exc:  # noqa: BLE001 - an adapter bug must not become a traceback
        app_module.log.warning("The %s adapter failed to read %s", adapter.name, lockfile, exc_info=True)
        console.print(f"Cannot use {lockfile.name}: the {adapter.name} adapter failed ({exc})",
                  style="red", markup=False)
        return 2
    if graph.versions and not packages:
        console.print(f"Cannot use {lockfile.name}: could not read the packages in it", style="red", markup=False)
        return 2
    settings: ProjectRunSettings | None = None
    settings_error: str | None = None
    try:
        settings = resolve_project_run_settings(root, cfg, allow_project_env=allow_project_env, out=console)
    except RunSettingsError as exc:
        settings_error = f"project run config unusable ({exc})"
    # Only the command line can allow every package; a stored list never can.
    standing = split_package_names(cfg.fix.allow_major)
    if settings is not None:
        standing |= settings.allow_major
    raw = (standing - {"*"}) | allow_major
    allowed_major = frozenset(
        "*" if n == "*" else normalise_package_name_for(adapter.ecosystem, n) for n in raw)

    # A package from a private registry, git or a local path is not the public one of
    # that name: its name is not sent to OSV, nor judged by the public package's advisories.
    public = [p for p in packages if getattr(p, "from_public_registry", True) is not False]
    not_public = len(packages) - len(public)
    yank_failures = 0
    locked_yanks: tuple[Yank, ...] = ()
    db = await open_db(enabled_plugins=set(cfg.plugins.enabled))
    try:
        say(f"Checking {len(public)} locked packages against OSV…")
        findings, osv_failures = await app_module._query_osv_findings(cfg, db, public)
        say(f"Checking {len(packages)} locked packages for yanked versions…")
        try:
            from packagealert.yanks import check_yanks
            found_yanks, yank_failures = await check_yanks(db, packages)
            locked_yanks = tuple(Yank(y.package, y.version, y.reason) for y in found_yanks)
        except Exception:  # noqa: BLE001 - yank status is advisory; the plan does not depend on it
            app_module.log.warning("Yank check failed", exc_info=True)
            yank_failures = len(packages)
        groups = group_findings(findings)
        try:
            say(f"Checking the ages of {len(groups)} recommended versions…")
            ages = await app_module._recommendation_ages(db, groups) if groups else {}
        except Exception:  # noqa: BLE001 - ages are advisory; plan without them
            app_module.log.warning("Could not check recommended versions against the cooldown period", exc_info=True)
            ages = {}
    finally:
        await db.close()

    plan = planner.plan_fixes(
        groups, graph, ages=ages, cooldown_days=cfg.sandbox.cooldown.period_days,
        allow_major=allowed_major, allow_cooldown=allow_cooldown,
        pins_every_copy=getattr(adapter, "pins_every_copy", False),
    )
    unverified_reason: str | None = None
    verified = False
    runner = None
    if plan.planned:
        runner, blocked = _captured_runner(cfg, adapter, lockfile.parent, settings, console, pause)
        if verify:
            from packagealert.parsers.process_args import SANDBOX_ENV
            from packagealert.sandbox.runner import _build_sandbox_env

            # Trials judge a project config's ${VAR}s (npm's .npmrc) as their sandbox expands them.
            token = SANDBOX_ENV.set(_build_sandbox_env(
                [*cfg.sandbox.extra_env, *(settings.env if settings is not None else [])]))
            try:
                plan, unverified_reason = await _verify(cfg, adapter, lockfile, plan, allow_cooldown, allowed_major,
                                                        console, settings, settings_error, say=say, runner=runner,
                                                        blocked=blocked, locked_yanks=locked_yanks,
                                                        direct=graph.direct, snap=snap)
            finally:
                SANDBOX_ENV.reset(token)
            verified = unverified_reason is None
        else:
            unverified_reason = "--no-verify"
    if unverified_reason is not None:
        # Untrialled, by --no-verify or because trials could not run: an adapter that
        # applies transitive fixes as its trials choose cannot apply them.
        plan = _hold_untrialled(plan, adapter, unverified_reason)
    if not verified:
        # verify_plan merges the registry's yanks with those its trials saw; without
        # it, list the registry's yanks minus what the commands upgrade.
        moved = {(normalise_package_name_for(adapter.ecosystem, p.package), p.version) for p in plan.planned}
        plan = dataclasses.replace(plan, yanked_locked=tuple(
            y for y in locked_yanks
            if (normalise_package_name_for(adapter.ecosystem, y.package), y.version) not in moved))
    # After verification, which can hold items for a major bump of another package.
    if any(h.reason == planner.MAJOR for h in plan.held):
        say("Checking the release history of held major upgrades…")
    cadences = {} if settings_error is not None else await _held_major_cadences(plan, settings, adapter)
    if plan.planned:
        say("Checking the project's installed environment…")
    selection = (await _sync_selection(adapter, lockfile.parent, settings, runner)
                 if plan.planned else SyncSelection())
    try:
        cmds = adapter.commands(plan, _elsewhere(lockfile.parent), selection.flags)
        if not isinstance(cmds, list) or not all(
            isinstance(argv, list) and all(isinstance(a, str) for a in argv) for argv in cmds
        ):
            raise TypeError(f"commands() returned {cmds!r}, not a list of argument lists")
    except Exception as exc:  # noqa: BLE001 - an adapter bug must not become a traceback
        app_module.log.warning("The %s adapter failed to build commands", adapter.name, exc_info=True)
        console.print(f"Cannot plan {lockfile.name}: the {adapter.name} adapter failed ({exc})",
                  style="red", markup=False)
        return 2
    outcome = None
    interrupted: BaseException | None = None
    if apply is not None and fmt == "json":
        outcome, interrupted = await _apply(apply, adapter, lockfile, plan, runner, settings, selection, snap,
                                            console, pause, osv_failures=osv_failures,
                                            unverified_reason=unverified_reason, json_output=True)
    if fmt == "json":
        print(json.dumps(_plan_json(lockfile, plan, cmds, osv_failures, unverified_reason, cadences,
                                    sync=selection, yank_failures=yank_failures, not_public=not_public,
                                    apply=outcome), indent=2))
    else:
        _print_plan(out, lockfile, plan, cmds, osv_failures, checked=len(public),
                    unverified_reason=unverified_reason, cadences=cadences, sync=selection,
                    yank_failures=yank_failures, not_public=not_public)
        if apply is not None:
            outcome, interrupted = await _apply(apply, adapter, lockfile, plan, runner, settings, selection, snap,
                                                console, pause, osv_failures=osv_failures,
                                                unverified_reason=unverified_reason, json_output=False,
                                                on_written=lambda o: _print_written(out, o))
            _print_apply_end(out, outcome)
    if interrupted is not None:
        # The report is out; stop as interrupted.
        raise interrupted
    return _exit_status(plan, osv_failures=osv_failures, unverified_reason=unverified_reason, outcome=outcome)


def _exit_status(plan: FixPlan, *, osv_failures: int, unverified_reason: str | None, outcome: dict | None) -> int:
    """0 when everything vulnerable is planned and checked and, under ``--apply`` (*outcome*),
    applied (or there was nothing to apply) and not left unsynced; 1 otherwise.

    Under ``--apply`` the exit follows the outcome: any refusal other than
    "nothing to apply" exits 1, so it always agrees with the reason reported.
    """
    ok = plan.complete and not osv_failures and unverified_reason is None
    if outcome is not None:
        ok = (ok and (outcome["applied"] or outcome["reason"] == "nothing to apply")
              and outcome["synced"] is not False)
    return 0 if ok else 1


async def _apply(opts: ApplyOptions, adapter, lockfile: Path, plan: FixPlan, runner, settings, selection, snap,
                 console, pause, *, osv_failures: int, unverified_reason: str | None, json_output: bool,
                 on_written: Callable[[dict], object] | None = None) -> tuple[dict, BaseException | None]:
    """Apply *plan* as ``--apply`` asks.

    Returns the JSON ``apply`` object describing what happened, and the
    KeyboardInterrupt or CancelledError that stopped the sync, if one did (the
    caller re-raises it once the outcome is printed). *on_written* is called
    with the outcome once the files are written, before the sync starts.
    """
    from packagealert.remediate import apply as apply_module

    outcome: dict = {"mode": opts.mode, "applied": False, "reason": None, "written": [], "backup": None,
                     "changes": [], "synced": None, "sync_command": None, "remaining": []}
    reason = None
    # What could not be checked comes first: an empty plan after an OSV outage, or
    # after every fix was held for want of verification, is not a clean project.
    if unverified_reason is not None:
        reason = f"the plan could not be verified ({unverified_reason})"
    elif osv_failures:
        reason = f"{osv_failures} package(s) could not be checked against OSV"
    elif plan.drift_unchecked:
        reason = (f"{plan.drift_unchecked} version(s) that re-locking the project installs could not be "
                  "checked for withdrawn releases")
    elif not plan.planned:
        reason = "nothing to apply"
    elif runner is None or settings is None or snap is None:
        reason = "the sandbox is unavailable"
    else:
        reason = apply_module.refusal(adapter, plan)
    if reason is None and opts.interactive and not opts.yes:
        count = 1 if plan.separate else len(plan.planned)
        with pause():
            try:
                confirmed = typer.confirm(f"Apply {count} fix(es) to {lockfile.name}?", default=False)
            except (typer.Abort, EOFError):
                confirmed = False
        if not confirmed:
            reason = "declined"
    if reason is not None or snap is None:
        outcome["reason"] = reason
        return outcome, None
    result = await apply_module.apply_plan(adapter, plan, _FixTrialRunner(runner, lockfile.parent, settings),
                                           snap, _BACKUP_ROOT)
    outcome.update(applied=result.applied, reason=result.reason, written=list(result.written),
                   backup=str(result.backup) if result.backup is not None else None,
                   changes=[{"package": c.package, "before": list(c.before), "after": list(c.after)}
                            for c in result.changes],
                   remaining=_deferred(plan) if result.applied else [])
    if not result.applied:
        # An interrupted apply (before anything was written, or a write that left the
        # project part-changed): the outcome, with any backup, is reported first, then
        # the interruption is re-raised.
        return outcome, result.interrupted
    if on_written is not None:
        on_written(outcome)
    interrupted = None
    if opts.mode == "sync":
        outcome["synced"], outcome["sync_command"], interrupted = await _sync(
            adapter, lockfile.parent, plan, runner, settings, selection, pause, json_output=json_output)
    return outcome, interrupted


async def _sync(adapter, project_dir: Path, plan: FixPlan, runner, settings, selection, pause, *,
                json_output: bool) -> tuple[bool, list[str] | None, BaseException | None]:
    """Run the adapter's sync command through pa run's sandbox path, from *project_dir*.

    Returns whether it succeeded, the command (None when the adapter gave no
    usable one), and the KeyboardInterrupt or CancelledError that stopped it.
    An exception or interruption while it runs counts as a failed sync."""
    from packagealert.cli import app as app_module
    from packagealert.sandbox.runner import _try_parse

    try:
        argv = adapter.sync_argv(plan, selection.flags)
    except Exception:  # noqa: BLE001 - an adapter bug must not become a traceback
        app_module.log.warning("The %s adapter failed to build its sync command", adapter.name, exc_info=True)
        return False, None, None
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
        app_module.log.warning("The %s adapter returned an unusable sync command: %r", adapter.name, argv)
        return False, None, None
    if _try_parse(argv) is None:
        # An unparsed command would make run() exec it directly, unsandboxed.
        app_module.log.warning("The sync command %s is not recognised as an install; not running it",
                               shlex.join(argv))
        return False, argv, None
    try:
        with pause(), contextlib.chdir(project_dir), \
                (_stdout_to_stderr() if json_output else contextlib.nullcontext()):
            code = await runner.run(argv, allow_network=not settings.no_network, extra_env=settings.env,
                                    flags=settings.flags)
    except (KeyboardInterrupt, asyncio.CancelledError) as exc:
        app_module.log.warning("The sync command %s was interrupted", shlex.join(argv))
        return False, argv, exc
    except Exception:  # noqa: BLE001 - the files are written; report the failed sync, not a traceback
        app_module.log.warning("The sync command %s failed", shlex.join(argv), exc_info=True)
        return False, argv, None
    return code == 0, argv, None


def _print_written(out, outcome: dict) -> None:
    """The first part of the apply block: what was written and where the originals are."""
    label = "lock only" if outcome["mode"] == "lock-only" else "lock, then the environment"
    changes = ", ".join(f"{c['package']} {', '.join(c['before']) or 'none'} → {', '.join(c['after']) or 'none'}"
                        for c in outcome["changes"])
    out.print(f"\nApplied ({label}):", markup=False)
    out.print(f"  ✓ {', '.join(outcome['written'])} updated: {changes}", style="green", markup=False)
    if outcome["backup"]:
        out.print(f"  Originals saved in {outcome['backup']}", style="dim", markup=False)


def _print_apply_end(out, outcome: dict) -> None:
    """The rest of the apply block: why nothing was applied, or the sync's result and what is left."""
    if not outcome["applied"]:
        out.print(f"\nNot applied: {outcome['reason']}", style="yellow", markup=False)
        return
    if outcome["synced"] is True:
        out.print("  ✓ The environment was synced", style="green", markup=False)
    elif outcome["synced"] is False:
        command = outcome["sync_command"]
        hint = f"run: {shlex.join(command)}" if command else "run the project's sync command"
        out.print(f"  The environment was not synced; {hint}", style="yellow", markup=False)
    if outcome["remaining"]:
        out.print(f"Left for another run: {', '.join(outcome['remaining'])}. Run pa fix --apply again.",
                  markup=False)


SYNC_UNCHECKED = ("Could not check which extras or groups the project's environment was installed with; "
                  "a plain sync may remove packages installed from them.")


# The most items verified at once, whatever an adapter asks for: each trial
# is a resolver process, and a large project's lock costs hundreds of MB.
_MAX_PARALLEL_TRIALS = 8


def _parallel_trials(adapter) -> int:
    """How many items to verify at once: the adapter's ``parallel_trials`` (1 when absent or malformed), at most 8."""
    value = getattr(adapter, "parallel_trials", 1)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return 1
    return min(value, _MAX_PARALLEL_TRIALS)


class _FixTrialRunner:
    """The TrialRunner pa fix hands an adapter: sandboxed commands for one project.

    Given *snap* (the snapshot ``--apply`` takes before planning), ``freeze()``
    copies every file the snapshot recorded into one scratch directory and
    checks it against the snapshot; from then on that copy is ``project_dir``,
    so everything an adapter reads (the lock, ``.npmrc``) and every command it
    runs sees exactly the snapshot's files, and the live project is not read
    again until the apply checks it. Each trial's own scratch copy is checked
    too. A copy that differs raises ``ApplyRefused`` and sets ``changed``.
    ``close()`` removes the frozen copy.
    """

    def __init__(self, runner, project_dir: Path, settings, snap=None) -> None:
        self._runner, self._dir, self._settings = runner, project_dir, settings
        self._snap = snap
        self.changed = False
        self._frozen: Path | None = None

    @property
    def project_dir(self) -> Path:
        return self._frozen or self._dir

    def _check_copy(self, files, copy: Path) -> None:
        """Raise ApplyRefused (and set ``changed``) unless *copy* holds the snapshot's *files*."""
        from packagealert.remediate.adapter import ApplyRefused
        from packagealert.remediate.apply import copy_is_snapshot

        if self._snap is None:
            return
        try:
            copy_is_snapshot(files, self._snap)(copy)
        except ApplyRefused:
            self.changed = True
            raise

    def freeze(self) -> None:
        """Make the checked copy of the snapshot's files that becomes ``project_dir``.

        Nothing is done without a snapshot that recorded its inputs (an apply is
        then refused anyway, and the trials run on the project itself).
        """
        import tempfile

        from packagealert.sandbox import runner as sandbox_runner

        if self._snap is None or not self._snap.inputs or self._frozen is not None:
            return
        root = sandbox_runner.SCRATCH_ROOT
        root.mkdir(parents=True, exist_ok=True)
        copy = Path(tempfile.mkdtemp(prefix="trial-", dir=root)).resolve()
        try:
            names = list(dict.fromkeys((*self._snap.files, *self._snap.inputs)))
            _copy_beneath(self._dir, copy, names)
            self._check_copy(names, copy)
        except BaseException:
            _remove_tree(copy)
            raise
        self._frozen = copy

    def close(self) -> None:
        """Remove the frozen copy, if one was made."""
        if self._frozen is not None:
            _remove_tree(self._frozen)
            self._frozen = None

    async def read_only(self, argv: list[str]):
        from packagealert.remediate.adapter import CommandResult

        # The frozen copy is a scratch directory, so a command runs there as a scratch run.
        out = await self._runner.run_captured(argv, cwd=self.project_dir, flags=self._settings.flags,
                                              extra_env=self._settings.env,
                                              allow_network=not self._settings.no_network,
                                              **({"scratch": True} if self._frozen is not None else {}))
        return CommandResult(out.returncode, out.stdout, out.stderr, out.timed_out)

    async def in_copy(self, files, argvs, edit=None, read_back=None):
        """Run *argvs* in a fresh scratch copy of *files*, read them back, remove the copy.

        A callable in *argvs* is an edit made on the copy at that point, between commands.

        Only regular files are copied and read back, each opened from its
        directory without following a symlink at any level (a symlinked file or
        directory, in the project or left in the copy by the command, reads as
        absent), so nothing outside the project or the copy is reached. The commands run in order and stop at the
        first that fails or times out; the copy is removed whatever happens.
        *read_back* names the files read back afterwards (default: every copied file).
        """
        import shutil
        import tempfile

        from packagealert.remediate.adapter import CommandResult, CopyResult
        from packagealert.remediate.apply import read_regular_beneath
        from packagealert.sandbox import runner as sandbox_runner

        for name in files:
            rel = Path(name)
            if not name or rel.is_absolute() or ".." in rel.parts:
                raise ValueError(f"not a project-relative file name: {name!r}")
        # The sandbox accepts a scratch run only inside its SCRATCH_ROOT.
        root = sandbox_runner.SCRATCH_ROOT
        root.mkdir(parents=True, exist_ok=True)
        scratch = Path(tempfile.mkdtemp(prefix="trial-", dir=root)).resolve()
        try:
            _copy_beneath(self.project_dir, scratch, files)
            self._check_copy(files, scratch)
            if edit is not None:
                edit(scratch)
            results = []
            for argv in argvs:
                if callable(argv):
                    # An edit between commands, made in Python on the copy.
                    argv(scratch)
                    continue
                out = await self._runner.run_captured(
                    argv, cwd=scratch, scratch=True, flags=self._settings.flags,
                    extra_env=self._settings.env, allow_network=not self._settings.no_network)
                results.append(CommandResult(out.returncode, out.stdout, out.stderr, out.timed_out))
                if out.returncode != 0 or out.timed_out:
                    break
            after = {name: read_regular_beneath(scratch, name) for name in (files if read_back is None else read_back)}
            return CopyResult(tuple(results), after)
        finally:
            shutil.rmtree(scratch, onexc=_make_removable)


def _copy_beneath(project_dir: Path, scratch: Path, files) -> None:
    """Copy each regular file of *files* from *project_dir* to the same name under *scratch*.

    Each is opened beneath the project directory without following a symlink at
    any level and copied from that descriptor, so a symlink swapped in meanwhile
    cannot bring in a file from outside the project; anything else is skipped.
    A copy keeps its source's permission bits, as ``copy_mode`` gives them.
    """
    import shutil

    from packagealert.remediate.apply import copy_mode, open_regular_beneath

    project_fd = os.open(project_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in files:
            fd = open_regular_beneath(project_fd, name)
            if fd is None:
                continue
            with os.fdopen(fd, "rb") as src:
                (scratch / name).parent.mkdir(parents=True, exist_ok=True)
                with open(scratch / name, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                    os.fchmod(dst.fileno(), copy_mode(os.fstat(src.fileno()).st_mode))
    finally:
        os.close(project_fd)


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, onexc=_make_removable)


def _make_removable(func, path, _exc) -> None:
    """shutil.rmtree onexc: make *path*'s directory writable and retry once; give up quietly."""
    import os

    try:
        os.chmod(os.path.dirname(path), 0o700)
        if os.path.isdir(path) and not os.path.islink(path):
            os.chmod(path, 0o700)
        func(path)
    except OSError:
        pass


def _captured_runner(cfg, adapter, project_dir: Path, settings, console, pause):
    """The one sandbox runner for pa fix's trials and checks, authorised up front.

    Returns (runner, None), (None, None) when no sandbox can run, or (None,
    reason) when a pre-run check refused the project's flags: python:ssh-keys,
    for example, asks before ~/.ssh is mounted where build code can read it.
    The spinner is paused so a prompt appears on a clean line.
    """
    from packagealert.sandbox.runner import SandboxRunner, bwrap_available

    if settings is None or not bwrap_available():
        return None, None
    runner = SandboxRunner(cfg, console=console)
    try:
        argv = adapter.probe_argv()
    except Exception:  # noqa: BLE001 - the trials will report the adapter's failure
        return runner, None
    with pause():
        allowed = runner.authorize_captured(argv, cwd=project_dir, flags=settings.flags)
    if not allowed:
        return None, "a sandbox pre-run check did not allow the project's flags"
    return runner, None


async def _sync_selection(adapter, project_dir: Path, settings, runner):
    """The adapter's sync selection for *project_dir*.

    A plain sync when the adapter has no selection hook; a plain sync with
    SYNC_UNCHECKED when the hook fails or returns something malformed, since a
    plain sync may then remove packages.
    """
    from packagealert.cli import app as app_module
    from packagealert.remediate.adapter import SyncSelection

    hook = getattr(adapter, "sync_selection", None)
    if not callable(hook):
        return SyncSelection()

    async def run(argv: list[str]) -> tuple[int, str]:
        if runner is None or settings is None:
            return 127, ""
        try:
            r = await runner.run_captured(argv, cwd=project_dir, flags=settings.flags, extra_env=settings.env,
                                          allow_network=not settings.no_network)
        except Exception:  # noqa: BLE001 - an unavailable sandbox means "could not check"
            return 127, ""
        return r.returncode, r.stdout

    try:
        sel = await cast("Callable[[Path, RunFn], Awaitable[object]]", hook)(project_dir, run)
    except Exception:  # noqa: BLE001 - an adapter bug must not stop the plan
        app_module.log.warning("The %s adapter failed to choose sync flags", adapter.name, exc_info=True)
        return SyncSelection(warning=SYNC_UNCHECKED)
    if (not isinstance(sel, SyncSelection) or not isinstance(sel.flags, tuple)
            or not all(isinstance(f, str) for f in sel.flags)
            or not (sel.warning is None or isinstance(sel.warning, str))):
        app_module.log.warning("The %s adapter returned an unusable sync selection: %r", adapter.name, sel)
        return SyncSelection(warning=SYNC_UNCHECKED)
    return sel


def _is_package_spec(p: object) -> bool:
    """A PackageSpec whose fields really have their declared types (a plugin built it)."""
    from packagealert.languages.base import PackageSpec

    return (
        isinstance(p, PackageSpec) and isinstance(p.name, str) and isinstance(p.ecosystem, str)
        and (p.version is None or isinstance(p.version, str))
    )


def _elsewhere(project_dir: Path) -> Path | None:
    """*project_dir* when it is not the current directory, so printed commands must name it."""
    try:
        here = Path.cwd().resolve()
    except OSError:  # the current directory was removed
        return project_dir
    return None if here == project_dir.resolve() else project_dir


def _major_package(h) -> str:
    """The package whose release history says whether this major hold is routine."""
    return h.needs_major[0] if h.needs_major else h.package


async def _held_major_cadences(plan: FixPlan, settings, adapter) -> dict[str, str | None]:
    """Release cadence of each package held for a major upgrade; {} when the adapter cannot say."""
    from packagealert.remediate import planner

    names = sorted({_major_package(h) for h in plan.held if h.reason == planner.MAJOR})
    if not names or (settings is not None and settings.no_network):
        return {}
    try:
        cadences = getattr(adapter, "cadences", None)
        if not callable(cadences):
            return {}
        result = await cast("Callable[[list[str]], Awaitable[object]]", cadences)(names)
    except Exception:  # noqa: BLE001 - the label is advisory; a failed lookup must not stop the plan
        return {}
    if not isinstance(result, dict):
        return {}
    # Only the documented values (or None) reach the label and the JSON.
    return {k: v for k, v in result.items() if isinstance(k, str) and (v is None or (isinstance(v, str) and v in _CADENCE_WHY))}


# (name, version) pairs the trial being judged installs from outside the public
# registry (TrialResult.non_public); before any trial, the baseline's. Set by each
# trial in the task that judges it, so concurrent verifications see only their own.
_TRIAL_NOT_PUBLIC: ContextVar[frozenset[tuple[str, str]]] = ContextVar("_TRIAL_NOT_PUBLIC", default=frozenset())


def _hold_untrialled(plan: FixPlan, adapter: object, reason: str = "--no-verify") -> FixPlan:
    """*plan* with the transitive items an adapter applies only as its trials choose held, when nothing is trialled.

    An adapter that can force a pin (npm) moves a transitive package with an
    override or a parent upgrade its trials pick; untrialled, such an item has
    neither, and its command would be a plain install that keeps the vulnerable
    version. Items with a direct pin, a parent upgrade or an override are kept.
    """
    from packagealert.remediate import planner
    from packagealert.remediate.planner import HeldFix

    if not getattr(adapter, "can_force", False):
        return plan
    keep, held = [], []
    for p in plan.planned:
        if p.direct or p.forced or p.all_parents or p.by_relock:
            keep.append(p)
            continue
        held.append(HeldFix(package=p.package, version=p.version, target=p.target,
                            reason=planner.COULD_NOT_VERIFY, advisories=p.advisories,
                            detail="how to apply a transitive fix (an override or a parent upgrade) is chosen by "
                                   f"trial-resolving it, which did not run ({reason})"))
    if not held:
        return plan
    return dataclasses.replace(plan, planned=keep, held=[*plan.held, *held])


async def _verify(cfg, adapter, lockfile: Path, plan: FixPlan, allow_cooldown: bool, allow_major: frozenset[str], console,
                  settings, settings_error: str | None,
                  say: Callable[[str], object] = lambda _message: None,
                  runner=None, blocked: str | None = None,
                  locked_yanks: tuple[Yank, ...] = (),
                  direct: frozenset[str] = frozenset(), snap=None) -> tuple[FixPlan, str | None]:
    """Trial-resolve each planned pin. Returns (plan, None), or (original plan, reason) when trials cannot run.

    A trial that fails for one pin holds that pin; it does not discard the rest.
    With *snap*, every trial runs on the snapshot's files (``_FixTrialRunner``);
    a project file that no longer matches it leaves the whole plan unverified.
    """
    from packagealert.sandbox.runner import SandboxRunner, bwrap_available

    if not bwrap_available():
        return plan, "bwrap (bubblewrap) is not installed"

    if settings_error is not None:
        return plan, settings_error
    if settings.no_network:
        return plan, "network is disabled by the project run config"
    if blocked is not None:
        return plan, blocked
    if runner is None:
        runner = SandboxRunner(cfg, console=console)
    project_dir = lockfile.parent

    run = _FixTrialRunner(runner, project_dir, settings, snap=snap)
    try:
        run.freeze()
        verified = await _verify_with(cfg, adapter, plan, allow_cooldown, allow_major, console, say,
                                      locked_yanks, direct, run)
    except Exception:
        if not run.changed:
            raise
        verified = None
    finally:
        run.close()
    if run.changed or verified is None:
        return plan, "the project changed while pa fix was running; run it again"
    return verified, None


async def _verify_with(cfg, adapter, plan: FixPlan, allow_cooldown: bool, allow_major: frozenset[str], console,
                       say: Callable[[str], object], locked_yanks, direct: frozenset[str], run) -> FixPlan:
    """``_verify``'s trials, run with *run*."""
    from packagealert.cli import app as app_module
    from packagealert.remediate.adapter import Change, TrialResult, Yank
    from packagealert.remediate.verify import verify_plan
    from packagealert.storage.db import open_db

    registry_yanks = getattr(adapter, "yanks_from_registry", False) is True
    drift_unchecked = 0

    async def with_registry_yanks(result, *, baseline: bool = False):
        """*result* with the yanked versions its changes install, looked up in the registry.

        For an adapter whose tool does not report yanks itself. A version the
        trial installs from outside the public registry (``non_public``) is not
        looked up. A lookup that fails is not "not yanked": a trial becomes
        inconclusive (its fix is held, as for an unavailable advisory lookup);
        the *baseline*, which every trial is judged against, is kept, with a
        warning that its versions were not checked.
        """
        from packagealert.languages.base import PackageSpec
        from packagealert.yanks import check_yanks

        new = sorted({(c.package, c.new) for c in result.changes if c.action in ("update", "add") and c.new})
        if not new:
            return result
        try:
            db = await open_db(enabled_plugins=set(cfg.plugins.enabled))
            try:
                found, failures = await check_yanks(
                    db, [PackageSpec(name=n, version=v, ecosystem=adapter.ecosystem,
                                     from_public_registry=(n, v) not in result.non_public) for n, v in new])
            finally:
                await db.close()
        except Exception:  # noqa: BLE001 - reported as unchecked below rather than raised
            app_module.log.warning("Yank check of a %s trial failed", adapter.name, exc_info=True)
            found, failures = [], len(new)
        if failures:
            what = f"{failures} version(s) it installs could not be checked for withdrawn releases (registry lookup failed)"
            if not baseline:
                return TrialResult("inconclusive", detail=what)
            nonlocal drift_unchecked
            drift_unchecked = failures
            console.print(f"⚠ Re-locking the project: {what}", style="yellow", markup=False)
        extra = tuple(Yank(y.package, y.version, y.reason) for y in found)
        return dataclasses.replace(result, yanked=(*result.yanked, *extra)) if extra else result

    async def trial(pins, floats, *, force=(), lowest=None):
        # Keywords only when given, so an adapter without them still works.
        extra: dict = {}
        if force:
            extra["force"] = force
        if lowest:
            extra["lowest"] = lowest
        result = await adapter.trial(pins, floats, run, **extra)
        # The checks that judge this result run next, in this task: they see only its own
        # non-public versions (the public package of such a name is another).
        _TRIAL_NOT_PUBLIC.set(frozenset(result.non_public) if isinstance(result, TrialResult) else frozenset())
        if registry_yanks and isinstance(result, TrialResult) and result.status == "resolved":
            result = await with_registry_yanks(result)
        return result

    async def advisories(pkgs):
        from packagealert.languages.base import PackageSpec
        # A non-public version has no public advisories of its own: answered without a lookup.
        not_public = _TRIAL_NOT_PUBLIC.get()
        public = [p for p in pkgs if p not in not_public]
        found, failures = [], 0
        if public:
            db = await open_db(enabled_plugins=set(cfg.plugins.enabled))
            try:
                specs = [PackageSpec(name=n, version=v, ecosystem=adapter.ecosystem) for n, v in public]
                found, failures = await app_module._query_osv_findings(cfg, db, specs)
            finally:
                await db.close()
        ids: dict[tuple[str, str], set[str]] = {p: set() for p in pkgs}
        for f in found:
            key = (f["package"], f["version"])
            ids.setdefault(key, set()).update([f["advisory_id"], *(f.get("aliases") or [])])
        # _query_osv_findings counts degraded results without saying which;
        # if any lookup failed, none of these answers can prove "no new advisories".
        degraded = bool(failures)
        return {p: (frozenset(ids.get(p, set())), degraded and p not in not_public) for p in pkgs}

    async def age(pkg, ver):
        # A non-public version's age is unknown (its publication date is not the public
        # package's), which leaves the fix marked as not cooldown-checked.
        if (pkg, ver) in _TRIAL_NOT_PUBLIC.get():
            return None
        db = await open_db(enabled_plugins=set(cfg.plugins.enabled))
        try:
            return await app_module._publication_age(db, adapter.ecosystem, pkg, ver)
        finally:
            await db.close()

    parent_upgrade_hook = getattr(adapter, "parent_upgrade", None)

    async def parent_upgrade(parent, package, target):
        found = await cast("Callable[..., Awaitable[object]]", parent_upgrade_hook)(parent, package, target, run)
        # A malformed answer is treated as none.
        if isinstance(found, tuple) and len(found) == 2 and all(isinstance(x, str) for x in found):
            return found
        return None

    drift: tuple = ()
    drift_yanked: tuple = ()
    baseline_not_public: frozenset[tuple[str, str]] = frozenset()
    baseline = getattr(adapter, "baseline", None)
    if callable(baseline):
        say("checking what re-locking the project changes with nothing pinned")
        try:
            found = await cast("Callable[[object], Awaitable[object]]", baseline)(run)
            # None means the adapter could not tell; a malformed return is treated the same way.
            if (isinstance(found, TrialResult) and found.status == "resolved"
                    and all(isinstance(c, Change) for c in found.changes)):
                # Drift installs versions like any trial, so they get the same yank lookup.
                if registry_yanks:
                    found = await with_registry_yanks(found, baseline=True)
                drift, drift_yanked = found.changes, found.yanked
                baseline_not_public = frozenset(found.non_public)
        except Exception:  # noqa: BLE001 - without a baseline, trials are judged against the project lock
            app_module.log.warning("The %s adapter's baseline failed", adapter.name, exc_info=True)
    # The drift is judged before any trial, against the baseline's own provenance.
    token = _TRIAL_NOT_PUBLIC.set(baseline_not_public)
    try:
        verified = await verify_plan(
            plan, ecosystem=adapter.ecosystem, trial=trial, advisories=advisories, age=age,
            cooldown_days=cfg.sandbox.cooldown.period_days, allow_cooldown=allow_cooldown,
            allow_major=allow_major, progress=say, locked_yanks=locked_yanks,
            can_force=getattr(adapter, "can_force", False),
            pins_every_copy=getattr(adapter, "pins_every_copy", False), drift=drift,
            drift_yanked=drift_yanked,
            # An adapter whose resolver only moves a transitive package inside its
            # dependents' declared ranges holds only for majors of direct dependencies.
            major_only=direct if getattr(adapter, "transitive_majors_ok", False) is True else None,
            parallel=_parallel_trials(adapter),
            parent_upgrade=parent_upgrade if callable(parent_upgrade_hook) else None)
    finally:
        _TRIAL_NOT_PUBLIC.reset(token)
    return dataclasses.replace(verified, drift_unchecked=drift_unchecked)


def _plan_json(lockfile: Path, plan: FixPlan, cmds: list[list[str]], osv_failures: int,
               unverified_reason: str | None, cadences: dict[str, str | None], *, sync=None,
               yank_failures: int = 0, not_public: int = 0, apply: dict | None = None) -> dict:
    from packagealert.remediate import planner
    from packagealert.remediate.adapter import SyncSelection

    sync = sync if sync is not None else SyncSelection()

    data = {
        "lockfile": str(lockfile),
        "planned": [{
            "package": p.package, "version": p.version, "target": p.target,
            "direct": p.direct, "path": p.path, "advisories": p.advisories,
            "left_open": p.left_open, "fixes_all": p.fixes_all,
            "fixes_all_advisories": list(p.fixes_all_advisories), "cooldown_checked": p.cooldown_checked,
            "verified": p.verified,
            "changes": [dataclasses.asdict(c) for c in p.changes],
            "parent": {"package": p.parent[0], "version": p.parent[1]} if p.parent else None,
            "more_parents": [{"package": n, "version": v} for n, v in p.more_parents],
            "forced": {"under": p.forced[0], "declares": p.forced[1]} if p.forced else None,
            "by_relock": p.by_relock,
        } for p in plan.planned],
        "held": [{
            "package": h.package, "version": h.version, "target": h.target,
            "reason": h.reason, "advisories": h.advisories, "detail": h.detail,
            "cadence": cadences.get(_major_package(h)) if h.reason == planner.MAJOR else None,
            "needs_major": list(h.needs_major),
        } for h in plan.held],
        "commands": cmds,
        "command_changes": [dataclasses.asdict(c) for c in plan.command_changes],
        "yanked_locked": [dataclasses.asdict(y) for y in plan.yanked_locked],
        "trial_failure": plan.trial_failure,
        "lock_drift": [dataclasses.asdict(c) for c in plan.drift],
        "lock_drift_unchecked": plan.drift_unchecked,
        "sync": {"flags": list(sync.flags), "warning": sync.warning},
        "separate": plan.separate,
        "separate_reason": plan.separate_reason,
        "deferred": _deferred(plan),
        "osv_failures": osv_failures,
        # Locked packages from a private registry, git or a local path, not looked up publicly.
        "not_public": not_public,
        "yank_failures": yank_failures,
        "verified": unverified_reason is None,
        "unverified_reason": unverified_reason,
    }
    if apply is not None:
        data["apply"] = apply
    return data


def _deferred(plan: FixPlan) -> list[str]:
    """Planned packages not covered by this round's lock command (separate mode only)."""
    if not plan.separate or not plan.planned:
        return []
    return sorted(p.package for p in plan.planned)[1:]


_CADENCE_WHY = {
    "every-release": "bumps its major version every release",
    "calendar": "uses calendar versioning",
}


def _describe_changes(changes) -> str:
    parts = []
    shown: set[tuple[str, tuple[str, ...]]] = set()
    for c in changes:
        if c.fork_versions:
            # A forked package is one Change per introduced version; show it once.
            if (c.package, c.fork_versions) in shown:
                continue
            shown.add((c.package, c.fork_versions))
        new = ", ".join(c.fork_versions) if c.fork_versions else c.new
        if c.action == "update":
            parts.append(f"{c.package} {c.old} → {new}")
        elif c.action == "add":
            parts.append(f"adds {c.package} {new}")
        else:
            parts.append(f"removes {c.package}")
    return ", ".join(parts)


def _print_plan(out, lockfile: Path, plan: FixPlan, cmds: list[list[str]],
                osv_failures: int, *, checked: int, unverified_reason: str | None = None,
                cadences: dict[str, str | None] | None = None, sync=None, yank_failures: int = 0,
                not_public: int = 0) -> None:
    from packagealert.remediate import planner
    from packagealert.remediate.adapter import SyncSelection

    sync = sync if sync is not None else SyncSelection()

    cadences = cadences or {}
    hint = {planner.COOLDOWN: " (use --allow-cooldown)"}
    out.print(f"\nFix plan for {lockfile}\n", markup=False, highlight=False)
    if not plan.planned and not plan.held:
        if osv_failures:
            out.print(f"No vulnerabilities found in {checked - osv_failures} checked packages; "
                      f"{osv_failures} could not be checked.", style="yellow", markup=False)
        else:
            out.print(f"No known vulnerabilities in {checked} locked packages.", style="green", markup=False)
    if not_public:
        out.print(f"{not_public} locked package(s) come from a private registry, git or a local path and were "
                  f"not looked up in public advisory databases.", style="dim", markup=False)
    if plan.planned:
        if unverified_reason is not None:
            out.print(f"Plan NOT verified ({unverified_reason}) — commands may fail or change other packages.",
                      style="yellow", markup=False, highlight=False)
        out.print(f"Planned ({len(plan.planned)}):", style="bold", markup=False)
        for p in plan.planned:
            fixed = [a for a in p.advisories if a not in p.left_open]
            note = " (not verified)" if unverified_reason is not None else ""
            out.print(f"  {p.package} {p.version} → {p.target}  fixes {', '.join(fixed)}{note}",
                      style="green", markup=False, highlight=False)
            if p.all_parents:
                out.print("    with " + ", ".join(f"{n} {v}" for n, v in p.all_parents), markup=False, highlight=False)
            if p.forced:
                # Every dependent's range admits the target (checked before planning
                # one); the override is needed because npm keeps a locked version its
                # range still allows.
                out.print(f"    pins {p.package} to {p.target} with a temporary override: npm would keep the "
                          f"locked {p.version}, though {p.forced[1]} under {p.forced[0]} allows {p.target}",
                          style="yellow", markup=False, highlight=False)
            if p.by_relock:
                out.print("    re-locking the project moves it there (the lock is out of date)",
                          style="dim", markup=False, highlight=False)
            if not p.cooldown_checked:
                out.print("    (age unknown — cooldown not checked)", style="yellow", markup=False)
            if not p.direct and len(p.path) > 1:
                out.print(f"    via {' ← '.join(reversed(p.path))}", style="dim", markup=False, highlight=False)
            if p.left_open:
                # Credit the major version only with what it fixes; the rest has no known fix.
                which = ("" if not p.fixes_all_advisories or set(p.fixes_all_advisories) >= set(p.left_open)
                         else f"{', '.join(p.fixes_all_advisories)} ")
                rest = (f" ({which}fixed in {p.fixes_all}, a new major version: use --allow-major {p.package})"
                        if p.fixes_all else "")
                out.print(f"    still open after this: {', '.join(p.left_open)}{rest}",
                          style="yellow", markup=False, highlight=False)
        if plan.separate:
            why = f": {plan.separate_reason}" if plan.separate_reason else ""
            out.print(f"\nThese fixes could not be verified as one command{why}. Only the first is printed.",
                      style="yellow", markup=False, highlight=False)
        out.print("\nCommands:", style="bold", markup=False)
        for argv in cmds:
            out.print(f"  {shlex.join(argv)}", markup=False, highlight=False, soft_wrap=True)
        if sync.flags:
            out.print("  (sync flags match what .venv has installed)", style="dim", markup=False)
        if sync.warning:
            out.print(f"  ⚠ {sync.warning}", style="yellow", markup=False, highlight=False)
        if plan.command_changes:
            out.print(f"  Also changes: {_describe_changes(plan.command_changes)}",
                      style="dim", markup=False, highlight=False)
        if deferred := _deferred(plan):
            out.print(f"\nNext, after applying that and re-running pa fix: {', '.join(deferred)}",
                      style="yellow", markup=False, highlight=False)
    if plan.drift:
        out.print(f"\n⚠ {lockfile.name} is out of date: re-locking it changes {len(plan.drift)} package(s) "
                  f"with nothing pinned, and every command below makes these changes too:",
                  style="yellow", markup=False, highlight=False)
        for c in plan.drift[:10]:
            move = f"{c.old} → {c.new}" if c.old and c.new else (f"+{c.new}" if c.new else f"-{c.old}")
            out.print(f"  {c.package} {move}", style="yellow", markup=False, highlight=False)
        if len(plan.drift) > 10:
            out.print(f"  … and {len(plan.drift) - 10} more (see --format json)", style="yellow", markup=False)
    if plan.yanked_locked:
        unchanged = " (these commands do not change them)" if plan.planned else ""
        out.print(f"\nAlready locked and yanked{unchanged}:", style="yellow", markup=False)
        for y in plan.yanked_locked:
            reason = f" ({y.reason})" if y.reason else ""
            out.print(f"  {y.package} {y.version}{reason}", style="yellow", markup=False, highlight=False)
    if yank_failures:
        out.print(f"⚠ Yank status unavailable for {yank_failures} package(s)", style="yellow", markup=False)
    if plan.held:
        if plan.trial_failure:
            out.print("\nEvery trial resolve failed the same way, so no fix could be verified:",
                      style="bold yellow", markup=False)
            out.print(f"  {plan.trial_failure}", style="yellow", markup=False, highlight=False)
        out.print(f"\nHeld back ({len(plan.held)}):", style="bold yellow", markup=False)
        for h in plan.held:
            if h.reason == planner.MALICIOUS:
                out.print(f"  {h.package} {h.version or ''}  {h.reason}: remove it; do not upgrade"
                          f"  ({', '.join(h.advisories)})", style="red", markup=False, highlight=False)
                continue
            target = f" → {h.target}" if h.target else ""
            if plan.trial_failure and h.reason == planner.COULD_NOT_VERIFY and h.detail == plan.trial_failure:
                detail = " (the error above)"
            else:
                detail = f": {h.detail}" if h.detail else ""
            if h.reason == planner.MAJOR:
                label = _major_package(h)
                why = _CADENCE_WHY.get(cadences.get(label) or "")
                routine = f" — routine for {label} ({why})" if why else ""
                hint_text = f"{routine} (use --allow-major {','.join(h.needs_major) or h.package})"
            else:
                hint_text = hint.get(h.reason, "")
            out.print(f"  {h.package} {h.version or ''}{target}  {h.reason}{detail}{hint_text}"
                      f"  ({', '.join(h.advisories)})", style="yellow", markup=False, highlight=False)
    if osv_failures:
        out.print(f"\n⚠ OSV lookup unavailable for {osv_failures} package(s) — these were "
                  f"NOT fully checked for advisories", style="yellow", markup=False)
