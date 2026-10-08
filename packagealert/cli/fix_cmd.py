"""`pa fix`: plan the upgrade commands that remove known vulnerabilities."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING, cast

import typer
from rich.console import Console

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from packagealert.remediate.adapter import RunFn, Yank
    from packagealert.remediate.planner import FixPlan

# pa fix discovers its package-manager adapter through the language registry
# (remediate.adapter.discover); the registry and adapters are imported inside
# _run_fix so `pa` stays as fast to start as before.


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
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config TOML file."),
):
    """Plan upgrade commands that fix vulnerable packages. Prints the commands; changes nothing in the project."""
    from packagealert.cli.app import _load, console

    if fmt not in ("text", "json"):
        console.print("--format must be one of: text, json", style="red", markup=False)
        raise typer.Exit(2)
    try:
        cli_allow_major = _parse_allow_major(allow_major)
    except ValueError as exc:
        console.print(str(exc), style="red", markup=False)
        raise typer.Exit(2) from None
    cfg, _ = _load(config)
    code = asyncio.run(_run_fix(cfg, path.resolve(), allow_major=cli_allow_major,
                                allow_cooldown=allow_cooldown, fmt=fmt,
                                verify=not no_verify,
                                allow_project_env=allow_project_env))
    raise typer.Exit(code)


_PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")


def _parse_allow_major(values: list[str]) -> frozenset[str]:
    """Package names from repeated/comma-separated values, ``all`` as ``"*"``.

    Raises ValueError (with the message to show) for a value that names nothing
    or is not a package name, such as a path.
    """
    from packagealert.cli.run_settings import normalise_package_names

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
        names |= {"*" if n == "all" else n for n in normalise_package_names(parts)}
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
                    verify: bool = True, allow_project_env: bool = False) -> int:
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
                                      verify=verify, allow_project_env=allow_project_env,
                                      out=out, console=console, say=status.update, pause=paused)
    finally:
        status.stop()


async def _plan_and_report(cfg, root: Path, *, allow_major: frozenset[str], allow_cooldown: bool, fmt: str,
                           verify: bool, allow_project_env: bool, out, console,
                           say: Callable[[str], object],
                           pause: Callable[[], contextlib.AbstractContextManager[None]]) -> int:
    from packagealert.cli import app as app_module
    from packagealert.cli.run_settings import (
        ProjectRunSettings,
        RunSettingsError,
        normalise_package_names,
        resolve_project_run_settings,
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
    standing = normalise_package_names(cfg.fix.allow_major)
    if settings is not None:
        standing |= settings.allow_major
    allowed_major = (standing - {"*"}) | allow_major

    yank_failures = 0
    locked_yanks: tuple[Yank, ...] = ()
    db = await open_db(enabled_plugins=set(cfg.plugins.enabled))
    try:
        say(f"Checking {len(packages)} locked packages against OSV…")
        findings, osv_failures = await app_module._query_osv_findings(cfg, db, packages)
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
    )
    unverified_reason: str | None = None
    verified = False
    runner = None
    if plan.planned:
        runner, blocked = _captured_runner(cfg, adapter, lockfile.parent, settings, console, pause)
        if verify:
            plan, unverified_reason = await _verify(cfg, adapter, lockfile, plan, allow_cooldown, allowed_major, console,
                                                    settings, settings_error, say=say, runner=runner,
                                                    blocked=blocked, locked_yanks=locked_yanks)
            verified = unverified_reason is None
        else:
            unverified_reason = "--no-verify"
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
    if fmt == "json":
        print(json.dumps(_plan_json(lockfile, plan, cmds, osv_failures, unverified_reason, cadences,
                                    sync=selection, yank_failures=yank_failures), indent=2))
    else:
        _print_plan(out, lockfile, plan, cmds, osv_failures, checked=len(packages),
                    unverified_reason=unverified_reason, cadences=cadences, sync=selection,
                    yank_failures=yank_failures)
    return 0 if plan.complete and not osv_failures and unverified_reason is None else 1


SYNC_UNCHECKED = ("Could not check which extras or groups the project's environment was installed with; "
                  "a plain sync may remove packages installed from them.")


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
        argv = adapter.trial_argv([], [])
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


async def _verify(cfg, adapter, lockfile: Path, plan: FixPlan, allow_cooldown: bool, allow_major: frozenset[str], console,
                  settings, settings_error: str | None,
                  say: Callable[[str], object] = lambda _message: None,
                  runner=None, blocked: str | None = None,
                  locked_yanks: tuple[Yank, ...] = ()) -> tuple[FixPlan, str | None]:
    """Trial-resolve each planned pin. Returns (plan, None), or (original plan, reason) when trials cannot run.

    A trial that fails for one pin holds that pin; it does not discard the rest.
    """
    from packagealert.cli import app as app_module
    from packagealert.remediate.verify import verify_plan
    from packagealert.sandbox.runner import SandboxRunner, bwrap_available
    from packagealert.storage.db import open_db

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

    async def trial(pins, floats):
        pinned = dict(pins)
        out = await runner.run_captured(adapter.trial_argv(pins, floats), cwd=project_dir,
                                        flags=settings.flags, extra_env=settings.env)
        return adapter.parse_trial(out.returncode, out.stderr, timed_out=out.timed_out, pinned=pinned)

    async def advisories(pkgs):
        from packagealert.languages.base import PackageSpec
        db = await open_db(enabled_plugins=set(cfg.plugins.enabled))
        try:
            specs = [PackageSpec(name=n, version=v, ecosystem=adapter.ecosystem) for n, v in pkgs]
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
        return {p: (frozenset(ids.get(p, set())), degraded) for p in pkgs}

    async def age(pkg, ver):
        db = await open_db(enabled_plugins=set(cfg.plugins.enabled))
        try:
            return await app_module._publication_age(db, adapter.ecosystem, pkg, ver)
        finally:
            await db.close()

    verified = await verify_plan(plan, ecosystem=adapter.ecosystem, trial=trial, advisories=advisories, age=age,
                                 cooldown_days=cfg.sandbox.cooldown.period_days, allow_cooldown=allow_cooldown,
                                 allow_major=allow_major, progress=say, locked_yanks=locked_yanks)
    return verified, None


def _plan_json(lockfile: Path, plan: FixPlan, cmds: list[list[str]], osv_failures: int,
               unverified_reason: str | None, cadences: dict[str, str | None], *, sync=None,
               yank_failures: int = 0) -> dict:
    from packagealert.remediate import planner
    from packagealert.remediate.adapter import SyncSelection

    sync = sync if sync is not None else SyncSelection()

    return {
        "lockfile": str(lockfile),
        "planned": [{
            "package": p.package, "version": p.version, "target": p.target,
            "direct": p.direct, "path": p.path, "advisories": p.advisories,
            "left_open": p.left_open, "cooldown_checked": p.cooldown_checked,
            "verified": p.verified,
            "changes": [dataclasses.asdict(c) for c in p.changes],
            "parent": {"package": p.parent[0], "version": p.parent[1]} if p.parent else None,
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
        "sync": {"flags": list(sync.flags), "warning": sync.warning},
        "separate": plan.separate,
        "separate_reason": plan.separate_reason,
        "deferred": _deferred(plan),
        "osv_failures": osv_failures,
        "yank_failures": yank_failures,
        "verified": unverified_reason is None,
        "unverified_reason": unverified_reason,
    }


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
                cadences: dict[str, str | None] | None = None, sync=None, yank_failures: int = 0) -> None:
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
            if p.parent:
                out.print(f"    with {p.parent[0]} {p.parent[1]}", markup=False, highlight=False)
            if not p.cooldown_checked:
                out.print("    (age unknown — cooldown not checked)", style="yellow", markup=False)
            if not p.direct and len(p.path) > 1:
                out.print(f"    via {' ← '.join(reversed(p.path))}", style="dim", markup=False, highlight=False)
            if p.left_open:
                out.print(f"    still open after this: {', '.join(p.left_open)}",
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
