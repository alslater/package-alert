from __future__ import annotations

import asyncio
import atexit
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import types
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from packagealert.config import load_config
from packagealert.logging_setup import configure_logging
from packagealert.daemon_pid import check_already_running, is_started_by_systemd, PID_FILE
from packagealert.plugins.registry import plugin_registry

log = logging.getLogger(__name__)

app = typer.Typer(
    name="package-alert",
    help="package-alert: Real-time developer security monitor for Python, Node.js, and PHP packages.",
)
console = Console()

_update_thread: threading.Thread | None = None
_atexit_registered = False


def _pipx_venvs_candidates() -> list[Path]:
    pipx_home = os.environ.get("PIPX_HOME")
    if pipx_home:
        return [Path(pipx_home).expanduser() / "venvs"]
    return [
        Path("~/.local/pipx/venvs").expanduser(),
        Path("~/.local/share/pipx/venvs").expanduser(),
    ]


def _uv_tool_dirs_candidates() -> list[Path]:
    uv_tool_dir = os.environ.get("UV_TOOL_DIR")
    if uv_tool_dir:
        return [Path(uv_tool_dir).expanduser()]
    return [Path("~/.local/share/uv/tools").expanduser()]


def _exe_is_under(candidates: list[Path]) -> bool:
    # Do NOT resolve symlinks — venv Pythons are symlinks to the system Python,
    # so resolve() would return /usr/bin/pythonX.Y and break the path check.
    # Normalise both exe and candidates with absolute() so relative paths (e.g.
    # from PIPX_HOME or UV_TOOL_DIR) match correctly regardless of call site.
    exe = Path(sys.executable).absolute()
    abs_candidates = [c.absolute() for c in candidates]
    for candidate in abs_candidates:
        try:
            exe.relative_to(candidate)
            return True
        except ValueError:
            continue
    return False


def _is_pipx_install() -> bool:
    return _exe_is_under(_pipx_venvs_candidates())


def _is_uv_tool_install() -> bool:
    return _exe_is_under(_uv_tool_dirs_candidates())


def _is_interactive() -> bool:
    return sys.stderr.isatty()


def _daemon_cmdline(pid: int) -> list[str] | None:
    """Return the original command line of *pid* by reading /proc/<pid>/cmdline, or None on error."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return [arg.decode(errors="replace") for arg in raw.rstrip(b"\x00").split(b"\x00")]
    except OSError:
        return None


schedule_app = typer.Typer(help="Manage projects registered for scheduled scans.")
app.add_typer(schedule_app, name="schedule")

scans_app = typer.Typer(help="List and display completed scheduled scan results.")
app.add_typer(scans_app, name="scans")

from packagealert.cli.languages_cmd import languages_app  # noqa: E402
app.add_typer(languages_app, name="languages")

from packagealert.cli.setup_cmd import cooldown_app, setup_app  # noqa: E402
app.add_typer(setup_app, name="setup")
app.add_typer(cooldown_app, name="cooldown")

from packagealert.cli.plugins import central_app  # noqa: E402
app.add_typer(central_app, name="central")

_cfg_option = typer.Option(None, "--config", "-c", help="Path to config TOML file.")

_verbose: bool = False
_plugin_commands_registered: bool = False


def _config_path_from_argv() -> "Path | None":
    """Extract --config / -c <path> from sys.argv without a full parse.

    Used during early plugin registration so that plugins enabled via
    ``pa --config <path> <cmd>`` have their CLI sub-apps registered.
    Handles all three forms: ``--config PATH``, ``--config=PATH``, ``-c PATH``,
    and ``-cPATH``.
    """
    import sys
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg in ("--config", "-c"):
            if i + 1 < len(args):
                return Path(args[i + 1])
        elif arg.startswith("--config="):
            value = arg[len("--config="):]
            if value:
                return Path(value)
        elif arg.startswith("-c") and len(arg) > 2:
            return Path(arg[2:])
    return None


def _register_plugin_commands() -> None:
    """Load enabled plugin entry points and register their CLI sub-apps.

    Called once from the Typer callback so that config I/O and plugin imports
    happen at command invocation time, not at module import time.  Reads
    --config / -c from sys.argv so that plugins enabled via a non-default
    config file also get their commands registered.
    """
    global _plugin_commands_registered
    if _plugin_commands_registered:
        return
    _plugin_commands_registered = True
    import logging as _logging
    from packagealert.config import read_enabled_plugins as _read_enabled_plugins
    from packagealert.plugins.registry import _load_entry_points as _lep
    argv_config = _config_path_from_argv()
    if argv_config is not None:
        argv_config = _apply_config_veto(argv_config, _read_enabled_plugins, _lep, warn=False)
    _enabled_plugin_names = set(_read_enabled_plugins(argv_config))
    for _name, _cls in plugin_registry.load_classes(only=_enabled_plugin_names).items():
        try:
            for _plugin_app in _cls.get_cli_commands():
                app.add_typer(_plugin_app)
        except Exception:
            _logging.getLogger(__name__).warning(
                "Failed to register CLI commands for plugin %r", _name, exc_info=True
            )


@app.callback()
def _main(verbose: bool = typer.Option(False, "--verbose", "-v", help="Show log output on the console.")):
    global _verbose, _update_thread, _atexit_registered
    _verbose = verbose
    _register_plugin_commands()

    if not _is_interactive():
        return

    from packagealert.update_check import read_notice, check_and_cache, is_cache_stale

    notice = read_notice()
    if notice:
        Console(stderr=True).print(f"[dim yellow]{notice}[/dim yellow]")

    stale = is_cache_stale()

    if stale and _update_thread is None:
        def _bg():
            asyncio.run(check_and_cache())

        _update_thread = threading.Thread(target=_bg, daemon=True)
        _update_thread.start()

        if not _atexit_registered:
            def _join():
                if _update_thread is not None:
                    _update_thread.join(timeout=2.0)
            atexit.register(_join)
            _atexit_registered = True


def _apply_config_veto(
    config: Path,
    read_enabled_plugins,
    load_entry_points,
    *,
    warn: bool = True,
) -> Path | None:
    """Return config if no enabled plugin vetoes it, None if vetoed.

    Two-pass strategy to ensure default-config veto plugins are checked before
    any candidate-config-only plugin code is imported:
    1. Resolve default-config enabled plugins; if any veto, return None immediately
       without importing anything from the candidate config.
    2. Only if pass 1 is clear: resolve plugins newly introduced by the candidate
       and check those for vetoes too.
    """
    default_enabled = set(read_enabled_plugins(None))
    default_classes = load_entry_points(only=default_enabled)
    for name, cls in default_classes.items():
        try:
            vetoes = cls.refuses_config_override()
        except Exception:
            log.warning("Plugin %r raised in refuses_config_override — treating as veto", name, exc_info=True)
            vetoes = True
        if vetoes:
            if warn:
                Console(stderr=True).print(
                    f"Warning: --config ignored because plugin '{name}' "
                    "enforces central policy.",
                    style="yellow",
                )
            return None

    candidate_only = set(read_enabled_plugins(config)) - default_enabled
    candidate_classes = load_entry_points(only=candidate_only)
    for name, cls in candidate_classes.items():
        try:
            vetoes = cls.refuses_config_override()
        except Exception:
            log.warning("Plugin %r raised in refuses_config_override — treating as veto", name, exc_info=True)
            vetoes = True
        if vetoes:
            if warn:
                Console(stderr=True).print(
                    f"Warning: --config ignored because plugin '{name}' "
                    "enforces central policy.",
                    style="yellow",
                )
            return None

    return config


def _load(config: Optional[Path], *, daemon: bool = False):
    if config is not None:
        from packagealert.config import read_enabled_plugins as _rep
        from packagealert.plugins.registry import _load_entry_points as _lep
        config = _apply_config_veto(config, _rep, _lep)
    cfg = load_config(config)
    configure_logging(cfg.log if daemon else cfg.cli_log, verbose=_verbose)
    if not daemon:
        plugin_registry.load(cfg, config_path=config)
    return cfg, config


@app.command()
def daemon(
    config: Optional[Path] = _cfg_option,
    background: bool = typer.Option(False, "--background", "-b", help="Daemonise: fork into the background and return immediately."),
):
    """Start the package-alert monitoring daemon."""
    from packagealert.daemon import Daemon, check_already_running
    existing_pid = check_already_running()
    if existing_pid:
        console.print(f"[red]Daemon is already running (pid {existing_pid}). Exiting.[/red]")
        raise typer.Exit(1)

    if background:
        # Double-fork so the daemon is fully detached from the terminal.
        pid = os.fork()
        if pid > 0:
            console.print(f"[dim]Daemon started in background (pid {pid}).[/dim]")
            raise typer.Exit(0)
        os.setsid()
        pid2 = os.fork()
        if pid2 > 0:
            os._exit(0)
        # Redirect stdio so the detached process has no terminal handles.
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(devnull, fd)
        os.close(devnull)

    cfg, effective_config_path = _load(config, daemon=True)
    d = Daemon(cfg, config_path=effective_config_path)
    asyncio.run(d.run())


@app.command()
def status(
    config: Optional[Path] = _cfg_option,
    json_output: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Show daemon running state, recent alerts, and configuration summary."""
    # Skips configure_logging intentionally — status is a read-only diagnostic check
    from packagealert.cli.status import gather_status, render_status
    data = asyncio.run(gather_status(config))
    render_status(data, as_json=json_output)


@app.command("scan-cache")
def scan_cache(config: Optional[Path] = _cfg_option):
    """Scan package manager caches for malicious packages."""
    cfg, _ = _load(config)
    asyncio.run(_run_scan_cache(cfg))


async def _run_scan_cache(cfg):
    from packagealert.osv.client import OsvClient
    from packagealert.osv.cache import OsvCache
    from packagealert.storage.db import open_db
    from packagealert.models.events import PackageEvent, normalise_ecosystem
    from packagealert.alerts.terminal import alert_malicious
    from packagealert.languages import registry as lang_registry
    from datetime import datetime, timezone

    db = await open_db()
    osv_client = OsvClient(cfg.osv)
    osv_cache = OsvCache(db, cfg.osv)
    found = 0

    lang_registry.load()
    for lang in lang_registry.all_languages():
        try:
            globs = lang.cache_file_globs()
            cache_dirs = lang.cache_paths()
        except Exception:
            log.warning(
                "cache_file_globs/cache_paths raised unexpectedly for lang=%s — skipping",
                getattr(lang, "name", "?"), exc_info=True,
            )
            continue
        if not globs:
            continue
        for cache_dir in cache_dirs:
            if not cache_dir.exists():
                continue
            seen: set[Path] = set()
            for glob in globs:
                for entry in cache_dir.glob(glob):
                    if entry in seen:
                        continue
                    seen.add(entry)
                    try:
                        metadata = lang.classify_cache_file(entry)
                    except Exception:
                        log.warning(
                            "classify_cache_file raised unexpectedly for lang=%s path=%s — skipping",
                            getattr(lang, "name", "?"), entry, exc_info=True,
                        )
                        continue
                    if not metadata or not metadata.version:
                        continue
                    result = await osv_cache.get(metadata.ecosystem.lower(), metadata.name, metadata.version)
                    if result is None:
                        results = await osv_client.batch_query([(metadata.ecosystem.lower(), metadata.name, metadata.version)])
                        if results:
                            result = results[0]
                            await osv_cache.set(metadata.ecosystem.lower(), metadata.name, metadata.version, result)
                    if result and result.has_malicious:
                        try:
                            _eco = normalise_ecosystem(metadata.ecosystem)
                        except ValueError:
                            continue
                        ev = PackageEvent(
                            ecosystem=_eco,
                            package_name=metadata.name,
                            version=metadata.version,
                            source="cache",
                            manager="unknown",
                            project_path=None,
                            timestamp=datetime.now(timezone.utc),
                        )
                        alert_malicious(ev, result)
                        found += 1

    console.print(f"Scan complete. [bold red]{found}[/bold red] malicious package(s) found.")
    await osv_client.aclose()
    await db.close()


@app.command()
def query(
    package: str = typer.Argument(..., help="Package name"),
    version: Optional[str] = typer.Argument(None, help="Package version"),
    ecosystem: str = typer.Option("pypi", "--ecosystem", "-e", help="OSV ecosystem identifier, e.g. pypi, npm, packagist, maven, crates.io, rubygems, nuget, go."),
    config: Optional[Path] = _cfg_option,
):
    """Query OSV for a specific package."""
    cfg, _ = _load(config)
    asyncio.run(_run_query(cfg, ecosystem, package, version))


async def _run_query(cfg, ecosystem: str, package: str, version: Optional[str]):
    from packagealert.osv.client import OsvClient
    from packagealert.osv.cache import OsvCache
    from packagealert.storage.db import open_db

    db = await open_db()
    client = OsvClient(cfg.osv)
    cache = OsvCache(db, cfg.osv)

    result = await cache.get(ecosystem, package, version)
    if result is None:
        results = await client.batch_query([(ecosystem, package, version)])
        result = results[0] if results else None
        if result:
            await cache.set(ecosystem, package, version, result)

    if result and result.advisories:
        for adv in result.advisories:
            colour = "red" if adv.is_malicious else "yellow"
            label = "[MALICIOUS]" if adv.is_malicious else "[VULN]"
            console.print(f"[bold {colour}]{label} {adv.id}[/bold {colour}] https://osv.dev/vulnerability/{adv.id}")
            if adv.summary:
                console.print(f"  Summary:  {adv.summary}")
            if adv.details:
                console.print(f"  Details:  {adv.details.strip()}")
            if adv.severity:
                console.print(f"  Severity: {adv.severity}")
            if adv.aliases:
                console.print(f"  Aliases:  {', '.join(adv.aliases)}")
    else:
        console.print(
            f"[green]No advisories found for {ecosystem}/{package}"
            f"{' ' + version if version else ''}[/green]"
        )

    await client.aclose()
    await db.close()


@app.command()
def alerts(
    limit: int = typer.Option(50, "--limit", "-n", help="Number of recent alerts to show"),
    config: Optional[Path] = _cfg_option,
):
    """Show recent alerts from the database."""
    cfg, _ = _load(config)
    asyncio.run(_run_alerts(cfg, limit))


async def _run_alerts(cfg, limit: int):
    import datetime as dt
    from packagealert.storage.db import open_db

    db = await open_db()
    table = Table(title="Recent Alerts")
    table.add_column("Package", style="bold")
    table.add_column("Ecosystem")
    table.add_column("Version")
    table.add_column("Advisory / Score")
    table.add_column("Project Path")
    table.add_column("Time")

    async with db.execute(
        "SELECT * FROM alerts ORDER BY alerted_at DESC LIMIT ?", (limit,)
    ) as cur:
        rows = await cur.fetchall()

    for row in rows:
        ts = dt.datetime.fromtimestamp(row["alerted_at"]).isoformat(timespec="seconds")
        advisory_or_score = row["advisory_id"] or (
            f"risk:{row['risk_score']}" if row["risk_score"] else ""
        )
        table.add_row(
            row["package_name"],
            row["ecosystem"],
            row["version"] or "",
            advisory_or_score,
            row["project_path"] or "",
            ts,
        )

    console.print(table)
    await db.close()


_SEVERITY_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _severity_colour(adv) -> str:
    if adv.severity:
        return _SEVERITY_COLOUR.get(adv.severity.upper(), "yellow")
    return "red" if adv.is_malicious else "yellow"


@app.command("scan-project")
def scan_project(
    path: Path = typer.Argument(Path("."), help="Project directory to scan."),
    scan_unpinned: bool = typer.Option(False, "--scan-unpinned", help="Query OSV for unpinned dependencies too."),
    scan_installed: bool = typer.Option(False, "--scan-installed", help="Scan venv/.venv or node_modules instead of lock files."),
    prod_only: bool = typer.Option(False, "--prod-only", help="Exclude dev dependencies from the scan. Mutually exclusive with --scan-installed. With --requirements, dev/prod is undetectable so all packages are included with a warning."),
    requirements: Optional[Path] = typer.Option(None, "--requirements", "-r", help="Explicit requirements file to scan (overrides auto-detection)."),
    details: bool = typer.Option(False, "--details", "-d", help="Show full advisory details."),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format: text, json, html."),
    config: Optional[Path] = _cfg_option,
):
    """Scan a project's lock files for malicious or vulnerable packages."""
    if fmt not in ("text", "json", "html", "browser"):
        console.print("[red]--format must be one of: text, json, html, browser[/red]")
        raise typer.Exit(1)
    if requirements is not None and scan_installed:
        console.print("[red]--requirements and --scan-installed are mutually exclusive[/red]")
        raise typer.Exit(1)
    if prod_only and scan_installed:
        console.print("[red]--prod-only and --scan-installed are mutually exclusive (installed environments have no dev/prod distinction)[/red]")
        raise typer.Exit(1)
    root = path.resolve()
    if requirements is not None:
        # Resolve relative to the project root so that `-r requirements-lock.txt`
        # works correctly when PATH is not the current working directory.
        requirements = (root / requirements).resolve()
        if not requirements.exists():
            console.print(f"[red]Requirements file not found: {requirements}[/red]")
            raise typer.Exit(1)
        if not requirements.is_file():
            console.print(f"[red]--requirements must be a file, not a directory: {requirements}[/red]")
            raise typer.Exit(1)
    cfg, _ = _load(config)
    asyncio.run(_run_scan_project(cfg, root, scan_unpinned, scan_installed, details, fmt, requirements=requirements, prod_only=prod_only))


async def _run_scan_project(
    cfg, root: Path, scan_unpinned: bool, installed: bool, show_details: bool, fmt: str,
    requirements: Optional[Path] = None,
    prod_only: bool = False,
):
    import json as jsonlib
    from packagealert.osv.client import OsvClient
    from packagealert.osv.cache import OsvCache
    from packagealert.storage.db import open_db
    from packagealert.parsers.lockfiles import (
        scan_project as detect_project,
        scan_installed as detect_installed,
        collect_requirements_packages,
        ProjectScan,
    )

    if requirements is not None:
        pinned, unpinned = collect_requirements_packages(requirements)
        result = ProjectScan(
            sources=[f"pypi ({requirements.name})"],
            pinned=pinned,
            unpinned=unpinned,
            dev_undetectable=[requirements.name] if prod_only else [],
        )
    elif installed:
        result = detect_installed(root)
    else:
        result = detect_project(root, prod_only=prod_only)

    if prod_only and result.dev_undetectable:
        warn_console = Console(stderr=True)
        for src in result.dev_undetectable:
            warn_console.print(
                f"Warning: {src} — some packages could not be classified as dev or prod and were included in the scan.",
                style="yellow",
                markup=False,
            )

    if not result.sources:
        console.print(f"[yellow]No supported lock files found in {root}[/yellow]")
        return

    to_query = list(result.pinned)
    if scan_unpinned:
        to_query.extend(result.unpinned)

    db = await open_db()
    osv_client = OsvClient(cfg.osv)
    osv_cache = OsvCache(db, cfg.osv)

    findings = []  # list of dicts for structured output

    batch_size = 50
    for i in range(0, len(to_query), batch_size):
        batch = to_query[i:i + batch_size]
        queries = [(p.ecosystem, p.name, p.version) for p in batch]

        cached = []
        uncached_queries = []
        for pkg, q in zip(batch, queries):
            osv_result = await osv_cache.get(*q)
            if osv_result is not None:
                cached.append(osv_result)
            else:
                uncached_queries.append(q)

        fresh = []
        if uncached_queries:
            fresh = await osv_client.batch_query(uncached_queries)
            for q, r in zip(uncached_queries, fresh):
                if r:
                    ecosystem, name, version = q
                    await osv_cache.set(ecosystem, name, version, r)

        for osv_result in cached + fresh:
            if not osv_result or not osv_result.advisories:
                continue
            for adv in osv_result.advisories:
                findings.append({
                    "package": osv_result.package_name,
                    "ecosystem": osv_result.ecosystem,
                    "version": osv_result.version,
                    "advisory_id": adv.id,
                    "is_malicious": adv.is_malicious,
                    "severity": adv.severity,
                    "summary": adv.summary,
                    "details": adv.details,
                    "fixed_versions": adv.fixed_versions,
                    "url": f"https://osv.dev/vulnerability/{adv.id}",
                })

    await osv_client.aclose()
    await db.close()

    from packagealert.models.scans import ScanResult
    from datetime import datetime, timezone
    scan = ScanResult(
        project_path=str(root),
        scan_type="installed" if installed else "project",
        finding_count=len(findings),
        findings=findings,
        sources=result.sources,
        scanned_at=datetime.now(timezone.utc),
    )
    await plugin_registry.fire_on_scan_complete(scan)

    unpinned_list = [{"name": p.name, "ecosystem": p.ecosystem} for p in result.unpinned]

    if fmt == "json":
        print(jsonlib.dumps({
            "root": str(root),
            "sources": result.sources,
            "unpinned": unpinned_list,
            "findings": findings,
        }, indent=2))
        return

    if fmt in ("html", "browser"):
        html = _render_html(root, result.sources, unpinned_list, findings)
        if fmt == "browser":
            open_html_in_browser(html)
        else:
            print(html)
        return

    # text output
    console.print(f"\nScanning [bold]{root}[/bold]")
    console.print(f"Detected: {', '.join(result.sources)}\n")

    if result.unpinned:
        console.print(f"[yellow]⚠ {len(result.unpinned)} unpinned dependenc{'y' if len(result.unpinned) == 1 else 'ies'} found:[/yellow]")
        for pkg in result.unpinned:
            console.print(f"  [yellow]- {pkg.name}[/yellow]")
        if not scan_unpinned:
            console.print("[dim]  (use --scan-unpinned to query OSV for these)[/dim]\n")
        else:
            console.print()

    if not to_query:
        console.print("[green]Nothing to scan.[/green]")
        return

    malicious = 0
    vulnerable = 0
    for f in findings:
        adv_obj = types.SimpleNamespace(**f)
        colour = _severity_colour(adv_obj)
        label = "[MALICIOUS]" if f["is_malicious"] else "[VULN]"
        severity_tag = f" [{f['severity']}]" if f["severity"] else ""
        summary_tag = f" — {f['summary']}" if f["summary"] else ""
        console.print(f"[{colour}]{label} {f['advisory_id']}{severity_tag}[/{colour}] {f['package']}@{f['version'] or 'unpinned'}{summary_tag}", highlight=False)
        if f.get("fixed_versions"):
            console.print(f"  [green]→ upgrade to: {', '.join(f['fixed_versions'])}[/green]")
        if show_details:
            if f["details"]:
                console.print(f"  {f['details'].strip()}", highlight=False)
            console.print(f"  {f['url']}")
        if f["is_malicious"]:
            malicious += 1
        else:
            vulnerable += 1

    console.print(f"\nScan complete: [bold red]{malicious} malicious[/bold red], [bold yellow]{vulnerable} vulnerable[/bold yellow], "
                  f"[yellow]{len(result.unpinned)} unpinned[/yellow] ({len(to_query)} packages checked)")


def open_html_in_browser(html: str) -> None:
    """Write *html* to a temp file and open it in the default browser."""
    import tempfile
    import webbrowser
    from rich.console import Console
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", prefix="package-alert-", dir="/tmp", delete=False
    ) as f:
        f.write(html)
        tmp_path = f.name
    webbrowser.open(f"file://{tmp_path}")
    Console().print(f"[dim]Report opened in browser: {tmp_path}[/dim]")


def _render_html(root: Path, sources: list, unpinned: list, findings: list, *, scanned_at: str = "") -> str:
    from html import escape
    malicious = sum(1 for f in findings if f["is_malicious"])
    vulnerable = len(findings) - malicious

    _SEVERITY_BG = {"CRITICAL": "#7f1d1d", "HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#16a34a"}

    def badge(f: dict) -> str:
        label = "MALICIOUS" if f["is_malicious"] else f.get("severity") or "VULN"
        bg = "#7f1d1d" if f["is_malicious"] else _SEVERITY_BG.get((f.get("severity") or "").upper(), "#d97706")
        return f'<span style="background:{bg};color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;font-weight:bold">{escape(label)}</span>'

    rows = ""
    for f in findings:
        fix_cell = escape(", ".join(f.get("fixed_versions") or [])) or "—"
        rows += f"""
        <tr>
          <td>{badge(f)}</td>
          <td><strong>{escape(f['package'])}</strong></td>
          <td>{escape(f['ecosystem'])}</td>
          <td>{escape(f['version'] or 'unpinned')}</td>
          <td><a href="{escape(f['url'])}">{escape(f['advisory_id'])}</a></td>
          <td>{escape(f['summary'] or '')}</td>
          <td>{fix_cell}</td>
        </tr>"""

    unpinned_rows = "".join(f"<li>{escape(p['name'])} ({escape(p['ecosystem'])})</li>" for p in unpinned)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>package-alert scan: {escape(str(root))}</title>
<style>
  body {{ font-family: sans-serif; margin: 2em; color: #1f2937; }}
  h1 {{ font-size: 1.4em; }}
  .meta {{ color: #6b7280; margin-bottom: 1.5em; }}
  .summary span {{ margin-right: 1.5em; font-weight: bold; }}
  .malicious {{ color: #dc2626; }}
  .vulnerable {{ color: #d97706; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1.5em; }}
  th {{ background: #f3f4f6; text-align: left; padding: 8px 12px; border-bottom: 2px solid #e5e7eb; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  tr:hover td {{ background: #f9fafb; }}
  ul {{ margin: 0.5em 0; padding-left: 1.5em; }}
  a {{ color: #2563eb; }}
</style>
</head>
<body>
<h1>package-alert scan report</h1>
<div class="meta">
  <div>Project: <strong>{escape(str(root))}</strong></div>
  <div>Sources: {escape(', '.join(sources))}</div>
  {"<div>Scanned: " + escape(scanned_at) + "</div>" if scanned_at else ""}
</div>
<div class="summary">
  <span class="malicious">{malicious} malicious</span>
  <span class="vulnerable">{vulnerable} vulnerable</span>
  <span>{len(unpinned)} unpinned</span>
</div>
{"<h2>Unpinned dependencies</h2><ul>" + unpinned_rows + "</ul>" if unpinned else ""}
<table>
  <thead><tr><th></th><th>Package</th><th>Ecosystem</th><th>Version</th><th>Advisory</th><th>Summary</th><th>Fix</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
</body>
</html>"""


@app.command("clear-cache")
def clear_cache(
    ecosystem: Optional[str] = typer.Option(None, "--ecosystem", "-e", help="Ecosystem to clear: pypi, npm, or packagist. Clears all if omitted."),
    config: Optional[Path] = _cfg_option,
):
    """Clear the OSV query cache, optionally filtered by ecosystem."""
    cfg, _ = _load(config)
    asyncio.run(_run_clear_cache(cfg, ecosystem))


async def _run_clear_cache(cfg, ecosystem: Optional[str]):
    from packagealert.storage.db import open_db

    if ecosystem and ecosystem not in ("pypi", "npm", "packagist"):
        console.print(f"[red]Unknown ecosystem '{ecosystem}'. Use 'pypi', 'npm', or 'packagist'.[/red]")
        raise typer.Exit(1)

    db = await open_db()
    if ecosystem:
        await db.execute("DELETE FROM osv_cache WHERE ecosystem=?", (ecosystem,))
    else:
        await db.execute("DELETE FROM osv_cache")
    await db.commit()
    changes = db.total_changes
    await db.close()

    label = ecosystem or "all"
    console.print(f"Cleared [bold]{changes}[/bold] {label} cache entr{'y' if changes == 1 else 'ies'}.")


@app.command("config-show")
def config_show(config: Optional[Path] = _cfg_option):
    """Show current configuration as JSON."""
    cfg = load_config(config)
    console.print_json(cfg.model_dump_json(indent=2))


@app.command("version")
def version_cmd():
    """Show the installed package-alert version."""
    console.print(_pkg_version("package-alert"))


_SYSTEMD_USER_DIR = Path.home() / ".config" / "systemd" / "user"
_SERVICE_NAME = "package-alert.service"


def _systemd_is_running() -> bool:
    return Path("/run/systemd/private").exists()


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    """Run systemctl --user <args>, raising typer.Exit on FileNotFoundError."""
    try:
        return subprocess.run(["systemctl", "--user", *args], capture_output=True)
    except FileNotFoundError:
        console.print("[red]systemctl not found on PATH.[/red]")
        raise typer.Exit(1)


_CONFIG_DIR = Path.home() / ".config" / "package-alert"
_DEFAULT_CONFIG_FILE = _CONFIG_DIR / "config.toml"

_DEFAULT_CONFIG_CONTENT = """\
[osv]
cache_ttl_hours = 24
base_url = "https://api.osv.dev/v1"
timeout_seconds = 10.0
max_retries = 3

[watch]
enable_cache_monitoring = true
enable_process_monitoring = true
process_poll_interval_seconds = 1.0

[alerts]
desktop_notifications = true
terminal_notifications = true
min_severity_for_desktop = "MEDIUM"

# Logging for the long-running daemon process.
[log]
# level = "INFO"              # DEBUG, INFO, WARNING, ERROR, CRITICAL
# file = "~/.local/share/package-alert/daemon.log"
# max_bytes = 10485760        # 10 MB per file before rotation
# backup_count = 3            # number of rotated files to keep

# Logging for short-lived CLI commands (scan-project, query, alerts, etc.).
[cli_log]
# level = "INFO"
# file = "~/.local/share/package-alert/cli.log"
# max_bytes = 10485760
# backup_count = 3

[heuristics]
enabled = true
warning_threshold = 40
critical_threshold = 70
# top_packages_refresh_days = 7

# Risk score dampening — reduces false positives for well-established packages.
# high_dependent_count = 1000     # dependents at which popularity factor reaches its floor
# high_version_count = 50         # version count proxy when dependent_count is unavailable
# popularity_floor = 0.25         # minimum popularity multiplier (0.0–1.0)
# popularity_failure_ttl_minutes = 60
# max_damping_age_days = 90       # age in days at which age factor reaches its floor
# age_floor = 0.25                # minimum age multiplier (0.0–1.0)
# age_failure_ttl_minutes = 60
# combined_damping_floor = 0.1    # floor for popularity_factor × age_factor

[sandbox]
# extra_env = []
# extra_tmpfs = []
# extra_ro_paths = []   # paths inside $HOME to re-expose read-only (e.g. editable installs)
# editable_roots = []   # permit pip install -e from external source dirs (e.g. ["~/dev"]); in-project installs always allowed

[sandbox.cooldown]
# period_days = 7
# on_new_medium_risk = "prompt"   # prompt | warn | block | allow (typosquat match detected)
# on_new_low_risk = "warn"
# non_interactive_escalation = "block"

[scheduler]
enabled = true
daily_hour = 2
weekly_day = 6
weekly_hour = 2
max_scan_history = 5
"""

_SERVICE_UNIT = """\
[Unit]
Description=package-alert developer security monitor
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/package-alert daemon --config %h/.config/package-alert/config.toml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=package-alert

[Install]
WantedBy=default.target
"""


@app.command("daemon-install")
def daemon_install_cmd():
    """Install and enable the package-alert systemd user service."""
    if not _systemd_is_running():
        console.print("[red]systemd is not running on this system.[/red]")
        raise typer.Exit(1)

    unit_path = _SYSTEMD_USER_DIR / _SERVICE_NAME
    if unit_path.exists():
        console.print(f"[yellow]Service file already exists at {unit_path}.[/yellow]")
        console.print("Run [bold]package-alert daemon-remove[/bold] first if you want to reinstall.")
        raise typer.Exit(1)

    if not _DEFAULT_CONFIG_FILE.exists():
        import os, stat, tempfile
        _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=_CONFIG_DIR, suffix=".tmp")
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "w") as f:
                fd = -1  # fdopen takes ownership; don't close twice
                f.write(_DEFAULT_CONFIG_CONTENT)
            os.replace(tmp, _DEFAULT_CONFIG_FILE)
        except Exception:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        # os.replace preserves the temp file's mode on Linux but not on all platforms;
        # chmod the destination explicitly so the config is always 0600.
        try:
            os.chmod(_DEFAULT_CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        console.print(f"[dim]Wrote default config to {_DEFAULT_CONFIG_FILE}[/dim]")
    else:
        console.print(f"[dim]Config already exists at {_DEFAULT_CONFIG_FILE} — leaving it unchanged.[/dim]")

    _SYSTEMD_USER_DIR.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(_SERVICE_UNIT)
    console.print(f"[dim]Wrote {unit_path}[/dim]")

    r = _systemctl("enable", "--now", _SERVICE_NAME)
    if r.returncode != 0:
        stderr = r.stderr.decode(errors="replace").strip()
        console.print(f"[red]systemctl enable --now failed:[/red] {stderr}")
        console.print(f"[dim]Unit file left at {unit_path} — fix the error and run:[/dim]")
        console.print(f"  systemctl --user enable --now {_SERVICE_NAME}")
        raise typer.Exit(r.returncode)

    console.print("[green]package-alert daemon installed and started.[/green]")
    console.print(f"[dim]Edit {_DEFAULT_CONFIG_FILE} to customise, then restart with:[/dim]")
    console.print(f"  systemctl --user restart {_SERVICE_NAME}")


@app.command("daemon-remove")
def daemon_remove_cmd():
    """Disable and remove the package-alert systemd user service."""
    if not _systemd_is_running():
        console.print("[red]systemd is not running on this system.[/red]")
        raise typer.Exit(1)

    unit_path = _SYSTEMD_USER_DIR / _SERVICE_NAME
    if not unit_path.exists():
        console.print("[yellow]No service file found — nothing to remove.[/yellow]")
        raise typer.Exit(0)

    _systemctl("disable", "--now", _SERVICE_NAME)

    unit_path.unlink()
    console.print(f"[dim]Removed {unit_path}[/dim]")

    _systemctl("daemon-reload")
    console.print("[green]package-alert daemon removed.[/green]")


@app.command("update")
def update_cmd(
    force: bool = typer.Option(False, "--force", help="Force reinstall even if already at the latest version."),
):
    """Upgrade package-alert to the latest version using pipx or uv."""
    # Mutually exclusive: a venv lives under exactly one tool's directory.
    is_uv = _is_uv_tool_install()
    is_pipx = _is_pipx_install()
    if not is_uv and not is_pipx:
        console.print("[red]package-alert is not installed via pipx or uv tool. Cannot self-update.[/red]")
        raise typer.Exit(1)

    version_before = _pkg_version("package-alert")

    if is_uv:
        cmd = ["uv", "tool", "install", "--reinstall", "package-alert"] if force else ["uv", "tool", "upgrade", "package-alert"]
        tool_name = "uv"
    else:
        cmd = ["pipx", "reinstall", "package-alert"] if force else ["pipx", "upgrade", "package-alert"]
        tool_name = "pipx"
    try:
        result = subprocess.run(cmd)
    except FileNotFoundError:
        console.print(f"[red]{tool_name} not found on PATH. Cannot self-update.[/red]")
        raise typer.Exit(1)

    if result.returncode != 0:
        raise typer.Exit(result.returncode)

    if force:
        console.print(f"[green]Reinstalled package-alert {version_before}.[/green]")
        raise typer.Exit(0)

    version_after = _pkg_version("package-alert")

    if version_before == version_after:
        console.print("[dim]Already up to date.[/dim]")
        raise typer.Exit(0)

    console.print(f"Upgraded package-alert [dim]{version_before}[/dim] → [green]{version_after}[/green].")

    pid = check_already_running()
    if pid is None:
        raise typer.Exit(0)

    try:
        if is_started_by_systemd(pid):
            r = _systemctl("restart", "package-alert")
            if r.returncode == 0:
                console.print("[green]Daemon restarted via systemd.[/green]")
            else:
                console.print(f"[yellow]systemctl restart failed (exit {r.returncode}); run [bold]journalctl --user -u package-alert -n 20[/bold] to see why.[/yellow]")
        else:
            cmd = _daemon_cmdline(pid) or ["package-alert", "daemon"]
            os.kill(pid, signal.SIGTERM)
            console.print(f"[dim]Stopping daemon (pid {pid})...[/dim]")
            deadline = time.time() + 10.0
            while PID_FILE.exists() and time.time() < deadline:
                time.sleep(0.5)
            if PID_FILE.exists():
                console.print("[yellow]Timed out waiting for daemon to stop; spawning new instance anyway.[/yellow]")
            proc = subprocess.Popen(cmd, start_new_session=True)
            # Confirm the new daemon started by waiting for a *new* PID (different from the old
            # one) to appear in the PID file and the process to be alive. This guards against the
            # case where the old daemon exited without removing the PID file, which would make a
            # simple exists() check report a false success.
            deadline = time.time() + 5.0
            new_pid = None
            while time.time() < deadline:
                if proc.poll() is not None:
                    console.print(f"[yellow]Daemon process exited early (code {proc.returncode}); it may already be running.[/yellow]")
                    break
                new_pid = check_already_running()
                if new_pid is not None and new_pid != pid:
                    console.print("[green]Daemon restarted.[/green]")
                    break
                time.sleep(0.2)
            else:
                console.print("[yellow]Daemon spawned but could not confirm it is running; it may still be starting.[/yellow]")
    except OSError as exc:
        console.print(f"[yellow]Could not restart daemon: {exc}[/yellow]")

    raise typer.Exit(0)


@app.command("run", context_settings={"allow_extra_args": True, "ignore_unknown_options": True, "allow_interspersed_args": False})
def run_cmd(
    ctx: typer.Context,
    no_network: bool = typer.Option(
        False, "--no-network",
        help="Block all outbound network access inside the sandbox. "
             "Only use this when all packages are already cached locally.",
    ),
    env: list[str] = typer.Option(
        [], "--env",
        help="Extra environment variable names to pass through into the sandbox. "
             "Repeatable: --env MY_TOKEN --env CUSTOM_REGISTRY_URL",
    ),
    flags: str = typer.Option(
        "", "--flags",
        help=(
            "Grant named capabilities to language modules. Comma-separated list of "
            "'namespace:capability' tokens, e.g. --flags python:ssh-keys. "
            "Modules ignore capabilities they don't recognise."
        ),
    ),
    expose_ssh_keys: bool = typer.Option(
        False, "--expose-ssh-keys",
        help="Deprecated: use --flags python:ssh-keys instead.",
        hidden=True,
    ),
    allow_external_lockfiles: bool = typer.Option(
        False, "--allow-external-lockfiles",
        help="Disable symlink containment checks on lock files. "
             "Without this flag, lock files that are symlinks resolving outside the project root are "
             "rejected at every stage: pre-flight scan, post-run lock-file scan, snapshot, and restore. "
             "Use this flag when lock files legitimately point outside the project (e.g. monorepo or editable-install setups).",
    ),
    no_change: bool = typer.Option(
        False, "--no-change", "-n",
        help="Dry-run mode: run the command in the sandbox and perform all pre- and post-checks, "
             "but always restore lock files to their pre-run state on exit regardless of outcome. "
             "Useful for auditing what a command would install without committing changes to the project.",
    ),
    config: Optional[Path] = _cfg_option,
):
    """Run a package manager command inside a bubblewrap sandbox.

    Pre-checks all packages against OSV before execution, then runs the command
    with the filesystem mounted read-only except for the target install directories.
    A post-install scan catches anything that slipped through the pre-flight check.

    The sandbox runs with a minimal environment. A safe set of variables (PATH,
    HOME, proxy settings, registry URLs, etc.) is always forwarded. Use --env to
    pass through additional variables, or set sandbox.extra_env in the config file.

    Network access is allowed by default so package managers can reach their
    registries. Use --no-network only when everything is already cached.

    Examples:

      package-alert run uv sync

      package-alert run npm install

      package-alert run pip install requests flask

      package-alert run --no-network uv sync   # fully offline, cache must be warm

      package-alert run --env MY_TOKEN uv sync

      package-alert run -n pipenv lock          # audit without keeping the new lock file

    When using shell hooks (package-alert setup shell), set PA_RUN_OPTS to pass
    options without modifying the hook:

      PA_RUN_OPTS="--no-change" pipenv install
      export PA_RUN_OPTS="--no-network"   # applies to all subsequent hook invocations
    """
    # Apply PA_RUN_OPTS environment variable — allows shell hook users to pass
    # package-alert run options without modifying the hook itself, e.g.:
    #   PA_RUN_OPTS="--no-change" pip install requests
    #   export PA_RUN_OPTS="--no-network"
    pa_opts_env = os.environ.get("PA_RUN_OPTS", "")
    _env_flags_list: list[str] = []
    if pa_opts_env.strip():
        import shlex as _shlex
        _tokens = _shlex.split(pa_opts_env)
        _i = 0
        while _i < len(_tokens):
            token = _tokens[_i]
            if token in ("--no-change", "-n"):
                no_change = True
            elif token == "--no-network":
                no_network = True
            elif token == "--expose-ssh-keys":
                expose_ssh_keys = True
            elif token == "--allow-external-lockfiles":
                allow_external_lockfiles = True
            elif token == "--flags" and _i + 1 < len(_tokens):
                _i += 1
                _env_flags_list.append(_tokens[_i])
            elif token == "--flags":
                console.print("[yellow]PA_RUN_OPTS: --flags requires a value (e.g. --flags python:ssh-keys) — ignored[/yellow]")
            elif token.startswith("--flags="):
                _env_flags_list.append(token[len("--flags="):])
            else:
                console.print(f"[yellow]PA_RUN_OPTS: unrecognised option {token!r} — ignored[/yellow]")
            _i += 1

    from packagealert.sandbox.runner import _parse_flags, _FLAG_TOKEN_RE

    def _warn_invalid_flag_tokens(flags_str: str, source: str) -> None:
        for _token in flags_str.split(","):
            _token = _token.strip()
            if ":" not in _token:
                continue
            _ns, _, _cap = _token.partition(":")
            if not _FLAG_TOKEN_RE.match(_ns.strip()) or not _FLAG_TOKEN_RE.match(_cap.strip()):
                console.print(
                    f"[yellow]⚠ {source}: {_token!r} ignored — namespace and capability must be "
                    f"lowercase letters, digits, hyphens, or underscores (e.g. python:ssh-keys)[/yellow]"
                )

    if flags:
        _warn_invalid_flag_tokens(flags, "--flags")
    parsed_flags = _parse_flags(flags)
    for _env_flags in _env_flags_list:
        _warn_invalid_flag_tokens(_env_flags, "PA_RUN_OPTS --flags")
        for ns, caps in _parse_flags(_env_flags).items():
            parsed_flags[ns] = parsed_flags.get(ns, frozenset()) | caps

    if expose_ssh_keys:
        console.print(
            "[yellow]⚠ --expose-ssh-keys is deprecated. Use --flags python:ssh-keys instead.[/yellow]"
        )
        parsed_flags = {
            **parsed_flags,
            "python": parsed_flags.get("python", frozenset()) | {"ssh-keys"},
        }

    command = list(ctx.args)
    if not command:
        console.print("[red]No command specified.[/red]")
        console.print("[dim]Usage: package-alert run [OPTIONS] <command> [args...][/dim]")
        raise typer.Exit(1)
    cfg, _ = _load(config)
    from packagealert.sandbox.runner import SandboxRunner
    runner = SandboxRunner(cfg)
    code = asyncio.run(runner.run(command, allow_network=not no_network, extra_env=env, flags=parsed_flags, allow_external_lockfiles=allow_external_lockfiles, no_change=no_change))
    raise typer.Exit(code)


@schedule_app.command("add")
def schedule_add(
    path: Optional[Path] = typer.Argument(None, help="Project directory (default: current directory)."),
    daily: bool = typer.Option(False, "--daily", help="Scan daily."),
    weekly: bool = typer.Option(False, "--weekly", help="Scan weekly."),
    installed: bool = typer.Option(False, "--installed", help="Scan actually-installed packages (default: lock files)."),
    config: Optional[Path] = _cfg_option,
):
    """Add the project to the scheduled scan list."""
    cfg, _ = _load(config)
    root = (path or Path.cwd()).resolve()
    if not root.is_dir():
        console.print(f"[red]Not a directory: {root}[/red]")
        raise typer.Exit(1)
    if daily and weekly:
        console.print("[red]Specify --daily or --weekly, not both.[/red]")
        raise typer.Exit(1)
    schedule = "daily" if daily else "weekly"
    scan_type = "installed" if installed else "project"
    asyncio.run(_schedule_add(cfg, str(root), schedule, scan_type))


async def _schedule_add(cfg, path: str, schedule: str, scan_type: str) -> None:
    from packagealert.storage.db import open_db
    from packagealert.scheduler.db import add_project
    db = await open_db()
    try:
        await add_project(db, path=path, schedule=schedule, scan_type=scan_type)
    finally:
        await db.close()
    console.print(f"[green]✓[/green] Added [bold]{path}[/bold] to {schedule} scans ({scan_type}).")


@schedule_app.command("remove")
def schedule_remove(
    path: Optional[Path] = typer.Argument(None, help="Project directory (default: current directory)."),
    installed: bool = typer.Option(False, "--installed", help="Remove only the installed-packages scan entry."),
    project: bool = typer.Option(False, "--project", help="Remove only the lock-file scan entry."),
    config: Optional[Path] = _cfg_option,
):
    """Remove the project from the scheduled scan list.

    Without --installed or --project, removes all scan entries for the project."""
    cfg, _ = _load(config)
    root = (path or Path.cwd()).resolve()
    if installed and project:
        console.print("[red]Specify --installed or --project, not both.[/red]")
        raise typer.Exit(1)
    scan_type: Optional[str] = "installed" if installed else ("project" if project else None)
    removed = asyncio.run(_schedule_remove(str(root), scan_type))
    label = f" ({scan_type})" if scan_type else ""
    if removed:
        console.print(f"[green]✓[/green] Removed [bold]{root}[/bold]{label} from scheduled scans.")
    else:
        console.print(f"[yellow]{root}[/yellow]{label} was not in the scheduled scan list.")


async def _schedule_remove(path: str, scan_type: Optional[str]) -> bool:
    from packagealert.storage.db import open_db
    from packagealert.scheduler.db import remove_project
    db = await open_db()
    try:
        return await remove_project(db, path, scan_type=scan_type)
    finally:
        await db.close()


@schedule_app.command("list")
def schedule_list(config: Optional[Path] = _cfg_option):
    """List all projects registered for scheduled scans."""
    _load(config)  # validates config; return value unused
    asyncio.run(_schedule_list())


async def _schedule_list() -> None:
    import datetime
    from packagealert.storage.db import open_db
    from packagealert.scheduler.db import list_projects

    db = await open_db()
    try:
        projects = await list_projects(db)
    finally:
        await db.close()

    if not projects:
        console.print("[dim]No projects registered for scheduled scans.[/dim]")
        return

    table = Table(title="Scheduled Projects")
    table.add_column("Path", style="bold")
    table.add_column("Schedule")
    table.add_column("Scan Type")
    table.add_column("Last Scanned")

    for p in projects:
        last = (
            datetime.datetime.fromtimestamp(p.last_scanned_at).strftime("%Y-%m-%d %H:%M")
            if p.last_scanned_at
            else "never"
        )
        table.add_row(p.path, p.schedule, p.scan_type, last)

    console.print(table)


@scans_app.command("list")
def scans_list(
    path: Optional[Path] = typer.Argument(None, help="Project directory (default: current directory)."),
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum number of scans to show."),
    config: Optional[Path] = _cfg_option,
):
    """List completed scheduled scans for a project."""
    _load(config)  # validates config; return value unused
    root = (path or Path.cwd()).resolve()
    asyncio.run(_scans_list(str(root), limit))


async def _scans_list(project_path: str, limit: int) -> None:
    import datetime
    import socket
    from packagealert.plugins.registry import plugin_registry
    from packagealert.storage.db import open_db
    from packagealert.scheduler.db import list_scan_results

    hostname = socket.gethostname()
    if await plugin_registry.try_scans_list(project_path, hostname, limit):
        return

    db = await open_db()
    try:
        records = await list_scan_results(db, project_path, limit=limit)
    finally:
        await db.close()

    if not records:
        console.print(f"[dim]No scan results found for {project_path}[/dim]")
        return

    _SEV_COLOUR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "bright_yellow", "LOW": "green"}

    table = Table(title=f"Scan results: {project_path}")
    table.add_column("ID", style="dim")
    table.add_column("Date")
    table.add_column("Schedule")
    table.add_column("Type")
    table.add_column("Findings", justify="right")
    table.add_column("Highest Severity")

    for r in records:
        date_str = datetime.datetime.fromtimestamp(r.scanned_at).strftime("%Y-%m-%d %H:%M")
        sev = r.max_severity or "—"
        colour = _SEV_COLOUR.get(r.max_severity or "", "dim")
        table.add_row(
            str(r.id),
            date_str,
            r.schedule,
            r.scan_type,
            str(r.finding_count),
            f"[{colour}]{sev}[/{colour}]",
        )

    console.print(table)


@scans_app.command("listall")
def scans_listall(
    limit: int = typer.Option(50, "--limit", "-n", help="Maximum number of scans to show."),
    config: Optional[Path] = _cfg_option,
):
    """List completed scheduled scans across all projects."""
    _load(config)  # validates config; return value unused
    asyncio.run(_scans_listall(limit))


async def _scans_listall(limit: int) -> None:
    import datetime
    import socket
    from packagealert.plugins.registry import plugin_registry
    from packagealert.storage.db import open_db
    from packagealert.scheduler.db import list_all_scan_results

    hostname = socket.gethostname()
    if await plugin_registry.try_scans_listall(hostname, limit):
        return

    db = await open_db()
    try:
        records = await list_all_scan_results(db, limit=limit)
    finally:
        await db.close()

    if not records:
        console.print("[dim]No scan results found.[/dim]")
        return

    _SEV_COLOUR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "bright_yellow", "LOW": "green"}

    table = Table(title="All scan results")
    table.add_column("ID", style="dim")
    table.add_column("Project", style="bold")
    table.add_column("Date")
    table.add_column("Schedule")
    table.add_column("Type")
    table.add_column("Findings", justify="right")
    table.add_column("Highest Severity")

    for r in records:
        date_str = datetime.datetime.fromtimestamp(r.scanned_at).strftime("%Y-%m-%d %H:%M")
        sev = r.max_severity or "—"
        colour = _SEV_COLOUR.get(r.max_severity or "", "dim")
        table.add_row(
            str(r.id),
            r.project_path,
            date_str,
            r.schedule,
            r.scan_type,
            str(r.finding_count),
            f"[{colour}]{sev}[/{colour}]",
        )

    console.print(table)


@scans_app.command("show")
def scans_show(
    scan_id: int = typer.Argument(..., help="Scan ID from 'scans list'."),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format: text, json, html, browser."),
    details: bool = typer.Option(False, "--details", "-d", help="Show full advisory details."),
    config: Optional[Path] = _cfg_option,
):
    """Show findings from a completed scheduled scan."""
    _load(config)  # validates config; return value unused
    asyncio.run(_scans_show(scan_id, fmt, details))


async def _scans_show(scan_id: int, fmt: str, show_details: bool) -> None:
    import datetime
    import json as jsonlib
    from packagealert.plugins.registry import plugin_registry
    from packagealert.storage.db import open_db
    from packagealert.scheduler.db import get_scan_result

    if await plugin_registry.try_scans_show(scan_id, fmt, show_details):
        return

    db = await open_db()
    try:
        record = await get_scan_result(db, scan_id)
    finally:
        await db.close()

    if record is None:
        console.print(f"[red]No scan result found with ID {scan_id}[/red]")
        raise typer.Exit(1)

    findings = record.findings
    root_str = record.project_path
    sources = record.sources
    date_str = datetime.datetime.fromtimestamp(record.scanned_at).strftime("%Y-%m-%d %H:%M:%S")

    if fmt == "json":
        print(jsonlib.dumps({
            "id": record.id,
            "project_path": root_str,
            "scanned_at": date_str,
            "schedule": record.schedule,
            "scan_type": record.scan_type,
            "sources": sources,
            "findings": findings,
        }, indent=2))
        return

    if fmt in ("html", "browser"):
        html = _render_html(Path(root_str), sources, [], findings, scanned_at=date_str)
        if fmt == "browser":
            open_html_in_browser(html)
        else:
            print(html)
        return

    # text output
    console.print(f"\nScan [bold]#{record.id}[/bold] — {root_str}")
    console.print(
        f"Run at: {date_str}  |  Schedule: {record.schedule}  |  "
        f"Type: {record.scan_type}  |  Sources: {', '.join(sources)}\n"
    )

    if not findings:
        console.print("[green]No findings — all clear.[/green]")
        return

    malicious = 0
    vulnerable = 0
    for f in findings:
        adv_obj = types.SimpleNamespace(**f)
        colour = _severity_colour(adv_obj)
        label = "[MALICIOUS]" if f["is_malicious"] else "[VULN]"
        severity_tag = f" [{f['severity']}]" if f["severity"] else ""
        summary_tag = f" — {f['summary']}" if f["summary"] else ""
        console.print(
            f"[{colour}]{label} {f['advisory_id']}{severity_tag}[/{colour}] "
            f"{f['package']}@{f['version'] or 'unpinned'}{summary_tag}",
            highlight=False,
        )
        if f.get("fixed_versions"):
            console.print(f"  [green]→ upgrade to: {', '.join(f['fixed_versions'])}[/green]")
        if show_details:
            if f.get("details"):
                console.print(f"  {f['details'].strip()}", highlight=False)
            console.print(f"  {f['url']}")
        if f["is_malicious"]:
            malicious += 1
        else:
            vulnerable += 1

    console.print(
        f"\nScan complete: [bold red]{malicious} malicious[/bold red], "
        f"[bold yellow]{vulnerable} vulnerable[/bold yellow] "
        f"({len(findings)} total findings)"
    )


def main():
    import sys
    import os
    app(prog_name=os.path.basename(sys.argv[0]))
