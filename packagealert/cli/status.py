"""Status command for package-alert."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import psutil

from packagealert.config import load_config, DEFAULT_CONFIG_PATH as _DEFAULT_CONFIG
from packagealert.daemon_pid import find_daemon_pid, is_started_by_systemd, PID_FILE as _PID_FILE
from packagealert.storage.db import DEFAULT_DB_PATH as _DB_PATH


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class AlertRow:
    package: str
    ecosystem: str
    version: str | None
    advisory_id: str | None
    risk_score: int | None
    severity: str
    alerted_at: float  # unix timestamp


@dataclass
class CentralStatus:
    enabled: bool
    plugin_name: str
    server_url: str
    last_heartbeat_at: str | None
    last_heartbeat_ok: bool | None
    last_heartbeat_error: str | None
    last_config_fetch_at: str | None
    last_config_fetch_ok: bool | None
    last_config_fetch_error: str | None
    # "Last seen" is the timestamp of the most recent successful heartbeat —
    # heartbeats fire on daemon start/stop and periodically while running, so
    # this is the best available proxy for "was central reachable, and when."
    # None if no heartbeat has ever succeeded.
    last_seen_at: str | None
    outbox_scan_count: int = 0
    outbox_alert_count: int = 0


@dataclass
class StatusData:
    # daemon
    daemon_running: bool
    daemon_pid: int | None
    daemon_uptime_seconds: float | None
    # config
    config_path: str
    cache_monitoring: bool
    process_monitoring: bool
    scheduler_enabled: bool
    # alerts
    alerts_last_7_days: int
    recent_alerts: list[AlertRow] = field(default_factory=list)
    # projects
    scheduled_projects_count: int = 0
    daemon_managed_by_systemd: bool = False
    # paths
    pid_file_path: str = ""
    pid_file_exists: bool = False
    db_path: str = ""
    db_exists: bool = False
    log_path: str = ""
    log_exists: bool = False
    cli_log_path: str = ""
    cli_log_exists: bool = False
    central: CentralStatus | None = None

    def to_dict(self) -> dict:
        return {
            "daemon": {
                "running": self.daemon_running,
                "pid": self.daemon_pid,
                "uptime_seconds": self.daemon_uptime_seconds,
                "managed_by_systemd": self.daemon_managed_by_systemd,
            },
            "config": {
                "path": self.config_path,
                "cache_monitoring": self.cache_monitoring,
                "process_monitoring": self.process_monitoring,
                "scheduler_enabled": self.scheduler_enabled,
            },
            "alerts": {
                "last_7_days_count": self.alerts_last_7_days,
                "recent": [
                    {
                        "package": a.package,
                        "ecosystem": a.ecosystem,
                        "version": a.version,
                        "advisory_id": a.advisory_id,
                        "severity": a.severity,
                        "risk_score": a.risk_score,
                        "alerted_at": datetime.fromtimestamp(
                            a.alerted_at, tz=timezone.utc
                        ).isoformat(timespec="seconds"),
                    }
                    for a in self.recent_alerts
                ],
            },
            "scheduled_projects_count": self.scheduled_projects_count,
            "central": {
                "enabled": self.central.enabled,
                "plugin_name": self.central.plugin_name,
                "server_url": self.central.server_url,
                "last_heartbeat_at": self.central.last_heartbeat_at,
                "last_heartbeat_ok": self.central.last_heartbeat_ok,
                "last_heartbeat_error": self.central.last_heartbeat_error,
                "last_config_fetch_at": self.central.last_config_fetch_at,
                "last_config_fetch_ok": self.central.last_config_fetch_ok,
                "last_config_fetch_error": self.central.last_config_fetch_error,
                "last_seen_at": self.central.last_seen_at,
                "outbox": {
                    "scan": self.central.outbox_scan_count,
                    "alert": self.central.outbox_alert_count,
                },
            } if self.central else None,
            "paths": {
                "pid_file": {"path": self.pid_file_path, "exists": self.pid_file_exists},
                "database": {"path": self.db_path, "exists": self.db_exists},
                "daemon_log": {"path": self.log_path, "exists": self.log_exists},
                "cli_log": {"path": self.cli_log_path, "exists": self.cli_log_exists},
            },
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity_label(
    risk_score: int | None,
    *,
    warning_threshold: int,
    critical_threshold: int,
) -> str:
    if risk_score is None:
        return "UNKNOWN"
    if risk_score >= critical_threshold:
        return "CRITICAL"
    if risk_score >= warning_threshold:
        return "MEDIUM"
    return "LOW"



def _format_uptime(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    total = int(seconds)  # sub-second precision dropped intentionally
    hours, rem = divmod(total, 3600)
    minutes = rem // 60  # seconds omitted — "2h 3m" is precise enough for display
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


_SEV_COLOUR = {
    "CRITICAL": "bold red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "UNKNOWN": "dim",
}


def render_status(
    data: StatusData,
    *,
    as_json: bool = False,
    console=None,
) -> None:
    """Print status to the terminal (rich) or stdout (JSON)."""
    if as_json:
        print(json.dumps(data.to_dict(), indent=2))
        return

    from rich.console import Console as RichConsole
    from rich.markup import escape
    if console is None:
        console = RichConsole()

    # ── Daemon ────────────────────────────────────────────────────────────────
    console.print("[bold]Daemon[/bold]")
    if data.daemon_running:
        uptime_str = _format_uptime(data.daemon_uptime_seconds)
        manager = ", via systemd" if data.daemon_managed_by_systemd else ""
        console.print(
            f"  Status:   [green]running[/green]"
            f"  (PID {data.daemon_pid}, up {uptime_str}{manager})"
        )
    else:
        console.print("  Status:   [red]stopped[/red]")
    console.print(f"  Config:   {escape(data.config_path)}")
    if data.daemon_running:
        cache = "[green]✓[/green]" if data.cache_monitoring else "[red]✗[/red]"
        proc = "[green]✓[/green]" if data.process_monitoring else "[red]✗[/red]"
        sched = "[green]✓[/green]" if data.scheduler_enabled else "[red]✗[/red]"
        console.print(f"  Monitors: cache {cache}  process {proc}  scheduler {sched}")

    console.print()

    # ── Alerts ────────────────────────────────────────────────────────────────
    console.print(
        f"[bold]Alerts[/bold] (last 7 days: {data.alerts_last_7_days} total)"
    )
    if data.recent_alerts:
        for alert in data.recent_alerts:
            ts = datetime.fromtimestamp(alert.alerted_at).strftime("%Y-%m-%d %H:%M")  # local time for display; to_dict() uses UTC
            colour = _SEV_COLOUR.get(alert.severity, "white")
            pkg = escape(alert.package)
            eco = escape(alert.ecosystem)
            ver = escape(alert.version or "")
            console.print(
                f"  {pkg:<15} {eco:<8}"
                f" {ver:<12}"
                f" [{colour}]{alert.severity:<10}[/{colour}] {ts}"
            )
    else:
        console.print("  [dim]No alerts in the last 7 days.[/dim]")

    console.print()

    # ── Logs ──────────────────────────────────────────────────────────────────
    console.print("[bold]Logs[/bold]")

    def _log_line(label: str, path: str, exists: bool) -> None:
        if not path:
            console.print(f"  {label + ':':<8} [dim]disabled[/dim]")
        else:
            indicator = "[green]✓[/green]" if exists else "[dim]✗ not yet created[/dim]"
            console.print(f"  {label + ':':<8} {escape(path)}  {indicator}")

    _log_line("Daemon", data.log_path, data.log_exists)
    _log_line("CLI", data.cli_log_path, data.cli_log_exists)

    console.print()

    # ── Scheduled projects ────────────────────────────────────────────────────
    console.print("[bold]Scheduled Projects[/bold]")
    if data.scheduled_projects_count > 0:
        n = data.scheduled_projects_count
        label = "project" if n == 1 else "projects"
        console.print(f"  {n} {label} registered")
    else:
        console.print("  [dim]No projects scheduled.[/dim]")

    if data.central is not None:
        console.print()
        console.print(f"[bold]Central[/bold]  [dim]({escape(data.central.plugin_name)})[/dim]")

        def _fmt_ts(at: str) -> str:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(at.replace("Z", "+00:00"))
                return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                return at

        def _central_line(label: str, value: str) -> None:
            console.print(f"  {label + ':':<13} {value}")

        server_val = escape(data.central.server_url) if data.central.server_url else "[dim](not set)[/dim]"
        _central_line("Server", server_val)

        def _conn_line(label: str, at: str | None, ok: bool | None, err: str | None) -> None:
            if at is None:
                _central_line(label, "[dim]never[/dim]")
                return
            if ok is True:
                status_str = "[green]ok[/green]"
            elif ok is False:
                status_str = f"[red]failed[/red] ({escape(err or '')})"
            else:
                status_str = "[dim]unknown[/dim]"
            _central_line(label, f"{_fmt_ts(at)}  {status_str}")

        _conn_line("Heartbeat", data.central.last_heartbeat_at,
                   data.central.last_heartbeat_ok, data.central.last_heartbeat_error)
        _conn_line("Config sync", data.central.last_config_fetch_at,
                   data.central.last_config_fetch_ok, data.central.last_config_fetch_error)

        if data.central.last_seen_at is not None:
            _central_line("Last seen", f"{_fmt_ts(data.central.last_seen_at)}  [green]ok[/green]")
        else:
            _central_line("Last seen", "[dim]never[/dim]")

        scan_n = data.central.outbox_scan_count
        alert_n = data.central.outbox_alert_count
        if scan_n or alert_n:
            _central_line(
                "Outbox",
                f"[yellow]{scan_n} scan(s), {alert_n} alert(s) pending sync[/yellow]",
            )
        else:
            _central_line("Outbox", "[dim]empty[/dim]")


async def gather_status(
    config_path: Path | None,
    *,
    _db=None,  # injectable for tests; if None, opens default DB when it exists
) -> StatusData:
    """Collect all status information."""
    from packagealert.storage.db import open_db

    effective_config_path = config_path
    if config_path is not None:
        from packagealert.config import read_enabled_plugins
        from packagealert.plugins.registry import _load_entry_points
        from packagealert.cli.app import _apply_config_veto
        effective_config_path = _apply_config_veto(config_path, read_enabled_plugins, _load_entry_points)
    cfg = load_config(effective_config_path)
    if effective_config_path is not None:
        resolved_cfg_path = str(effective_config_path)
    elif _DEFAULT_CONFIG.exists():
        resolved_cfg_path = str(_DEFAULT_CONFIG)
    else:
        resolved_cfg_path = "(defaults)"

    # ── Daemon ────────────────────────────────────────────────────────────────
    pid = find_daemon_pid()

    managed_by_systemd = is_started_by_systemd(pid) if pid is not None else False
    uptime: float | None = None
    if pid is not None:
        try:
            uptime = time.time() - psutil.Process(pid).create_time()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            uptime = None  # process exists but is inaccessible; report running with unknown uptime
        except psutil.NoSuchProcess:
            pid = None

    # ── Paths ─────────────────────────────────────────────────────────────────
    log_path = cfg.log.file
    log_path_str = str(log_path) if log_path else ""
    log_exists = log_path.exists() if log_path else False

    cli_log_path = cfg.cli_log.file
    cli_log_path_str = str(cli_log_path) if cli_log_path else ""
    cli_log_exists = cli_log_path.exists() if cli_log_path else False

    # ── DB queries ────────────────────────────────────────────────────────────
    alerts_count = 0
    recent_alerts: list[AlertRow] = []
    scheduled_count = 0
    outbox_counts = {"scan": 0, "alert": 0}

    if _db is not None:
        db = _db
        close_db = False
        db_exists = True
        db_path_str = str(_DB_PATH)
    elif _DB_PATH.exists():
        db = await open_db(_DB_PATH, enabled_plugins=set(cfg.plugins.enabled))
        close_db = True
        db_exists = True
        db_path_str = str(_DB_PATH)
    else:
        db = None
        close_db = False
        db_exists = False
        db_path_str = str(_DB_PATH)

    if db is not None:
        try:
            cutoff = time.time() - 7 * 86400
            async with db.execute(
                "SELECT COUNT(*) as cnt FROM alerts WHERE alerted_at >= ?", (cutoff,)
            ) as cur:
                row = await cur.fetchone()
                alerts_count = row["cnt"]

            async with db.execute(
                "SELECT package_name, ecosystem, version, advisory_id, risk_score, alerted_at"
                " FROM alerts WHERE alerted_at >= ? ORDER BY alerted_at DESC LIMIT 3",
                (cutoff,),
            ) as cur:
                rows = await cur.fetchall()

            for row in rows:
                recent_alerts.append(AlertRow(
                    package=row["package_name"],
                    ecosystem=row["ecosystem"],
                    version=row["version"],
                    advisory_id=row["advisory_id"],
                    risk_score=row["risk_score"],
                    severity=_severity_label(
                        row["risk_score"],
                        warning_threshold=cfg.heuristics.warning_threshold,
                        critical_threshold=cfg.heuristics.critical_threshold,
                    ),
                    alerted_at=row["alerted_at"],
                ))

            async with db.execute("SELECT COUNT(*) as cnt FROM scheduled_projects") as cur:
                row = await cur.fetchone()
                scheduled_count = row["cnt"]

            if "pa-central" in cfg.plugins.enabled:
                from packagealert.plugins.central import outbox as _outbox
                outbox_counts = await _outbox.count_by_kind(db)
        finally:
            if close_db:
                await db.close()

    pid_file_str = str(_PID_FILE)
    pid_file_exists = _PID_FILE.exists()

    # ── Central ─────────────────────────────────────────────────────────────────
    central_status: CentralStatus | None = None
    if "pa-central" in cfg.plugins.enabled:
        from packagealert.plugins.central.state import read_state, _STATE_PATH
        state = read_state(_STATE_PATH)

        central_status = CentralStatus(
            enabled=True,
            plugin_name="pa-central",
            server_url=cfg.plugins.pa_central.server_url,
            last_heartbeat_at=state.get("last_heartbeat_at"),
            last_heartbeat_ok=state.get("last_heartbeat_ok"),
            last_heartbeat_error=state.get("last_heartbeat_error"),
            last_config_fetch_at=state.get("last_config_fetch_at"),
            last_config_fetch_ok=state.get("last_config_fetch_ok"),
            last_config_fetch_error=state.get("last_config_fetch_error"),
            last_seen_at=state.get("last_seen_at"),
            outbox_scan_count=outbox_counts["scan"],
            outbox_alert_count=outbox_counts["alert"],
        )

    return StatusData(
        daemon_running=pid is not None,
        daemon_pid=pid,
        daemon_uptime_seconds=uptime,
        daemon_managed_by_systemd=managed_by_systemd,
        config_path=resolved_cfg_path,
        cache_monitoring=cfg.watch.enable_cache_monitoring,
        process_monitoring=cfg.watch.enable_process_monitoring,
        scheduler_enabled=cfg.scheduler.enabled,
        alerts_last_7_days=alerts_count,
        recent_alerts=recent_alerts,
        scheduled_projects_count=scheduled_count,
        pid_file_path=pid_file_str,
        pid_file_exists=pid_file_exists,
        db_path=db_path_str,
        db_exists=db_exists,
        log_path=log_path_str,
        log_exists=log_exists,
        cli_log_path=cli_log_path_str,
        cli_log_exists=cli_log_exists,
        central=central_status,
    )
