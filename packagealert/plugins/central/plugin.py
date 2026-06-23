from __future__ import annotations

import asyncio
import logging
import socket
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from packagealert.plugins.base import AgentPlugin, ConfigField, ScanNotFound
from packagealert.plugins.central.client import CentralClient
from packagealert.plugins.central.state import read_state, read_overlay, write_state, write_overlay, strip_overlay_unsafe_keys, _STATE_PATH, _OVERLAY_PATH

if TYPE_CHECKING:
    from packagealert.config import AppConfig
    from packagealert.models.events import PackageEvent
    from packagealert.models.risk import RiskReport
    from packagealert.models.advisories import OsvResult
    from packagealert.models.scans import ScanResult

log = logging.getLogger(__name__)


_STATUS_COLOUR = {"findings": "yellow", "clean": "green", "error": "red"}
_SEV_COLOUR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "bright_yellow", "LOW": "green"}


def _render_scans_table(records: list[dict], *, title: str, show_project: bool = False) -> None:
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table
    console = Console()
    if not records:
        console.print("[dim]No scan results found.[/dim]")
        return
    table = Table(title=title)
    table.add_column("ID", style="dim")
    if show_project:
        table.add_column("Project", style="bold")
    table.add_column("Date")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    for r in records:
        scanned_at = str(r.get("scanned_at") or "")
        try:
            dt = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
            date_str = dt.astimezone().strftime("%Y-%m-%d %H:%M")
        except Exception:
            date_str = escape(scanned_at[:16])
        status = r.get("status", "")
        colour = _STATUS_COLOUR.get(status, "dim")
        row = [escape(str(r.get("id") or ""))]
        if show_project:
            row.append(escape(str(r.get("project_path") or "")))
        row += [
            date_str,
            escape(str(r.get("scan_type") or "")),
            f"[{colour}]{escape(status)}[/{colour}]",
            escape(str(r.get("finding_count") or 0)),
        ]
        table.add_row(*row)
    console.print(table)


def _render_scan_detail(record: dict, fmt: str, show_details: bool) -> None:
    import json as jsonlib
    from pathlib import Path
    from rich.console import Console
    from rich.markup import escape
    console = Console()

    scan_id = record.get("id")
    project_path = str(record.get("project_path") or "")
    scan_type = str(record.get("scan_type") or "")
    findings = record.get("findings") or []
    sources = record.get("sources") or []
    scanned_at = str(record.get("scanned_at") or "")
    try:
        dt = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
        date_str = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        date_str = scanned_at

    if fmt == "json":
        print(jsonlib.dumps({
            "id": scan_id,
            "project_path": project_path,
            "scanned_at": date_str,
            "scan_type": scan_type,
            "schedule": record.get("schedule"),
            "status": record.get("status"),
            "finding_count": record.get("finding_count", len(findings)),
            "sources": sources,
            "findings": findings,
        }, indent=2))
        return

    if fmt in ("html", "browser"):
        from packagealert.cli.app import _render_html, open_html_in_browser
        html = _render_html(Path(project_path), sources, [], findings, scanned_at=date_str)
        if fmt == "browser":
            open_html_in_browser(html)
        else:
            print(html)
        return

    console.print(f"\nScan [bold]#{escape(str(scan_id))}[/bold] — {escape(project_path)}")
    console.print(f"Run at: {date_str}  |  Type: {escape(scan_type)}\n")

    if not findings:
        console.print("[green]No findings — all clear.[/green]")
        return

    for f in findings:
        sev = (f.get("severity") or "").upper()
        colour = _SEV_COLOUR.get(sev, "red" if f.get("is_malicious") else "yellow")
        label = "[MALICIOUS]" if f.get("is_malicious") else "[VULN]"
        severity_tag = f" [{escape(sev)}]" if sev else ""
        summary_tag = f" — {escape(f.get('summary') or '')}" if f.get("summary") else ""
        console.print(
            f"[{colour}]{label} {escape(f.get('advisory_id') or '')}{severity_tag}[/{colour}] "
            f"{escape(f.get('package') or '')}@{escape(f.get('version') or 'unpinned')}{summary_tag}",
            highlight=False,
        )
        if f.get("fixed_versions"):
            fixed = ", ".join(escape(v) for v in f["fixed_versions"])
            console.print(f"  [green]→ upgrade to: {fixed}[/green]")
        if show_details:
            if f.get("details"):
                console.print(f"  {escape((f.get('details') or '').strip())}", highlight=False)
            if f.get("url"):
                console.print(f"  {escape(f.get('url') or '')}")


def apply_overlay_to_config(toml_str: str, cfg: "AppConfig") -> None:
    """Apply a fleet config overlay TOML to *cfg* in-place.

    Delegates generic overlay merging to ``packagealert.plugins.overlay``, then
    pins back the pa-central credentials that must never be overwritten by a
    fleet-server-supplied overlay.
    """
    from packagealert.plugins.overlay import apply_overlay_to_config as _apply
    api_key = cfg.plugins.pa_central.api_key
    server_url = cfg.plugins.pa_central.server_url
    _apply(toml_str, cfg)
    cfg.plugins.pa_central.api_key = api_key
    cfg.plugins.pa_central.server_url = server_url


class CentralPlugin(AgentPlugin):
    name = "pa-central"

    @classmethod
    def refuses_config_override(cls) -> bool:
        return True

    @classmethod
    def startup_config_overlay(cls) -> str | None:
        import tomli_w
        toml_str = read_overlay(_OVERLAY_PATH)
        if toml_str is None:
            return None
        try:
            raw = tomllib.loads(toml_str)
            strip_overlay_unsafe_keys(raw)
            return tomli_w.dumps(raw) if raw else None
        except Exception:
            log.warning("Could not sanitise startup overlay; skipping it", exc_info=True)
            return None

    def __init__(self) -> None:
        self._cfg: AppConfig | None = None
        self._cfg_baseline: AppConfig | None = None
        self._cfg_path: Path | None = None
        self._client: CentralClient | None = None
        self._task: asyncio.Task | None = None
        self._start_time: datetime | None = None
        self._overlay: dict | None = None
        self._last_config_fetch_at: datetime | None = None
        self._state_path: Path = _STATE_PATH
        self._overlay_path: Path = _OVERLAY_PATH

    def config_fields(self) -> list[ConfigField]:
        return [
            ConfigField("api_key", "Fleet server API key", secret=True),
            ConfigField("server_url", "Fleet server URL"),
            ConfigField("allow_http", "Allow plain HTTP connections to the fleet server (default: false)"),
            ConfigField("heartbeat_interval_seconds", "Seconds between daemon heartbeats (default: 300, min: 60)"),
            ConfigField("config_fetch_interval_seconds", "Seconds between config overlay fetches (default: 3600, min: 60)"),
        ]

    def setup(self, cfg: "AppConfig", config_path: "Path | None" = None) -> None:
        self._state_path = _STATE_PATH      # read at setup time (allows test patching)
        self._overlay_path = _OVERLAY_PATH  # read at setup time (allows test patching)
        self._cfg = cfg
        self._cfg_path = config_path
        # Capture a clean baseline from the base config file, without applying
        # the persisted overlay, so _clear_config_overlay() can restore the true
        # pre-overlay state. If this fails, baseline stays None and the fallback
        # in _clear_config_overlay is skipped rather than silently keeping stale
        # overlay values.
        self._cfg_baseline: "AppConfig | None" = None
        try:
            from packagealert.config import load_config_without_overlay
            self._cfg_baseline = load_config_without_overlay(config_path)
        except Exception:
            log.warning("pa-central: failed to capture pre-overlay config baseline", exc_info=True)
        fleet_cfg = cfg.plugins.pa_central
        self._client = CentralClient(
            server_url=fleet_cfg.server_url,
            api_key=fleet_cfg.api_key,
            allow_http=fleet_cfg.allow_http,
        )
        state = read_state(self._state_path)
        if state.get("last_config_fetch_at"):
            try:
                self._last_config_fetch_at = datetime.fromisoformat(state["last_config_fetch_at"])
            except Exception:
                pass

    def _hostname(self) -> str:
        return socket.gethostname()

    def _pa_version(self) -> str | None:
        try:
            from importlib.metadata import version
            return version("package-alert")
        except Exception:
            return None

    def _uptime_seconds(self) -> int | None:
        if self._start_time is None:
            return None
        return int((datetime.now(timezone.utc) - self._start_time).total_seconds())

    def _apply_config_overlay(self, toml_str: str) -> None:
        try:
            raw = tomllib.loads(toml_str)
            strip_overlay_unsafe_keys(raw)
            self._overlay = raw
            import tomli_w
            write_overlay(tomli_w.dumps(raw), self._overlay_path)
        except Exception:
            log.warning("Failed to parse fleet config overlay", exc_info=True)
            return
        if self._cfg is not None:
            apply_overlay_to_config(tomli_w.dumps(self._overlay), self._cfg)

    def _clear_config_overlay(self) -> None:
        """Remove the persisted overlay and restore in-memory config to its pre-overlay state.

        Reloads the base config from disk (with the overlay file already removed) so that
        any previously-applied overlay values are fully reverted. Falls back to the baseline
        snapshot captured at setup() if the reload fails.
        """
        self._overlay = {}
        try:
            self._overlay_path.unlink(missing_ok=True)
        except Exception:
            log.warning("Failed to remove fleet config overlay file", exc_info=True)
        if self._cfg is None:
            return
        restored: "AppConfig | None" = None
        try:
            from packagealert.config import load_config_without_overlay
            restored = load_config_without_overlay(self._cfg_path)
        except Exception:
            log.warning("Failed to reload base config after overlay clear — using startup baseline", exc_info=True)
        source = restored if restored is not None else self._cfg_baseline
        if source is not None:
            for field_name in type(self._cfg).model_fields:
                setattr(self._cfg, field_name, getattr(source, field_name))

    async def on_daemon_start(self, uptime_start: datetime) -> None:
        self._start_time = uptime_start
        if not self._client.configured:
            return
        ok, err = await self._client.heartbeat(
            hostname=self._hostname(),
            pa_version=self._pa_version(),
            daemon_status="running",
            uptime_seconds=0,
        )
        state = read_state(self._state_path)
        state["last_heartbeat_at"] = datetime.now(timezone.utc).isoformat()
        state["last_heartbeat_ok"] = ok
        state["last_heartbeat_error"] = err
        write_state(state, self._state_path)
        await self._fetch_and_apply()
        self._task = asyncio.create_task(self._background_loop())

    async def on_daemon_stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._client is not None:
            if self._client.configured:
                ok, err = await self._client.heartbeat(
                    hostname=self._hostname(),
                    pa_version=self._pa_version(),
                    daemon_status="stopped",
                    uptime_seconds=self._uptime_seconds(),
                )
                state = read_state(self._state_path)
                state["last_heartbeat_at"] = datetime.now(timezone.utc).isoformat()
                state["last_heartbeat_ok"] = ok
                state["last_heartbeat_error"] = err
                write_state(state, self._state_path)
            await self._client.aclose()

    async def on_alert(self, event: "PackageEvent", result: "OsvResult | RiskReport") -> None:
        if self._client is not None and self._client.configured:
            await self._client.report_alert(self._hostname(), event, result)

    def is_scan_store(self) -> bool:
        return self._client is not None and self._client.configured

    async def on_scan_complete(self, scan: "ScanResult") -> None:
        if self._client is not None and self._client.configured:
            await self._client.report_scan(self._hostname(), scan)

    async def scans_list(self, project_path: str, hostname: str, limit: int) -> bool:
        if self._client is None or not self._client.configured:
            return False
        records = await self._client.list_scans(hostname, project_path, limit)
        if records is None:
            from rich.console import Console
            Console().print("[red]Failed to fetch scans from fleet server.[/red]")
            return True
        _render_scans_table(records, title=f"Scan results: {project_path}")
        return True

    async def scans_listall(self, hostname: str, limit: int) -> bool:
        if self._client is None or not self._client.configured:
            return False
        records = await self._client.list_scans(hostname, None, limit)
        if records is None:
            from rich.console import Console
            Console().print("[red]Failed to fetch scans from fleet server.[/red]")
            return True
        _render_scans_table(records, title="All scan results", show_project=True)
        return True

    async def scans_show(self, scan_id: int, fmt: str, show_details: bool) -> bool:
        if self._client is None or not self._client.configured:
            return False
        try:
            record = await self._client.get_scan(scan_id)
        except ScanNotFound:
            # Server authoritatively says this scan ID does not exist — don't
            # fall through to local SQLite, which uses a different ID space.
            from rich.console import Console
            Console().print(f"[red]No scan result found with ID {scan_id}[/red]")
            return True
        if record is None:
            # Network/server error — fall through so the user gets feedback.
            return False
        _render_scan_detail(record, fmt, show_details)
        return True

    async def _fetch_and_apply(self) -> None:
        assert self._client is not None
        hostname = self._hostname()
        now = datetime.now(timezone.utc)
        state = read_state(self._state_path)

        toml_str, cfg_err = await self._client.fetch_config(hostname)
        if toml_str is None:
            pass  # 204 (no change) or error — leave existing overlay in place
        elif not toml_str.strip():
            self._clear_config_overlay()  # empty 200 — server is clearing the overlay
        else:
            self._apply_config_overlay(toml_str)
        self._last_config_fetch_at = now
        state["last_config_fetch_at"] = now.isoformat()
        state["last_config_fetch_ok"] = cfg_err is None
        state["last_config_fetch_error"] = cfg_err

        entries = await self._client.fetch_cooldowns(hostname)
        if entries:
            await self._sync_cooldowns(entries)

        write_state(state, self._state_path)

    async def _sync_cooldowns(self, entries: list[dict]) -> None:
        try:
            from packagealert.storage.db import open_db, store_cooldown_cleared
            db = await open_db()
            try:
                for entry in entries:
                    pkg = entry.get("package_name")
                    version = entry.get("package_version")
                    ecosystem = entry.get("ecosystem", "pypi")
                    if pkg and version:
                        await store_cooldown_cleared(db, ecosystem=ecosystem, package=pkg, version=version)
            finally:
                await db.close()
        except Exception:
            log.warning("Fleet cooldown sync failed", exc_info=True)

    async def _background_loop(self) -> None:
        assert self._cfg is not None
        assert self._client is not None
        fleet_cfg = self._cfg.plugins.pa_central
        tick = max(min(fleet_cfg.heartbeat_interval_seconds, fleet_cfg.config_fetch_interval_seconds), 1)
        _last_heartbeat_at: datetime | None = None
        while True:
            await asyncio.sleep(tick)
            now = datetime.now(timezone.utc)
            hostname = self._hostname()

            hb_due = (
                _last_heartbeat_at is None
                or (now - _last_heartbeat_at).total_seconds() >= fleet_cfg.heartbeat_interval_seconds
            )
            if hb_due:
                ok, err = await self._client.heartbeat(
                    hostname=hostname,
                    pa_version=self._pa_version(),
                    daemon_status="running",
                    uptime_seconds=self._uptime_seconds(),
                )
                _last_heartbeat_at = now
                state = read_state(self._state_path)
                state["last_heartbeat_at"] = now.isoformat()
                state["last_heartbeat_ok"] = ok
                state["last_heartbeat_error"] = err
                write_state(state, self._state_path)

            cfg_due = (
                self._last_config_fetch_at is None
                or (now - self._last_config_fetch_at).total_seconds() >= fleet_cfg.config_fetch_interval_seconds
            )
            if cfg_due:
                await self._fetch_and_apply()
