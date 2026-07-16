from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import socket
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from packagealert.plugins.base import AgentPlugin, ConfigField, ScanNotFound
from packagealert.plugins.central.client import AlertPayload, CentralClient, ScanPayload
from packagealert.plugins.central import outbox
from packagealert.plugins.central.outbox import OutboxEntry, OutboxKind
from packagealert.plugins.central.state import read_state, read_overlay, write_state, write_overlay, strip_overlay_unsafe_keys, _STATE_PATH, _OVERLAY_PATH
from packagealert.storage.db import DEFAULT_DB_PATH, open_db

if TYPE_CHECKING:
    import aiosqlite
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


def _log_unparseable_outbox_entry(entry_id: int, kind: str, outcome: str) -> None:
    """Log the shared "BUG: central_outbox entry ... unparseable payload_json"
    message, with *outcome* describing what this call site does about it
    (e.g. "Discarding permanently.", "Skipping in pending-sync display.").

    payload_json is written once at enqueue time and never mutated, so a
    parse failure here always indicates a serialization or DB corruption
    bug, not a transient failure — every call site treats it the same way
    (log loudly, exclude the entry, never retry), just with a different
    concrete action. Centralised so the three call sites (pending-sync
    display, project-filtered pending-sync display, drain) can't drift out
    of sync in wording.
    """
    log.error(
        "BUG: central_outbox entry %d (kind=%s) has unparseable payload_json "
        "— this indicates a serialization or DB corruption bug, not a "
        "transient failure. %s",
        entry_id, kind, outcome, exc_info=True,
    )


def _render_pending_outbox(entries: list[OutboxEntry]) -> None:
    import json as jsonlib
    from datetime import datetime
    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table
    if not entries:
        return
    table = Table(title="Pending sync (queued locally, central unreachable)")
    table.add_column("Project", style="bold")
    table.add_column("Queued at")
    table.add_column("Findings", justify="right")
    rows_added = 0
    for e in entries:
        try:
            payload = jsonlib.loads(e.payload_json)
        except Exception:
            # This is a read-only display path (unlike _drain_outbox, it must
            # not mutate the outbox), but an unparseable entry here is the
            # same underlying bug _drain_outbox already flags loudly — log
            # it the same way so corruption is diagnosable rather than
            # silently producing a table with no rows under it.
            _log_unparseable_outbox_entry(e.id, e.kind, "Skipping in pending-sync display.")
            continue
        queued_at = datetime.fromtimestamp(e.created_at).strftime("%Y-%m-%d %H:%M")
        table.add_row(
            escape(str(payload.get("root") or "")),
            queued_at,
            escape(str(payload.get("finding_count") or 0)),
        )
        rows_added += 1
    if rows_added == 0:
        return
    Console().print(table)


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

    @classmethod
    def extra_schema(cls) -> str | None:
        return """
        CREATE TABLE IF NOT EXISTS central_outbox (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            kind         TEXT NOT NULL CHECK(kind IN ('scan', 'alert')),
            payload_json TEXT NOT NULL,
            created_at   REAL NOT NULL,
            attempts     INTEGER NOT NULL DEFAULT 0,
            last_error   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_central_outbox_created ON central_outbox(created_at);
        """

    def __init__(self) -> None:
        self._cfg: AppConfig | None = None
        self._cfg_baseline: AppConfig | None = None
        self._cfg_path: Path | None = None
        self._client: CentralClient | None = None
        self._task: asyncio.Task | None = None
        self._db: "aiosqlite.Connection | None" = None  # long-lived connection, set in on_daemon_start()
        # Guards every use of self._db. aiosqlite serializes individual
        # execute()/commit() calls on its worker thread, but NOT an entire
        # multi-statement coroutine sequence — outbox.enqueue()'s BEGIN
        # IMMEDIATE/INSERT/COMMIT is not atomic against a second coroutine
        # issuing its own BEGIN IMMEDIATE on the SAME connection in between
        # (unlike two separate connections, where BEGIN IMMEDIATE's file
        # lock genuinely serializes them). Confirmed directly: two
        # concurrent enqueue() calls sharing one connection produced
        # `OperationalError('cannot start a transaction within a
        # transaction')` on one of them, silently discarding that report.
        # schedule_alert() explicitly fires each alert as an independent
        # background task, so concurrent _enqueue_outbox() calls against
        # self._db are a real, expected occurrence, not a hypothetical one —
        # and _drain_outbox() runs concurrently with those from its own
        # periodic tick. This lock must be held across each COMPLETE
        # operation against self._db (the whole enqueue call, or the whole
        # drain loop's sequence of dequeue/delete/mark_failed calls), not
        # just around opening the connection.
        self._db_lock = asyncio.Lock()
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

    def _record_heartbeat_result(self, ok: bool, err: str | None, *, at: datetime) -> None:
        state = read_state(self._state_path)
        state["last_heartbeat_at"] = at.isoformat()
        state["last_heartbeat_ok"] = ok
        state["last_heartbeat_error"] = err
        if ok:
            # Only updated on success — unlike last_heartbeat_at/ok above,
            # this survives a subsequent failed heartbeat so `pa status` can
            # answer "when did we last actually hear back from central."
            state["last_seen_at"] = at.isoformat()
        write_state(state, self._state_path)

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
        self._record_heartbeat_result(ok, err, at=datetime.now(timezone.utc))
        await self._fetch_and_apply()
        # Long-lived connection reused by _enqueue_outbox/_drain_outbox for
        # the daemon's whole lifetime, instead of each call re-running
        # open_db()'s full schema/migration pass — _drain_outbox() fires on
        # every background-loop tick and _enqueue_outbox() on every failed
        # alert/scan report, so re-doing that work per call is real,
        # sustained cost. Left None if this fails; both call sites already
        # fall back to a per-call open_db() when self._db is unavailable.
        try:
            self._db = await open_db(DEFAULT_DB_PATH, enabled_plugins={"pa-central"})
        except Exception:
            log.warning("pa-central: failed to open long-lived outbox connection — falling back to per-call open_db()", exc_info=True)
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
                self._record_heartbeat_result(ok, err, at=datetime.now(timezone.utc))
            await self._client.aclose()
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def on_alert(self, event: "PackageEvent", result: "OsvResult | RiskReport") -> None:
        if self._client is None or not self._client.configured:
            return
        outcome = await self._client.report_alert(self._hostname(), event, result)
        if not outcome.ok and outcome.payload is not None:
            await self._enqueue_outbox("alert", outcome.payload)

    def is_scan_store(self) -> bool:
        return self._client is not None and self._client.configured

    async def on_scan_complete(self, scan: "ScanResult") -> None:
        if self._client is None or not self._client.configured:
            return
        outcome = await self._client.report_scan(self._hostname(), scan)
        if not outcome.ok and outcome.payload is not None:
            await self._enqueue_outbox("scan", outcome.payload)

    async def scans_list(self, project_path: str, hostname: str, limit: int) -> bool:
        if self._client is None or not self._client.configured:
            return False
        records = await self._client.list_scans(hostname, project_path, limit)
        if records is None:
            from rich.console import Console
            Console().print("[red]Failed to fetch scans from fleet server.[/red]")
            await self._render_pending_scans(project_path)
            return True
        _render_scans_table(records, title=f"Scan results: {project_path}")
        await self._render_pending_scans(project_path)
        return True

    async def scans_listall(self, hostname: str, limit: int) -> bool:
        if self._client is None or not self._client.configured:
            return False
        records = await self._client.list_scans(hostname, None, limit)
        if records is None:
            from rich.console import Console
            Console().print("[red]Failed to fetch scans from fleet server.[/red]")
            await self._render_pending_scans(None)
            return True
        _render_scans_table(records, title="All scan results", show_project=True)
        await self._render_pending_scans(None)
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

    async def _render_pending_scans(self, project_path: str | None) -> None:
        try:
            db = await open_db(DEFAULT_DB_PATH, enabled_plugins={"pa-central"})
        except Exception:
            log.warning("Failed to open DB for pending-scan display", exc_info=True)
            return
        try:
            try:
                entries = await outbox.dequeue_all(db, kind="scan")
            finally:
                await db.close()
        except Exception:
            log.warning("Failed to read central_outbox for pending-scan display", exc_info=True)
            return
        if project_path is not None:
            import json as jsonlib
            filtered = []
            for e in entries:
                try:
                    payload = jsonlib.loads(e.payload_json)
                except Exception:
                    # Same underlying bug _render_pending_outbox/_drain_outbox
                    # already flag loudly — log it here too, since this
                    # filter runs first and would otherwise silently drop
                    # the entry before it ever reaches that logging.
                    _log_unparseable_outbox_entry(e.id, e.kind, "Excluding from project-filtered pending-sync display.")
                    continue
                if payload.get("root") == project_path:
                    filtered.append(e)
            entries = filtered
        _render_pending_outbox(entries)

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
            db = await open_db(enabled_plugins={"pa-central"})
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

    async def _enqueue_outbox(
        self, kind: OutboxKind, payload: ScanPayload | AlertPayload | None
    ) -> None:
        if payload is None:
            return
        # Reuse the long-lived connection opened in on_daemon_start() when
        # available (the common case — on_alert/on_scan_complete both fire
        # from the daemon). Falls back to a per-call open_db() for
        # on_scan_complete's other callers (scheduled scans, one-shot CLI
        # scans), which run without the daemon lifecycle ever starting.
        if self._db is not None:
            try:
                async with self._db_lock:
                    await outbox.enqueue(self._db, kind=kind, payload_json=json.dumps(payload))
            except Exception:
                log.warning("Failed to enqueue %s report to central_outbox", kind, exc_info=True)
            return
        try:
            db = await open_db(DEFAULT_DB_PATH, enabled_plugins={"pa-central"})
            try:
                await outbox.enqueue(db, kind=kind, payload_json=json.dumps(payload))
            finally:
                await db.close()
        except Exception:
            log.warning("Failed to enqueue %s report to central_outbox", kind, exc_info=True)

    async def _drain_outbox(self) -> None:
        assert self._client is not None
        # _drain_outbox only runs from _background_loop, which only starts
        # after on_daemon_start() has already tried to open self._db — so
        # self._db is set here unless that open failed, in which case fall
        # back to a per-call connection rather than skipping the drain
        # entirely for the rest of the daemon's lifetime. owns_db tracks
        # whether THIS call opened its own connection (and so must close
        # it) versus borrowed the long-lived self._db (which must survive
        # for the next tick — closing it here would break every
        # subsequent drain for the rest of the daemon's lifetime).
        if self._db is not None:
            db = self._db
            owns_db = False
        else:
            try:
                db = await open_db(DEFAULT_DB_PATH, enabled_plugins={"pa-central"})
            except Exception:
                log.warning("Failed to open DB for central_outbox drain", exc_info=True)
                return
            owns_db = True
        # Every individual call against the shared db is wrapped in
        # self._db_lock (a no-op contextlib.nullcontext() when owns_db — a
        # per-call connection is never shared with a concurrent
        # _enqueue_outbox(), so no lock is needed there). The lock is NOT
        # held across self._client.send_*_payload()'s network I/O between
        # DB calls — only around each discrete dequeue_all/delete/
        # mark_failed — so a slow fleet-server response can't stall
        # concurrent alert reports behind this drain for the network
        # call's full duration.
        lock = contextlib.nullcontext() if owns_db else self._db_lock
        try:
            try:
                async with lock:
                    entries = await outbox.dequeue_all(db)
                for i, entry in enumerate(entries):
                    try:
                        payload = json.loads(entry.payload_json)
                    except Exception:
                        # payload_json is written once at enqueue time and never
                        # mutated, so a parse failure here can never resolve on a
                        # future retry — retrying would just loop forever, wasting
                        # a queue slot until the cap eventually evicts it with no
                        # trace of why. Deleting now is the correct outcome, but
                        # this should never happen in practice: it indicates a bug
                        # in payload construction/serialization or DB corruption,
                        # not a transient failure. Log loudly so it's investigated.
                        _log_unparseable_outbox_entry(entry.id, entry.kind, "Discarding permanently.")
                        async with lock:
                            await outbox.delete(db, entry.id)
                        continue
                    if entry.kind == "scan":
                        outcome = await self._client.send_scan_payload(payload)
                    else:
                        outcome = await self._client.send_alert_payload(payload)
                    if outcome.ok:
                        async with lock:
                            await outbox.delete(db, entry.id)
                        continue
                    async with lock:
                        await outbox.mark_failed(db, entry.id, outcome.error or "send failed")
                    if outcome.error_kind == "retryable":
                        # Server-wide/retryable failure — connection-level
                        # (refused, timed out, DNS failure), or an HTTP
                        # response indicating the server itself is the
                        # problem (5xx, 429 rate limited, 401/403 auth
                        # broken) — rather than a rejection specific to this
                        # one payload. Every other queued entry would almost
                        # certainly fail identically this tick, so stop here
                        # instead of burning a request per row against a
                        # server that's down, overloaded, or rate-limiting.
                        # They stay queued and are retried next tick.
                        log.warning(
                            "central_outbox drain stopping early: retryable error "
                            "(%s) — %d/%d entries remain queued for next tick",
                            outcome.error, len(entries) - i, len(entries),
                        )
                        break
            finally:
                if owns_db:
                    await db.close()
        except Exception:
            log.warning("central_outbox drain failed", exc_info=True)

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
                self._record_heartbeat_result(ok, err, at=now)

            cfg_due = (
                self._last_config_fetch_at is None
                or (now - self._last_config_fetch_at).total_seconds() >= fleet_cfg.config_fetch_interval_seconds
            )
            if cfg_due:
                await self._fetch_and_apply()

            await self._drain_outbox()
