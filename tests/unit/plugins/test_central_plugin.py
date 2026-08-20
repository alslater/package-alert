from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from packagealert.config import AppConfig
from packagealert.models.advisories import OsvAdvisory, OsvResult
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport, RiskSignal
from packagealert.models.scans import ScanResult
from packagealert.plugins.central import outbox
from packagealert.plugins.central.client import ReportResult, build_scan_payload
from packagealert.storage.db import open_db


def test_central_plugin_extra_schema_creates_central_outbox_table():
    from packagealert.plugins.central.plugin import CentralPlugin
    schema = CentralPlugin.extra_schema()
    assert schema is not None
    assert "CREATE TABLE IF NOT EXISTS central_outbox" in schema
    assert "idx_central_outbox_created" in schema


async def test_open_db_with_pa_central_enabled_creates_central_outbox(tmp_path):
    from packagealert.storage.db import open_db
    conn = await open_db(tmp_path / "test.db", enabled_plugins={"pa-central"})
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            rows = await cur.fetchall()
        tables = {r["name"] for r in rows}
        assert "central_outbox" in tables
    finally:
        await conn.close()


async def test_open_db_with_pa_central_disabled_does_not_create_central_outbox(tmp_path):
    from packagealert.storage.db import open_db
    conn = await open_db(tmp_path / "test.db", enabled_plugins=set())
    try:
        async with conn.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
            rows = await cur.fetchall()
        tables = {r["name"] for r in rows}
        assert "central_outbox" not in tables
    finally:
        await conn.close()


def _cfg(api_key: str = "sk-test", server_url: str = "https://fleet.example.com") -> AppConfig:
    cfg = AppConfig()
    cfg.plugins.enabled = ["pa-central"]
    cfg.plugins.pa_central.api_key = api_key
    cfg.plugins.pa_central.server_url = server_url
    cfg.plugins.pa_central.heartbeat_interval_seconds = 60
    cfg.plugins.pa_central.config_fetch_interval_seconds = 120
    return cfg


def _event() -> PackageEvent:
    return PackageEvent(
        ecosystem="pypi", package_name="evil", version="1.0",
        source="process", manager="pip", project_path=None,
        timestamp=datetime.now(UTC),
    )


def _osv() -> OsvResult:
    return OsvResult(
        ecosystem="pypi", package_name="evil", version="1.0",
        advisories=[OsvAdvisory(id="MAL-1", summary="bad", severity="CRITICAL")],
    )


def _risk() -> RiskReport:
    return RiskReport(
        package_name="risky", ecosystem="pypi", score=80,
        signals=[RiskSignal(name="typosquat", score=80, reason="looks bad")],
    )


def _scan(*, finding_count: int = 0, findings: list | None = None) -> ScanResult:
    return ScanResult(
        project_path="/proj", scan_type="project",
        finding_count=finding_count, findings=findings if findings is not None else [],
        sources=["pypi"], scanned_at=datetime.now(UTC),
    )


def _setup_plugin(tmp_path: Path, cfg=None):
    from packagealert.plugins.central.plugin import CentralPlugin
    plugin = CentralPlugin()
    with patch("packagealert.plugins.central.plugin._STATE_PATH", tmp_path / "central-state.json"), \
         patch("packagealert.plugins.central.plugin._OVERLAY_PATH", tmp_path / "central-overlay.toml"):
        plugin.setup(cfg or _cfg())
    return plugin


@pytest.fixture
async def plugin(tmp_path):
    """A configured CentralPlugin with DEFAULT_DB_PATH patched to a per-test
    temp file for the duration of the test, and the client closed afterward.

    Most tests just need a ready-to-use plugin; construct it via `_setup_plugin`
    directly (with a custom cfg) only when a test needs that flexibility.
    """
    p = _setup_plugin(tmp_path)
    with patch("packagealert.plugins.central.plugin.DEFAULT_DB_PATH", tmp_path / "pa.db"):
        yield p
    await p._client.aclose()


async def _seed_outbox(tmp_path: Path, *, kind: str, payload) -> None:
    """Enqueue one entry with the given kind and payload (dict, JSON-encoded)."""
    db = await open_db(tmp_path / "pa.db", enabled_plugins={"pa-central"})
    try:
        await outbox.enqueue(db, kind=kind, payload_json=json.dumps(payload))
    finally:
        await db.close()


async def _seed_outbox_raw(tmp_path: Path, *, kind: str, payload_json: str) -> None:
    """Enqueue one entry with a raw (possibly malformed) payload_json string."""
    db = await open_db(tmp_path / "pa.db", enabled_plugins={"pa-central"})
    try:
        await outbox.enqueue(db, kind=kind, payload_json=payload_json)
    finally:
        await db.close()


async def _read_outbox(tmp_path: Path, *, kind: str | None = None) -> list[outbox.OutboxEntry]:
    db = await open_db(tmp_path / "pa.db", enabled_plugins={"pa-central"})
    try:
        return await outbox.dequeue_all(db, kind=kind)
    finally:
        await db.close()


async def test_setup_creates_client(plugin):
    assert plugin._client is not None


async def test_on_alert_osv_calls_report_alert(plugin):
    plugin._client.report_alert = AsyncMock(return_value=ReportResult(ok=True, payload=None))
    await plugin.on_alert(_event(), _osv())
    plugin._client.report_alert.assert_awaited_once()


async def test_on_alert_risk_calls_report_alert(plugin):
    plugin._client.report_alert = AsyncMock(return_value=ReportResult(ok=True, payload=None))
    await plugin.on_alert(_event(), _risk())
    plugin._client.report_alert.assert_awaited_once()


async def test_on_scan_complete_with_findings(plugin):
    plugin._client.report_scan = AsyncMock(
        return_value=ReportResult(ok=True, payload={"root": "/proj"})
    )
    await plugin.on_scan_complete(_scan(finding_count=2, findings=[{}]))
    plugin._client.report_scan.assert_awaited_once()


async def test_on_scan_complete_no_findings_reports(plugin):
    plugin._client.report_scan = AsyncMock(
        return_value=ReportResult(ok=True, payload={"root": "/proj"})
    )
    await plugin.on_scan_complete(_scan())
    plugin._client.report_scan.assert_awaited_once()


async def test_on_scan_complete_enqueues_on_failure(plugin, tmp_path):
    failed_payload = {"root": "/proj", "finding_count": 1}
    plugin._client.report_scan = AsyncMock(
        return_value=ReportResult(ok=False, payload=failed_payload, error="send failed")
    )
    await plugin.on_scan_complete(_scan(finding_count=1, findings=[{}]))

    entries = await _read_outbox(tmp_path, kind="scan")
    assert len(entries) == 1
    # the enqueued payload is the exact one report_scan already built and
    # attempted to send — on_scan_complete must not rebuild it.
    assert json.loads(entries[0].payload_json) == failed_payload


async def test_on_scan_complete_does_not_enqueue_on_success(plugin, tmp_path):
    plugin._client.report_scan = AsyncMock(
        return_value=ReportResult(ok=True, payload={"root": "/proj"}, error=None)
    )
    await plugin.on_scan_complete(_scan())

    assert await _read_outbox(tmp_path, kind="scan") == []


async def test_on_scan_complete_does_not_enqueue_when_payload_is_none(plugin, tmp_path):
    # report_scan() builds the payload exactly once, inside CentralClient;
    # on_scan_complete never rebuilds it, so a build failure there (which
    # report_scan() surfaces as ok=False, payload=None) must not attempt to
    # enqueue anything, and must not raise.
    plugin._client.report_scan = AsyncMock(
        return_value=ReportResult(ok=False, payload=None, error="payload build error")
    )
    await plugin.on_scan_complete(_scan(finding_count=1, findings=[{}]))

    assert await _read_outbox(tmp_path, kind="scan") == []


async def test_on_alert_enqueues_on_failure(plugin, tmp_path):
    failed_payload = {"package_name": "evil", "kind": "osv"}
    plugin._client.report_alert = AsyncMock(
        return_value=ReportResult(ok=False, payload=failed_payload, error="send failed")
    )
    await plugin.on_alert(_event(), _osv())

    entries = await _read_outbox(tmp_path, kind="alert")
    assert len(entries) == 1
    assert json.loads(entries[0].payload_json) == failed_payload


async def test_on_alert_does_not_enqueue_on_success(plugin, tmp_path):
    plugin._client.report_alert = AsyncMock(
        return_value=ReportResult(ok=True, payload={"package_name": "evil"}, error=None)
    )
    await plugin.on_alert(_event(), _osv())

    assert await _read_outbox(tmp_path, kind="alert") == []


async def test_on_alert_does_not_enqueue_when_payload_is_none(plugin, tmp_path):
    # report_alert() builds the payload exactly once, inside CentralClient;
    # on_alert never rebuilds it, so a build failure there (which
    # report_alert() surfaces as ok=False, payload=None) must not attempt to
    # enqueue anything, and must not raise.
    plugin._client.report_alert = AsyncMock(
        return_value=ReportResult(ok=False, payload=None, error="payload build error")
    )
    await plugin.on_alert(_event(), _osv())

    assert await _read_outbox(tmp_path, kind="alert") == []


async def test_config_overlay_strips_credentials(tmp_path):
    cfg = _cfg()
    plugin = _setup_plugin(tmp_path, cfg)
    toml = 'api_key = "evil"\nserver_url = "https://evil.com"\n[heuristics]\nwarning_threshold = 99\n'
    plugin._apply_config_overlay(toml)
    # credentials must not be changed
    assert cfg.plugins.pa_central.api_key == "sk-test"
    assert cfg.plugins.pa_central.server_url == "https://fleet.example.com"
    # overlay applied
    assert plugin._overlay is not None
    await plugin._client.aclose()


async def test_config_overlay_strips_plugins_enabled(tmp_path):
    cfg = _cfg()
    plugin = _setup_plugin(tmp_path, cfg)
    toml = '[plugins]\nenabled = ["evil-plugin"]\n[heuristics]\nwarning_threshold = 99\n'
    plugin._apply_config_overlay(toml)
    # fleet server must not be able to enable additional plugins
    assert "evil-plugin" not in cfg.plugins.enabled
    assert plugin._overlay is not None
    assert plugin._overlay.get("plugins", {}).get("enabled") is None
    await plugin._client.aclose()


async def test_on_daemon_stop_sends_stopped_heartbeat(plugin):
    plugin._client.heartbeat = AsyncMock(return_value=(True, None))
    plugin._task = None
    await plugin.on_daemon_stop()
    plugin._client.heartbeat.assert_awaited_once()
    call_args = plugin._client.heartbeat.call_args
    assert "stopped" in str(call_args)


async def test_last_seen_at_set_on_successful_heartbeat(plugin, tmp_path):
    from packagealert.plugins.central.state import read_state

    plugin._client.heartbeat = AsyncMock(return_value=(True, None))
    plugin._task = None
    await plugin.on_daemon_stop()

    state = read_state(tmp_path / "central-state.json")
    assert state["last_seen_at"] is not None
    assert state["last_seen_at"] == state["last_heartbeat_at"]


async def test_last_seen_at_survives_a_subsequent_failed_heartbeat(plugin, tmp_path):
    # last_heartbeat_at/ok get overwritten on every attempt, but last_seen_at
    # must only ever move forward on success — a later failed heartbeat must
    # not erase the record of when we last actually heard back.
    from packagealert.plugins.central.state import read_state

    plugin._client.heartbeat = AsyncMock(return_value=(True, None))
    plugin._client.fetch_config = AsyncMock(return_value=(None, None))
    plugin._client.fetch_cooldowns = AsyncMock(return_value=None)
    plugin._task = None
    try:
        await plugin.on_daemon_start(datetime.now(UTC))
        state_after_success = read_state(tmp_path / "central-state.json")
        last_seen_after_success = state_after_success["last_seen_at"]
        assert last_seen_after_success is not None

        plugin._client.heartbeat = AsyncMock(return_value=(False, "connection refused"))
        await plugin.on_daemon_stop()

        state_after_failure = read_state(tmp_path / "central-state.json")
        assert state_after_failure["last_heartbeat_ok"] is False
        assert state_after_failure["last_heartbeat_error"] == "connection refused"
        # last_seen_at is unchanged — still points at the earlier success.
        assert state_after_failure["last_seen_at"] == last_seen_after_success
    finally:
        # on_daemon_stop already cancels/awaits plugin._task in the success
        # path above, but guard here in case the test fails before that.
        if plugin._task is not None and not plugin._task.done():
            plugin._task.cancel()


async def test_drain_outbox_deletes_on_success(plugin, tmp_path):
    plugin._client.send_scan_payload = AsyncMock(
        return_value=ReportResult(ok=True, payload={"a": 1})
    )
    plugin._client.send_alert_payload = AsyncMock(
        return_value=ReportResult(ok=True, payload={"b": 2})
    )
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 1})
    await _seed_outbox(tmp_path, kind="alert", payload={"b": 2})

    await plugin._drain_outbox()

    assert await _read_outbox(tmp_path) == []
    plugin._client.send_scan_payload.assert_awaited_once_with({"a": 1})
    plugin._client.send_alert_payload.assert_awaited_once_with({"b": 2})


async def test_drain_outbox_marks_failed_and_keeps_entry(plugin, tmp_path):
    plugin._client.send_scan_payload = AsyncMock(
        return_value=ReportResult(ok=False, payload={"a": 1}, error="HTTP 503 — server unavailable")
    )
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 1})

    await plugin._drain_outbox()

    remaining = await _read_outbox(tmp_path)
    assert len(remaining) == 1
    assert remaining[0].attempts == 1
    # last_error carries the actual diagnostic from the failed send, not a
    # generic placeholder — operationally useful for debugging why a report
    # keeps failing to resend.
    assert remaining[0].last_error == "HTTP 503 — server unavailable"


async def test_drain_outbox_stops_early_on_retryable_connection_error(plugin, tmp_path, caplog):
    # A connection-level failure (server unreachable) means every other
    # queued entry would almost certainly fail the same way this tick — stop
    # attempting further entries rather than burning a connection attempt
    # per row. The failed entry is still marked failed and stays queued;
    # entries never attempted are left completely untouched.
    plugin._client.send_scan_payload = AsyncMock(
        return_value=ReportResult(
            ok=False, payload={"a": 1}, error="connection refused", error_kind="retryable"
        )
    )
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 1})
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 2})

    with caplog.at_level("WARNING"):
        await plugin._drain_outbox()

    # send_scan_payload was only attempted once, not twice.
    plugin._client.send_scan_payload.assert_awaited_once()

    remaining = await _read_outbox(tmp_path)
    assert len(remaining) == 2
    attempted = [e for e in remaining if e.attempts > 0]
    untouched = [e for e in remaining if e.attempts == 0]
    assert len(attempted) == 1
    assert attempted[0].last_error == "connection refused"
    assert len(untouched) == 1
    assert untouched[0].last_error is None

    # The log's count must match reality: both rows (the one just marked
    # failed above, plus the untouched one) remain queued for next tick —
    # not just the entries after the failing index.
    assert "2/2 entries remain queued for next tick" in caplog.text


@pytest.mark.parametrize("status, error", [(500, "HTTP 500"), (503, "HTTP 503"), (429, "HTTP 429"), (401, "HTTP 401"), (403, "HTTP 403")])
async def test_drain_outbox_stops_early_on_retryable_http_status(plugin, tmp_path, status, error):
    # 5xx (server error), 429 (rate limited), and 401/403 (auth broken) are
    # server-wide/retryable, not specific to this one payload — the drain
    # must stop rather than sending the rest of a possibly-large queue
    # against a server that's down, overloaded, or rejecting all auth.
    plugin._client.send_scan_payload = AsyncMock(
        return_value=ReportResult(
            ok=False, payload={"a": 1}, error=error, error_kind="retryable"
        )
    )
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 1})
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 2})

    await plugin._drain_outbox()

    plugin._client.send_scan_payload.assert_awaited_once()
    remaining = await _read_outbox(tmp_path)
    untouched = [e for e in remaining if e.attempts == 0]
    assert len(untouched) == 1


async def test_drain_outbox_does_not_stop_early_on_payload_specific_http_error(plugin, tmp_path):
    # A payload-specific HTTP error (e.g. 422 validation failure) means the
    # server was reached and is otherwise healthy — it just rejected this
    # one payload. Other queued entries may still succeed, so draining must
    # continue trying them rather than stopping.
    plugin._client.send_scan_payload = AsyncMock(
        return_value=ReportResult(
            ok=False, payload={"a": 1}, error="HTTP 422", error_kind="payload_specific"
        )
    )
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 1})
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 2})

    await plugin._drain_outbox()

    assert plugin._client.send_scan_payload.await_count == 2
    remaining = await _read_outbox(tmp_path)
    assert len(remaining) == 2
    assert all(e.attempts == 1 for e in remaining)


async def test_drain_outbox_discards_unparseable_entry_but_continues(plugin, tmp_path):
    # payload_json is write-once at enqueue time; a row that fails to parse
    # can never resolve on a future retry, so it is permanently discarded
    # (not mark_failed'd) rather than looping forever. The rest of the batch
    # must still be processed.
    plugin._client.send_scan_payload = AsyncMock(
        return_value=ReportResult(ok=True, payload={"a": 1})
    )
    await _seed_outbox_raw(tmp_path, kind="scan", payload_json="{not valid json")
    await _seed_outbox(tmp_path, kind="scan", payload={"a": 1})

    await plugin._drain_outbox()

    # Malformed entry is gone entirely (not marked failed, not retried).
    assert await _read_outbox(tmp_path) == []
    # The well-formed entry in the same batch was still sent and deleted.
    plugin._client.send_scan_payload.assert_awaited_once_with({"a": 1})


async def test_on_daemon_start_opens_long_lived_db_connection(tmp_path):
    # _enqueue_outbox/_drain_outbox reuse a connection opened once in
    # on_daemon_start(), rather than re-running open_db()'s full
    # schema/migration pass on every call — real cost given _drain_outbox
    # fires every background-loop tick for the daemon's whole lifetime.
    plugin = _setup_plugin(tmp_path)
    plugin._client.heartbeat = AsyncMock(return_value=(True, None))
    plugin._client.fetch_config = AsyncMock(return_value=(None, None))
    plugin._client.fetch_cooldowns = AsyncMock(return_value=None)
    plugin._client.send_scan_payload = AsyncMock(return_value=ReportResult(ok=True, payload={"a": 1}))
    plugin._client.send_alert_payload = AsyncMock(return_value=ReportResult(ok=True, payload={"b": 2}))

    with patch("packagealert.plugins.central.plugin.DEFAULT_DB_PATH", tmp_path / "pa.db"), \
         patch("packagealert.plugins.central.plugin.open_db", wraps=open_db) as wrapped_open_db:
        await plugin.on_daemon_start(datetime.now(UTC))
        try:
            assert plugin._db is not None
            wrapped_open_db.assert_called_once()

            await plugin._enqueue_outbox("scan", {"a": 1})
            await plugin._enqueue_outbox("alert", {"b": 2})
            await plugin._drain_outbox()
            await plugin._drain_outbox()

            # No additional open_db() calls from any of the above — all four
            # reused the connection opened once in on_daemon_start().
            wrapped_open_db.assert_called_once()
        finally:
            plugin._task.cancel()
            await plugin.on_daemon_stop()

    assert plugin._db is None  # closed by on_daemon_stop()
    await plugin._client.aclose()


async def test_concurrent_enqueue_outbox_does_not_lose_reports(plugin, tmp_path):
    # aiosqlite serializes individual execute()/commit() calls on its worker
    # thread, but NOT an entire multi-statement coroutine sequence —
    # outbox.enqueue()'s BEGIN IMMEDIATE/INSERT/COMMIT is not atomic against
    # a second coroutine issuing its own BEGIN IMMEDIATE on the SAME
    # connection in between. schedule_alert() fires each alert as an
    # independent background task, so concurrent _enqueue_outbox() calls
    # against the shared self._db are a real, expected occurrence — without
    # a lock serializing them, one of two concurrent enqueue() calls fails
    # with "cannot start a transaction within a transaction" and its report
    # is silently discarded (caught and logged by _enqueue_outbox()).
    plugin._db = await open_db(tmp_path / "shared.db", enabled_plugins={"pa-central"})
    try:
        await asyncio.gather(
            plugin._enqueue_outbox("alert", {"a": 1}),
            plugin._enqueue_outbox("alert", {"a": 2}),
        )
        entries = await outbox.dequeue_all(plugin._db)
        assert len(entries) == 2, "both concurrent reports must be persisted, not just one"
    finally:
        await plugin._db.close()


async def test_concurrent_enqueue_and_drain_do_not_lose_reports(plugin, tmp_path, caplog):
    # _drain_outbox() runs on its own periodic tick and can overlap with
    # concurrent _enqueue_outbox() calls against the same shared self._db —
    # the drain loop's dequeue_all/delete/mark_failed calls must be
    # serialized against a concurrent enqueue()'s BEGIN IMMEDIATE the same
    # way two enqueue() calls must be serialized against each other. Two
    # concurrent enqueues are included alongside the drain because that
    # pairing is what reliably reproduces the "cannot start a transaction
    # within a transaction" race in practice — a lone enqueue racing a
    # lock-free drain does not reliably interleave badly under asyncio's
    # single-threaded scheduling, but this guards the same self._db_lock
    # path drain uses regardless.
    plugin._db = await open_db(tmp_path / "shared.db", enabled_plugins={"pa-central"})
    plugin._client.send_scan_payload = AsyncMock(return_value=ReportResult(ok=True, payload={"a": 1}))
    plugin._client.send_alert_payload = AsyncMock(return_value=ReportResult(ok=True, payload={"b": 2}))
    try:
        await outbox.enqueue(plugin._db, kind="scan", payload_json=json.dumps({"a": 0}))
        await asyncio.gather(
            plugin._drain_outbox(),
            plugin._enqueue_outbox("alert", {"a": 1}),
            plugin._enqueue_outbox("alert", {"a": 2}),
        )
        assert not any(
            "Failed to enqueue" in r.message or "drain failed" in r.message
            for r in caplog.records
        ), "no enqueue or drain call should have failed/logged an exception"
        # The drain call may or may not have caught the two new entries
        # depending on exact interleaving — the correctness requirement is
        # that neither enqueue() ever raised/lost its report, not a specific
        # ordering. Whatever remains queued must be exactly what wasn't
        # drained, never fewer than that due to a lost write.
        remaining = await outbox.dequeue_all(plugin._db)
        # 3 entries were ever enqueued (1 seeded + 2 concurrent); each is
        # either still queued or was drained (deleted) — total accounted
        # for must be 3, i.e. no entry silently vanished from a failed
        # BEGIN IMMEDIATE without being recorded as drained.
        drained_count = plugin._client.send_alert_payload.await_count + plugin._client.send_scan_payload.await_count
        assert len(remaining) + drained_count == 3
    finally:
        await plugin._db.close()


async def test_scans_list_shows_pending_outbox_entries(plugin, tmp_path, capsys):
    plugin._client.list_scans = AsyncMock(return_value=[])
    payload = build_scan_payload("host", _scan(finding_count=1, findings=[{}]))
    await _seed_outbox(tmp_path, kind="scan", payload=payload)

    handled = await plugin.scans_list("/proj", "host", 20)

    assert handled is True
    out = capsys.readouterr().out
    assert "Pending sync" in out
    assert "/proj" in out


async def test_scans_listall_shows_pending_outbox_entries(plugin, tmp_path, capsys):
    plugin._client.list_scans = AsyncMock(return_value=[])
    payload = build_scan_payload("host", _scan(finding_count=1, findings=[{}]))
    await _seed_outbox(tmp_path, kind="scan", payload=payload)

    handled = await plugin.scans_listall("host", 20)

    assert handled is True
    out = capsys.readouterr().out
    assert "Pending sync" in out


async def test_scans_list_shows_pending_when_central_unreachable(plugin, tmp_path, capsys):
    plugin._client.list_scans = AsyncMock(return_value=None)
    payload = build_scan_payload("host", _scan(finding_count=1, findings=[{}]))
    await _seed_outbox(tmp_path, kind="scan", payload=payload)

    handled = await plugin.scans_list("/proj", "host", 20)

    assert handled is True
    out = capsys.readouterr().out
    assert "Failed to fetch scans from fleet server" in out
    assert "Pending sync" in out
    assert "/proj" in out


async def test_scans_listall_shows_pending_when_central_unreachable(plugin, tmp_path, capsys):
    plugin._client.list_scans = AsyncMock(return_value=None)
    payload = build_scan_payload("host", _scan(finding_count=1, findings=[{}]))
    await _seed_outbox(tmp_path, kind="scan", payload=payload)

    handled = await plugin.scans_listall("host", 20)

    assert handled is True
    out = capsys.readouterr().out
    assert "Failed to fetch scans from fleet server" in out
    assert "Pending sync" in out


async def test_render_pending_scans_swallows_dequeue_error(plugin):
    with patch.object(outbox, "dequeue_all", AsyncMock(side_effect=RuntimeError("boom"))):
        # Must not raise — outbox read failures are logged and swallowed.
        await plugin._render_pending_scans(None)


async def test_scans_list_does_not_crash_on_outbox_read_failure(plugin):
    plugin._client.list_scans = AsyncMock(return_value=[])
    with patch.object(outbox, "dequeue_all", AsyncMock(side_effect=RuntimeError("boom"))):
        handled = await plugin.scans_list("/proj", "host", 20)

    assert handled is True


async def test_scans_list_prints_no_table_when_all_pending_entries_unparseable(plugin, tmp_path, capsys, caplog):
    # If every queued entry's payload_json fails to parse, the pending-sync
    # table must not print with a title and headers but zero data rows —
    # that reads as "there should be data here but it's missing", which is
    # more confusing than showing nothing. The corruption is still logged
    # loudly, matching how _drain_outbox already flags the same condition.
    # scans_list passes a concrete project_path, so entries are dropped by
    # _render_pending_scans's project-path filter before _render_pending_outbox
    # ever sees them — that filter needs its own logging for the same bug.
    plugin._client.list_scans = AsyncMock(return_value=[])
    await _seed_outbox_raw(tmp_path, kind="scan", payload_json="{not valid json")
    await _seed_outbox_raw(tmp_path, kind="scan", payload_json="also not json")

    with caplog.at_level("ERROR"):
        handled = await plugin.scans_list("/proj", "host", 20)

    assert handled is True
    out = capsys.readouterr().out
    assert "Pending sync" not in out
    assert caplog.text.count("BUG: central_outbox entry") == 2


async def test_scans_listall_prints_no_table_when_all_pending_entries_unparseable(plugin, tmp_path, capsys, caplog):
    # scans_listall passes project_path=None, so entries reach
    # _render_pending_outbox directly (bypassing _render_pending_scans's
    # filter) — this exercises that function's own unparseable-entry guard.
    plugin._client.list_scans = AsyncMock(return_value=[])
    await _seed_outbox_raw(tmp_path, kind="scan", payload_json="{not valid json")
    await _seed_outbox_raw(tmp_path, kind="scan", payload_json="also not json")

    with caplog.at_level("ERROR"):
        handled = await plugin.scans_listall("host", 20)

    assert handled is True
    out = capsys.readouterr().out
    assert "Pending sync" not in out
    assert caplog.text.count("BUG: central_outbox entry") == 2


def _scan_record_with_risk() -> dict:
    return {
        "id": 42, "project_path": "/proj", "scan_type": "project",
        "status": "clean", "finding_count": 0, "findings": [],
        "sources": ["pypi"], "scanned_at": "2026-01-01T00:00:00+00:00",
        "risks": [{
            "package": "reqeusts", "ecosystem": "pypi", "version": "1.0.0",
            "score": 46, "level": "warning",
            "signals": [{"name": "typosquat", "score": 15, "reason": "resembles 'requests'"}],
        }],
        "risk_failures": 2,
    }


def test_render_scan_detail_json_includes_risks(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail
    _render_scan_detail(_scan_record_with_risk(), "json", show_details=False)
    out = json.loads(capsys.readouterr().out)
    assert out["risks"] == _scan_record_with_risk()["risks"]
    assert out["risk_failures"] == 2


def test_render_scan_detail_text_shows_risks_when_no_findings(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail
    _render_scan_detail(_scan_record_with_risk(), "text", show_details=False)
    out = capsys.readouterr().out
    assert "No findings — all clear." not in out
    assert "reqeusts" in out
    assert "warning" in out


def test_render_scan_detail_text_shows_risk_failures(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail
    _render_scan_detail(_scan_record_with_risk(), "text", show_details=False)
    out = capsys.readouterr().out
    assert "2" in out and "unavailable" in out


def test_render_scan_detail_html_includes_risks(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail
    _render_scan_detail(_scan_record_with_risk(), "html", show_details=False)
    out = capsys.readouterr().out
    assert "reqeusts" in out


def _scan_record_with_low_signal_risk() -> dict:
    return {
        "id": 42, "project_path": "/proj", "scan_type": "project",
        "status": "clean", "finding_count": 0, "findings": [],
        "sources": ["pypi"], "scanned_at": "2026-01-01T00:00:00+00:00",
        "risks": [{
            "package": "obscure-lib", "ecosystem": "pypi", "version": "1.0.0",
            "score": 5, "level": "info",
            "signals": [{"name": "low_popularity", "score": 5, "reason": "not found on deps.dev"}],
        }],
        "risk_failures": 0,
    }


def test_render_scan_detail_html_hides_low_signal_risks_by_default(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail
    _render_scan_detail(_scan_record_with_low_signal_risk(), "html", show_details=False)
    out = capsys.readouterr().out
    assert "obscure-lib" not in out


def test_render_scan_detail_html_shows_low_signal_risks_with_details(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail
    _render_scan_detail(_scan_record_with_low_signal_risk(), "html", show_details=True)
    out = capsys.readouterr().out
    assert "obscure-lib" in out


def test_render_scan_detail_text_hides_low_signal_risks_by_default(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail
    _render_scan_detail(_scan_record_with_low_signal_risk(), "text", show_details=False)
    out = capsys.readouterr().out
    assert "obscure-lib" not in out


def test_render_scan_detail_text_reports_suppressed_low_signal_count(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail
    _render_scan_detail(_scan_record_with_low_signal_risk(), "text", show_details=False)
    out = capsys.readouterr().out
    assert "1 low-signal row" in out
    assert "--details" in out
