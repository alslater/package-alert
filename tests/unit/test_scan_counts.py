"""Every scan's not_public, yanked and yank_failures reach plugins, scan history and pa-central (#121).

Without them a scan of private packages, or one whose yank check failed, looks fully checked
wherever the counts are not shown."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from packagealert.config import AppConfig, load_config
from packagealert.models.scans import ScanResult

_YANKED = [{"ecosystem": "npm", "package": "pub", "version": "1.0.0", "reason": "Bad release"}]


def _lock(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"pub": "^1.0.0", "evil": "^1.0.0"}},
        "node_modules/pub": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz"},
        "node_modules/evil": {"version": "1.0.0", "resolved": "https://npm.corp.example/evil/-/evil-1.0.0.tgz"},
    }}))


async def test_scan_project_hands_plugins_every_count(tmp_path, capsys):
    from packagealert.cli.app import _run_scan_project

    _lock(tmp_path)
    fired: list[ScanResult] = []

    async def capture(scan):
        fired.append(scan)

    with patch("packagealert.cli.app._query_osv_findings", AsyncMock(return_value=([], 0))), \
            patch("packagealert.cli.app._risk_pass", AsyncMock(return_value=([], 0))), \
            patch("packagealert.yanks.check_yanks", AsyncMock(return_value=([], 2))), \
            patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})), \
            patch("packagealert.plugins.registry.plugin_registry.fire_on_scan_complete", capture):
        await _run_scan_project(load_config(None), tmp_path, scan_unpinned=False, installed=False,
                                show_details=False, fmt="json", no_risk=False)
    [scan] = fired
    assert (scan.not_public, scan.yank_failures, scan.yank_checked) == (1, 2, True)
    shown = json.loads(capsys.readouterr().out)
    assert (shown["yank_checked"], shown["yanked"], shown["yank_failures"]) == (True, [], 2)


@pytest.mark.parametrize(("installed", "no_yank"), [(False, True), (True, False)])
async def test_a_scan_that_skips_the_yank_check_says_so(tmp_path, capsys, installed, no_yank):
    """--no-yank and --scan-installed run no yank check: the scan must not claim one."""
    from packagealert.cli.app import _run_scan_project

    _lock(tmp_path)
    if installed:                                            # an installed tree to enumerate
        (tmp_path / "node_modules" / "pub").mkdir(parents=True)
        (tmp_path / "node_modules" / "pub" / "package.json").write_text(json.dumps({"name": "pub", "version": "1.0.0"}))
    fired: list[ScanResult] = []

    async def capture(scan):
        fired.append(scan)

    check = AsyncMock(return_value=([], 0))
    with patch("packagealert.cli.app._query_osv_findings", AsyncMock(return_value=([], 0))), \
            patch("packagealert.cli.app._risk_pass", AsyncMock(return_value=([], 0))), \
            patch("packagealert.yanks.check_yanks", check), \
            patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})), \
            patch("packagealert.plugins.registry.plugin_registry.fire_on_scan_complete", capture):
        await _run_scan_project(load_config(None), tmp_path, scan_unpinned=False, installed=installed,
                                show_details=False, fmt="json", no_risk=False, no_yank=no_yank)
    [scan] = fired
    assert scan.yank_checked is False and check.await_count == 0
    shown = json.loads(capsys.readouterr().out)              # what a repo scan forwards to pa-central
    assert (shown["yank_checked"], shown["yanked"], shown["yank_failures"]) == (False, None, None)


async def test_a_scheduled_scan_counts_not_public_packages(tmp_path):
    from packagealert.scheduler.runner import ScheduledScanner

    _lock(tmp_path)
    runner = ScheduledScanner.__new__(ScheduledScanner)
    runner._run_osv_queries = AsyncMock(return_value=([], 0))
    _findings, _sources, _osv, not_public = await runner._scan_project(tmp_path)
    assert not_public == 1


@pytest.mark.asyncio
async def test_a_scheduled_scans_not_public_reaches_plugins_and_history(tmp_path):
    from packagealert.scheduler.db import (
        add_project,
        get_scan_result,
        list_all_scan_results,
        list_scan_results,
    )
    from packagealert.scheduler.runner import ScheduledScanner
    from packagealert.storage.db import open_db

    proj = tmp_path / "proj"
    proj.mkdir()
    db = await open_db(tmp_path / "t.db")
    fired: list[ScanResult] = []

    async def capture(scan):
        fired.append(scan)

    try:
        await add_project(db, path=str(proj), schedule="daily", scan_type="project")
        scanner = ScheduledScanner(AppConfig(), db)
        with patch.object(scanner, "_scan_project", new=AsyncMock(return_value=([], ["uv.lock"], 0, 5))), \
                patch("packagealert.plugins.registry.plugin_registry.fire_on_scan_complete", capture):
            await scanner.run_due_scans()
        assert [s.not_public for s in fired] == [5]
        [record] = await list_scan_results(db, str(proj), limit=5)
        assert record.not_public == 5
        assert [r.not_public for r in await list_all_scan_results(db)] == [5]
        detail = await get_scan_result(db, record.id)
        assert detail is not None and detail.not_public == 5
    finally:
        await db.close()


async def test_a_scan_history_row_from_before_the_column_reads_zero(tmp_path):
    import sqlite3

    from packagealert.scheduler.db import get_scan_result
    from packagealert.storage.db import open_db

    con = sqlite3.connect(tmp_path / "old.db")
    con.executescript("""
        CREATE TABLE scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_path TEXT NOT NULL, scanned_at REAL NOT NULL,
            schedule TEXT NOT NULL CHECK(schedule IN ('daily','weekly')),
            scan_type TEXT NOT NULL DEFAULT 'project' CHECK(scan_type IN ('project','installed')),
            findings_json TEXT NOT NULL, sources_json TEXT NOT NULL,
            max_severity TEXT, finding_count INTEGER NOT NULL DEFAULT 0,
            osv_failures INTEGER NOT NULL DEFAULT 0);
        INSERT INTO scan_results(project_path,scanned_at,schedule,scan_type,findings_json,sources_json,
                                 max_severity,finding_count)
            VALUES('/old',1.0,'daily','project','[]','["uv.lock"]',NULL,0);
    """)
    con.commit()
    con.close()
    db = await open_db(tmp_path / "old.db")
    try:
        record = await get_scan_result(db, 1)
        assert record is not None and record.not_public == 0
    finally:
        await db.close()


def test_the_payload_carries_every_count():
    from packagealert.plugins.central.client import build_scan_payload

    scan = ScanResult(project_path="/p", scan_type="project", finding_count=0, findings=[], sources=["uv.lock"],
                      scanned_at=datetime(2026, 1, 1, tzinfo=UTC), yanked=_YANKED, yank_failures=2, not_public=3,
                      yank_checked=True)
    payload = build_scan_payload("host", scan)
    assert (payload["not_public"], payload["yanked"], payload["yank_failures"]) == (3, _YANKED, 2)
    assert payload["yank_checked"] is True


def test_a_scan_without_a_yank_check_sends_no_yank_results():
    """A scheduled scan (or one built by a plugin) never ran the yank check: its payload says so,
    rather than "nothing yanked, nothing failed"."""
    from packagealert.plugins.central.client import build_scan_payload

    scan = ScanResult(project_path="/p", scan_type="project", finding_count=0, findings=[], sources=["uv.lock"],
                      scanned_at=datetime(2026, 1, 1, tzinfo=UTC))
    payload = build_scan_payload("host", scan)
    assert payload["yank_checked"] is False
    assert payload["yanked"] is None and payload["yank_failures"] is None


def _record(**extra) -> dict:
    return {"id": 7, "project_path": "/p", "scan_type": "project", "findings": [], "sources": ["uv.lock"],
            "scanned_at": "2026-01-01T00:00:00+00:00", **extra}


def test_a_retrieved_scan_shows_every_count(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail

    record = _record(not_public=3, yanked=_YANKED, yank_failures=2, yank_checked=True)
    _render_scan_detail(record, "json", show_details=False)
    shown = json.loads(capsys.readouterr().out)
    assert (shown["not_public"], shown["yanked"], shown["yank_failures"]) == (3, _YANKED, 2)
    _render_scan_detail(record, "text", show_details=False)
    text = capsys.readouterr().out
    assert "3 locked package(s)" in text and "pub 1.0.0" in text and "unavailable for 2" in text
    assert "all clear" not in text                          # contradicting the yank warning above it
    _render_scan_detail(record, "html", show_details=False)
    html = capsys.readouterr().out
    assert "3 locked package(s)" in html and "2 yank-unchecked" in html


def test_a_retrieved_scan_from_a_server_without_the_counts_still_renders(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail

    _render_scan_detail(_record(), "json", show_details=False)
    shown = json.loads(capsys.readouterr().out)
    assert (shown["not_public"], shown["yank_checked"], shown["yanked"], shown["yank_failures"]) == (0, False, None, None)
    _render_scan_detail(_record(), "text", show_details=False)
    assert "No findings" in capsys.readouterr().out


async def test_the_scan_history_views_show_not_public(tmp_path, capsys, monkeypatch):
    from packagealert.cli.app import _findings_cell, _scans_show
    from packagealert.scheduler.db import save_scan_result
    from packagealert.storage import db as storage_db
    from packagealert.storage.db import open_db

    monkeypatch.setattr(storage_db, "DEFAULT_DB_PATH", tmp_path / "t.db")
    db = await open_db(tmp_path / "t.db")
    try:
        record_id = await save_scan_result(db, project_path="/p", schedule="daily", findings=[], sources=["uv.lock"],
                                           not_public=4)
    finally:
        await db.close()
    cfg = load_config(None)
    await _scans_show(cfg, record_id, "json", show_details=False)
    assert json.loads(capsys.readouterr().out)["not_public"] == 4
    await _scans_show(cfg, record_id, "text", show_details=False)
    assert "4 locked package(s)" in capsys.readouterr().out
    await _scans_show(cfg, record_id, "html", show_details=False)
    assert "4 locked package(s)" in capsys.readouterr().out

    from types import SimpleNamespace

    row = SimpleNamespace(findings=[], finding_count=0, osv_failures=0, not_public=4)
    assert "+4 not public" in _findings_cell(row)


def test_scan_result_keeps_its_positional_order():
    """A plugin that builds a ScanResult positionally, up to `remediations`, keeps meaning the
    same: the fields added since come after it."""
    remediations = [{"package": "x"}]
    scan = ScanResult("/p", "project", 0, [], ["uv.lock"], datetime(2026, 1, 1, tzinfo=UTC), [], 0, 0, [], 0,
                      remediations)
    assert scan.remediations == remediations
    assert scan.yank_checked is False and scan.not_public == 0


def test_a_retrieved_scan_with_yanked_versions_is_not_all_clear(capsys):
    from packagealert.plugins.central.plugin import _render_scan_detail

    _render_scan_detail(_record(yanked=_YANKED, yank_failures=0, yank_checked=True), "text", show_details=False)
    text = capsys.readouterr().out
    assert "pub 1.0.0" in text and "all clear" not in text
