"""Unit tests for scheduler database tables."""
from __future__ import annotations

import time
import pytest
from packagealert.storage.db import open_db
from packagealert.scheduler.db import (
    add_project, remove_project, list_projects, get_project,
    save_scan_result, list_scan_results, list_all_scan_results, get_scan_result,
    prune_scan_results, update_last_scanned,
)


@pytest.fixture
async def db(tmp_path):
    conn = await open_db(tmp_path / "test.db")
    yield conn
    await conn.close()


@pytest.mark.asyncio
async def test_scheduled_projects_table_exists(db):
    async with db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scheduled_projects'"
    ) as cur:
        row = await cur.fetchone()
    assert row is not None


@pytest.mark.asyncio
async def test_scan_results_table_exists(db):
    async with db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_results'"
    ) as cur:
        row = await cur.fetchone()
    assert row is not None


@pytest.mark.asyncio
async def test_scheduled_projects_columns(db):
    async with db.execute("PRAGMA table_info(scheduled_projects)") as cur:
        cols = {r["name"] for r in await cur.fetchall()}
    assert {"id", "path", "schedule", "scan_type", "added_at", "last_scanned_at"} <= cols
    # Verify (path, scan_type) uniqueness, not just path
    async with db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='scheduled_projects'") as cur:
        row = await cur.fetchone()
    assert "UNIQUE(path, scan_type)" in row["sql"]


@pytest.mark.asyncio
async def test_scan_results_columns(db):
    async with db.execute("PRAGMA table_info(scan_results)") as cur:
        cols = {r["name"] for r in await cur.fetchall()}
    assert {"id", "project_path", "scanned_at", "schedule", "scan_type", "findings_json",
            "sources_json", "max_severity", "finding_count"} <= cols


@pytest.mark.asyncio
async def test_scheduled_projects_unique_constraint(db):
    """UNIQUE(path, scan_type) prevents duplicate (path, scan_type) pairs."""
    await db.execute(
        "INSERT INTO scheduled_projects(path, schedule, scan_type, added_at) VALUES(?,?,?,?)",
        ("/myapp", "daily", "project", 1.0),
    )
    await db.commit()
    import aiosqlite
    with pytest.raises(aiosqlite.IntegrityError):
        await db.execute(
            "INSERT INTO scheduled_projects(path, schedule, scan_type, added_at) VALUES(?,?,?,?)",
            ("/myapp", "weekly", "project", 2.0),
        )
        await db.commit()



@pytest.mark.asyncio
async def test_add_and_get_project(db):
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="project")
    p = await get_project(db, "/home/user/myapp", "project")
    assert p is not None
    assert p.path == "/home/user/myapp"
    assert p.schedule == "daily"
    assert p.scan_type == "project"
    assert p.last_scanned_at is None


@pytest.mark.asyncio
async def test_add_both_scan_types_for_same_project(db):
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="project")
    await add_project(db, path="/home/user/myapp", schedule="weekly", scan_type="installed")
    p1 = await get_project(db, "/home/user/myapp", "project")
    p2 = await get_project(db, "/home/user/myapp", "installed")
    assert p1.schedule == "daily"
    assert p2.schedule == "weekly"
    # Both coexist independently
    projects = await list_projects(db)
    assert len(projects) == 2


@pytest.mark.asyncio
async def test_add_project_duplicate_updates_schedule(db):
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="project")
    await add_project(db, path="/home/user/myapp", schedule="weekly", scan_type="project")
    p = await get_project(db, "/home/user/myapp", "project")
    assert p.schedule == "weekly"
    assert p.scan_type == "project"


@pytest.mark.asyncio
async def test_remove_project_specific_type(db):
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="project")
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="installed")
    removed = await remove_project(db, "/home/user/myapp", scan_type="project")
    assert removed is True
    assert await get_project(db, "/home/user/myapp", "project") is None
    assert await get_project(db, "/home/user/myapp", "installed") is not None


@pytest.mark.asyncio
async def test_remove_project_all_types(db):
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="project")
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="installed")
    removed = await remove_project(db, "/home/user/myapp", scan_type=None)
    assert removed is True
    assert await list_projects(db) == []


@pytest.mark.asyncio
async def test_remove_nonexistent_project(db):
    removed = await remove_project(db, "/does/not/exist", scan_type=None)
    assert removed is False


@pytest.mark.asyncio
async def test_list_projects(db):
    await add_project(db, path="/a", schedule="daily", scan_type="project")
    await add_project(db, path="/a", schedule="daily", scan_type="installed")
    await add_project(db, path="/b", schedule="weekly", scan_type="project")
    projects = await list_projects(db)
    assert len(projects) == 3
    paths = [p.path for p in projects]
    assert paths.count("/a") == 2
    assert "/b" in paths


@pytest.mark.asyncio
async def test_update_last_scanned(db):
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="project")
    await add_project(db, path="/home/user/myapp", schedule="daily", scan_type="installed")
    t = time.time()
    await update_last_scanned(db, "/home/user/myapp", "project", t)
    p_project = await get_project(db, "/home/user/myapp", "project")
    p_installed = await get_project(db, "/home/user/myapp", "installed")
    assert p_project.last_scanned_at == pytest.approx(t)
    assert p_installed.last_scanned_at is None  # unaffected


@pytest.mark.asyncio
async def test_save_and_get_scan_result(db):
    findings = [{"package": "evil", "severity": "HIGH", "advisory_id": "MAL-1",
                 "is_malicious": True, "summary": "bad", "details": None,
                 "fixed_versions": [], "url": "https://osv.dev/MAL-1",
                 "ecosystem": "pypi", "version": "1.0"}]
    rec_id = await save_scan_result(
        db,
        project_path="/home/user/myapp",
        schedule="daily",
        scan_type="installed",
        findings=findings,
        sources=["pip list"],
    )
    rec = await get_scan_result(db, rec_id)
    assert rec is not None
    assert rec.finding_count == 1
    assert rec.max_severity == "HIGH"
    assert rec.scan_type == "installed"
    assert rec.sources == ["pip list"]
    assert rec.findings[0]["package"] == "evil"


@pytest.mark.asyncio
async def test_list_scan_results_newest_first(db):
    base = 1_000_000.0
    for i in range(3):
        # Use distinct timestamps to guarantee ordering is deterministic
        await db.execute(
            """INSERT INTO scan_results(project_path, scanned_at, schedule, scan_type,
                   findings_json, sources_json, finding_count)
               VALUES(?,?,?,?,?,?,?)""",
            ("/p", base + i, "daily", "project", "[]", "[]", 0),
        )
        await db.commit()
    results = await list_scan_results(db, "/p", scan_type="project")
    assert len(results) == 3
    times = [r.scanned_at for r in results]
    assert times == sorted(times, reverse=True)


@pytest.mark.asyncio
async def test_prune_scan_results_keeps_n_most_recent_per_type(db):
    # Add 4 project scans and 4 installed scans for same project
    for _ in range(4):
        await save_scan_result(db, project_path="/p", schedule="daily",
                               scan_type="project", findings=[], sources=[])
        await save_scan_result(db, project_path="/p", schedule="daily",
                               scan_type="installed", findings=[], sources=[])
    await prune_scan_results(db, "/p", "project", keep=2)
    project_results = await list_scan_results(db, "/p", scan_type="project")
    installed_results = await list_scan_results(db, "/p", scan_type="installed")
    assert len(project_results) == 2   # pruned to 2
    assert len(installed_results) == 4  # unaffected


@pytest.mark.asyncio
async def test_max_severity_none_when_no_findings(db):
    rec_id = await save_scan_result(db, project_path="/p", schedule="daily",
                                    scan_type="project", findings=[], sources=["uv.lock"])
    rec = await get_scan_result(db, rec_id)
    assert rec.max_severity is None
    assert rec.finding_count == 0


@pytest.mark.asyncio
async def test_list_all_scan_results_returns_all_projects(db):
    await save_scan_result(db, project_path="/proj/a", schedule="daily",
                           scan_type="project", findings=[], sources=[])
    await save_scan_result(db, project_path="/proj/b", schedule="weekly",
                           scan_type="installed", findings=[], sources=[])
    await save_scan_result(db, project_path="/proj/a", schedule="daily",
                           scan_type="installed", findings=[], sources=[])

    records = await list_all_scan_results(db)
    assert len(records) == 3
    paths = {r.project_path for r in records}
    assert paths == {"/proj/a", "/proj/b"}


@pytest.mark.asyncio
async def test_list_all_scan_results_newest_first(db):
    for i in range(3):
        await db.execute(
            """INSERT INTO scan_results(project_path, scanned_at, schedule, scan_type,
                   findings_json, sources_json, finding_count)
               VALUES(?,?,?,?,?,?,?)""",
            (f"/proj/{i}", 1_000_000.0 + i, "daily", "project", "[]", "[]", 0),
        )
        await db.commit()
    records = await list_all_scan_results(db)
    times = [r.scanned_at for r in records]
    assert times == sorted(times, reverse=True)


@pytest.mark.asyncio
async def test_list_all_scan_results_limit(db):
    for i in range(5):
        await save_scan_result(db, project_path=f"/proj/{i}", schedule="daily",
                               scan_type="project", findings=[], sources=[])
    records = await list_all_scan_results(db, limit=3)
    assert len(records) == 3
