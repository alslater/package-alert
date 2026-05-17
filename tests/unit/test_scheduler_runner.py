"""Unit tests for ScheduledScanner."""
from __future__ import annotations

import datetime as dt
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from packagealert.scheduler.runner import ScheduledScanner, _is_due
from packagealert.scheduler.db import ScheduledProject


def _make_project(schedule: str, last_scanned_at: float | None, scan_type: str = "project") -> ScheduledProject:
    return ScheduledProject(
        path="/home/user/myapp",
        schedule=schedule,
        scan_type=scan_type,
        added_at=time.time(),
        last_scanned_at=last_scanned_at,
    )


class TestIsDue:
    # All tests use fixed "now" and pass it via _now to avoid time-of-day flakiness.
    # daily_hour=2, weekly_day=6 (Sunday), weekly_hour=2 throughout.

    def test_never_scanned_is_always_due(self):
        now = dt.datetime(2026, 1, 6, 15, 0)  # Tuesday 15:00
        p = _make_project("daily", None)
        assert _is_due(p, daily_hour=2, weekly_day=6, weekly_hour=2, _now=now) is True

    def test_daily_due_after_scheduled_hour_passes(self):
        # Tuesday 15:00; last ran Monday 02:15 — today's 02:00 window is in the past, not yet hit
        now = dt.datetime(2026, 1, 6, 15, 0)
        last = dt.datetime(2026, 1, 5, 2, 15)
        p = _make_project("daily", last.timestamp())
        assert _is_due(p, daily_hour=2, weekly_day=6, weekly_hour=2, _now=now) is True

    def test_daily_not_due_before_scheduled_hour(self):
        # Tuesday 01:00; daily_hour=2 hasn't arrived yet
        now = dt.datetime(2026, 1, 6, 1, 0)
        last = dt.datetime(2026, 1, 5, 2, 15)
        p = _make_project("daily", last.timestamp())
        assert _is_due(p, daily_hour=2, weekly_day=6, weekly_hour=2, _now=now) is False

    def test_daily_not_due_already_ran_today(self):
        # Tuesday 15:00; already ran at Tuesday 02:15 — after today's window
        now = dt.datetime(2026, 1, 6, 15, 0)
        last = dt.datetime(2026, 1, 6, 2, 15)
        p = _make_project("daily", last.timestamp())
        assert _is_due(p, daily_hour=2, weekly_day=6, weekly_hour=2, _now=now) is False

    def test_weekly_due_after_configured_day_and_hour(self):
        # Sunday 2026-01-11 15:00; last ran previous Sunday 02:15 — this week's window passed
        now = dt.datetime(2026, 1, 11, 15, 0)   # Sunday, weekday=6
        last = dt.datetime(2026, 1, 4, 2, 15)    # prev Sunday 02:15
        p = _make_project("weekly", last.timestamp())
        assert _is_due(p, daily_hour=2, weekly_day=6, weekly_hour=2, _now=now) is True

    def test_weekly_not_due_already_ran_this_week(self):
        # Monday 2026-01-12 15:00; ran Sunday 02:15 — already hit this week's slot
        now = dt.datetime(2026, 1, 12, 15, 0)   # Monday, weekday=0
        last = dt.datetime(2026, 1, 11, 2, 15)   # Sunday 02:15
        p = _make_project("weekly", last.timestamp())
        assert _is_due(p, daily_hour=2, weekly_day=6, weekly_hour=2, _now=now) is False

    def test_weekly_not_due_before_scheduled_hour_on_target_day(self):
        # Sunday 2026-01-11 01:00; weekly_hour=2 hasn't arrived yet today
        now = dt.datetime(2026, 1, 11, 1, 0)    # Sunday, weekday=6, before 02:00
        last = dt.datetime(2026, 1, 4, 2, 15)    # prev Sunday 02:15
        p = _make_project("weekly", last.timestamp())
        assert _is_due(p, daily_hour=2, weekly_day=6, weekly_hour=2, _now=now) is False


class TestScheduledScanner:
    @pytest.mark.asyncio
    async def test_run_due_scans_skips_nonexistent_project(self, tmp_path):
        from packagealert.config import AppConfig
        from packagealert.storage.db import open_db
        from packagealert.scheduler.db import add_project

        db = await open_db(tmp_path / "test.db")
        await add_project(db, path="/does/not/exist", schedule="daily", scan_type="project")

        cfg = AppConfig()
        scanner = ScheduledScanner(cfg, db)
        # Should not raise, just log a warning and skip
        await scanner.run_due_scans()
        await db.close()

    @pytest.mark.asyncio
    async def test_run_due_scans_stores_result(self, tmp_path):
        from packagealert.config import AppConfig
        from packagealert.storage.db import open_db
        from packagealert.scheduler.db import add_project, list_scan_results

        db = await open_db(tmp_path / "test.db")
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "requirements.txt").write_text("requests==2.31.0\n")

        await add_project(db, path=str(project_dir), schedule="daily", scan_type="project")

        cfg = AppConfig()
        scanner = ScheduledScanner(cfg, db)

        mock_findings = [
            {"package": "requests", "ecosystem": "pypi", "version": "2.31.0",
             "advisory_id": "CVE-2025-1", "is_malicious": False,
             "severity": "HIGH", "summary": "test", "details": None,
             "fixed_versions": ["2.32.0"], "url": "https://osv.dev/CVE-2025-1"}
        ]

        with patch.object(scanner, "_scan_project", new=AsyncMock(return_value=(mock_findings, ["requirements.txt"]))):
            await scanner.run_due_scans()

        results = await list_scan_results(db, str(project_dir), scan_type="project")
        assert len(results) == 1
        assert results[0].finding_count == 1
        assert results[0].max_severity == "HIGH"
        await db.close()

    @pytest.mark.asyncio
    async def test_both_scan_types_run_independently(self, tmp_path):
        """A project registered for both types runs both scanners independently."""
        from packagealert.config import AppConfig
        from packagealert.storage.db import open_db
        from packagealert.scheduler.db import add_project, list_scan_results

        db = await open_db(tmp_path / "test.db")
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "requirements.txt").write_text("requests==2.31.0\n")

        await add_project(db, path=str(project_dir), schedule="daily", scan_type="project")
        await add_project(db, path=str(project_dir), schedule="daily", scan_type="installed")

        cfg = AppConfig()
        scanner = ScheduledScanner(cfg, db)

        with patch.object(scanner, "_scan_project", new=AsyncMock(return_value=([], ["requirements.txt"]))) as mock_p, \
             patch.object(scanner, "_scan_installed", new=AsyncMock(return_value=([], ["pip list"]))) as mock_i:
            await scanner.run_due_scans()
            mock_p.assert_called_once()
            mock_i.assert_called_once()

        project_results = await list_scan_results(db, str(project_dir), scan_type="project")
        installed_results = await list_scan_results(db, str(project_dir), scan_type="installed")
        assert len(project_results) == 1
        assert len(installed_results) == 1
        await db.close()

    @pytest.mark.asyncio
    async def test_run_due_scans_uses_scan_installed_for_installed_type(self, tmp_path):
        from packagealert.config import AppConfig
        from packagealert.storage.db import open_db
        from packagealert.scheduler.db import add_project

        db = await open_db(tmp_path / "test.db")
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()

        await add_project(db, path=str(project_dir), schedule="daily", scan_type="installed")

        cfg = AppConfig()
        scanner = ScheduledScanner(cfg, db)

        with patch.object(scanner, "_scan_installed", new=AsyncMock(return_value=([], ["pip list"]))) as mock_installed, \
             patch.object(scanner, "_scan_project", new=AsyncMock(return_value=([], []))) as mock_project:
            await scanner.run_due_scans()
            mock_installed.assert_called_once()
            mock_project.assert_not_called()

        await db.close()

    @pytest.mark.asyncio
    async def test_run_due_scans_prunes_old_results(self, tmp_path):
        from packagealert.config import AppConfig
        from packagealert.storage.db import open_db
        from packagealert.scheduler.db import add_project, save_scan_result, list_scan_results

        db = await open_db(tmp_path / "test.db")
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / "requirements.txt").write_text("requests==2.31.0\n")

        await add_project(db, path=str(project_dir), schedule="daily", scan_type="project")
        # Pre-populate 5 existing results (at max_scan_history default)
        for _ in range(5):
            await save_scan_result(db, project_path=str(project_dir),
                                   schedule="daily", scan_type="project", findings=[], sources=[])

        cfg = AppConfig()
        scanner = ScheduledScanner(cfg, db)

        with patch.object(scanner, "_scan_project", new=AsyncMock(return_value=([], ["requirements.txt"]))):
            await scanner.run_due_scans()

        results = await list_scan_results(db, str(project_dir), scan_type="project")
        # Should have exactly max_scan_history (5) results, not 6
        assert len(results) == 5
        await db.close()


@pytest.mark.asyncio
async def test_scheduler_loop_calls_run_due_scans():
    """_scheduler_loop calls run_due_scans repeatedly until cancelled."""
    import asyncio
    from packagealert.daemon import _scheduler_loop

    call_count = 0

    async def fake_run_due():
        nonlocal call_count
        call_count += 1

    scanner = MagicMock()
    scanner.run_due_scans = AsyncMock(side_effect=fake_run_due)

    task = asyncio.create_task(_scheduler_loop(scanner, interval=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert call_count >= 2


@pytest.mark.asyncio
async def test_daemon_does_not_start_scheduler_when_disabled():
    """scheduler.enabled = False must prevent ScheduledScanner from being created."""
    import asyncio
    from packagealert.config import AppConfig
    from packagealert.daemon import Daemon
    from unittest.mock import AsyncMock, patch

    cfg = AppConfig.model_validate({
        "scheduler": {"enabled": False},
        "watch": {"enable_process_monitoring": False, "enable_cache_monitoring": False},
    })

    mock_db = AsyncMock()
    mock_osv = AsyncMock()
    mock_pop = AsyncMock()

    with patch("packagealert.daemon.open_db", return_value=mock_db), \
         patch("packagealert.daemon.OsvClient", return_value=mock_osv), \
         patch("packagealert.daemon.OsvCache"), \
         patch("packagealert.daemon.PopularityClient", return_value=mock_pop), \
         patch("packagealert.daemon.PopularityCache"), \
         patch("packagealert.daemon.RiskEngine"), \
         patch("packagealert.daemon.warn_missing_paths"), \
         patch("packagealert.daemon.ScheduledScanner") as MockScanner:

        daemon = Daemon(cfg)
        run_task = asyncio.create_task(daemon._run())
        await asyncio.sleep(0)
        run_task.cancel()
        try:
            await run_task
        except (asyncio.CancelledError, Exception):
            pass

    MockScanner.assert_not_called()
