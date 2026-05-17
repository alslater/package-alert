"""Unit tests for the status command."""
from __future__ import annotations

import json
import io
import time
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from rich.console import Console
from packagealert.cli.status import _format_uptime, _severity_label, gather_status, render_status, StatusData, AlertRow
from packagealert.storage.db import open_db


@pytest.fixture
async def mem_db(tmp_path):
    """File-backed SQLite DB at tmp_path/test.db with schema applied."""
    conn = await open_db(tmp_path / "test.db")
    yield conn
    await conn.close()


def test_severity_label_critical():
    assert _severity_label(75, warning_threshold=40, critical_threshold=70) == "CRITICAL"


def test_severity_label_medium():
    assert _severity_label(50, warning_threshold=40, critical_threshold=70) == "MEDIUM"


def test_severity_label_low():
    assert _severity_label(20, warning_threshold=40, critical_threshold=70) == "LOW"


def test_severity_label_boundary_warning():
    # exactly at warning_threshold → MEDIUM
    assert _severity_label(40, warning_threshold=40, critical_threshold=70) == "MEDIUM"


def test_severity_label_boundary_critical():
    # exactly at critical_threshold → CRITICAL
    assert _severity_label(70, warning_threshold=40, critical_threshold=70) == "CRITICAL"


def test_severity_label_none_score():
    assert _severity_label(None, warning_threshold=40, critical_threshold=70) == "UNKNOWN"


def test_format_uptime_none():
    assert _format_uptime(None) == "unknown"


def test_format_uptime_minutes_only():
    assert _format_uptime(150) == "2m"


def test_format_uptime_hours_and_minutes():
    assert _format_uptime(3661) == "1h 1m"


def test_format_uptime_zero():
    assert _format_uptime(0) == "0m"


@pytest.mark.asyncio
async def test_gather_status_daemon_running(mem_db, tmp_path):
    create_time = time.time() - 3600  # started 1 hour ago
    mock_proc = MagicMock()
    mock_proc.create_time.return_value = create_time

    with (
        patch("packagealert.cli.status.check_already_running", return_value=12345),
        patch("packagealert.cli.status.psutil.Process", return_value=mock_proc),
        patch("packagealert.cli.status._DB_PATH", tmp_path / "test.db"),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        (tmp_path / "daemon.pid").write_text("12345")
        data = await gather_status(None, _db=mem_db)

    assert data.daemon_running is True
    assert data.daemon_pid == 12345
    assert data.daemon_uptime_seconds == pytest.approx(3600, abs=5)
    assert data.db_exists is True


@pytest.mark.asyncio
async def test_gather_status_daemon_stopped(mem_db, tmp_path):
    with (
        patch("packagealert.cli.status.check_already_running", return_value=None),
        patch("packagealert.cli.status._DB_PATH", tmp_path / "test.db"),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None, _db=mem_db)

    assert data.daemon_running is False
    assert data.daemon_pid is None
    assert data.daemon_uptime_seconds is None


@pytest.mark.asyncio
async def test_gather_status_alerts_and_count(mem_db, tmp_path):
    now = time.time()
    # Insert 2 recent alerts and 1 old alert (> 7 days)
    await mem_db.execute(
        "INSERT INTO alerts(package_name, ecosystem, version, advisory_id, risk_score, alerted_at)"
        " VALUES(?,?,?,?,?,?)",
        ("requests", "pypi", "2.28.0", "MAL-1", 80, now - 3600),
    )
    await mem_db.execute(
        "INSERT INTO alerts(package_name, ecosystem, version, advisory_id, risk_score, alerted_at)"
        " VALUES(?,?,?,?,?,?)",
        ("numpy", "pypi", "1.24.0", "VULN-2", 45, now - 86400),
    )
    await mem_db.execute(
        "INSERT INTO alerts(package_name, ecosystem, version, advisory_id, risk_score, alerted_at)"
        " VALUES(?,?,?,?,?,?)",
        ("old-pkg", "pypi", "1.0.0", "OLD-1", 30, now - 8 * 86400),  # older than 7 days
    )
    await mem_db.commit()

    await mem_db.execute(
        "INSERT INTO scheduled_projects(path, schedule, scan_type, added_at) VALUES(?,?,?,?)",
        ("/proj/a", "daily", "project", now),
    )
    await mem_db.commit()

    with (
        patch("packagealert.cli.status.check_already_running", return_value=None),
        patch("packagealert.cli.status._DB_PATH", tmp_path / "test.db"),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None, _db=mem_db)

    assert data.alerts_last_7_days == 2
    assert len(data.recent_alerts) == 2
    assert data.recent_alerts[0].package == "requests"
    assert data.recent_alerts[0].severity == "CRITICAL"  # risk_score 80 >= critical_threshold 70
    assert data.recent_alerts[1].severity == "MEDIUM"    # risk_score 45 >= warning_threshold 40
    assert data.scheduled_projects_count == 1


@pytest.mark.asyncio
async def test_gather_status_psutil_no_such_process(mem_db, tmp_path):
    import psutil as _psutil
    mock_proc = MagicMock()
    mock_proc.create_time.side_effect = _psutil.NoSuchProcess(pid=12345)

    with (
        patch("packagealert.cli.status.check_already_running", return_value=12345),
        patch("packagealert.cli.status.psutil.Process", return_value=mock_proc),
        patch("packagealert.cli.status._DB_PATH", tmp_path / "test.db"),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None, _db=mem_db)

    assert data.daemon_running is False
    assert data.daemon_pid is None
    assert data.daemon_uptime_seconds is None


@pytest.mark.asyncio
async def test_gather_status_psutil_access_denied(mem_db, tmp_path):
    import psutil as _psutil
    mock_proc = MagicMock()
    mock_proc.create_time.side_effect = _psutil.AccessDenied(pid=12345)

    with (
        patch("packagealert.cli.status.check_already_running", return_value=12345),
        patch("packagealert.cli.status.psutil.Process", return_value=mock_proc),
        patch("packagealert.cli.status._DB_PATH", tmp_path / "test.db"),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None, _db=mem_db)

    assert data.daemon_running is True   # process exists, just inaccessible
    assert data.daemon_pid == 12345
    assert data.daemon_uptime_seconds is None


@pytest.mark.asyncio
async def test_gather_status_psutil_zombie_process(mem_db, tmp_path):
    import psutil as _psutil
    mock_proc = MagicMock()
    mock_proc.create_time.side_effect = _psutil.ZombieProcess(pid=12345)

    with (
        patch("packagealert.cli.status.check_already_running", return_value=12345),
        patch("packagealert.cli.status.psutil.Process", return_value=mock_proc),
        patch("packagealert.cli.status._DB_PATH", tmp_path / "test.db"),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None, _db=mem_db)

    assert data.daemon_running is True   # zombie still occupies the PID
    assert data.daemon_pid == 12345
    assert data.daemon_uptime_seconds is None


@pytest.mark.asyncio
async def test_gather_status_no_db(tmp_path):
    missing_db = tmp_path / "nonexistent.db"
    with (
        patch("packagealert.cli.status.check_already_running", return_value=None),
        patch("packagealert.cli.status._DB_PATH", missing_db),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None)

    assert data.alerts_last_7_days == 0
    assert data.recent_alerts == []
    assert data.scheduled_projects_count == 0
    assert data.db_exists is False


# ── render_status tests ───────────────────────────────────────────────────────


def _make_status_data(*, running=True, alerts=None) -> StatusData:
    return StatusData(
        daemon_running=running,
        daemon_pid=99999 if running else None,
        daemon_uptime_seconds=7320.0 if running else None,  # 2h 2m
        config_path="/home/user/.config/package-alert/config.toml",
        cache_monitoring=True,
        process_monitoring=True,
        scheduler_enabled=True,
        alerts_last_7_days=len(alerts) if alerts else 0,
        recent_alerts=alerts or [],
        scheduled_projects_count=3,
        pid_file_path="/home/user/.local/share/package-alert/daemon.pid",
        pid_file_exists=running,
        db_path="/home/user/.local/share/package-alert/package-alert.db",
        db_exists=True,
        log_path="/home/user/.local/share/package-alert/package-alert.log",
        log_exists=True,
    )


def test_render_status_json_structure(capsys):
    data = _make_status_data()
    render_status(data, as_json=True)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert "daemon" in parsed
    assert "config" in parsed
    assert "alerts" in parsed
    assert "scheduled_projects_count" in parsed
    assert "paths" in parsed
    assert parsed["daemon"]["running"] is True
    assert parsed["daemon"]["pid"] == 99999


def test_render_status_json_daemon_stopped(capsys):
    data = _make_status_data(running=False)
    render_status(data, as_json=True)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["daemon"]["running"] is False
    assert parsed["daemon"]["pid"] is None
    assert parsed["daemon"]["uptime_seconds"] is None


def test_render_status_rich_running():
    data = _make_status_data()
    console = Console(file=io.StringIO(), highlight=False)
    render_status(data, as_json=False, console=console)
    output = console.file.getvalue()
    assert "running" in output
    assert "99999" in output  # PID
    assert "2h 2m" in output  # uptime


def test_render_status_rich_stopped():
    data = _make_status_data(running=False)
    console = Console(file=io.StringIO(), highlight=False)
    render_status(data, as_json=False, console=console)
    output = console.file.getvalue()
    assert "stopped" in output


def test_render_status_rich_shows_alerts_section(capsys):
    alerts = [
        AlertRow(
            package="evil-pkg",
            ecosystem="pypi",
            version="1.0.0",
            advisory_id="MAL-1",
            risk_score=80,
            severity="CRITICAL",
            alerted_at=1716000000.0,
        )
    ]
    data = _make_status_data(alerts=alerts)
    console = Console(file=io.StringIO(), highlight=False)
    render_status(data, as_json=False, console=console)
    output = console.file.getvalue()
    assert "Alerts" in output
    assert "evil-pkg" in output
    assert "CRITICAL" in output


def test_render_status_rich_no_alerts_message():
    data = _make_status_data(alerts=[])
    console = Console(file=io.StringIO(), highlight=False)
    render_status(data, as_json=False, console=console)
    output = console.file.getvalue()
    assert "No alerts" in output


def test_render_status_rich_scheduled_projects():
    data = _make_status_data()
    console = Console(file=io.StringIO(), highlight=False)
    render_status(data, as_json=False, console=console)
    output = console.file.getvalue()
    assert "Scheduled Projects" in output
    assert "3 projects registered" in output


def test_render_status_rich_no_scheduled_projects():
    data = _make_status_data()
    data.scheduled_projects_count = 0
    console = Console(file=io.StringIO(), highlight=False)
    render_status(data, as_json=False, console=console)
    output = console.file.getvalue()
    assert "No projects scheduled" in output


def test_render_status_json_includes_severity(capsys):
    alerts = [
        AlertRow(
            package="evil-pkg",
            ecosystem="pypi",
            version="1.0.0",
            advisory_id="MAL-1",
            risk_score=80,
            severity="CRITICAL",
            alerted_at=1716000000.0,
        )
    ]
    data = _make_status_data(alerts=alerts)
    render_status(data, as_json=True)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["alerts"]["recent"][0]["severity"] == "CRITICAL"
    assert parsed["alerts"]["recent"][0]["risk_score"] == 80
