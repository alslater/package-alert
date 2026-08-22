"""Unit tests for the status command."""
from __future__ import annotations

import io
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from packagealert.cli.status import (
    AlertRow,
    StatusData,
    _format_uptime,
    _severity_label,
    gather_status,
    render_status,
)
from packagealert.config import AppConfig
from packagealert.daemon_pid import is_started_by_systemd as _started_by_systemd
from packagealert.storage.db import open_db

_FIXED_CONFIG = AppConfig()  # default thresholds: warning=40, critical=70


@pytest.fixture(autouse=True)
def fixed_config():
    """Pin load_config to a deterministic AppConfig so tests don't read ~/.config."""
    with patch("packagealert.cli.status.load_config", return_value=_FIXED_CONFIG):
        yield


@pytest.fixture
async def mem_db(tmp_path):
    """File-backed SQLite DB at tmp_path/test.db with schema applied.

    Always includes pa-central's schema (central_outbox) regardless of the
    machine's actual default config file — some tests in this module seed
    central_outbox directly, and open_db()'s default enabled_plugins
    resolution reads ~/.config/package-alert/config.toml, so without this
    the test's pass/fail would depend on whatever plugins happen to be
    enabled in that file on the machine running the suite.
    """
    conn = await open_db(tmp_path / "test.db", enabled_plugins={"pa-central"})
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


def test_started_by_systemd_true():
    environ = b"PATH=/usr/bin\x00INVOCATION_ID=abc123\x00HOME=/root"
    with patch("pathlib.Path.read_bytes", return_value=environ):
        assert _started_by_systemd(1234) is True


def test_started_by_systemd_false():
    environ = b"PATH=/usr/bin\x00HOME=/root\x00TERM=xterm"
    with patch("pathlib.Path.read_bytes", return_value=environ):
        assert _started_by_systemd(1234) is False


def test_started_by_systemd_oserror():
    with patch("pathlib.Path.read_bytes", side_effect=OSError):
        assert _started_by_systemd(1234) is False


@pytest.mark.asyncio
async def test_gather_status_daemon_running(mem_db, tmp_path):
    create_time = time.time() - 3600  # started 1 hour ago
    mock_proc = MagicMock()
    mock_proc.create_time.return_value = create_time

    with (
        patch("packagealert.cli.status.find_daemon_pid", return_value=12345),
        patch("packagealert.cli.status.psutil.Process", return_value=mock_proc),
        patch("packagealert.cli.status.is_started_by_systemd", return_value=False),
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
        patch("packagealert.cli.status.find_daemon_pid", return_value=None),
        patch("packagealert.cli.status.psutil.process_iter", return_value=[]),
        patch("packagealert.cli.status._DB_PATH", tmp_path / "test.db"),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None, _db=mem_db)

    assert data.daemon_running is False
    assert data.daemon_pid is None
    assert data.daemon_uptime_seconds is None


@pytest.mark.asyncio
async def test_gather_status_daemon_running_via_process_scan(mem_db, tmp_path):
    """Daemon detected via find_daemon_pid (which includes process scan fallback)."""
    create_time = time.time() - 120

    with (
        patch("packagealert.cli.status.find_daemon_pid", return_value=9999),
        patch("packagealert.cli.status.psutil.Process") as mock_process_cls,
        patch("packagealert.cli.status.is_started_by_systemd", return_value=False),
        patch("packagealert.cli.status._DB_PATH", tmp_path / "test.db"),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        mock_process_cls.return_value.create_time.return_value = create_time
        data = await gather_status(None, _db=mem_db)

    assert data.daemon_running is True
    assert data.daemon_pid == 9999
    assert data.daemon_uptime_seconds == pytest.approx(120, abs=5)


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
        patch("packagealert.cli.status.find_daemon_pid", return_value=None),
        patch("packagealert.cli.status.psutil.process_iter", return_value=[]),
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
        patch("packagealert.cli.status.find_daemon_pid", return_value=12345),
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
        patch("packagealert.cli.status.find_daemon_pid", return_value=12345),
        patch("packagealert.cli.status.psutil.Process", return_value=mock_proc),
        patch("packagealert.cli.status.is_started_by_systemd", return_value=False),
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
        patch("packagealert.cli.status.find_daemon_pid", return_value=12345),
        patch("packagealert.cli.status.psutil.Process", return_value=mock_proc),
        patch("packagealert.cli.status.is_started_by_systemd", return_value=False),
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
        patch("packagealert.cli.status.find_daemon_pid", return_value=None),
        patch("packagealert.cli.status.psutil.process_iter", return_value=[]),
        patch("packagealert.cli.status._DB_PATH", missing_db),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None)

    assert data.alerts_last_7_days == 0
    assert data.recent_alerts == []
    assert data.scheduled_projects_count == 0
    assert data.db_exists is False


@pytest.mark.asyncio
async def test_gather_status_central_reports_outbox_counts_and_last_seen(mem_db, tmp_path):
    import json as jsonlib

    from packagealert.plugins.central import outbox as central_outbox
    from packagealert.plugins.central.state import _default_state, write_state

    await central_outbox.enqueue(mem_db, kind="scan", payload_json=jsonlib.dumps({"a": 1}))
    await central_outbox.enqueue(mem_db, kind="scan", payload_json=jsonlib.dumps({"a": 2}))
    await central_outbox.enqueue(mem_db, kind="alert", payload_json=jsonlib.dumps({"b": 1}))

    state_path = tmp_path / "central-state.json"
    state = _default_state()
    state["last_heartbeat_at"] = "2026-07-15T10:00:00+00:00"
    state["last_heartbeat_ok"] = False
    state["last_heartbeat_error"] = "connection refused"
    state["last_seen_at"] = "2026-07-15T09:00:00+00:00"
    write_state(state, state_path)

    cfg = AppConfig()
    cfg.plugins.enabled = ["pa-central"]
    cfg.plugins.pa_central.server_url = "https://fleet.example.com"

    with (
        patch("packagealert.cli.status.load_config", return_value=cfg),
        patch("packagealert.cli.status.find_daemon_pid", return_value=None),
        patch("packagealert.cli.status.psutil.process_iter", return_value=[]),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
        patch("packagealert.plugins.central.state._STATE_PATH", state_path),
    ):
        data = await gather_status(None, _db=mem_db)

    assert data.central is not None
    assert data.central.enabled is True
    assert data.central.server_url == "https://fleet.example.com"
    assert data.central.outbox_scan_count == 2
    assert data.central.outbox_alert_count == 1
    # last_seen_at is the earlier success, distinct from the more recent
    # failed last_heartbeat_at/ok/error — both must be surfaced separately.
    assert data.central.last_seen_at == "2026-07-15T09:00:00+00:00"
    assert data.central.last_heartbeat_ok is False
    assert data.central.last_heartbeat_error == "connection refused"


@pytest.mark.asyncio
async def test_gather_status_central_disabled_has_no_central_section(mem_db, tmp_path):
    cfg = AppConfig()
    cfg.plugins.enabled = []

    with (
        patch("packagealert.cli.status.load_config", return_value=cfg),
        patch("packagealert.cli.status.find_daemon_pid", return_value=None),
        patch("packagealert.cli.status.psutil.process_iter", return_value=[]),
        patch("packagealert.cli.status._PID_FILE", tmp_path / "daemon.pid"),
    ):
        data = await gather_status(None, _db=mem_db)

    assert data.central is None


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
        log_path="/home/user/.local/share/package-alert/daemon.log",
        log_exists=True,
        cli_log_path="/home/user/.local/share/package-alert/cli.log",
        cli_log_exists=True,
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
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "running" in output
    assert "99999" in output  # PID
    assert "2h 2m" in output  # uptime


def test_render_status_rich_shows_systemd():
    data = _make_status_data()
    data.daemon_managed_by_systemd = True
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "via systemd" in output


def test_render_status_rich_no_systemd_label_when_user_started():
    data = _make_status_data()
    data.daemon_managed_by_systemd = False
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "systemd" not in output


def test_render_status_json_managed_by_systemd(capsys):
    data = _make_status_data()
    data.daemon_managed_by_systemd = True
    render_status(data, as_json=True)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["daemon"]["managed_by_systemd"] is True


def test_render_status_rich_stopped():
    data = _make_status_data(running=False)
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
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
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "Alerts" in output
    assert "evil-pkg" in output
    assert "CRITICAL" in output


def test_render_status_rich_no_alerts_message():
    data = _make_status_data(alerts=[])
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "No alerts" in output


def test_render_status_rich_scheduled_projects():
    data = _make_status_data()
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "Scheduled Projects" in output
    assert "3 projects registered" in output


def test_render_status_rich_no_scheduled_projects():
    data = _make_status_data()
    data.scheduled_projects_count = 0
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "No projects scheduled" in output


def test_render_status_rich_shows_log_paths():
    data = _make_status_data()
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "Logs" in output
    assert "daemon.log" in output
    assert "cli.log" in output


def test_render_status_rich_log_not_yet_created():
    data = _make_status_data()
    data.log_exists = False
    data.cli_log_exists = False
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "not yet created" in output


def test_render_status_rich_log_disabled():
    data = _make_status_data()
    data.log_path = ""
    data.cli_log_path = ""
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "disabled" in output


def test_render_status_rich_shows_central_outbox_and_last_seen():
    from packagealert.cli.status import CentralStatus

    data = _make_status_data()
    data.central = CentralStatus(
        enabled=True,
        plugin_name="pa-central",
        server_url="https://fleet.example.com",
        last_heartbeat_at="2026-07-15T10:00:00+00:00",
        last_heartbeat_ok=False,
        last_heartbeat_error="connection refused",
        last_config_fetch_at=None,
        last_config_fetch_ok=None,
        last_config_fetch_error=None,
        last_seen_at="2026-07-15T09:00:00+00:00",
        outbox_scan_count=2,
        outbox_alert_count=1,
    )
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "Last seen" in output
    assert "2026-07-15" in output  # last_seen_at timestamp rendered
    assert "Outbox" in output
    assert "2 scan(s)" in output
    assert "1 alert(s)" in output


def test_render_status_rich_shows_never_seen_when_no_successful_heartbeat():
    from packagealert.cli.status import CentralStatus

    data = _make_status_data()
    data.central = CentralStatus(
        enabled=True,
        plugin_name="pa-central",
        server_url="https://fleet.example.com",
        last_heartbeat_at=None,
        last_heartbeat_ok=None,
        last_heartbeat_error=None,
        last_config_fetch_at=None,
        last_config_fetch_ok=None,
        last_config_fetch_error=None,
        last_seen_at=None,
        outbox_scan_count=0,
        outbox_alert_count=0,
    )
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    render_status(data, as_json=False, console=console)
    output = buf.getvalue()
    assert "Last seen" in output
    assert "never" in output
    assert "Outbox" in output
    assert "empty" in output


def test_render_status_json_includes_central_outbox_and_last_seen(capsys):
    from packagealert.cli.status import CentralStatus

    data = _make_status_data()
    data.central = CentralStatus(
        enabled=True,
        plugin_name="pa-central",
        server_url="https://fleet.example.com",
        last_heartbeat_at="2026-07-15T10:00:00+00:00",
        last_heartbeat_ok=True,
        last_heartbeat_error=None,
        last_config_fetch_at=None,
        last_config_fetch_ok=None,
        last_config_fetch_error=None,
        last_seen_at="2026-07-15T10:00:00+00:00",
        outbox_scan_count=3,
        outbox_alert_count=5,
    )
    render_status(data, as_json=True)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["central"]["last_seen_at"] == "2026-07-15T10:00:00+00:00"
    assert parsed["central"]["outbox"] == {"scan": 3, "alert": 5}


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
