from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from packagealert.cli.app import app, _is_pipx_install

runner = CliRunner()


def test_is_pipx_install_legacy_path(tmp_path):
    # ~/.local/pipx/venvs — the path pipx uses by default on most systems
    pipx_venvs = tmp_path / ".local" / "pipx" / "venvs"
    fake_exe = str(pipx_venvs / "package-alert" / "bin" / "python")
    import os
    env = {k: v for k, v in os.environ.items() if k != "PIPX_HOME"}
    with patch.dict("os.environ", env, clear=True):
        with patch("packagealert.cli.app._pipx_venvs_candidates", return_value=[pipx_venvs]):
            with patch.object(sys, "executable", fake_exe):
                assert _is_pipx_install() is True


def test_is_pipx_install_xdg_path(tmp_path):
    # ~/.local/share/pipx/venvs — XDG-compliant path, also supported
    pipx_venvs = tmp_path / ".local" / "share" / "pipx" / "venvs"
    fake_exe = str(pipx_venvs / "package-alert" / "bin" / "python")
    import os
    env = {k: v for k, v in os.environ.items() if k != "PIPX_HOME"}
    with patch.dict("os.environ", env, clear=True):
        with patch("packagealert.cli.app._pipx_venvs_candidates", return_value=[pipx_venvs]):
            with patch.object(sys, "executable", fake_exe):
                assert _is_pipx_install() is True


def test_is_pipx_install_outside_pipx(tmp_path):
    pipx_venvs = tmp_path / ".local" / "pipx" / "venvs"
    fake_exe = str(tmp_path / "some_other_venv" / "bin" / "python")
    with patch("packagealert.cli.app._pipx_venvs_candidates", return_value=[pipx_venvs]):
        with patch.object(sys, "executable", fake_exe):
            assert _is_pipx_install() is False


def test_is_pipx_install_respects_pipx_home(tmp_path):
    custom_home = tmp_path / "mypipx"
    pipx_venvs = custom_home / "venvs"
    fake_exe = str(pipx_venvs / "package-alert" / "bin" / "python")
    with patch.dict("os.environ", {"PIPX_HOME": str(custom_home)}):
        with patch("packagealert.cli.app._pipx_venvs_candidates", return_value=[pipx_venvs]):
            with patch.object(sys, "executable", fake_exe):
                assert _is_pipx_install() is True


def test_update_not_pipx_install():
    with patch("packagealert.cli.app._is_pipx_install", return_value=False):
        result = runner.invoke(app, ["update"])
    assert result.exit_code == 1
    assert "not installed via pipx" in result.output


def test_update_pipx_not_on_path():
    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                result = runner.invoke(app, ["update"])
    assert result.exit_code == 1
    assert "pipx" in result.output.lower()


def test_update_delegates_to_pipx_and_forwards_exit_code():
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                result = runner.invoke(app, ["update"])
    mock_run.assert_called_once_with(["pipx", "upgrade", "package-alert"])
    assert result.exit_code == 0


def test_update_forwards_nonzero_exit_code():
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=1)
    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("subprocess.run", return_value=mock_result):
                result = runner.invoke(app, ["update"])
    assert result.exit_code == 1


# --- update notice + background thread tests ---

import json
import time as _time


def test_cli_prints_notice_when_update_available(tmp_path):
    cache = tmp_path / "update-check.json"
    cache.write_text(json.dumps({
        "checked_at": _time.time(),
        "latest": "9.9.9",
        "current": "0.1.2",
    }))
    with patch("packagealert.cli.app._is_interactive", return_value=True):
        with patch("packagealert.update_check.CACHE_FILE", cache):
            with patch("packagealert.update_check.pkg_version", return_value="0.1.2"):
                with patch("packagealert.cli.app._is_pipx_install", return_value=False):
                    result = runner.invoke(app, ["update"])
    combined = result.output + (result.stderr if hasattr(result, "stderr") else "")
    assert "9.9.9" in combined


def test_cli_spawns_background_thread_when_cache_stale(tmp_path):
    cache = tmp_path / "update-check.json"
    # cache is absent — stale
    import packagealert.cli.app as _app
    _app._update_thread = None  # reset module state between tests

    check_called = []

    async def fake_check():
        check_called.append(1)

    with patch("packagealert.cli.app._is_interactive", return_value=True):
        with patch("packagealert.update_check.CACHE_FILE", cache):
            with patch("packagealert.update_check.check_and_cache", fake_check):
                with patch("packagealert.cli.app._is_pipx_install", return_value=False):
                    runner.invoke(app, ["update"])
                    if _app._update_thread:
                        _app._update_thread.join(timeout=2.0)

    assert len(check_called) >= 1


def test_cli_does_not_spawn_thread_when_cache_fresh(tmp_path):
    cache = tmp_path / "update-check.json"
    cache.write_text(json.dumps({
        "checked_at": _time.time(),
        "latest": "0.1.2",
        "current": "0.1.2",
    }))
    import packagealert.cli.app as _app
    _app._update_thread = None  # reset module state between tests

    check_called = []

    async def fake_check():
        check_called.append(1)

    with patch("packagealert.cli.app._is_interactive", return_value=True):
        with patch("packagealert.update_check.CACHE_FILE", cache):
            with patch("packagealert.update_check.check_and_cache", fake_check):
                with patch("packagealert.cli.app._is_pipx_install", return_value=False):
                    runner.invoke(app, ["update"])
                    if _app._update_thread:
                        _app._update_thread.join(timeout=2.0)

    assert len(check_called) == 0


def test_update_no_restart_when_version_unchanged():
    """pipx runs but version didn't change — no SIGTERM, no Popen."""
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("subprocess.run", return_value=mock_result):
            with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
                with patch("subprocess.Popen") as mock_popen:
                    with patch("os.kill") as mock_kill:
                        result = runner.invoke(app, ["update"])
    assert result.exit_code == 0
    mock_kill.assert_not_called()
    mock_popen.assert_not_called()
    assert "up to date" in result.output.lower()


def test_update_no_restart_when_daemon_not_running():
    """Version changed but daemon is not running — no SIGTERM, no Popen."""
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
    call_count = [0]

    def version_side_effect(pkg):
        call_count[0] += 1
        return "0.1.2" if call_count[0] == 1 else "0.2.0"

    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("subprocess.run", return_value=mock_result):
            with patch("packagealert.cli.app._pkg_version", side_effect=version_side_effect):
                with patch("packagealert.cli.app.check_already_running", return_value=None):
                    with patch("subprocess.Popen") as mock_popen:
                        with patch("os.kill") as mock_kill:
                            result = runner.invoke(app, ["update"])
    assert result.exit_code == 0
    mock_kill.assert_not_called()
    mock_popen.assert_not_called()


def _make_version_side_effect(before="0.1.2", after="0.2.0"):
    call_count = [0]
    def side_effect(pkg):
        call_count[0] += 1
        return before if call_count[0] == 1 else after
    return side_effect


def test_update_systemd_restarts_via_systemctl():
    """Version changed, daemon running under systemd — systemctl restart called, no SIGTERM, no Popen."""
    import subprocess as sp
    pipx_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
    systemctl_result = sp.CompletedProcess(args=["systemctl", "--user", "restart", "package-alert"], returncode=0)

    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("subprocess.run", side_effect=[pipx_result, systemctl_result]) as mock_run:
            with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
                with patch("packagealert.cli.app.check_already_running", return_value=9999):
                    with patch("packagealert.cli.app.is_started_by_systemd", return_value=True):
                        with patch("os.kill") as mock_kill:
                            with patch("subprocess.Popen") as mock_popen:
                                result = runner.invoke(app, ["update"])

    assert result.exit_code == 0
    mock_kill.assert_not_called()
    mock_popen.assert_not_called()
    assert mock_run.call_args_list[1].args[0] == ["systemctl", "--user", "restart", "package-alert"]
    assert "restarted" in result.output.lower()


def test_update_systemd_restart_failure_prints_warning():
    """systemctl restart exits non-zero — warning shown, no crash."""
    import subprocess as sp
    pipx_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
    systemctl_result = sp.CompletedProcess(args=["systemctl", "--user", "restart", "package-alert"], returncode=1)

    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("subprocess.run", side_effect=[pipx_result, systemctl_result]):
            with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
                with patch("packagealert.cli.app.check_already_running", return_value=9999):
                    with patch("packagealert.cli.app.is_started_by_systemd", return_value=True):
                        result = runner.invoke(app, ["update"])

    assert result.exit_code == 0
    assert "journalctl" in result.output


def test_update_non_systemd_sigterm_then_popen():
    """Version changed, daemon running without systemd — spawns with original cmdline, confirms via new PID."""
    import subprocess as sp
    import signal as _sig
    mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None  # process still running
    mock_proc.returncode = None
    original_cmd = ["package-alert", "daemon", "--config", "/custom/config.toml"]

    # check_already_running: first call returns old pid (pre-upgrade check), subsequent calls
    # in the post-spawn confirmation loop return a new pid to signal successful restart.
    car_results = iter([9999, None, 8888])

    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("subprocess.run", return_value=mock_result):
            with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
                with patch("packagealert.cli.app.check_already_running", side_effect=lambda: next(car_results)):
                    with patch("packagealert.cli.app.is_started_by_systemd", return_value=False):
                        with patch("packagealert.cli.app._daemon_cmdline", return_value=original_cmd):
                            with patch("packagealert.cli.app.PID_FILE") as mock_pid_file:
                                mock_pid_file.exists.return_value = False  # old daemon stopped cleanly
                                with patch("os.kill") as mock_kill:
                                    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
                                        result = runner.invoke(app, ["update"])

    assert result.exit_code == 0
    mock_kill.assert_called_once_with(9999, _sig.SIGTERM)
    mock_popen.assert_called_once_with(original_cmd, start_new_session=True)
    assert "restarted" in result.output.lower()


def test_update_non_systemd_falls_back_to_default_cmd_when_cmdline_unreadable():
    """_daemon_cmdline returns None (e.g. /proc unreadable) — falls back to default command."""
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.returncode = None
    car_results = iter([9999, None, 8888])

    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("subprocess.run", return_value=mock_result):
            with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
                with patch("packagealert.cli.app.check_already_running", side_effect=lambda: next(car_results)):
                    with patch("packagealert.cli.app.is_started_by_systemd", return_value=False):
                        with patch("packagealert.cli.app._daemon_cmdline", return_value=None):
                            with patch("packagealert.cli.app.PID_FILE") as mock_pid_file:
                                mock_pid_file.exists.return_value = False
                                with patch("os.kill"):
                                    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
                                        result = runner.invoke(app, ["update"])

    assert result.exit_code == 0
    mock_popen.assert_called_once_with(["package-alert", "daemon"], start_new_session=True)


def test_update_non_systemd_timeout_still_spawns():
    """Old daemon doesn't stop (timeout), Popen called; new daemon never confirms — warning shown."""
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.returncode = None

    # check_already_running: first call returns old pid; post-spawn loop always returns old pid
    # (or None), never a new one — so confirmation times out.
    car_results = iter([9999, 9999, 9999, 9999, 9999])

    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("subprocess.run", return_value=mock_result):
            with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
                with patch("packagealert.cli.app.check_already_running", side_effect=lambda: next(car_results)):
                    with patch("packagealert.cli.app.is_started_by_systemd", return_value=False):
                        with patch("packagealert.cli.app.PID_FILE") as mock_pid_file:
                            mock_pid_file.exists.return_value = True  # never disappears
                            with patch("packagealert.cli.app.time") as mock_time:
                                mock_time.time.side_effect = [0.0, 0.0, 999.0, 0.0, 999.0]
                                mock_time.sleep = lambda _: None
                                with patch("os.kill"):
                                    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
                                        result = runner.invoke(app, ["update"])

    assert result.exit_code == 0
    mock_popen.assert_called_once()
    assert "timed out" in result.output.lower()


def test_update_os_kill_error_prints_warning():
    """os.kill raises OSError — warning shown, no crash, exit 0."""
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)

    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("subprocess.run", return_value=mock_result):
            with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
                with patch("packagealert.cli.app.check_already_running", return_value=9999):
                    with patch("packagealert.cli.app.is_started_by_systemd", return_value=False):
                        with patch("os.kill", side_effect=ProcessLookupError("no such process")):
                            with patch("subprocess.Popen") as mock_popen:
                                result = runner.invoke(app, ["update"])

    assert result.exit_code == 0
    mock_popen.assert_not_called()
    assert "could not restart" in result.output.lower()


def test_force_calls_pipx_reinstall():
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "reinstall", "package-alert"], returncode=0)
    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("subprocess.run", return_value=mock_result) as mock_run:
                result = runner.invoke(app, ["update", "--force"])
    mock_run.assert_called_once_with(["pipx", "reinstall", "package-alert"])
    assert result.exit_code == 0


def test_force_prints_reinstalled_message():
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "reinstall", "package-alert"], returncode=0)
    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("subprocess.run", return_value=mock_result):
                result = runner.invoke(app, ["update", "--force"])
    assert "reinstalled" in result.output.lower()


def test_force_forwards_nonzero_exit_code():
    import subprocess as sp
    mock_result = sp.CompletedProcess(args=["pipx", "reinstall", "package-alert"], returncode=1)
    with patch("packagealert.cli.app._is_pipx_install", return_value=True):
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("subprocess.run", return_value=mock_result):
                result = runner.invoke(app, ["update", "--force"])
    assert result.exit_code == 1
