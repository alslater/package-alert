from __future__ import annotations

import itertools
import json
import os
import sys
import time as _time
from unittest.mock import MagicMock, patch

import pytest

from typer.testing import CliRunner

from packagealert.cli.app import app, _is_pipx_install, _is_uv_tool_install

runner = CliRunner()


def test_is_pipx_install_legacy_path(tmp_path):
    # ~/.local/pipx/venvs — the path pipx uses by default on most systems.
    # _pipx_venvs_candidates is fully injected, so no env vars can reach the
    # code under test; no environment isolation is required here.
    pipx_venvs = tmp_path / ".local" / "pipx" / "venvs"
    pipx_venvs.mkdir(parents=True)
    fake_exe = str(pipx_venvs / "package-alert" / "bin" / "python")
    with patch("packagealert.cli.app._pipx_venvs_candidates", return_value=[pipx_venvs]):
        with patch.object(sys, "executable", fake_exe):
            assert _is_pipx_install() is True


def test_is_pipx_install_xdg_path(tmp_path):
    # ~/.local/share/pipx/venvs — XDG-compliant path, also supported.
    # _pipx_venvs_candidates is fully injected, so no env vars can reach the
    # code under test; no environment isolation is required here.
    pipx_venvs = tmp_path / ".local" / "share" / "pipx" / "venvs"
    pipx_venvs.mkdir(parents=True)
    fake_exe = str(pipx_venvs / "package-alert" / "bin" / "python")
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
    # PIPX_HOME set — candidates derived from env var, not the defaults
    custom_home = tmp_path / "mypipx"
    pipx_venvs = custom_home / "venvs"
    pipx_venvs.mkdir(parents=True)
    fake_exe = str(pipx_venvs / "package-alert" / "bin" / "python")
    with patch.dict("os.environ", {"PIPX_HOME": str(custom_home)}):
        with patch.object(sys, "executable", fake_exe):
            assert _is_pipx_install() is True


def test_is_pipx_install_relative_pipx_home(tmp_path, monkeypatch):
    # PIPX_HOME set to a relative path — _pipx_venvs_candidates must normalise it
    # to absolute so it matches sys.executable (which is always absolute).
    custom_home = tmp_path / "mypipx"
    custom_home.mkdir(parents=True)
    fake_exe = str(custom_home / "venvs" / "package-alert" / "bin" / "python")
    # chdir first, then compute the relative path from that cwd
    monkeypatch.chdir(tmp_path)
    rel = os.path.relpath(custom_home)  # "mypipx" — relative to tmp_path
    monkeypatch.setenv("PIPX_HOME", rel)
    with patch.object(sys, "executable", fake_exe):
        assert _is_pipx_install() is True


def test_update_not_pipx_install():
    with patch("packagealert.cli.app._is_pipx_install", return_value=False):
        with patch("packagealert.cli.app._is_uv_tool_install", return_value=False):
            result = runner.invoke(app, ["update"])
    assert result.exit_code == 1
    assert "pipx or uv tool" in result.output


def _make_run_dispatcher(upgrade_cmd, *, systemctl_rc=0):
    """Return a subprocess.run side_effect that routes by command.

    Routes the expected upgrade command and the standard systemctl restart
    command to pre-configured CompletedProcess results. Any unexpected command
    raises AssertionError so new calls added to the flow fail loudly instead of
    silently raising StopIteration.
    """
    import subprocess as sp

    systemctl_cmd = ["systemctl", "--user", "restart", "package-alert"]

    def dispatcher(cmd, *args, **kwargs):
        if cmd == upgrade_cmd:
            return sp.CompletedProcess(args=cmd, returncode=0)
        if cmd == systemctl_cmd:
            return sp.CompletedProcess(args=cmd, returncode=systemctl_rc)
        raise AssertionError(f"Unexpected subprocess.run call: {cmd!r}")

    return dispatcher


def _make_version_side_effect(before="0.1.2", after="0.2.0"):
    calls = itertools.count()
    def side_effect(*args, **kwargs):
        return before if next(calls) == 0 else after
    return side_effect


class TestPipxUpdate:
    """Tests for the pipx installation branch of the update command.

    The autouse fixture pins both installer-detection functions so every test
    in this class reliably exercises the pipx path, regardless of the
    environment the test suite runs in.
    """

    @pytest.fixture(autouse=True)
    def pipx_install(self):
        with patch("packagealert.cli.app._is_uv_tool_install", return_value=False):
            with patch("packagealert.cli.app._is_pipx_install", return_value=True):
                yield

    def test_update_pipx_not_on_path(self):
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", side_effect=FileNotFoundError):
                result = runner.invoke(app, ["update"])
        assert result.exit_code == 1
        assert "pipx" in result.output.lower()

    def test_update_delegates_to_pipx_and_forwards_exit_code(self):
        import subprocess as sp
        mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=0)
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", return_value=mock_result) as mock_run:
                result = runner.invoke(app, ["update"])
        mock_run.assert_called_once_with(["pipx", "upgrade", "package-alert"])
        assert result.exit_code == 0

    def test_update_forwards_nonzero_exit_code(self):
        import subprocess as sp
        mock_result = sp.CompletedProcess(args=["pipx", "upgrade", "package-alert"], returncode=1)
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", return_value=mock_result):
                result = runner.invoke(app, ["update"])
        assert result.exit_code == 1

    def test_force_calls_pipx_reinstall(self):
        import subprocess as sp
        mock_result = sp.CompletedProcess(args=["pipx", "reinstall", "package-alert"], returncode=0)
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", return_value=mock_result) as mock_run:
                result = runner.invoke(app, ["update", "--force"])
        mock_run.assert_called_once_with(["pipx", "reinstall", "package-alert"])
        assert result.exit_code == 0

    def test_force_prints_reinstalled_message(self):
        import subprocess as sp
        mock_result = sp.CompletedProcess(args=["pipx", "reinstall", "package-alert"], returncode=0)
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", return_value=mock_result):
                result = runner.invoke(app, ["update", "--force"])
        assert "reinstalled" in result.output.lower()

    def test_force_forwards_nonzero_exit_code(self):
        import subprocess as sp
        mock_result = sp.CompletedProcess(args=["pipx", "reinstall", "package-alert"], returncode=1)
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", return_value=mock_result):
                result = runner.invoke(app, ["update", "--force"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Post-upgrade daemon restart logic (installer-agnostic)
# ---------------------------------------------------------------------------

_UPGRADE_OK = [
    (["pipx", "upgrade", "package-alert"], False),
    (["uv", "tool", "upgrade", "package-alert"], True),
]


class TestDaemonRestart:
    """Tests for the post-upgrade daemon restart logic.

    The restart code runs after any successful upgrade and is entirely
    independent of which installer was used.  The autouse fixture stubs the
    upgrade step with a generic successful result so each test focuses purely
    on the restart behaviour.
    """

    @pytest.fixture(autouse=True, params=_UPGRADE_OK, ids=["pipx", "uv"])
    def upgraded(self, request):
        import subprocess as sp
        cmd, is_uv = request.param
        ok = sp.CompletedProcess(args=cmd, returncode=0)
        with patch("packagealert.cli.app._is_pipx_install", return_value=not is_uv):
            with patch("packagealert.cli.app._is_uv_tool_install", return_value=is_uv):
                with patch("packagealert.cli.app.subprocess.run", return_value=ok):
                    yield cmd

    def test_no_restart_when_version_unchanged(self):
        """Upgrade ran but version didn't change — no SIGTERM, no Popen."""
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.check_already_running", return_value=None):
                with patch("packagealert.cli.app.subprocess.Popen") as mock_popen:
                    with patch("packagealert.cli.app.os.kill") as mock_kill:
                        result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        mock_kill.assert_not_called()
        mock_popen.assert_not_called()
        assert "up to date" in result.output.lower()

    def test_no_restart_when_daemon_not_running(self):
        """Version changed but daemon is not running — no SIGTERM, no Popen."""
        with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
            with patch("packagealert.cli.app.check_already_running", return_value=None):
                with patch("packagealert.cli.app.subprocess.Popen") as mock_popen:
                    with patch("packagealert.cli.app.os.kill") as mock_kill:
                        result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        mock_kill.assert_not_called()
        mock_popen.assert_not_called()

    def test_systemd_restarts_via_systemctl(self, upgraded):
        """Version changed, daemon running under systemd — systemctl restart called, no SIGTERM, no Popen."""
        upgrade_cmd = upgraded
        systemctl_cmd = ["systemctl", "--user", "restart", "package-alert"]
        with patch("packagealert.cli.app.subprocess.run",
                   side_effect=_make_run_dispatcher(upgrade_cmd)) as mock_run:
            with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
                with patch("packagealert.cli.app.check_already_running", return_value=9999):
                    with patch("packagealert.cli.app.is_started_by_systemd", return_value=True):
                        with patch("packagealert.cli.app.os.kill") as mock_kill:
                            with patch("packagealert.cli.app.subprocess.Popen") as mock_popen:
                                result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        mock_kill.assert_not_called()
        mock_popen.assert_not_called()
        assert mock_run.call_args_list[0].args[0] == upgrade_cmd
        assert mock_run.call_args_list[1].args[0] == systemctl_cmd
        assert "restarted" in result.output.lower()

    def test_systemd_restart_failure_prints_warning(self, upgraded):
        """systemctl restart exits non-zero — warning shown, no crash."""
        upgrade_cmd = upgraded
        with patch("packagealert.cli.app.subprocess.run",
                   side_effect=_make_run_dispatcher(upgrade_cmd, systemctl_rc=1)):
            with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
                with patch("packagealert.cli.app.check_already_running", return_value=9999):
                    with patch("packagealert.cli.app.is_started_by_systemd", return_value=True):
                        result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        assert "journalctl" in result.output.lower()

    def test_non_systemd_sigterm_then_popen(self, tmp_path):
        """Version changed, daemon running without systemd — spawns with original cmdline, confirms via new PID."""
        import signal as _sig
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.returncode = None
        original_cmd = ["package-alert", "daemon", "--config", "/custom/config.toml"]
        car_results = itertools.chain([9999, None], itertools.repeat(8888))
        pid_file = tmp_path / "package-alert.pid"
        # File absent — daemon stopped cleanly after SIGTERM
        with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
            with patch("packagealert.cli.app.check_already_running", side_effect=lambda: next(car_results)):
                with patch("packagealert.cli.app.is_started_by_systemd", return_value=False):
                    with patch("packagealert.cli.app._daemon_cmdline", return_value=original_cmd):
                        with patch("packagealert.cli.app.PID_FILE", pid_file):
                            with patch("packagealert.cli.app.os.kill") as mock_kill:
                                with patch("packagealert.cli.app.subprocess.Popen", return_value=mock_proc) as mock_popen:
                                    result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        mock_kill.assert_called_once_with(9999, _sig.SIGTERM)
        mock_popen.assert_called_once_with(original_cmd, start_new_session=True)
        assert "restarted" in result.output.lower()

    def test_non_systemd_falls_back_to_default_cmd_when_cmdline_unreadable(self, tmp_path):
        """_daemon_cmdline returns None (e.g. /proc unreadable) — falls back to default command."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.returncode = None
        car_results = itertools.chain([9999, None], itertools.repeat(8888))
        pid_file = tmp_path / "package-alert.pid"
        # File absent — daemon stopped cleanly after SIGTERM
        with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
            with patch("packagealert.cli.app.check_already_running", side_effect=lambda: next(car_results)):
                with patch("packagealert.cli.app.is_started_by_systemd", return_value=False):
                    with patch("packagealert.cli.app._daemon_cmdline", return_value=None):
                        with patch("packagealert.cli.app.PID_FILE", pid_file):
                            with patch("packagealert.cli.app.os.kill"):
                                with patch("packagealert.cli.app.subprocess.Popen", return_value=mock_proc) as mock_popen:
                                    result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        mock_popen.assert_called_once_with(["package-alert", "daemon"], start_new_session=True)

    def test_non_systemd_timeout_still_spawns(self, tmp_path):
        """Old daemon doesn't stop (timeout), Popen called; new daemon never confirms — warning shown."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.returncode = None
        car_results = itertools.repeat(9999)
        pid_file = tmp_path / "package-alert.pid"
        pid_file.write_text("9999")  # File persists — daemon never stops
        with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
            with patch("packagealert.cli.app.check_already_running", side_effect=lambda: next(car_results)):
                with patch("packagealert.cli.app.is_started_by_systemd", return_value=False):
                    with patch("packagealert.cli.app.PID_FILE", pid_file):
                        # Each call returns a value 11 s higher than the last.
                        # The stop-loop deadline is time()+10 and the confirm-loop
                        # deadline is time()+5, so the very next time() call always
                        # exceeds both, forcing an immediate timeout. Time is
                        # strictly non-decreasing, so no backward-time anomalies.
                        _clock = itertools.count(step=11)
                        with patch("packagealert.cli.app.time.time", side_effect=lambda: float(next(_clock))):
                            with patch("packagealert.cli.app.time.sleep"):
                                with patch("packagealert.cli.app.os.kill"):
                                    with patch("packagealert.cli.app.subprocess.Popen", return_value=mock_proc) as mock_popen:
                                        result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        mock_popen.assert_called_once()
        assert "timed out" in result.output.lower()

    def test_os_kill_error_prints_warning(self):
        """os.kill raises OSError — warning shown, no crash, exit 0."""
        with patch("packagealert.cli.app._pkg_version", side_effect=_make_version_side_effect()):
            with patch("packagealert.cli.app.check_already_running", return_value=9999):
                with patch("packagealert.cli.app.is_started_by_systemd", return_value=False):
                    with patch("packagealert.cli.app.os.kill", side_effect=ProcessLookupError("no such process")):
                        with patch("packagealert.cli.app.subprocess.Popen") as mock_popen:
                            result = runner.invoke(app, ["update"])
        assert result.exit_code == 0
        mock_popen.assert_not_called()
        assert "could not restart" in result.output.lower()


# --- update notice + background thread tests ---


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


# ---------------------------------------------------------------------------
# uv tool install detection
# ---------------------------------------------------------------------------

def test_is_uv_tool_install_with_injected_candidates(tmp_path, monkeypatch):
    # Unset UV_TOOL_DIR so _uv_tool_dirs_candidates() cannot take the env-var
    # branch and bypass the injected return value.
    monkeypatch.delenv("UV_TOOL_DIR", raising=False)
    uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
    uv_tools.mkdir(parents=True)
    fake_exe = str(uv_tools / "package-alert" / "bin" / "python")
    with patch("packagealert.cli.app._uv_tool_dirs_candidates", return_value=[uv_tools]):
        with patch.object(sys, "executable", fake_exe):
            assert _is_uv_tool_install() is True


def test_is_uv_tool_install_outside_uv(tmp_path):
    uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
    fake_exe = str(tmp_path / "some_other_venv" / "bin" / "python")
    with patch("packagealert.cli.app._uv_tool_dirs_candidates", return_value=[uv_tools]):
        with patch.object(sys, "executable", fake_exe):
            assert _is_uv_tool_install() is False


def test_is_uv_tool_install_respects_uv_tool_dir(tmp_path, monkeypatch):
    # custom_tools is outside all default uv directories; UV_TOOL_DIR makes it detectable.
    custom_tools = tmp_path / "myuv" / "tools"
    custom_tools.mkdir(parents=True)
    fake_exe = str(custom_tools / "package-alert" / "bin" / "python")
    monkeypatch.setenv("UV_TOOL_DIR", str(custom_tools))
    with patch.object(sys, "executable", fake_exe):
        assert _is_uv_tool_install() is True


def test_is_uv_tool_install_not_detected_without_uv_tool_dir(tmp_path, monkeypatch):
    # Same path but UV_TOOL_DIR absent — must not be detected via default candidates.
    custom_tools = tmp_path / "myuv" / "tools"
    custom_tools.mkdir(parents=True)
    fake_exe = str(custom_tools / "package-alert" / "bin" / "python")
    monkeypatch.delenv("UV_TOOL_DIR", raising=False)
    with patch.object(sys, "executable", fake_exe):
        assert _is_uv_tool_install() is False


def test_is_uv_tool_install_relative_uv_tool_dir(tmp_path, monkeypatch):
    # UV_TOOL_DIR set to a relative path — _uv_tool_dirs_candidates must normalise it
    # to absolute so it matches sys.executable (which is always absolute).
    custom_tools = tmp_path / "tools"
    custom_tools.mkdir(parents=True)
    fake_exe = str(custom_tools / "package-alert" / "bin" / "python")
    # chdir first, then compute the relative path from that cwd
    monkeypatch.chdir(tmp_path)
    rel = os.path.relpath(custom_tools)  # "tools" — relative to tmp_path
    monkeypatch.setenv("UV_TOOL_DIR", rel)
    with patch.object(sys, "executable", fake_exe):
        assert _is_uv_tool_install() is True


# ---------------------------------------------------------------------------
# uv command shape
# ---------------------------------------------------------------------------

class TestUvUpdate:
    """Tests for the uv tool installation branch of the update command."""

    @pytest.fixture(autouse=True)
    def uv_install(self):
        with patch("packagealert.cli.app._is_pipx_install", return_value=False):
            with patch("packagealert.cli.app._is_uv_tool_install", return_value=True):
                yield

    def test_update_delegates_to_uv_upgrade(self):
        import subprocess as sp
        mock_result = sp.CompletedProcess(args=["uv", "tool", "upgrade", "package-alert"], returncode=0)
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", return_value=mock_result) as mock_run:
                result = runner.invoke(app, ["update"])
        mock_run.assert_called_once_with(["uv", "tool", "upgrade", "package-alert"])
        assert result.exit_code == 0

    def test_update_force_calls_uv_install_reinstall(self):
        import subprocess as sp
        mock_result = sp.CompletedProcess(args=["uv", "tool", "install", "--reinstall", "package-alert"], returncode=0)
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", return_value=mock_result) as mock_run:
                result = runner.invoke(app, ["update", "--force"])
        mock_run.assert_called_once_with(["uv", "tool", "install", "--reinstall", "package-alert"])
        assert result.exit_code == 0

    def test_update_uv_not_on_path(self):
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", side_effect=FileNotFoundError):
                result = runner.invoke(app, ["update"])
        assert result.exit_code == 1
        assert "uv" in result.output.lower()

    def test_update_uv_forwards_nonzero_exit_code(self):
        import subprocess as sp
        mock_result = sp.CompletedProcess(args=["uv", "tool", "upgrade", "package-alert"], returncode=1)
        with patch("packagealert.cli.app._pkg_version", return_value="0.1.2"):
            with patch("packagealert.cli.app.subprocess.run", return_value=mock_result):
                result = runner.invoke(app, ["update"])
        assert result.exit_code == 1


