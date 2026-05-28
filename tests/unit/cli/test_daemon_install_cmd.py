from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from packagealert.cli.app import app

runner = CliRunner()


def _ok() -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")


def _fail(code: int = 1, stderr: str = "some error") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=code, stdout=b"", stderr=stderr.encode())


# ── daemon-install ─────────────────────────────────────────────────────────────

def test_daemon_install_rejects_non_systemd():
    with patch("packagealert.cli.app._systemd_is_running", return_value=False):
        result = runner.invoke(app, ["daemon-install"])
    assert result.exit_code == 1
    assert "systemd" in result.output.lower()


def test_daemon_install_refuses_if_unit_already_exists(tmp_path):
    unit_path = tmp_path / "package-alert.service"
    unit_path.write_text("[Unit]\n")
    with patch("packagealert.cli.app._systemd_is_running", return_value=True):
        with patch("packagealert.cli.app._SYSTEMD_USER_DIR", tmp_path):
            result = runner.invoke(app, ["daemon-install"])
    assert result.exit_code == 1
    assert "already exists" in result.output


def test_daemon_install_writes_unit_and_enables(tmp_path):
    config_dir = tmp_path / "config"
    config_file = config_dir / "config.toml"
    with patch("packagealert.cli.app._systemd_is_running", return_value=True):
        with patch("packagealert.cli.app._SYSTEMD_USER_DIR", tmp_path):
            with patch("packagealert.cli.app._CONFIG_DIR", config_dir):
                with patch("packagealert.cli.app._DEFAULT_CONFIG_FILE", config_file):
                    with patch("subprocess.run", return_value=_ok()) as mock_run:
                        result = runner.invoke(app, ["daemon-install"])

    assert result.exit_code == 0, result.output
    assert "installed and started" in result.output.lower()
    unit_path = tmp_path / "package-alert.service"
    assert unit_path.exists()
    assert "ExecStart=" in unit_path.read_text()
    assert config_file.exists()
    assert "[osv]" in config_file.read_text()
    mock_run.assert_called_once_with(
        ["systemctl", "--user", "enable", "--now", "package-alert.service"],
        capture_output=True,
    )


def test_daemon_install_skips_config_if_already_exists(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text("[osv]\ncache_ttl_hours = 48\n")
    with patch("packagealert.cli.app._systemd_is_running", return_value=True):
        with patch("packagealert.cli.app._SYSTEMD_USER_DIR", tmp_path):
            with patch("packagealert.cli.app._CONFIG_DIR", config_dir):
                with patch("packagealert.cli.app._DEFAULT_CONFIG_FILE", config_file):
                    with patch("subprocess.run", return_value=_ok()):
                        result = runner.invoke(app, ["daemon-install"])

    assert result.exit_code == 0, result.output
    assert "leaving it unchanged" in result.output
    assert "cache_ttl_hours = 48" in config_file.read_text()


def _patch_config(tmp_path):
    config_dir = tmp_path / "config"
    config_file = config_dir / "config.toml"
    return config_dir, config_file


def test_daemon_install_prints_error_on_systemctl_failure(tmp_path):
    config_dir, config_file = _patch_config(tmp_path)
    with patch("packagealert.cli.app._systemd_is_running", return_value=True):
        with patch("packagealert.cli.app._SYSTEMD_USER_DIR", tmp_path):
            with patch("packagealert.cli.app._CONFIG_DIR", config_dir):
                with patch("packagealert.cli.app._DEFAULT_CONFIG_FILE", config_file):
                    with patch("subprocess.run", return_value=_fail(1, "some systemd error")):
                        result = runner.invoke(app, ["daemon-install"])

    assert result.exit_code == 1
    assert "failed" in result.output.lower()
    assert "some systemd error" in result.output


def test_daemon_install_prints_error_when_systemctl_not_found(tmp_path):
    config_dir, config_file = _patch_config(tmp_path)
    with patch("packagealert.cli.app._systemd_is_running", return_value=True):
        with patch("packagealert.cli.app._SYSTEMD_USER_DIR", tmp_path):
            with patch("packagealert.cli.app._CONFIG_DIR", config_dir):
                with patch("packagealert.cli.app._DEFAULT_CONFIG_FILE", config_file):
                    with patch("subprocess.run", side_effect=FileNotFoundError):
                        result = runner.invoke(app, ["daemon-install"])

    assert result.exit_code == 1
    assert "systemctl not found" in result.output.lower()


# ── daemon-remove ──────────────────────────────────────────────────────────────

def test_daemon_remove_rejects_non_systemd():
    with patch("packagealert.cli.app._systemd_is_running", return_value=False):
        result = runner.invoke(app, ["daemon-remove"])
    assert result.exit_code == 1
    assert "systemd" in result.output.lower()


def test_daemon_remove_nothing_to_do_if_no_unit(tmp_path):
    with patch("packagealert.cli.app._systemd_is_running", return_value=True):
        with patch("packagealert.cli.app._SYSTEMD_USER_DIR", tmp_path):
            result = runner.invoke(app, ["daemon-remove"])
    assert result.exit_code == 0
    assert "nothing to remove" in result.output.lower()


def test_daemon_remove_prints_error_when_systemctl_not_found(tmp_path):
    unit_path = tmp_path / "package-alert.service"
    unit_path.write_text("[Unit]\n")
    with patch("packagealert.cli.app._systemd_is_running", return_value=True):
        with patch("packagealert.cli.app._SYSTEMD_USER_DIR", tmp_path):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                result = runner.invoke(app, ["daemon-remove"])
    assert result.exit_code == 1
    assert "systemctl not found" in result.output.lower()


def test_daemon_remove_disables_and_deletes_unit(tmp_path):
    unit_path = tmp_path / "package-alert.service"
    unit_path.write_text("[Unit]\n")

    with patch("packagealert.cli.app._systemd_is_running", return_value=True):
        with patch("packagealert.cli.app._SYSTEMD_USER_DIR", tmp_path):
            with patch("subprocess.run", return_value=_ok()) as mock_run:
                result = runner.invoke(app, ["daemon-remove"])

    assert result.exit_code == 0, result.output
    assert not unit_path.exists()
    assert "removed" in result.output.lower()
    calls = [c.args[0] for c in mock_run.call_args_list]
    assert ["systemctl", "--user", "disable", "--now", "package-alert.service"] in calls
    assert ["systemctl", "--user", "daemon-reload"] in calls
