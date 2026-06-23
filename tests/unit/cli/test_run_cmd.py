"""Tests for `package-alert run` CLI option parsing and PA_RUN_OPTS handling."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from packagealert.cli.app import app

runner = CliRunner()


def _make_mock_runner(return_code: int = 0):
    """Return a patched SandboxRunner whose run() returns *return_code*."""
    mock = AsyncMock(return_value=return_code)
    return mock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _invoke(args: list[str], env: dict[str, str] | None = None):
    """Invoke the CLI with optional environment overrides."""
    from unittest.mock import MagicMock
    mock_cfg = MagicMock()
    with patch("packagealert.cli.app._load", return_value=(mock_cfg, None)), \
         patch("packagealert.sandbox.runner.SandboxRunner") as MockRunner:
        MockRunner.return_value.run = AsyncMock(return_value=0)
        result = runner.invoke(app, args, env=env)
        run_kwargs = MockRunner.return_value.run.call_args
    return result, run_kwargs


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------

def test_run_cmd_passes_command_to_runner():
    result, call = _invoke(["run", "pip", "install", "requests"])
    assert result.exit_code == 0
    args, kwargs = call
    assert args[0] == ["pip", "install", "requests"]


def test_run_cmd_no_command_exits_1():
    with patch("packagealert.cli.app._load"):
        result = runner.invoke(app, ["run"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# --no-change / -n
# ---------------------------------------------------------------------------

def test_no_change_flag_long():
    _, call = _invoke(["run", "--no-change", "pip", "install", "requests"])
    assert call.kwargs["no_change"] is True


def test_no_change_flag_short():
    _, call = _invoke(["run", "-n", "pip", "install", "requests"])
    assert call.kwargs["no_change"] is True


def test_no_change_defaults_false():
    _, call = _invoke(["run", "pip", "install", "requests"])
    assert call.kwargs["no_change"] is False


# ---------------------------------------------------------------------------
# --no-network
# ---------------------------------------------------------------------------

def test_no_network_flag():
    _, call = _invoke(["run", "--no-network", "pip", "install", "requests"])
    assert call.kwargs["allow_network"] is False


def test_network_allowed_by_default():
    _, call = _invoke(["run", "pip", "install", "requests"])
    assert call.kwargs["allow_network"] is True


# ---------------------------------------------------------------------------
# PA_RUN_OPTS — environment variable
# ---------------------------------------------------------------------------

def test_pa_run_opts_no_change():
    _, call = _invoke(["run", "pip", "install", "requests"],
                      env={"PA_RUN_OPTS": "--no-change"})
    assert call.kwargs["no_change"] is True


def test_pa_run_opts_no_change_short():
    _, call = _invoke(["run", "pip", "install", "requests"],
                      env={"PA_RUN_OPTS": "-n"})
    assert call.kwargs["no_change"] is True


def test_pa_run_opts_no_network():
    _, call = _invoke(["run", "pip", "install", "requests"],
                      env={"PA_RUN_OPTS": "--no-network"})
    assert call.kwargs["allow_network"] is False


def test_pa_run_opts_multiple_flags():
    _, call = _invoke(["run", "pip", "install", "requests"],
                      env={"PA_RUN_OPTS": "--no-change --no-network"})
    assert call.kwargs["no_change"] is True
    assert call.kwargs["allow_network"] is False


def test_pa_run_opts_expose_ssh_keys():
    _, call = _invoke(["run", "pip", "install", "requests"],
                      env={"PA_RUN_OPTS": "--expose-ssh-keys"})
    assert "ssh-keys" in call.kwargs["flags"].get("python", frozenset())


def test_pa_run_opts_allow_external_lockfiles():
    _, call = _invoke(["run", "pip", "install", "requests"],
                      env={"PA_RUN_OPTS": "--allow-external-lockfiles"})
    assert call.kwargs["allow_external_lockfiles"] is True


def test_pa_run_opts_empty_string_ignored():
    _, call = _invoke(["run", "pip", "install", "requests"],
                      env={"PA_RUN_OPTS": ""})
    assert call.kwargs["no_change"] is False
    assert call.kwargs["allow_network"] is True


def test_pa_run_opts_unrecognised_token_warns_and_continues():
    result, call = _invoke(["run", "pip", "install", "requests"],
                           env={"PA_RUN_OPTS": "--bogus-flag"})
    assert result.exit_code == 0
    assert "unrecognised" in result.output.lower() or "ignored" in result.output.lower()


def test_pa_run_opts_does_not_override_explicit_cli_flag():
    # CLI flag takes precedence — PA_RUN_OPTS applies only when the flag
    # isn't already set.  With --no-change from CLI the value stays True
    # even if PA_RUN_OPTS is empty.
    _, call = _invoke(["run", "--no-change", "pip", "install", "requests"],
                      env={"PA_RUN_OPTS": ""})
    assert call.kwargs["no_change"] is True


# ---------------------------------------------------------------------------
# Passthrough: package manager options must not be consumed by pa run
# ---------------------------------------------------------------------------

def test_package_manager_help_flag_passed_through():
    """pip --help must reach pip, not be consumed as pa run's --help."""
    _, call = _invoke(["run", "pip", "--help"])
    args, _ = call
    assert "--help" in args[0]


def test_package_manager_short_n_flag_passed_through():
    """Package managers that use -n must receive it, not have it consumed as --no-change."""
    _, call = _invoke(["run", "npm", "install", "-n"])
    args, _ = call
    assert "-n" in args[0]


# ---------------------------------------------------------------------------
# --flags option
# ---------------------------------------------------------------------------

class TestFlagsOption:
    def test_flags_forwarded_to_runner(self, monkeypatch):
        """--flags is parsed and passed as a dict to runner.run()."""
        calls = []

        async def fake_run(self_runner, argv, *, allow_network=True, extra_env=None, expose_ssh_keys=False, flags=None, allow_external_lockfiles=False, no_change=False):
            calls.append({"flags": flags})
            return 0

        from unittest.mock import patch
        from typer.testing import CliRunner
        from packagealert.cli.app import app

        with patch("packagealert.sandbox.runner.SandboxRunner.run", fake_run):
            runner = CliRunner()
            result = runner.invoke(app, ["run", "--flags", "python:ssh-keys", "uv", "sync"])
        assert result.exit_code == 0, result.output
        assert calls[0]["flags"] == {"python": frozenset({"ssh-keys"})}

    def test_expose_ssh_keys_deprecated_warning(self, monkeypatch):
        """--expose-ssh-keys prints a deprecation warning."""
        calls = []

        async def fake_run(self_runner, argv, *, allow_network=True, extra_env=None, expose_ssh_keys=False, flags=None, allow_external_lockfiles=False, no_change=False):
            calls.append({"flags": flags})
            return 0

        from unittest.mock import patch
        from typer.testing import CliRunner
        from packagealert.cli.app import app

        with patch("packagealert.sandbox.runner.SandboxRunner.run", fake_run):
            runner = CliRunner()
            result = runner.invoke(app, ["run", "--expose-ssh-keys", "uv", "sync"])
        assert result.exit_code == 0, result.output
        assert "deprecated" in result.output.lower() or "python:ssh-keys" in result.output
