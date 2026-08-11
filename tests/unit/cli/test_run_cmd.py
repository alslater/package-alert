"""Tests for `package-alert run` CLI option parsing and PA_RUN_OPTS handling."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from packagealert.cli.app import app
from packagealert.project_config import ProjectRunConfig, ProjectRunConfigError

runner = CliRunner()


def _make_mock_runner(return_code: int = 0):
    """Return a patched SandboxRunner whose run() returns *return_code*."""
    mock = AsyncMock(return_value=return_code)
    return mock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _invoke(
    args: list[str],
    env: dict[str, str] | None = None,
    proj_cfg: ProjectRunConfig | ProjectRunConfigError | None = None,
):
    """Invoke the CLI with optional environment and project-config overrides.

    *proj_cfg* controls what ``find_project_run_config`` returns:
    - ``None`` (default) → no ``.pa-run.toml`` found
    - a ``ProjectRunConfig`` instance → that config is returned
    - a ``ProjectRunConfigError`` instance → that error is raised
    """
    mock_cfg = MagicMock()

    def _fake_find_proj_cfg(_cwd: Path) -> ProjectRunConfig | None:
        if isinstance(proj_cfg, ProjectRunConfigError):
            raise proj_cfg
        return proj_cfg

    with patch("packagealert.cli.app._load", return_value=(mock_cfg, None)), \
         patch("packagealert.project_config.find_project_run_config", _fake_find_proj_cfg), \
         patch("packagealert.sandbox.runner.SandboxRunner") as MockRunner:
        MockRunner.return_value.run = AsyncMock(return_value=0)
        result = runner.invoke(app, args, env=env)
        run_kwargs = MockRunner.return_value.run.call_args
    return result, run_kwargs


def _proj_cfg(**kwargs) -> ProjectRunConfig:
    """Build a ProjectRunConfig with a dummy source path."""
    defaults = {"source": Path("/project/.pa-run.toml"), "flags": "", "env": [], "no_network": False, "allow_external_lockfiles": False}
    return ProjectRunConfig(**{**defaults, **kwargs})


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------

def test_run_cmd_passes_command_to_runner():
    result, call = _invoke(["run", "pip", "install", "requests"])
    assert result.exit_code == 0
    args, _kwargs = call
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
    result, _call = _invoke(["run", "pip", "install", "requests"],
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
# .pa-run.toml — project config integration
# ---------------------------------------------------------------------------

class TestProjectRunConfig:
    def test_proj_cfg_flags_applied(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(flags="python:ssh-keys"))
        assert "ssh-keys" in call.kwargs["flags"].get("python", frozenset())

    def test_proj_cfg_no_network_applied(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(no_network=True))
        assert call.kwargs["allow_network"] is False

    def test_proj_cfg_allow_external_lockfiles_applied(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(allow_external_lockfiles=True))
        assert call.kwargs["allow_external_lockfiles"] is True

    def test_proj_cfg_env_prepended(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(env=["FROM_TOML"]))
        assert "FROM_TOML" in call.kwargs["extra_env"]

    def test_proj_cfg_path_printed_to_console(self):
        result, _ = _invoke(["run", "uv", "sync"],
                            proj_cfg=_proj_cfg())
        assert ".pa-run.toml" in result.output

    def test_proj_cfg_error_exits_1(self):
        err = ProjectRunConfigError(Path("/project/.pa-run.toml"), "unknown key: foo")
        result, _ = _invoke(["run", "uv", "sync"], proj_cfg=err)
        assert result.exit_code == 1
        assert "foo" in result.output

    def test_no_proj_cfg_no_output(self):
        result, _ = _invoke(["run", "uv", "sync"])
        assert ".pa-run.toml" not in result.output


class TestMergeOrder:
    """Three-source merge: .pa-run.toml < PA_RUN_OPTS < CLI flags."""

    # --- flags union ---

    def test_flags_proj_cfg_only(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(flags="python:ssh-keys"))
        assert call.kwargs["flags"] == {"python": frozenset({"ssh-keys"})}

    def test_flags_env_only(self):
        _, call = _invoke(["run", "uv", "sync"],
                          env={"PA_RUN_OPTS": "--flags python:network"})
        assert call.kwargs["flags"] == {"python": frozenset({"network"})}

    def test_flags_cli_only(self):
        _, call = _invoke(["run", "--flags", "python:ssh-keys", "uv", "sync"])
        assert call.kwargs["flags"] == {"python": frozenset({"ssh-keys"})}

    def test_flags_proj_and_env_unioned(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(flags="python:ssh-keys"),
                          env={"PA_RUN_OPTS": "--flags python:network"})
        assert call.kwargs["flags"] == {"python": frozenset({"ssh-keys", "network"})}

    def test_flags_proj_and_cli_unioned(self):
        _, call = _invoke(["run", "--flags", "python:network", "uv", "sync"],
                          proj_cfg=_proj_cfg(flags="python:ssh-keys"))
        assert call.kwargs["flags"] == {"python": frozenset({"ssh-keys", "network"})}

    def test_flags_all_three_sources_unioned(self):
        _, call = _invoke(["run", "--flags", "ruby:gems", "uv", "sync"],
                          proj_cfg=_proj_cfg(flags="python:ssh-keys"),
                          env={"PA_RUN_OPTS": "--flags python:network"})
        assert "ssh-keys" in call.kwargs["flags"].get("python", frozenset())
        assert "network" in call.kwargs["flags"].get("python", frozenset())
        assert "gems" in call.kwargs["flags"].get("ruby", frozenset())

    def test_flags_duplicate_capability_deduplicated(self):
        _, call = _invoke(["run", "--flags", "python:ssh-keys", "uv", "sync"],
                          proj_cfg=_proj_cfg(flags="python:ssh-keys"),
                          env={"PA_RUN_OPTS": "--flags python:ssh-keys"})
        assert call.kwargs["flags"] == {"python": frozenset({"ssh-keys"})}

    # --- no_network OR-ing ---

    def test_no_network_from_proj_cfg_not_overridden_by_absence_elsewhere(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(no_network=True))
        assert call.kwargs["allow_network"] is False

    def test_no_network_from_env_not_overridden_by_proj_cfg_false(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(no_network=False),
                          env={"PA_RUN_OPTS": "--no-network"})
        assert call.kwargs["allow_network"] is False

    def test_no_network_from_cli_wins(self):
        _, call = _invoke(["run", "--no-network", "uv", "sync"],
                          proj_cfg=_proj_cfg(no_network=False))
        assert call.kwargs["allow_network"] is False

    # --- allow_external_lockfiles OR-ing ---

    def test_allow_external_lockfiles_from_proj_cfg(self):
        _, call = _invoke(["run", "uv", "sync"],
                          proj_cfg=_proj_cfg(allow_external_lockfiles=True))
        assert call.kwargs["allow_external_lockfiles"] is True

    def test_allow_external_lockfiles_from_env(self):
        _, call = _invoke(["run", "uv", "sync"],
                          env={"PA_RUN_OPTS": "--allow-external-lockfiles"})
        assert call.kwargs["allow_external_lockfiles"] is True

    def test_allow_external_lockfiles_from_cli(self):
        _, call = _invoke(["run", "--allow-external-lockfiles", "uv", "sync"],
                          proj_cfg=_proj_cfg(allow_external_lockfiles=False))
        assert call.kwargs["allow_external_lockfiles"] is True

    # --- env union ---

    def test_env_proj_and_cli_both_forwarded(self):
        _, call = _invoke(["run", "--env", "CLI_VAR", "uv", "sync"],
                          proj_cfg=_proj_cfg(env=["TOML_VAR"]))
        assert "TOML_VAR" in call.kwargs["extra_env"]
        assert "CLI_VAR" in call.kwargs["extra_env"]

    def test_env_duplicate_deduplicated(self):
        _, call = _invoke(["run", "--env", "SHARED", "uv", "sync"],
                          proj_cfg=_proj_cfg(env=["SHARED"]))
        assert call.kwargs["extra_env"].count("SHARED") == 1

    def test_env_dedup_preserves_order(self):
        _, call = _invoke(["run", "--env", "CLI_VAR", "uv", "sync"],
                          proj_cfg=_proj_cfg(env=["TOML_VAR", "SHARED"]))
        env = list(call.kwargs["extra_env"])
        assert env.index("TOML_VAR") < env.index("CLI_VAR")


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


# ---------------------------------------------------------------------------
# project_env_allowlist enforcement
# ---------------------------------------------------------------------------

class TestProjectEnvAllowlist:
    """Tests for .pa-run.toml env allowlist enforcement."""

    def _invoke_with_allowlist(
        self,
        args: list[str],
        proj_cfg: ProjectRunConfig | None = None,
        allowlist: list[str] | None = None,
        env: dict[str, str] | None = None,
    ):
        from unittest.mock import AsyncMock, MagicMock, patch

        from typer.testing import CliRunner

        from packagealert.cli.app import app

        mock_cfg = MagicMock()
        mock_cfg.sandbox.project_env_allowlist = allowlist or []

        def _fake_find(cwd):
            return proj_cfg

        runner = CliRunner()
        with patch("packagealert.cli.app._load", return_value=(mock_cfg, None)), \
             patch("packagealert.project_config.find_project_run_config", _fake_find), \
             patch("packagealert.sandbox.runner.SandboxRunner") as MockRunner:
            MockRunner.return_value.run = AsyncMock(return_value=0)
            result = runner.invoke(app, args, env=env)
            run_kwargs = MockRunner.return_value.run.call_args
        return result, run_kwargs

    def test_untrusted_no_env_no_abort(self):
        cfg = _proj_cfg(trusted=False, env=[])
        result, _ = self._invoke_with_allowlist(["run", "uv", "sync"], proj_cfg=cfg)
        assert result.exit_code == 0

    def test_untrusted_env_in_allowlist_forwarded(self):
        cfg = _proj_cfg(trusted=False, env=["MY_TOKEN"])
        result, call = self._invoke_with_allowlist(
            ["run", "uv", "sync"], proj_cfg=cfg, allowlist=["MY_TOKEN"]
        )
        assert result.exit_code == 0
        assert "MY_TOKEN" in call.kwargs["extra_env"]

    def test_untrusted_env_not_in_allowlist_aborts(self):
        cfg = _proj_cfg(trusted=False, env=["AWS_SECRET_ACCESS_KEY"])
        result, _ = self._invoke_with_allowlist(["run", "uv", "sync"], proj_cfg=cfg)
        assert result.exit_code == 1
        assert "AWS_SECRET_ACCESS_KEY" in result.output
        assert "project_env_allowlist" in result.output

    def test_untrusted_env_not_in_allowlist_allow_flag_proceeds(self):
        cfg = _proj_cfg(trusted=False, env=["AWS_SECRET_ACCESS_KEY"])
        result, call = self._invoke_with_allowlist(
            ["run", "--allow-project-env", "uv", "sync"], proj_cfg=cfg
        )
        assert result.exit_code == 0
        assert "AWS_SECRET_ACCESS_KEY" in call.kwargs["extra_env"]
        assert "allow-project-env" in result.output.lower() or "skipping" in result.output.lower()

    def test_untrusted_env_partially_in_allowlist_shows_blocked_only(self):
        cfg = _proj_cfg(trusted=False, env=["MY_TOKEN", "AWS_SECRET"])
        result, _ = self._invoke_with_allowlist(
            ["run", "uv", "sync"], proj_cfg=cfg, allowlist=["MY_TOKEN"]
        )
        assert result.exit_code == 1
        assert "AWS_SECRET" in result.output
        assert "MY_TOKEN" not in result.output

    def test_trusted_env_not_in_allowlist_forwarded_freely(self):
        cfg = _proj_cfg(trusted=True, env=["AWS_SECRET_ACCESS_KEY"])
        result, call = self._invoke_with_allowlist(["run", "uv", "sync"], proj_cfg=cfg)
        assert result.exit_code == 0
        assert "AWS_SECRET_ACCESS_KEY" in call.kwargs["extra_env"]

    def test_allow_project_env_no_proj_cfg_no_effect(self):
        result, _ = self._invoke_with_allowlist(
            ["run", "--allow-project-env", "uv", "sync"], proj_cfg=None
        )
        assert result.exit_code == 0

    def test_allow_project_env_trusted_cfg_no_effect(self):
        cfg = _proj_cfg(trusted=True, env=["MY_TOKEN"])
        result, _ = self._invoke_with_allowlist(
            ["run", "--allow-project-env", "uv", "sync"], proj_cfg=cfg
        )
        assert result.exit_code == 0

    def test_empty_allowlist_default_untrusted_env_aborts(self):
        cfg = _proj_cfg(trusted=False, env=["GITHUB_TOKEN"])
        result, _ = self._invoke_with_allowlist(["run", "uv", "sync"], proj_cfg=cfg, allowlist=[])
        assert result.exit_code == 1
