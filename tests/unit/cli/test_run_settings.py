from __future__ import annotations

import io

import pytest
from rich.console import Console

from packagealert.cli.run_settings import RunSettingsError, resolve_project_run_settings
from packagealert.config import AppConfig


def _out():
    return Console(file=io.StringIO(), width=200, color_system=None)


def test_no_config_no_env(tmp_path, monkeypatch):
    monkeypatch.delenv("PA_RUN_OPTS", raising=False)
    s = resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=_out())
    assert (s.source, s.flags, s.env, s.no_network) == (None, {}, [], False)


def test_pa_run_opts_flags_and_switches(tmp_path, monkeypatch):
    monkeypatch.setenv("PA_RUN_OPTS", "--flags python:uv-auth --no-network")
    s = resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=_out())
    assert s.flags == {"python": frozenset({"uv-auth"})} and s.no_network


def test_project_file_flags(tmp_path, monkeypatch):
    monkeypatch.delenv("PA_RUN_OPTS", raising=False)
    monkeypatch.setattr("packagealert.project_config.find_project_run_config",
                        lambda cwd: type("C", (), {"source": tmp_path / ".pa-run.toml", "flags": "python:uv-auth",
                                                   "env": [], "no_network": False,
                                                   "allow_external_lockfiles": False, "trusted": True})())
    s = resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=_out())
    assert s.flags == {"python": frozenset({"uv-auth"})} and s.source == tmp_path / ".pa-run.toml"


def test_untrusted_env_outside_allowlist_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("PA_RUN_OPTS", raising=False)
    monkeypatch.setattr("packagealert.project_config.find_project_run_config",
                        lambda cwd: type("C", (), {"source": tmp_path / ".pa-run.toml", "flags": "",
                                                   "env": ["SECRET"], "no_network": False,
                                                   "allow_external_lockfiles": False, "trusted": False})())
    with pytest.raises(RunSettingsError):
        resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=_out())


def test_bracketed_pa_run_opts_token_is_reported_not_parsed_as_markup(tmp_path, monkeypatch):
    monkeypatch.setenv("PA_RUN_OPTS", "[/foo]")
    buf = io.StringIO()
    out = Console(file=buf, width=200, color_system=None)
    resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=out)
    assert "[/foo]" in buf.getvalue()


def test_bracketed_flag_token_is_reported_not_parsed_as_markup(tmp_path, monkeypatch):
    monkeypatch.setenv("PA_RUN_OPTS", "--flags [/x]:y")
    buf = io.StringIO()
    out = Console(file=buf, width=200, color_system=None)
    resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=out)
    assert "[/x]:y" in buf.getvalue()


def _fake_project_config(monkeypatch, tmp_path, *, allow_major, trusted):
    monkeypatch.delenv("PA_RUN_OPTS", raising=False)
    monkeypatch.setattr("packagealert.project_config.find_project_run_config",
                        lambda cwd: type("C", (), {"source": tmp_path / ".pa-run.toml", "flags": "",
                                                   "env": [], "no_network": False,
                                                   "allow_external_lockfiles": False,
                                                   "allow_major": allow_major, "trusted": trusted})())


def test_allow_major_defaults_to_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("PA_RUN_OPTS", raising=False)
    s = resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=_out())
    assert s.allow_major == frozenset()


def test_trusted_project_file_allow_major_is_normalised(tmp_path, monkeypatch):
    _fake_project_config(monkeypatch, tmp_path, allow_major=["Cryptography", "zope_interface", "My.Pkg"],
                         trusted=True)
    s = resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=_out())
    assert s.allow_major == frozenset({"cryptography", "zope-interface", "my-pkg"})


def test_untrusted_project_file_allow_major_is_ignored_with_a_warning(tmp_path, monkeypatch):
    _fake_project_config(monkeypatch, tmp_path, allow_major=["cryptography"], trusted=False)
    buf = io.StringIO()
    out = Console(file=buf, width=300, color_system=None)
    s = resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=out)
    assert s.allow_major == frozenset()
    assert (f"{tmp_path / '.pa-run.toml'}: allow_major ignored — this .pa-run.toml is not trusted "
            f"(see .pa-run.toml trust rules)") in buf.getvalue()


def test_untrusted_project_file_without_allow_major_does_not_warn(tmp_path, monkeypatch):
    _fake_project_config(monkeypatch, tmp_path, allow_major=[], trusted=False)
    buf = io.StringIO()
    out = Console(file=buf, width=300, color_system=None)
    resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=out)
    assert "allow_major" not in buf.getvalue()


def test_project_settings_accept_seven_positional_arguments():
    from packagealert.cli.run_settings import ProjectRunSettings
    assert ProjectRunSettings(None, {}, [], False, False, False, False).allow_major == frozenset()



@pytest.mark.parametrize("value", [
    "'--no-network' --flags 'python:uv-auth",
    "\"--no-change\" --no-network 'x",
    "--no-network --flags 'python:uv-auth",
])
def test_malformed_pa_run_opts_quoting_is_rejected(tmp_path, monkeypatch, value):
    # Recovering from broken quoting would mean guessing which options were meant,
    # and a wrong guess can drop --no-network or --no-change.
    monkeypatch.setenv("PA_RUN_OPTS", value)
    buf = io.StringIO()
    out = Console(file=buf, width=200, color_system=None)
    with pytest.raises(RunSettingsError):
        resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=out)
    assert "PA_RUN_OPTS" in buf.getvalue()


def test_quoted_protective_options_in_well_formed_pa_run_opts_apply(tmp_path, monkeypatch):
    monkeypatch.setenv("PA_RUN_OPTS", "'--no-network' \"--no-change\" --flags 'python:uv-auth'")
    s = resolve_project_run_settings(tmp_path, AppConfig(), allow_project_env=False, out=_out())
    assert s.no_network and s.no_change and s.flags == {"python": frozenset({"uv-auth"})}
