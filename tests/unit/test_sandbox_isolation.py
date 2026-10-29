"""Container isolation (PA_SANDBOX_ISOLATION=container): see SANDBOX.md."""

from __future__ import annotations

import asyncio
import itertools
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from packagealert.config import AppConfig
from packagealert.sandbox import isolation
from packagealert.sandbox import runner as runner_mod
from packagealert.sandbox.runner import (
    CapturedRunError,
    SandboxRunner,
    credential_dirs,
    sandbox_unavailable_reason,
)


@pytest.fixture
def container(monkeypatch, tmp_path):
    """Container isolation, an unprivileged uid and a credential-free home."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv(isolation.ENV_VAR, isolation.CONTAINER)
    monkeypatch.setattr(isolation.os, "geteuid", lambda: 1000)
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    return home


@pytest.mark.parametrize(("value", "expected"), [
    (None, isolation.BWRAP), ("", isolation.BWRAP), ("bwrap", isolation.BWRAP), (" bwrap ", isolation.BWRAP),
    ("container", isolation.CONTAINER), (" container", isolation.CONTAINER),
])
def test_selection_values(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv(isolation.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(isolation.ENV_VAR, value)
    assert isolation.selected() == expected


@pytest.mark.parametrize("value", ["Container", "contianer", "none", "docker"])
def test_unknown_value_raises(monkeypatch, value):
    monkeypatch.setenv(isolation.ENV_VAR, value)
    with pytest.raises(isolation.IsolationError, match="expected bwrap or container"):
        isolation.selected()


def test_unknown_value_is_the_unavailable_reason(monkeypatch):
    monkeypatch.setenv(isolation.ENV_VAR, "contianer")
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    reason = sandbox_unavailable_reason()
    assert reason is not None and "unknown PA_SANDBOX_ISOLATION value 'contianer'" in reason


def test_bwrap_reason_is_unchanged(monkeypatch):
    monkeypatch.delenv(isolation.ENV_VAR, raising=False)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: False)
    assert sandbox_unavailable_reason() == "bwrap (bubblewrap) is not installed"
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    assert sandbox_unavailable_reason() is None


def test_container_needs_no_bwrap(container, monkeypatch):
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: False)
    assert sandbox_unavailable_reason() is None


def test_container_refuses_root(container, monkeypatch):
    monkeypatch.setattr(isolation.os, "geteuid", lambda: 0)
    assert sandbox_unavailable_reason() == (
        "container isolation refuses to run as root; run package-alert as an unprivileged user")


@pytest.mark.parametrize("index", range(len(credential_dirs())))
def test_container_refuses_each_credential_path(container, index):
    path = credential_dirs()[index]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()
    reason = sandbox_unavailable_reason()
    assert reason is not None and str(path) in reason and "credentials in $HOME" in reason


def test_run_captured_refuses_an_unknown_value_without_running(monkeypatch, tmp_path):
    monkeypatch.setenv(isolation.ENV_VAR, "contianer")
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("a command ran"))
    (tmp_path / "uv.lock").write_text("version = 1\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname="p"\nversion="0"\n')
    with pytest.raises(CapturedRunError, match="unknown PA_SANDBOX_ISOLATION"):
        asyncio.run(SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path))


@pytest.mark.parametrize(("value", "message"), [
    ("container", "pa run is not supported with PA_SANDBOX_ISOLATION=container"),
    ("contianer", "unknown PA_SANDBOX_ISOLATION value 'contianer' (expected bwrap or container)"),
])
def test_pa_run_is_refused(container, monkeypatch, value, message):
    # bwrap reported present, so only run()'s isolation guard can refuse (on a host without bwrap too).
    monkeypatch.setenv(isolation.ENV_VAR, value)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    monkeypatch.setattr(runner_mod, "_build_sandbox_env", lambda *a: pytest.fail("got past the isolation guard"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("a command ran"))
    monkeypatch.setattr(runner_mod.os, "execvp", lambda *a: pytest.fail("exec"))
    console = Console(record=True, width=200)
    assert asyncio.run(SandboxRunner(AppConfig(), console=console).run(["uv", "pip", "install", "x"])) == 1
    assert message in console.export_text()


async def test_verify_reports_the_container_refusal(container, monkeypatch, tmp_path):
    from packagealert.cli.fix_cmd import _verify
    from packagealert.remediate.planner import FixPlan

    monkeypatch.setattr(isolation.os, "geteuid", lambda: 0)
    plan = FixPlan()
    out, reason = await _verify(AppConfig(), object(), tmp_path / "uv.lock", plan, False, frozenset(), Console(),
                                None, None)
    assert out is plan
    assert reason == "container isolation refuses to run as root; run package-alert as an unprivileged user"


def test_captured_runner_gives_none_when_container_is_refused(container, monkeypatch, tmp_path):
    import contextlib

    from packagealert.cli.fix_cmd import _captured_runner
    from packagealert.cli.run_settings import ProjectRunSettings

    monkeypatch.setattr(isolation.os, "geteuid", lambda: 0)
    settings = ProjectRunSettings(None, {}, [], False, False, False, False)
    assert _captured_runner(AppConfig(), object(), tmp_path, settings, Console(), contextlib.nullcontext) == (None, None)


# --- the fresh home ---


def _homes(tmp_path):
    real = (tmp_path / "real").resolve()
    fresh = (tmp_path / "fresh").resolve()
    real.mkdir()
    fresh.mkdir()
    deny = [real / ".ssh", real / ".aws"]
    return real, fresh, deny


def test_allowlisted_entries_are_copied_at_their_relative_paths(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    (real / ".config" / "uv").mkdir(parents=True)
    (real / ".config" / "uv" / "uv.toml").write_text("index-url = 'x'\n")
    (real / ".npmrc").write_text("registry=x\n")
    (real / "notes.txt").write_text("not allowlisted\n")
    isolation.populate_home(fresh, [real / ".config" / "uv", real / ".npmrc"], [],
                            exclude=[], real_home=real, deny=deny)
    assert (fresh / ".config" / "uv" / "uv.toml").read_text() == "index-url = 'x'\n"
    assert (fresh / ".npmrc").read_text() == "registry=x\n"
    assert not (fresh / "notes.txt").exists()


def test_a_stow_style_symlinked_entry_lands_at_its_own_path(tmp_path):
    # bwrap: --ro-bind ~/dotfiles/npmrc ~/.npmrc. The copy must be found where npm looks.
    real, fresh, deny = _homes(tmp_path)
    (real / "dotfiles").mkdir()
    (real / "dotfiles" / "npmrc").write_text("registry=x\n")
    (real / ".npmrc").symlink_to(real / "dotfiles" / "npmrc")
    (real / "dotfiles" / "uv").mkdir()
    (real / "dotfiles" / "uv" / "uv.toml").write_text("native-tls = true\n")
    (real / ".config").mkdir()
    (real / ".config" / "uv").symlink_to(real / "dotfiles" / "uv")
    isolation.populate_home(fresh, [real / ".npmrc", real / ".config" / "uv"], [],
                            exclude=[], real_home=real, deny=deny)
    assert (fresh / ".npmrc").read_text() == "registry=x\n"
    assert not (fresh / ".npmrc").is_symlink()
    assert (fresh / ".config" / "uv" / "uv.toml").read_text() == "native-tls = true\n"
    assert not (fresh / "dotfiles").exists()


def _uv_store(real):
    store = real / ".local" / "share" / "uv" / "credentials"
    store.mkdir(parents=True)
    (store / "credentials.toml").write_text("REAL-TOKEN\n")
    (real / ".local" / "share" / "uv" / "tools").mkdir()
    return store


def test_a_hidden_path_is_left_out(tmp_path):
    # #83: uv's store sits inside the runtime entry ~/.local/share/uv; without the flag it must not appear.
    real, fresh, deny = _homes(tmp_path)
    store = _uv_store(real)
    isolation.populate_home(fresh, [real / ".local" / "share" / "uv"], [], exclude=[], real_home=real,
                            deny=deny, hidden=[store])
    assert (fresh / ".local" / "share" / "uv" / "tools").is_dir()
    assert not (fresh / ".local" / "share" / "uv" / "credentials").exists()


def test_a_hidden_path_is_restored_only_by_its_writable_bind(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    store = _uv_store(real)
    snap = tmp_path / "pa-uv-auth-snap"
    snap.mkdir()
    (snap / "credentials.toml").write_text("SNAPSHOT\n")
    isolation.populate_home(fresh, [real / ".local" / "share" / "uv"], [(snap, store)], exclude=[],
                            real_home=real, deny=deny, hidden=[store])
    assert (fresh / ".local" / "share" / "uv" / "credentials" / "credentials.toml").read_text() == "SNAPSHOT\n"


def test_an_entry_inside_a_hidden_path_is_skipped(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    store = _uv_store(real)
    isolation.populate_home(fresh, [store], [], exclude=[], real_home=real, deny=deny, hidden=[store])
    assert not (fresh / ".local").exists()


def test_the_python_plugin_hides_uvs_credential_dir_and_the_default_one(monkeypatch, tmp_path):
    # The trial's uv may look at the default location when pa's XDG_DATA_HOME differs, so both are hidden.
    from packagealert.languages.python import PythonLanguage

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    default = tmp_path / "home" / ".local" / "share" / "uv" / "credentials"
    monkeypatch.setattr(PythonLanguage, "_uv_credentials_dir", staticmethod(lambda: tmp_path / "creds"))
    assert PythonLanguage().sandbox_hidden_home_paths() == [tmp_path / "creds", default]
    monkeypatch.setattr(PythonLanguage, "_uv_credentials_dir", staticmethod(lambda: default))
    assert PythonLanguage().sandbox_hidden_home_paths() == [default]


def test_a_symlinked_home_still_matches(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    (real / ".npmrc").write_text("registry=x\n")
    alias = tmp_path / "home-link"
    alias.symlink_to(real)
    isolation.populate_home(fresh, [alias / ".npmrc"], [], exclude=[], real_home=real, deny=deny)
    assert (fresh / ".npmrc").read_text() == "registry=x\n"


@pytest.mark.parametrize("target", ["inside", "outside"])
def test_an_entry_under_a_symlinked_parent_lands_at_its_path_as_written(tmp_path, target):
    # bwrap mounts ~/.config/uv at ~/.config/uv even when ~/.config -> ~/dotfiles/config (or out of
    # $HOME): resolving the parent moved the copy to <fresh>/dotfiles/config/uv, where uv never looks.
    real, fresh, deny = _homes(tmp_path)
    config = real / "dotfiles" / "config" if target == "inside" else tmp_path / "xdg-config"
    (config / "uv").mkdir(parents=True)
    (config / "uv" / "uv.toml").write_text("native-tls = true\n")
    (real / ".config").symlink_to(config)
    isolation.populate_home(fresh, [real / ".config" / "uv"], [], exclude=[], real_home=real, deny=deny)
    assert (fresh / ".config" / "uv" / "uv.toml").read_text() == "native-tls = true\n"
    assert not (fresh / ".config").is_symlink()
    assert not (fresh / "dotfiles").exists()


def test_an_entry_under_a_symlinked_parent_of_a_symlinked_home_keeps_its_path(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    (real / "dotfiles" / "config" / "uv").mkdir(parents=True)
    (real / "dotfiles" / "config" / "uv" / "uv.toml").write_text("x\n")
    (real / ".config").symlink_to(real / "dotfiles" / "config")
    alias = tmp_path / "home-link"
    alias.symlink_to(real)
    isolation.populate_home(fresh, [alias / ".config" / "uv"], [], exclude=[], real_home=real, deny=deny)
    assert (fresh / ".config" / "uv" / "uv.toml").read_text() == "x\n"


def test_a_writable_bind_under_a_symlinked_parent_lands_at_dest_as_written(tmp_path):
    # `uv auth dir` names the store through ~/.local even when ~/.local is a symlink.
    real, fresh, deny = _homes(tmp_path)
    (real / "dotfiles" / "local").mkdir(parents=True)
    (real / ".local").symlink_to(real / "dotfiles" / "local")
    src = tmp_path / "pa-uv-auth-snap"
    src.mkdir()
    (src / "credentials.toml").write_text("token\n")
    dest = real / ".local" / "share" / "uv" / "credentials"
    isolation.populate_home(fresh, [], [(src, dest)], exclude=[], real_home=real, deny=deny)
    assert (fresh / ".local" / "share" / "uv" / "credentials" / "credentials.toml").read_text() == "token\n"
    assert not (fresh / "dotfiles").exists()


@pytest.mark.parametrize("path", ["relative/.npmrc", "{real}/../real/.npmrc", "{real}"])
def test_rebase_rejects_relative_dotdot_and_home_itself(tmp_path, path):
    real, fresh, _ = _homes(tmp_path)
    assert isolation.rebase(Path(path.format(real=real)), real, fresh) is None


def test_writes_to_a_copy_leave_the_original_unchanged(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    (real / ".npmrc").write_text("registry=x\n")
    isolation.populate_home(fresh, [real / ".npmrc"], [], exclude=[], real_home=real, deny=deny)
    (fresh / ".npmrc").write_text("changed\n")
    assert (real / ".npmrc").read_text() == "registry=x\n"
    assert not (fresh / ".npmrc").is_symlink()


def test_a_link_into_a_credential_dir_is_skipped(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    (real / ".ssh").mkdir()
    (real / ".ssh" / "id_rsa").write_text("KEY")
    (real / ".config" / "pip").mkdir(parents=True)
    (real / ".config" / "pip" / "key").symlink_to(real / ".ssh" / "id_rsa")
    (real / ".config" / "pip" / "pip.conf").write_text("[global]\n")
    isolation.populate_home(fresh, [real / ".config" / "pip"], [], exclude=[], real_home=real, deny=deny)
    assert (fresh / ".config" / "pip" / "pip.conf").exists()
    assert not (fresh / ".config" / "pip" / "key").exists()


def test_an_entry_inside_a_credential_dir_is_refused(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    (real / ".ssh").mkdir()
    with pytest.raises(isolation.IsolationRefused, match="credential"):
        isolation.populate_home(fresh, [real / ".ssh"], [], exclude=[], real_home=real, deny=deny)


def test_cwd_and_project_entries_are_not_copied(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    project = real / "work" / "proj"
    project.mkdir(parents=True)
    (project / "uv.lock").write_text("x")
    isolation.populate_home(fresh, [project, real / "work"], [], exclude=[project], real_home=real, deny=deny)
    assert not (fresh / "work").exists()


def test_entries_outside_home_are_not_copied(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    outside = tmp_path / "opt"
    outside.mkdir()
    (outside / "tool").write_text("x")
    isolation.populate_home(fresh, [outside], [], exclude=[], real_home=real, deny=deny)
    assert list(fresh.iterdir()) == []


def test_symlink_loop_and_fifo_are_skipped(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    cfg = real / ".config" / "tool"
    cfg.mkdir(parents=True)
    (cfg / "loop").symlink_to(cfg)
    os.mkfifo(cfg / "pipe")
    (cfg / "ok").write_text("1")
    isolation.populate_home(fresh, [cfg], [], exclude=[], real_home=real, deny=deny)
    assert (fresh / ".config" / "tool" / "ok").read_text() == "1"
    assert not (fresh / ".config" / "tool" / "pipe").exists()


def test_a_symlinked_alias_of_a_sibling_is_copied_at_both_paths(tmp_path):
    # Not a loop: bwrap shows tool/a and tool/b, and configuration may name either.
    real, fresh, deny = _homes(tmp_path)
    tool = real / ".config" / "tool"
    (tool / "a").mkdir(parents=True)
    (tool / "a" / "settings.toml").write_text("x = 1\n")
    (tool / "b").symlink_to(tool / "a")
    (tool / "c").symlink_to("a")  # relative, too
    isolation.populate_home(fresh, [tool], [], exclude=[], real_home=real, deny=deny)
    for name in ("a", "b", "c"):
        assert (fresh / ".config" / "tool" / name / "settings.toml").read_text() == "x = 1\n"


def test_a_link_to_an_ancestor_is_still_a_loop(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    tool = real / ".config" / "tool"
    (tool / "sub").mkdir(parents=True)
    (tool / "sub" / "f").write_text("1")
    (tool / "sub" / "up").symlink_to(tool)
    isolation.populate_home(fresh, [tool], [], exclude=[], real_home=real, deny=deny)
    assert (fresh / ".config" / "tool" / "sub" / "f").read_text() == "1"
    assert not (fresh / ".config" / "tool" / "sub" / "up").exists()


def test_alias_fan_out_is_bounded_by_the_entry_limit(tmp_path, monkeypatch):
    # Each level links twice to the next: 2**depth paths with no bytes to count.
    real, fresh, deny = _homes(tmp_path)
    root = real / ".config" / "tool"
    levels = [root / f"l{i}" for i in range(12)]
    for d in levels:
        d.mkdir(parents=True)
    for here, nxt in itertools.pairwise(levels):
        (here / "x").symlink_to(nxt)
        (here / "y").symlink_to(nxt)
    monkeypatch.setattr(isolation, "HOME_COPY_ENTRIES", 1000)
    with pytest.raises(isolation.IsolationRefused, match="too large to copy"):
        isolation.populate_home(fresh, [levels[0]], [], exclude=[], real_home=real, deny=deny)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write a read-only file")
@pytest.mark.parametrize("overlap", ["repeated", "ancestor"])
def test_overlapping_entries_copy_a_read_only_file_twice(tmp_path, overlap):
    # sandbox.extra_ro_paths may repeat an allowlisted file or name its ancestor; copy2 keeps a
    # 0400 mode, so the second copy must replace the first rather than open it for writing.
    real, fresh, deny = _homes(tmp_path)
    (real / ".config" / "tool").mkdir(parents=True)
    auth = real / ".config" / "tool" / "auth.toml"
    auth.write_text("token\n")
    auth.chmod(0o400)
    entries = [auth, auth] if overlap == "repeated" else [real / ".config", real / ".config" / "tool"]
    try:
        isolation.populate_home(fresh, entries, [], exclude=[], real_home=real, deny=deny)
        copied = fresh / ".config" / "tool" / "auth.toml"
        assert copied.read_text() == "token\n"
        assert copied.stat().st_mode & 0o777 == 0o400
    finally:
        for p in (auth, fresh / ".config" / "tool" / "auth.toml"):
            if p.exists():
                p.chmod(0o600)


def test_the_copy_limit_refuses(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    big = real / ".local" / "share" / "uv"
    big.mkdir(parents=True)
    (big / "python.tar").write_bytes(b"x" * 2048)
    with pytest.raises(isolation.IsolationRefused, match="too large to copy"):
        isolation.populate_home(fresh, [big], [], exclude=[], real_home=real, deny=deny, limit=1024)


def test_a_writable_bind_lands_at_dest_rebased(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    src = tmp_path / "pa-uv-auth-snap"
    src.mkdir()
    (src / "credentials.toml").write_text("token\n")
    dest = real / ".local" / "share" / "uv" / "credentials"
    dest.mkdir(parents=True)
    (dest / "credentials.toml").write_text("original\n")
    isolation.populate_home(fresh, [], [(src, dest)], exclude=[], real_home=real, deny=deny)
    copied = fresh / ".local" / "share" / "uv" / "credentials" / "credentials.toml"
    assert copied.read_text() == "token\n"
    copied.write_text("changed\n")
    assert (src / "credentials.toml").read_text() == "token\n"
    assert (dest / "credentials.toml").read_text() == "original\n"


def test_a_writable_bind_hides_what_a_home_entry_put_at_its_destination(tmp_path):
    # bwrap's bind replaces the directory: a file the snapshot omits must not show through.
    real, fresh, deny = _homes(tmp_path)
    tool = real / ".config" / "tool"
    tool.mkdir(parents=True)
    (tool / "auth.json").write_text("original-secret")
    (tool / "settings.toml").write_text("from home")
    src = tmp_path / "pa-snap"
    src.mkdir()
    (src / "settings.toml").write_text("from snapshot")
    isolation.populate_home(fresh, [real / ".config"], [(src, tool)], exclude=[], real_home=real, deny=deny)
    copied = fresh / ".config" / "tool"
    assert sorted(p.name for p in copied.iterdir()) == ["settings.toml"]
    assert (copied / "settings.toml").read_text() == "from snapshot"


def test_a_later_overlapping_bind_hides_an_earlier_one(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    outer_src, inner_src = tmp_path / "pa-outer", tmp_path / "pa-inner"
    (outer_src / "inner").mkdir(parents=True)
    (outer_src / "inner" / "stale").write_text("x")
    (outer_src / "kept").write_text("y")
    inner_src.mkdir()
    (inner_src / "fresh").write_text("z")
    dest = real / ".local" / "share" / "tool"
    isolation.populate_home(fresh, [], [(outer_src, dest), (inner_src, dest / "inner")],
                            exclude=[], real_home=real, deny=deny)
    target = fresh / ".local" / "share" / "tool"
    assert (target / "kept").read_text() == "y"
    assert sorted(p.name for p in (target / "inner").iterdir()) == ["fresh"]


def test_a_writable_bind_replaces_a_file_at_its_destination(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    (real / ".toolrc").write_text("a file where the bind goes")
    src = tmp_path / "pa-snap"
    src.mkdir()
    (src / "f").write_text("1")
    isolation.populate_home(fresh, [real / ".toolrc"], [(src, real / ".toolrc")], exclude=[], real_home=real,
                            deny=deny)
    assert (fresh / ".toolrc" / "f").read_text() == "1"


def test_a_writable_bind_outside_home_is_refused(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    src = tmp_path / "pa-snap"
    src.mkdir()
    with pytest.raises(isolation.IsolationRefused, match="outside"):
        isolation.populate_home(fresh, [], [(src, tmp_path / "elsewhere")], exclude=[], real_home=real, deny=deny)


# --- the environment ---


def test_env_is_kept_and_home_redirected(tmp_path):
    real, fresh, _ = _homes(tmp_path)
    env = {"PATH": "/usr/bin", "HOME": str(real), "LANG": "C.UTF-8"}
    out = isolation.container_env(env, real, fresh)
    assert out["PATH"] == "/usr/bin" and out["LANG"] == "C.UTF-8"
    assert out["HOME"] == str(fresh)
    assert out["XDG_CONFIG_HOME"] == str(fresh / ".config")
    assert out["XDG_CACHE_HOME"] == str(fresh / ".cache")
    assert out["XDG_DATA_HOME"] == str(fresh / ".local" / "share")


def test_xdg_under_home_is_rebased(tmp_path):
    real, fresh, _ = _homes(tmp_path)
    out = isolation.container_env({"XDG_DATA_HOME": str(real / "xdg")}, real, fresh)
    assert out["XDG_DATA_HOME"] == str(fresh / "xdg")


def test_xdg_under_a_symlinked_parent_is_rebased_as_written(tmp_path):
    # Must agree with where populate_home put the entries and binds under that same directory.
    real, fresh, _ = _homes(tmp_path)
    (real / "dotfiles" / "local").mkdir(parents=True)
    (real / ".local").symlink_to(real / "dotfiles" / "local")
    out = isolation.container_env({"XDG_DATA_HOME": str(real / ".local" / "share")}, real, fresh)
    assert out["XDG_DATA_HOME"] == str(fresh / ".local" / "share")


@pytest.mark.parametrize("value", ["relative/xdg", "/opt/xdg", ""])
def test_xdg_outside_home_or_relative_gets_the_default(tmp_path, value):
    real, fresh, _ = _homes(tmp_path)
    out = isolation.container_env({"XDG_DATA_HOME": value}, real, fresh)
    assert out["XDG_DATA_HOME"] == str(fresh / ".local" / "share")


@pytest.mark.parametrize("key", ["", "A=B"])
def test_a_bad_env_name_is_refused(tmp_path, key):
    real, fresh, _ = _homes(tmp_path)
    with pytest.raises(isolation.IsolationRefused, match="not a valid"):
        isolation.container_env({key: "v"}, real, fresh)


# --- execution ---


def _gone(pid: int, within: float = 5.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def test_execute_passes_exactly_the_env(tmp_path):
    env = {"PATH": os.environ["PATH"], "ONLY": "this"}
    res = isolation._execute([sys.executable, "-c", "import os,json;print(json.dumps(dict(os.environ)))"],
                             env, tmp_path, 30)
    seen = json.loads(res.stdout)
    seen.pop("LC_CTYPE", None)  # Python may set it on start-up
    assert seen == env and res.returncode == 0 and not res.timed_out


def test_timeout_kills_the_whole_process_group(tmp_path):
    pidfile = tmp_path / "pid"
    script = f"sleep 300 & echo $! > {pidfile}; wait"
    res = isolation._execute(["/bin/sh", "-c", script], {"PATH": os.environ["PATH"]}, tmp_path, 1)
    assert res == isolation.ContainerResult(-1, "", "", timed_out=True)
    assert _gone(int(pidfile.read_text()))


def test_a_grandchild_left_behind_is_killed_after_a_normal_exit(tmp_path):
    pidfile = tmp_path / "pid"
    # The shell exits at once, leaving its background sleep in the same process group.
    script = f"sleep 300 >/dev/null 2>&1 & echo $! > {pidfile}"
    res = isolation._execute(["/bin/sh", "-c", script], {"PATH": os.environ["PATH"]}, tmp_path, 30)
    assert res.returncode == 0
    assert _gone(int(pidfile.read_text()))


def test_a_background_child_holding_the_pipe_does_not_turn_success_into_a_timeout(tmp_path):
    # communicate() waits for EOF, not for the command: the leftover group member is killed.
    pidfile = tmp_path / "child"
    start = time.monotonic()
    res = isolation._execute(["/bin/sh", "-c", f"sleep 30 & echo $! > {pidfile}; printf done"],
                             {"PATH": os.environ["PATH"]}, tmp_path, 5)
    assert time.monotonic() - start < 2
    assert (res.returncode, res.stdout, res.timed_out) == (0, "done", False)
    assert _gone(int(pidfile.read_text()), 1.0)


def test_a_failing_command_keeps_its_status_and_output_with_a_child_left_behind(tmp_path):
    res = isolation._execute(["/bin/sh", "-c", "sleep 30 & echo oops >&2; exit 3"],
                             {"PATH": os.environ["PATH"]}, tmp_path, 5)
    assert (res.returncode, res.stderr, res.timed_out) == (3, "oops\n", False)


def test_a_grandchild_holding_the_pipe_cannot_hang_the_run(tmp_path):
    # setsid escapes the process group and keeps stdout open; the run still ends at the timeout.
    start = time.monotonic()
    res = isolation._execute(["/bin/sh", "-c", "setsid sleep 30 & echo started"], {"PATH": os.environ["PATH"]},
                             tmp_path, 2)
    assert time.monotonic() - start < 10
    assert res.timed_out


def _container_call(tmp_path, **over):
    kw: dict[str, Any] = {"env": {"PATH": os.environ["PATH"]}, "home_ro_dirs": [], "extra_tmpfs": [],
                          "writable_binds": [], "allow_network": True, "cwd": tmp_path, "timeout": 30,
                          "exclude": [tmp_path]}
    kw.update(over)
    return kw


def _symlinked_uv_store(home, shape):
    """A uv credential store reached through a symlink; returns (as uv names it, the real dir)."""
    named = home / ".local" / "share" / "uv" / "credentials"
    if shape == "parent":  # ~/.local -> ~/dotfiles/local
        real = home / "dotfiles" / "local" / "share" / "uv" / "credentials"
        real.mkdir(parents=True)
        (home / ".local").symlink_to(home / "dotfiles" / "local")
    else:  # the credential directory itself: ~/.local/share/uv/credentials -> ~/.auth/uv
        real = home / ".auth" / "uv"
        real.mkdir(parents=True)
        named.parent.mkdir(parents=True)
        named.symlink_to(real)
    (real / "credentials.toml").write_text("TOKEN\n")
    return named, real


@pytest.mark.parametrize("shape", ["parent", "itself"])
def test_uv_auth_reaches_the_trial_through_a_symlinked_store(container, monkeypatch, tmp_path, shape):
    # The real hook binds the resolved dir (bwrap cannot mount on a symlink); the trial must still
    # find the snapshot where uv names the store, though the hidden-path filter drops the original.
    from packagealert.languages.base import SandboxTargets
    from packagealert.languages.python import PythonLanguage

    home = container
    named, real = _symlinked_uv_store(home, shape)
    monkeypatch.setattr(PythonLanguage, "_uv_credentials_dir", staticmethod(lambda: named))
    snaps = tmp_path / "snaps"
    snaps.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(snaps))

    binds = PythonLanguage().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), SandboxTargets())
    assert [dest for _src, dest in binds] == [real.resolve()]
    # The snapshot must be told apart from a copy of the real store, which has the same contents.
    (binds[0][0] / "credentials.toml").write_text("SNAPSHOT\n")
    script = ("import os; p = os.path.join(os.environ['HOME'], '.local/share/uv/credentials/credentials.toml');"
              "print(open(p).read() if os.path.exists(p) else 'MISSING')")
    res = isolation.run_container([sys.executable, "-c", script], [], **_container_call(
        tmp_path, writable_binds=binds, home_ro_dirs=[home / ".local" / "share" / "uv"]))
    assert res.stdout.strip() == "SNAPSHOT"


def test_hidden_paths_do_not_depend_on_the_registry_being_loaded(monkeypatch):
    # Called before anything loaded the registry, it must still hide uv's store, not return [].
    from packagealert.languages import registry as lang_registry

    monkeypatch.setattr(lang_registry, "_registry", {})
    monkeypatch.setattr(lang_registry, "_loaded", False)
    assert isolation._hidden_home_paths()


def test_a_bind_is_placed_at_a_hidden_name_only_when_it_resolves_to_dest(tmp_path):
    real, fresh, deny = _homes(tmp_path)
    src = tmp_path / "pa-snap"
    src.mkdir()
    (src / "f").write_text("1")
    dest = real / ".auth" / "uv"
    dest.mkdir(parents=True)
    unrelated = real / ".local" / "share" / "other" / "credentials"
    isolation.populate_home(fresh, [], [(src, dest)], exclude=[], real_home=real, deny=deny, hidden=[unrelated])
    assert (fresh / ".auth" / "uv" / "f").read_text() == "1"
    assert not (fresh / ".local").exists()


def test_run_container_refuses_no_network(container, tmp_path):
    with pytest.raises(isolation.IsolationRefused, match="cannot disable the network"):
        isolation.run_container(["/bin/true"], [], **_container_call(tmp_path, allow_network=False))


def test_run_container_refuses_extra_tmpfs(container, tmp_path):
    with pytest.raises(isolation.IsolationRefused, match="cannot hide paths"):
        isolation.run_container(["/bin/true"], [], **_container_call(tmp_path, extra_tmpfs=[tmp_path]))


def test_run_container_rechecks_the_preconditions(container, monkeypatch, tmp_path):
    monkeypatch.setattr(isolation.os, "geteuid", lambda: 0)
    with pytest.raises(isolation.IsolationRefused, match="as root"):
        isolation.run_container(["/bin/true"], [], **_container_call(tmp_path))


def test_run_container_sees_the_fresh_home_and_removes_it(container, tmp_path):
    res = isolation.run_container([sys.executable, "-c", "import os;print(os.environ['HOME'])"], [],
                                  **_container_call(tmp_path))
    fresh = Path(res.stdout.strip())
    assert fresh.name.startswith("pa-home-") and fresh != container
    assert not fresh.exists()


def test_run_container_removes_the_home_after_a_timeout(container, monkeypatch, tmp_path):
    seen = {}

    def spy(argv, env, cwd, timeout, **_kw):
        seen["home"] = Path(env["HOME"])
        assert seen["home"].is_dir()
        return isolation.ContainerResult(-1, "", "", timed_out=True)

    monkeypatch.setattr(isolation, "_execute", spy)
    assert isolation.run_container(["/bin/true"], [], **_container_call(tmp_path)).timed_out
    assert not seen["home"].exists()


def test_run_container_removes_the_home_after_a_failure(container, monkeypatch, tmp_path):
    seen = {}

    def boom(argv, env, cwd, timeout, **_kw):
        seen["home"] = Path(env["HOME"])
        raise OSError("no such file")

    monkeypatch.setattr(isolation, "_execute", boom)
    with pytest.raises(OSError):
        isolation.run_container(["/bin/true"], [], **_container_call(tmp_path))
    assert not seen["home"].exists()


def test_run_container_hides_uvs_store_without_the_flag(container, monkeypatch, tmp_path):
    store = container / ".local" / "share" / "uv" / "credentials"
    store.mkdir(parents=True)
    (store / "credentials.toml").write_text("REAL-TOKEN\n")
    monkeypatch.setattr(isolation, "_hidden_home_paths", lambda: [store])
    seen = {}

    def spy(argv, env, cwd, timeout, **_kw):
        home = Path(env["HOME"])
        seen["store"] = (home / ".local" / "share" / "uv" / "credentials").exists()
        seen["uv"] = (home / ".local" / "share" / "uv").is_dir()
        return isolation.ContainerResult(0, "", "")

    monkeypatch.setattr(isolation, "_execute", spy)
    isolation.run_container(["/bin/true"], [], **_container_call(
        tmp_path, home_ro_dirs=[container / ".local" / "share" / "uv"], exclude=[tmp_path / "work"]))
    assert seen == {"store": False, "uv": True}


def test_a_plugin_without_the_hook_hides_nothing(monkeypatch):
    from packagealert.languages import registry

    class Plain:
        name = "plain"

    monkeypatch.setattr(registry, "all_languages", lambda: [Plain()])
    assert isolation._hidden_home_paths() == []


def _plugin(result):
    class Plugin:
        name = "plug"

        def sandbox_hidden_home_paths(self):
            if isinstance(result, BaseException):
                raise result
            return result() if callable(result) else result

    return Plugin()


@pytest.mark.parametrize("result", [
    pytest.param(lambda: (Path("/h/a"), Path("/h/b")), id="tuple"),
    pytest.param(lambda: (p for p in (Path("/h/a"), Path("/h/b"))), id="generator"),
    pytest.param(lambda: ["/h/a", Path("/h/b")], id="str-items"),
    pytest.param(lambda: {Path("/h/a"): 1, Path("/h/b"): 2}.keys(), id="keys-view"),
])
def test_any_iterable_of_paths_or_strs_is_hidden(monkeypatch, result):
    from packagealert.languages import registry

    monkeypatch.setattr(registry, "all_languages", lambda: [_plugin(result)])
    assert isolation._hidden_home_paths() == [Path("/h/a"), Path("/h/b")]


@pytest.mark.parametrize("result", [
    pytest.param(RuntimeError("plugin bug"), id="raises"),
    pytest.param(None, id="none"),
    pytest.param(Path("/h/a"), id="bare-path"),
    pytest.param("/h/a", id="bare-str"),
    pytest.param(lambda: [Path("/h/a"), 3], id="non-path-item"),
    pytest.param(lambda: [Path("/h/a"), None], id="none-item"),
    pytest.param(lambda: [b"/h/a"], id="bytes-item"),
])
def test_a_failing_hidden_hook_refuses(monkeypatch, result):
    # The hook's job is hiding credentials: a broken one must refuse the trial, never hide nothing.
    from packagealert.languages import registry

    monkeypatch.setattr(registry, "all_languages", lambda: [_plugin(result)])
    with pytest.raises(isolation.IsolationRefused, match="plug"):
        isolation._hidden_home_paths()


async def test_a_failing_hidden_hook_refuses_the_trial(container, monkeypatch, tmp_path):
    from packagealert.languages import registry

    _project(tmp_path)
    seen = _container_env(monkeypatch)
    real = registry.all_languages
    monkeypatch.setattr(registry, "all_languages", lambda: [*real(), _plugin(RuntimeError("plugin bug"))])
    with pytest.raises(CapturedRunError, match="plug"):
        await SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path)
    assert seen == {}


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
async def test_a_home_copy_error_is_a_preparation_refusal(container, monkeypatch, tmp_path):
    # Only a failure to start the process may say "could not start the command".
    cfg = container / ".config" / "tool"
    cfg.mkdir(parents=True)
    secret = cfg / "unreadable"
    secret.write_text("x")
    secret.chmod(0)
    monkeypatch.setattr(isolation, "_execute", lambda *a, **k: pytest.fail("the command ran"))
    try:
        with pytest.raises(isolation.IsolationRefused, match="could not prepare the fresh home: .*unreadable"):
            isolation.run_container(["/bin/true"], [], **_container_call(
                tmp_path, home_ro_dirs=[cfg], exclude=[tmp_path / "work"]))
        _project(tmp_path / "proj")
        runner = SandboxRunner(AppConfig())
        monkeypatch.setattr(runner, "_assemble_sandbox", _with_home_ro(runner._assemble_sandbox, cfg))
        with pytest.raises(CapturedRunError, match="^could not prepare the fresh home"):
            await runner.run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path / "proj")
    finally:
        secret.chmod(0o600)


def _with_home_ro(assemble, entry):
    def wrapped(*a, **k):
        asm = assemble(*a, **k)
        asm.home_ro.append(entry)
        return asm
    return wrapped


def test_run_container_removes_a_home_the_trial_left_unreadable(container, tmp_path):
    # rmtree reported the locked directory as a failed os.open; retrying that as a one-argument
    # call raised TypeError from run_container's finally, losing the result and the home's removal.
    script = ("import os; h = os.environ['HOME']; os.makedirs(h + '/a/locked/inner');"
              "open(h + '/a/locked/inner/creds', 'w').write('x'); os.chmod(h + '/a/locked', 0); print(h)")
    res = isolation.run_container([sys.executable, "-c", script], [], **_container_call(tmp_path))
    assert res.returncode == 0
    fresh = Path(res.stdout.strip())
    assert fresh.name.startswith("pa-home-")
    assert not fresh.exists()


def test_run_container_creates_write_dirs(container, tmp_path):
    target = tmp_path / "made" / "here"
    isolation.run_container(["/bin/true"], [target], **_container_call(tmp_path))
    assert target.is_dir()


# --- parity through run_captured ---


def _project(tmp_path):
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "uv.lock").write_text("version = 1\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname="p"\nversion="0"\n')


def _bwrap_env(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        if cmd[0] == "bwrap":  # not the plugin hooks' own subprocess calls (uv auth dir)
            seen["env"] = {cmd[i + 1]: cmd[i + 2] for i, a in enumerate(cmd) if a == "--setenv"}
        empty = "" if kw.get("text") or kw.get("universal_newlines") else b""  # check_output() wants bytes
        return subprocess.CompletedProcess(cmd, 0, stdout=empty, stderr=empty)

    monkeypatch.delenv(isolation.ENV_VAR, raising=False)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    monkeypatch.setattr(subprocess, "run", fake_run)
    return seen


def _container_env(monkeypatch):
    seen = {}

    def spy(argv, env, cwd, timeout, **_kw):
        seen["env"], seen["argv"], seen["cwd"] = dict(env), argv, cwd
        return isolation.ContainerResult(0, "", "")

    monkeypatch.setattr(isolation, "_execute", spy)
    return seen


_REDIRECTED = {"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"}


async def test_child_env_is_the_same_under_both_isolations(container, monkeypatch, tmp_path):
    _project(tmp_path)
    monkeypatch.setenv("LANG", "C.UTF-8")
    bw = _bwrap_env(monkeypatch)
    await SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path)
    monkeypatch.setenv(isolation.ENV_VAR, isolation.CONTAINER)
    ct = _container_env(monkeypatch)
    out = await SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path)
    assert out == runner_mod.CapturedRun(0, "", "", False)
    strip = lambda e: {k: v for k, v in e.items() if k not in _REDIRECTED}
    assert strip(ct["env"]) == strip(bw["env"])
    assert Path(ct["env"]["HOME"]).name.startswith("pa-home-")
    assert ct["cwd"] == tmp_path


@pytest.mark.parametrize("mode", [isolation.BWRAP, isolation.CONTAINER])
async def test_an_unapproved_argv_is_refused_in_both(container, monkeypatch, tmp_path, mode):
    _project(tmp_path)
    _bwrap_env(monkeypatch) if mode == isolation.BWRAP else _container_env(monkeypatch)
    if mode == isolation.CONTAINER:
        monkeypatch.setenv(isolation.ENV_VAR, isolation.CONTAINER)
    with pytest.raises(CapturedRunError, match="not an approved"):
        await SandboxRunner(AppConfig()).run_captured(["uv", "--version"], cwd=tmp_path)


@pytest.mark.parametrize("mode", [isolation.BWRAP, isolation.CONTAINER])
async def test_a_scratch_cwd_outside_the_scratch_root_is_refused_in_both(container, monkeypatch, tmp_path, mode):
    _project(tmp_path)
    monkeypatch.setattr(runner_mod, "SCRATCH_ROOT", tmp_path / "scratch-root")
    (tmp_path / "scratch-root").mkdir()
    _bwrap_env(monkeypatch) if mode == isolation.BWRAP else _container_env(monkeypatch)
    if mode == isolation.CONTAINER:
        monkeypatch.setenv(isolation.ENV_VAR, isolation.CONTAINER)
    with pytest.raises(CapturedRunError, match="not a scratch directory"):
        await SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path, scratch=True)


@pytest.mark.parametrize("mode", [isolation.BWRAP, isolation.CONTAINER])
async def test_pre_run_checks_run_in_both(container, monkeypatch, tmp_path, mode):
    _project(tmp_path)
    _bwrap_env(monkeypatch) if mode == isolation.BWRAP else _container_env(monkeypatch)
    if mode == isolation.CONTAINER:
        monkeypatch.setenv(isolation.ENV_VAR, isolation.CONTAINER)
    runner = SandboxRunner(AppConfig())
    calls = []
    monkeypatch.setattr(runner, "authorize_captured", lambda argv, **kw: calls.append((argv, kw["flags"])) or True)
    await runner.run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path, flags={"python": frozenset()})
    assert calls == [(["uv", "lock", "--dry-run"], {"python": frozenset()})]


def _group_gone(pgid: int, within: float) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.02)
    return False


@pytest.mark.timeout(60)
async def test_cancelling_a_container_run_kills_its_process_group(container, monkeypatch, tmp_path):
    # Ctrl-C under asyncio.run cancels the awaiting task; the trial (in its own session, so the
    # terminal's SIGINT never reaches it) must die with it, and the call must return at once.
    _project(tmp_path)
    leader, child = tmp_path / "leader", tmp_path / "child"
    real_execute = isolation._execute
    seen = {}

    def long_sleep(argv, env, cwd, timeout, **kw):
        seen["home"] = Path(env["HOME"])
        script = f"echo $$ > {leader}; sleep 300 & echo $! > {child}; wait"
        return real_execute(["/bin/sh", "-c", script], {"PATH": os.environ["PATH"]}, cwd, timeout, **kw)

    monkeypatch.setattr(isolation, "_execute", long_sleep)
    # A bounded timeout, so a regression ends in seconds instead of hanging the suite.
    task = asyncio.create_task(SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path,
                                                                       timeout=8))
    deadline = time.monotonic() + 10
    while not (child.exists() and child.read_text().strip()) and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    pgid, sleeper = int(leader.read_text()), int(child.read_text())
    try:
        start = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=15)
        elapsed = time.monotonic() - start
        assert elapsed < 2, f"run_captured took {elapsed:.1f}s to return after cancellation"
        # Cleaned up before the cancellation propagates, not later in a leftover thread.
        assert not seen["home"].exists()
        # Polled only so init can reap the orphaned sleep (a zombie still counts as a group member).
        assert _group_gone(pgid, 1.0), "the trial's process group outlived the cancellation"
        assert _gone(sleeper, 0.5)
    finally:
        isolation._kill_group(pgid)


def test_execute_starts_nothing_once_cancelled(tmp_path):
    marker = tmp_path / "ran"
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(isolation.Cancelled):
        isolation._execute(["/bin/sh", "-c", f"touch {marker}"], {"PATH": os.environ["PATH"]}, tmp_path, 10,
                           cancel=cancel)
    assert not marker.exists()


def test_run_container_cancelled_before_it_starts_copies_and_runs_nothing(container, monkeypatch, tmp_path):
    marker = tmp_path / "ran"
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(isolation, "populate_home", lambda *a, **kw: pytest.fail("copied a home after cancellation"))
    with pytest.raises(isolation.Cancelled):
        isolation.run_container(["/bin/sh", "-c", f"touch {marker}"], [], **_container_call(tmp_path), cancel=cancel)
    assert not marker.exists()


def test_run_container_cancelled_while_preparing_the_home_starts_nothing(container, monkeypatch, tmp_path):
    marker = tmp_path / "ran"
    cancel = threading.Event()
    real_populate = isolation.populate_home
    seen = {}

    def populate_then_cancel(fresh, *a, **kw):
        seen["home"] = fresh
        real_populate(fresh, *a, **kw)
        cancel.set()  # Ctrl-C lands while the (up to 64 MiB) home copy is still running

    monkeypatch.setattr(isolation, "populate_home", populate_then_cancel)
    with pytest.raises(isolation.Cancelled):
        isolation.run_container(["/bin/sh", "-c", f"touch {marker}"], [], **_container_call(tmp_path), cancel=cancel)
    assert not marker.exists()
    assert not seen["home"].exists()


@pytest.mark.timeout(60)
async def test_a_trial_cancelled_during_home_preparation_never_runs(container, monkeypatch, tmp_path):
    # run_captured gives up after a grace period; the worker must not then start the build code.
    _project(tmp_path)
    marker = tmp_path / "ran"
    entered, release = threading.Event(), threading.Event()
    real_populate = isolation.populate_home

    def slow_populate(*a, **kw):
        entered.set()
        release.wait(10)  # a long home copy, still going when the task is cancelled
        real_populate(*a, **kw)

    real_execute = isolation._execute

    def run_marker(argv, env, cwd, timeout, **kw):
        return real_execute(["/bin/sh", "-c", f"touch {marker}"], {"PATH": os.environ["PATH"]}, cwd, timeout, **kw)

    monkeypatch.setattr(isolation, "populate_home", slow_populate)
    monkeypatch.setattr(isolation, "_execute", run_marker)
    monkeypatch.setattr("packagealert.sandbox.runner._CANCEL_GRACE", 0.1)
    task = asyncio.create_task(SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path,
                                                                       timeout=8))
    while not entered.is_set():
        await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=15)
    release.set()  # the worker outlived the grace period; let its home copy finish
    await asyncio.sleep(1.0)
    assert not marker.exists(), "the trial started after run_captured had been cancelled"


@pytest.mark.parametrize("mode", [isolation.BWRAP, isolation.CONTAINER])
async def test_run_captured_removes_a_kept_rejected_ancestor_after_the_run(container, monkeypatch, tmp_path, mode):
    # Through the real caller: the deferred snapshot reaches run_captured's final cleanup, which
    # holds only if the WritableBinds object is passed along uncopied (a copy loses .deferred).
    from packagealert.languages.python import PythonLanguage
    from packagealert.sandbox import runner as sandbox_runner

    project = tmp_path / "proj"
    _project(project)
    snaps = tmp_path / "tmp"
    snaps.mkdir()
    monkeypatch.setattr(sandbox_runner.tempfile, "gettempdir", lambda: str(snaps))
    outer = snaps / "pa-outer"
    inner = outer / "pa-inner"
    inner.mkdir(parents=True)
    (outer / "credentials.toml").write_text("secret")
    dest = container / ".local" / "share" / "tool"
    dest.mkdir(parents=True)
    monkeypatch.setattr(PythonLanguage, "configure_sandbox_writable",
                        lambda self, *a: [(inner, dest), (outer, tmp_path / "outside-home")])
    during = {}
    if mode == isolation.BWRAP:
        _bwrap_env(monkeypatch)
        fake_run = subprocess.run

        def run(cmd, **kw):
            if cmd[0] == "bwrap":
                during["outer"] = outer.exists()
                during["bound"] = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--bind" and cmd[i + 2] == str(dest)]
            return fake_run(cmd, **kw)

        monkeypatch.setattr(subprocess, "run", run)
    else:
        def spy(argv, env, cwd, timeout, **kw):
            during["outer"] = outer.exists()
            return isolation.ContainerResult(0, "", "")

        monkeypatch.setattr(isolation, "_execute", spy)
    await SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=project)
    assert during["outer"] is True  # kept while the trial ran, so the inner pair was accepted
    if mode == isolation.BWRAP:
        assert during["bound"] == [str(inner)]  # the ancestor itself is never mounted
    assert not outer.exists()


async def test_container_refusal_becomes_a_captured_run_error(container, monkeypatch, tmp_path):
    _project(tmp_path)
    _container_env(monkeypatch)
    with pytest.raises(CapturedRunError, match="cannot disable the network"):
        await SandboxRunner(AppConfig()).run_captured(["uv", "lock", "--dry-run"], cwd=tmp_path, allow_network=False)


# --- pa fix --apply sync ---


def _invoke_fix(args, monkeypatch):
    from unittest.mock import patch

    from typer.testing import CliRunner

    from packagealert.cli.app import app

    seen = {}

    async def fake_run_fix(cfg, root, **kw):
        seen.update(kw)
        return 0

    with patch("packagealert.cli.fix_cmd._run_fix", fake_run_fix):
        res = CliRunner().invoke(app, ["fix", *args])
    return res, seen


_SYNC_REFUSAL = "pa fix --apply under PA_SANDBOX_ISOLATION=container needs --lock-only (installing is not supported)"


def test_apply_sync_is_refused_before_planning(container, monkeypatch, tmp_path):
    res, seen = _invoke_fix([str(tmp_path), "--apply", "--sync", "--yes"], monkeypatch)
    assert res.exit_code == 2
    assert _SYNC_REFUSAL in res.output
    assert seen == {}


def test_interactive_default_apply_is_refused(container, monkeypatch, tmp_path):
    from packagealert.cli import fix_cmd

    monkeypatch.setattr(fix_cmd, "_interactive", lambda: True)
    for var in fix_cmd._CI_VARIABLES:
        monkeypatch.delenv(var, raising=False)
    res, seen = _invoke_fix([str(tmp_path), "--apply", "--yes"], monkeypatch)
    assert res.exit_code == 2 and _SYNC_REFUSAL in res.output and seen == {}


def test_apply_lock_only_is_allowed(container, monkeypatch, tmp_path):
    res, seen = _invoke_fix([str(tmp_path), "--apply", "--lock-only", "--yes"], monkeypatch)
    assert res.exit_code == 0, res.output
    assert seen["apply"].mode == "lock-only"


def test_apply_sync_is_unchanged_under_bwrap(monkeypatch, tmp_path):
    monkeypatch.delenv(isolation.ENV_VAR, raising=False)
    res, seen = _invoke_fix([str(tmp_path), "--apply", "--sync", "--yes"], monkeypatch)
    assert res.exit_code == 0, res.output
    assert seen["apply"].mode == "sync"


def test_an_entry_inside_another_is_copied_once(tmp_path):
    """~/.local/share/uv/tools inside ~/.local/share/uv: one copy, counted once against the
    limit, so a tree that fits once is not refused for fitting only twice."""
    real, fresh, deny = _homes(tmp_path)
    tools = real / ".local" / "share" / "uv" / "tools" / "cowsay"
    tools.mkdir(parents=True)
    (tools / "big").write_bytes(b"x" * 600)
    entries = [real / ".local" / "share" / "uv" / "tools", real / ".local" / "share" / "uv"]
    isolation.populate_home(fresh, entries, [], exclude=[], real_home=real, deny=deny, limit=1000)
    assert (fresh / ".local" / "share" / "uv" / "tools" / "cowsay" / "big").stat().st_size == 600


def test_an_entry_the_outer_copy_left_out_is_still_copied(tmp_path):
    """~/tools and ~/tools/bin with bin -> . : the outer copy prunes bin as a loop, so the
    bin entry, which the command is shown, is copied on its own."""
    real, fresh, deny = _homes(tmp_path)
    (real / "tools").mkdir()
    (real / "tools" / "launcher").write_text("#!/bin/sh\n")
    (real / "tools" / "bin").symlink_to(".")
    isolation.populate_home(fresh, [real / "tools", real / "tools" / "bin"], [], exclude=[], real_home=real,
                            deny=deny)
    assert (fresh / "tools" / "launcher").exists()
    assert (fresh / "tools" / "bin" / "launcher").exists()


def test_an_inner_entry_restores_what_the_outer_copy_pruned_without_recounting(tmp_path):
    """~/tools and ~/tools/bin with bin/up -> .. : the outer copy creates bin but prunes up as a
    loop; bin's own copy restores bin/up/launcher, and tools/launcher counts once."""
    real, fresh, deny = _homes(tmp_path)
    (real / "tools" / "bin").mkdir(parents=True)
    (real / "tools" / "launcher").write_bytes(b"x" * 600)
    (real / "tools" / "bin" / "up").symlink_to("..")
    isolation.populate_home(fresh, [real / "tools", real / "tools" / "bin"], [], exclude=[], real_home=real,
                            deny=deny, limit=1300)
    assert (fresh / "tools" / "bin" / "up" / "launcher").exists()
