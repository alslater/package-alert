"""Integration tests for uv tool and pipx parser → sandbox target resolution.

These tests exercise the full chain:
  parse_uv_args / parse_pipx_args
  → _try_parse (runner)
  → resolve_sandbox_targets (python language plugin)
  → post_run_scan_targets (python language plugin)

They do NOT require bubblewrap or a real install — they use tmp_path to
create synthetic venv structures and verify the right paths flow through.
"""
from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import patch

from packagealert.languages import registry as lang_registry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_venv(base: Path, name: str) -> tuple[Path, Path]:
    """Create a minimal venv skeleton under base/name.  Returns (venv_root, site_packages)."""
    venv = base / name
    sp_dir = venv / "lib" / "python3.12" / "site-packages"
    sp_dir.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    bin_dir = venv / "bin"
    bin_dir.mkdir()
    python = bin_dir / "python"
    python.write_text("#!/bin/sh\n")
    python.chmod(python.stat().st_mode | stat.S_IEXEC)
    return venv, sp_dir


def _python_lang():
    lang_registry.load()
    from packagealert.languages.python import PythonLanguage
    for lang in lang_registry.all_languages():
        if isinstance(lang, PythonLanguage):
            return lang
    raise RuntimeError("PythonLanguage not registered")


# ---------------------------------------------------------------------------
# _try_parse integration — uv tool install
# ---------------------------------------------------------------------------

class TestTryParseUvTool:
    def test_uv_tool_install_recognised(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["uv", "tool", "install", "ruff"])
        assert result is not None
        assert result.manager == "uv"
        assert result.packages == ["ruff"]

    def test_uv_tool_install_skips_python_flag_via_try_parse(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["uv", "tool", "install", "--python", "3.12", "ruff"])
        assert result is not None
        assert result.packages == ["ruff"]

    def test_uv_tool_install_propagates_extra_write_home_dirs(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["uv", "tool", "install", "ruff"])
        assert result is not None
        home = Path.home()
        uv_tools = home / ".local" / "share" / "uv" / "tools"
        assert uv_tools in result.extra_write_home_dirs

    def test_uv_tool_upgrade_recognised(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["uv", "tool", "upgrade", "ruff"])
        assert result is not None
        assert result.packages == ["ruff"]

    def test_uv_tool_list_not_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["uv", "tool", "list"])
        assert result is None

    def test_uv_tool_uninstall_not_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["uv", "tool", "uninstall", "ruff"])
        assert result is None


# ---------------------------------------------------------------------------
# _try_parse integration — pipx
# ---------------------------------------------------------------------------

class TestTryParsePipx:
    def test_pipx_install_recognised(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "install", "httpie"])
        assert result is not None
        assert result.manager == "pipx"
        assert result.packages == ["httpie"]

    def test_pipx_install_skips_python_flag_via_try_parse(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "install", "--python", "3.11", "httpie"])
        assert result is not None
        assert result.packages == ["httpie"]

    def test_pipx_upgrade_recognised(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "upgrade", "httpie"])
        assert result is not None
        assert result.packages == ["httpie"]

    def test_pipx_inject_carries_target_env_name(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "inject", "httpie", "httpx"])
        assert result is not None
        assert result.target_env_name == "httpie"
        assert result.packages == ["httpx"]

    def test_pipx_inject_skips_python_flag_via_try_parse(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "inject", "--python", "3.11", "httpie", "httpx"])
        assert result is not None
        assert result.target_env_name == "httpie"
        assert result.packages == ["httpx"]

    def test_pipx_list_not_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "list"])
        assert result is None

    def test_pipx_uninstall_not_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "uninstall", "httpie"])
        assert result is None

    def test_pipx_run_not_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "run", "cowsay", "hello"])
        assert result is None

    def test_pipx_install_propagates_extra_write_home_dirs(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "install", "httpie"])
        assert result is not None
        from packagealert.parsers.process_args import _pipx_home
        pipx_venvs = _pipx_home() / "venvs"
        assert pipx_venvs in result.extra_write_home_dirs

    def test_pipx_upgrade_all_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "upgrade-all"])
        assert result is not None
        assert result.manager == "pipx"
        assert result.packages == []
        assert result.extra_write_home_dirs

    def test_pipx_reinstall_all_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "reinstall-all"])
        assert result is not None
        assert result.packages == []
        assert result.extra_write_home_dirs

    def test_pipx_install_all_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "install-all"])
        assert result is not None
        assert result.packages == []
        assert result.extra_write_home_dirs

    def test_pipx_uninstall_all_not_sandboxed(self):
        from packagealert.sandbox.runner import _try_parse
        lang_registry.load()
        result = _try_parse(["pipx", "uninstall-all"])
        assert result is None


# ---------------------------------------------------------------------------
# resolve_sandbox_targets — uv tool install (fresh install, venv absent)
# ---------------------------------------------------------------------------

class TestResolveUvToolInstall:
    def test_uv_tool_venvs_dir_added_to_write_dirs(self, tmp_path):
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert uv_tools in result.write_dirs

    def test_uv_tool_fresh_install_has_no_scan_targets(self, tmp_path):
        """For a fresh install the tool venv doesn't exist yet — scan_targets must be empty
        so the runner falls through to post_run_scan_targets after the install."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert result.scan_targets == []

    def test_uv_tool_fresh_install_pre_registers_venv_for_rollback(self, tmp_path):
        """Fresh install: absent tool venv must be pre-registered in snapshot_only_dirs so
        a partial install (non-zero exit before post_run_scan_targets) is rolled back."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"
        expected_venv = uv_tools / "ruff"  # does not exist

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert expected_venv in result.snapshot_only_dirs

    def test_versioned_spec_maps_to_bare_tool_name_for_venv_path(self, tmp_path):
        """'uv tool install ruff==0.5' must look up the venv at tools/ruff, not tools/ruff==0.5."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"
        expected_venv = uv_tools / "ruff"  # bare name, venv does not exist yet

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff==0.5.0"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert expected_venv in result.snapshot_only_dirs
        # Must NOT have registered any path containing '=='
        for p in result.snapshot_only_dirs + result.scan_targets:
            assert "==" not in str(p)

    def test_extras_spec_maps_to_bare_tool_name_for_venv_path(self, tmp_path):
        """'uv tool install ruff[dev]' must look up the venv at tools/ruff, not tools/ruff[dev]."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"
        expected_venv = uv_tools / "ruff"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff[dev]"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert expected_venv in result.snapshot_only_dirs
        for p in result.snapshot_only_dirs + result.scan_targets:
            assert "[" not in str(p)

    def test_uv_tool_upgrade_existing_venv_has_scan_target(self, tmp_path):
        """For an upgrade the venv already exists — scan_targets must point at site-packages."""
        lang = _python_lang()
        # Path.home() is patched to tmp_path, so the canonical uv tools path becomes:
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        _venv_root, sp = _make_venv(uv_tools, "ruff")
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert sp in result.scan_targets

    def test_uv_tool_upgrade_snapshots_bin_dir(self, tmp_path):
        """Upgrading an existing tool venv must snapshot bin/ for rollback of entry-point scripts."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        venv_root, _sp = _make_venv(uv_tools, "ruff")
        tool_bin = venv_root / "bin"
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert tool_bin in result.snapshot_only_dirs
        assert tool_bin in result.write_dirs

    def test_local_bin_goes_to_snapshot_only_not_scan(self, tmp_path):
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert local_bin in result.snapshot_only_dirs
        assert local_bin not in result.scan_targets

    def test_invalid_pyvenv_cfg_surfaces_warning_not_exception(self, tmp_path):
        """venv_site_packages() raising ValueError must not propagate — warning surfaced instead."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        # Create a venv with a corrupt pyvenv.cfg so venv_site_packages raises.
        venv = uv_tools / "ruff"
        (venv / "bin").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("version = ../../../etc\n")
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert result.scan_targets == []
        assert result.warnings  # at least one warning surfaced
        assert uv_tools in result.write_dirs  # write access still granted

    def test_traversal_tool_name_rejected_in_resolve(self, tmp_path):
        """tool_name containing path separators must be rejected to prevent escaping venvs_dir."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["../../.ssh/authorized_keys"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        # Must not have snapshotted anything outside uv_tools
        for p in result.snapshot_only_dirs:
            assert ".ssh" not in str(p)
        # Entire venvs dir snapshotted as fallback (no valid tool name)
        assert uv_tools in result.snapshot_only_dirs

    def test_dotdot_tool_name_rejected_in_resolve(self, tmp_path):
        """tool_name of '..' must be rejected — Path('..').name == '..' bypasses the separator check."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=[".."], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        # '..' must not appear as a component after the tools dir
        for p in result.snapshot_only_dirs:
            relative = p.relative_to(uv_tools) if p.is_relative_to(uv_tools) else None
            if relative:
                assert ".." not in relative.parts
        assert uv_tools in result.snapshot_only_dirs



# ---------------------------------------------------------------------------
# resolve_sandbox_targets — pipx
# ---------------------------------------------------------------------------

class TestResolvePipxInstall:
    def _make_parsed(self, tmp_path, subcmd="install", tool="httpie", packages=None):
        from packagealert.parsers.process_args import ParsedInstall
        pipx_venvs = tmp_path / "pipx" / "venvs"
        local_bin = tmp_path / "bin"
        if packages is None:
            packages = [tool]
        return ParsedInstall(
            manager="pipx", packages=packages, ecosystem="pypi",
            extra_write_home_dirs=[pipx_venvs, local_bin],
        ), pipx_venvs, local_bin

    def test_pipx_venvs_dir_added_to_write_dirs(self, tmp_path):
        lang = _python_lang()
        parsed, pipx_venvs, _ = self._make_parsed(tmp_path)
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)
        assert pipx_venvs in result.write_dirs

    def test_pipx_fresh_install_no_scan_targets(self, tmp_path):
        lang = _python_lang()
        parsed, pipx_venvs, _ = self._make_parsed(tmp_path)
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)
        assert result.scan_targets == []

    def test_pipx_fresh_install_pre_registers_venv_for_rollback(self, tmp_path):
        """Fresh pipx install: absent tool venv must be pre-registered so a partial install
        (non-zero exit before post_run_scan_targets) can be rolled back."""
        lang = _python_lang()
        pipx_venvs = tmp_path / "pipx" / "venvs"
        local_bin = tmp_path / "bin"
        expected_venv = pipx_venvs / "httpie"  # does not exist

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="pipx", packages=["httpie"], ecosystem="pypi",
            extra_write_home_dirs=[pipx_venvs, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert expected_venv in result.snapshot_only_dirs

    def test_pipx_upgrade_existing_venv_has_scan_target(self, tmp_path):
        lang = _python_lang()
        pipx_venvs = tmp_path / "pipx" / "venvs"
        _venv_root, sp = _make_venv(pipx_venvs, "httpie")
        local_bin = tmp_path / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="pipx", packages=["httpie"], ecosystem="pypi",
            extra_write_home_dirs=[pipx_venvs, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)
        assert sp in result.scan_targets

    def test_pipx_upgrade_snapshots_bin_dir(self, tmp_path):
        """Upgrading an existing pipx tool venv must snapshot bin/ for rollback of entry-point scripts."""
        lang = _python_lang()
        pipx_venvs = tmp_path / "pipx" / "venvs"
        venv_root, _sp = _make_venv(pipx_venvs, "httpie")
        tool_bin = venv_root / "bin"
        local_bin = tmp_path / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="pipx", packages=["httpie"], ecosystem="pypi",
            extra_write_home_dirs=[pipx_venvs, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert tool_bin in result.snapshot_only_dirs
        assert tool_bin in result.write_dirs

    def test_pipx_inject_uses_target_env_name(self, tmp_path):
        """inject: target_env_name picks the right venv even though packages[0] is the injected package."""
        lang = _python_lang()
        pipx_venvs = tmp_path / "pipx" / "venvs"
        _venv_root, sp = _make_venv(pipx_venvs, "httpie")
        local_bin = tmp_path / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="pipx", packages=["httpx"], ecosystem="pypi",
            extra_write_home_dirs=[pipx_venvs, local_bin],
            target_env_name="httpie",
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)
        assert sp in result.scan_targets

    def test_pipx_upgrade_all_snapshots_venvs_dir_for_rollback(self, tmp_path):
        """upgrade-all has no tool name — the entire venvs dir must be snapshot for rollback."""
        lang = _python_lang()
        pipx_venvs = tmp_path / "pipx" / "venvs"
        pipx_venvs.mkdir(parents=True)
        local_bin = tmp_path / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="pipx", packages=[], ecosystem="pypi",
            extra_write_home_dirs=[pipx_venvs, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            result = lang.resolve_sandbox_targets(parsed, tmp_path)

        assert pipx_venvs in result.snapshot_only_dirs
        assert result.scan_targets == []
        assert pipx_venvs in result.write_dirs


# ---------------------------------------------------------------------------
# post_run_scan_targets — venv discovered after install
# ---------------------------------------------------------------------------

class TestPostRunScanTargets:
    def test_uv_tool_install_discovers_new_venv(self, tmp_path):
        lang = _python_lang()
        # Must match tmp_path / ".local/share/uv/tools" so the venvs_dir comparison hits.
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        venv_root, sp = _make_venv(uv_tools, "ruff")
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        assert venv_root in targets
        assert sp in targets

    def test_pipx_install_discovers_new_venv(self, tmp_path):
        lang = _python_lang()
        pipx_venvs = tmp_path / "pipx" / "venvs"
        venv_root, sp = _make_venv(pipx_venvs, "httpie")
        local_bin = tmp_path / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="pipx", packages=["httpie"], ecosystem="pypi",
            extra_write_home_dirs=[pipx_venvs, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        assert venv_root in targets
        assert sp in targets

    def test_pipx_inject_uses_target_env_name_for_scan(self, tmp_path):
        """post_run_scan_targets must use target_env_name so inject scans the right venv."""
        lang = _python_lang()
        pipx_venvs = tmp_path / "pipx" / "venvs"
        venv_root, sp = _make_venv(pipx_venvs, "httpie")
        local_bin = tmp_path / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="pipx", packages=["httpx"], ecosystem="pypi",
            extra_write_home_dirs=[pipx_venvs, local_bin],
            target_env_name="httpie",
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir", return_value=pipx_venvs):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        assert venv_root in targets
        assert sp in targets

    def test_versioned_spec_uses_bare_name_for_venv_lookup(self, tmp_path):
        """post_run_scan_targets must strip version pins — 'ruff==0.5' looks up venv 'ruff'."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        venv_root, sp = _make_venv(uv_tools, "ruff")
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff==0.5.0"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        assert venv_root in targets
        assert sp in targets
        for p in targets:
            assert "==" not in str(p)

    def test_absent_venv_returns_empty(self, tmp_path):
        """If the venv was never created (install failed), post_run_scan_targets returns []."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["nonexistent-tool"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        assert targets == []

    def test_invalid_pyvenv_cfg_returns_venv_root_as_rollback_target(self, tmp_path):
        """Invalid pyvenv.cfg must not suppress post_run entirely — return [venv_root] for rollback."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        venv_root, _sp = _make_venv(uv_tools, "ruff")
        # Overwrite pyvenv.cfg with a path-traversal version value that triggers ValueError.
        (venv_root / "pyvenv.cfg").write_text("version = ../../../etc\n")
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        assert targets == [venv_root]

    def test_tool_manager_does_not_fall_back_to_project_venv(self, tmp_path):
        """If the tool venv wasn't created, post_run must return [] — never the project .venv."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"
        # No tool venv created — but a .venv exists in cwd (unrelated project venv).
        _project_venv, _project_sp = _make_venv(tmp_path, ".venv")

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["ruff"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        assert targets == []

    def test_traversal_tool_name_rejected_in_post_run(self, tmp_path):
        """tool_name with path separators must be ignored in post_run — return []."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=["../../../.ssh/id_rsa"], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        assert targets == []
        for p in targets:
            assert ".ssh" not in str(p)

    def test_dotdot_tool_name_rejected_in_post_run(self, tmp_path):
        """tool_name of '..' must be rejected in post_run — Path('..').name == '..' bypasses separator check."""
        lang = _python_lang()
        uv_tools = tmp_path / ".local" / "share" / "uv" / "tools"
        local_bin = tmp_path / ".local" / "bin"
        # Create a venv one level above uv_tools to verify '..' can't escape
        _make_venv(uv_tools.parent, "escape-target")

        from packagealert.parsers.process_args import ParsedInstall
        parsed = ParsedInstall(
            manager="uv", packages=[".."], ecosystem="pypi",
            extra_write_home_dirs=[uv_tools, local_bin],
        )
        with patch("packagealert.languages.python.Path.home", return_value=tmp_path), \
             patch("packagealert.languages.python._pipx_venvs_dir",
                   return_value=tmp_path / ".local" / "pipx" / "venvs"):
            targets = lang.post_run_scan_targets(parsed, tmp_path)

        # Must not have returned a path outside uv_tools
        for p in targets:
            assert p.is_relative_to(uv_tools), f"{p} escaped uv_tools"
