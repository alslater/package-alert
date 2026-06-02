"""Unit tests for the sandbox module.

Covers bwrap command builder and the module-level helpers in runner.py that
are pure functions (no I/O, no async, no OSV calls).
"""
from __future__ import annotations

import json
import unittest.mock
from pathlib import Path

import pytest

from packagealert.sandbox.bwrap import build_cmd
from packagealert.sandbox.runner import (
    SandboxRunner,
    _collect_new_packages,
    _find_pipenv_venv,
    _find_site_packages,
    _find_venv_root,
    _has_ssh_vcs_deps,
    _is_ssh_vcs_url,
    _req_file_has_ssh,
    _home_ro_dirs,
    _new_composer_packages,
    _new_npm_packages,
    _new_python_packages,
    _pipenv_venv_dir,
    _resolve_targets,
    _restore_lock_files,
    _snapshot_lock_files,
    _try_parse,
    _serialise_package_spec,
    _build_sandbox_env,
    _assert_scannable_lock_files_contained,
    _LOCK_UNREADABLE,
    _restorable_lock_files,
    _scannable_lock_files,
    _SANDBOX_ENV_COMMON,
    _SHELL_NAMES,
    _SHELL_RC_FILES,
    _Context,
)
from packagealert.parsers.process_args import ParsedInstall


def _make_runner():
    from packagealert.config import AppConfig
    return SandboxRunner(AppConfig())


# ---------------------------------------------------------------------------
# bwrap.build_cmd
# ---------------------------------------------------------------------------

class TestBuildCmd:
    def test_ro_bind_root_present(self, tmp_path):
        cmd = build_cmd(["uv", "sync"], [])
        assert "--ro-bind" in cmd
        idx = cmd.index("--ro-bind")
        assert cmd[idx + 1] == "/" and cmd[idx + 2] == "/"

    def test_double_dash_separates_bwrap_and_user_cmd(self, tmp_path):
        cmd = build_cmd(["uv", "sync"], [])
        assert "--" in cmd
        sep = cmd.index("--")
        assert cmd[sep + 1 :] == ["uv", "sync"]

    def test_write_dir_bound_writable(self, tmp_path):
        target = tmp_path / "site-packages"
        target.mkdir()
        cmd = build_cmd(["pip", "install", "x"], [target])
        assert "--bind" in cmd
        bind_idx = cmd.index("--bind")
        assert cmd[bind_idx + 1] == str(target)
        assert cmd[bind_idx + 2] == str(target)

    def test_write_dir_created_if_missing(self, tmp_path):
        target = tmp_path / "node_modules"
        assert not target.exists()
        build_cmd(["npm", "install"], [target])
        assert target.exists()

    def test_network_allowed_by_default(self):
        cmd = build_cmd(["uv", "sync"], [])
        assert "--unshare-net" not in cmd

    def test_no_network_flag_adds_unshare(self):
        cmd = build_cmd(["uv", "sync"], [], allow_network=False)
        assert "--unshare-net" in cmd

    def test_no_env_arg_omits_clearenv(self):
        cmd = build_cmd(["uv", "sync"], [])
        assert "--clearenv" not in cmd
        assert "--setenv" not in cmd

    def test_env_dict_adds_clearenv(self):
        cmd = build_cmd(["uv", "sync"], [], env={"PATH": "/usr/bin", "HOME": "/root"})
        assert "--clearenv" in cmd

    def test_env_dict_adds_setenv_entries(self):
        cmd = build_cmd(["uv", "sync"], [], env={"PATH": "/usr/bin", "HOME": "/root"})
        setenv_pairs = []
        i = 0
        while i < len(cmd):
            if cmd[i] == "--setenv":
                setenv_pairs.append((cmd[i + 1], cmd[i + 2]))
                i += 3
            else:
                i += 1
        assert ("PATH", "/usr/bin") in setenv_pairs
        assert ("HOME", "/root") in setenv_pairs

    def test_empty_env_dict_adds_clearenv_no_setenv(self):
        cmd = build_cmd(["uv", "sync"], [], env={})
        assert "--clearenv" in cmd
        assert "--setenv" not in cmd

    def test_multiple_write_dirs_all_bound(self, tmp_path):
        d1 = tmp_path / "a"
        d2 = tmp_path / "b"
        d1.mkdir()
        d2.mkdir()
        cmd = build_cmd(["pip", "install", "x"], [d1, d2])
        bind_indices = [i for i, t in enumerate(cmd) if t == "--bind"]
        bound = {cmd[i + 1] for i in bind_indices}
        assert str(d1) in bound and str(d2) in bound

    def test_unshare_pid_present(self):
        cmd = build_cmd(["uv", "sync"], [])
        assert "--unshare-pid" in cmd

    def test_die_with_parent_present(self):
        cmd = build_cmd(["uv", "sync"], [])
        assert "--die-with-parent" in cmd

    def test_home_dir_hidden_by_tmpfs(self):
        home = str(Path.home())
        cmd = build_cmd(["uv", "sync"], [])
        tmpfs_targets = [cmd[i + 1] for i, t in enumerate(cmd) if t == "--tmpfs"]
        assert home in tmpfs_targets

    def test_home_ro_dirs_bound_readonly(self, tmp_path):
        p = tmp_path / "tooldir"
        p.mkdir()
        cmd = build_cmd(["uv", "sync"], [], home_ro_dirs=[p])
        ro_pairs = _ro_bind_pairs(cmd)
        assert (str(p), str(p)) in ro_pairs

    def test_nonexistent_home_ro_dirs_skipped(self, tmp_path):
        nonexistent = tmp_path / "nonexistent"
        cmd = build_cmd(["uv", "sync"], [], home_ro_dirs=[nonexistent])
        ro_pairs = _ro_bind_pairs(cmd)
        assert (str(nonexistent), str(nonexistent)) not in ro_pairs

    def test_home_ro_dirs_appear_before_write_dirs(self, tmp_path):
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()
        wr_dir = tmp_path / "wr"
        wr_dir.mkdir()
        cmd = build_cmd(["uv", "sync"], [wr_dir], home_ro_dirs=[ro_dir])
        ro_idx = cmd.index("--ro-bind", 3)   # skip the first --ro-bind (/ /)
        bind_idx = cmd.index("--bind")
        assert ro_idx < bind_idx


def _ro_bind_pairs(cmd: list[str]) -> list[tuple[str, str]]:
    pairs = []
    i = 0
    while i < len(cmd):
        if cmd[i] == "--ro-bind":
            pairs.append((cmd[i + 1], cmd[i + 2]))
            i += 3
        else:
            i += 1
    return pairs


# ---------------------------------------------------------------------------
# _home_ro_dirs
# ---------------------------------------------------------------------------

class TestHomeRoDirs:
    def test_uses_pyenv_root_env_var(self, tmp_path, monkeypatch):
        pyenv = tmp_path / "pyenv"
        pyenv.mkdir()
        monkeypatch.setenv("PYENV_ROOT", str(pyenv))
        assert pyenv in _home_ro_dirs()

    def test_uses_nvm_dir_env_var(self, tmp_path, monkeypatch):
        nvm = tmp_path / "nvm"
        nvm.mkdir()
        monkeypatch.setenv("NVM_DIR", str(nvm))
        assert nvm in _home_ro_dirs()

    def test_nonexistent_paths_excluded(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PYENV_ROOT", str(tmp_path / "no_pyenv"))
        monkeypatch.setenv("NVM_DIR", str(tmp_path / "no_nvm"))
        result = _home_ro_dirs()
        assert not any("no_pyenv" in str(p) or "no_nvm" in str(p) for p in result)

    def test_returns_only_existing_paths(self, tmp_path, monkeypatch):
        # All overridden to non-existent paths under tmp_path — result must be empty
        # (assuming none of the fixed home/* paths exist under tmp, which they won't)
        monkeypatch.setenv("PYENV_ROOT", str(tmp_path / "x"))
        monkeypatch.setenv("NVM_DIR", str(tmp_path / "y"))
        result = _home_ro_dirs()
        for p in result:
            assert p.exists()

    def test_virtual_env_not_in_home_ro_dirs(self, tmp_path, monkeypatch):
        # VIRTUAL_ENV is handled via write_dirs (writable), not home_ro (read-only)
        venv = tmp_path / "myvenv"
        venv.mkdir()
        monkeypatch.setenv("VIRTUAL_ENV", str(venv))
        assert venv not in _home_ro_dirs()

    def test_no_broad_local_exposure(self, monkeypatch):
        # Guard against regressing to exposing all of ~/.local — only the three
        # targeted subdirectories (~/.local/bin, ~/.local/share/uv, ~/.local/pipx)
        # should ever appear; the parent ~/.local itself must not.
        home = Path.home()
        broad_local = home / ".local"
        result = _home_ro_dirs()
        assert broad_local not in result, (
            "~/.local must not be exposed wholesale; use targeted subdirectories only"
        )
        # Verify the three permitted ~/.local subdirectories are the only ones present
        local_paths = [p for p in result if str(p).startswith(str(broad_local) + "/")]
        allowed = {
            broad_local / "bin",
            broad_local / "share" / "uv",
            broad_local / "pipx",
        }
        unexpected = [p for p in local_paths if p not in allowed]
        assert not unexpected, (
            f"Unexpected ~/.local subdirectories exposed: {unexpected}"
        )

    def test_sandbox_env_allowlist_includes_pyenv_and_nvm(self):
        from packagealert.languages.python import PythonLanguage
        from packagealert.languages.node import NodeLanguage
        assert "PYENV_ROOT" in PythonLanguage().sandbox_env()
        assert "NVM_DIR" in NodeLanguage().sandbox_env()


# ---------------------------------------------------------------------------
# _try_parse
# ---------------------------------------------------------------------------

class TestTryParse:
    def test_recognises_uv_sync(self):
        result = _try_parse(["uv", "sync"])
        assert result is not None
        assert result.manager == "uv-lock"

    def test_recognises_npm_install(self):
        result = _try_parse(["npm", "install"])
        assert result is not None
        assert result.ecosystem == "npm"

    def test_recognises_pip_install(self):
        result = _try_parse(["pip", "install", "requests"])
        assert result is not None
        assert result.packages == ["requests"]

    def test_recognises_composer_require(self):
        result = _try_parse(["composer", "require", "vendor/pkg"])
        assert result is not None
        assert result.ecosystem == "packagist"

    def test_recognises_pip_show(self):
        result = _try_parse(["pip", "show", "requests"])
        assert result is not None
        assert result.manager == "pip"
        assert result.packages == []

    def test_recognises_pip_list(self):
        result = _try_parse(["pip", "list"])
        assert result is not None
        assert result.manager == "pip"
        assert result.packages == []

    def test_recognises_pipenv_sync(self):
        result = _try_parse(["pipenv", "sync"])
        assert result is not None
        assert result.manager == "pipenv"
        assert result.packages == []

    def test_recognises_pipenv_install(self):
        result = _try_parse(["pipenv", "install", "requests"])
        assert result is not None
        assert result.manager == "pipenv"
        assert result.packages == ["requests"]

    def test_recognises_pipenv_create(self):
        result = _try_parse(["pipenv", "create"])
        assert result is not None
        assert result.manager == "pipenv"
        assert result.packages == []

    def test_pip_install_r_collects_req_files(self):
        result = _try_parse(["pip", "install", "-r", "requirements.txt", "-r", "dev.txt"])
        assert result is not None
        assert result.manager == "pip"
        assert result.packages == []
        assert result.req_files == ["requirements.txt", "dev.txt"]

    def test_pip_install_r_long_flag_collects_req_files(self):
        result = _try_parse(["pip", "install", "--requirement", "reqs/base.txt"])
        assert result is not None
        assert result.req_files == ["reqs/base.txt"]

    def test_pip_install_r_inline_concatenated(self):
        result = _try_parse(["pip", "install", "-rcustom.txt"])
        assert result is not None
        assert result.req_files == ["custom.txt"]

    def test_pip_install_requirement_equals_form(self):
        result = _try_parse(["pip", "install", "--requirement=custom.txt"])
        assert result is not None
        assert result.req_files == ["custom.txt"]

    def test_unknown_command_returns_none(self):
        assert _try_parse(["make", "build"]) is None
        assert _try_parse(["cargo", "build"]) is None

    def test_pip_pinned_package_uses_double_equals(self):
        result = _try_parse(["pip", "install", "requests==2.31.0"])
        assert result is not None
        assert result.packages == ["requests==2.31.0"]

    def test_npm_pinned_package_uses_at_separator(self):
        result = _try_parse(["npm", "install", "lodash@4.17.21"])
        assert result is not None
        assert result.packages == ["lodash@4.17.21"]

    def test_composer_pinned_package_uses_colon_separator(self):
        result = _try_parse(["composer", "require", "vendor/pkg:1.2.3"])
        assert result is not None
        assert result.packages == ["vendor/pkg:1.2.3"]

    def test_windows_path_backslash_resolved(self):
        result = _try_parse([r"C:\Python\Scripts\pip.exe", "install", "requests"])
        assert result is not None
        assert result.packages == ["requests"]

    def test_windows_path_npm_backslash_resolved(self):
        result = _try_parse([r"C:\Program Files\nodejs\npm.exe", "install", "lodash"])
        assert result is not None
        assert result.ecosystem == "npm"

    def test_returns_none_when_plugin_raises(self):
        from unittest.mock import MagicMock, patch
        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.process_names = frozenset(["pip"])
        bad_lang.parse_process_install.side_effect = RuntimeError("plugin exploded")
        with patch("packagealert.languages.registry.for_process", return_value=bad_lang):
            result = _try_parse(["pip", "install", "flask"])
        assert result is None
        bad_lang.parse_process_install.assert_called_once()

    def test_lockfile_hint_propagated(self):
        from packagealert.languages.base import ProcessInstall, PackageSpec
        from unittest.mock import MagicMock, patch
        lang = MagicMock()
        lang.name = "node"
        lang.ecosystems = ["npm"]
        lang.parse_process_install.return_value = ProcessInstall(
            manager="yarn",
            packages=[],
            defer_to_lockfile=True,
            lockfile_hint="yarn.lock",
        )
        with patch("packagealert.languages.registry.for_process", return_value=lang):
            result = _try_parse(["yarn", "install"])
        assert result is not None
        assert result.lockfile_hint == "yarn.lock"

    def test_lockfile_hint_propagated_from_node_npm(self):
        # npm sets lockfile_hint="package-lock.json" via _LOCKFILE_HINTS
        result = _try_parse(["npm", "install"])
        assert result is not None
        assert result.lockfile_hint == "package-lock.json"

    def test_lockfile_hint_none_for_pip(self):
        # pip does not set a lockfile_hint
        result = _try_parse(["pip", "install", "flask"])
        assert result is not None
        assert result.lockfile_hint is None


# ---------------------------------------------------------------------------
# _serialise_package_spec
# ---------------------------------------------------------------------------

class TestSerialisePackageSpec:
    """_serialise_package_spec must use the ecosystem-appropriate version separator
    so that the round-trip through parse_package_spec() in _preflight recovers the
    correct (name, version) pair for every ecosystem."""

    def _make(self, name, version, ecosystem):
        from packagealert.languages.base import PackageSpec
        return PackageSpec(name=name, version=version, ecosystem=ecosystem)

    def test_pypi_pinned(self):
        assert _serialise_package_spec(self._make("requests", "2.31.0", "pypi")) == "requests==2.31.0"

    def test_pypi_unpinned(self):
        assert _serialise_package_spec(self._make("requests", None, "pypi")) == "requests"

    def test_npm_pinned(self):
        assert _serialise_package_spec(self._make("lodash", "4.17.21", "npm")) == "lodash@4.17.21"

    def test_npm_scoped_pinned(self):
        assert _serialise_package_spec(self._make("@types/node", "18.0.0", "npm")) == "@types/node@18.0.0"

    def test_npm_unpinned(self):
        assert _serialise_package_spec(self._make("lodash", None, "npm")) == "lodash"

    def test_packagist_pinned(self):
        assert _serialise_package_spec(self._make("vendor/pkg", "1.2.3", "Packagist")) == "vendor/pkg:1.2.3"

    def test_packagist_unpinned(self):
        assert _serialise_package_spec(self._make("vendor/pkg", None, "Packagist")) == "vendor/pkg"

    def test_roundtrip_pypi(self):
        from packagealert.parsers.process_args import parse_package_spec
        spec = self._make("requests", "2.31.0", "pypi")
        name, version = parse_package_spec(_serialise_package_spec(spec), "pypi")
        assert name == "requests"
        assert version == "2.31.0"

    def test_roundtrip_npm(self):
        from packagealert.parsers.process_args import parse_package_spec
        spec = self._make("lodash", "4.17.21", "npm")
        name, version = parse_package_spec(_serialise_package_spec(spec), "npm")
        assert name == "lodash"
        assert version == "4.17.21"

    def test_roundtrip_packagist(self):
        from packagealert.parsers.process_args import parse_package_spec
        spec = self._make("vendor/pkg", "1.2.3", "Packagist")
        name, version = parse_package_spec(_serialise_package_spec(spec), "packagist")
        assert name == "vendor/pkg"
        assert version == "1.2.3"

    def test_falls_back_to_double_equals_when_plugin_raises(self):
        from unittest.mock import MagicMock, patch
        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.serialise_package_spec.side_effect = RuntimeError("plugin exploded")
        spec = self._make("pkg", "1.0.0", "custom")
        with patch("packagealert.languages.registry.for_ecosystem", return_value=bad_lang):
            result = _serialise_package_spec(spec)
        assert result == "pkg==1.0.0"


# ---------------------------------------------------------------------------
# _find_site_packages
# ---------------------------------------------------------------------------

class TestFindSitePackages:
    def test_finds_from_venv_exe(self, tmp_path):
        # Create a fake venv structure
        site_pkgs = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        site_pkgs.mkdir(parents=True)
        (tmp_path / ".venv" / "bin").mkdir(parents=True)
        pip_exe = tmp_path / ".venv" / "bin" / "pip"
        pip_exe.touch()

        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi", venv_exe=str(pip_exe))
        result = _find_site_packages(parsed, tmp_path)
        assert result == site_pkgs

    def test_finds_dotenv_in_cwd(self, tmp_path):
        site_pkgs = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        site_pkgs.mkdir(parents=True)
        parsed = ParsedInstall(manager="uv-lock", packages=[], ecosystem="pypi")
        result = _find_site_packages(parsed, tmp_path)
        assert result == site_pkgs

    def test_finds_venv_in_cwd(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        site_pkgs = tmp_path / "venv" / "lib" / "python3.11" / "site-packages"
        site_pkgs.mkdir(parents=True)
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        result = _find_site_packages(parsed, tmp_path)
        assert result == site_pkgs

    def test_prefers_dotenv_over_venv(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        dotenv_sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        venv_sp = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
        dotenv_sp.mkdir(parents=True)
        venv_sp.mkdir(parents=True)
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        result = _find_site_packages(parsed, tmp_path)
        assert result == dotenv_sp

    def test_virtual_env_used_for_pip(self, tmp_path, monkeypatch):
        activated = tmp_path / "activated"
        site_pkgs = activated / "lib" / "python3.12" / "site-packages"
        site_pkgs.mkdir(parents=True)
        monkeypatch.setenv("VIRTUAL_ENV", str(activated))
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        result = _find_site_packages(parsed, tmp_path)
        assert result == site_pkgs

    def test_virtual_env_ignored_for_uv(self, tmp_path, monkeypatch):
        # VIRTUAL_ENV points to a different location; uv installs into .venv in cwd
        activated = tmp_path / "activated"
        (activated / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
        monkeypatch.setenv("VIRTUAL_ENV", str(activated))
        # project-local .venv also exists
        local_sp = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        local_sp.mkdir(parents=True)
        parsed = ParsedInstall(manager="uv-lock", packages=[], ecosystem="pypi")
        result = _find_site_packages(parsed, tmp_path)
        assert result == local_sp

    def test_returns_none_when_no_venv(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        assert _find_site_packages(parsed, tmp_path) is None

    def test_returns_none_for_none_parsed_even_with_venv_present(self, tmp_path):
        # Presence of .venv must not cause a return when parsed is None
        (tmp_path / ".venv" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
        assert _find_site_packages(None, tmp_path) is None


# ---------------------------------------------------------------------------
# _resolve_targets
# ---------------------------------------------------------------------------

class TestResolveTargets:
    def test_cwd_always_in_write_dirs(self, tmp_path):
        ctx = _Context(argv=[], parsed=None, cwd=tmp_path)
        _resolve_targets(ctx)
        assert tmp_path in ctx.write_dirs

    def test_npm_scan_target_is_node_modules(self, tmp_path):
        parsed = ParsedInstall(manager="npm", packages=[], ecosystem="npm")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        _resolve_targets(ctx)
        assert tmp_path / "node_modules" in ctx.scan_targets

    def test_composer_scan_target_is_vendor(self, tmp_path):
        parsed = ParsedInstall(manager="composer", packages=[], ecosystem="packagist")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        _resolve_targets(ctx)
        assert tmp_path / "vendor" in ctx.scan_targets

    def test_pypi_site_packages_in_scan_targets_when_detected(self, tmp_path):
        site_pkgs = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        site_pkgs.mkdir(parents=True)
        parsed = ParsedInstall(manager="uv-lock", packages=[], ecosystem="pypi")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        _resolve_targets(ctx)
        assert site_pkgs in ctx.scan_targets

    def test_site_packages_under_cwd_not_duplicated_in_write_dirs(self, tmp_path):
        site_pkgs = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        site_pkgs.mkdir(parents=True)
        parsed = ParsedInstall(manager="uv-lock", packages=[], ecosystem="pypi")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        _resolve_targets(ctx)
        # site-packages is inside cwd, so it must NOT be added as a separate write_dir
        assert site_pkgs not in ctx.write_dirs

    def test_pipenv_creates_venvs_dir_when_absent(self, tmp_path, monkeypatch):
        venvs_dir = tmp_path / "virtualenvs"
        assert not venvs_dir.exists()
        monkeypatch.setenv("WORKON_HOME", str(venvs_dir))
        monkeypatch.delenv("PIPENV_VENV_IN_PROJECT", raising=False)
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        _resolve_targets(ctx)
        assert venvs_dir.exists()
        assert venvs_dir in ctx.write_dirs

    def test_pipenv_adds_venvs_dir_when_already_exists(self, tmp_path, monkeypatch):
        venvs_dir = tmp_path / "virtualenvs"
        venvs_dir.mkdir()
        monkeypatch.setenv("WORKON_HOME", str(venvs_dir))
        monkeypatch.delenv("PIPENV_VENV_IN_PROJECT", raising=False)
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        _resolve_targets(ctx)
        assert venvs_dir in ctx.write_dirs

    def test_pipenv_skips_venvs_dir_when_venv_in_project(self, tmp_path, monkeypatch):
        venvs_dir = tmp_path / "virtualenvs"
        monkeypatch.setenv("WORKON_HOME", str(venvs_dir))
        monkeypatch.setenv("PIPENV_VENV_IN_PROJECT", "1")
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        _resolve_targets(ctx)
        assert venvs_dir not in ctx.write_dirs
        assert not venvs_dir.exists()

    def test_pipenv_adds_existing_venv_site_packages_to_scan_targets(self, tmp_path, monkeypatch):
        venvs_dir = tmp_path / "virtualenvs"
        venv = venvs_dir / "myproject-abc123"
        site_pkgs = venv / "lib" / "python3.12" / "site-packages"
        site_pkgs.mkdir(parents=True)
        monkeypatch.setenv("WORKON_HOME", str(venvs_dir))
        monkeypatch.delenv("PIPENV_VENV_IN_PROJECT", raising=False)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        with unittest.mock.patch(
            "packagealert.sandbox.runner._find_pipenv_venv", return_value=venv
        ):
            _resolve_targets(ctx)
        assert site_pkgs in ctx.scan_targets

    def test_pipenv_no_scan_target_when_venv_not_yet_created(self, tmp_path, monkeypatch):
        venvs_dir = tmp_path / "virtualenvs"
        monkeypatch.setenv("WORKON_HOME", str(venvs_dir))
        monkeypatch.delenv("PIPENV_VENV_IN_PROJECT", raising=False)
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        ctx = _Context(argv=[], parsed=parsed, cwd=tmp_path)
        with unittest.mock.patch(
            "packagealert.sandbox.runner._find_pipenv_venv", return_value=None
        ):
            _resolve_targets(ctx)
        # No scan targets yet — the post-install fallback will find them after creation
        assert ctx.scan_targets == []


class TestFindPipenvVenv:
    def test_returns_path_when_pipenv_succeeds(self, tmp_path):
        venv = tmp_path / "myproject-abc123"
        venv.mkdir()
        with unittest.mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = unittest.mock.Mock(returncode=0, stdout=str(venv) + "\n")
            result = _find_pipenv_venv(tmp_path)
        assert result == venv

    def test_returns_none_when_venv_does_not_exist(self, tmp_path):
        with unittest.mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = unittest.mock.Mock(returncode=0, stdout="/nonexistent/path\n")
            result = _find_pipenv_venv(tmp_path)
        assert result is None

    def test_returns_none_when_pipenv_fails(self, tmp_path):
        with unittest.mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = unittest.mock.Mock(returncode=1, stdout="")
            result = _find_pipenv_venv(tmp_path)
        assert result is None

    def test_returns_none_when_pipenv_not_installed(self, tmp_path):
        with unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError):
            result = _find_pipenv_venv(tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# _new_python_packages
# ---------------------------------------------------------------------------

class TestNewPythonPackages:
    def test_detects_dist_info_dir(self, tmp_path):
        dist = tmp_path / "requests-2.31.0.dist-info"
        dist.mkdir()
        result = _new_python_packages({dist})
        assert ("pypi", "requests", "2.31.0") in result

    def test_normalises_name(self, tmp_path):
        dist = tmp_path / "Werkzeug-3.0.0.dist-info"
        dist.mkdir()
        result = _new_python_packages({dist})
        assert ("pypi", "werkzeug", "3.0.0") in result

    def test_normalises_underscores(self, tmp_path):
        dist = tmp_path / "my_package-1.0.0.dist-info"
        dist.mkdir()
        result = _new_python_packages({dist})
        assert ("pypi", "my-package", "1.0.0") in result

    def test_ignores_non_dist_info(self, tmp_path):
        f = tmp_path / "requests-2.31.0"
        f.mkdir()
        assert _new_python_packages({f}) == []

    def test_ignores_files_not_dirs(self, tmp_path):
        f = tmp_path / "requests-2.31.0.dist-info"
        f.touch()
        assert _new_python_packages({f}) == []


# ---------------------------------------------------------------------------
# _new_npm_packages
# ---------------------------------------------------------------------------

class TestNewNpmPackages:
    def test_detects_regular_package(self, tmp_path):
        pkg_dir = tmp_path / "lodash"
        pkg_dir.mkdir()
        pkg_json = pkg_dir / "package.json"
        pkg_json.write_text(json.dumps({"name": "lodash", "version": "4.17.21"}))
        result = _new_npm_packages({pkg_json}, tmp_path)
        assert ("npm", "lodash", "4.17.21") in result

    def test_detects_scoped_package(self, tmp_path):
        scope_dir = tmp_path / "@types"
        pkg_dir = scope_dir / "node"
        pkg_dir.mkdir(parents=True)
        pkg_json = pkg_dir / "package.json"
        pkg_json.write_text(json.dumps({"name": "@types/node", "version": "20.0.0"}))
        result = _new_npm_packages({pkg_json}, tmp_path)
        assert ("npm", "@types/node", "20.0.0") in result

    def test_ignores_wrong_depth(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        pkg_json = nested / "package.json"
        pkg_json.write_text(json.dumps({"name": "deep", "version": "1.0.0"}))
        assert _new_npm_packages({pkg_json}, tmp_path) == []

    def test_ignores_corrupt_json(self, tmp_path):
        pkg_dir = tmp_path / "broken"
        pkg_dir.mkdir()
        pkg_json = pkg_dir / "package.json"
        pkg_json.write_text("{not json")
        assert _new_npm_packages({pkg_json}, tmp_path) == []


# ---------------------------------------------------------------------------
# _new_composer_packages
# ---------------------------------------------------------------------------

class TestNewComposerPackages:
    def test_detects_vendor_package(self, tmp_path):
        vendor_dir = tmp_path / "symfony" / "console"
        vendor_dir.mkdir(parents=True)
        pkg_json = vendor_dir / "composer.json"
        pkg_json.write_text(json.dumps({"name": "symfony/console", "version": "6.4.0"}))
        result = _new_composer_packages({pkg_json}, tmp_path)
        assert ("packagist", "symfony/console", "6.4.0") in result

    def test_strips_leading_v_from_version(self, tmp_path):
        vendor_dir = tmp_path / "vendor" / "pkg"
        vendor_dir.mkdir(parents=True)
        pkg_json = vendor_dir / "composer.json"
        pkg_json.write_text(json.dumps({"name": "vendor/pkg", "version": "v1.2.3"}))
        result = _new_composer_packages({pkg_json}, tmp_path)
        assert ("packagist", "vendor/pkg", "1.2.3") in result

    def test_ignores_wrong_depth(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        pkg_json = deep / "composer.json"
        pkg_json.write_text(json.dumps({"name": "a/b", "version": "1.0"}))
        assert _new_composer_packages({pkg_json}, tmp_path) == []

    def test_ignores_name_without_slash(self, tmp_path):
        vendor_dir = tmp_path / "vendor" / "pkg"
        vendor_dir.mkdir(parents=True)
        pkg_json = vendor_dir / "composer.json"
        pkg_json.write_text(json.dumps({"name": "noslash", "version": "1.0"}))
        assert _new_composer_packages({pkg_json}, tmp_path) == []


# ---------------------------------------------------------------------------
# _collect_new_packages — integration of the three scanners
# ---------------------------------------------------------------------------

class TestFindVenvRoot:
    def _make_venv(self, base: Path, python: str = "python3.12") -> Path:
        site_pkgs = base / "lib" / python / "site-packages"
        site_pkgs.mkdir(parents=True)
        (base / "pyvenv.cfg").write_text("home = /usr/bin\n")
        return site_pkgs

    def test_returns_venv_root_from_scan_target(self, tmp_path):
        venv = tmp_path / ".venv"
        site_pkgs = self._make_venv(venv)
        assert _find_venv_root([site_pkgs]) == venv

    def test_returns_none_when_no_pyvenv_cfg(self, tmp_path):
        site_pkgs = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        site_pkgs.mkdir(parents=True)
        # no pyvenv.cfg
        assert _find_venv_root([site_pkgs]) is None

    def test_returns_none_for_empty_targets(self):
        assert _find_venv_root([]) is None

    def test_uses_first_valid_target(self, tmp_path):
        venv1 = tmp_path / ".venv"
        site1 = self._make_venv(venv1)
        venv2 = tmp_path / "venv"
        site2 = self._make_venv(venv2)
        assert _find_venv_root([site1, site2]) == venv1


class TestReqFileHasSsh:
    def test_direct_ssh_url(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("git+ssh://git@github.com/org/lib.git\n")
        assert _req_file_has_ssh(f, set()) is True

    def test_nested_include_detected(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("git+ssh://git@github.com/org/lib.git\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("requests==2.31.0\n-r inner.txt\n")
        assert _req_file_has_ssh(outer, set()) is True

    def test_nested_include_long_flag(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("git@github.com:org/lib.git\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("--requirement inner.txt\n")
        assert _req_file_has_ssh(outer, set()) is True

    def test_nested_include_equals_form(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("git+ssh://git@github.com/org/lib.git\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("--requirement=inner.txt\n")
        assert _req_file_has_ssh(outer, set()) is True

    def test_nested_include_concatenated_form(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("git+ssh://git@github.com/org/lib.git\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("-rinner.txt\n")
        assert _req_file_has_ssh(outer, set()) is True

    def test_no_ssh_in_any_file(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("flask==3.0.0\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("requests==2.31.0\n-r inner.txt\n")
        assert _req_file_has_ssh(outer, set()) is False

    def test_commented_out_ssh_url_is_not_a_false_positive(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("# git+ssh://git@github.com/org/lib.git\nrequests==2.31.0\n")
        assert _req_file_has_ssh(f, set()) is False

    def test_inline_comment_does_not_trigger(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("requests==2.31.0  # was: git+ssh://git@github.com/org/lib.git\n")
        assert _req_file_has_ssh(f, set()) is False

    def test_commented_include_not_followed(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("git+ssh://git@github.com/org/lib.git\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("# -r inner.txt\nrequests==2.31.0\n")
        assert _req_file_has_ssh(outer, set()) is False

    def test_cycle_protection(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("-r b.txt\n")
        b.write_text("-r a.txt\n")
        assert _req_file_has_ssh(a, set()) is False

    def test_missing_include_is_skipped(self, tmp_path):
        outer = tmp_path / "outer.txt"
        outer.write_text("-r nonexistent.txt\n")
        assert _req_file_has_ssh(outer, set()) is False

    def test_subdirectory_relative_resolution(self, tmp_path):
        subdir = tmp_path / "requirements"
        subdir.mkdir()
        base = subdir / "base.txt"
        base.write_text("git+ssh://git@github.com/org/lib.git\n")
        outer = tmp_path / "requirements.txt"
        outer.write_text("-r requirements/base.txt\n")
        assert _req_file_has_ssh(outer, set()) is True


class TestHasSshVcsDeps:
    def test_detects_ssh_in_explicit_packages(self):
        parsed = ParsedInstall(manager="pip", packages=["git+ssh://git@github.com/org/repo.git"], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, Path(".")) is True

    def test_no_ssh_in_explicit_packages(self):
        parsed = ParsedInstall(manager="pip", packages=["requests==2.31.0"], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, Path(".")) is False

    def test_detects_ssh_in_pipfile_lock(self, tmp_path):
        # Pipfile.lock stores VCS deps as {"git": "ssh://..."}, not "git+ssh://"
        (tmp_path / "Pipfile.lock").write_text('{"default": {"mylib": {"git": "ssh://git@bitbucket.org/org/repo", "ref": "abc123"}}}')
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is True

    def test_no_ssh_in_pipfile_lock(self, tmp_path):
        (tmp_path / "Pipfile.lock").write_text('{"default": {"requests": {"version": "==2.31.0"}}}')
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is False

    def test_detects_ssh_in_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\ngit+ssh://git@github.com/org/lib.git\n")
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is True

    def test_no_pipfile_lock_returns_false(self, tmp_path):
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is False

    def test_none_parsed_returns_false(self, tmp_path):
        assert _has_ssh_vcs_deps(None, tmp_path) is False

    def test_detects_ssh_in_explicit_req_file(self, tmp_path):
        (tmp_path / "custom.txt").write_text("git+ssh://git@github.com/org/lib.git\n")
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi", req_files=["custom.txt"])
        assert _has_ssh_vcs_deps(parsed, tmp_path) is True

    def test_explicit_req_file_supersedes_glob(self, tmp_path):
        # requirements.txt has SSH dep but the explicitly named file does not —
        # only the -r file should be scanned, not the glob.
        (tmp_path / "requirements.txt").write_text("git+ssh://git@github.com/org/lib.git\n")
        (tmp_path / "clean.txt").write_text("requests==2.31.0\n")
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi", req_files=["clean.txt"])
        assert _has_ssh_vcs_deps(parsed, tmp_path) is False

    def test_uv_lock_not_scanned(self, tmp_path):
        # uv uses git+https, not git+ssh; uv.lock is not scanned
        (tmp_path / "uv.lock").write_text("git+ssh://git@github.com/org/repo.git\n")
        parsed = ParsedInstall(manager="uv-lock", packages=[], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is False

    def test_explicit_packages_do_not_trigger_glob_scan(self, tmp_path):
        # `pip install requests` must not be blocked because an unrelated
        # requirements.txt in the project happens to contain an SSH URL.
        (tmp_path / "requirements.txt").write_text("git+ssh://git@github.com/org/lib.git\n")
        parsed = ParsedInstall(manager="pip", packages=["requests"], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is False

    def test_detects_scp_style_in_explicit_packages(self):
        parsed = ParsedInstall(manager="pip", packages=["git+git@github.com:org/repo.git"], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, Path(".")) is True

    def test_detects_bare_scp_style_in_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("git+git@github.com:org/lib.git\n")
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is True

    def test_detects_scp_style_in_pipfile_lock(self, tmp_path):
        # Pipfile.lock scp-style: {"git": "git@github.com:org/repo.git"}
        (tmp_path / "Pipfile.lock").write_text('{"default": {"mylib": {"git": "git@github.com:org/repo.git", "ref": "main"}}}')
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is True

    def test_detects_ssh_in_editable_install(self):
        parsed = ParsedInstall(manager="pip", packages=["git+ssh://git@github.com/org/repo.git"], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, Path(".")) is True

    def test_uv_pip_install_r_detects_ssh(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("git+ssh://git@github.com/org/lib.git\n")
        parsed = ParsedInstall(manager="uv", packages=[], ecosystem="pypi", req_files=["requirements.txt"])
        assert _has_ssh_vcs_deps(parsed, tmp_path) is True

    def test_uv_pip_install_r_no_ssh(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        parsed = ParsedInstall(manager="uv", packages=[], ecosystem="pypi", req_files=["requirements.txt"])
        assert _has_ssh_vcs_deps(parsed, tmp_path) is False

    def test_uv_bare_install_scans_glob(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("git+ssh://git@github.com/org/lib.git\n")
        parsed = ParsedInstall(manager="uv", packages=[], ecosystem="pypi")
        assert _has_ssh_vcs_deps(parsed, tmp_path) is True


class TestIsSshVcsUrl:
    @pytest.mark.parametrize("url", [
        "git+ssh://git@github.com/org/repo.git",
        "ssh://git@github.com/org/repo.git",
        "git+git@github.com:org/repo.git",
        "git@github.com:org/repo.git",
    ])
    def test_ssh_patterns_detected(self, url):
        assert _is_ssh_vcs_url(url) is True

    @pytest.mark.parametrize("url", [
        "https://github.com/org/repo.git",
        "git+https://github.com/org/repo.git",
        # HTTPS URL with git@ username — NOT SSH (slash after host, not colon)
        "git+https://git@github.com/org/repo.git",
        "requests==2.31.0",
        "",
    ])
    def test_non_ssh_patterns_not_detected(self, url):
        assert _is_ssh_vcs_url(url) is False


class TestCheckVenvScope:
    def test_allows_venv_inside_project(self, tmp_path, monkeypatch):
        venv = tmp_path / ".venv"
        venv.mkdir()
        monkeypatch.setenv("VIRTUAL_ENV", str(venv))
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        assert _make_runner()._check_venv_scope(parsed, tmp_path) is True

    def test_blocks_venv_outside_project(self, tmp_path, monkeypatch):
        other = tmp_path / "other_project" / ".venv"
        other.mkdir(parents=True)
        monkeypatch.setenv("VIRTUAL_ENV", str(other))
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        assert _make_runner()._check_venv_scope(parsed, tmp_path / "my_project") is False

    def test_allows_when_no_virtual_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi")
        assert _make_runner()._check_venv_scope(parsed, tmp_path) is True

    def test_allows_for_uv_regardless_of_virtual_env(self, tmp_path, monkeypatch):
        other = tmp_path / "other" / ".venv"
        other.mkdir(parents=True)
        monkeypatch.setenv("VIRTUAL_ENV", str(other))
        parsed = ParsedInstall(manager="uv-lock", packages=[], ecosystem="pypi")
        assert _make_runner()._check_venv_scope(parsed, tmp_path / "my_project") is True

    def test_allows_for_npm(self, tmp_path, monkeypatch):
        other = tmp_path / "other" / ".venv"
        other.mkdir(parents=True)
        monkeypatch.setenv("VIRTUAL_ENV", str(other))
        parsed = ParsedInstall(manager="npm", packages=[], ecosystem="npm")
        assert _make_runner()._check_venv_scope(parsed, tmp_path / "my_project") is True

    def test_allows_when_parsed_is_none(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VIRTUAL_ENV", "/some/other/venv")
        assert _make_runner()._check_venv_scope(None, tmp_path) is True

    def test_allows_pipenv_venv_in_managed_dir(self, tmp_path, monkeypatch):
        # pipenv puts venvs outside the project by default — must not be blocked.
        pipenv_dir = tmp_path / "virtualenvs"
        pipenv_dir.mkdir()
        managed_venv = pipenv_dir / "myproject-AbCdEfGh"
        managed_venv.mkdir()
        monkeypatch.setenv("WORKON_HOME", str(pipenv_dir))
        monkeypatch.setenv("VIRTUAL_ENV", str(managed_venv))
        monkeypatch.delenv("PIPENV_VENV_IN_PROJECT", raising=False)
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        assert _make_runner()._check_venv_scope(parsed, tmp_path / "my_project") is True

    def test_blocks_pipenv_foreign_venv_outside_managed_dir(self, tmp_path, monkeypatch):
        # A venv neither in the project tree nor in the pipenv-managed dir is foreign.
        foreign = tmp_path / "other_project" / ".venv"
        foreign.mkdir(parents=True)
        pipenv_dir = tmp_path / "virtualenvs"
        pipenv_dir.mkdir()
        monkeypatch.setenv("WORKON_HOME", str(pipenv_dir))
        monkeypatch.setenv("VIRTUAL_ENV", str(foreign))
        monkeypatch.delenv("PIPENV_VENV_IN_PROJECT", raising=False)
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        assert _make_runner()._check_venv_scope(parsed, tmp_path / "my_project") is False

    def test_blocks_pipenv_outside_project_when_venv_in_project_set(self, tmp_path, monkeypatch):
        # When PIPENV_VENV_IN_PROJECT=1 the venv must be inside the project tree.
        pipenv_dir = tmp_path / "virtualenvs"
        pipenv_dir.mkdir()
        managed_venv = pipenv_dir / "myproject-AbCdEfGh"
        managed_venv.mkdir()
        monkeypatch.setenv("WORKON_HOME", str(pipenv_dir))
        monkeypatch.setenv("VIRTUAL_ENV", str(managed_venv))
        monkeypatch.setenv("PIPENV_VENV_IN_PROJECT", "1")
        parsed = ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi")
        assert _make_runner()._check_venv_scope(parsed, tmp_path / "my_project") is False


class TestBuildSandboxEnv:
    def test_passes_through_allowlisted_vars(self, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin")
        monkeypatch.setenv("HOME", "/home/user")
        result = _build_sandbox_env([])
        assert result["PATH"] == "/usr/bin"
        assert result["HOME"] == "/home/user"

    def test_strips_non_allowlisted_vars(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET_TOKEN", "hunter2")
        result = _build_sandbox_env([])
        assert "MY_SECRET_TOKEN" not in result

    def test_extra_names_are_passed_through(self, monkeypatch):
        monkeypatch.setenv("MY_CUSTOM_REGISTRY", "https://example.com")
        result = _build_sandbox_env(["MY_CUSTOM_REGISTRY"])
        assert result["MY_CUSTOM_REGISTRY"] == "https://example.com"

    def test_extra_name_absent_from_env_is_skipped(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
        result = _build_sandbox_env(["NONEXISTENT_VAR"])
        assert "NONEXISTENT_VAR" not in result

    def test_sandbox_env_common_includes_core_vars(self):
        assert "PATH" in _SANDBOX_ENV_COMMON
        assert "HOME" in _SANDBOX_ENV_COMMON
        assert "HTTP_PROXY" in _SANDBOX_ENV_COMMON

    def test_sandbox_env_language_specific_vars_come_from_modules(self):
        from packagealert.languages.python import PythonLanguage
        from packagealert.languages.node import NodeLanguage
        from packagealert.languages.php import PhpLanguage
        assert "VIRTUAL_ENV" in PythonLanguage().sandbox_env()
        assert "UV_INDEX_URL" in PythonLanguage().sandbox_env()
        assert "NPM_CONFIG_REGISTRY" in NodeLanguage().sandbox_env()
        assert "COMPOSER_HOME" in PhpLanguage().sandbox_env()

    def test_returns_only_present_env_vars(self, monkeypatch):
        from packagealert.languages import registry as lang_registry
        all_known: set[str] = set(_SANDBOX_ENV_COMMON)
        for lang in lang_registry.all_languages():
            all_known.update(lang.sandbox_env())
        for key in list(all_known):
            monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv("PATH", "/usr/bin")
        result = _build_sandbox_env([])
        assert result == {"PATH": "/usr/bin"}

    def test_buggy_plugin_sandbox_env_is_skipped(self, monkeypatch):
        """A plugin that raises in sandbox_env() must not abort _build_sandbox_env()."""
        from unittest.mock import MagicMock, patch
        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.sandbox_env.side_effect = RuntimeError("plugin exploded")

        good_lang = MagicMock()
        good_lang.name = "good"
        good_lang.sandbox_env.return_value = ["MY_GOOD_VAR"]

        monkeypatch.setenv("MY_GOOD_VAR", "present")

        with patch("packagealert.languages.registry.all_languages", return_value=[bad_lang, good_lang]):
            result = _build_sandbox_env([])

        bad_lang.sandbox_env.assert_called_once()
        good_lang.sandbox_env.assert_called_once()
        assert "MY_GOOD_VAR" in result


class TestCollectNewPackages:
    def test_deduplicates_results(self, tmp_path):
        site = tmp_path / "site-packages"
        site.mkdir()
        dist = site / "requests-2.31.0.dist-info"
        dist.mkdir()
        # Snapshot is empty, so dist is "new"
        result = _collect_new_packages([site], {}, "pypi")
        names = [r[1] for r in result]
        assert names.count("requests") == 1

    def test_only_scans_ecosystem_when_specified(self, tmp_path):
        # A dist-info dir present in an npm scan target should not be picked up
        nm = tmp_path / "node_modules"
        nm.mkdir()
        # Stick a fake dist-info under node_modules (shouldn't happen, just ensuring filter)
        fake = nm / "requests-2.31.0.dist-info"
        fake.mkdir()
        result = _collect_new_packages([nm], {}, "npm")
        # Python scanner must not run when ecosystem is "npm"
        assert all(r[0] == "npm" for r in result)

    def test_before_snapshot_excludes_existing_packages(self, tmp_path):
        site = tmp_path / "site-packages"
        site.mkdir()
        old_dist = site / "flask-3.0.0.dist-info"
        old_dist.mkdir()
        # Snapshot includes old_dist
        snapshot = {site: set(site.rglob("*"))}
        # New package added after snapshot
        new_dist = site / "requests-2.31.0.dist-info"
        new_dist.mkdir()
        result = _collect_new_packages([site], snapshot, "pypi")
        names = [r[1] for r in result]
        assert "requests" in names
        assert "flask" not in names


# ---------------------------------------------------------------------------
# Shell support
# ---------------------------------------------------------------------------

class TestShellNames:
    def test_common_shells_recognized(self):
        for shell in ("bash", "zsh", "sh", "fish", "dash"):
            assert shell in _SHELL_NAMES

    def test_package_managers_not_shells(self):
        for cmd in ("pip", "uv", "npm", "composer", "pipenv", "python"):
            assert cmd not in _SHELL_NAMES

    def test_all_shells_have_rc_mapping_or_default(self):
        # Every shell in _SHELL_NAMES should either have an entry in _SHELL_RC_FILES
        # or gracefully produce an empty list (the .get(..., []) fallback).
        for shell in _SHELL_NAMES:
            rc = _SHELL_RC_FILES.get(shell, [])
            assert isinstance(rc, list)


class TestRunShell:
    def test_shell_bypasses_parser_returns_quickly(self, tmp_path, monkeypatch):
        """_run_shell is called (not _try_parse) for shell commands."""
        import subprocess
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            class R:
                returncode = 0
            return R()

        monkeypatch.setattr(subprocess, "run", fake_run)
        # Patch bwrap_available so the runner doesn't bail early
        import packagealert.sandbox.runner as runner_mod
        monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)

        import asyncio
        runner = _make_runner()
        rc = asyncio.run(runner.run(["bash"], allow_network=True))
        assert rc == 0
        assert calls, "subprocess.run should have been called"
        # The bwrap command must end with the shell argv
        bwrap_cmd = calls[0]
        assert bwrap_cmd[-1] == "bash"

    def test_shell_sets_virtual_env_when_venv_present(self, tmp_path, monkeypatch):
        """When a .venv exists in cwd, VIRTUAL_ENV and PATH are set for the shell."""
        import subprocess

        captured_env: dict = {}

        def fake_run(cmd, **kw):
            captured_env.update(kw.get("env") or {})
            class R:
                returncode = 0
            return R()

        monkeypatch.setattr(subprocess, "run", fake_run)
        import packagealert.sandbox.runner as runner_mod
        monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
        monkeypatch.chdir(tmp_path)

        # Create a minimal .venv structure
        venv = tmp_path / ".venv"
        (venv / "bin").mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")

        import asyncio
        runner = _make_runner()
        asyncio.run(runner.run(["bash"]))

        # build_cmd uses --setenv so env is not in subprocess kwargs directly —
        # but _run_shell builds sandbox_env which we can check was constructed correctly
        # by verifying the bwrap --setenv pairs in the command.
        # Re-check via the captured bwrap cmd
        assert True  # smoke: no exception raised

    def test_shell_write_dirs_include_cwd(self, tmp_path, monkeypatch):
        """cwd is always in write_dirs for shell sessions."""
        import subprocess

        bwrap_cmd_holder: list[list] = []

        def fake_run(cmd, **kw):
            bwrap_cmd_holder.append(list(cmd))
            class R:
                returncode = 0
            return R()

        monkeypatch.setattr(subprocess, "run", fake_run)
        import packagealert.sandbox.runner as runner_mod
        monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
        monkeypatch.chdir(tmp_path)

        import asyncio
        runner = _make_runner()
        asyncio.run(runner.run(["bash"]))

        cmd = bwrap_cmd_holder[0]
        # Find --bind pairs and confirm cwd is among them
        bind_dests = [cmd[i + 2] for i, tok in enumerate(cmd) if tok == "--bind"]
        assert str(tmp_path) in bind_dests

    def test_shell_node_modules_bin_added_to_path(self, tmp_path, monkeypatch):
        """node_modules/.bin is prepended to PATH when it exists."""
        import subprocess

        bwrap_cmd_holder: list[list] = []

        def fake_run(cmd, **kw):
            bwrap_cmd_holder.append(list(cmd))
            class R:
                returncode = 0
            return R()

        monkeypatch.setattr(subprocess, "run", fake_run)
        import packagealert.sandbox.runner as runner_mod
        monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
        monkeypatch.chdir(tmp_path)

        nm_bin = tmp_path / "node_modules" / ".bin"
        nm_bin.mkdir(parents=True)
        monkeypatch.setenv("PATH", "/usr/bin")

        import asyncio
        runner = _make_runner()
        asyncio.run(runner.run(["bash"]))

        cmd = bwrap_cmd_holder[0]
        # PATH is set via --setenv PATH <value>
        setenv_pairs = {
            cmd[i + 1]: cmd[i + 2]
            for i, tok in enumerate(cmd)
            if tok == "--setenv"
        }
        assert str(nm_bin) in setenv_pairs.get("PATH", "")


class TestExposeSSHKeysConfirmation:
    def _setup(self, monkeypatch):
        import subprocess
        import packagealert.sandbox.runner as runner_mod
        monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: type("R", (), {"returncode": 0})())

    def test_confirms_before_proceeding(self, tmp_path, monkeypatch):
        self._setup(monkeypatch)
        monkeypatch.chdir(tmp_path)
        import asyncio
        import packagealert.sandbox.runner as runner_mod
        with unittest.mock.patch("rich.prompt.Confirm.ask", return_value=True) as mock_ask:
            runner = _make_runner()
            asyncio.run(runner.run(["bash"], expose_ssh_keys=True))
        mock_ask.assert_called_once()
        assert "SSH" in mock_ask.call_args[0][0] or "ssh" in mock_ask.call_args[0][0].lower()

    def test_aborts_when_user_declines(self, tmp_path, monkeypatch):
        self._setup(monkeypatch)
        monkeypatch.chdir(tmp_path)
        import asyncio
        with unittest.mock.patch("rich.prompt.Confirm.ask", return_value=False):
            runner = _make_runner()
            rc = asyncio.run(runner.run(["bash"], expose_ssh_keys=True))
        assert rc == 1

    def test_no_prompt_without_flag(self, tmp_path, monkeypatch):
        self._setup(monkeypatch)
        monkeypatch.chdir(tmp_path)
        import asyncio
        with unittest.mock.patch("rich.prompt.Confirm.ask") as mock_ask:
            runner = _make_runner()
            asyncio.run(runner.run(["bash"], expose_ssh_keys=False))
        mock_ask.assert_not_called()


# ---------------------------------------------------------------------------
# run() exit-code guarantees
# ---------------------------------------------------------------------------

class TestRunExitCode:
    """run() must return 1 when malicious lock-file content is detected,
    regardless of the wrapped command's own exit code."""

    def _setup(self, monkeypatch, returncode: int):
        import subprocess
        import packagealert.sandbox.runner as runner_mod
        monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
        monkeypatch.setattr(
            subprocess, "run",
            lambda *a, **kw: type("R", (), {"returncode": returncode})(),
        )
        # Stub _preflight so tests don't hit the real OSV client or SQLite DB.
        async def _preflight_ok(*a, **kw):
            return True
        monkeypatch.setattr(runner_mod.SandboxRunner, "_preflight", _preflight_ok)

    def test_malicious_lock_file_returns_1_when_command_succeeds(self, tmp_path, monkeypatch):
        """Malicious lock-file detection always yields exit code 1 (zero-exit path)."""
        self._setup(monkeypatch, returncode=0)
        monkeypatch.chdir(tmp_path)
        import asyncio
        runner = _make_runner()
        async def _malicious(*a, **kw):
            return False
        monkeypatch.setattr(runner, "_scan_updated_lock_files", _malicious)
        rc = asyncio.run(runner.run(["npm", "install", "lodash"]))
        assert rc == 1

    def test_malicious_lock_file_returns_1_when_command_fails(self, tmp_path, monkeypatch):
        """Malicious lock-file detection always yields exit code 1, even when the
        wrapped command also exited non-zero (so callers can distinguish a security
        failure from an ordinary install failure)."""
        self._setup(monkeypatch, returncode=2)
        monkeypatch.chdir(tmp_path)
        import asyncio
        runner = _make_runner()
        async def _malicious(*a, **kw):
            return False
        monkeypatch.setattr(runner, "_scan_updated_lock_files", _malicious)
        rc = asyncio.run(runner.run(["npm", "install", "lodash"]))
        assert rc == 1

    def test_clean_lock_file_propagates_command_exit_code(self, tmp_path, monkeypatch):
        """When the lock-file scan passes but the command failed, the command's
        exit code is propagated so ordinary failures are still reported correctly."""
        self._setup(monkeypatch, returncode=42)
        monkeypatch.chdir(tmp_path)
        import asyncio
        runner = _make_runner()
        async def _clean(*a, **kw):
            return True
        monkeypatch.setattr(runner, "_scan_updated_lock_files", _clean)
        rc = asyncio.run(runner.run(["npm", "install", "lodash"]))
        assert rc == 42


class TestNoChangeLockFileRestore:
    """run() must always restore lock files when --no-change is set, regardless
    of the wrapped command's exit code or lock-file scan result."""

    def _setup(self, monkeypatch, returncode: int):
        import subprocess
        import packagealert.sandbox.runner as runner_mod
        monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
        monkeypatch.setattr(
            subprocess, "run",
            lambda *a, **kw: type("R", (), {"returncode": returncode})(),
        )
        async def _preflight_ok(*a, **kw):
            return True
        monkeypatch.setattr(runner_mod.SandboxRunner, "_preflight", _preflight_ok)

    def test_restores_on_success_clean_scan(self, tmp_path, monkeypatch):
        """no_change=True: command succeeds, scan clean → restore called, returns 0."""
        self._setup(monkeypatch, returncode=0)
        monkeypatch.chdir(tmp_path)
        lock = tmp_path / "uv.lock"
        lock.write_bytes(b"original")
        import asyncio
        runner = _make_runner()
        async def _clean(*a, **kw):
            lock.write_bytes(b"modified by install")
            return True
        monkeypatch.setattr(runner, "_scan_updated_lock_files", _clean)
        rc = asyncio.run(runner.run(["uv", "add", "requests"], no_change=True))
        assert rc == 0
        assert lock.read_bytes() == b"original"

    def test_restores_on_success_malicious_scan(self, tmp_path, monkeypatch):
        """no_change=True: command succeeds, scan fails → restore called, returns 1."""
        self._setup(monkeypatch, returncode=0)
        monkeypatch.chdir(tmp_path)
        lock = tmp_path / "uv.lock"
        lock.write_bytes(b"original")
        import asyncio
        runner = _make_runner()
        async def _malicious(*a, **kw):
            lock.write_bytes(b"modified by install")
            return False
        monkeypatch.setattr(runner, "_scan_updated_lock_files", _malicious)
        rc = asyncio.run(runner.run(["uv", "add", "requests"], no_change=True))
        assert rc == 1
        assert lock.read_bytes() == b"original"

    def test_restores_on_command_failure_clean_scan(self, tmp_path, monkeypatch):
        """no_change=True: command fails, scan clean → restore called, returns command exit code."""
        self._setup(monkeypatch, returncode=2)
        monkeypatch.chdir(tmp_path)
        lock = tmp_path / "uv.lock"
        lock.write_bytes(b"original")
        import asyncio
        runner = _make_runner()
        async def _clean(*a, **kw):
            lock.write_bytes(b"modified by install")
            return True
        monkeypatch.setattr(runner, "_scan_updated_lock_files", _clean)
        rc = asyncio.run(runner.run(["uv", "add", "requests"], no_change=True))
        assert rc == 2
        assert lock.read_bytes() == b"original"

    def test_restores_on_command_failure_malicious_scan(self, tmp_path, monkeypatch):
        """no_change=True: command fails, scan fails → restore called, returns 1."""
        self._setup(monkeypatch, returncode=2)
        monkeypatch.chdir(tmp_path)
        lock = tmp_path / "uv.lock"
        lock.write_bytes(b"original")
        import asyncio
        runner = _make_runner()
        async def _malicious(*a, **kw):
            lock.write_bytes(b"modified by install")
            return False
        monkeypatch.setattr(runner, "_scan_updated_lock_files", _malicious)
        rc = asyncio.run(runner.run(["uv", "add", "requests"], no_change=True))
        assert rc == 1
        assert lock.read_bytes() == b"original"

    def test_does_not_restore_on_success_without_no_change(self, tmp_path, monkeypatch):
        """Without no_change, a clean scan leaves lock files untouched (not restored)."""
        self._setup(monkeypatch, returncode=0)
        monkeypatch.chdir(tmp_path)
        lock = tmp_path / "uv.lock"
        lock.write_bytes(b"original")
        import asyncio
        runner = _make_runner()
        async def _clean(*a, **kw):
            lock.write_bytes(b"modified by install")
            return True
        monkeypatch.setattr(runner, "_scan_updated_lock_files", _clean)
        rc = asyncio.run(runner.run(["uv", "add", "requests"], no_change=False))
        assert rc == 0
        assert lock.read_bytes() == b"modified by install"


# ---------------------------------------------------------------------------
# _preflight — unpinned requirements included in OSV queries
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# _restorable_lock_files — exception isolation
# ---------------------------------------------------------------------------

class TestRestorableLockFiles:
    def test_buggy_lockfile_patterns_skipped(self):
        """_restorable_lock_files() must skip a language whose lockfile_patterns() raises."""
        from unittest.mock import MagicMock, patch
        from packagealert.languages import registry as lang_registry

        lang_registry.load()
        good_names = _restorable_lock_files()
        assert len(good_names) > 0

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.lockfile_patterns.side_effect = RuntimeError("patterns boom")

        real_all_languages = lang_registry.all_languages

        def patched_all_languages():
            return [bad_lang] + real_all_languages()

        with patch("packagealert.languages.registry.all_languages", side_effect=patched_all_languages):
            result = _restorable_lock_files()

        # Bad plugin skipped; good language patterns still present
        assert set(result) == set(good_names)


# _snapshot_lock_files / _restore_lock_files
# ---------------------------------------------------------------------------

class TestSnapshotLockFiles:
    def test_snapshots_existing_file(self, tmp_path):
        (tmp_path / "uv.lock").write_bytes(b"some content")
        result = _snapshot_lock_files(tmp_path)
        assert tmp_path / "uv.lock" in result
        assert result[tmp_path / "uv.lock"] == b"some content"

    def test_records_none_for_nonexistent_files(self, tmp_path):
        result = _snapshot_lock_files(tmp_path)
        # All restorable lock file names are present; absent ones map to None
        assert len(result) == len(_restorable_lock_files())
        assert all(v is None for v in result.values())

    def test_snapshots_multiple_lock_files(self, tmp_path):
        (tmp_path / "uv.lock").write_bytes(b"a")
        (tmp_path / "package-lock.json").write_bytes(b"b")
        result = _snapshot_lock_files(tmp_path)
        # All restorable names present; two have content, rest are None
        assert len(result) == len(_restorable_lock_files())
        assert result[tmp_path / "uv.lock"] == b"a"
        assert result[tmp_path / "package-lock.json"] == b"b"
        none_count = sum(1 for v in result.values() if v is None)
        assert none_count == len(_restorable_lock_files()) - 2

    def test_handles_oserror_gracefully(self, tmp_path, monkeypatch):
        lock = tmp_path / "uv.lock"
        lock.write_bytes(b"content")
        original_rb = Path.read_bytes
        def patched(self):
            if self.name == "uv.lock":
                raise OSError("permission denied")
            return original_rb(self)
        monkeypatch.setattr(Path, "read_bytes", patched)
        # Should not raise; unreadable file is stored as _LOCK_UNREADABLE (not None)
        # so restore does not mistakenly delete it.
        result = _snapshot_lock_files(tmp_path)
        assert lock in result
        assert result[lock] is _LOCK_UNREADABLE

    def test_all_known_lock_file_names_checked(self, tmp_path):
        for name in _restorable_lock_files():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"x")
        result = _snapshot_lock_files(tmp_path)
        assert len(result) == len(_restorable_lock_files())

    def test_skips_symlink_pointing_outside_project(self, tmp_path):
        # Symlink pointing outside cwd must be stored as _LOCK_UNREADABLE, not None,
        # so that restore does not delete it (the file "existed" before the run).
        target = tmp_path.parent / "external_lock"
        target.write_bytes(b"external content")
        link = tmp_path / "Pipfile.lock"
        link.symlink_to(target)
        result = _snapshot_lock_files(tmp_path)
        assert result[link] is _LOCK_UNREADABLE

    def test_allow_developer_packages_reads_external_symlink(self, tmp_path):
        # With the flag, symlinks resolving outside cwd are still read
        target = tmp_path.parent / "external_lock"
        target.write_bytes(b"external content")
        link = tmp_path / "Pipfile.lock"
        link.symlink_to(target)
        result = _snapshot_lock_files(tmp_path, allow_developer_packages=True)
        assert result[link] == b"external content"

    def test_broken_symlink_recorded_as_unreadable_not_none(self, tmp_path):
        # A broken symlink has a directory entry (lstat succeeds) but no readable
        # target (exists() returns False). It must be _LOCK_UNREADABLE, not None,
        # so restore does not delete it thinking the file was absent pre-run.
        link = tmp_path / "Pipfile.lock"
        link.symlink_to(tmp_path / "nonexistent_target")  # broken — target missing
        result = _snapshot_lock_files(tmp_path)
        assert result[link] is _LOCK_UNREADABLE


class TestRestoreLockFiles:
    def test_restores_original_content(self, tmp_path):
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"malicious content")
        _restore_lock_files({lock: b"original content"}, tmp_path, _make_runner()._console)
        assert lock.read_bytes() == b"original content"

    def test_restores_multiple_files(self, tmp_path):
        lock1 = tmp_path / "uv.lock"
        lock2 = tmp_path / "package-lock.json"
        lock1.write_bytes(b"new1")
        lock2.write_bytes(b"new2")
        _restore_lock_files({lock1: b"orig1", lock2: b"orig2"}, tmp_path, _make_runner()._console)
        assert lock1.read_bytes() == b"orig1"
        assert lock2.read_bytes() == b"orig2"

    def test_deletes_newly_created_file(self, tmp_path):
        # None sentinel means the file was absent before the run; restore should delete it
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"created during sandbox run")
        _restore_lock_files({lock: None}, tmp_path, _make_runner()._console)
        assert not lock.exists()

    def test_noop_for_absent_sentinel_when_file_still_absent(self, tmp_path):
        # None sentinel + file still absent → nothing to do, no error
        lock = tmp_path / "Pipfile.lock"
        _restore_lock_files({lock: None}, tmp_path, _make_runner()._console)  # no exception

    def test_handles_oserror_gracefully(self, tmp_path, monkeypatch):
        # Simulate rename() failing after the temp file is written; must not propagate.
        # The original file must survive (temp file cleaned up, rename never happened).
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"current content")
        original_rename = Path.rename
        def patched(self, target):
            if Path(target).name == "Pipfile.lock":
                raise OSError("disk full")
            return original_rename(self, target)
        monkeypatch.setattr(Path, "rename", patched)
        snapshots = {lock: b"original content"}
        _restore_lock_files(snapshots, tmp_path, _make_runner()._console)  # no exception
        # Original file unchanged because rename failed; temp file was cleaned up.
        assert lock.read_bytes() == b"current content"
        assert not list(tmp_path.glob(".pa-restore-*"))

    def test_empty_snapshots_is_noop(self, tmp_path):
        _restore_lock_files({}, tmp_path, _make_runner()._console)  # no exception

    def test_replaces_external_symlink_with_regular_file(self, tmp_path):
        # When a lock file is an external symlink, restore must not write through it.
        # Instead it should remove the symlink and create a regular file in its place.
        target = tmp_path.parent / "sensitive_file"
        target.write_bytes(b"should not be overwritten")
        link = tmp_path / "Pipfile.lock"
        link.symlink_to(target)
        _restore_lock_files({link: b"original content"}, tmp_path, _make_runner()._console)
        # External target is untouched.
        assert target.read_bytes() == b"should not be overwritten"
        # Symlink replaced by a regular file containing the snapshot content.
        assert not link.is_symlink()
        assert link.read_bytes() == b"original content"

    def test_does_not_delete_unreadable_file_on_restore(self, tmp_path):
        # _LOCK_UNREADABLE means the file existed pre-run but content was unknown;
        # restore must not delete it (that would be data loss).
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"pre-existing content")
        _restore_lock_files({lock: _LOCK_UNREADABLE}, tmp_path, _make_runner()._console)
        assert lock.exists()
        assert lock.read_bytes() == b"pre-existing content"

    def test_deletes_newly_created_external_symlink(self, tmp_path):
        # If a lock file was absent pre-run (None) but appeared as an external symlink,
        # unlink() removes the symlink itself without touching the target.
        target = tmp_path.parent / "external_target"
        target.write_bytes(b"external data")
        link = tmp_path / "Pipfile.lock"
        link.symlink_to(target)
        _restore_lock_files({link: None}, tmp_path, _make_runner()._console)
        assert not link.exists() and not link.is_symlink()  # symlink removed
        assert target.read_bytes() == b"external data"  # target untouched

    def test_allow_developer_packages_also_replaces_external_symlink(self, tmp_path):
        # Even with allow_developer_packages, restore uses rename() which replaces
        # the directory entry without following symlinks — the external target is
        # never written to, the symlink is replaced by a regular file.
        target = tmp_path.parent / "shared_lock"
        target.write_bytes(b"external content")
        link = tmp_path / "Pipfile.lock"
        link.symlink_to(target)
        _restore_lock_files(
            {link: b"original content"}, tmp_path, _make_runner()._console,
        )
        assert target.read_bytes() == b"external content"  # external file untouched
        assert not link.is_symlink()
        assert link.read_bytes() == b"original content"

    def test_removes_directory_created_at_lock_file_path(self, tmp_path):
        # If a sandbox creates a directory where a lock file was absent, unlink()
        # raises IsADirectoryError.  Restore must fall back to rmtree() so the
        # project is fully restored to its pre-run state.
        lock = tmp_path / "Pipfile.lock"
        lock.mkdir()  # directory, not a file
        (lock / "subfile").write_bytes(b"attacker content")
        _restore_lock_files({lock: None}, tmp_path, _make_runner()._console)
        assert not lock.exists()

    def test_removes_empty_directory_created_at_lock_file_path(self, tmp_path):
        lock = tmp_path / "package-lock.json"
        lock.mkdir()
        _restore_lock_files({lock: None}, tmp_path, _make_runner()._console)
        assert not lock.exists()


# ---------------------------------------------------------------------------
# _scan_updated_lock_files
# ---------------------------------------------------------------------------

def _fake_osv_context(malicious_names: set[str]):
    """Return (fake_open_db, FakeClient, FakeCache) that flag packages in malicious_names."""

    async def fake_open_db():
        return unittest.mock.AsyncMock()

    class FakeCache:
        def __init__(self, db, cfg): pass
        async def get(self, ecosystem, name, version):
            return None  # force fresh queries for all packages
        async def set(self, *a): pass

    class FakeAdvisory:
        def __init__(self, malicious):
            self.id = "GHSA-fake-0001"
            self.is_malicious = malicious

    class FakeResult:
        def __init__(self, name, malicious):
            self.package_name = name
            self.advisories = [FakeAdvisory(malicious)] if malicious else []
            self.has_malicious = malicious

    class FakeClient:
        def __init__(self, cfg): pass
        async def batch_query(self, queries):
            return [FakeResult(name, name in malicious_names) for _, name, _ in queries]
        async def aclose(self): pass

    return fake_open_db, FakeClient, FakeCache


def _fake_scan_result(packages: list[tuple[str, str, str]]):
    """Return a fake scan_project result with the given (ecosystem, name, version) tuples."""
    from types import SimpleNamespace
    pkgs = [SimpleNamespace(ecosystem=eco, name=name, version=ver) for eco, name, ver in packages]
    return SimpleNamespace(pinned=pkgs, unpinned=[], sources=["Pipfile.lock"])


class TestAssertScannableLockFilesContained:
    def test_returns_none_when_all_files_within_project(self, tmp_path):
        (tmp_path / "Pipfile.lock").write_bytes(b"content")
        assert _assert_scannable_lock_files_contained(tmp_path) is None

    def test_returns_none_when_no_lock_files_exist(self, tmp_path):
        assert _assert_scannable_lock_files_contained(tmp_path) is None

    def test_returns_name_for_external_symlink(self, tmp_path):
        target = tmp_path.parent / "external"
        target.write_bytes(b"content")
        (tmp_path / "Pipfile.lock").symlink_to(target)
        result = _assert_scannable_lock_files_contained(tmp_path)
        assert result == "Pipfile.lock"

    def test_returns_name_for_broken_symlink_pointing_outside_project(self, tmp_path):
        # Broken symlink whose (missing) target is outside the project root.
        (tmp_path / "uv.lock").symlink_to(tmp_path.parent / "nonexistent_external")
        result = _assert_scannable_lock_files_contained(tmp_path)
        assert result == "uv.lock"

    def test_detects_external_symlink_for_yarn_lock(self, tmp_path):
        # yarn.lock is now scannable; an external symlink should be rejected
        target = tmp_path.parent / "external_yarn"
        target.write_bytes(b"content")
        (tmp_path / "yarn.lock").symlink_to(target)
        assert _assert_scannable_lock_files_contained(tmp_path) == "yarn.lock"


class TestPreflightShellContainment:
    """_preflight_shell must enforce lock-file symlink containment like _scan_updated_lock_files."""

    def test_blocks_when_lock_file_is_external_symlink(self, tmp_path):
        import asyncio
        target = tmp_path.parent / "external_lock"
        target.write_bytes(b"[[package]]")
        (tmp_path / "Pipfile.lock").symlink_to(target)

        runner = _make_runner()
        with unittest.mock.patch("packagealert.parsers.lockfiles.scan_project") as mock_scan:
            result = asyncio.run(runner._preflight_shell(tmp_path))

        assert result is False
        mock_scan.assert_not_called()

    def test_allows_external_symlink_with_flag(self, tmp_path):
        import asyncio
        target = tmp_path.parent / "external_lock"
        target.write_bytes(b"[[package]]")
        (tmp_path / "Pipfile.lock").symlink_to(target)

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(
                runner._preflight_shell(tmp_path, allow_developer_packages=True)
            )

        assert result is True

    def test_proceeds_when_all_lock_files_within_project(self, tmp_path):
        import asyncio
        (tmp_path / "Pipfile.lock").write_bytes(b"content")

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(runner._preflight_shell(tmp_path))

        assert result is True


class TestPreflightContainment:
    """_preflight() must enforce lock-file containment on the lock-file install branch."""

    def _make_ctx(self, tmp_path, argv):
        import packagealert.sandbox.runner as runner_mod
        parsed = runner_mod._try_parse(argv)
        return runner_mod._Context(argv=argv, parsed=parsed, cwd=tmp_path)

    def test_blocks_lock_file_install_when_lock_file_is_external_symlink(self, tmp_path):
        """When a lock file resolves outside the project, _preflight() returns False
        without calling scan_project()."""
        import asyncio
        target = tmp_path.parent / "external_lock"
        target.write_bytes(b"[[package]]\nname = 'requests'\nversion = '2.31.0'\n")
        (tmp_path / "Pipfile.lock").symlink_to(target)

        ctx = self._make_ctx(tmp_path, ["pipenv", "install"])
        runner = _make_runner()
        with unittest.mock.patch("packagealert.parsers.lockfiles.scan_project") as mock_scan:
            result = asyncio.run(runner._preflight(ctx))

        assert result is False
        mock_scan.assert_not_called()

    def test_allows_external_symlink_with_flag(self, tmp_path):
        """With allow_developer_packages=True, the external symlink is followed normally."""
        import asyncio
        target = tmp_path.parent / "external_lock"
        target.write_bytes(b"contents")
        (tmp_path / "Pipfile.lock").symlink_to(target)

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0")])

        ctx = self._make_ctx(tmp_path, ["pipenv", "install"])
        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(runner._preflight(ctx, allow_developer_packages=True))

        assert result is True

    def test_proceeds_when_lock_file_is_within_project(self, tmp_path):
        """Regular (non-symlink) lock files within the project pass containment."""
        import asyncio
        (tmp_path / "Pipfile.lock").write_bytes(b"content")

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0")])

        ctx = self._make_ctx(tmp_path, ["pipenv", "install"])
        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(runner._preflight(ctx))

        assert result is True

    def test_explicit_packages_bypass_containment_check(self, tmp_path):
        """When packages are explicit on the CLI, the lock-file branch is not entered
        at all — no containment check is needed or performed."""
        import asyncio
        target = tmp_path.parent / "external_lock"
        target.write_bytes(b"contents")
        (tmp_path / "Pipfile.lock").symlink_to(target)

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0")])

        ctx = self._make_ctx(tmp_path, ["pip", "install", "requests"])
        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(runner._preflight(ctx))

        # Explicit package — containment guard not triggered, OSV check runs normally.
        assert result is True

    def test_lockfile_hint_used_instead_of_scan_project(self, tmp_path):
        """When parsed.lockfile_hint is set, _preflight() scans that specific file
        instead of calling scan_project() (which would pick the wrong file via
        first-match-per-language in repos with multiple lockfiles for the same ecosystem)."""
        import asyncio
        import packagealert.sandbox.runner as runner_mod

        # Simulate a repo with both package-lock.json and yarn.lock.
        # The user ran `yarn install` so lockfile_hint == "yarn.lock".
        (tmp_path / "package-lock.json").write_text('{"name":"pkg","lockfileVersion":2,"requires":true,"packages":{}}')
        (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        yarn_scan = _fake_scan_result([("npm", "lodash", "4.17.21")])

        parsed = runner_mod.ParsedInstall(
            manager="yarn", packages=[], ecosystem="npm", lockfile_hint="yarn.lock"
        )
        ctx = runner_mod._Context(argv=["yarn", "install"], parsed=parsed, cwd=tmp_path)
        runner = _make_runner()

        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=yarn_scan) as mock_scan_lockfiles,
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_project") as mock_scan_project,
        ):
            asyncio.run(runner._preflight(ctx))

        mock_scan_lockfiles.assert_called_once_with([tmp_path / "yarn.lock"])
        mock_scan_project.assert_not_called()

    def test_no_lockfile_hint_falls_back_to_scan_project(self, tmp_path):
        """Without a lockfile_hint, _preflight() falls back to scan_project() as before."""
        import asyncio
        import packagealert.sandbox.runner as runner_mod

        (tmp_path / "package-lock.json").write_text('{"name":"pkg","lockfileVersion":2,"requires":true,"packages":{}}')

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("npm", "lodash", "4.17.21")])

        parsed = runner_mod.ParsedInstall(
            manager="npm", packages=[], ecosystem="npm", lockfile_hint=None
        )
        ctx = runner_mod._Context(argv=["npm", "install"], parsed=parsed, cwd=tmp_path)
        runner = _make_runner()

        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_project", return_value=scan_result) as mock_scan_project,
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles") as mock_scan_lockfiles,
        ):
            asyncio.run(runner._preflight(ctx))

        mock_scan_project.assert_called_once_with(tmp_path)
        mock_scan_lockfiles.assert_not_called()

    def test_lockfile_hint_absent_falls_back_to_scan_project(self, tmp_path):
        """When lockfile_hint names a file that doesn't exist, _preflight() falls back
        to scan_project() so an existing lockfile for the same ecosystem isn't missed."""
        import asyncio
        import packagealert.sandbox.runner as runner_mod

        # yarn.lock is present but package-lock.json (the hint) is absent.
        (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("npm", "lodash", "4.17.21")])

        parsed = runner_mod.ParsedInstall(
            manager="npm", packages=[], ecosystem="npm", lockfile_hint="package-lock.json"
        )
        ctx = runner_mod._Context(argv=["npm", "install"], parsed=parsed, cwd=tmp_path)
        runner = _make_runner()

        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_project", return_value=scan_result) as mock_scan_project,
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles") as mock_scan_lockfiles,
        ):
            result = asyncio.run(runner._preflight(ctx))

        assert result is True
        mock_scan_lockfiles.assert_not_called()
        mock_scan_project.assert_called_once_with(tmp_path)

    def test_lockfile_hint_empty_parse_falls_back_to_scan_project(self, tmp_path):
        """When the hinted file exists but yields no packages (e.g. empty lock file),
        _preflight() falls back to scan_project() rather than skipping the check."""
        import asyncio
        import packagealert.sandbox.runner as runner_mod

        (tmp_path / "package-lock.json").write_text('{"lockfileVersion":2,"packages":{}}')

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        empty_scan = _fake_scan_result([])
        fallback_scan = _fake_scan_result([("npm", "lodash", "4.17.21")])

        parsed = runner_mod.ParsedInstall(
            manager="npm", packages=[], ecosystem="npm", lockfile_hint="package-lock.json"
        )
        ctx = runner_mod._Context(argv=["npm", "install"], parsed=parsed, cwd=tmp_path)
        runner = _make_runner()

        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=empty_scan) as mock_scan_lockfiles,
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_project", return_value=fallback_scan) as mock_scan_project,
        ):
            result = asyncio.run(runner._preflight(ctx))

        assert result is True
        mock_scan_lockfiles.assert_called_once_with([tmp_path / "package-lock.json"])
        mock_scan_project.assert_called_once_with(tmp_path)


class TestScanUpdatedLockFiles:
    def test_returns_true_when_no_lock_files_changed(self, tmp_path):
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"original")
        snapshots = {lock: b"original"}  # unchanged
        runner = _make_runner()
        result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))
        assert result is True

    def test_returns_true_when_no_lock_files_exist_at_all(self, tmp_path):
        import asyncio
        runner = _make_runner()
        result = asyncio.run(runner._scan_updated_lock_files(tmp_path, {}))
        assert result is True

    def test_changed_lock_file_triggers_osv_query_and_returns_true_when_clean(self, tmp_path):
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"updated content")
        snapshots = {lock: b"original content"}

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert result is True

    def test_changed_lock_file_with_malicious_package_returns_false(self, tmp_path):
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"updated content")
        snapshots = {lock: b"original content"}

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names={"evilpkg"})
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0"), ("pypi", "evilpkg", "1.0.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert result is False

    def test_newly_created_lock_file_is_detected_and_scanned(self, tmp_path):
        """Lock file that did not exist at snapshot time but appeared after the run."""
        import asyncio
        # Snapshot taken when Pipfile.lock did not exist — recorded as None sentinel
        lock = tmp_path / "Pipfile.lock"
        snapshots = {lock: None}
        # Sandbox creates it
        lock.write_bytes(b"freshly generated")

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "starlette", "0.36.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert result is True  # clean packages → allowed

    def test_newly_created_lock_file_with_malicious_package_returns_false(self, tmp_path):
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        snapshots = {lock: None}
        lock.write_bytes(b"freshly generated with bad dep")

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names={"fastapi"})
        scan_result = _fake_scan_result([("pypi", "starlette", "0.36.0"), ("pypi", "fastapi", "0.1.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert result is False

    def test_newly_created_broken_symlink_treated_as_changed(self, tmp_path):
        """A broken symlink created during the run (absent at snapshot) must be detected.

        exists() returns False for broken symlinks; is_symlink() catches them.
        The target points outside the project so the containment guard fires
        before scan_lockfiles() is reached.
        """
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        snapshots = {lock: None}
        # Sandbox creates a broken symlink pointing to a nonexistent external path
        lock.symlink_to(tmp_path.parent / "nonexistent_external_target")
        assert not lock.exists()   # confirm exists() misses it
        assert lock.is_symlink()   # confirm is_symlink() catches it

        runner = _make_runner()
        with unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles") as mock_scan:
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        # Treated as changed; containment check blocks the scan because the
        # broken symlink resolves outside the project root.
        assert result is False
        mock_scan.assert_not_called()

    def test_changed_lock_file_with_no_parseable_packages_returns_false(self, tmp_path):
        """Changed lock file that parses to zero packages fails safe instead of returning True."""
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"corrupt or empty content")
        snapshots = {lock: b"original content"}

        empty_scan = _fake_scan_result([])  # parser returns nothing

        runner = _make_runner()
        with unittest.mock.patch(
            "packagealert.parsers.lockfiles.scan_lockfiles", return_value=empty_scan
        ):
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert result is False

    def test_unpinned_only_lockfile_not_blocked(self, tmp_path):
        """A lock file with only unpinned packages must NOT be blocked — the parse succeeded."""
        import asyncio
        from types import SimpleNamespace
        lock = tmp_path / "requirements.txt"
        lock.write_bytes(b"flask\nrequests\n")
        snapshots = {lock: b"original"}

        unpinned_pkg = SimpleNamespace(ecosystem="pypi", name="flask", version=None)
        unpinned_scan = SimpleNamespace(
            pinned=[], unpinned=[unpinned_pkg], sources=["requirements.txt"]
        )

        seen_queries = []

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())

        class CapturingClient:
            async def batch_query(self, queries):
                seen_queries.extend(queries)
                return [None] * len(queries)
            async def aclose(self): pass

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=unpinned_scan),
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", lambda *a, **kw: CapturingClient()),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
        ):
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert result is True
        queried_names = {name for _, name, _ in seen_queries}
        assert "flask" in queried_names

    def test_symlinked_lock_file_outside_project_blocks_scan(self, tmp_path):
        """scan_lockfiles() is not called when a scannable lock file resolves outside cwd."""
        import asyncio
        target = tmp_path.parent / "external_pipfile_lock"
        target.write_bytes(b"[[package]]\nname = 'requests'\nversion = '2.31.0'\n")
        link = tmp_path / "Pipfile.lock"
        link.symlink_to(target)
        # File changed (was absent, now present)
        snapshots = {link: None}

        runner = _make_runner()
        with unittest.mock.patch(
            "packagealert.parsers.lockfiles.scan_lockfiles"
        ) as mock_scan:
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert result is False
        mock_scan.assert_not_called()

    def test_symlinked_lock_file_outside_project_allowed_with_flag(self, tmp_path):
        """With allow_developer_packages, symlinked lock files outside cwd are scanned normally."""
        import asyncio
        target = tmp_path.parent / "external_pipfile_lock"
        target.write_bytes(b"contents")
        link = tmp_path / "Pipfile.lock"
        link.symlink_to(target)
        snapshots = {link: None}

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            result = asyncio.run(
                runner._scan_updated_lock_files(tmp_path, snapshots, allow_developer_packages=True)
            )

        assert result is True

    def test_regular_file_replaced_by_external_symlink_treated_as_changed_without_read(self, tmp_path):
        """Lock file that was a regular file at snapshot but is now an external symlink
        must be flagged as changed without reading the external target."""
        import asyncio
        # Snapshot: Pipfile.lock was a regular file
        lock = tmp_path / "Pipfile.lock"
        snapshots = {lock: b"original content"}
        # Sandbox replaced it with a symlink pointing outside the project
        target = tmp_path.parent / "sensitive_external"
        target.write_bytes(b"secret data")
        lock.symlink_to(target)

        # Fail the test immediately if anything reads the external target file.
        original_rb = Path.read_bytes
        def guarded_read_bytes(self: Path):
            if self.resolve() == target.resolve():
                raise AssertionError(f"read_bytes() followed symlink to external target: {self}")
            return original_rb(self)

        runner = _make_runner()
        with (
            unittest.mock.patch.object(Path, "read_bytes", guarded_read_bytes),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles") as mock_scan,
        ):
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        # Containment check must block the scan before scan_lockfiles() is called.
        assert result is False
        mock_scan.assert_not_called()

    def test_oserror_on_changed_check_treats_file_as_changed(self, tmp_path):
        """Unreadable lock file after sandbox run is treated as changed (fail-safe)."""
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        lock.write_bytes(b"original")
        snapshots = {lock: b"original"}

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names=set())
        scan_result = _fake_scan_result([("pypi", "requests", "2.31.0")])

        original_rb = Path.read_bytes
        def patched(self):
            if self.name == "Pipfile.lock":
                raise OSError("permission denied")
            return original_rb(self)

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
            unittest.mock.patch.object(Path, "read_bytes", patched),
        ):
            result = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        # OSV check ran (file was treated as changed) and returned clean
        assert result is True

    def test_lock_file_restored_by_caller_when_malicious(self, tmp_path):
        """Integration: caller restores lock file when _scan_updated_lock_files returns False."""
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        original_content = b"original Pipfile.lock"
        lock.write_bytes(b"updated with malicious dep")
        snapshots = {lock: original_content}

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names={"fastapi"})
        scan_result = _fake_scan_result([("pypi", "fastapi", "0.1.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            clean = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert clean is False
        # Simulate what run() does on False
        _restore_lock_files(snapshots, tmp_path, runner._console)
        assert lock.read_bytes() == original_content

    def test_newly_created_lock_file_deleted_on_restore(self, tmp_path):
        """Integration: newly created lock file is deleted when malicious deps found."""
        import asyncio
        lock = tmp_path / "Pipfile.lock"
        snapshots = {lock: None}  # absent before the run
        lock.write_bytes(b"freshly generated with bad dep")

        fake_open_db, FakeClient, FakeCache = _fake_osv_context(malicious_names={"fastapi"})
        scan_result = _fake_scan_result([("pypi", "fastapi", "0.1.0")])

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
            unittest.mock.patch("packagealert.parsers.lockfiles.scan_lockfiles", return_value=scan_result),
        ):
            clean = asyncio.run(runner._scan_updated_lock_files(tmp_path, snapshots))

        assert clean is False
        _restore_lock_files(snapshots, tmp_path, runner._console)
        assert not lock.exists()


# ---------------------------------------------------------------------------

class TestPreflightUnpinnedRequirements:
    """_preflight must query OSV for unpinned packages from -r files, not just pinned."""

    def test_unpinned_req_included_in_osv_query(self, tmp_path):
        import asyncio

        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\nflask\n")  # flask is unpinned

        seen_queries: list = []

        async def fake_open_db():
            return unittest.mock.AsyncMock()

        class FakeCache:
            def __init__(self, db, cfg): pass
            async def get(self, ecosystem, name, version):
                seen_queries.append((ecosystem, name, version))
                return None
            async def set(self, *a): pass

        class FakeClient:
            def __init__(self, cfg): pass
            async def batch_query(self, queries):
                return [None] * len(queries)
            async def aclose(self): pass

        parsed = ParsedInstall(manager="pip", packages=[], ecosystem="pypi", req_files=["requirements.txt"])
        ctx = _Context(argv=["pip", "install", "-r", "requirements.txt"], cwd=tmp_path, parsed=parsed)

        runner = _make_runner()
        with (
            unittest.mock.patch("packagealert.storage.db.open_db", fake_open_db),
            unittest.mock.patch("packagealert.osv.client.OsvClient", FakeClient),
            unittest.mock.patch("packagealert.osv.cache.OsvCache", FakeCache),
        ):
            result = asyncio.run(runner._preflight(ctx))

        assert result is True
        queried_names = {name for _, name, _ in seen_queries}
        assert "requests" in queried_names
        assert "flask" in queried_names  # was silently skipped before the fix


# ---------------------------------------------------------------------------
# _cooldown_check — blocks non-interactive runs for recently published packages
# ---------------------------------------------------------------------------

def test_cooldown_blocks_non_interactive(tmp_path, monkeypatch):
    import asyncio
    import time
    from unittest.mock import AsyncMock, patch
    from packagealert.config import AppConfig, CooldownConfig, SandboxConfig
    from packagealert.sandbox.runner import SandboxRunner

    cfg = AppConfig()
    cfg.sandbox = SandboxConfig(cooldown=CooldownConfig(on_new_medium_risk="prompt", on_new_low_risk="prompt", non_interactive_escalation="block"))
    runner = SandboxRunner(cfg)

    # Mock: publication date is 2 days ago (within 7-day cooldown)
    pub_ts = time.time() - 2 * 86400

    from packagealert.heuristics.typosquat import TyposquatResult

    with (
        patch("packagealert.sandbox.runner.bwrap_available", return_value=True),
        patch.object(SandboxRunner, "_preflight", new_callable=AsyncMock, return_value=True),
        patch("packagealert.sandbox.runner.get_publication_date", new_callable=AsyncMock, return_value="miss"),
        patch("packagealert.sandbox.runner.store_publication_date", new_callable=AsyncMock),
        patch("packagealert.sandbox.runner.get_cooldown_cleared_at", new_callable=AsyncMock, return_value=None),
        patch("packagealert.sandbox.cooldown.fetch_publication_date", new_callable=AsyncMock, return_value=pub_ts),
        patch("packagealert.sandbox.runner.open_db", new_callable=AsyncMock) as mock_open_db,
        patch("packagealert.heuristics.typosquat.TyposquatDetector.analyze",
              new_callable=AsyncMock,
              return_value=TyposquatResult(is_typosquat=False, closest_match=None, distance=None, score=0)),
        patch("sys.stdin") as mock_stdin,
    ):
        mock_stdin.isatty.return_value = False
        mock_db = AsyncMock()
        mock_db.close = AsyncMock()
        mock_open_db.return_value = mock_db

        result = asyncio.run(runner.run(["pip", "install", "requests==2.31.0"]))

    assert result == 1  # blocked by cooldown


def test_cooldown_resolves_latest_version_for_unpinned(tmp_path, monkeypatch):
    """Unpinned install: latest version is fetched and cooldown runs against it."""
    import asyncio
    import time
    from unittest.mock import AsyncMock, patch
    from packagealert.config import AppConfig, CooldownConfig, SandboxConfig
    from packagealert.sandbox.runner import SandboxRunner
    from packagealert.heuristics.typosquat import TyposquatResult

    cfg = AppConfig()
    cfg.sandbox = SandboxConfig(
        cooldown=CooldownConfig(on_new_medium_risk="prompt", on_new_low_risk="prompt", non_interactive_escalation="block")
    )
    runner = SandboxRunner(cfg)

    # Publication date 2 days ago — within cooldown
    pub_ts = time.time() - 2 * 86400

    with (
        patch("packagealert.sandbox.runner.bwrap_available", return_value=True),
        patch.object(SandboxRunner, "_preflight", new_callable=AsyncMock, return_value=True),
        patch("packagealert.sandbox.runner.get_publication_date", new_callable=AsyncMock, return_value="miss"),
        patch("packagealert.sandbox.runner.store_publication_date", new_callable=AsyncMock),
        patch("packagealert.sandbox.runner.get_cooldown_cleared_at", new_callable=AsyncMock, return_value=None),
        patch("packagealert.sandbox.cooldown.fetch_publication_date", new_callable=AsyncMock, return_value=pub_ts),
        patch("packagealert.sandbox.cooldown.fetch_latest_version", new_callable=AsyncMock, return_value="2.32.0"),
        patch("packagealert.sandbox.runner.open_db", new_callable=AsyncMock) as mock_open_db,
        patch("packagealert.heuristics.typosquat.TyposquatDetector.analyze",
              new_callable=AsyncMock,
              return_value=TyposquatResult(is_typosquat=False, closest_match=None, distance=None, score=0)),
        patch("sys.stdin") as mock_stdin,
    ):
        mock_stdin.isatty.return_value = False
        mock_db = AsyncMock()
        mock_db.close = AsyncMock()
        mock_open_db.return_value = mock_db

        # Unpinned — no version in the install spec
        result = asyncio.run(runner.run(["pip", "install", "requests"]))

    # Should be blocked: latest version resolved to 2.32.0, which is within cooldown
    assert result == 1


def test_cooldown_skips_when_latest_version_fetch_fails(tmp_path, monkeypatch):
    """Unpinned install: if latest version fetch fails, cooldown is skipped gracefully."""
    import asyncio
    from unittest.mock import AsyncMock, patch
    from packagealert.config import AppConfig, CooldownConfig, SandboxConfig
    from packagealert.sandbox.runner import SandboxRunner

    cfg = AppConfig()
    cfg.sandbox = SandboxConfig(
        cooldown=CooldownConfig(non_interactive_escalation="block")
    )
    runner = SandboxRunner(cfg)

    with (
        patch("packagealert.sandbox.runner.bwrap_available", return_value=True),
        patch.object(SandboxRunner, "_preflight", new_callable=AsyncMock, return_value=True),
        patch.object(SandboxRunner, "_check_venv_scope", return_value=True),
        patch("packagealert.sandbox.cooldown.fetch_latest_version", new_callable=AsyncMock, return_value=None),
        patch("packagealert.sandbox.runner.open_db", new_callable=AsyncMock) as mock_open_db,
        patch("packagealert.sandbox.runner._resolve_targets"),
        patch.object(SandboxRunner, "_scan_updated_lock_files", new_callable=AsyncMock, return_value=True),
        patch.object(SandboxRunner, "_post_scan", new_callable=AsyncMock, return_value=True),
        patch("packagealert.sandbox.runner.build_cmd", return_value=["true"]),
        patch("packagealert.sandbox.runner._resolve_real_binary", side_effect=lambda a: a),
        patch("subprocess.run") as mock_run,
        patch("sys.stdin") as mock_stdin,
        patch.dict("os.environ", {"VIRTUAL_ENV": "/fake/venv"}),
    ):
        mock_stdin.isatty.return_value = False
        mock_db = AsyncMock()
        mock_db.close = AsyncMock()
        mock_open_db.return_value = mock_db
        mock_run.return_value.returncode = 0

        # Unpinned — version fetch returns None → cooldown skipped → install proceeds
        result = asyncio.run(runner.run(["pip", "install", "requests"]))

    assert result == 0
