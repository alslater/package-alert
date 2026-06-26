"""Tests for packagealert.project_config."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from packagealert.project_config import (
    ProjectRunConfig,
    ProjectRunConfigError,
    _is_world_writable,
    _path_is_trusted,
    find_project_run_config,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_toml(path: Path, content: str) -> Path:
    """Write *content* to *path* and return *path*."""
    path.write_text(textwrap.dedent(content))
    return path


# ---------------------------------------------------------------------------
# find_project_run_config — walk-up discovery
# ---------------------------------------------------------------------------

class TestFindProjectRunConfig:
    def test_finds_file_in_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(tmp_path)
        assert result is not None
        assert result.flags == "python:ssh-keys"

    def test_finds_file_in_parent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        subdir = tmp_path / "project" / "src"
        subdir.mkdir(parents=True)
        write_toml(tmp_path / "project" / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(subdir)
        assert result is not None
        assert result.flags == "python:ssh-keys"

    def test_closer_file_wins_over_ancestor(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        subdir = tmp_path / "project" / "src"
        subdir.mkdir(parents=True)
        write_toml(tmp_path / ".pa-run.toml", 'flags = "python:network"\n')
        write_toml(tmp_path / "project" / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(subdir)
        assert result is not None
        assert result.flags == "python:ssh-keys"

    def test_returns_none_when_no_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        subdir = tmp_path / "project"
        subdir.mkdir()
        result = find_project_run_config(subdir)
        assert result is None

    def test_stops_at_home_ceiling(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Place home at tmp_path/home; config only at tmp_path (above home)
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        write_toml(tmp_path / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(home)
        assert result is None

    def test_config_above_vcs_root_found_and_trusted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        repo = home / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        subdir = repo / "src" / "lib"
        subdir.mkdir(parents=True)
        # Config above the VCS root (at home level) — found and trusted
        write_toml(home / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(subdir)
        assert result is not None
        assert result.flags == "python:ssh-keys"
        assert result.trusted is True

    def test_vcs_root_itself_is_checked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        repo = home / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        subdir = repo / "src"
        subdir.mkdir()
        write_toml(repo / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(subdir)
        assert result is not None
        assert result.flags == "python:ssh-keys"

    def test_hg_root_config_above_found_and_trusted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        repo = home / "repo"
        repo.mkdir()
        (repo / ".hg").mkdir()
        subdir = repo / "src"
        subdir.mkdir()
        # Config above the .hg root — found and trusted
        write_toml(home / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(subdir)
        assert result is not None
        assert result.flags == "python:ssh-keys"
        assert result.trusted is True

    def test_outside_home_walk_stops_at_vcs_root(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # cwd is outside $HOME — walk must stop at the VCS root, not continue to filesystem root
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        outside = tmp_path / "srv" / "myrepo"
        outside.mkdir(parents=True)
        (outside / ".git").mkdir()
        subdir = outside / "src"
        subdir.mkdir()
        # Config placed above VCS root but still outside $HOME — must not be found
        write_toml(tmp_path / "srv" / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(subdir)
        assert result is None

    def test_outside_home_config_at_vcs_root_is_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Config AT the VCS root is still found (stop fires after checking the directory)
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        outside = tmp_path / "srv" / "myrepo"
        outside.mkdir(parents=True)
        (outside / ".git").mkdir()
        subdir = outside / "src"
        subdir.mkdir()
        write_toml(outside / ".pa-run.toml", 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(subdir)
        assert result is not None
        assert result.flags == "python:ssh-keys"
        assert result.trusted is False  # inside VCS root

    def test_symlink_config_skipped_and_walk_continues(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        subdir = tmp_path / "project"
        subdir.mkdir()
        # Symlink in subdir points to a real config at home level
        real_config = tmp_path / ".pa-run.toml"
        write_toml(real_config, 'flags = "python:ssh-keys"\n')
        (subdir / ".pa-run.toml").symlink_to(real_config)
        # The symlink should be skipped; the real file at tmp_path should be found
        result = find_project_run_config(subdir)
        assert result is not None
        assert result.source == real_config.resolve()

    def test_symlink_config_emits_warning(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        import logging
        monkeypatch.setenv("HOME", str(tmp_path))
        subdir = tmp_path / "project"
        subdir.mkdir()
        real_config = tmp_path / "real.toml"
        write_toml(real_config, "")
        (subdir / ".pa-run.toml").symlink_to(real_config)
        with caplog.at_level(logging.WARNING, logger="packagealert.project_config"):
            find_project_run_config(subdir)
        assert any("symlink" in r.message.lower() for r in caplog.records)

    def test_source_path_recorded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        config_path = tmp_path / ".pa-run.toml"
        write_toml(config_path, 'flags = "python:ssh-keys"\n')
        result = find_project_run_config(tmp_path)
        assert result is not None
        assert result.source == config_path.resolve()


# ---------------------------------------------------------------------------
# _load / parsing
# ---------------------------------------------------------------------------

class TestLoad:
    def test_empty_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", "")
        result = find_project_run_config(tmp_path)
        assert result == ProjectRunConfig(source=(tmp_path / ".pa-run.toml").resolve())

    def test_flags_string(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", 'flags = "python:ssh-keys,python:network"\n')
        result = find_project_run_config(tmp_path)
        assert result is not None
        assert result.flags == "python:ssh-keys,python:network"

    def test_env_list(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", 'env = ["MY_TOKEN", "REGISTRY"]\n')
        result = find_project_run_config(tmp_path)
        assert result is not None
        assert result.env == ["MY_TOKEN", "REGISTRY"]

    def test_env_single_string(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", 'env = "MY_TOKEN"\n')
        result = find_project_run_config(tmp_path)
        assert result is not None
        assert result.env == ["MY_TOKEN"]

    def test_no_network_true(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", "no_network = true\n")
        result = find_project_run_config(tmp_path)
        assert result is not None
        assert result.no_network is True

    def test_allow_external_lockfiles_true(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", "allow_external_lockfiles = true\n")
        result = find_project_run_config(tmp_path)
        assert result is not None
        assert result.allow_external_lockfiles is True

    def test_unknown_key_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", 'unknown_key = "oops"\n')
        with pytest.raises(ProjectRunConfigError) as exc_info:
            find_project_run_config(tmp_path)
        assert "unknown_key" in str(exc_info.value)

    def test_flags_wrong_type_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", "flags = 42\n")
        with pytest.raises(ProjectRunConfigError) as exc_info:
            find_project_run_config(tmp_path)
        assert "flags" in str(exc_info.value)

    def test_env_wrong_type_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", "env = 42\n")
        with pytest.raises(ProjectRunConfigError) as exc_info:
            find_project_run_config(tmp_path)
        assert "env" in str(exc_info.value)

    def test_no_network_wrong_type_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", 'no_network = "yes"\n')
        with pytest.raises(ProjectRunConfigError) as exc_info:
            find_project_run_config(tmp_path)
        assert "no_network" in str(exc_info.value)

    def test_invalid_toml_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        (tmp_path / ".pa-run.toml").write_text("this is not toml ][")
        with pytest.raises(ProjectRunConfigError):
            find_project_run_config(tmp_path)

    def test_error_includes_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        write_toml(tmp_path / ".pa-run.toml", 'bad_key = "x"\n')
        with pytest.raises(ProjectRunConfigError) as exc_info:
            find_project_run_config(tmp_path)
        assert ".pa-run.toml" in str(exc_info.value)
        assert exc_info.value.path == tmp_path / ".pa-run.toml"


# ---------------------------------------------------------------------------
# _is_world_writable
# ---------------------------------------------------------------------------

class TestIsWorldWritable:
    def test_normal_file_not_world_writable(self, tmp_path):
        f = tmp_path / "f"
        f.write_text("")
        f.chmod(0o644)
        assert _is_world_writable(f) is False

    def test_world_writable_file(self, tmp_path):
        f = tmp_path / "f"
        f.write_text("")
        f.chmod(0o646)
        assert _is_world_writable(f) is True

    def test_group_writable_not_world_writable(self, tmp_path):
        f = tmp_path / "f"
        f.write_text("")
        f.chmod(0o664)
        assert _is_world_writable(f) is False

    def test_oserror_returns_true(self, tmp_path):
        missing = tmp_path / "does_not_exist"
        assert _is_world_writable(missing) is True

    def test_sticky_bit_directory_not_world_writable(self, tmp_path):
        d = tmp_path / "sticky"
        d.mkdir()
        d.chmod(0o1777)  # world-writable + sticky (like /tmp)
        assert _is_world_writable(d) is False

    def test_world_writable_directory_without_sticky(self, tmp_path):
        d = tmp_path / "open"
        d.mkdir()
        d.chmod(0o777)
        assert _is_world_writable(d) is True

    def test_sticky_bit_has_no_effect_on_files(self, tmp_path):
        f = tmp_path / "f"
        f.write_text("")
        f.chmod(0o1002)  # world-writable + sticky bit set on a file
        assert _is_world_writable(f) is True


# ---------------------------------------------------------------------------
# _path_is_trusted
# ---------------------------------------------------------------------------

class TestPathIsTrusted:
    def test_clean_permissions_trusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        subdir = home / "dev"
        subdir.mkdir()
        f = subdir / ".pa-run.toml"
        f.write_text("")
        subdir.chmod(0o755)
        f.chmod(0o644)
        home.chmod(0o755)
        assert _path_is_trusted(f, home) is None

    def test_world_writable_file_untrusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        f = home / ".pa-run.toml"
        f.write_text("")
        f.chmod(0o646)
        home.chmod(0o755)
        assert _path_is_trusted(f, home) is not None

    def test_world_writable_containing_dir_untrusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        subdir = home / "dev"
        subdir.mkdir()
        f = subdir / ".pa-run.toml"
        f.write_text("")
        subdir.chmod(0o757)
        f.chmod(0o644)
        home.chmod(0o755)
        assert _path_is_trusted(f, home) is not None

    def test_world_writable_home_untrusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        f = home / ".pa-run.toml"
        f.write_text("")
        f.chmod(0o644)
        home.chmod(0o757)
        assert _path_is_trusted(f, home) is not None

    def test_world_writable_intermediate_dir_untrusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        mid = home / "mid"
        mid.mkdir()
        subdir = mid / "project"
        subdir.mkdir()
        f = subdir / ".pa-run.toml"
        f.write_text("")
        f.chmod(0o644)
        subdir.chmod(0o755)
        mid.chmod(0o757)
        home.chmod(0o755)
        assert _path_is_trusted(f, home) is not None

    def test_group_writable_is_trusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        f = home / ".pa-run.toml"
        f.write_text("")
        f.chmod(0o664)
        home.chmod(0o775)
        assert _path_is_trusted(f, home) is None


# ---------------------------------------------------------------------------
# TestTrustFlag — trust field set by find_project_run_config
# ---------------------------------------------------------------------------

class TestTrustFlag:
    def test_home_file_no_vcs_trusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        home.chmod(0o755)
        cfg_file = home / ".pa-run.toml"
        write_toml(cfg_file, "")
        cfg_file.chmod(0o644)
        result = find_project_run_config(home)
        assert result is not None and result.trusted is True

    def test_above_vcs_root_trusted(self, tmp_path, monkeypatch):
        # Config at dev/ is above the VCS root at dev/myrepo/; start from dev/
        # (outside the VCS root) so the walk reaches it and returns trusted=True.
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        home.chmod(0o755)
        dev = home / "dev"
        dev.mkdir()
        dev.chmod(0o755)
        cfg_file = dev / ".pa-run.toml"
        write_toml(cfg_file, "")
        cfg_file.chmod(0o644)
        repo = dev / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        result = find_project_run_config(dev)
        assert result is not None and result.trusted is True

    def test_at_vcs_root_untrusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        home.chmod(0o755)
        repo = home / "repo"
        repo.mkdir()
        repo.chmod(0o755)
        (repo / ".git").mkdir()
        cfg_file = repo / ".pa-run.toml"
        write_toml(cfg_file, "")
        cfg_file.chmod(0o644)
        result = find_project_run_config(repo)
        assert result is not None and result.trusted is False

    def test_below_vcs_root_untrusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        home.chmod(0o755)
        repo = home / "repo"
        repo.mkdir()
        repo.chmod(0o755)
        (repo / ".git").mkdir()
        subdir = repo / "src"
        subdir.mkdir()
        subdir.chmod(0o755)
        cfg_file = subdir / ".pa-run.toml"
        write_toml(cfg_file, "")
        cfg_file.chmod(0o644)
        result = find_project_run_config(subdir)
        assert result is not None and result.trusted is False

    def test_world_writable_file_above_vcs_root_untrusted(self, tmp_path, monkeypatch):
        # Start from dev/ (outside VCS root) so the walk reaches the config.
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        home.chmod(0o755)
        dev = home / "dev"
        dev.mkdir()
        dev.chmod(0o755)
        cfg_file = dev / ".pa-run.toml"
        write_toml(cfg_file, "")
        cfg_file.chmod(0o646)  # world-writable
        repo = dev / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        result = find_project_run_config(dev)
        assert result is not None and result.trusted is False

    def test_world_writable_dir_above_vcs_root_untrusted(self, tmp_path, monkeypatch):
        # Start from dev/ (outside VCS root) so the walk reaches the config.
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        home.chmod(0o755)
        dev = home / "dev"
        dev.mkdir()
        dev.chmod(0o757)  # world-writable dir
        cfg_file = dev / ".pa-run.toml"
        write_toml(cfg_file, "")
        cfg_file.chmod(0o644)
        repo = dev / "myrepo"
        repo.mkdir()
        (repo / ".git").mkdir()
        result = find_project_run_config(dev)
        assert result is not None and result.trusted is False

    def test_world_writable_logs_warning(self, tmp_path, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("HOME", str(tmp_path))
        home = tmp_path.resolve(strict=False)
        home.chmod(0o755)
        cfg_file = home / ".pa-run.toml"
        write_toml(cfg_file, "")
        cfg_file.chmod(0o646)  # world-writable
        with caplog.at_level(logging.WARNING, logger="packagealert.project_config"):
            result = find_project_run_config(home)
        assert result is not None and result.trusted is False
        assert any("world-writable" in r.message.lower() for r in caplog.records)

    def test_trusted_defaults_true_on_direct_construction(self):
        cfg = ProjectRunConfig(source=Path("/some/.pa-run.toml"))
        assert cfg.trusted is True
