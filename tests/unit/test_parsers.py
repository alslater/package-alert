import json
from pathlib import Path

import pytest

from packagealert.parsers.lockfiles import (
    _is_pylock_filename,
    collect_requirements_packages,
)
from packagealert.parsers.process_args import (
    parse_composer_args,
    parse_npm_args,
    parse_package_spec,
    parse_pip_args,
    parse_pnpm_args,
    parse_uv_args,
    parse_yarn_args,
)


def test_pip_install_single():
    result = parse_pip_args(["pip", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_install_with_version():
    result = parse_pip_args(["pip", "install", "requests==2.31.0"])
    assert result is not None
    assert result.packages == ["requests==2.31.0"]


def test_pip_install_multiple():
    result = parse_pip_args(["pip", "install", "requests", "flask", "django==4.0"])
    assert result is not None
    assert len(result.packages) == 3


def test_pip_non_install_passthrough():
    # Only install modifies the package set — everything else passes through directly.
    assert parse_pip_args(["pip", "list"]) is None
    assert parse_pip_args(["pip", "show", "requests"]) is None
    assert parse_pip_args(["pip", "freeze"]) is None
    assert parse_pip_args(["pip", "some-future-subcommand"]) is None


def test_pip_global_flags_before_install_subcommand():
    # Global flags before the subcommand must not prevent install detection.
    result = parse_pip_args(["pip", "-q", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]

    result = parse_pip_args(["pip", "--disable-pip-version-check", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]

    result = parse_pip_args(["pip", "-q", "--no-input", "install", "-r", "requirements.txt"])
    assert result is not None
    assert result.req_files == ["requirements.txt"]

    # Value-consuming flags must not cause the value to be mistaken for the subcommand.
    result = parse_pip_args(["pip", "--cache-dir", "/tmp/sjsh", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]

    result = parse_pip_args(["pip", "--cache-dir=/tmp/sjsh", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]

    # Boolean global flags must not consume the next token (which is the subcommand).
    result = parse_pip_args(["pip", "--isolated", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]

    result = parse_pip_args(["pip", "--no-deps", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_global_flags_before_non_install_subcommand():
    # Global flags before a non-install subcommand still pass through.
    assert parse_pip_args(["pip", "-q", "list"]) is None
    assert parse_pip_args(["pip", "--disable-pip-version-check", "show", "requests"]) is None
    assert parse_pip_args(["pip", "--cache-dir", "/tmp", "list"]) is None


def test_pip_install_from_requirements_parses_req_files():
    result = parse_pip_args(["pip", "install", "-r", "requirements.txt"])
    assert result is not None
    assert result.manager == "pip"
    assert result.packages == []
    assert result.req_files == ["requirements.txt"]


def test_pip_install_requirement_inline_concatenated():
    result = parse_pip_args(["pip", "install", "-rcustom.txt"])
    assert result is not None
    assert result.req_files == ["custom.txt"]


def test_pip_install_requirement_equals_form():
    result = parse_pip_args(["pip", "install", "--requirement=custom.txt"])
    assert result is not None
    assert result.req_files == ["custom.txt"]


def test_pip_install_editable_vcs_space_separated():
    result = parse_pip_args(["pip", "install", "-e", "git+ssh://git@github.com/org/repo.git"])
    assert result is not None
    assert result.packages == ["git+ssh://git@github.com/org/repo.git"]


def test_pip_install_editable_vcs_equals_form():
    result = parse_pip_args(["pip", "install", "--editable=git+ssh://git@github.com/org/repo.git"])
    assert result is not None
    assert result.packages == ["git+ssh://git@github.com/org/repo.git"]


def test_pip_install_editable_local_path_not_in_packages():
    # Local path editables are dropped from packages so _preflight falls
    # through to the lock-file scan rather than finding no OSV queries.
    result = parse_pip_args(["pip", "install", "-e", "."])
    assert result is not None
    assert result.packages == []


def test_pip_install_editable_absolute_path_not_in_packages():
    result = parse_pip_args(["pip", "install", "-e", "/home/user/myproject"])
    assert result is not None
    assert result.packages == []


def test_pip_install_editable_relative_path_not_in_packages():
    result = parse_pip_args(["pip", "install", "--editable=../sibling"])
    assert result is not None
    assert result.packages == []


class TestUvProjectSubcommands:
    """Parametrized coverage of uv add/remove positional extraction.

    `remove` never populates `packages`: removal is not an install, and
    letting the removed names flow into `packages` would make the
    risk/cooldown gates and OSV pre-flight query them as if they were about
    to be installed — see the `remove` branch in `parse_uv_args` and
    `TestUvRemoveNeverPopulatesQueries` below for the end-to-end regression
    coverage. Only `add` extracts positionals into `packages`.

    All cases assert manager=="uv-project".  Structural edge cases that need
    their own assertion (end-of-options marker, sync/lock empty packages) are
    kept as dedicated test methods below the parametrized matrix.
    """

    @pytest.mark.parametrize("argv_suffix,expected", [
        # --- basic positionals ---
        (["add", "httpx"],                                                        ["httpx"]),
        (["add", "httpx", "rich"],                                                ["httpx", "rich"]),
        # --- boolean flags stripped ---
        (["add", "--dev", "httpx"],                                               ["httpx"]),
        (["add", "httpx", "--dev"],                                               ["httpx"]),
        # --- value-consuming flags (space-separated form) ---
        (["add", "--index-url", "https://pypi.org/simple", "httpx"],             ["httpx"]),
        (["add", "httpx", "--extra", "security"],                                 ["httpx"]),
        (["add", "--group", "dev", "httpx"],                                      ["httpx"]),
        (["add", "--marker", "python_version>='3.11'", "httpx"],                  ["httpx"]),
        (["add", "-r", "requirements.txt", "httpx"],                              ["httpx"]),
        (["add", "--script", "myscript.py", "httpx"],                             ["httpx"]),
        (["add", "--upgrade-package", "rich", "httpx"],                           ["httpx"]),
        # --- equals-form flags (single token, value must not bleed) ---
        (["add", "--index-url=https://pypi.org/simple", "httpx"],                 ["httpx"]),
        # --- combined short flag (single token, no value consumed) ---
        (["add", "-p3.12", "httpx"],                                              ["httpx"]),
        # --- package sandwiched between flags ---
        (["add", "--dev", "httpx", "--index-url=https://pypi.org/simple"],        ["httpx"]),
    ])
    def test_packages_extracted(self, argv_suffix, expected):
        result = parse_uv_args(["uv"] + argv_suffix)
        assert result is not None
        assert result.manager == "uv-project"
        assert result.packages == expected

    @pytest.mark.parametrize("argv_suffix", [
        ["remove", "httpx"],
        ["remove", "httpx", "rich"],
        ["remove", "--dev", "httpx"],
        ["remove", "httpx", "--dev"],
        ["remove", "--package", "mylib", "httpx"],
        ["remove", "httpx", "--package", "mylib"],
        ["remove", "--group", "dev", "httpx"],
        ["remove", "--python=3.12", "httpx"],
        ["remove", "--", "httpx"],
    ])
    def test_remove_never_populates_packages(self, argv_suffix):
        # Removal is not an install: the removed names must never surface in
        # `packages`, regardless of how they're positioned among flags.
        result = parse_uv_args(["uv"] + argv_suffix)
        assert result is not None
        assert result.manager == "uv-project"
        assert result.packages == []
        assert result.is_lockfile_install is False

    def test_add_end_of_options_marker(self):
        # Tokens after -- are positionals even if they look like flags.
        result = parse_uv_args(["uv", "add", "--dev", "--", "httpx", "--not-a-flag"])
        assert result is not None
        assert result.manager == "uv-project"
        assert result.packages == ["httpx", "--not-a-flag"]

    def test_sync_returns_empty_packages(self):
        result = parse_uv_args(["uv", "sync"])
        assert result is not None
        assert result.manager == "uv-project"
        assert result.packages == []
        assert result.is_lockfile_install is True

    def test_lock_returns_empty_packages(self):
        result = parse_uv_args(["uv", "lock"])
        assert result is not None
        assert result.manager == "uv-project"
        assert result.packages == []

    def test_lock_is_not_a_lockfile_install(self):
        """REGRESSION: `uv lock` only regenerates uv.lock from pyproject.toml
        (a fresh resolution) — it installs nothing and doesn't even read the
        existing lock file. It was grouped with `sync` and marked
        is_lockfile_install=True, so the pre-flight gates scanned the
        current (about-to-be-replaced) uv.lock as if its contents were being
        installed."""
        result = parse_uv_args(["uv", "lock"])
        assert result is not None
        assert result.is_lockfile_install is False

    def test_add_req_files_captured(self):
        # -r/--requirements value must be recorded in req_files (not treated as a package).
        result = parse_uv_args(["uv", "add", "-r", "requirements.txt"])
        assert result is not None
        assert result.manager == "uv-project"
        assert result.req_files == ["requirements.txt"]
        assert result.packages == []

    def test_add_req_files_and_explicit_package(self):
        result = parse_uv_args(["uv", "add", "-r", "requirements.txt", "httpx"])
        assert result is not None
        assert result.req_files == ["requirements.txt"]
        assert result.packages == ["httpx"]

    def test_add_req_files_end_of_options_not_collected(self):
        # Values after -- are positionals, not flag values; req_files stops at --.
        result = parse_uv_args(["uv", "add", "--", "httpx"])
        assert result is not None
        assert result.req_files == []
        assert result.packages == ["httpx"]

    def test_add_req_files_equals_form(self):
        # --requirements=file.txt must populate req_files.
        result = parse_uv_args(["uv", "add", "--requirements=requirements.txt"])
        assert result is not None
        assert result.req_files == ["requirements.txt"]

    def test_add_req_files_concatenated_short(self):
        # -rrequirements.txt (no space) must populate req_files.
        result = parse_uv_args(["uv", "add", "-rrequirements.txt"])
        assert result is not None
        assert result.req_files == ["requirements.txt"]


def test_uv_non_install_recognised():
    # uv run and other non-install subcommands are recognised with no packages.
    result = parse_uv_args(["uv", "run", "python"])
    assert result is not None
    assert result.packages == []


def test_uv_tool_install_recognised():
    from pathlib import Path
    result = parse_uv_args(["uv", "tool", "install", "ruff"])
    assert result is not None
    assert result.packages == ["ruff"]
    uv_tools = Path.home() / ".local" / "share" / "uv" / "tools"
    assert any(p == uv_tools or p.is_relative_to(uv_tools) for p in result.extra_write_home_dirs)


def test_uv_tool_upgrade_recognised():
    from pathlib import Path
    result = parse_uv_args(["uv", "tool", "upgrade", "ruff"])
    assert result is not None
    uv_tools = Path.home() / ".local" / "share" / "uv" / "tools"
    assert any(p == uv_tools or p.is_relative_to(uv_tools) for p in result.extra_write_home_dirs)


def test_uv_tool_install_skips_python_flag_value():
    result = parse_uv_args(["uv", "tool", "install", "--python", "3.12", "ruff"])
    assert result is not None
    assert result.packages == ["ruff"]


def test_uv_tool_install_skips_short_python_flag_value():
    result = parse_uv_args(["uv", "tool", "install", "-p", "3.12", "ruff"])
    assert result is not None
    assert result.packages == ["ruff"]


def test_uv_tool_install_skips_with_flag_value():
    result = parse_uv_args(["uv", "tool", "install", "--with", "httpx", "ruff"])
    assert result is not None
    assert result.packages == ["ruff"]


def test_uv_tool_run_recognised():
    result = parse_uv_args(["uv", "tool", "run", "ruff", "check", "."])
    assert result is not None
    assert result.extra_write_home_dirs == []


def test_uv_tool_list_not_sandboxed():
    # uv tool list is a read-only query — must not be sandboxed.
    result = parse_uv_args(["uv", "tool", "list"])
    assert result is None


def test_uv_tool_dir_not_sandboxed():
    result = parse_uv_args(["uv", "tool", "dir"])
    assert result is None


def test_uv_tool_uninstall_not_sandboxed():
    result = parse_uv_args(["uv", "tool", "uninstall", "ruff"])
    assert result is None


def test_pipx_install_recognised():
    from pathlib import Path

    from packagealert.parsers.process_args import _pipx_home, parse_pipx_args
    result = parse_pipx_args(["pipx", "install", "httpie"])
    assert result is not None
    assert result.manager == "pipx"
    assert result.packages == ["httpie"]
    pipx_venvs = _pipx_home() / "venvs"
    assert any(p == pipx_venvs or p.is_relative_to(pipx_venvs) for p in result.extra_write_home_dirs)
    assert Path.home() / ".local" / "bin" in result.extra_write_home_dirs


def test_pipx_upgrade_recognised():
    from packagealert.parsers.process_args import _pipx_home, parse_pipx_args
    result = parse_pipx_args(["pipx", "upgrade", "httpie"])
    assert result is not None
    assert result.packages == ["httpie"]
    pipx_venvs = _pipx_home() / "venvs"
    assert any(p == pipx_venvs or p.is_relative_to(pipx_venvs) for p in result.extra_write_home_dirs)


def test_pipx_reinstall_recognised():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "reinstall", "httpie"])
    assert result is not None
    assert result.packages == ["httpie"]


def test_pipx_install_skips_python_flag_value():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "install", "--python", "3.12", "httpie"])
    assert result is not None
    assert result.packages == ["httpie"]


def test_pipx_inject_skips_python_flag_value():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "inject", "--python", "3.12", "httpie", "httpx"])
    assert result is not None
    assert result.target_env_name == "httpie"
    assert result.packages == ["httpx"]


def test_pipx_inject_recognised():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "inject", "httpie", "httpx"])
    assert result is not None
    assert result.packages == ["httpx"]
    assert result.target_env_name == "httpie"


def test_pipx_install_skips_spec_flag_value():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "install", "--spec", "httpie==3.2.1", "httpie"])
    assert result is not None
    assert result.packages == ["httpie"]


def test_pipx_list_not_sandboxed():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "list"])
    assert result is None


def test_pipx_run_not_sandboxed():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "run", "cowsay", "hello"])
    assert result is None


def test_pipx_uninstall_not_sandboxed():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "uninstall", "httpie"])
    assert result is None


def test_pipx_uninstall_all_not_sandboxed():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "uninstall-all"])
    assert result is None


def test_pipx_upgrade_all_sandboxed():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "upgrade-all"])
    assert result is not None
    assert result.manager == "pipx"
    assert result.packages == []
    assert result.extra_write_home_dirs  # venvs dir and bin are writable


def test_pipx_reinstall_all_sandboxed():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "reinstall-all"])
    assert result is not None
    assert result.packages == []
    assert result.extra_write_home_dirs


def test_pipx_install_all_sandboxed():
    from packagealert.parsers.process_args import parse_pipx_args
    result = parse_pipx_args(["pipx", "install-all"])
    assert result is not None
    assert result.packages == []
    assert result.extra_write_home_dirs


# --- _pipx_home() resolution ---

class TestPipxHomeResolution:
    def test_pipx_home_env_var_honoured(self, tmp_path, monkeypatch):
        from packagealert.parsers.process_args import _pipx_home
        target = tmp_path / ".local" / "mypipx"
        target.mkdir(parents=True)
        monkeypatch.setenv("PIPX_HOME", str(target))
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        assert _pipx_home() == target

    def test_pipx_home_env_var_honoured_when_not_yet_created(self, tmp_path, monkeypatch):
        """$PIPX_HOME that doesn't exist yet (first-use) must still be accepted if safe."""
        from packagealert.parsers.process_args import _pipx_home
        target = tmp_path / ".local" / "pipx-new"
        # Intentionally NOT created — pipx creates it on first use.
        monkeypatch.setenv("PIPX_HOME", str(target))
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        assert _pipx_home() == target

    def test_pipx_home_relative_env_var_returns_absolute(self, tmp_path, monkeypatch):
        """A relative $PIPX_HOME that resolves under $HOME must be returned as an absolute path."""
        from packagealert.parsers.process_args import _pipx_home
        # Put cwd inside tmp_path so the relative path resolves to a safe location.
        local_pipx = tmp_path / ".local" / "mypipx"
        local_pipx.mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("PIPX_HOME", ".local/mypipx")
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert result.is_absolute()

    def test_legacy_path_used_when_exists(self, tmp_path, monkeypatch):
        """~/.local/pipx exists → use it even if the XDG default is different."""
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.delenv("PIPX_HOME", raising=False)
        legacy = tmp_path / ".local" / "pipx"
        legacy.mkdir(parents=True)
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert result == legacy

    def test_xdg_default_when_no_legacy(self, tmp_path, monkeypatch):
        """No $PIPX_HOME, no legacy ~/.local/pipx → Linux default is XDG_DATA_HOME/pipx."""
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert result == tmp_path / ".local" / "share" / "pipx"

    def test_xdg_data_home_respected(self, tmp_path, monkeypatch):
        """XDG_DATA_HOME overrides the default data dir."""
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.delenv("PIPX_HOME", raising=False)
        xdg = tmp_path / "xdgdata"
        monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert result == xdg / "pipx"

    def test_xdg_data_home_relative_falls_back_to_default(self, tmp_path, monkeypatch):
        """Relative XDG_DATA_HOME must be rejected — it would resolve relative to cwd."""
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", "relative/xdg")
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert result == tmp_path / ".local" / "share" / "pipx"

    def test_xdg_data_home_relative_under_home_still_rejected(self, tmp_path, monkeypatch):
        """Relative XDG_DATA_HOME must be rejected even when cwd is under $HOME.

        resolve(strict=False) turns relative paths into absolute ones (relative to cwd).
        If cwd happens to be under $HOME the resolved path would pass is_relative_to($HOME),
        so we must check is_absolute() on the *raw* value before resolving.
        """
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.delenv("PIPX_HOME", raising=False)
        # "local/share" is relative — if cwd == tmp_path (our fake $HOME),
        # resolve() would produce tmp_path/"local"/"share", which IS under $HOME.
        monkeypatch.setenv("XDG_DATA_HOME", "local/share")
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        monkeypatch.chdir(tmp_path)
        result = _pipx_home()
        assert result == tmp_path / ".local" / "share" / "pipx"

    def test_xdg_data_home_outside_home_falls_back_to_default(self, tmp_path, monkeypatch):
        """XDG_DATA_HOME pointing outside $HOME must be rejected."""
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", "/tmp/attacker-xdg")
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert result == tmp_path / ".local" / "share" / "pipx"

    def test_pipx_home_dotdot_traversal_rejected(self, tmp_path, monkeypatch):
        """$PIPX_HOME with '..' that escapes home after normalisation must be rejected."""
        from packagealert.parsers.process_args import _pipx_home
        # ~/.local/../.ssh/pipx passes is_relative_to(home/".local") lexically but
        # normalises to ~/.ssh/pipx — outside all safe prefixes.
        traversal = str(tmp_path / ".local" / ".." / ".ssh" / "pipx")
        monkeypatch.setenv("PIPX_HOME", traversal)
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        result = _pipx_home()
        assert ".ssh" not in str(result)

    def test_xdg_data_home_dotdot_traversal_rejected(self, tmp_path, monkeypatch):
        """XDG_DATA_HOME with '..' that escapes home after normalisation must be rejected."""
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        # /home/user/../etc passes is_relative_to($HOME) lexically but resolves outside $HOME
        traversal = str(tmp_path) + "/../etc"
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", traversal)
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert "etc" not in str(result).split("/")[-3:]
        assert result == tmp_path / ".local" / "share" / "pipx"

    def test_dangerous_pipx_home_falls_back_to_default(self, tmp_path, monkeypatch):
        """$PIPX_HOME pointing outside ~/.local should be rejected and fall back."""
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.setenv("PIPX_HOME", "/etc/malicious")
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        result = _pipx_home()
        assert str(result) != "/etc/malicious"
        assert "malicious" not in str(result)

    @pytest.mark.parametrize("cred_dir", [".ssh", ".aws", ".gnupg", ".kube", ".docker"])
    def test_xdg_data_home_credential_dir_rejected(self, tmp_path, monkeypatch, cred_dir):
        """XDG_DATA_HOME pointing at a credential directory must be rejected."""
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / cred_dir))
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        monkeypatch.setattr("packagealert.sandbox.runner.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert cred_dir not in result.parts
        assert result == tmp_path / ".local" / "share" / "pipx"

    @pytest.mark.parametrize("cred_dir", [".ssh", ".aws", ".gnupg"])
    def test_xdg_data_home_subdir_of_credential_dir_rejected(self, tmp_path, monkeypatch, cred_dir):
        """XDG_DATA_HOME pointing inside a credential directory must also be rejected."""
        import sys
        if not sys.platform.startswith("linux"):
            pytest.skip("Linux-specific XDG default")
        from packagealert.parsers.process_args import _pipx_home
        monkeypatch.delenv("PIPX_HOME", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / cred_dir / "subdir"))
        monkeypatch.setattr("packagealert.parsers.process_args.Path.home", lambda: tmp_path)
        monkeypatch.setattr("packagealert.sandbox.runner.Path.home", lambda: tmp_path)
        result = _pipx_home()
        assert cred_dir not in result.parts
        assert result == tmp_path / ".local" / "share" / "pipx"


def test_npm_install_package():
    result = parse_npm_args(["npm", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


def test_npm_install_no_args_returns_empty():
    result = parse_npm_args(["npm", "install"])
    assert result is not None
    assert result.packages == []


def test_npm_non_install_returns_none():
    # npm run and other non-install subcommands return None so the daemon doesn't
    # treat them as install events and scan the lockfile unnecessarily.
    assert parse_npm_args(["npm", "run", "build"]) is None
    assert parse_npm_args(["npm", "test"]) is None
    assert parse_npm_args(["npm", "audit"]) is None


def test_npm_uninstall_defers_to_lockfile():
    # Removal subcommands mutate package-lock.json, so they must trigger lockfile scanning.
    for subcmd in ("uninstall", "remove", "rm", "un", "r"):
        result = parse_npm_args(["npm", subcmd, "lodash"])
        assert result is not None, f"npm {subcmd} should not return None"
        assert result.manager == "npm"
        assert result.packages == []


def test_npm_audit_fix_defers_to_lockfile():
    # `npm audit fix` can modify package-lock.json, so it must trigger lockfile scanning.
    result = parse_npm_args(["npm", "audit", "fix"])
    assert result is not None
    assert result.manager == "npm"
    assert result.packages == []


def test_npm_audit_without_fix_returns_none():
    # Plain `npm audit` is read-only.
    assert parse_npm_args(["npm", "audit"]) is None
    assert parse_npm_args(["npm", "audit", "--json"]) is None


def test_npm_ci_returns_empty_packages():
    result = parse_npm_args(["npm", "ci"])
    assert result is not None
    assert result.packages == []


def test_pip3_recognized():
    result = parse_pip_args(["pip3", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_uv_pip_install():
    result = parse_uv_args(["uv", "pip", "install", "numpy"])
    assert result is not None
    assert result.packages == ["numpy"]


def test_uv_pip_install_r_space_separated():
    result = parse_uv_args(["uv", "pip", "install", "-r", "requirements.txt"])
    assert result is not None
    assert result.packages == []
    assert result.req_files == ["requirements.txt"]


def test_uv_pip_install_r_concatenated():
    result = parse_uv_args(["uv", "pip", "install", "-rrequirements.txt"])
    assert result is not None
    assert result.req_files == ["requirements.txt"]


def test_uv_pip_install_requirement_equals_form():
    result = parse_uv_args(["uv", "pip", "install", "--requirement=custom.txt"])
    assert result is not None
    assert result.req_files == ["custom.txt"]


def test_uv_pip_install_editable_local_path_excluded():
    result = parse_uv_args(["uv", "pip", "install", "-e", "."])
    assert result is not None
    assert result.packages == []


def test_uv_pip_install_editable_vcs_included():
    result = parse_uv_args(["uv", "pip", "install", "-e", "git+ssh://git@github.com/org/repo.git"])
    assert result is not None
    assert result.packages == ["git+ssh://git@github.com/org/repo.git"]


def test_pip_config_settings_value_not_treated_as_package():
    # --config-settings editable_mode=strict must not be parsed as a package spec
    result = parse_pip_args([
        "pip", "install", "-e", "../../libs/graph",
        "--config-settings", "editable_mode=strict",
    ])
    assert result is not None
    assert result.packages == []


def test_pip_config_settings_short_flag_not_treated_as_package():
    result = parse_pip_args(["pip", "install", "requests", "-C", "editable_mode=compat"])
    assert result is not None
    assert result.packages == ["requests"]


def test_uv_pip_install_config_settings_value_not_treated_as_package():
    result = parse_uv_args([
        "uv", "pip", "install", "-e", "../../libs/graph",
        "--config-settings", "editable_mode=strict",
    ])
    assert result is not None
    assert result.packages == []


def test_uv_pip_install_config_setting_singular_value_not_treated_as_package():
    result = parse_uv_args([
        "uv", "pip", "install", "-e", "../../libs/graph",
        "--config-setting", "editable_mode=strict",
    ])
    assert result is not None
    assert result.packages == []


def test_pip_full_path_recognized():
    result = parse_pip_args(["/home/user/.venv/bin/pip", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


class TestUvPipSync:
    """REGRESSION (P1): `uv pip sync <SRC_FILE>...` installs the packages
    listed in the given requirements/pylock files (uv's own docs) — it used
    to fall through to the `("run", "python", ..., "pip", "venv")` catch-all
    (matched on `subcmd == "pip"` alone, without checking the sub-subcommand)
    and return an empty ParsedInstall with no req_files at all, so risk,
    cooldown, and OSV pre-flight all received zero queries for a real
    install."""

    def test_single_src_file_captured_as_req_file(self):
        result = parse_uv_args(["uv", "pip", "sync", "requirements.txt"])
        assert result is not None
        assert result.manager == "uv"
        assert result.req_files == ["requirements.txt"]
        assert result.packages == []

    def test_multiple_src_files_all_captured(self):
        result = parse_uv_args(["uv", "pip", "sync", "base.txt", "dev.txt"])
        assert result is not None
        assert result.req_files == ["base.txt", "dev.txt"]

    def test_constraints_flag_value_not_treated_as_src_file(self):
        result = parse_uv_args(["uv", "pip", "sync", "requirements.txt", "-c", "constraints.txt"])
        assert result is not None
        assert result.req_files == ["requirements.txt"]

    def test_constraints_long_flag_value_not_treated_as_src_file(self):
        result = parse_uv_args(["uv", "pip", "sync", "--constraints", "constraints.txt", "requirements.txt"])
        assert result is not None
        assert result.req_files == ["requirements.txt"]

    def test_boolean_flags_not_treated_as_src_files(self):
        result = parse_uv_args(["uv", "pip", "sync", "requirements.txt", "--require-hashes"])
        assert result is not None
        assert result.req_files == ["requirements.txt"]

    def test_no_index_before_src_file_does_not_consume_it(self):
        """REGRESSION (P1): `--no-index` is a boolean flag with no value of
        its own (uv's own docs) — it was wrongly listed among
        value-consuming flags, so `uv pip sync --no-index requirements.txt`
        treated "requirements.txt" as --no-index's argument and skipped it,
        producing req_files=[] and bypassing risk/cooldown/OSV checks
        entirely for a valid sync."""
        result = parse_uv_args(["uv", "pip", "sync", "--no-index", "requirements.txt"])
        assert result is not None
        assert result.req_files == ["requirements.txt"]

    def test_no_index_after_src_file_does_not_consume_next_token(self):
        result = parse_uv_args(["uv", "pip", "sync", "requirements.txt", "--no-index", "dev.txt"])
        assert result is not None
        assert result.req_files == ["requirements.txt", "dev.txt"]

    def test_should_gate_true_by_default(self):
        result = parse_uv_args(["uv", "pip", "sync", "requirements.txt"])
        assert result is not None
        assert result.should_gate is True

    def test_dry_run_should_not_gate(self):
        """`--dry-run` resolves dependencies and prints the plan without
        actually installing anything (uv's own docs)."""
        result = parse_uv_args(["uv", "pip", "sync", "requirements.txt", "--dry-run"])
        assert result is not None
        assert result.req_files == ["requirements.txt"]
        assert result.should_gate is False


class TestUvSystemPythonTarget:
    """REGRESSION (P1): `uv pip sync`/`uv pip install --system` (or the
    equivalent UV_SYSTEM_PYTHON env var) switches uv's own interpreter
    discovery from "searching in virtual environments" to "searching in
    search path or managed installations" — verified empirically (`uv pip
    sync -v`) that this explicitly ignores an active VIRTUAL_ENV. Without
    detecting this, `_discover_target_python_version` kept prioritizing
    VIRTUAL_ENV, so `uv pip sync --system pylock.toml` with an active venv
    evaluated packages.marker against the wrong (venv, not system) Python
    version entirely."""

    def test_pip_sync_system_flag_sets_is_system_python_target(self):
        result = parse_uv_args(["uv", "pip", "sync", "pylock.toml", "--system"])
        assert result is not None
        assert result.is_system_python_target is True

    def test_pip_install_system_flag_sets_is_system_python_target(self):
        result = parse_uv_args(["uv", "pip", "install", "--system", "requests"])
        assert result is not None
        assert result.is_system_python_target is True

    def test_no_system_flag_defaults_to_false(self):
        result = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
        assert result is not None
        assert result.is_system_python_target is False

    def test_uv_system_python_env_var_truthy_values(self, monkeypatch):
        """REGRESSION (P1): uv's complete boolean vocabulary for
        UV_SYSTEM_PYTHON, verified empirically against uv 0.12.2 (`uv pip
        sync -v` DEBUG output) — "1"/"true"/"yes"/"on"/"y"/"t" all switch
        interpreter discovery to system mode, case-insensitively. Only
        checking "1"/"true"/"yes" left "on"/"y"/"t" (and their case
        variants) undetected, so is_system_python_target stayed False and
        marker evaluation could fall back to an active venv instead of the
        system target for those forms."""
        for value in (
            "1", "true", "TRUE", "True", "yes", "Yes", "YES",
            "on", "On", "ON", "y", "Y", "t", "T",
        ):
            monkeypatch.setenv("UV_SYSTEM_PYTHON", value)
            result = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
            assert result is not None
            assert result.is_system_python_target is True, f"failed for {value!r}"

    def test_uv_system_python_env_var_falsy_values(self, monkeypatch):
        for value in (
            "0", "false", "False", "FALSE", "no", "No", "NO",
            "off", "Off", "OFF", "n", "N", "f", "F",
        ):
            monkeypatch.setenv("UV_SYSTEM_PYTHON", value)
            result = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
            assert result is not None
            assert result.is_system_python_target is False, f"failed for {value!r}"

    def test_uv_system_python_env_var_unset_defaults_to_false(self, monkeypatch):
        monkeypatch.delenv("UV_SYSTEM_PYTHON", raising=False)
        result = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
        assert result is not None
        assert result.is_system_python_target is False


class TestUvSyncShouldGate:
    """REGRESSION (P2): `uv sync --dry-run` performs a dry run "without
    writing the lockfile or modifying the project environment" (uv's own
    docs) — only `--check` was recognised as report-only, so `--dry-run`
    was still classified as gating a real install."""

    def test_dry_run_should_not_gate(self):
        result = parse_uv_args(["uv", "sync", "--dry-run"])
        assert result is not None
        assert result.is_lockfile_install is True
        assert result.should_gate is False

    def test_check_still_should_not_gate(self):
        result = parse_uv_args(["uv", "sync", "--check"])
        assert result is not None
        assert result.should_gate is False

    def test_bare_sync_should_gate(self):
        result = parse_uv_args(["uv", "sync"])
        assert result is not None
        assert result.should_gate is True


def test_pip3_full_path_recognized():
    result = parse_pip_args(["/usr/bin/pip3", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_python_m_pip_install():
    result = parse_pip_args(["python3", "-m", "pip", "install", "django"])
    assert result is not None
    assert result.packages == ["django"]


def test_python_full_path_m_pip_install():
    result = parse_pip_args(["/usr/bin/python3", "-m", "pip", "install", "numpy"])
    assert result is not None
    assert result.packages == ["numpy"]


def test_uv_full_path_recognized():
    result = parse_uv_args(["/home/user/.cargo/bin/uv", "add", "httpx"])
    assert result is not None
    assert result.packages == ["httpx"]


def test_npm_full_path_recognized():
    result = parse_npm_args(["/usr/local/bin/npm", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


# Windows .exe and Node *-cli.js normalisation tests

def test_pip_exe_recognized():
    result = parse_pip_args(["pip.exe", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_versioned_exe_recognized_windows():
    result = parse_pip_args(["pip3.12.exe", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_pip_windows_full_path_backslash():
    result = parse_pip_args([r"C:\Python\Scripts\pip.exe", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_npm_windows_full_path_backslash():
    result = parse_npm_args([r"C:\Program Files\nodejs\npm.exe", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


def test_npm_cli_js_recognized():
    result = parse_npm_args(["/usr/lib/node_modules/npm/bin/npm-cli.js", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


def test_npx_cli_js_recognized():
    # npx-cli.js is used by some Node.js distributions
    result = parse_npm_args(["npx-cli.js", "install"])
    assert result is None  # npx is not npm — should remain unrecognised by parse_npm_args


# Version-suffix normalisation tests

def test_pip_versioned_exe_recognized():
    result = parse_pip_args(["pip3.12", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_versioned_full_path_recognized():
    result = parse_pip_args(["/usr/bin/pip3.12", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_python_versioned_m_pip_recognized():
    result = parse_pip_args(["python3.11", "-m", "pip", "install", "django"])
    assert result is not None
    assert result.packages == ["django"]


def test_python_versioned_script_pip_recognized():
    result = parse_pip_args(["python3.11", "/usr/bin/pip3.12", "install", "numpy"])
    assert result is not None
    assert result.packages == ["numpy"]


def test_python_script_pip_install():
    # python /path/to/venv/bin/pip install <pkg>  — the exact pattern that was missed
    result = parse_pip_args([
        "/home/aslate/tmp/test/venv/bin/python",
        "/home/aslate/tmp/test/venv/bin/pip",
        "install",
        "opencv-python",
    ])
    assert result is not None
    assert result.packages == ["opencv-python"]


def test_python_flags_before_m_pip():
    # python -O -m pip install foo — flags precede -m pip
    result = parse_pip_args(["python3", "-O", "-m", "pip", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_python_multiple_flags_before_m_pip():
    result = parse_pip_args(["python3", "-W", "ignore", "-I", "-m", "pip", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_python_m_other_module_not_recognised():
    # python -m something_else should not be treated as pip
    result = parse_pip_args(["python3", "-m", "pytest", "tests/"])
    assert result is None


def test_python_script_args_not_misclassified():
    # python3 myscript.py -m pip install evil  — args to the script, not to python
    result = parse_pip_args(["python3", "myscript.py", "-m", "pip", "install", "evil"])
    assert result is None


def test_python_c_not_recognised():
    # python3 -c "..." should not be treated as pip
    result = parse_pip_args(["python3", "-c", "import pip; pip.main()"])
    assert result is None


def test_python_combined_short_flag_m_pip():
    # python3 -Wd -m pip install foo  — -Wd is -W default (combined form)
    result = parse_pip_args(["python3", "-Wd", "-m", "pip", "install", "foo"])
    assert result is not None
    assert result.packages == ["foo"]


def test_python_long_option_m_pip():
    # python3 --check-hash-based-pycs always -m pip install foo
    result = parse_pip_args(["python3", "--check-hash-based-pycs", "always", "-m", "pip", "install", "foo"])
    assert result is not None
    assert result.packages == ["foo"]


def test_python_long_option_equals_m_pip():
    # python3 --check-hash-based-pycs=always -m pip install foo
    result = parse_pip_args(["python3", "--check-hash-based-pycs=always", "-m", "pip", "install", "foo"])
    assert result is not None
    assert result.packages == ["foo"]


# ---------------------------------------------------------------------------
# parse_composer_args
# ---------------------------------------------------------------------------

class TestParseComposerArgs:
    # --- bare composer binary ---

    def test_require_single_package(self):
        result = parse_composer_args(["composer", "require", "vendor/pkg"])
        assert result is not None
        assert result.manager == "composer"
        assert result.ecosystem == "packagist"
        assert result.packages == ["vendor/pkg"]

    def test_require_multiple_packages(self):
        result = parse_composer_args(["composer", "require", "vendor/a", "vendor/b"])
        assert result is not None
        assert result.packages == ["vendor/a", "vendor/b"]

    def test_require_flags_stripped(self):
        result = parse_composer_args(["composer", "require", "--dev", "vendor/pkg", "--no-interaction"])
        assert result is not None
        assert result.packages == ["vendor/pkg"]

    def test_install_returns_empty_packages(self):
        result = parse_composer_args(["composer", "install"])
        assert result is not None
        assert result.manager == "composer"
        assert result.packages == []

    def test_update_returns_empty_packages(self):
        result = parse_composer_args(["composer", "update"])
        assert result is not None
        assert result.packages == []

    def test_upgrade_returns_empty_packages(self):
        result = parse_composer_args(["composer", "upgrade"])
        assert result is not None
        assert result.packages == []

    def test_full_path_composer(self):
        result = parse_composer_args(["/usr/local/bin/composer", "require", "vendor/pkg"])
        assert result is not None
        assert result.packages == ["vendor/pkg"]

    def test_non_install_subcommand_returns_none(self):
        for subcmd in ("dump-autoload", "show", "validate", "run-script", "diagnose", "search"):
            assert parse_composer_args(["composer", subcmd]) is None, (
                f"expected None for read-only composer {subcmd}"
            )

    def test_no_subcommand_ignored(self):
        assert parse_composer_args(["composer"]) is None

    def test_unrelated_binary_ignored(self):
        assert parse_composer_args(["pip", "install", "requests"]) is None
        assert parse_composer_args(["npm", "install"]) is None

    # --- php wrapper invocations ---

    def test_php_composer_phar_require(self):
        result = parse_composer_args(["php", "composer.phar", "require", "vendor/pkg"])
        assert result is not None
        assert result.packages == ["vendor/pkg"]

    def test_php8_composer_phar_install(self):
        result = parse_composer_args(["php8", "/path/to/composer.phar", "install"])
        assert result is not None
        assert result.packages == []

    def test_php7_composer_phar_require(self):
        result = parse_composer_args(["php7", "composer.phar", "require", "vendor/a"])
        assert result is not None
        assert result.packages == ["vendor/a"]

    def test_php_without_composer_in_script_name_ignored(self):
        assert parse_composer_args(["php", "other-script.php", "install"]) is None

    def test_php_no_second_arg_ignored(self):
        assert parse_composer_args(["php"]) is None

    # --- version-suffixed php executables ---

    def test_php_versioned_minor_composer_phar(self):
        result = parse_composer_args(["php8.2", "composer.phar", "require", "vendor/pkg"])
        assert result is not None
        assert result.packages == ["vendor/pkg"]

    def test_php_versioned_full_minor_install(self):
        result = parse_composer_args(["/usr/bin/php8.1", "/usr/local/bin/composer.phar", "install"])
        assert result is not None
        assert result.packages == []

    def test_php_versioned_major_only(self):
        # php8 (no minor) is also valid and was already supported; verify not broken
        result = parse_composer_args(["php8", "composer.phar", "require", "monolog/monolog"])
        assert result is not None
        assert result.packages == ["monolog/monolog"]

    def test_php_versioned_7x(self):
        result = parse_composer_args(["php7.4", "composer.phar", "install"])
        assert result is not None
        assert result.packages == []


# ---------------------------------------------------------------------------
# collect_requirements_packages
# ---------------------------------------------------------------------------


class TestCollectRequirementsPackages:
    def test_parses_pinned_packages(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("requests==2.31.0\nflask==3.0.0\n")
        pinned, _ = collect_requirements_packages(f)
        names = [p.name for p in pinned]
        assert "requests" in names
        assert "flask" in names

    def test_follows_nested_include(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("cryptography==42.0.0\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("requests==2.31.0\n-r inner.txt\n")
        pinned, _ = collect_requirements_packages(outer)
        names = [p.name for p in pinned]
        assert "requests" in names
        assert "cryptography" in names

    def test_follows_include_equals_form(self, tmp_path):
        inner = tmp_path / "inner.txt"
        inner.write_text("cryptography==42.0.0\n")
        outer = tmp_path / "outer.txt"
        outer.write_text("--requirement=inner.txt\n")
        pinned, _ = collect_requirements_packages(outer)
        assert any(p.name == "cryptography" for p in pinned)

    def test_cycle_protection(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("-r b.txt\nrequests==2.31.0\n")
        b.write_text("-r a.txt\nflask==3.0.0\n")
        pinned, _ = collect_requirements_packages(a)
        names = [p.name for p in pinned]
        assert "requests" in names
        assert "flask" in names

    def test_comments_ignored(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("# requests==1.0.0\nflask==3.0.0\n")
        pinned, _ = collect_requirements_packages(f)
        assert all(p.name != "requests" for p in pinned)
        assert any(p.name == "flask" for p in pinned)

    def test_missing_include_skipped(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("-r nonexistent.txt\nrequests==2.31.0\n")
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "requests" for p in pinned)

    def test_cross_directory_include(self, tmp_path):
        # requirements/base.txt includes ../root.txt — common monorepo pattern.
        # Requires passing the project root as allowed_root.
        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        root_req = tmp_path / "root.txt"
        root_req.write_text("flask==3.0.0\n")
        base = reqs_dir / "base.txt"
        base.write_text("-r ../root.txt\ncryptography==42.0.0\n")
        pinned, _ = collect_requirements_packages(base, allowed_root=tmp_path)
        names = {p.name for p in pinned}
        assert "flask" in names
        assert "cryptography" in names

    def test_shared_visited_deduplicates_across_roots(self, tmp_path):
        shared = tmp_path / "shared.txt"
        shared.write_text("requests==2.31.0\n")
        a = tmp_path / "a.txt"
        a.write_text("-r shared.txt\n")
        b = tmp_path / "b.txt"
        b.write_text("-r shared.txt\n")
        visited: set[Path] = set()
        pinned_a, _ = collect_requirements_packages(a, visited)
        pinned_b, _ = collect_requirements_packages(b, visited)
        # shared.txt is only processed once across both calls
        total = [p.name for p in pinned_a + pinned_b]
        assert total.count("requests") == 1

    def test_scheme_vcs_url_not_recorded_as_package(self, tmp_path):
        # git+https://... was matched by _UNPINNED_RE and recorded as name "git"
        f = tmp_path / "reqs.txt"
        f.write_text("git+https://github.com/org/repo.git\nrequests==2.31.0\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "git" not in all_names
        assert "requests" in [p.name for p in pinned]

    def test_ssh_vcs_url_not_recorded_as_package(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("git+ssh://git@github.com/org/repo.git\nflask==3.0.0\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "git" not in all_names
        assert "flask" in [p.name for p in pinned]

    def test_scp_style_vcs_not_recorded_as_package(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("git@github.com:org/repo.git\ndjango==4.2\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "git" not in all_names
        assert "django" in [p.name for p in pinned]

    def test_local_relative_path_not_recorded_as_package(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("./localpkg\n../otherpkg\nrequests==2.31.0\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "." not in all_names
        assert ".." not in all_names
        assert "requests" in [p.name for p in pinned]

    def test_absolute_path_not_recorded_as_package(self, tmp_path):
        f = tmp_path / "reqs.txt"
        f.write_text("/abs/path/pkg\nrequests==2.31.0\n")
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert not any(n.startswith("/") for n in all_names)
        assert "requests" in [p.name for p in pinned]


class TestIsPylockFilename:
    """REGRESSION (P1): dispatch to the pylock TOML parser must match PEP
    751's exact naming convention (pylock.toml or pylock.<name>.toml with a
    dot-free <name>), not merely a `.toml` suffix — `-r`/`--requirement`
    places no restriction on a requirements file's name or extension, so a
    file like "requirements.toml" must still be read as requirements.txt."""

    @pytest.mark.parametrize("name", [
        "pylock.toml",
        "pylock.dev.toml",
        "pylock.prod.toml",
        "pylock.test123.toml",
    ])
    def test_matches_pep751_names(self, name):
        assert _is_pylock_filename(name) is True

    @pytest.mark.parametrize("name", [
        "requirements.toml",
        "pyproject.toml",
        "uv.toml",
        "mypylock.toml",
        "pylock.toml.bak",
        "pylock.a.b.toml",
        "pylock..toml",
        "pylocktoml",
        "PYLOCK.TOML",
        "pylock.TOML",
    ])
    def test_rejects_non_pep751_names(self, name):
        assert _is_pylock_filename(name) is False


class TestCollectPylockPackages:
    """REGRESSION (P1): `uv pip sync`/`uv pip install` accept a PEP 751
    pylock.toml wherever a requirements.txt is accepted, but
    collect_requirements_packages read every .toml file line-by-line as if
    it were requirements.txt — TOML syntax like `name = "requests"` matched
    the same pinned/unpinned regexes used for requirements lines, producing
    bogus packages literally named "name"/"version"/"lock-version" while
    never surfacing the real packages at all."""

    # Trimmed excerpt of a real `uv pip compile --format pylock.toml` output.
    _REAL_PYLOCK_TOML = '''\
# This file was autogenerated by uv via the following command:
#    uv pip compile requirements.txt --universal --format pylock.toml -o pylock.toml
lock-version = "1.0"
created-by = "uv"
requires-python = ">=3.14"

[[packages]]
name = "certifi"
version = "2026.7.22"
sdist = { url = "https://files.pythonhosted.org/packages/a3/certifi-2026.7.22.tar.gz", hashes = { sha256 = "741e2c3b" } }

[[packages]]
name = "requests"
version = "2.31.0"
sdist = { url = "https://files.pythonhosted.org/packages/9d/requests-2.31.0.tar.gz", hashes = { sha256 = "942c5a75" } }
wheels = [{ url = "https://files.pythonhosted.org/packages/70/requests-2.31.0-py3-none-any.whl", hashes = { sha256 = "58cd2187" } }]
'''

    def test_real_pylock_toml_extracts_actual_packages(self, tmp_path):
        """The exact reported failure mode: before the fix, this file
        produced pinned=[] and unpinned=[name, version, ...] garbage."""
        f = tmp_path / "pylock.toml"
        f.write_text(self._REAL_PYLOCK_TOML)
        pinned, unpinned = collect_requirements_packages(f)
        names_versions = {(p.name, p.version) for p in pinned}
        assert ("certifi", "2026.7.22") in names_versions
        assert ("requests", "2.31.0") in names_versions
        assert unpinned == []

    def test_bogus_toml_key_names_not_recorded_as_packages(self, tmp_path):
        f = tmp_path / "pylock.toml"
        f.write_text(self._REAL_PYLOCK_TOML)
        pinned, unpinned = collect_requirements_packages(f)
        all_names = [p.name for p in pinned + unpinned]
        assert "name" not in all_names
        assert "version" not in all_names
        assert "lock-version" not in all_names
        assert "created-by" not in all_names

    def test_pylock_dev_toml_name_variant_also_parsed_as_toml(self, tmp_path):
        # PEP 751 also allows pylock.<name>.toml (e.g. pylock.dev.toml).
        f = tmp_path / "pylock.dev.toml"
        f.write_text(self._REAL_PYLOCK_TOML)
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "requests" and p.version == "2.31.0" for p in pinned)

    def test_package_without_version_is_unpinned(self, tmp_path):
        # A VCS/directory/archive-sourced entry has no PyPI version string.
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "mylocalpkg"\n'
            'directory = { path = "../mylocalpkg" }\n'
        )
        pinned, unpinned = collect_requirements_packages(f)
        assert pinned == []
        assert any(p.name == "mylocalpkg" and p.version is None for p in unpinned)

    def test_malformed_toml_does_not_raise(self, tmp_path):
        f = tmp_path / "pylock.toml"
        f.write_text("this is not valid toml [[[\n")
        pinned, unpinned = collect_requirements_packages(f)
        assert pinned == []
        assert unpinned == []

    def test_missing_toml_file_returns_empty(self, tmp_path):
        pinned, unpinned = collect_requirements_packages(tmp_path / "pylock.toml")
        assert pinned == []
        assert unpinned == []

    def test_requirements_txt_still_parsed_as_text_not_toml(self, tmp_path):
        # Regression guard: only a PEP 751 pylock filename is dispatched to
        # the pylock parser — a plain .txt file must still go through the
        # requirements.txt path.
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\n")
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "requests" and p.version == "2.31.0" for p in pinned)

    def test_requirements_toml_is_not_treated_as_pylock(self, tmp_path):
        """REGRESSION (P1 follow-up): dispatch was keyed on any `.toml`
        suffix, not the PEP 751 filename convention. `-r`/`--requirement`
        places no restriction on the requirements file's name or extension,
        so a real requirements file merely named "requirements.toml" was
        misrouted to the pylock parser (which found no [[packages]] table
        and returned zero packages), silently bypassing risk/cooldown/OSV
        checks for a valid `pip install -r requirements.toml`."""
        f = tmp_path / "requirements.toml"
        f.write_text("requests==2.31.0\nflask==3.0.0\n")
        pinned, _ = collect_requirements_packages(f)
        names_versions = {(p.name, p.version) for p in pinned}
        assert ("requests", "2.31.0") in names_versions
        assert ("flask", "3.0.0") in names_versions

    def test_similarly_named_toml_file_not_treated_as_pylock(self, tmp_path):
        # "mypylock.toml" / "pylock.toml.bak"-shaped names must not match —
        # only the exact PEP 751 convention should dispatch to the TOML parser.
        f = tmp_path / "mypylock.toml"
        f.write_text("requests==2.31.0\n")
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "requests" and p.version == "2.31.0" for p in pinned)

    def test_pylock_multi_dot_name_not_treated_as_pylock(self, tmp_path):
        # PEP 751 requires the <name> segment to be dot-free; "a.b" has a dot.
        f = tmp_path / "pylock.a.b.toml"
        f.write_text("requests==2.31.0\n")
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "requests" and p.version == "2.31.0" for p in pinned)


class TestCollectPylockPackagesMarkers:
    """REGRESSION (P1): PEP 751's installation algorithm requires "If
    packages.marker is specified, check if it is satisfied; if it isn't,
    skip to the next package." A universal (multi-platform) pylock.toml —
    the common case, e.g. `uv pip compile --universal` — routinely contains
    mutually-exclusive platform variants (verified against a real
    `uv pip compile --universal --format pylock.toml` run: a Windows-only
    dependency like colorama gets `marker = "sys_platform == 'win32'"`).
    Without evaluating packages.marker, every entry was queried regardless
    of platform, so a vulnerable Windows-only package could incorrectly
    block `uv pip sync` on Linux even though uv itself would never install
    it there. Markers below use conditions that are unambiguously
    true/false on every platform (python_version, a nonexistent platform
    name) so these tests are portable across CI runners."""

    def test_unsatisfied_marker_package_is_excluded(self, tmp_path):
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "windows-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "sys_platform == \'nonexistent-platform-xyz\'"\n'
        )
        pinned, unpinned = collect_requirements_packages(f)
        assert pinned == []
        assert unpinned == []

    def test_satisfied_marker_package_is_included(self, tmp_path):
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "always-present-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version >= \'3.0\'"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "always-present-pkg" and p.version == "1.0.0" for p in pinned)

    def test_package_without_marker_is_always_included(self, tmp_path):
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "unconditional-pkg"\n'
            'version = "1.0.0"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "unconditional-pkg" for p in pinned)

    def test_mixed_universal_lockfile_only_returns_satisfied_packages(self, tmp_path):
        """The exact scenario reported: a universal pylock with mutually
        exclusive platform variants must only surface the ones satisfied on
        this environment."""
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "cross-platform-pkg"\n'
            'version = "1.0.0"\n\n'
            '[[packages]]\n'
            'name = "windows-only-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "sys_platform == \'nonexistent-platform-xyz\'"\n\n'
            '[[packages]]\n'
            'name = "always-satisfied-pkg"\n'
            'version = "3.0.0"\n'
            'marker = "python_version >= \'3.0\'"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        names = {p.name for p in pinned}
        assert names == {"cross-platform-pkg", "always-satisfied-pkg"}
        assert "windows-only-pkg" not in names

    def test_malformed_marker_fails_open(self, tmp_path):
        """An unparseable marker must not silently drop the package — fail
        open (still scan it) rather than fail closed (silently skip a real
        dependency and lose OSV/risk coverage on it)."""
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "badmarker-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "this is not [[[ a valid marker"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "badmarker-pkg" and p.version == "1.0.0" for p in pinned)

    def test_undefined_comparison_marker_fails_open_instead_of_crashing(self, tmp_path):
        """REGRESSION (P2): `python_version ~= 'dog'` parses successfully as
        a well-formed marker (InvalidMarker is not raised), but evaluating
        it raises UndefinedComparison — packaging.markers.Marker.evaluate()
        applies `~=` to a value ('dog') that isn't a valid version, and its
        own docstring documents this as a distinct raise from
        UndefinedEnvironmentName. Only the latter was caught, so this
        scenario propagated uncaught and aborted the whole pylock scan
        (collect_requirements_packages and every caller) instead of failing
        open on the one malformed entry, exactly like any other
        unparseable marker."""
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "bad-comparison-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version ~= \'dog\'"\n\n'
            '[[packages]]\n'
            'name = "unaffected-pkg"\n'
            'version = "2.0.0"\n'
        )
        # Must not raise — this call crashing (instead of returning) is the
        # exact reported failure mode.
        pinned, _ = collect_requirements_packages(f)
        names_versions = {(p.name, p.version) for p in pinned}
        assert ("bad-comparison-pkg", "1.0.0") in names_versions
        assert ("unaffected-pkg", "2.0.0") in names_versions

    def test_unpinned_package_with_unsatisfied_marker_is_excluded(self, tmp_path):
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "windows-only-vcs-pkg"\n'
            'marker = "sys_platform == \'nonexistent-platform-xyz\'"\n'
            'directory = { path = "../winpkg" }\n'
        )
        pinned, unpinned = collect_requirements_packages(f)
        assert pinned == []
        assert unpinned == []

    def test_unselected_extra_marker_package_is_excluded(self, tmp_path):
        """REGRESSION (P2): PEP 751 requires evaluating packages.marker in
        the lock_file context, where `extras` defaults to the empty set
        (matching the spec's install algorithm default: "extras SHOULD be
        set to the empty set by default"). Evaluating with packaging's
        default "metadata" context instead left `extras`/`dependency_groups`
        undefined, so this marker raised UndefinedEnvironmentName and the
        fail-open handler incorrectly retained a package that a real `uv
        pip sync pylock.toml` (no --extra flag) would never install."""
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "dev-extra-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "\'dev\' in extras"\n'
        )
        pinned, unpinned = collect_requirements_packages(f)
        assert pinned == []
        assert unpinned == []

    def test_unselected_dependency_group_marker_package_is_excluded(self, tmp_path):
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "testing-group-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "\'testing\' in dependency_groups"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        assert pinned == []

    def test_package_without_extras_marker_is_still_included(self, tmp_path):
        # Control: an unconditional package alongside extras-gated ones must
        # still surface, confirming the fix doesn't over-exclude.
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "core-pkg"\n'
            'version = "2.0.0"\n\n'
            '[[packages]]\n'
            'name = "dev-extra-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "\'dev\' in extras"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        names = {p.name for p in pinned}
        assert names == {"core-pkg"}

    def test_nonstandard_singular_extra_marker_fails_open(self, tmp_path):
        """`extra == 'dev'` (PEP 508's singular, metadata-only variable) is
        not a valid lock_file-context marker per PEP 751 (which uses the
        plural, set-valued `extras`) — it still raises
        UndefinedEnvironmentName under context="lock_file" and must keep
        failing open (retained, not silently dropped) like any other
        unparseable/unresolvable marker."""
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "legacy-extra-marker-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "extra == \'dev\'"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "legacy-extra-marker-pkg" and p.version == "1.0.0" for p in pinned)

    def test_default_group_marker_package_is_included_on_bare_sync(self, tmp_path):
        """REGRESSION (P1): PEP 751's install algorithm requires
        "dependency_groups SHOULD be the set created from default-groups by
        default" — the top-level default-groups key (not a CLI flag)
        represents what a *bare* sync/install pulls in implicitly (the
        key's own doc: "meant to be used in situations where
        packages.marker necessitates such a group to exist"). Without
        seeding dependency_groups from it, a package marked e.g. `marker =
        "'runtime' in dependency_groups"` was omitted from every gate even
        though a bare `uv pip sync pylock.toml` (no --group flag at all)
        genuinely installs it — contradicting the documented claim that a
        bare sync is fully scanned."""
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n'
            'default-groups = ["runtime"]\n\n'
            '[[packages]]\n'
            'name = "runtime-group-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "\'runtime\' in dependency_groups"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        assert any(p.name == "runtime-group-pkg" and p.version == "1.0.0" for p in pinned)

    def test_non_default_group_marker_package_still_excluded(self, tmp_path):
        # A group named in default-groups is seeded; one that isn't must
        # still require an explicit --group selection (out of scope here).
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n'
            'default-groups = ["runtime"]\n\n'
            '[[packages]]\n'
            'name = "runtime-group-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "\'runtime\' in dependency_groups"\n\n'
            '[[packages]]\n'
            'name = "dev-group-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "\'dev\' in dependency_groups"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        names = {p.name for p in pinned}
        assert names == {"runtime-group-pkg"}

    def test_absent_default_groups_key_still_excludes_group_marker_package(self, tmp_path):
        # Regression guard: no default-groups key at all must still default
        # dependency_groups to the empty set, not silently include everything.
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "dev-group-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "\'dev\' in dependency_groups"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        assert pinned == []

    def test_malformed_default_groups_key_falls_back_to_empty_set(self, tmp_path):
        # A default-groups key that isn't an array of strings must not crash
        # or be trusted — fall back to packaging's own empty-set default.
        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n'
            'default-groups = "runtime"\n\n'
            '[[packages]]\n'
            'name = "runtime-group-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "\'runtime\' in dependency_groups"\n'
        )
        pinned, _ = collect_requirements_packages(f)
        assert pinned == []


class TestDiscoverTargetPythonVersion:
    """REGRESSION (P1): a bare `uv pip sync`/`uv pip install` (no
    --python/--python-version flag) does not target package-alert's own
    running interpreter — verified empirically against a real `uv` install
    (`uv pip sync -v`'s own DEBUG output: "Searching for default Python
    interpreter in virtual environments") to resolve, in order,
    VIRTUAL_ENV, then CONDA_PREFIX, then a `.venv` found by walking up from
    cwd. If package-alert runs under a different Python than that target —
    the common case whenever a project's `.venv` pins a version other than
    package-alert's own — a marker like `python_version == '3.12'` must be
    evaluated against the target's version, not package-alert's, or a real
    dependency the sync installs is silently excluded from every gate.

    Every test here explicitly monkeypatches VIRTUAL_ENV/CONDA_PREFIX
    (delenv'd first) since the pytest process itself may be running with
    its own VIRTUAL_ENV set — see feedback_test_patterns for the
    delenv-based env-var isolation this session already uses elsewhere.
    """

    def _write_pyvenv_cfg(self, venv_dir, *, version_info=None, version=None):
        venv_dir.mkdir(parents=True, exist_ok=True)
        lines = []
        if version_info is not None:
            lines.append(f"version_info = {version_info}")
        if version is not None:
            lines.append(f"version = {version}")
        (venv_dir / "pyvenv.cfg").write_text("\n".join(lines) + "\n")

    def _write_conda_meta(self, env_dir, *, python_version, build="h8ab3286_2_cpython", extra_packages=()):
        # Matches the real structure verified against a `micromamba create`
        # environment: no pyvenv.cfg at all, one JSON record per installed
        # package under conda-meta/, each with top-level name/version keys.
        import json

        meta_dir = env_dir / "conda-meta"
        meta_dir.mkdir(parents=True, exist_ok=True)
        (meta_dir / f"python-{python_version}-{build}.json").write_text(
            json.dumps({"name": "python", "version": python_version})
        )
        for name, version in extra_packages:
            (meta_dir / f"{name}-{version}-0.json").write_text(
                json.dumps({"name": name, "version": version})
            )

    def test_virtual_env_pyvenv_cfg_short_version_info_key(self, tmp_path, monkeypatch):
        # uv venv writes the short `version_info` key (e.g. "3.12").
        venv_dir = tmp_path / "target_venv"
        self._write_pyvenv_cfg(venv_dir, version_info="3.12")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py312-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.12\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        assert any(p.name == "py312-only-pkg" for p in pinned)

    def test_virtual_env_pyvenv_cfg_full_version_key(self, tmp_path, monkeypatch):
        # stdlib `venv` writes the full `version` key (e.g. "3.13.1").
        venv_dir = tmp_path / "target_venv"
        self._write_pyvenv_cfg(venv_dir, version="3.13.1")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py313-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.13\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        assert any(p.name == "py313-only-pkg" for p in pinned)

    def test_target_version_excludes_package_alert_own_version(self, tmp_path, monkeypatch):
        """The exact reported scenario: package-alert running under one
        Python (simulated here as 3.99, guaranteed not to match) while the
        target venv pins a different version (3.12) — a package gated on
        package-alert's own version must be excluded, since that is not
        what will actually be installed."""
        venv_dir = tmp_path / "target_venv"
        self._write_pyvenv_cfg(venv_dir, version_info="3.12")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "runs-on-3.12-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.12\'"\n\n'
            '[[packages]]\n'
            'name = "runs-on-3.99-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "python_version == \'3.99\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        names = {p.name for p in pinned}
        assert names == {"runs-on-3.12-pkg"}

    def test_conda_prefix_takes_precedence_when_virtual_env_absent(self, tmp_path, monkeypatch):
        conda_env = tmp_path / "conda_env"
        self._write_conda_meta(conda_env, python_version="3.11.15")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("CONDA_PREFIX", str(conda_env))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py311-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.11\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        assert any(p.name == "py311-only-pkg" for p in pinned)

    def test_virtual_env_takes_precedence_over_conda_prefix(self, tmp_path, monkeypatch):
        virtual_env_dir = tmp_path / "venv_target"
        conda_dir = tmp_path / "conda_target"
        self._write_pyvenv_cfg(virtual_env_dir, version_info="3.12")
        self._write_conda_meta(conda_dir, python_version="3.11.15")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(virtual_env_dir))
        monkeypatch.setenv("CONDA_PREFIX", str(conda_dir))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py312-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.12\'"\n\n'
            '[[packages]]\n'
            'name = "py311-only-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "python_version == \'3.11\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        names = {p.name for p in pinned}
        assert names == {"py312-only-pkg"}

    def test_local_venv_discovered_by_walking_up_from_cwd(self, tmp_path, monkeypatch):
        project_dir = tmp_path / "project"
        self._write_pyvenv_cfg(project_dir / ".venv", version_info="3.12")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)

        f = project_dir / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py312-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.12\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=project_dir)
        assert any(p.name == "py312-only-pkg" for p in pinned)

    def test_local_venv_discovered_from_a_subdirectory(self, tmp_path, monkeypatch):
        project_dir = tmp_path / "project"
        subdir = project_dir / "subdir"
        subdir.mkdir(parents=True)
        self._write_pyvenv_cfg(project_dir / ".venv", version_info="3.12")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)

        f = subdir / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py312-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.12\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=subdir)
        assert any(p.name == "py312-only-pkg" for p in pinned)

    def test_virtual_env_takes_precedence_over_local_venv(self, tmp_path, monkeypatch):
        project_dir = tmp_path / "project"
        self._write_pyvenv_cfg(project_dir / ".venv", version_info="3.12")
        env_venv = tmp_path / "active_env"
        self._write_pyvenv_cfg(env_venv, version_info="3.13")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(env_venv))

        f = project_dir / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py313-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.13\'"\n\n'
            '[[packages]]\n'
            'name = "py312-only-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "python_version == \'3.12\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=project_dir)
        names = {p.name for p in pinned}
        assert names == {"py313-only-pkg"}

    def test_no_venv_discoverable_anywhere_leaves_marker_environment_unset(self, tmp_path, monkeypatch):
        # No VIRTUAL_ENV/CONDA_PREFIX, no .venv anywhere under tmp_path —
        # must not crash, and must fall back to evaluating without a
        # python_version override (package-alert's own interpreter).
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "unconditional-pkg"\n'
            'version = "1.0.0"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        assert any(p.name == "unconditional-pkg" for p in pinned)

    def test_malformed_pyvenv_cfg_falls_back_gracefully(self, tmp_path, monkeypatch):
        venv_dir = tmp_path / "broken_venv"
        venv_dir.mkdir()
        (venv_dir / "pyvenv.cfg").write_text("not a valid = key = value line\ngarbage\n")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "unconditional-pkg"\n'
            'version = "1.0.0"\n'
        )
        # Must not raise despite the malformed pyvenv.cfg.
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        assert any(p.name == "unconditional-pkg" for p in pinned)

    def test_conda_prefix_read_from_conda_meta_not_pyvenv_cfg(self, tmp_path, monkeypatch):
        """REGRESSION (P1): a real conda/mamba environment has no
        pyvenv.cfg at all (verified against a `micromamba create -p ./env
        python=3.11` environment) — its Python version instead lives in
        conda-meta/python-<version>-<build>.json. The discovery function
        used to call the venv-only pyvenv.cfg reader for CONDA_PREFIX too,
        so an active conda environment's version was never actually read."""
        conda_env = tmp_path / "conda_env"
        self._write_conda_meta(conda_env, python_version="3.11.15")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("CONDA_PREFIX", str(conda_env))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py311-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.11\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        assert any(p.name == "py311-only-pkg" for p in pinned)

    def test_conda_meta_python_dateutil_not_mistaken_for_interpreter(self, tmp_path, monkeypatch):
        """A conda-forge package literally named `python-dateutil` (a real,
        common package) produces a conda-meta/python-*.json file too — the
        filename alone must not be trusted; only a record whose own "name"
        field is exactly "python" may supply the interpreter version."""
        conda_env = tmp_path / "conda_env"
        self._write_conda_meta(
            conda_env, python_version="3.11.15",
            extra_packages=[("python-dateutil", "2.9.0")],
        )
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("CONDA_PREFIX", str(conda_env))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py311-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.11\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        assert any(p.name == "py311-only-pkg" for p in pinned)

    def test_conda_only_has_python_dateutil_no_real_interpreter_record(self, tmp_path, monkeypatch):
        """Defensive: if somehow only the dateutil-shaped file exists (no
        real python package record), "2.9.0" must never be mistaken for the
        interpreter version. CONDA_PREFIX is still positively selected
        here, so the correct outcome per the target-version-unknown fix is
        fail-open retention (see test_unreadable_conda_prefix_...), not
        silent exclusion — package-alert genuinely doesn't know this
        conda environment's real Python version and must not guess."""
        conda_env = tmp_path / "conda_env"
        meta_dir = conda_env / "conda-meta"
        meta_dir.mkdir(parents=True)
        import json
        (meta_dir / "python-dateutil-2.9.0-pyhd8ed1ab_0.json").write_text(
            json.dumps({"name": "python-dateutil", "version": "2.9.0"})
        )
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("CONDA_PREFIX", str(conda_env))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py-two-nine-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'2.9\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        assert any(p.name == "py-two-nine-only-pkg" for p in pinned)

    def test_active_conda_env_excludes_project_venv_marker(self, tmp_path, monkeypatch):
        """The exact reported scenario: an active conda environment (3.11)
        alongside a project .venv pinning a different version (3.12). uv
        gives CONDA_PREFIX precedence over a discovered .venv, so a package
        marked for the venv's version must NOT be included, and one marked
        for the conda environment's actual version must be."""
        conda_env = tmp_path / "conda_env"
        self._write_conda_meta(conda_env, python_version="3.11.15")
        self._write_pyvenv_cfg(tmp_path / ".venv", version_info="3.12")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("CONDA_PREFIX", str(conda_env))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py311-conda-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.11\'"\n\n'
            '[[packages]]\n'
            'name = "py312-venv-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "python_version == \'3.12\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        names = {p.name for p in pinned}
        assert names == {"py311-conda-pkg"}

    def test_unreadable_conda_prefix_does_not_fall_through_to_local_venv(self, tmp_path, monkeypatch):
        """REGRESSION (P1): once CONDA_PREFIX is set, its version lookup
        must be terminal — a set-but-unreadable conda environment (no
        conda-meta at all here) must NOT fall through to a lower-priority
        .venv discovery, since uv itself already committed to CONDA_PREFIX
        as the active environment and would never silently prefer a
        different location. Both packages below are gated on a
        python_version marker, so both must be retained by fail-open
        (target version unknown) — if the fallthrough bug were reintroduced
        and the .venv's 3.12 were silently adopted, only the 3.12-marked
        package would survive, distinguishing the two failure modes."""
        broken_conda_env = tmp_path / "broken_conda_env"
        broken_conda_env.mkdir()  # no conda-meta directory at all
        self._write_pyvenv_cfg(tmp_path / ".venv", version_info="3.12")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("CONDA_PREFIX", str(broken_conda_env))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py312-venv-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.12\'"\n\n'
            '[[packages]]\n'
            'name = "py311-other-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "python_version == \'3.11\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        # Both retained (fail-open, target unknown) — NOT just the 3.12 one,
        # which is what a silent .venv fallthrough would have produced.
        names = {p.name for p in pinned}
        assert names == {"py312-venv-pkg", "py311-other-pkg"}

    def test_unreadable_virtual_env_is_target_version_unknown_not_none(self, tmp_path, monkeypatch):
        """REGRESSION (P1): a set-but-unreadable VIRTUAL_ENV must return the
        _TARGET_VERSION_UNKNOWN sentinel, distinct from None. Conflating
        the two (both previously returned None) let the caller fall back
        to evaluating markers against package-alert's own interpreter —
        an arbitrary, unrelated Python version — instead of recognising
        that a target WAS selected and its version is simply unknown."""
        from packagealert.parsers.lockfiles import (
            _TARGET_VERSION_UNKNOWN,
            _discover_target_python_version,
        )

        broken_venv = tmp_path / "broken_venv"
        broken_venv.mkdir()  # no pyvenv.cfg at all
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(broken_venv))

        result = _discover_target_python_version(tmp_path)
        assert result is _TARGET_VERSION_UNKNOWN
        assert result is not None

    def test_no_target_anywhere_returns_none_not_the_sentinel(self, tmp_path, monkeypatch):
        # The genuine "nothing applies" case must stay distinct from the
        # sentinel too, so the caller keeps its existing safe fallback
        # (package-alert's own interpreter) rather than treating every
        # bare invocation as target-unknown.
        from packagealert.parsers.lockfiles import (
            _TARGET_VERSION_UNKNOWN,
            _discover_target_python_version,
        )

        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)

        result = _discover_target_python_version(tmp_path)
        assert result is None
        assert result is not _TARGET_VERSION_UNKNOWN

    def test_existing_but_unreadable_local_venv_is_terminal_too(self, tmp_path, monkeypatch):
        """A .venv directory found during walk-up IS the target (uv doesn't
        keep searching parent directories for a different one once it
        finds one) — so an unreadable pyvenv.cfg inside it must also
        become target-unknown, not silently continue walking up to a
        parent .venv."""
        project_dir = tmp_path / "project"
        (project_dir / ".venv").mkdir(parents=True)  # exists, but no pyvenv.cfg
        # A parent .venv that IS readable — must NOT be adopted instead.
        self._write_pyvenv_cfg(tmp_path / ".venv", version_info="3.10")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)

        f = project_dir / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py310-parent-venv-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.10\'"\n\n'
            '[[packages]]\n'
            'name = "py311-other-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "python_version == \'3.11\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=project_dir)
        # Both retained (fail-open) — the parent's 3.10 must NOT be
        # silently adopted just because the nearer .venv was unreadable.
        names = {p.name for p in pinned}
        assert names == {"py310-parent-venv-pkg", "py311-other-pkg"}

    def test_target_unknown_still_evaluates_non_version_markers_normally(self, tmp_path, monkeypatch):
        """Only python_version/python_full_version markers must fail open
        when the target's version is unknown — a platform/extras/
        dependency-group marker has nothing to do with the unresolved
        Python version and must still be evaluated for real."""
        broken_conda_env = tmp_path / "broken_conda_env"
        broken_conda_env.mkdir()  # no conda-meta at all
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("CONDA_PREFIX", str(broken_conda_env))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "windows-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "sys_platform == \'nonexistent-platform-xyz\'"\n\n'
            '[[packages]]\n'
            'name = "unconditional-pkg"\n'
            'version = "2.0.0"\n\n'
            '[[packages]]\n'
            'name = "unknown-version-pkg"\n'
            'version = "3.0.0"\n'
            'marker = "python_version == \'3.12\'"\n'
        )
        pinned, _ = collect_requirements_packages(f, allowed_root=tmp_path)
        names = {p.name for p in pinned}
        # windows-only-pkg's platform marker is still genuinely evaluated
        # and correctly excludes it; the version-dependent marker fails
        # open instead of guessing.
        assert names == {"unconditional-pkg", "unknown-version-pkg"}

    def test_marker_references_python_version_ignores_string_literal_match(self):
        from packagealert.parsers.lockfiles import _marker_references_python_version

        assert _marker_references_python_version("python_version == '3.12'") is True
        assert _marker_references_python_version("python_full_version >= '3.10'") is True
        assert _marker_references_python_version("sys_platform == 'python_version'") is False
        assert _marker_references_python_version("'dev' in extras") is False

    def test_system_python_target_retains_version_marked_package_despite_active_venv(self, tmp_path, monkeypatch):
        """REGRESSION (P1): the exact reported scenario — an active Python
        3.12 venv (VIRTUAL_ENV set) alongside `uv pip sync --system
        pylock.toml` targeting the system Python (3.11 in the report's
        example). uv's own --system discovery ignores VIRTUAL_ENV entirely
        (verified empirically), so a package marked for the system's real
        version must be retained (fail-open, target unknown) rather than
        excluded by evaluating against the active venv's version."""
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "pyvenv.cfg").write_text("version_info = 3.12\n")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py311-system-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.11\'"\n\n'
            '[[packages]]\n'
            'name = "py312-venv-only-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "python_version == \'3.12\'"\n'
        )
        pinned, _ = collect_requirements_packages(
            f, allowed_root=tmp_path, is_system_python_target=True
        )
        # Both retained (fail-open, target unknown) — NOT just the 3.12
        # one, which is what evaluating against the active venv would give.
        names = {p.name for p in pinned}
        assert names == {"py311-system-only-pkg", "py312-venv-only-pkg"}

    def test_system_python_target_false_still_uses_venv_discovery(self, tmp_path, monkeypatch):
        # Control: without is_system_python_target, the active venv's
        # version must still be used normally (regression guard for the
        # existing VIRTUAL_ENV-discovery fix).
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "pyvenv.cfg").write_text("version_info = 3.12\n")
        monkeypatch.delenv("VIRTUAL_ENV", raising=False)
        monkeypatch.delenv("CONDA_PREFIX", raising=False)
        monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

        f = tmp_path / "pylock.toml"
        f.write_text(
            'lock-version = "1.0"\n\n'
            '[[packages]]\n'
            'name = "py312-venv-only-pkg"\n'
            'version = "1.0.0"\n'
            'marker = "python_version == \'3.12\'"\n\n'
            '[[packages]]\n'
            'name = "py311-other-pkg"\n'
            'version = "2.0.0"\n'
            'marker = "python_version == \'3.11\'"\n'
        )
        pinned, _ = collect_requirements_packages(
            f, allowed_root=tmp_path, is_system_python_target=False
        )
        names = {p.name for p in pinned}
        assert names == {"py312-venv-only-pkg"}


class TestCollectRequirementsPackagesTraversal:
    def test_absolute_include_is_rejected(self, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("evil==1.0.0\n")
        reqs = tmp_path / "requirements.txt"
        reqs.write_text(f"-r {secret}\nrequests==2.31.0\n")
        pinned, _ = collect_requirements_packages(reqs)
        names = {p.name for p in pinned}
        assert "evil" not in names
        assert "requests" in names

    def test_relative_parent_include_is_allowed(self, tmp_path):
        # requirements/base.txt with -r ../root.txt is a normal monorepo pattern
        # when the caller passes the project root as allowed_root.
        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        (tmp_path / "root.txt").write_text("flask==3.0.0\n")
        (reqs_dir / "base.txt").write_text("-r ../root.txt\ncryptography==42.0.0\n")
        pinned, _ = collect_requirements_packages(reqs_dir / "base.txt", allowed_root=tmp_path)
        names = {p.name for p in pinned}
        assert "flask" in names
        assert "cryptography" in names

    def test_deep_traversal_outside_root_is_blocked(self, tmp_path):
        # -r ../../../../etc/passwd should be blocked even though it is relative.
        secret = tmp_path.parent / "secret.txt"
        secret.write_text("evil==1.0.0\n")
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("-r ../secret.txt\nrequests==2.31.0\n")
        # Default allowed_root = tmp_path; ../secret.txt resolves outside it.
        pinned, _ = collect_requirements_packages(reqs)
        names = {p.name for p in pinned}
        assert "evil" not in names
        assert "requests" in names


# ---------------------------------------------------------------------------
# parse_package_spec — VCS / non-PyPI token rejection
# ---------------------------------------------------------------------------

class TestParsePackageSpec:
    def test_plain_name(self):
        assert parse_package_spec("requests", "pypi") == ("requests", None)

    def test_pinned_version(self):
        assert parse_package_spec("requests==2.31.0", "pypi") == ("requests", "2.31.0")

    def test_scheme_vcs_url_rejected(self):
        # git+ssh:// and other scheme-based VCS refs must return ("", None)
        assert parse_package_spec("git+ssh://git@github.com/org/repo.git", "pypi") == ("", None)

    def test_https_vcs_url_rejected(self):
        assert parse_package_spec("git+https://github.com/org/repo.git", "pypi") == ("", None)

    def test_scp_style_vcs_rejected(self):
        # git@host:path was previously parsed as package name "git"
        assert parse_package_spec("git@github.com:org/repo.git", "pypi") == ("", None)

    def test_scp_style_with_git_plus_prefix_rejected(self):
        assert parse_package_spec("git+git@github.com:org/repo.git", "pypi") == ("", None)

    def test_https_with_git_at_username_not_rejected(self):
        # HTTPS URL with git@ username — rejected by "://" guard, not scp regex
        assert parse_package_spec("git+https://git@github.com/org/repo.git", "pypi") == ("", None)


class TestScanProject:
    """Tests for scan_project() lockfile dispatch logic."""

    def _setup_registry(self):
        from packagealert.languages import registry as reg
        reg.load()

    def test_scan_project_finds_package_lock(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {"node_modules/lodash": {"version": "4.17.21"}},
        }))

        result = scan_project(tmp_path)
        names = [p.name for p in result.pinned]
        assert "lodash" in names

    def test_scan_project_skips_empty_parse_result_and_continues(self, tmp_path):
        """A file that exists but parse_lockfile returns [] must not block
        the scan from trying subsequent lockfile patterns for the same language.

        PythonLanguage patterns start with ["uv.lock", "Pipfile.lock", "requirements.txt", ...].
        A malformed uv.lock (invalid TOML) yields no specs; the scan must fall
        through to requirements.txt and find packages there.
        """
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        # Malformed uv.lock — PythonLanguage.parse_lockfile() will return []
        (tmp_path / "uv.lock").write_text("this is not valid toml [[[\n")

        # requirements.txt is the third pattern — should be reached after uv.lock yields nothing
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

        result = scan_project(tmp_path)
        names = [p.name for p in result.pinned]
        assert "requests" in names

    def test_scan_project_empty_project_returns_empty(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        result = scan_project(tmp_path)
        assert result.pinned == []
        assert result.unpinned == []
        assert result.sources == []

    def test_scan_project_composer_lock_detected_as_source(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = {"packages": [{"name": "vendor/pkg", "version": "1.0.0"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        result = scan_project(tmp_path)
        assert any("composer.lock" in s for s in result.sources)

    def test_scan_project_composer_lock_packages_in_pinned(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = {
            "packages": [
                {"name": "vendor/alpha", "version": "2.3.4"},
                {"name": "vendor/beta", "version": "v1.0.0"},
            ],
            "packages-dev": [{"name": "vendor/gamma", "version": "0.5.0"}],
        }
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        result = scan_project(tmp_path)
        names = {p.name for p in result.pinned}
        assert {"vendor/alpha", "vendor/beta", "vendor/gamma"} <= names

    def test_scan_project_composer_lock_v_prefix_stripped(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = {"packages": [{"name": "vendor/pkg", "version": "v3.1.4"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        result = scan_project(tmp_path)
        pkg = next(p for p in result.pinned if p.name == "vendor/pkg")
        assert pkg.version == "3.1.4"

    def test_scan_project_composer_json_only_returns_empty(self, tmp_path):
        # PhpLanguage declares ["composer.lock"] as its lockfile pattern; composer.json
        # is not a lockfile, so with no composer.lock present the scan returns empty.
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        (tmp_path / "composer.json").write_text(json.dumps({"require": {"vendor/pkg": "1.2.3"}}))
        result = scan_project(tmp_path)
        assert result.sources == []
        assert result.pinned == []

    def test_scan_project_composer_lock_takes_precedence_over_json(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = {"packages": [{"name": "vendor/from-lock", "version": "9.0.0"}], "packages-dev": []}
        (tmp_path / "composer.lock").write_text(json.dumps(lock))
        (tmp_path / "composer.json").write_text(json.dumps({"require": {"vendor/from-json": "1.0.0"}}))
        result = scan_project(tmp_path)
        pinned_names = {p.name for p in result.pinned}
        assert "vendor/from-lock" in pinned_names
        assert "vendor/from-json" not in pinned_names

    def test_scan_project_requirements_subdir_variant(self, tmp_path):
        # Repos without a top-level requirements.txt may use requirements/base.txt etc.
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        (reqs_dir / "base.txt").write_text("flask==3.0.0\nclick==8.1.7\n")
        result = scan_project(tmp_path)
        names = {p.name for p in result.pinned}
        assert "flask" in names
        assert "click" in names

    def test_scan_project_top_level_requirements_takes_precedence_over_subdir(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        reqs_dir = tmp_path / "requirements"
        reqs_dir.mkdir()
        (reqs_dir / "base.txt").write_text("flask==3.0.0\n")
        result = scan_project(tmp_path)
        names = {p.name for p in result.pinned}
        assert "requests" in names
        assert "flask" not in names


class TestScanLockfilesExceptionIsolation:
    def _setup_registry(self):
        from packagealert.languages import registry as lang_registry
        lang_registry.load()

    def test_buggy_plugin_skipped_remaining_paths_still_scanned(self, tmp_path):
        from unittest.mock import MagicMock, patch

        from packagealert.parsers.lockfiles import scan_lockfiles

        self._setup_registry()

        good_file = tmp_path / "requirements.txt"
        good_file.write_text("flask==3.0.0\n")
        bad_file = tmp_path / "package-lock.json"
        bad_file.write_text("{}")

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.parse_lockfile.side_effect = RuntimeError("plugin exploded")

        from packagealert.languages import registry as lang_registry
        real_for_lockfile = lang_registry.for_lockfile

        def patched_for_lockfile(path):
            from pathlib import Path as _Path
            if _Path(path).name == "package-lock.json":
                return bad_lang
            return real_for_lockfile(path)

        with patch("packagealert.languages.registry.for_lockfile", side_effect=patched_for_lockfile):
            result = scan_lockfiles([bad_file, good_file])

        bad_lang.parse_lockfile.assert_called_once()
        names = [p.name for p in result.pinned]
        assert "flask" in names

    def test_buggy_plugin_in_scan_project_continues_to_next_pattern(self, tmp_path):
        from unittest.mock import MagicMock, patch

        from packagealert.parsers.lockfiles import scan_project

        self._setup_registry()

        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.ecosystems = ["pypi"]
        bad_lang.lockfile_patterns.return_value = ["requirements.txt"]
        bad_lang.parse_lockfile.side_effect = RuntimeError("plugin exploded")

        from packagealert.languages import registry as lang_registry
        real_all_languages = lang_registry.all_languages

        def patched_all_languages():
            return [bad_lang] + real_all_languages()

        with patch("packagealert.languages.registry.all_languages", side_effect=patched_all_languages):
            result = scan_project(tmp_path)

        bad_lang.parse_lockfile.assert_called_once()
        # Real python language still finds requirements.txt
        names = [p.name for p in result.pinned]
        assert "flask" in names

    def test_buggy_lockfile_patterns_in_scan_project_skips_language(self, tmp_path):
        """scan_project() must skip a language whose lockfile_patterns() raises and keep scanning."""
        from unittest.mock import MagicMock, patch

        from packagealert.parsers.lockfiles import scan_project

        self._setup_registry()

        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.lockfile_patterns.side_effect = RuntimeError("patterns boom")

        from packagealert.languages import registry as lang_registry
        real_all_languages = lang_registry.all_languages

        def patched_all_languages():
            return [bad_lang] + real_all_languages()

        with patch("packagealert.languages.registry.all_languages", side_effect=patched_all_languages):
            result = scan_project(tmp_path)

        # Good language still found its lockfile
        names = [p.name for p in result.pinned]
        assert "flask" in names


class TestScanInstalledExceptionIsolation:
    def test_buggy_plugin_skipped_good_lang_still_runs(self, tmp_path):
        from unittest.mock import MagicMock, patch

        from packagealert.languages import registry as lang_registry
        from packagealert.parsers.lockfiles import scan_installed
        lang_registry.load()

        bad_lang = MagicMock()
        bad_lang.name = "bad"
        bad_lang.detect_installed_packages.side_effect = RuntimeError("plugin exploded")

        real_all_languages = lang_registry.all_languages

        def patched_all_languages():
            return [bad_lang] + real_all_languages()

        with patch("packagealert.languages.registry.all_languages", side_effect=patched_all_languages):
            result = scan_installed(tmp_path)

        bad_lang.detect_installed_packages.assert_called_once()
        # Result should not contain anything from the bad plugin, but should not crash
        assert isinstance(result.pinned, list)


class TestParseYarnArgs:
    def test_yarn_add_single(self):
        result = parse_yarn_args(["yarn", "add", "lodash"])
        assert result is not None
        assert result.manager == "yarn"
        assert result.packages == ["lodash"]

    def test_yarn_add_multiple(self):
        result = parse_yarn_args(["yarn", "add", "react", "react-dom"])
        assert result is not None
        assert result.packages == ["react", "react-dom"]

    def test_yarn_add_strips_flags(self):
        result = parse_yarn_args(["yarn", "add", "--dev", "jest"])
        assert result is not None
        assert result.packages == ["jest"]

    def test_yarn_install_returns_empty_packages(self):
        result = parse_yarn_args(["yarn", "install"])
        assert result is not None
        assert result.manager == "yarn"
        assert result.packages == []

    def test_bare_yarn_returns_empty_packages(self):
        result = parse_yarn_args(["yarn"])
        assert result is not None
        assert result.packages == []

    def test_yarn_remove_defers_to_lockfile(self):
        result = parse_yarn_args(["yarn", "remove", "lodash"])
        assert result is not None
        assert result.manager == "yarn"
        assert result.packages == []

    def test_yarn_non_install_returns_none(self):
        assert parse_yarn_args(["yarn", "run", "test"]) is None
        assert parse_yarn_args(["yarn", "audit"]) is None

    def test_yarn_unknown_subcommand_returns_none(self):
        assert parse_yarn_args(["yarn", "frobnicate"]) is None

    def test_yarn_wrong_exe_returns_none(self):
        assert parse_yarn_args(["npm", "add", "lodash"]) is None

    def test_yarn_empty_returns_none(self):
        assert parse_yarn_args([]) is None

    def test_yarn_full_path(self):
        result = parse_yarn_args(["/usr/local/bin/yarn", "add", "express"])
        assert result is not None
        assert result.packages == ["express"]


class TestParsePnpmArgs:
    def test_pnpm_add_single(self):
        result = parse_pnpm_args(["pnpm", "add", "lodash"])
        assert result is not None
        assert result.manager == "pnpm"
        assert result.packages == ["lodash"]

    def test_pnpm_add_multiple(self):
        result = parse_pnpm_args(["pnpm", "add", "react", "react-dom"])
        assert result is not None
        assert result.packages == ["react", "react-dom"]

    def test_pnpm_add_strips_flags(self):
        result = parse_pnpm_args(["pnpm", "add", "--save-dev", "jest"])
        assert result is not None
        assert result.packages == ["jest"]

    def test_pnpm_install_returns_empty_packages(self):
        result = parse_pnpm_args(["pnpm", "install"])
        assert result is not None
        assert result.manager == "pnpm"
        assert result.packages == []

    def test_pnpm_i_alias(self):
        result = parse_pnpm_args(["pnpm", "i"])
        assert result is not None
        assert result.packages == []

    def test_pnpm_remove_defers_to_lockfile(self):
        for subcmd in ("remove", "rm", "uninstall", "un"):
            result = parse_pnpm_args(["pnpm", subcmd, "lodash"])
            assert result is not None, f"pnpm {subcmd} should not return None"
            assert result.manager == "pnpm"
            assert result.packages == []

    def test_pnpm_non_install_returns_none(self):
        assert parse_pnpm_args(["pnpm", "run", "build"]) is None
        assert parse_pnpm_args(["pnpm", "audit"]) is None

    def test_pnpm_unknown_subcommand_returns_none(self):
        assert parse_pnpm_args(["pnpm", "frobnicate"]) is None

    def test_pnpm_wrong_exe_returns_none(self):
        assert parse_pnpm_args(["npm", "add", "lodash"]) is None

    def test_pnpm_empty_returns_none(self):
        assert parse_pnpm_args([]) is None

    def test_pnpm_no_args_returns_none(self):
        assert parse_pnpm_args(["pnpm"]) is None

    def test_pnpm_full_path(self):
        result = parse_pnpm_args(["/usr/local/bin/pnpm", "add", "express"])
        assert result is not None
        assert result.packages == ["express"]


class TestScanLockfilesSubdirPattern:
    """scan_lockfiles() must recognise lockfiles in subdirectory patterns."""

    def test_subdir_lockfile_is_scanned(self, tmp_path):
        from packagealert.languages import registry as lang_registry
        from packagealert.parsers.lockfiles import scan_lockfiles
        lang_registry.load()

        req_dir = tmp_path / "requirements"
        req_dir.mkdir()
        req_file = req_dir / "base.txt"
        req_file.write_text("flask==3.0.0\n")

        result = scan_lockfiles([req_file])

        names = [p.name for p in result.pinned]
        assert "flask" in names

    def test_bare_filename_matching_subdir_pattern_is_not_misidentified(self, tmp_path):
        from packagealert.languages import registry as lang_registry
        from packagealert.parsers.lockfiles import scan_lockfiles
        lang_registry.load()

        # "base.txt" at the root should NOT match "requirements/base.txt"
        base_txt = tmp_path / "base.txt"
        base_txt.write_text("flask==3.0.0\n")

        result = scan_lockfiles([base_txt])

        assert result.pinned == []
        assert result.sources == []


# ---------------------------------------------------------------------------
# PythonLanguage.prepare_sandbox_argv / sandbox_extra_write_paths
# ---------------------------------------------------------------------------

class TestPythonSandboxArgv:
    def _lang(self):
        from packagealert.languages.python import PythonLanguage
        return PythonLanguage()

    def test_relative_editable_absolutised(self, tmp_path):
        lang = self._lang()
        result = lang.prepare_sandbox_argv(["pip", "install", "-e", "../../other"], tmp_path)
        assert result[3] == str((tmp_path / "../../other").resolve())

    def test_extras_preserved(self, tmp_path):
        lang = self._lang()
        result = lang.prepare_sandbox_argv(["pip", "install", "-e", ".[dev]"], tmp_path)
        expected = str((tmp_path / ".").resolve()) + "[dev]"
        assert result[3] == expected

    def test_absolute_path_unchanged(self, tmp_path):
        lang = self._lang()
        abs_path = str(tmp_path / "myproject")
        result = lang.prepare_sandbox_argv(["pip", "install", "-e", abs_path], tmp_path)
        assert result[3] == abs_path

    def test_vcs_url_unchanged(self, tmp_path):
        lang = self._lang()
        url = "git+https://github.com/org/repo.git"
        result = lang.prepare_sandbox_argv(["pip", "install", "-e", url], tmp_path)
        assert result[3] == url

    def test_long_form_editable_absolutised(self, tmp_path):
        lang = self._lang()
        result = lang.prepare_sandbox_argv(["pip", "install", "--editable=../other"], tmp_path)
        expected = f"--editable={(tmp_path / '../other').resolve()}"
        assert result[2] == expected


class TestPythonSandboxWritePaths:
    def _lang(self):
        from packagealert.languages.python import PythonLanguage
        return PythonLanguage()

    def test_external_editable_returned(self, tmp_path):
        lang = self._lang()
        external = tmp_path / "other"
        external.mkdir()
        cwd = tmp_path / "project"
        cwd.mkdir()
        result = lang.sandbox_extra_write_paths(
            ["pip", "install", "-e", str(external)], cwd
        )
        assert external.resolve() in result

    def test_in_project_editable_excluded(self, tmp_path):
        lang = self._lang()
        cwd = tmp_path / "project"
        cwd.mkdir()
        # pip install -e . — inside cwd, should not be returned
        result = lang.sandbox_extra_write_paths(
            ["pip", "install", "-e", str(cwd)], cwd
        )
        assert not result

    def test_nonexistent_path_excluded(self, tmp_path):
        lang = self._lang()
        cwd = tmp_path / "project"
        cwd.mkdir()
        result = lang.sandbox_extra_write_paths(
            ["pip", "install", "-e", str(tmp_path / "nonexistent")], cwd
        )
        assert not result

    def test_vcs_url_excluded(self, tmp_path):
        lang = self._lang()
        result = lang.sandbox_extra_write_paths(
            ["pip", "install", "-e", "git+https://github.com/org/repo.git"], tmp_path
        )
        assert not result


# ---------------------------------------------------------------------------
# prod_only filtering
# ---------------------------------------------------------------------------

class TestProdOnly:
    """Tests for scan_project(prod_only=True) dev dep filtering."""

    def _setup_registry(self):
        from packagealert.languages import registry as reg
        reg.load()

    def test_prod_only_filters_dev_packages(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/express": {"version": "4.18.0"},
                "node_modules/jest": {"version": "29.0.0", "dev": True},
            },
        }))

        result = scan_project(tmp_path, prod_only=True)
        names = [p.name for p in result.pinned]
        assert "express" in names
        assert "jest" not in names

    def test_prod_only_false_includes_dev_packages(self, tmp_path):
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/express": {"version": "4.18.0"},
                "node_modules/jest": {"version": "29.0.0", "dev": True},
            },
        }))

        result = scan_project(tmp_path, prod_only=False)
        names = [p.name for p in result.pinned]
        assert "express" in names
        assert "jest" in names

    def test_prod_only_dev_undetectable_for_requirements_txt(self, tmp_path):
        """requirements.txt has no dev/prod concept — dev_undetectable should be populated."""
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\n")

        result = scan_project(tmp_path, prod_only=True)
        assert result.dev_undetectable == ["requirements.txt"]

    def test_prod_only_empty_dev_undetectable_when_source_supports_it(self, tmp_path):
        """package-lock.json supports dev detection — dev_undetectable should be empty."""
        self._setup_registry()
        from packagealert.parsers.lockfiles import scan_project

        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/express": {"version": "4.18.0"},
                "node_modules/jest": {"version": "29.0.0", "dev": True},
            },
        }))

        result = scan_project(tmp_path, prod_only=True)
        assert result.dev_undetectable == []

    def test_prod_only_all_dev_lockfile_does_not_fall_through_to_lower_priority_pattern(self, tmp_path):
        """When the highest-priority lockfile pattern for a language parses successfully
        but all packages are dev-only, scan_project must treat it as the winning match
        and not fall through to a lower-priority pattern for the same language."""
        self._setup_registry()
        from unittest.mock import patch

        # Patch node language to have two patterns: high-priority returns all dev,
        # low-priority returns a prod package. The low-priority must never be reached.
        from packagealert.languages.base import PackageSpec
        from packagealert.parsers.lockfiles import scan_project

        all_dev = [PackageSpec(name="jest", version="29.0.0", ecosystem="npm", is_dev=True)]
        prod_pkg = [PackageSpec(name="express", version="4.18.0", ecosystem="npm", is_dev=False)]

        from packagealert.languages import registry as reg
        reg.load()
        node_lang = next(ln for ln in reg.all_languages() if ln.name == "node")

        call_count = {"n": 0}

        def patched_patterns():
            return ["package-lock.json", "yarn.lock"]

        def patched_parse(path):
            call_count["n"] += 1
            if path.name == "package-lock.json":
                return all_dev
            return prod_pkg  # should never be reached

        # Create both lockfiles so both patterns would match
        (tmp_path / "package-lock.json").write_text("{}")
        (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n")

        with patch.object(node_lang, "lockfile_patterns", patched_patterns), \
             patch.object(node_lang, "parse_lockfile", patched_parse):
            result = scan_project(tmp_path, prod_only=True)

        # package-lock.json was the winning match — source recorded even with empty output
        assert any("package-lock.json" in s for s in result.sources)
        # yarn.lock must never have been parsed
        assert call_count["n"] == 1, "lower-priority pattern was reached when it should not have been"
        # express (from yarn.lock) must not appear
        assert not any(p.name == "express" for p in result.pinned)


class TestScanLockfilesAllDev:
    """scan_lockfiles() all-dev filtering must still record source and dev_undetectable."""

    def test_scan_lockfiles_all_dev_records_source(self, tmp_path):
        """When prod_only=True and all packages are dev-only, the source must still
        appear in ProjectScan.sources — consistent with scan_project behaviour."""
        from packagealert.parsers.lockfiles import scan_lockfiles

        lock = tmp_path / "package-lock.json"
        lock.write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "node_modules/jest": {"version": "29.0.0", "dev": True},
            },
        }))

        from packagealert.languages import registry as reg
        reg.load()

        result = scan_lockfiles([lock], prod_only=True)
        assert any("package-lock.json" in s for s in result.sources)
        assert result.pinned == []

    def test_scan_lockfiles_dev_undetectable_only_for_present_sources(self, tmp_path):
        """dev_undetectable entries must correspond to sources that appear in
        ProjectScan.sources (no orphan warnings for all-dev-filtered files).
        Use yarn.lock without a package.json — all packages get is_dev=None."""
        from packagealert.parsers.lockfiles import scan_lockfiles

        lock = tmp_path / "yarn.lock"
        lock.write_text(
            "# yarn lockfile v1\n\n"
            "jest@^29.0.0:\n"
            "  version \"29.0.0\"\n"
        )
        # No package.json — yarn parser returns is_dev=None for all entries

        from packagealert.languages import registry as reg
        reg.load()

        result = scan_lockfiles([lock], prod_only=True)
        # dev_undetectable fires because jest has is_dev=None
        assert "yarn.lock" in result.dev_undetectable
        # source must also be present — no orphan warning
        assert any("yarn.lock" in s for s in result.sources)
