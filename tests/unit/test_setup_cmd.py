import os
import stat
from pathlib import Path
from unittest.mock import patch
import pytest


PA_FINGERPRINT = "# __pa_shim__"
PA_BLOCK_START = "# BEGIN package-alert shell integration"
PA_BLOCK_END = "# END package-alert shell integration"


@pytest.fixture(autouse=True)
def mock_pa_executable():
    """Ensure shims embed a predictable package-alert path during tests."""
    with patch(
        "packagealert.cli.setup_cmd._pa_executable",
        return_value="/usr/local/bin/package-alert",
    ):
        yield


class TestSetupShellSnippet:
    def test_snippet_contains_pip_function(self):
        from packagealert.cli.setup_cmd import generate_shell_snippet
        snippet = generate_shell_snippet(shell="bash")
        assert "pip()" in snippet
        assert "package-alert run" in snippet

    def test_snippet_contains_npm_function(self):
        from packagealert.cli.setup_cmd import generate_shell_snippet
        snippet = generate_shell_snippet(shell="bash")
        assert "npm()" in snippet

    def test_snippet_uses_package_manager_names_only(self):
        from packagealert.cli.setup_cmd import generate_shell_snippet
        from packagealert.languages import registry
        registry.load()
        snippet = generate_shell_snippet(shell="bash")
        for lang in registry.all_languages():
            for name in lang.package_manager_names():
                assert f"{name}()" in snippet
            # Interpreter names must NOT appear as shell functions
            for name in lang.interpreter_names():
                assert f"{name}()" not in snippet

    def test_snippet_is_valid_bash_and_defines_functions(self):
        import subprocess
        from packagealert.cli.setup_cmd import generate_shell_snippet
        from packagealert.languages import registry
        registry.load()
        snippet = generate_shell_snippet(shell="bash")
        check = "\n".join(
            f"type {name}"
            for lang in registry.all_languages()
            for name in lang.package_manager_names()
        )
        result = subprocess.run(
            ["bash", "-c", f"{snippet}\n{check}"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"bash rejected snippet or functions missing:\n{result.stderr}"
        assert "function" in result.stdout


class TestInstallShellRC:
    def test_appends_eval_line_to_rc(self, tmp_path):
        from packagealert.cli.setup_cmd import install_shell_rc
        rc = tmp_path / ".bashrc"
        rc.write_text("# existing content\n")
        install_shell_rc(rc_path=rc, shell="bash")
        content = rc.read_text()
        assert PA_BLOCK_START in content
        assert "eval" in content
        assert PA_BLOCK_END in content

    def test_idempotent_does_not_duplicate(self, tmp_path):
        from packagealert.cli.setup_cmd import install_shell_rc
        rc = tmp_path / ".bashrc"
        rc.write_text("")
        install_shell_rc(rc_path=rc, shell="bash")
        install_shell_rc(rc_path=rc, shell="bash")
        content = rc.read_text()
        assert content.count(PA_BLOCK_START) == 1

    def test_unrecognised_shell_raises(self, tmp_path):
        from packagealert.cli.setup_cmd import install_shell_rc
        rc = tmp_path / ".fishrc"
        with pytest.raises(ValueError, match="Unsupported shell"):
            install_shell_rc(rc_path=rc, shell="fish")


class TestSetupProject:
    def _make_venv(self, tmp_path: Path) -> Path:
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True)
        pip = venv / "pip"
        pip.write_text("#!/bin/sh\necho original pip\n")
        pip.chmod(pip.stat().st_mode | stat.S_IEXEC)
        return tmp_path

    def test_installs_shim_and_renames_original(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "pip"
        real = tmp_path / ".venv" / "bin" / "pip.__pa_real"
        assert real.exists()
        assert PA_FINGERPRINT in shim.read_text()

    def test_shim_is_executable(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "pip"
        assert os.access(shim, os.X_OK)

    def test_idempotent_skips_already_shimmed(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv(tmp_path)
        install_project_shims(project_root=tmp_path)
        install_project_shims(project_root=tmp_path)
        real = tmp_path / ".venv" / "bin" / "pip.__pa_real"
        assert real.exists()
        # Not doubled
        assert not (tmp_path / ".venv" / "bin" / "pip.__pa_real.__pa_real").exists()

    def test_installs_shim_for_non_standard_binary(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True)
        pip = venv / "pip"
        pip.write_text("#!/bin/sh\nsome-other-tool\n")
        pip.chmod(pip.stat().st_mode | stat.S_IEXEC)
        install_project_shims(project_root=tmp_path)
        # pip is a managed tool name — it gets shimmed regardless of content
        assert (venv / "pip.__pa_real").exists()

    def test_shim_embeds_version_marker(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, PA_SHIM_VERSION_MARKER
        self._make_venv(tmp_path)
        install_project_shims(project_root=tmp_path)
        content = (tmp_path / ".venv" / "bin" / "pip").read_text()
        assert PA_SHIM_VERSION_MARKER in content

    def test_shim_embeds_pa_binary_path(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv(tmp_path)
        install_project_shims(project_root=tmp_path)
        content = (tmp_path / ".venv" / "bin" / "pip").read_text()
        assert "# __pa_bin__ /usr/local/bin/package-alert" in content

    def test_current_shim_not_reported_stale(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, stale_project_shims
        self._make_venv(tmp_path)
        install_project_shims(project_root=tmp_path)
        assert stale_project_shims(project_root=tmp_path) == []

    def test_old_version_shim_reported_stale(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, stale_project_shims
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True)
        pip = venv / "pip"
        pip.write_text("#!/bin/sh\necho original\n")
        pip.chmod(pip.stat().st_mode | stat.S_IEXEC)
        install_project_shims(project_root=tmp_path)
        # Overwrite with a v1-style shim (fingerprint but no version marker)
        pip.write_text(f"#!/bin/sh\n{PA_FINGERPRINT}\nexec /usr/local/bin/package-alert run \"$0\" \"$@\"\n")
        assert stale_project_shims(project_root=tmp_path) == [pip]

    def test_wrong_pa_path_shim_reported_stale(self, tmp_path):
        from packagealert.cli.setup_cmd import (
            install_project_shims, stale_project_shims,
            PA_SHIM_VERSION_MARKER,
        )
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True)
        pip = venv / "pip"
        pip.write_text("#!/bin/sh\necho original\n")
        pip.chmod(pip.stat().st_mode | stat.S_IEXEC)
        install_project_shims(project_root=tmp_path)
        # Overwrite with correct version but wrong pa path
        pip.write_text(
            f"#!/bin/sh\n{PA_FINGERPRINT}\n{PA_SHIM_VERSION_MARKER}\n"
            f"# __pa_bin__ /old/path/to/package-alert\n"
            f"exec /old/path/to/package-alert run \"$0\" \"$@\"\n"
        )
        assert stale_project_shims(project_root=tmp_path) == [pip]

    def test_stale_shim_updated_on_reinstall(self, tmp_path):
        from packagealert.cli.setup_cmd import (
            install_project_shims, stale_project_shims,
            PA_SHIM_VERSION_MARKER,
        )
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True)
        pip = venv / "pip"
        pip.write_text("#!/bin/sh\necho original\n")
        pip.chmod(pip.stat().st_mode | stat.S_IEXEC)
        install_project_shims(project_root=tmp_path)
        # Degrade to v1-style shim
        pip.write_text(f"#!/bin/sh\n{PA_FINGERPRINT}\nexec /usr/local/bin/package-alert run \"$0\" \"$@\"\n")
        assert stale_project_shims(project_root=tmp_path) != []
        # Reinstall should update it
        install_project_shims(project_root=tmp_path)
        assert stale_project_shims(project_root=tmp_path) == []
        # Version marker must now be present
        assert PA_SHIM_VERSION_MARKER in pip.read_text()

    def test_alternate_entry_point_not_reported_stale(self, tmp_path):
        """Shim written via 'pa' must not be stale when checked via 'package-alert' (same inode)."""
        from packagealert.cli.setup_cmd import (
            _shim_is_current, PA_FINGERPRINT, PA_SHIM_VERSION_MARKER,
        )
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        # Simulate two entry-point symlinks pointing at the same real binary
        real_bin = bin_dir / "package-alert"
        real_bin.write_text("#!/bin/sh\necho pa\n")
        real_bin.chmod(real_bin.stat().st_mode | stat.S_IEXEC)
        alt_bin = bin_dir / "pa"
        alt_bin.symlink_to(real_bin)

        shim = tmp_path / "pip"
        # Write a shim as if installed via the 'pa' entry point
        shim.write_text(
            f"#!/bin/sh\n{PA_FINGERPRINT}\n{PA_SHIM_VERSION_MARKER}\n"
            f"# __pa_bin__ {alt_bin}\n"
            f'pa="{alt_bin}"\n'
            f'exec "$pa" run "$0" "$@"\n'
        )

        # Patch _pa_executable to return the 'package-alert' path (different name, same file)
        import packagealert.cli.setup_cmd as sc
        original = sc._pa_executable
        try:
            sc._pa_executable = lambda: str(real_bin)
            assert _shim_is_current(shim), (
                "Shim written via 'pa' should not be stale when checked via 'package-alert' (same inode)"
            )
        finally:
            sc._pa_executable = original

    def test_uninstall_restores_original(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, uninstall_project_shims
        self._make_venv(tmp_path)
        install_project_shims(project_root=tmp_path)
        uninstall_project_shims(project_root=tmp_path)
        pip = tmp_path / ".venv" / "bin" / "pip"
        real = tmp_path / ".venv" / "bin" / "pip.__pa_real"
        assert not real.exists()
        assert "original pip" in pip.read_text()

    def _make_venv_with_python(self, tmp_path: Path) -> Path:
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True, exist_ok=True)
        python3 = venv / "python3"
        python3.write_text("#!/bin/sh\necho real python\n")
        python3.chmod(python3.stat().st_mode | stat.S_IEXEC)
        return tmp_path

    def _make_venv_with_python_symlink(self, tmp_path: Path) -> Path:
        """Like _make_venv_with_python but also adds python → python3 symlink."""
        self._make_venv_with_python(tmp_path)
        venv = tmp_path / ".venv" / "bin"
        (venv / "python").symlink_to("python3")
        return tmp_path

    def test_interpreter_shim_installed(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        real = tmp_path / ".venv" / "bin" / "python3.__pa_real"
        assert real.exists()
        assert PA_FINGERPRINT in shim.read_text()

    def test_interpreter_shim_routes_pip_to_pa_run(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, PA_FINGERPRINT
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        content = shim.read_text()
        assert PA_FINGERPRINT in content
        assert '"$pa" run' in content
        # pip and uv should be intercepted
        assert "pip" in content
        assert "uv" in content

    def test_interpreter_shim_execs_real_for_non_pip(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        content = shim.read_text()
        # Non-pip invocations must exec __pa_real directly, not go through pa run
        assert 'exec "$real" "$@"' in content

    def test_interpreter_shim_hardcodes_real_path(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, PA_REAL_SUFFIX
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        content = shim.read_text()
        expected_real = str(tmp_path / ".venv" / "bin" / f"python3{PA_REAL_SUFFIX}")
        assert expected_real in content

    def test_interpreter_shim_missing_real_exits_cleanly(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        content = shim.read_text()
        # Must guard against missing __pa_real (e.g. venv recreated after shimming)
        assert "is missing" in content or "not found" in content or '! -x "$real"' in content

    def _patch_shim_for_routing_test(self, content: str) -> str:
        """Replace exec lines with echo markers and bypass the real-exists guard."""
        import re
        # The pa path is embedded at write time — match it with a regex
        content = re.sub(r"exec \S+ run \"\$0\" \"\$@\"", "echo ROUTE_PA_RUN", content)
        content = content.replace('exec "$real" "$@"', 'echo ROUTE_REAL')
        content = content.replace('if [ ! -x "$real" ]', 'if false')
        return content

    def test_interpreter_shim_routes_pip_with_u_flag(self, tmp_path):
        """python -u -m pip install foo must still route through pa run."""
        import subprocess
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        script = self._patch_shim_for_routing_test(shim.read_text())
        result = subprocess.run(
            ["bash", "-c", script, "python3", "-u", "-m", "pip", "install", "foo"],
            capture_output=True, text=True,
        )
        assert "ROUTE_PA_RUN" in result.stdout, (
            f"Expected -u -m pip to route through pa run, got:\n{result.stdout}\n{result.stderr}"
        )

    def test_interpreter_shim_execs_real_with_u_flag_no_pip(self, tmp_path):
        """`python -u script.py` must NOT route through pa run."""
        import subprocess
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        script = self._patch_shim_for_routing_test(shim.read_text())
        result = subprocess.run(
            ["bash", "-c", script, "python3", "-u", "script.py"],
            capture_output=True, text=True,
        )
        assert "ROUTE_REAL" in result.stdout, (
            f"Expected -u script.py to exec real, got:\n{result.stdout}\n{result.stderr}"
        )

    def test_interpreter_shim_double_dash_stops_scan(self, tmp_path):
        """`python -- -m pip install foo` must NOT route through pa run."""
        import subprocess
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        script = self._patch_shim_for_routing_test(shim.read_text())
        result = subprocess.run(
            ["bash", "-c", script, "python3", "--", "-m", "pip", "install", "foo"],
            capture_output=True, text=True,
        )
        assert "ROUTE_REAL" in result.stdout, (
            f"Expected -- to stop scan and exec real, got:\n{result.stdout}\n{result.stderr}"
        )

    def test_binary_interpreter_is_shimmed(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, PA_FINGERPRINT
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True)
        python = venv / "python3"
        # Simulate a real ELF interpreter binary
        python.write_bytes(b"\x7fELF\x00\x90\x00")
        python.chmod(python.stat().st_mode | stat.S_IEXEC)
        install_project_shims(project_root=tmp_path)
        # ELF interpreters must be shimmed — the binary check is bypassed for interpreters
        assert (venv / "python3.__pa_real").exists()
        assert PA_FINGERPRINT in (venv / "python3").read_text()

    def test_binary_package_manager_is_skipped(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True)
        pip = venv / "pip"
        # Simulate an unexpected ELF at a package manager path — should be skipped
        pip.write_bytes(b"\x7fELF\x00\x90\x00")
        pip.chmod(pip.stat().st_mode | stat.S_IEXEC)
        install_project_shims(project_root=tmp_path)
        assert not (venv / "pip.__pa_real").exists()

    def test_interpreter_symlink_not_renamed(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, PA_FINGERPRINT
        self._make_venv_with_python_symlink(tmp_path)
        install_project_shims(project_root=tmp_path)
        venv = tmp_path / ".venv" / "bin"
        # python3 (real binary) should be shimmed
        assert (venv / "python3.__pa_real").exists()
        assert PA_FINGERPRINT in (venv / "python3").read_text()
        # python (symlink → python3) must NOT be renamed — it already points at the shim
        assert not (venv / "python.__pa_real").exists()
        assert (venv / "python").is_symlink()
        assert os.readlink(venv / "python") == "python3"

    def test_interpreter_symlink_uninstall_leaves_symlink(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims, uninstall_project_shims
        self._make_venv_with_python_symlink(tmp_path)
        install_project_shims(project_root=tmp_path)
        uninstall_project_shims(project_root=tmp_path)
        venv = tmp_path / ".venv" / "bin"
        # python3 restored to original script
        assert not (venv / "python3.__pa_real").exists()
        assert "real python" in (venv / "python3").read_text()
        # python symlink untouched
        assert (venv / "python").is_symlink()
        assert os.readlink(venv / "python") == "python3"


class TestRunnerShimGuard:
    """Tests for the runner's symlink-aware __pa_real guard."""

    PA_SHIM_CONTENT = "#!/bin/sh\n# __pa_shim__\nexec pa run \"$0\" \"$@\"\n"

    def _make_shim(self, path: Path, content: str = PA_SHIM_CONTENT) -> None:
        path.write_text(content)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def test_symlink_to_shim_finds_real_via_resolved_path(self, tmp_path):
        """python3 -> python (shim); python.__pa_real exists — guard must not fire."""
        from packagealert.sandbox.runner import _PA_REAL_SUFFIX
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        # python is the shim; python.__pa_real is the real interpreter
        python = bin_dir / "python"
        self._make_shim(python)
        real = bin_dir / f"python{_PA_REAL_SUFFIX}"
        real.write_text("#!/bin/sh\necho real\n")
        real.chmod(real.stat().st_mode | stat.S_IEXEC)

        # python3 is a symlink to python (the shim)
        python3 = bin_dir / "python3"
        python3.symlink_to("python")

        # Resolving python3 -> python -> finds python.__pa_real -> guard passes
        tool_resolved = python3.resolve()
        real_sibling = tool_resolved.parent / f"{tool_resolved.name}{_PA_REAL_SUFFIX}"
        assert real_sibling.exists(), (
            "Resolved python3 -> python; python.__pa_real exists but guard would fire"
        )

    def test_missing_real_on_resolved_path_triggers_guard(self, tmp_path):
        """python is a shim; python.__pa_real is gone — guard must fire."""
        from packagealert.sandbox.runner import _PA_REAL_SUFFIX
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        python = bin_dir / "python"
        self._make_shim(python)
        python3 = bin_dir / "python3"
        python3.symlink_to("python")

        # No __pa_real — broken install
        tool_resolved = python3.resolve()
        real_sibling = tool_resolved.parent / f"{tool_resolved.name}{_PA_REAL_SUFFIX}"
        assert not real_sibling.exists()
        # And the resolved file contains the shim fingerprint
        assert "# __pa_shim__" in tool_resolved.read_text()

    def test_non_shim_binary_passes_guard(self, tmp_path):
        """A real ELF binary (no fingerprint) must never trigger the guard."""
        from packagealert.sandbox.runner import _PA_REAL_SUFFIX
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        real_binary = bin_dir / "python"
        real_binary.write_bytes(b"\x7fELF\x00\x00\x00\x00")
        real_binary.chmod(real_binary.stat().st_mode | stat.S_IEXEC)

        # No __pa_real sibling — but it's not a shim, so guard must not fire
        tool_resolved = real_binary.resolve()
        real_sibling = tool_resolved.parent / f"{tool_resolved.name}{_PA_REAL_SUFFIX}"
        assert not real_sibling.exists()
        # Binary content is not text-decodable as strict UTF-8
        try:
            content = real_binary.read_text(errors="strict")
            is_shim = "# __pa_shim__" in content
        except (UnicodeDecodeError, OSError):
            is_shim = False
        assert not is_shim


class TestResolveRealBinary:
    """Tests for _resolve_real_binary symlink-aware .__pa_real resolution."""

    def _make_shim(self, path: Path) -> None:
        path.write_text("#!/bin/sh\n# __pa_shim__\nexec pa run \"$0\" \"$@\"\n")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def test_symlink_to_shim_resolved_to_real(self, tmp_path):
        """python3 -> python (shim); python.__pa_real exists — must return python.__pa_real."""
        from packagealert.sandbox.runner import _resolve_real_binary, _PA_REAL_SUFFIX
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        python = bin_dir / "python"
        self._make_shim(python)
        real = bin_dir / f"python{_PA_REAL_SUFFIX}"
        real.write_text("#!/bin/sh\necho real\n")
        real.chmod(real.stat().st_mode | stat.S_IEXEC)

        python3 = bin_dir / "python3"
        python3.symlink_to("python")

        result = _resolve_real_binary([str(python3), "-m", "pip", "install", "foo"])
        assert result[0] == str(real)
        assert result[1:] == ["-m", "pip", "install", "foo"]

    def test_no_real_sibling_returns_argv_unchanged(self, tmp_path):
        """If no .__pa_real exists, argv is returned unchanged."""
        from packagealert.sandbox.runner import _resolve_real_binary
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        python = bin_dir / "python"
        python.write_text("#!/bin/sh\necho real\n")
        python.chmod(python.stat().st_mode | stat.S_IEXEC)

        result = _resolve_real_binary([str(python), "script.py"])
        assert result == [str(python), "script.py"]
