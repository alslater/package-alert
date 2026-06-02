import os
import stat
from pathlib import Path
import pytest


PA_FINGERPRINT = "package-alert run"
PA_BLOCK_START = "# BEGIN package-alert shell integration"
PA_BLOCK_END = "# END package-alert shell integration"


class TestSetupShellSnippet:
    def test_snippet_contains_pip_function(self):
        from packagealert.cli.setup_cmd import generate_shell_snippet
        snippet = generate_shell_snippet(shell="bash")
        assert "pip()" in snippet
        assert PA_FINGERPRINT in snippet

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
        python = venv / "python3"
        python.write_text("#!/bin/sh\necho real python\n")
        python.chmod(python.stat().st_mode | stat.S_IEXEC)
        return tmp_path

    def test_interpreter_shim_installed(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        real = tmp_path / ".venv" / "bin" / "python3.__pa_real"
        assert real.exists()
        assert PA_FINGERPRINT in shim.read_text()

    def test_interpreter_shim_intercepts_m_pip(self, tmp_path):
        import subprocess
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        content = shim.read_text()
        assert "-m pip" in content
        assert "package-alert run pip" in content

    def test_interpreter_shim_passes_through_other_args(self, tmp_path):
        import subprocess
        from packagealert.cli.setup_cmd import install_project_shims
        self._make_venv_with_python(tmp_path)
        install_project_shims(project_root=tmp_path)
        shim = tmp_path / ".venv" / "bin" / "python3"
        content = shim.read_text()
        # The pass-through branch must exec the .__pa_real binary, not package-alert run
        assert "python3.__pa_real" in content

    def test_binary_interpreter_is_skipped(self, tmp_path):
        from packagealert.cli.setup_cmd import install_project_shims
        venv = tmp_path / ".venv" / "bin"
        venv.mkdir(parents=True)
        python = venv / "python3"
        # Simulate an ELF binary with non-UTF-8 bytes
        python.write_bytes(b"\x7fELF\x00\x90\x00")
        python.chmod(python.stat().st_mode | stat.S_IEXEC)
        install_project_shims(project_root=tmp_path)
        assert not (venv / "python3.__pa_real").exists()
