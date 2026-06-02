import asyncio
import os
import stat
import time
from pathlib import Path
from unittest.mock import patch
import pytest


PA_FINGERPRINT = "# __pa_shim__"
PA_REAL_SUFFIX = ".__pa_real"


@pytest.fixture(autouse=True)
def mock_pa_executable():
    with patch(
        "packagealert.cli.setup_cmd._pa_executable",
        return_value="/usr/local/bin/package-alert",
    ):
        yield


@pytest.fixture
def venv_project(tmp_path):
    """Minimal project with a .venv/bin/pip binary."""
    bin_dir = tmp_path / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    pip = bin_dir / "pip"
    pip.write_text("#!/bin/sh\necho real pip\n")
    pip.chmod(pip.stat().st_mode | stat.S_IEXEC)
    return tmp_path


class TestSetupProjectIntegration:
    def test_shim_installed_and_executable(self, venv_project):
        from packagealert.cli.setup_cmd import install_project_shims
        install_project_shims(project_root=venv_project)
        shim = venv_project / ".venv" / "bin" / "pip"
        real = venv_project / ".venv" / "bin" / f"pip{PA_REAL_SUFFIX}"
        assert real.exists()
        assert PA_FINGERPRINT in shim.read_text()
        assert os.access(shim, os.X_OK)

    def test_uninstall_restores(self, venv_project):
        from packagealert.cli.setup_cmd import install_project_shims, uninstall_project_shims
        install_project_shims(project_root=venv_project)
        uninstall_project_shims(project_root=venv_project)
        pip = venv_project / ".venv" / "bin" / "pip"
        real = venv_project / ".venv" / "bin" / f"pip{PA_REAL_SUFFIX}"
        assert not real.exists()
        assert "real pip" in pip.read_text()

    def test_idempotent(self, venv_project):
        from packagealert.cli.setup_cmd import install_project_shims
        install_project_shims(project_root=venv_project)
        install_project_shims(project_root=venv_project)
        real = venv_project / ".venv" / "bin" / f"pip{PA_REAL_SUFFIX}"
        assert real.exists()
        assert not (venv_project / ".venv" / "bin" / f"pip{PA_REAL_SUFFIX}{PA_REAL_SUFFIX}").exists()


class TestCooldownAllowIntegration:
    def test_cooldown_allow_creates_cleared_record(self, tmp_path):
        from packagealert.storage.db import open_db, get_cooldown_cleared_at, store_cooldown_cleared

        async def _run():
            db = await open_db(tmp_path / "test.db")
            await store_cooldown_cleared(db, ecosystem="PyPI", package="requests", version="2.31.0")
            result = await get_cooldown_cleared_at(db, ecosystem="PyPI", package="requests", version="2.31.0")
            await db.close()
            return result

        result = asyncio.run(_run())
        assert result is not None
        assert result == pytest.approx(time.time(), abs=5)


class TestCooldownEngineEndToEnd:
    def test_within_cooldown_non_interactive_blocks(self):
        from packagealert.config import CooldownConfig
        from packagealert.languages.base import PackageSpec
        from packagealert.sandbox.cooldown import decide

        pkg = PackageSpec(name="newpkg", version="1.0.0", ecosystem="PyPI")
        cfg = CooldownConfig(period_days=7, on_new_medium_risk="prompt", non_interactive_escalation="block")
        decision = decide(pkg, age_days=2.0, risk_score=45, cfg=cfg, is_tty=False)
        assert decision.action == "block"

    def test_beyond_cooldown_allows(self):
        from packagealert.config import CooldownConfig
        from packagealert.languages.base import PackageSpec
        from packagealert.sandbox.cooldown import decide

        pkg = PackageSpec(name="oldpkg", version="1.0.0", ecosystem="PyPI")
        cfg = CooldownConfig(period_days=7)
        decision = decide(pkg, age_days=30.0, risk_score=0, cfg=cfg, is_tty=False)
        assert decision.action == "allow"

    def test_cleared_record_allows_within_period(self, tmp_path):
        from packagealert.config import CooldownConfig
        from packagealert.languages.base import PackageSpec
        from packagealert.sandbox.cooldown import decide_with_cleared

        pkg = PackageSpec(name="newpkg", version="1.0.0", ecosystem="PyPI")
        cfg = CooldownConfig(period_days=7)
        cleared_at = time.time() - (2 * 86400)  # cleared 2 days ago, still valid
        decision = decide_with_cleared(
            pkg, age_days=3.0, risk_score=0, cfg=cfg, is_tty=False,
            cleared_at=cleared_at,
        )
        assert decision.action == "allow"
