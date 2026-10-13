"""pa fix --apply's re-resolve with a real uv (network and bwrap required)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from packagealert.remediate import apply
from packagealert.remediate.planner import FixPlan, PlannedFix

UV = str(Path(__file__).resolve().parents[2] / ".venv" / "bin" / "uv")
# How uv reports a registry it could not reach.
_NETWORK_ERROR = re.compile(
    r"Failed to fetch|error sending request|dns error|failed to lookup address|Connection (?:refused|reset)"
    r"|operation timed out|Request failed after \d+ retries", re.IGNORECASE)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap not installed"),
    pytest.mark.skipif(not Path(UV).exists(), reason="the repository's .venv/bin/uv does not exist"),
]


def _lock(p: Path) -> None:
    r = subprocess.run([UV, "lock", "-q", "--upgrade-package", "urllib3==2.2.1"], cwd=p,
                       check=False, capture_output=True, text=True, timeout=300)
    if r.returncode:
        # Only a registry uv could not reach is an outage to skip; any other failure is a
        # regression (in the command, the fixture or uv) and fails.
        if _NETWORK_ERROR.search(r.stderr):
            pytest.skip(f"uv could not reach the registry: {r.stderr[-200:]}")
        pytest.fail(f"uv lock failed on the scratch project: {r.stderr[-500:]}")


def _project(tmp_path: Path, pyproject: str) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "pyproject.toml").write_text(pyproject)
    _lock(p)
    return p


async def _apply(tmp_path, project, after):
    from packagealert.cli.fix_cmd import _FixTrialRunner
    from packagealert.cli.run_settings import ProjectRunSettings
    from packagealert.config import load_config
    from packagealert.languages import registry
    from packagealert.languages.python_fix.uv import UvFixAdapter
    from packagealert.sandbox.runner import SandboxRunner

    registry.load()
    item = PlannedFix(package="urllib3", version="2.2.1", target="2.8.0", direct=True, path=["proj", "urllib3"],
                      advisories=["GHSA-x"], left_open=[], cooldown_checked=True, verified=True)
    plan = FixPlan(planned=[item], verified_after=after)
    adapter = UvFixAdapter()
    run = _FixTrialRunner(SandboxRunner(load_config(None)), project,
                          ProjectRunSettings(None, {}, [], False, False, False, False))
    snap = apply.snapshot(project, apply.checked_files(adapter))
    return await apply.apply_plan(adapter, plan, run, snap, tmp_path / "backups")


async def test_static_project_is_applied(tmp_path):
    from packagealert.languages.python_fix.uv import versions_in

    project = _project(tmp_path, '[project]\nname = "p"\nversion = "0.1.0"\nrequires-python = ">=3.12"\n'
                                 'dependencies = ["urllib3>=2"]\n')
    expected = dict(versions_in((project / "uv.lock").read_bytes()))
    expected["urllib3"] = frozenset({"2.8.0"})
    result = await _apply(tmp_path, project, expected)
    reason = result.reason or ""
    # Only a network failure while re-resolving is skipped (_lock() has just shown the network
    # works, so this is a transient outage); any other refusal is a regression and fails.
    if not result.applied and _NETWORK_ERROR.search(reason):
        pytest.skip(reason)
    assert result.applied, result.reason
    assert versions_in((project / "uv.lock").read_bytes())["urllib3"] == frozenset({"2.8.0"})


async def test_dynamic_project_outside_git_is_refused_without_writing(tmp_path):
    p = tmp_path / "proj"
    (p / "src" / "dynp").mkdir(parents=True)
    (p / "src" / "dynp" / "__init__.py").write_text('__version__ = "0.3.1"\n')
    (p / "pyproject.toml").write_text('[project]\nname = "dynp"\ndynamic = ["version"]\nrequires-python = ">=3.12"\n'
                                     'dependencies = ["urllib3>=2"]\n[build-system]\nrequires = ["hatchling"]\n'
                                     'build-backend = "hatchling.build"\n[tool.hatch.version]\n'
                                     'path = "src/dynp/__init__.py"\n')
    _lock(p)
    before = (p / "uv.lock").read_bytes()
    result = await _apply(tmp_path, p, {"urllib3": frozenset({"2.8.0"})})
    assert not result.applied
    assert result.reason is not None and "git" in result.reason
    assert (p / "uv.lock").read_bytes() == before


def test_a_lock_failure_that_is_not_a_network_error_fails(tmp_path):
    """The setup helper fails, rather than skips, when uv lock fails for any other reason."""
    p = tmp_path / "proj"
    p.mkdir()
    (p / "pyproject.toml").write_text('[project]\nname = "p"\nversion = "not a version"\n')
    # Any outcome is caught (a skip included), so the test fails if the helper skips.
    with pytest.raises(BaseException) as outcome:
        _lock(p)
    assert outcome.type is pytest.fail.Exception, outcome.type
    assert "uv lock failed" in str(outcome.value)
