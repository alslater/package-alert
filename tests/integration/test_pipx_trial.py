"""pa fix --tools --pipx's trial through the real sandbox (bwrap, pipx and network required).

It runs against Task 1's scratch pipx home (PA_PIPX_SCRATCH, see tests/fixtures/pip_trial/README.md),
never the real ~/.local/pipx, and is skipped without one.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from rich.console import Console

from packagealert.cli.fix_cmd import _FixTrialRunner
from packagealert.cli.run_settings import ProjectRunSettings
from packagealert.config import AppConfig
from packagealert.languages import python_tools
from packagealert.languages.python_fix import pipx_app
from packagealert.sandbox import isolation
from packagealert.sandbox.runner import SandboxRunner, bwrap_available

if TYPE_CHECKING:
    from packagealert.remediate.adapter import TrialRunner

pytestmark = [pytest.mark.integration, pytest.mark.bwrap]


async def test_trial_runs_in_the_real_trial_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    """trial() through pa fix's real in_copy and the bwrap sandbox, against Task 1's scratch pipx
    home (PA_PIPX_SCRATCH, see tests/fixtures/pip_trial/README.md), never the real one: its local
    app, whose checkout the trial builds in place (so sandbox.editable_roots names it)."""
    scratch = os.environ.get("PA_PIPX_SCRATCH")
    try:
        mode = isolation.selected()
    except isolation.IsolationError:
        mode = None
    # pipx trials refuse container isolation, so bwrap must be the selected isolation.
    if not scratch or not shutil.which("pipx") or mode != isolation.BWRAP or not bwrap_available():
        pytest.skip("needs PA_PIPX_SCRATCH (a scratch pipx home with localapp), pipx and bwrap isolation")
    home = Path(scratch) / "pipx_home"
    real = Path.home() / ".local" / "pipx"
    assert home.resolve() != real.resolve() and (home / "venvs" / "localapp").is_dir()
    monkeypatch.setenv("PIPX_HOME", str(home))
    monkeypatch.setenv("PIPX_SHARED_LIBS", str(home / "shared"))
    [root] = [r for r in python_tools.tool_roots(("pipx",)) if r.active]
    envs, _ = python_tools.tool_envs(root)
    [env] = [e for e in envs if e.name == "localapp"]
    adapter = pipx_app.PipxAppFixAdapter.for_env(env)
    assert adapter.held_reason() is None
    settings = ProjectRunSettings(source=None, flags={}, env=[], no_network=False, allow_external_lockfiles=False,
                                  no_change=False, expose_ssh_keys=False)
    cfg = AppConfig()
    cfg.sandbox.editable_roots = [Path(scratch) / "src"]
    run = _FixTrialRunner(SandboxRunner(cfg, console=Console(stderr=True)), env.venv_root, settings)
    base = await adapter.baseline(cast("TrialRunner", run))
    assert base is not None and base.status == "resolved"
    assert base.changes == () and base.after == adapter.state.installed
