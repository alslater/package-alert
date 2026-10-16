"""Container isolation end to end: no bwrap needed (network and a non-root user required)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from packagealert.sandbox import isolation

ROOT = Path(__file__).resolve().parents[2]
UV = str(ROOT / ".venv" / "bin" / "uv")
PA = str(ROOT / ".venv" / "bin" / "pa")
_NETWORK_ERROR = re.compile(
    r"Failed to fetch|error sending request|dns error|failed to lookup address|Connection (?:refused|reset)"
    r"|operation timed out|Request failed after \d+ retries|could not be checked against OSV", re.IGNORECASE)

def _system_python_312() -> bool:
    """With a fresh HOME, uv finds no uv-managed Python; it needs one >= 3.12 on PATH (or would download one)."""
    if not Path(UV).exists():
        return False
    cache = tempfile.mkdtemp(prefix="pa-probe-cache-")
    try:
        r = subprocess.run([UV, "python", "find", "--system", ">=3.12"], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "HOME": "/nonexistent", "UV_PYTHON_DOWNLOADS": "never",
                                "UV_CACHE_DIR": cache}, check=False)
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    return r.returncode == 0


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.geteuid() == 0, reason="container isolation refuses root"),
    pytest.mark.skipif(not Path(UV).exists(), reason="the repository's .venv/bin/uv does not exist"),
    pytest.mark.skipif(not _system_python_312(), reason="needs a system Python >= 3.12 on PATH"),
]


# --- credential-path parity: uv must look exactly where the snapshot was placed ---


@pytest.mark.parametrize("xdg", [None, "xdg", "symlinked-local"])
def test_uv_auth_dir_names_the_rebased_snapshot(tmp_path, xdg):
    real = (tmp_path / "home").resolve()
    fresh = (tmp_path / "fresh").resolve()
    real.mkdir()
    fresh.mkdir()
    if xdg == "symlinked-local":
        # ~/.local -> ~/dotfiles/local: uv still looks under <HOME>/.local, not the link's target.
        (real / "dotfiles" / "local").mkdir(parents=True)
        (real / ".local").symlink_to(real / "dotfiles" / "local")
        xdg = None
    env = {"PATH": os.environ["PATH"], "HOME": str(real)}
    if xdg:
        env["XDG_DATA_HOME"] = str(real / xdg)
    data = Path(env["XDG_DATA_HOME"]) if xdg else real / ".local" / "share"
    dest = data / "uv" / "credentials"
    dest.mkdir(parents=True)
    src = tmp_path / "pa-uv-auth-snap"
    src.mkdir()
    (src / "credentials.toml").write_text("[[credential]]\n")
    isolation.populate_home(fresh, [], [(src, dest)], exclude=[], real_home=real, deny=[])
    child_env = isolation.container_env(env, real, fresh)
    out = subprocess.run([UV, "auth", "dir"], env=child_env, capture_output=True, text=True, check=True)
    expected = fresh / dest.relative_to(real)
    assert Path(out.stdout.strip()) == expected
    assert (expected / "credentials.toml").exists()


def _symlinked_uv_home(tmp_path, monkeypatch, shape):
    home = tmp_path / "home"
    named = home / ".local" / "share" / "uv" / "credentials"
    if shape == "parent":  # ~/.local -> ~/dotfiles/local
        store = home / "dotfiles" / "local" / "share" / "uv" / "credentials"
        store.mkdir(parents=True)
        (home / ".local").symlink_to(home / "dotfiles" / "local")
    else:  # ~/.local/share/uv/credentials -> ~/.auth/uv
        store = home / ".auth" / "uv"
        store.mkdir(parents=True)
        named.parent.mkdir(parents=True)
        named.symlink_to(store)
    (store / "credentials.toml").write_text("[[credential]]\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", f"{ROOT / '.venv' / 'bin'}:{os.environ['PATH']}")
    snaps = tmp_path / "snaps"
    snaps.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(snaps))
    return home


@pytest.mark.parametrize("shape", ["parent", "itself"])
def test_uv_names_the_hooks_snapshot_under_container_isolation(tmp_path, monkeypatch, shape):
    # End to end with uv naming the store: the plugin's hook and hidden paths, the fresh home,
    # and `uv auth dir` run with container_env()'s environment.
    from packagealert.languages.base import SandboxTargets
    from packagealert.languages.python import PythonLanguage

    home = _symlinked_uv_home(tmp_path, monkeypatch, shape)
    binds = PythonLanguage().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), SandboxTargets())
    assert binds, "the hook found no credential store"
    # Told apart from a copy of the real store (same contents) by a marker only the snapshot has.
    (binds[0][0] / "credentials.toml").write_text("# snapshot\n[[credential]]\n")
    hidden = isolation._hidden_home_paths()
    assert hidden, "nothing hidden: the real store would be copied in from the home entry"
    fresh = (tmp_path / "fresh").resolve()
    fresh.mkdir()
    real = home.resolve()
    isolation.populate_home(fresh, [home / ".local" / "share" / "uv"], binds, exclude=[], real_home=real, deny=[],
                            hidden=hidden)
    child_env = isolation.container_env({"PATH": os.environ["PATH"], "HOME": str(home)}, real, fresh)
    out = subprocess.run([UV, "auth", "dir"], env=child_env, capture_output=True, text=True, check=True)
    named = Path(out.stdout.strip())
    assert named == fresh / ".local" / "share" / "uv" / "credentials"
    assert (named / "credentials.toml").read_text() == "# snapshot\n[[credential]]\n"


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap not installed")
@pytest.mark.parametrize("shape", ["plain", "itself"])
def test_uv_auth_snapshot_is_readable_and_writable_under_bwrap(tmp_path, monkeypatch, shape):
    # bwrap skips a bind whose destination is a symlink, so the hook must bind the resolved dir.
    from packagealert.languages.base import SandboxTargets
    from packagealert.languages.python import PythonLanguage
    from packagealert.sandbox import runner as sandbox_runner
    from packagealert.sandbox.bwrap import build_cmd

    if not sandbox_runner.bwrap_available():
        pytest.skip("bwrap cannot create a sandbox here")
    if shape == "plain":
        home = tmp_path / "home"
        store = home / ".local" / "share" / "uv" / "credentials"
        store.mkdir(parents=True)
        (store / "credentials.toml").write_text("[[credential]]\n")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.setenv("PATH", f"{ROOT / '.venv' / 'bin'}:{os.environ['PATH']}")
        snaps = tmp_path / "snaps"
        snaps.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(snaps))
    else:
        home = _symlinked_uv_home(tmp_path, monkeypatch, shape)
    named = PythonLanguage._uv_credentials_dir()
    binds = PythonLanguage().configure_sandbox_writable(None, tmp_path, frozenset({"uv-auth"}), SandboxTargets())
    try:
        home_ro = sandbox_runner._home_ro_dirs()
        script = f"cat {named}/credentials.toml && touch {named}/written && echo WROTE"
        cmd = build_cmd(["/bin/sh", "-c", script], [], env={"PATH": os.environ["PATH"], "HOME": str(home)},
                        home_ro_dirs=home_ro, writable_binds=binds,
                        post_ro_tmpfs=sandbox_runner._post_ro_tmpfs_dirs(home_ro))
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        assert res.returncode == 0, res.stderr
        assert res.stdout.split() == ["[[credential]]", "WROTE"]
    finally:
        sandbox_runner._cleanup_writable_binds(binds)


# --- pa fix end to end ---


def _clean_env(home: Path, **extra: str) -> dict[str, str]:
    env = {"PATH": f"{ROOT / '.venv' / 'bin'}:{os.environ['PATH']}", "HOME": str(home), "LANG": "C.UTF-8",
           isolation.ENV_VAR: isolation.CONTAINER}
    env.update(extra)
    return env


def _pa_fix(project: Path, env: dict[str, str]) -> dict:
    r = subprocess.run([PA, "fix", ".", "--format", "json"], cwd=project, env=env, capture_output=True, text=True,
                       timeout=900, check=False)
    if r.returncode not in (0, 1):
        pytest.fail(f"pa fix exited {r.returncode}: {r.stderr[-800:]}")
    data = json.loads(r.stdout)
    # A registry outage surfaces in osv_failures, trial_failure or a held item's detail; never consult
    # unverified_reason, or a genuine verification failure that mentions a timeout would become a skip.
    outage = [data["trial_failure"] or "", *(h.get("detail") or "" for h in data["held"])]
    if data["osv_failures"] or any(_NETWORK_ERROR.search(t) for t in outage):
        pytest.skip("the network was unavailable")
    return data


def _uv_project(tmp_path: Path, pyproject: str) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "pyproject.toml").write_text(pyproject)
    r = subprocess.run([UV, "lock", "-q"], cwd=p, capture_output=True, text=True, timeout=300, check=False)
    if r.returncode:
        if _NETWORK_ERROR.search(r.stderr):
            pytest.skip(f"uv could not reach the registry: {r.stderr[-200:]}")
        pytest.fail(f"uv lock failed: {r.stderr[-500:]}")
    return p


_URLLIB3 = ('[project]\nname = "p"\nversion = "0.1.0"\nrequires-python = ">=3.12"\n'
            'dependencies = ["urllib3==2.2.1"]\n')


def test_uv_plan_is_verified_without_bwrap(tmp_path):
    project = _uv_project(tmp_path, _URLLIB3)
    (project / "pyproject.toml").write_text(_URLLIB3.replace("==2.2.1", ">=2.2.1"))
    home = tmp_path / "home"
    home.mkdir()
    data = _pa_fix(project, _clean_env(home))
    assert data["verified"] is True, data["unverified_reason"]
    assert [p["package"] for p in data["planned"]] == ["urllib3"]
    assert data["planned"][0]["verified"] is True


@pytest.mark.skipif(shutil.which("npm") is None, reason="npm not installed")
def test_npm_plan_is_verified_without_bwrap(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    (p / "package.json").write_text('{"name":"p","version":"1.0.0","dependencies":{"express":"^4.17.1"}}')
    r = subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "express@4.17.1"], cwd=p,
                       capture_output=True, text=True, timeout=300, check=False)
    if r.returncode:
        pytest.skip(f"npm could not lock the fixture: {r.stderr[-200:]}")
    home = tmp_path / "home"
    home.mkdir()
    data = _pa_fix(p, _clean_env(home))
    # What is planned depends on the registry's state (cooldown, newer advisories), which
    # bwrap would see identically; this test checks only that trials ran without bwrap.
    assert data["verified"] is True, data["unverified_reason"]
    assert data["trial_failure"] is None, data["trial_failure"]
    unverifiable = [h for h in data["held"] if h["reason"] == "could not verify"]
    assert unverifiable == [], unverifiable


def test_no_network_project_runs_no_trial(tmp_path):
    project = _uv_project(tmp_path, _URLLIB3)
    (project / "pyproject.toml").write_text(_URLLIB3.replace("==2.2.1", ">=2.2.1"))
    (project / ".pa-run.toml").write_text("no_network = true\n")
    home = tmp_path / "home"
    home.mkdir()
    data = _pa_fix(project, _clean_env(home))
    assert data["verified"] is False
    assert data["unverified_reason"] == "network is disabled by the project run config"
    # No trial ran: the plan is reported but never verified, and nothing was held or failed by a trial.
    assert data["planned"] and all(p["verified"] is False for p in data["planned"])
    assert data["held"] == []
    assert data["trial_failure"] is None


# --- R1: same-uid /proc access is why the launcher must hold no secrets ---

_BACKEND = '''
import os

# A positive witness that the backend ran: container isolation does not confine writes (R4), so an
# absolute path outside the trial's directory survives the run.
WITNESS = __WITNESS__

def _hunt():
    with open(WITNESS, "a") as f:
        f.write("hunted\\n")
    pid = os.getppid()
    while pid > 1:
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                if b"PA_TEST_SECRET=" in f.read():
                    raise RuntimeError("LEAKED-PA_TEST_SECRET")
            with open(f"/proc/{pid}/stat") as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError):
            return

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    _hunt()
    d = os.path.join(metadata_directory, "leaky-0.1.0.dist-info")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "METADATA"), "w") as f:
        f.write("Metadata-Version: 2.1\\nName: leaky\\nVersion: 0.1.0\\nRequires-Dist: urllib3>=2.2.1\\n")
    return "leaky-0.1.0.dist-info"

def get_requires_for_build_wheel(config_settings=None):
    _hunt()
    return []

# uv resolves the root project through the editable hooks and falls back to build_editable
# (a backend with only the wheel hooks fails: "module has no attribute 'build_editable'").
get_requires_for_build_editable = get_requires_for_build_wheel
prepare_metadata_for_build_editable = prepare_metadata_for_build_wheel

def _wheel(wheel_directory):
    import zipfile
    name = "leaky-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(os.path.join(wheel_directory, name), "w") as z:
        z.writestr("leaky-0.1.0.dist-info/METADATA",
                   "Metadata-Version: 2.1\\nName: leaky\\nVersion: 0.1.0\\nRequires-Dist: urllib3>=2.2.1\\n")
        z.writestr("leaky-0.1.0.dist-info/WHEEL", "Wheel-Version: 1.0\\nGenerator: leaky\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n")
        z.writestr("leaky-0.1.0.dist-info/RECORD", "")
    return name

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _hunt()
    return _wheel(wheel_directory)

def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    _hunt()
    return _wheel(wheel_directory)
'''

_LEAKY = ('[project]\nname = "leaky"\ndynamic = ["version"]\nrequires-python = ">=3.12"\n'
          'dependencies = ["urllib3>=2.2.1"]\n'
          '[build-system]\nrequires = []\nbuild-backend = "leaky_backend"\nbackend-path = ["."]\n')


def _witness(tmp_path: Path) -> Path:
    return tmp_path / "backend-ran"


def _leaky_project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    (p / "leaky_backend.py").write_text(_BACKEND.replace("__WITNESS__", repr(str(_witness(tmp_path)))))
    (p / "pyproject.toml").write_text(_LEAKY)
    # The backend matches the variable's name, so the setup lock must not carry it at all.
    env = {k: v for k, v in os.environ.items() if k != "PA_TEST_SECRET"}
    r = subprocess.run([UV, "lock", "-q", "--upgrade-package", "urllib3==2.2.1"], cwd=p, capture_output=True,
                       text=True, timeout=300, check=False, env=env)
    if r.returncode:
        if _NETWORK_ERROR.search(r.stderr):
            pytest.skip("network")
        pytest.fail(f"uv lock failed: {r.stderr[-500:]}")
    # The setup lock ran the backend too; only a run under pa fix may leave the witness.
    _witness(tmp_path).unlink(missing_ok=True)
    return p


def test_a_scrubbed_launch_leaks_nothing(tmp_path):
    project = _leaky_project(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    data = _pa_fix(project, _clean_env(home))
    assert "LEAKED-PA_TEST_SECRET" not in json.dumps(data)
    # Not vacuous: the backend really ran (and hunted) under pa fix's trial.
    witness = _witness(tmp_path)
    assert witness.exists() and "hunted" in witness.read_text(), "the build backend never ran under pa fix"


def test_control_a_secret_in_pas_environment_is_reachable(tmp_path):
    # Proves the test can see the leak R1 exists to prevent: same-uid code reads pa's environ.
    project = _leaky_project(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    data = _pa_fix(project, _clean_env(home, PA_TEST_SECRET="s3cret"))
    assert "LEAKED-PA_TEST_SECRET" in json.dumps(data)
