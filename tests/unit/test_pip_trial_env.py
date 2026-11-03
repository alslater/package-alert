"""tests/fixtures/pip_trial/env.example.sh must refuse a scratch root that is the user's home or
inside ~/.local, however either is spelled: the recorder deletes work directories under it."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

TRIAL_DIR = Path(__file__).parents[1] / "fixtures" / "pip_trial"
ENV_SCRIPT = TRIAL_DIR / "env.example.sh"


def _source(home: Path, scratch: Path) -> subprocess.CompletedProcess[str]:
    env = {"HOME": str(home), "PA_PIPX_SCRATCH": str(scratch), "PATH": os.defpath}
    return subprocess.run(["bash", "-c", f'. "{ENV_SCRIPT}"'], env=env, capture_output=True, text=True,
                          check=False, timeout=30)


def _stub_pipx(bin_dir: Path) -> None:
    """A pipx whose ``environment`` reports the locations pipx 1.18.4 derives from the variables
    env.example.sh sets; any other command fails loudly."""
    bin_dir.mkdir()
    stub = bin_dir / "pipx"
    stub.write_text('#!/bin/sh\n[ "$1" = environment ] || { echo "stub pipx: $*" >&2; exit 99; }\n'
                    'echo "PIPX_HOME=$PIPX_HOME"; echo "PIPX_BIN_DIR=$PIPX_BIN_DIR"; echo "PIPX_MAN_DIR=$PIPX_MAN_DIR"\n'
                    'echo "PIPX_SHARED_LIBS=$PIPX_SHARED_LIBS"; echo "PIPX_LOCAL_VENVS=$PIPX_HOME/venvs"\n'
                    'echo "PIPX_LOG_DIR=$PIPX_HOME/logs"; echo "PIPX_TRASH_DIR=$PIPX_HOME/.trash"\n'
                    'echo "PIPX_COMPLETION_DIR=$PIPX_COMPLETION_DIR"\n')
    stub.chmod(0o755)


def _run(script: str, args: list[str], home: Path, scratch: Path, bin_dir: Path) -> subprocess.CompletedProcess[str]:
    env = {"HOME": str(home), "PA_PIPX_SCRATCH": str(scratch), "PATH": f"{bin_dir}:{os.defpath}"}
    return subprocess.run(["bash", str(TRIAL_DIR / script), *args], env=env, capture_output=True, text=True,
                          check=False, timeout=30)


@pytest.mark.parametrize("scratch", ["home", "real", "local"])
def test_the_real_home_is_refused_through_a_linked_home(tmp_path: Path, scratch: str) -> None:
    real = tmp_path / "real"
    (real / ".local" / "x").mkdir(parents=True)
    home = tmp_path / "home"
    home.symlink_to(real, target_is_directory=True)
    target = {"home": home, "real": real, "local": home / ".local" / "x"}[scratch]
    res = _source(home, target)
    assert res.returncode != 0 and "refusing scratch root" in res.stderr
    assert sorted(p.name for p in real.iterdir()) == [".local"], "nothing is created in the home"


def test_a_scratch_directory_in_a_linked_home_is_accepted(tmp_path: Path) -> None:
    real = tmp_path / "real"
    (real / "scratch").mkdir(parents=True)
    home = tmp_path / "home"
    home.symlink_to(real, target_is_directory=True)
    res = _source(home, home / "scratch")
    assert "refusing scratch root" not in res.stderr
    assert (real / "scratch" / "work").is_dir()


@pytest.mark.parametrize("spelling", ["link", "target"])
def test_the_target_of_a_linked_local_is_refused(tmp_path: Path, spelling: str) -> None:
    home = tmp_path / "home"
    home.mkdir()
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "x").mkdir(parents=True)
    (home / ".local").symlink_to(elsewhere, target_is_directory=True)
    res = _source(home, home / ".local" / "x" if spelling == "link" else elsewhere / "x")
    assert res.returncode != 0 and "refusing scratch root" in res.stderr
    assert not (elsewhere / "x" / "work").exists()


@pytest.mark.parametrize("script", ["record_trial.sh", "readonly_trial.sh"])
@pytest.mark.parametrize(("which", "name"), [("case", "../../victim"), ("case", ".."), ("case", ""),
                                             ("app", "../x"), ("app", "a/b")])
def test_a_case_or_app_name_is_one_path_component(tmp_path: Path, script: str, which: str, name: str) -> None:
    """The recorder deletes $S/work/CASE: a CASE such as ../../victim would delete a directory
    outside the scratch root."""
    home = tmp_path / "home"
    scratch = home / "scratch"
    scratch.mkdir(parents=True)
    victim = home / "victim"
    (victim / "keep").mkdir(parents=True)
    _stub_pipx(tmp_path / "bin")
    case, app = (name, "app") if which == "case" else ("c", name)
    args = [case, app, "", ""] if script == "record_trial.sh" else [case, app]
    env = {"HOME": str(home), "PA_PIPX_SCRATCH": str(scratch), "PATH": f"{tmp_path / 'bin'}:{os.defpath}"}
    res = subprocess.run(["bash", str(TRIAL_DIR / script), *args], env=env, capture_output=True, text=True,
                         check=False, timeout=30)
    assert res.returncode == 2 and "single path component" in res.stderr, res.stderr
    assert (victim / "keep").is_dir()


@pytest.mark.parametrize("entry", ["work", "bin"])
def test_a_linked_scratch_work_or_bin_directory_is_refused(tmp_path: Path, entry: str) -> None:
    """The recorders delete $S/work/CASE: a $S/work that links elsewhere would have them delete
    there instead, although $S itself passes every check."""
    home = tmp_path / "home"
    scratch = home / "scratch"
    scratch.mkdir(parents=True)
    elsewhere = home / "existing"
    (elsewhere / "case1").mkdir(parents=True)
    (scratch / entry).symlink_to(elsewhere, target_is_directory=True)
    _stub_pipx(tmp_path / "bin")
    env = {"HOME": str(home), "PA_PIPX_SCRATCH": str(scratch), "PATH": f"{tmp_path / 'bin'}:{os.defpath}"}
    res = subprocess.run(["bash", str(TRIAL_DIR / "record_trial.sh"), "case1", "app", "", ""], env=env,
                         capture_output=True, text=True, check=False, timeout=30)
    assert res.returncode != 0 and f"{scratch / entry} is a link" in res.stderr, res.stderr
    assert (elsewhere / "case1").is_dir()


@pytest.mark.parametrize("linked", ["pipx_home", "pipx_home/venvs"])
def test_a_scratch_pipx_home_linking_into_the_real_one_is_refused(tmp_path: Path, linked: str) -> None:
    """Every location pipx derives is spelled under $S, so only its resolved path shows that a
    linked pipx_home (or venvs inside it) leads into the user's real pipx environments."""
    home = tmp_path / "home"
    real = home / ".local" / "pipx"
    (real / "venvs" / "app").mkdir(parents=True)
    scratch = home / "scratch"
    scratch.mkdir()
    target = real if linked == "pipx_home" else real / "venvs"
    if linked != "pipx_home":
        (scratch / "pipx_home").mkdir()
    (scratch / linked).symlink_to(target, target_is_directory=True)
    _stub_pipx(tmp_path / "bin")
    res = _run("record_trial.sh", ["case1", "app", "", ""], home, scratch, tmp_path / "bin")
    assert res.returncode != 0 and "resolves outside" in res.stderr, res.stderr
    assert sorted(p.name for p in (real / "venvs").iterdir()) == ["app"]


def test_the_scratch_isolation_check_still_passes_without_links(tmp_path: Path) -> None:
    home = tmp_path / "home"
    scratch = home / "scratch"
    scratch.mkdir(parents=True)
    _stub_pipx(tmp_path / "bin")
    env = {"HOME": str(home), "PA_PIPX_SCRATCH": str(scratch), "PATH": f"{tmp_path / 'bin'}:{os.defpath}"}
    res = subprocess.run(["bash", "-ec", f'. "{ENV_SCRIPT}"; echo ok'], env=env, capture_output=True, text=True,
                         check=False, timeout=30)
    assert res.returncode == 0 and res.stdout.strip() == "ok", res.stderr


def test_readonly_trial_writes_into_a_fresh_directory_not_a_linked_one(tmp_path: Path) -> None:
    """A $S/work/ro linking elsewhere is not reused: the redirections would truncate files there
    before bwrap even starts."""
    home = tmp_path / "home"
    scratch = home / "scratch"
    (scratch / "pipx_home" / "venvs").mkdir(parents=True)
    (scratch / "pipx_home" / "venvs" / ".app.lock").write_text("")
    (scratch / "work").mkdir()
    results = home / "existing-results"
    results.mkdir()
    (results / "case1.out").write_text("keep\n")
    (scratch / "work" / "ro").symlink_to(results, target_is_directory=True)
    _stub_pipx(tmp_path / "bin")
    res = _run("readonly_trial.sh", ["case1", "app"], home, scratch, tmp_path / "bin")
    assert "output in " + str(scratch / "work" / "ro.") in res.stdout, res.stderr
    assert (results / "case1.out").read_text() == "keep\n"
    assert sorted(p.name for p in results.iterdir()) == ["case1.out"]
