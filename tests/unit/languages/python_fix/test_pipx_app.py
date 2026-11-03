"""pa fix for pipx apps: metadata, the fix command and the trial command."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from packagealert.languages.python_fix.pipx_app import (
    MetadataError,
    PipxAppFixAdapter,
    PipxMetadata,
    apply_argv,
    is_trial_command,
    option_args,
    parse_pip_trial,
    read_metadata,
    trial_argv,
    trial_files,
)
from packagealert.languages.python_fix.pipx_app import (
    shared_pip_version as _real_shared_pip_version,
)
from packagealert.languages.python_tools import ToolEnv, ToolPackage
from packagealert.remediate import planner
from packagealert.remediate.adapter import (
    Blocker,
    Change,
    CommandResult,
    CopyResult,
    TrialResult,
    Yank,
)
from packagealert.remediate.planner import FixPlan, PlannedFix
from packagealert.remediate.verify import verify_plan
from packagealert.sandbox import runner as runner_mod

if TYPE_CHECKING:
    from packagealert.remediate.adapter import TrialRunner

_PATH = "/home/user/.local/pipx/venvs/{}/bin/{}"


def _w() -> Path:
    """A scratch copy's path (the scratch root is per test)."""
    return runner_mod.SCRATCH_ROOT / "trial-x"


def _pkg(name: str, spec: str, pip_args: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "app_paths": [{"__Path__": _PATH.format(name, name), "__type__": "Path"}],
        "app_paths_of_dependencies": {},
        "apps": [name],
        "apps_of_dependencies": [],
        "include_apps": True,
        "include_dependencies": False,
        "package": name,
        "package_or_url": spec,
        "package_version": "1.0",
        "pinned": False,
        "pip_args": pip_args or [],
        "suffix": "",
        **extra,
    }


def _meta(main: dict[str, Any], injected: dict[str, Any] | None = None, **top: Any) -> dict[str, Any]:
    return {
        "backend": "pip",
        "injected_packages": injected or {},
        "main_package": main,
        "pipx_metadata_version": "0.6",
        "python_version": "Python 3.13.13",
        "venv_args": [],
        **top,
    }


def _read(doc: Any) -> PipxMetadata:
    return read_metadata(json.dumps(doc))


def _httpie() -> PipxMetadata:
    return _read(_meta(
        _pkg("httpie", "httpie", ["--index-url", "https://pypi.example/simple"]),
        {"requests": _pkg("requests", "requests==2.25.1", ["--pre"])},
    ))


def test_read_metadata_reads_main_and_injected() -> None:
    awscli = _read(_meta(_pkg("awscli", "awscli")))
    assert awscli.main.name == "awscli"
    assert awscli.main.spec == "awscli"
    assert awscli.main.main and not awscli.main.local and not awscli.main.editable
    assert awscli.injected == () and awscli.unsupported == ()
    assert awscli.backend == "pip" and awscli.version == "0.6"

    meta = _httpie()
    assert meta.main.pip_args == ("--index-url", "https://pypi.example/simple")
    (requests,) = meta.injected
    assert (requests.name, requests.spec, requests.main) == ("requests", "requests==2.25.1", False)
    assert requests.pip_args == ("--pre",)
    assert meta.unsupported == ()


def test_read_metadata_backend_defaults_to_pip() -> None:
    doc = _meta(_pkg("a", "a"))
    del doc["backend"]
    assert _read(doc).backend == "pip"
    assert _read({**doc, "backend": "uv"}).backend == "uv"


def test_read_metadata_local_and_editable() -> None:
    local = _read(_meta(_pkg("app", "/work/app", ["--force-reinstall", "--editable"])))
    assert local.main.local and local.main.editable
    assert local.unsupported == ()
    url = _read(_meta(_pkg("app", "file:///work/app")))
    assert url.main.local and not url.main.editable
    assert not _read(_meta(_pkg("app", "app @ https://x.example/a.whl"))).main.local


@pytest.mark.parametrize("doc", [
    [],
    "text",
    {"injected_packages": {}},
    {"main_package": {"package": "a"}},
    {"main_package": _pkg("a", "a") | {"package_or_url": 3}},
    {"main_package": _pkg("a", "a", ["--pre"]) | {"pip_args": "--pre"}},
    {"main_package": _pkg("a", "a"), "injected_packages": []},
    {"main_package": _pkg("a", "a"), "injected_packages": {"b": "b"}},
    _meta(_pkg("a", "a\0b")),
    _meta(_pkg("a", "a"), {"b": _pkg("b", "b", ["--pre\0"])}),
    _meta(_pkg("a", "a"), venv_args=["\0"]),
])
def test_read_metadata_rejects_malformed(doc: Any) -> None:
    with pytest.raises(MetadataError):
        _read(doc)


def test_read_metadata_rejects_invalid_json_and_deep_nesting() -> None:
    with pytest.raises(MetadataError):
        read_metadata("{not json")
    with pytest.raises(MetadataError):
        read_metadata('{"main_package": ' + "[" * 100000 + "]" * 100000 + "}")


@pytest.mark.parametrize("arg", [["--no-deps"], ["--target", "x"], ["--use-pep517"]])
def test_unsupported_pip_args_are_recorded(arg: list[str]) -> None:
    meta = _read(_meta(_pkg("a", "a", ["--pre", *arg])))
    assert meta.unsupported == (arg[0],)
    assert meta.main.pip_args == ("--pre",)
    injected = _read(_meta(_pkg("a", "a"), {"b": _pkg("b", "b", arg)}))
    assert arg[0] in injected.unsupported


def test_editable_is_unsupported_on_an_injected_package() -> None:
    meta = _read(_meta(_pkg("a", "a"), {"b": _pkg("b", "/work/b", ["--editable"])}))
    assert meta.unsupported == ("--editable (injected)",)


def test_force_reinstall_is_ignored() -> None:
    meta = _read(_meta(_pkg("app", "/work/app", ["--force-reinstall"])))
    assert meta.unsupported == ()
    assert "--force-reinstall" not in apply_argv("app", meta, [("x", "1")])
    assert "--force-reinstall" not in trial_argv("app", meta, [("x", "1")], workdir=_w())


@pytest.mark.parametrize("spec", ["a\n--index-url https://evil", "a\r-r x", "a\x00", "a\x7f", "-r evil.txt", "--pre"])
@pytest.mark.parametrize("where", ["spec", "name", "injected"])
def test_read_metadata_rejects_option_injection(spec: str, where: str) -> None:
    if where == "spec":
        doc = _meta(_pkg("a", spec))
    elif where == "name":
        doc = _meta(_pkg(spec, "a"))
    else:
        doc = _meta(_pkg("a", "a"), {"b": _pkg("b", spec)})
    with pytest.raises(MetadataError):
        _read(doc)


def test_read_metadata_rejects_unknown_version_and_missing_pip_args() -> None:
    with pytest.raises(MetadataError, match="unsupported pipx metadata version 99"):
        _read(_meta(_pkg("a", "a"), pipx_metadata_version="99"))
    doc = _meta(_pkg("a", "a"))
    del doc["main_package"]["pip_args"]
    with pytest.raises(MetadataError):
        _read(doc)
    assert _read(_meta(_pkg("a", "a"), pipx_metadata_version="0.12")).version == "0.12"


@pytest.mark.parametrize("name", ["-r", "a b", "a\nb", "", "a==1"])
def test_bad_pin_names_are_refused(name: str) -> None:
    meta = _httpie()
    with pytest.raises(ValueError):
        apply_argv("httpie", meta, [(name, "1.0")])
    with pytest.raises(ValueError):
        trial_argv("httpie", meta, [(name, "1.0")], workdir=_w())
    argv = trial_argv("httpie", meta, [], workdir=_w())
    assert not is_trial_command([*argv, f"{name}==1.0"])


def test_conflicting_index_urls_are_unsupported() -> None:
    meta = _read(_meta(_pkg("a", "a", ["--index-url", "https://one/s"]),
                       {"b": _pkg("b", "b", ["--index-url", "https://two/s"])}))
    assert meta.unsupported == ("--index-url (differs between packages)",)
    same = _read(_meta(_pkg("a", "a", ["--index-url", "https://one/s"]),
                       {"b": _pkg("b", "b", ["--index-url", "https://one/s"])}))
    assert same.unsupported == ()


def test_pip_args_equals_form_and_dedupe() -> None:
    meta = _read(_meta(
        _pkg("a", "a", ["--index-url=https://i.example/s", "--trusted-host", "i.example"]),
        {"b": _pkg("b", "b", ["--trusted-host=i.example", "--pre"])},
    ))
    assert option_args(meta) == ["--index-url", "https://i.example/s", "--trusted-host", "i.example", "--pre"]


def test_apply_argv_never_names_the_main_package() -> None:
    meta = _httpie()
    argv = apply_argv("httpie", meta, [("urllib3", "1.26.19"), ("certifi", "2024.2.2")])
    assert argv == ["pipx", "runpip", "httpie", "install", *option_args(meta),
                    "urllib3==1.26.19", "certifi==2024.2.2"]
    assert option_args(meta)
    assert apply_argv("httpie", meta, [("HTTPie", "9.9"), ("urllib3", "1.26.19")]) == [
        "pipx", "runpip", "httpie", "install", *option_args(meta), "urllib3==1.26.19"]


def test_trial_argv_passes_main_only_through_files() -> None:
    meta = _httpie()
    argv = trial_argv("httpie", meta, [("urllib3", "1.26.19"), ("httpie", "9.9")], workdir=_w())
    assert meta.main.spec not in argv[4:]
    assert "httpie==9.9" not in argv
    for flag, name in (("-r", "reqs.txt"), ("-c", "cons.txt"), ("--report", "report.json")):
        i = argv.index(flag)
        assert argv[i:i + 2] == [flag, str(_w() / name)], "absolute: pipx runs pip in the app's venv directory"
    assert {"--dry-run", "--no-input"} <= set(argv)
    assert "--quiet" not in argv, "pip prints a conflict's cause only at its default verbosity"
    assert argv[-1] == "urllib3==1.26.19"
    assert is_trial_command(argv)


def test_is_trial_command_accepts_only_trial_argv() -> None:
    meta = _httpie()
    argv = trial_argv("httpie", meta, [("urllib3", "1.26.19")], workdir=_w())
    assert is_trial_command(argv)
    assert is_trial_command(["/usr/bin/pipx.__pa_real", *argv[1:]])
    assert is_trial_command(trial_argv("httpie", meta, [], workdir=_w()))
    assert not is_trial_command([*argv, "evilpkg"])
    assert not is_trial_command([*argv, "-e", "evilpkg"])
    assert not is_trial_command([a for a in argv if a != "--dry-run"])
    assert not is_trial_command([a for a in argv if a != "--no-input"])
    assert not is_trial_command([*argv[:4], "--quiet", *argv[4:]])
    report = str(_w() / "report.json")
    assert not is_trial_command(["--report" if a == report else a for a in argv][:-1] + ["-"])
    assert not is_trial_command([("-" if a == report else a) for a in argv])
    assert not is_trial_command([a.replace(str(_w()), "/home/user/project") for a in argv])
    assert not is_trial_command([a.replace(str(_w()), str(runner_mod.SCRATCH_ROOT)) for a in argv])
    assert not is_trial_command([a.replace(str(_w()), f"{runner_mod.SCRATCH_ROOT}/../x") for a in argv])
    assert not is_trial_command([a.replace("report.json", "x.json") for a in argv])
    assert not is_trial_command([("reqs.txt" if a == str(_w() / "reqs.txt") else a) for a in argv])
    other = [*argv[:-3], str(runner_mod.SCRATCH_ROOT / "trial-y" / "report.json"), argv[-1]]
    assert not is_trial_command(other), "every file in one directory"
    assert not is_trial_command(["other", *argv[1:]])
    assert not is_trial_command(["pipx", "install", "httpie"])
    assert not is_trial_command(["pipx", "runpip", "httpie", "uninstall", "-y", "x"])
    assert not is_trial_command(["pipx", "runpip", "httpie", "install", "--dry-run", "--no-input",
                                 "-r", "/etc/passwd", "-c", str(_w() / "cons.txt"), "--report", report])
    assert not is_trial_command([*argv[:4], "--target", "/x", *argv[4:]])
    for app in ("../other", "a/b", "..", "."):
        assert not is_trial_command([*argv[:2], app, *argv[3:]])
    assert not is_trial_command([])


def test_trial_files() -> None:
    files = trial_files(_httpie(), "3.2.2")
    assert files == {"reqs.txt": "httpie\nrequests==2.25.1\n", "cons.txt": "httpie==3.2.2\n"}
    extras = _read(_meta(_pkg("bandit", "bandit[baseline]")))
    assert trial_files(extras, "1.9.4") == {"reqs.txt": "bandit[baseline]\n", "cons.txt": "bandit==1.9.4\n"}


def test_trial_files_local_and_editable_main() -> None:
    local = _read(_meta(_pkg("app", "/work/app")))
    assert trial_files(local, "1.0") == {"reqs.txt": "/work/app\n", "cons.txt": "app==1.0\n"}
    editable = _read(_meta(_pkg("app", "/work/app", ["--editable"])))
    assert trial_files(editable, "1.0")["reqs.txt"] == "-e /work/app\n"
    assert trial_files(editable, None)["cons.txt"] == ""


# ---- parse_pip_trial -------------------------------------------------------------------------

_FIX = Path(__file__).parents[3] / "fixtures" / "pip_trial"
_HTTPIE = {"httpie": frozenset({"3.2.2"}), "requests": frozenset({"2.25.1"}), "urllib3": frozenset({"1.26.5"}),
           "certifi": frozenset({"2020.12.5"}), "pygments": frozenset({"2.7.4"})}
_LOCALAPP = {"localapp": frozenset({"1.0"}), "idna": frozenset({"3.4"})}
_LOCALDEP = {**_HTTPIE, "localdep": frozenset({"1.0"})}
_PYGMENTS = Change("update", "pygments", "2.7.4", "2.21.0")


def _case(case: str, **kw: Any) -> TrialResult:
    report = (_FIX / f"{case}.report.json").read_bytes() if (_FIX / f"{case}.report.json").exists() else None
    args: dict[str, Any] = {
        "returncode": int((_FIX / f"{case}.exitcode.txt").read_text().strip()), "report": report,
        "stderr": (_FIX / f"{case}.stderr.txt").read_text(), "stdout": (_FIX / f"{case}.stdout.txt").read_text(),
        "main": "httpie", "app": "httpie", "pinned": {},
        "local": frozenset(), "installed": _HTTPIE,
    }
    args.update(kw)
    rc, rep, err = args.pop("returncode"), args.pop("report"), args.pop("stderr")
    return parse_pip_trial(rc, rep, err, **args)


def _item(pkg: str, ver: str, target: str) -> PlannedFix:
    return PlannedFix(package=pkg, version=ver, target=target, direct=False, path=["httpie", pkg],
                      advisories=["GHSA-x"], left_open=[], cooldown_checked=True)


async def _verify(result: TrialResult, pkg: str = "urllib3", ver: str = "1.26.5", target: str = "2.2.2") -> FixPlan:
    async def trial(pins: Any, floats: Any, *, force: Any = (), lowest: Any = None) -> TrialResult:
        return result

    async def advisories(pkgs: Any) -> dict[Any, Any]:
        return {p: (frozenset(), False) for p in pkgs}

    async def age(p: str, v: str) -> None:
        return None

    return await verify_plan(FixPlan(planned=[_item(pkg, ver, target)]), ecosystem="PyPI", trial=trial,
                             advisories=advisories, age=age, cooldown_days=7, allow_cooldown=False)


_MOVE = "the fix needs a newer httpie: run pipx upgrade httpie, then plan again"


async def test_conflict_reaches_the_plan_as_blocked():
    result = _case("conflict", pinned={"urllib3": "2.2.2"})
    out = await _verify(result)
    [held] = out.held
    assert held.reason == planner.BLOCKED
    assert held.detail == "requests 2.25.1 requires urllib3<1.27 and >=1.21.1"


async def test_an_apps_own_cap_reaches_the_plan_naming_the_app():
    """awscli v1's case: the app's own requirement blocks the pin (recorded with a local app
    requiring urllib3<1.26.17); the reason names that requirement, never the trial's files."""
    result = _case("capped_conflict", main="cappedapp", app="cappedapp", pinned={"urllib3": "1.26.19"},
                   installed={"cappedapp": frozenset({"1.0"}), "urllib3": frozenset({"1.26.5"})})
    out = await _verify(result, target="1.26.19")
    [held] = out.held
    assert held.reason == planner.BLOCKED
    assert held.detail == "cappedapp 1.0 requires urllib3<1.26.17"


@pytest.mark.parametrize("case,app", [("deep_capped_conflict", "deepcapapp"), ("deep_range_conflict", "deeprangeapp")])
async def test_a_dependencys_cap_is_the_blocker_even_where_pip_names_the_app(case: str, app: str):
    """The cap one level down (the app requires requests, which caps urllib3): with a range on
    requests pip's sentence names the app too ("Cannot install deeprangeapp, requests==2.25.1
    and urllib3==2.2.2"), which must not read as the app having to move."""
    result = _case(case, main=app, app=app, pinned={"urllib3": "2.2.2"},
                   installed={app: frozenset({"1.0"}), "requests": frozenset({"2.25.1"}),
                              "urllib3": frozenset({"1.26.20"})})
    assert result.blocker is not None and result.blocker.parent == "requests"
    out = await _verify(result, ver="1.26.20")
    [held] = out.held
    assert held.reason == planner.BLOCKED
    assert held.detail.startswith("requests 2.25.1 requires urllib3<1.27 and >=1.21.1")


async def test_main_package_move_reaches_the_plan_as_blocked_with_detail():
    out = await _verify(_case("main_moves", pinned={"httpie": "3.2.4"}), "httpie", "3.2.2", "3.2.4")
    [held] = out.held
    assert held.reason == planner.BLOCKED
    assert held.detail == _MOVE


def test_baseline_report_changes_nothing_but_the_repair():
    result = _case("baseline")
    assert result.status == "resolved" and result.changes == (_PYGMENTS,)
    assert _case("baseline_only_if_needed").changes == (_PYGMENTS,)


def test_upgrade_pin_lists_every_change():
    result = _case("upgrade", pinned={"urllib3": "1.26.20"})
    assert result.status == "resolved"
    assert result.changes == (_PYGMENTS, Change("update", "urllib3", "1.26.5", "1.26.20"))
    assert result.blocker is None and result.yanked == ()


def test_requested_reinstall_at_same_version_is_not_a_change():
    installed = {**_HTTPIE, "pygments": frozenset({"2.21.0"})}
    assert _case("baseline", installed=installed).changes == ()


def test_conflict_is_blocked_with_the_requirement_that_causes_it():
    result = _case("conflict", pinned={"urllib3": "2.2.2"})
    assert result.status == "blocked"
    assert result.blocker == Blocker("requests", "urllib3<1.27 and >=1.21.1", "2.25.1")
    assert result.detail == "requests 2.25.1 requires urllib3<1.27 and >=1.21.1"
    assert "reqs.txt" not in result.detail and "/SCRATCH" not in result.detail


def test_a_conflict_without_its_cause_never_names_the_trials_files():
    stderr = ("ERROR: Cannot install -r /x/fix-scratch/trial-1/reqs.txt (line 1) and urllib3==1.26.19 because "
              "these package versions have conflicting dependencies.\n")
    result = parse_pip_trial(1, None, stderr, main="cappedapp", app="cappedapp", pinned={"urllib3": "1.26.19"},
                             local=frozenset(), installed=_HTTPIE)
    assert result.status == "blocked"
    assert result.detail == ("Cannot install cappedapp's requirements and urllib3==1.26.19 because these "
                             "package versions have conflicting dependencies.")


def test_conflict_naming_the_requiring_parent_sets_the_blocker():
    stderr = ("ERROR: Cannot install requests==2.25.1 and urllib3==2.2.2 because these package versions "
              "have conflicting dependencies.\n\nThe conflict is caused by:\n"
              "    The user requested urllib3==2.2.2\n    requests 2.25.1 depends on urllib3<1.27 and >=1.21.1\n")
    result = parse_pip_trial(1, None, stderr, main="httpie", app="httpie", pinned={"urllib3": "2.2.2"},
                             local=frozenset(), installed=_HTTPIE)
    assert result.status == "blocked"
    assert result.blocker == Blocker("requests", "urllib3<1.27 and >=1.21.1", "2.25.1")
    assert result.detail == "requests 2.25.1 requires urllib3<1.27 and >=1.21.1"


def test_nonexistent_version_is_blocked():
    result = _case("nosuch", pinned={"urllib3": "99.0"})
    assert result.status == "blocked"
    assert result.detail == "Could not find a version that satisfies the requirement urllib3==99.0"


def test_yanked_version_is_reported_as_yanked():
    result = _case("yanked", pinned={"certifi": "2022.5.18"})
    assert result.status == "resolved"
    assert result.yanked == (Yank("certifi", "2022.5.18", "Incorrectly claims to support Python 3.5."),)


@pytest.mark.parametrize("main", ["httpie", "HTTPie"])
def test_moving_main_package_is_blocked(main: str) -> None:
    result = _case("main_moves", main=main, app="httpie")
    assert (result.status, result.blocker) == ("blocked", None)
    assert result.detail == f"the fix needs a newer {main}: run pipx upgrade httpie, then plan again"


def test_moving_main_package_names_the_app_when_it_differs():
    result = _case("main_moves", main="Foo_Bar", app="foo", installed={"foo-bar": frozenset({"1.0"})},
                   report=b'{"install": [{"metadata": {"name": "foo-bar", "version": "2.0"}, '
                          b'"download_info": {"url": "https://files.pythonhosted.org/x"}}]}')
    assert result.detail == "the fix needs a newer Foo_Bar: run pipx upgrade foo, then plan again"


def test_nonzero_exit_with_valid_report_is_judged_by_report():
    result = _case("upgrade", returncode=1, stderr="ERROR: something noisy\n")
    assert result.status == "resolved" and Change("update", "urllib3", "1.26.5", "1.26.20") in result.changes


def test_zero_exit_without_report_is_inconclusive():
    result = _case("baseline", report=None)
    assert result.status == "inconclusive" and "no readable report" in result.detail
    assert _case("baseline", report=b"").status == "inconclusive"


@pytest.mark.parametrize("report", [b"{not json", b"[]", b'{"install": 3}', b'{"install": [{"metadata": 1}]}'])
def test_unparseable_report_is_inconclusive(report: bytes) -> None:
    assert _case("baseline", report=report).status == "inconclusive"


def test_old_pip_is_inconclusive_with_upgrade_shared_advice():
    result = _case("pip_too_old", pip_version="22.1")
    assert result.status == "inconclusive"
    assert result.detail == "pipx's shared pip 22.1 is too old to verify: run pipx upgrade-shared"


def test_index_401_with_private_index_is_inconclusive():
    """Under --no-input pip never names the 401: the fixture reads as a missing version."""
    result = _case("index_401", private_index=True, pinned={"urllib3": "1.26.20"})
    assert result.status == "inconclusive"
    assert result.detail == "the index returned no match; it may need credentials the sandbox does not have"


def test_an_index_offering_no_versions_is_inconclusive_without_a_recorded_private_index():
    """An index from PIP_INDEX_URL or pip.conf is not in the app's recorded options; an index
    that lists no version of a package being pinned to a real release did not answer, which is
    not a block a risk acceptance could quote."""
    result = _case("index_401", private_index=False, pinned={"urllib3": "1.26.20"})
    assert result.status == "inconclusive"
    assert _case("nosuch", pinned={"urllib3": "99.0"}).status == "blocked"


def test_a_401_shown_in_stderr_names_credentials():
    stderr = "WARNING: 401 Error, Credentials not correct for http://x/simple/urllib3/\nERROR: No matching distribution found\n"
    result = parse_pip_trial(1, None, stderr, main="httpie", app="httpie", pinned={}, local=frozenset(),
                             installed=_HTTPIE, private_index=True)
    assert (result.status, result.detail) == ("inconclusive", "the index needs credentials the sandbox does not have")


def test_a_pip_traceback_is_inconclusive_with_its_exception():
    """pip's internal-error banner is ``ERROR: Exception:``; the detail is the traceback's last line
    (here a password prompt reading a closed stdin)."""
    result = _case("index_401_prompt", private_index=True, pinned={"urllib3": "1.26.20"})
    assert (result.status, result.detail) == ("inconclusive", "EOFError: EOF when reading a line")


def test_an_sdist_only_pin_resolves():
    result = _case("sdist_only", pinned={"pycrypto": "2.6.1"})
    assert result.status == "resolved"
    assert result.changes == (Change("add", "pycrypto", None, "2.6.1"), _PYGMENTS)


def test_a_shared_pip_pipx_rebuilt_during_the_trial_is_inconclusive():
    """pipx rebuilds a shared pip that does not import and re-runs the command, so the report
    comes from a newer pip than the one checked before the trial."""
    result = _case("pip_too_old_py312_repaired", pip_version="22.1", pinned={"urllib3": "1.26.20"})
    assert (result.status, result.detail) == ("inconclusive", "the trial ran pip 26.2.2, not the pip 22.1 checked before it")


def test_detail_redacts_credentials():
    stderr = "ERROR: Something failed fetching https://user:s3cret@idx.example/simple/x/\n"
    result = parse_pip_trial(1, None, stderr, main="httpie", app="httpie", pinned={}, local=frozenset(),
                             installed=_HTTPIE)
    assert result.status == "inconclusive" and "s3cret" not in result.detail


def test_timeout_is_inconclusive():
    assert _case("baseline", timed_out=True).status == "inconclusive"


@pytest.mark.parametrize(("case", "name", "installed"),
                         [("local_unchanged", "localapp", _LOCALAPP), ("editable_unchanged", "editapp", {"editapp": frozenset({"1.0"})})])
def test_unchanged_local_requirement_is_not_a_change(case: str, name: str, installed: dict[str, frozenset[str]]) -> None:
    result = _case(case, main=name, app=name, installed=installed, local=frozenset({name}))
    assert result.status == "resolved" and result.changes == ()
    assert result.non_public == frozenset({(name, "1.0")})


def test_local_main_with_a_new_checkout_version_is_blocked():
    result = _case("local_main_bumped_noconstraint", main="localapp", app="localapp", installed=_LOCALAPP,
                   local=frozenset({"localapp"}))
    assert result.status == "blocked"
    assert result.detail == "the fix needs a newer localapp: run pipx upgrade localapp, then plan again"
    conflict = _case("local_main_bumped", main="localapp", app="localapp", installed=_LOCALAPP,
                     local=frozenset({"localapp"}))
    assert (conflict.status, conflict.detail) == ("blocked", result.detail)


def test_changed_sourced_dependency_is_could_not_verify():
    result = _case("sourced_dep_bumped", installed=_LOCALDEP, local=frozenset({"localdep"}))
    assert result.status == "inconclusive"
    assert result.detail == ("localdep is built from file:///SCRATCH/src/localdep and would change from 1.0 to 1.1; "
                             "the fix command cannot reproduce that")
    unchanged = _case("sourced_dep_unchanged", installed=_LOCALDEP, local=frozenset({"localdep"}))
    assert unchanged.status == "resolved" and unchanged.changes == (_PYGMENTS,)


def test_checks_run_main_before_sourced_before_local():
    """A moved main package wins over a changed sourced dependency listed before it."""
    report = (b'{"install": [{"metadata": {"name": "localdep", "version": "1.1"}, "is_direct": true, '
              b'"download_info": {"url": "file:///x", "dir_info": {}}}, '
              b'{"metadata": {"name": "httpie", "version": "3.2.4"}, '
              b'"download_info": {"url": "https://files.pythonhosted.org/x"}}]}')
    result = _case("baseline", report=report, installed=_LOCALDEP, local=frozenset({"localdep"}))
    assert result.detail == _MOVE


@pytest.mark.parametrize("main", ["HTTPie[net]", "httpie>=3", "httpie @ file:///x", "httpie[net]>=3; python_version>'3'"])
def test_main_spec_is_reduced_to_its_distribution_name(main: str) -> None:
    result = _case("main_moves", main=main, app="httpie")
    assert (result.status, result.detail) == ("blocked", f"the fix needs a newer {main}: run pipx upgrade httpie, then plan again")
    conflict = parse_pip_trial(1, None, "ERROR: Cannot install httpie==3.2.2 and urllib3==2.2.2 because x\n",
                               main=main, app="httpie", pinned={}, local=frozenset(), installed=_HTTPIE)
    assert conflict.detail.startswith("the fix needs a newer")


def test_a_package_named_forbidden_is_not_a_401():
    stderr = ("ERROR: Could not find a version that satisfies the requirement forbidden==1 (from versions: 0.1)\n"
              "ERROR: No matching distribution found for forbidden==1\n")
    result = parse_pip_trial(1, None, stderr, main="httpie", app="httpie", pinned={}, local=frozenset(),
                             installed=_HTTPIE, private_index=False)
    assert result.status == "blocked" and "credentials" not in result.detail


def test_http_status_phrases_are_credentials():
    for line in ("403 Client Error: Forbidden for url: http://x", "HTTP error 401 while getting http://x"):
        r = parse_pip_trial(1, None, f"WARNING: {line}\n", main="m", app="m", pinned={}, local=frozenset(), installed={})
        assert r.detail == "the index needs credentials the sandbox does not have"


def test_yank_reason_is_redacted():
    report = (b'{"install": [{"metadata": {"name": "certifi", "version": "2022.5.18"}, "is_yanked": true, '
              b'"download_info": {"url": "https://files.pythonhosted.org/x"}}]}')
    stderr = ("WARNING: The candidate selected for download or install is a yanked version: 'certifi' candidate "
              "(version 2022.5.18 at https://files.pythonhosted.org/x)\n"
              "Reason for being yanked: see https://u:pw@host/why\n")
    result = _case("baseline", report=report, stderr=stderr)
    assert "pw" not in (result.yanked[0].reason or "")


def test_unchanged_local_package_is_non_public_even_without_local_url():
    report = (b'{"install": [{"metadata": {"name": "dep", "version": "1.0"}, '
              b'"download_info": {"url": "https://files.pythonhosted.org/x"}}]}')
    result = _case("baseline", report=report, installed={**_HTTPIE, "dep": frozenset({"1.0"})}, local=frozenset({"Dep"}))
    assert result.non_public == frozenset({("dep", "1.0")})


def test_the_oldest_verified_pip_reads_the_same():
    """pip 26.2.1 (the reference machine's shared pip) reports and fails as 26.2.2 does."""
    now = {**_HTTPIE, "urllib3": frozenset({"1.26.20"}), "certifi": frozenset({"2026.10.23"}),
           "pygments": frozenset({"2.21.0"})}
    assert _case("pip2621_baseline", installed=now).changes == ()
    assert _case("pip2621_upgrade", installed=now, pinned={"urllib3": "1.26.19"}).changes == (
        Change("update", "urllib3", "1.26.20", "1.26.19"),)
    conflict = _case("pip2621_conflict", installed=now, pinned={"urllib3": "2.2.2"})
    assert conflict.status == "blocked"
    assert conflict.detail.startswith("Cannot install requests==2.25.1 and urllib3==2.2.2 because")


# ---- the adapter -----------------------------------------------------------------------------

_VENVS = Path("/home/user/.local/pipx/venvs")
_HTTPIE_INSTALLED = {"httpie": "3.2.2", "requests": "2.25.1", "urllib3": "1.26.5", "certifi": "2020.12.5",
                     "pygments": "2.7.4"}


@pytest.fixture(autouse=True)
def _live_pipx(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pipx home the sandboxed pipx uses, and its shared pip, unless a test says otherwise."""
    from packagealert.languages.python_fix import pipx_app

    monkeypatch.setattr(pipx_app, "_pipx_home", lambda: _VENVS.parent)
    monkeypatch.setattr(pipx_app, "shared_pip_version", lambda env: "26.2.2")
    # The shared libraries follow the home, not a PIPX_SHARED_LIBS from the shell running the tests.
    monkeypatch.delenv("PIPX_SHARED_LIBS", raising=False)


def _tool_env(doc: dict[str, Any], packages: dict[str, str], *, name: str = "httpie", public: bool = True,
              site: Path | None = None, venvs: Path = _VENVS) -> ToolEnv:
    return ToolEnv("pipx", name, venvs / name, "3.12", site, [], {"kind": "pypi"},
                   packages=[ToolPackage(n, v, public) for n, v in packages.items()],
                   distribution=doc["main_package"]["package"])


def _adapter(doc: dict[str, Any], packages: dict[str, str] | None = None, **kw: Any) -> PipxAppFixAdapter:
    text = json.dumps(doc)
    return PipxAppFixAdapter(_tool_env(doc, _HTTPIE_INSTALLED if packages is None else packages, **kw),
                             read_metadata(text), text.encode())


_HTTPIE_DOC = _meta(_pkg("httpie", "httpie==3.2.2", ["requests==2.25.1"]))


def _httpie_doc(**top: Any) -> dict[str, Any]:
    return _meta(_pkg("httpie", "httpie"), {"requests": _pkg("requests", "requests==2.25.1")}, **top)


def _report(*items: tuple[str, str], host: str = "https://files.pythonhosted.org") -> bytes:
    return json.dumps({"version": "1", "pip_version": "26.2.2", "environment": {}, "install": [
        {"metadata": {"name": n, "version": v}, "download_info": {"url": f"{host}/x/{n}-{v}.whl", "archive_info": {}},
         "is_direct": False, "is_yanked": False, "requested": True} for n, v in items]}).encode()


class _Run:
    """A TrialRunner whose in_copy answers each trial (keyed by its pins) with a report."""

    project_dir = Path("/x")

    def __init__(self, reports: dict[tuple[str, ...], bytes | None], tmp: Path, *, rc: int = 0,
                 stderr: str = "", stdout: str = "") -> None:
        self.reports, self.tmp, self.rc, self.stderr, self.stdout = reports, tmp, rc, stderr, stdout
        self.calls: list[tuple[Any, ...]] = []
        self.written: list[dict[str, str]] = []
        self.argvs: list[list[str]] = []

    async def read_only(self, argv: list[str]) -> Any:
        raise AssertionError("the pipx trial runs in a scratch copy")

    async def in_copy(self, files: Any, argvs: Any, edit: Any = None, read_back: Any = None) -> CopyResult:
        self.calls.append((files, argvs, edit, read_back))
        write, command = argvs
        copy = self.tmp / f"copy{len(self.calls)}"
        copy.mkdir()
        assert write(copy) is None
        self.written.append({p.name: p.read_text() for p in copy.iterdir()})
        argv = command(copy)
        self.argvs.append(argv)
        pins = tuple(argv[argv.index(str(copy / "report.json")) + 1:])
        stderr = self.stderr.replace("{copy}", str(copy))
        return CopyResult((CommandResult(self.rc, self.stdout, stderr),), {"report.json": self.reports[pins]})


_BASE = _report(("Pygments", "2.21.0"))
_UP = _report(("urllib3", "1.26.20"), ("Pygments", "2.21.0"))


async def test_adapter_trial_writes_files_and_reads_report(tmp_path: Path) -> None:
    a = _adapter(_httpie_doc())
    run = _Run({(): _BASE, ("urllib3==1.26.20",): _UP}, tmp_path)
    result = await a.trial([("urllib3", "1.26.20")], [], cast("TrialRunner", run))
    assert result.status == "resolved", result.detail
    files, argvs, edit, read_back = run.calls[0]
    assert files == [] and edit is None and read_back == ["report.json"]
    assert callable(argvs[0]) and callable(argvs[1])
    assert run.argvs[0] == trial_argv("httpie", a.meta, [("urllib3", "1.26.20")], workdir=tmp_path / "copy1")
    assert run.written[0] == {"reqs.txt": "httpie\nrequests==2.25.1\n", "cons.txt": "httpie==3.2.2\n"}


async def test_the_trial_reads_a_conflicts_cause_from_pips_stdout(tmp_path: Path) -> None:
    a = _adapter(_httpie_doc())
    stderr = ("ERROR: Cannot install -r /x/reqs.txt (line 2) and urllib3==2.2.2 because these package versions "
              "have conflicting dependencies.\n")
    stdout = ("\nThe conflict is caused by:\n    The user requested urllib3==2.2.2\n"
              "    requests 2.25.1 depends on urllib3<1.27 and >=1.21.1\n\n")
    run = _Run({(): _BASE, ("urllib3==2.2.2",): None}, tmp_path, rc=1, stderr=stderr, stdout=stdout)
    result = await a.trial([("urllib3", "2.2.2")], [], cast("TrialRunner", run))
    assert (result.status, result.detail) == ("blocked", "requests 2.25.1 requires urllib3<1.27 and >=1.21.1")


async def test_a_pin_of_the_main_package_is_held_for_pipx_upgrade(tmp_path: Path) -> None:
    """The command never names the main package, so a fix of the app itself is the user's
    pipx upgrade, held as such without a trial."""
    a = _adapter(_httpie_doc())
    run = _Run({(): _BASE}, tmp_path)
    result = await a.trial([("httpie", "3.2.3")], [], cast("TrialRunner", run))
    assert (result.status, result.detail) == ("blocked", _MOVE)
    assert result.blocker is None
    assert run.argvs == []
    out = await _verify(result, "httpie", "3.2.2", "3.2.3")
    [held] = out.held
    assert (held.reason, held.detail) == (planner.BLOCKED, result.detail)


async def test_changes_measured_from_baseline(tmp_path: Path) -> None:
    """What every runpip install repairs anyway (the fixture's Pygments) is the baseline's, not the pin's."""
    a = _adapter(_httpie_doc())
    run = _Run({(): _BASE, ("urllib3==1.26.20",): _UP}, tmp_path)
    result = await a.trial([("urllib3", "1.26.20")], [], cast("TrialRunner", run))
    assert result.changes == (Change("update", "urllib3", "1.26.5", "1.26.20"),)
    assert result.after == {"httpie": {"3.2.2"}, "requests": {"2.25.1"}, "urllib3": {"1.26.20"},
                            "certifi": {"2020.12.5"}, "pygments": {"2.21.0"}}
    await a.trial([("urllib3", "1.26.20")], [], cast("TrialRunner", run))
    assert [argv[-1].endswith("report.json") for argv in run.argvs].count(True) == 1, "the baseline runs once"


@pytest.mark.parametrize(("case", "reason"), [
    ("another_app", "its metadata is for black, so pipx would act on another app"),
    ("unsupported", "the command cannot carry over the app's --no-binary"),
    ("unsupported_url", "the command cannot carry over the app's -ihttps://REDACTED@corp.example/simple"),
    ("uv_backend", "uv backend not supported yet"),
    ("shared", "pipx owns its shared libraries: run pipx upgrade-shared"),
])
async def test_held_reason_cases(case: str, reason: str) -> None:
    from packagealert.languages.python_tools import PIPX_SHARED

    if case == "shared":
        env = ToolEnv("pipx", PIPX_SHARED, _VENVS.parent / "shared", "3.12", None, [], {"kind": "unknown"},
                      packages=[ToolPackage("pip", "26.2.1", True)])
        a = PipxAppFixAdapter.for_env(env)
        assert a.load_graph(Path("pipx_metadata.json")).versions == {"pip": frozenset({"26.2.1"})}
    else:
        doc = {"another_app": _meta(_pkg("black", "black")),
               "unsupported": _meta(_pkg("httpie", "httpie", ["--no-binary", ":all:"])),
               "unsupported_url": _meta(_pkg("httpie", "httpie", ["-ihttps://u:s3cret@corp.example/simple"])),
               "uv_backend": _httpie_doc(backend="uv")}[case]
        a = _adapter(doc)
    assert a.held_reason() == reason
    result = await a.trial([("urllib3", "1.26.20")], [], cast("TrialRunner", None))
    assert (result.status, result.detail) == ("inconclusive", reason)
    assert await a.baseline(cast("TrialRunner", None)) is None
    assert a.apply_argv(FixPlan(planned=[_fix("urllib3", "1.26.5", "1.26.20")],
                                verified_after={"urllib3": frozenset({"1.26.20"})})) is None


def test_held_when_pipx_would_act_on_another_venvs_directory() -> None:
    a = _adapter(_httpie_doc(), venvs=Path("/home/user/.local/share/pipx/venvs"))
    assert a.held_reason() == ("pipx would act on /home/user/.local/pipx/venvs/httpie, "
                               "not /home/user/.local/share/pipx/venvs/httpie")


def test_a_suffixed_app_is_its_own() -> None:
    a = _adapter(_meta(_pkg("httpie", "httpie", suffix="@3")), name="httpie-3")
    assert a.held_reason() == "its metadata is for httpie@3, so pipx would act on another app"
    assert _adapter(_meta(_pkg("httpie", "httpie", suffix="-3")), name="httpie-3").held_reason() is None


def _site(tmp_path: Path, requires: dict[str, list[str]]) -> Path:
    site = tmp_path / "site-packages"
    for dist, reqs in requires.items():
        info = site / f"{dist}-1.0.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: x\n" + "".join(f"Requires-Dist: {r}\n" for r in reqs))
    return site


def test_graph_marks_local_main_as_local_source(tmp_path: Path) -> None:
    site = _site(tmp_path, {"localapp": ["idna"], "idna": []})
    doc = _meta(_pkg("localapp", "/home/user/src/localapp"), {"six": _pkg("six", "six")})
    a = _adapter(doc, {"localapp": "1.0", "idna": "3.4", "six": "1.16.0"}, name="localapp", site=site)
    g = a.load_graph(Path("pipx_metadata.json"))
    assert g.members == {"pipx:localapp"}
    assert g.direct == {"localapp", "six"}
    assert g.local_source == {"localapp"}
    assert "localapp" in g.non_registry
    assert g.path_to("idna") == ["pipx:localapp", "localapp", "idna"]


async def test_private_names_not_sent_for_cadence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.languages.python_fix import release_cadence

    asked: list[str] = []

    async def cadences(names: list[str]) -> dict[str, str]:
        asked.extend(names)
        return dict.fromkeys(names, "frequent")

    monkeypatch.setattr(release_cadence, "cadences", cadences)
    a = _adapter(_httpie_doc(), {**_HTTPIE_INSTALLED, "inhouse": "1.0"})
    a.env.packages[-1] = ToolPackage("inhouse", "1.0", False)
    a = PipxAppFixAdapter(a.env, a.meta, a.state.receipt_bytes)
    corp = _report(("corp", "2.0"), host="https://corp.example")
    await a.trial([("requests", "2.31.0")], [], cast("TrialRunner", _Run({(): _BASE, ("requests==2.31.0",): corp},
                                                                           tmp_path)))
    found = await a.cadences(["corp", "inhouse", "requests"])
    assert asked == ["requests"]
    assert found == {"corp": None, "inhouse": None, "requests": "frequent"}


def _fix(package: str, version: str, target: str) -> PlannedFix:
    return PlannedFix(package=package, version=version, target=target, direct=False, path=[], advisories=["A"],
                      left_open=[], cooldown_checked=True, verified=True)


async def test_unplanned_major_move_is_held_and_has_no_command(tmp_path: Path) -> None:
    a = _adapter(_httpie_doc())
    moved = _report(("urllib3", "1.26.20"), ("requests", "3.0.0"))
    run = _Run({(): _report(), ("urllib3==1.26.20",): moved}, tmp_path)

    async def trial(pins: Any, floats: Any, *, force: Any = (), lowest: Any = None) -> TrialResult:
        return await a.trial(pins, floats, cast("TrialRunner", run))

    async def advisories(pkgs: Any) -> dict[Any, Any]:
        return {p: (frozenset(), False) for p in pkgs}

    async def age(p: str, v: str) -> None:
        return None

    plan = await verify_plan(FixPlan(planned=[_item("urllib3", "1.26.5", "1.26.20")]), ecosystem="PyPI",
                             trial=trial, advisories=advisories, age=age, cooldown_days=7, allow_cooldown=False)
    [held] = plan.held
    assert held.reason == planner.MAJOR and held.needs_major == ("requests",)
    assert a.apply_argv(plan) is None


_FIXED_AFTER = {"httpie": frozenset({"3.2.2"}), "requests": frozenset({"2.32.0"}),
                "charset-normalizer": frozenset({"3.3.0"}), "idna": frozenset({"3.7"}),
                "urllib3": frozenset({"1.26.5"})}
_FIX_INSTALLED = {"httpie": "3.2.2", "requests": "2.25.1", "charset-normalizer": "2.0.0", "idna": "2.10",
                  "urllib3": "1.26.5"}


def test_pins_include_an_unplanned_dependency_the_fix_moves() -> None:
    a = _adapter(_httpie_doc(), _FIX_INSTALLED)
    plan = FixPlan(planned=[_fix("requests", "2.25.1", "2.32.0")], verified_after=_FIXED_AFTER)
    pins = [("charset-normalizer", "3.3.0"), ("idna", "3.7"), ("requests", "2.32.0")]
    assert a.pins(plan) == pins
    assert a.apply_argv(plan) == ["pipx", "runpip", "httpie", "install", "charset-normalizer==3.3.0", "idna==3.7",
                                  "requests==2.32.0"]
    # Never the main package, even if the verified end state moved it.
    moved_main = FixPlan(planned=plan.planned, verified_after={**_FIXED_AFTER, "httpie": frozenset({"3.2.4"})})
    assert a.pins(moved_main) == pins


def test_pins_are_empty_and_there_is_no_command_without_a_verified_end_state() -> None:
    a = _adapter(_httpie_doc(), _FIX_INSTALLED)
    plan = FixPlan(planned=[_fix("requests", "2.25.1", "2.32.0")])
    assert a.pins(plan) == [] and a.apply_argv(plan) is None


def test_a_sourced_package_the_end_state_changes_has_no_command() -> None:
    doc = _meta(_pkg("httpie", "httpie"), {"localdep": _pkg("localdep", "/home/user/src/localdep")})
    a = _adapter(doc, {**_FIX_INSTALLED, "localdep": "1.0"})
    plan = FixPlan(planned=[_fix("requests", "2.25.1", "2.32.0")],
                   verified_after={**_FIXED_AFTER, "localdep": frozenset({"1.1"})})
    with pytest.raises(ValueError, match="localdep"):
        a.pins(plan)
    assert a.apply_argv(plan) is None


def test_several_versions_in_the_end_state_have_no_command() -> None:
    a = _adapter(_httpie_doc(), _FIX_INSTALLED)
    plan = FixPlan(planned=[_fix("requests", "2.25.1", "2.32.0")],
                   verified_after={**_FIXED_AFTER, "idna": frozenset({"3.7", "3.6"})})
    assert a.apply_argv(plan) is None


def test_commands_hide_credentials() -> None:
    doc = _meta(_pkg("httpie", "httpie", ["--index-url", "https://u:s3cret@corp.example/simple"]))
    a = _adapter(doc, _FIX_INSTALLED)
    plan = FixPlan(planned=[_fix("requests", "2.25.1", "2.32.0")], verified_after=_FIXED_AFTER)
    [command] = a.commands(plan)
    assert "s3cret" not in " ".join(command)
    assert "s3cret" in " ".join(a.apply_argv(plan) or [])


def test_command_names_pipx_home_not_where_its_venvs_resolve(monkeypatch: pytest.MonkeyPatch,
                                                             tmp_path: Path) -> None:
    """With venvs a link (to data/pipx-venvs), the venv's resolved path names no pipx home."""
    from packagealert.languages.python_fix import pipx_app

    home, real = tmp_path / "pipx", tmp_path / "data" / "pipx-venvs"
    (real / "httpie").mkdir(parents=True)
    home.mkdir()
    (home / "venvs").symlink_to(real)
    monkeypatch.setattr(pipx_app, "_pipx_home", lambda: home)
    monkeypatch.setenv("PIPX_HOME", str(home))
    a = _adapter(_httpie_doc(), _FIX_INSTALLED, venvs=real)
    plan = FixPlan(planned=[_fix("requests", "2.25.1", "2.32.0")], verified_after=_FIXED_AFTER)
    [command] = a.commands(plan)
    assert command[:2] == ["env", f"PIPX_HOME={home}"]


def test_read_only_paths_follow_pipx_shared_libs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The shared libraries apply refuses to see made writable are the ones pipx uses."""
    from packagealert.languages.python_fix import pipx_app
    from packagealert.sandbox.runner import _try_parse

    a = _adapter(_httpie_doc(), _FIX_INSTALLED)
    plan = FixPlan(planned=[_fix("requests", "2.25.1", "2.32.0")], verified_after=_FIXED_AFTER)
    parsed = _try_parse(a.apply_argv(plan) or [])
    [default] = a.read_only_paths(parsed)
    assert default.name == "shared" and default != tmp_path / "elsewhere"
    monkeypatch.setenv("PIPX_SHARED_LIBS", str(tmp_path / "elsewhere"))
    monkeypatch.setattr(pipx_app, "_pipx_shared", lambda: tmp_path / "elsewhere")
    assert a.read_only_paths(parsed) == [tmp_path / "elsewhere"]


def test_probe_argv_is_the_baseline_trial() -> None:
    a = _adapter(_httpie_doc())
    assert a.probe_argv() == trial_argv("httpie", a.meta, [], workdir=runner_mod.SCRATCH_ROOT / "trial")
    assert is_trial_command(a.probe_argv())


# ---- the shared pip --------------------------------------------------------------------------

def _shared(home: Path, *versions: str, pythons: tuple[str, ...] = ("python3.12",)) -> None:
    for py in pythons:
        site = home / "shared" / "lib" / py / "site-packages"
        site.mkdir(parents=True)
        for v in versions:
            (site / f"pip-{v}.dist-info").mkdir()


def test_shared_pip_version_reads_the_dist_info(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.languages.python_fix import pipx_app

    monkeypatch.setattr(pipx_app, "_pipx_home", lambda: tmp_path)
    env = _tool_env(_httpie_doc(), _HTTPIE_INSTALLED)
    assert _real_shared_pip_version(env) is None
    _shared(tmp_path, "26.2.1")
    assert _real_shared_pip_version(env) == "26.2.1"


def test_an_apps_own_pip_is_the_one_the_trial_checks(tmp_path: Path) -> None:
    """``<venv>/bin/python -m pip`` imports a pip in the app's own site-packages (a dependency of
    the app, as for chalice) before pipx's shared one: that is the pip whose version counts."""
    from packagealert.languages.python_fix.pipx_app import trial_pip_version

    site = tmp_path / "site-packages"
    site.mkdir()
    env = _tool_env(_httpie_doc(), _HTTPIE_INSTALLED, site=site)
    assert trial_pip_version(env) == ("26.2.2", False)
    (site / "pip").mkdir()
    assert trial_pip_version(env) == (None, True), "a pip with no dist-info: which version cannot be told"
    (site / "pip-22.1.dist-info").mkdir()
    assert trial_pip_version(env) == ("22.1", True)


async def test_an_apps_own_old_pip_holds_without_running_a_trial(tmp_path: Path) -> None:
    site = tmp_path / "site-packages"
    (site / "pip").mkdir(parents=True)
    (site / "pip-22.1.dist-info").mkdir()
    a = PipxAppFixAdapter(_tool_env(_httpie_doc(), _HTTPIE_INSTALLED, site=site), read_metadata(json.dumps(_httpie_doc())),
                          json.dumps(_httpie_doc()).encode())
    result = await a.trial([("urllib3", "1.26.20")], [], cast("TrialRunner", _NoRun()))
    assert (result.status, result.detail) == (
        "inconclusive", "the app's own pip 22.1 is too old to verify (pipx runpip runs it rather than the shared one)")


def test_a_report_from_another_pip_than_the_one_checked_is_inconclusive() -> None:
    result = _case("upgrade", pinned={"urllib3": "1.26.20"}, pip_version="26.2.1")
    assert (result.status, result.detail) == ("inconclusive", "the trial ran pip 26.2.2, not the pip 26.2.1 checked before it")
    assert _case("upgrade", pinned={"urllib3": "1.26.20"}, pip_version="26.2.2").status == "resolved"


def test_the_oldest_verified_pip_is_the_oldest_in_the_fixtures() -> None:
    from packagealert.languages.python_fix import pipx_app

    versions = {json.loads(f.read_bytes())["pip_version"] for f in _FIX.glob("*.report.json") if f.stat().st_size}
    from packaging.version import Version
    assert pipx_app.OLDEST_VERIFIED_PIP == str(min(versions, key=Version))
    assert Version(pipx_app.OLDEST_VERIFIED_PIP) >= Version("22.2")


class _NoRun:
    project_dir = Path("/x")

    async def in_copy(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("no trial may run")

    async def read_only(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("no trial may run")


@pytest.mark.parametrize("version", ["22.1", "26.2.0"])
async def test_old_shared_pip_holds_without_running_a_trial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                            version: str) -> None:
    from packagealert.languages.python_fix import pipx_app

    monkeypatch.setattr(pipx_app, "shared_pip_version", _real_shared_pip_version)
    monkeypatch.setattr(pipx_app, "_pipx_home", lambda: tmp_path)
    _shared(tmp_path, version)
    a = _adapter(_httpie_doc(), venvs=tmp_path / "venvs")
    result = await a.trial([("urllib3", "1.26.20")], [], cast("TrialRunner", _NoRun()))
    assert (result.status, result.detail) == (
        "inconclusive", f"pipx's shared pip {version} is too old to verify: run pipx upgrade-shared")
    assert await a.baseline(cast("TrialRunner", _NoRun())) is None


@pytest.mark.parametrize(("versions", "pythons"), [
    (("26.2.1", "26.2.2"), ("python3.12",)),
    (("26.2.2",), ("python3.12", "python3.13")),
    ((), ("python3.12",)),
])
async def test_ambiguous_shared_pip_is_inconclusive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                    versions: tuple[str, ...], pythons: tuple[str, ...]) -> None:
    from packagealert.languages.python_fix import pipx_app

    monkeypatch.setattr(pipx_app, "shared_pip_version", _real_shared_pip_version)
    monkeypatch.setattr(pipx_app, "_pipx_home", lambda: tmp_path)
    _shared(tmp_path, *versions, pythons=pythons)
    a = _adapter(_httpie_doc(), venvs=tmp_path / "venvs")
    result = await a.trial([("urllib3", "1.26.20")], [], cast("TrialRunner", _NoRun()))
    assert (result.status, result.detail) == ("inconclusive", "cannot tell which pip pipx uses")


async def test_uv_backend_skips_shared_pip_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """A uv-backend app does not use the shared pip; it is held before the pip is looked at."""
    from packagealert.languages.python_fix import pipx_app

    def boom(env: Any) -> str:
        raise AssertionError("the shared pip was read")

    monkeypatch.setattr(pipx_app, "shared_pip_version", boom)
    result = await _adapter(_httpie_doc(backend="uv")).trial([("urllib3", "1.26.20")], [],
                                                              cast("TrialRunner", _NoRun()))
    assert result.detail == "uv backend not supported yet"


async def test_a_sandbox_refusal_is_inconclusive_with_its_reason(tmp_path: Path) -> None:
    class Refusing(_Run):
        async def in_copy(self, *a: Any, **k: Any) -> CopyResult:
            raise RuntimeError("sandbox.editable_roots does not allow /home/user/src/localapp")

    result = await _adapter(_httpie_doc()).trial([("urllib3", "1.26.20")], [],
                                                 cast("TrialRunner", Refusing({}, tmp_path)))
    assert (result.status, result.detail) == (
        "inconclusive", "sandbox.editable_roots does not allow /home/user/src/localapp")


# ---- the sandbox -----------------------------------------------------------------------------

@pytest.fixture
def pipx_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake $HOME holding a pipx home with one app, httpie; the scratch root under it."""


    home = tmp_path / "home"
    venv = home / ".local" / "pipx" / "venvs" / "httpie"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion = 3.12.12\n")
    (venv / "pipx_metadata.json").write_text(json.dumps(_httpie_doc()))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PIPX_HOME", str(home / ".local" / "pipx"))
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.delenv("PIP_CONFIG_FILE", raising=False)
    monkeypatch.setattr(runner_mod, "SCRATCH_ROOT", home / ".cache" / "package-alert" / "fix-scratch")
    runner_mod.SCRATCH_ROOT.mkdir(parents=True)
    monkeypatch.setattr(runner_mod, "bwrap_available", lambda: True)
    return home


def _scratch(home: Path) -> Path:
    import tempfile

    from packagealert.sandbox import runner as runner_mod

    return Path(tempfile.mkdtemp(prefix="trial-", dir=runner_mod.SCRATCH_ROOT)).resolve()


async def _trial_sandbox(monkeypatch: pytest.MonkeyPatch, build: Any, home: Path,
                         editable_roots: list[Path] | None = None) -> dict[str, Any]:
    """Run the trial *build(scratch copy)* returns through run_captured(scratch=True); what
    build_cmd() was given."""
    from packagealert.config import AppConfig
    from packagealert.sandbox.runner import SandboxRunner

    seen: dict[str, Any] = {}

    def fake_build_cmd(argv: list[str], write_dirs: list[Path], **kw: Any) -> list[str]:
        seen.update(kw, argv=argv, write_dirs=list(write_dirs))
        return ["true"]

    monkeypatch.setattr("packagealert.sandbox.runner.build_cmd", fake_build_cmd)
    cfg = AppConfig()
    cfg.sandbox.editable_roots = list(editable_roots or [])
    seen["cwd"] = _scratch(home)
    await SandboxRunner(cfg).run_captured(build(seen["cwd"]), cwd=seen["cwd"], scratch=True)
    return seen


async def test_the_trial_binds_only_the_apps_lock_file_and_never_its_venv(
        pipx_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    venvs = pipx_home / ".local" / "pipx" / "venvs"
    meta = read_metadata((venvs / "httpie" / "pipx_metadata.json").read_text())
    seen = await _trial_sandbox(monkeypatch, lambda w: trial_argv("httpie", meta, [], workdir=w), pipx_home)
    lock = venvs / ".httpie.lock"
    assert seen["write_files"] == [lock] and lock.is_file(), "pipx opens the app's lock read-write"
    assert seen["write_dirs"] == [seen["cwd"]]
    for d in seen["write_dirs"]:
        assert not (venvs / "httpie").is_relative_to(d) and not d.is_relative_to(venvs)


async def test_a_hard_linked_lock_file_is_refused(pipx_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.sandbox.runner import CapturedRunError

    venvs = pipx_home / ".local" / "pipx" / "venvs"
    target = pipx_home / ".bashrc"
    target.write_text("")
    (venvs / ".httpie.lock").hardlink_to(target)
    meta = read_metadata((venvs / "httpie" / "pipx_metadata.json").read_text())
    with pytest.raises(CapturedRunError, match="lock"):
        await _trial_sandbox(monkeypatch, lambda w: trial_argv("httpie", meta, [], workdir=w), pipx_home)


def test_a_fifo_at_the_lock_path_is_refused_without_blocking(tmp_path: Path) -> None:
    """Build code in an earlier run (venvs is writable then) can leave a FIFO where the lock goes;
    opening it to write would block until something read it, hanging pa fix."""
    import os
    import subprocess
    import sys

    lock = tmp_path / ".httpie.lock"
    os.mkfifo(lock)
    code = ("import sys; from pathlib import Path; from packagealert.sandbox.runner import CapturedRunError, "
            "_create_write_files\ntry:\n    _create_write_files([Path(sys.argv[1])])\nexcept CapturedRunError as e:\n"
            "    print(e); sys.exit(3)")
    done = subprocess.run([sys.executable, "-c", code, str(lock)], capture_output=True, text=True, timeout=30,
                          check=False)
    assert done.returncode == 3 and "cannot bind the lock file" in done.stdout


async def test_a_local_apps_checkout_is_writable_for_its_trial(pipx_home: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.sandbox.runner import CapturedRunError

    checkout = pipx_home / "src" / "localapp"
    checkout.mkdir(parents=True)
    (checkout / "setup.py").write_text("")
    venvs = pipx_home / ".local" / "pipx" / "venvs"
    (venvs / "localapp").mkdir()
    doc = _meta(_pkg("localapp", str(checkout), ["--editable"]))
    (venvs / "localapp" / "pipx_metadata.json").write_text(json.dumps(doc))
    meta = read_metadata(json.dumps(doc))

    def argv(w: Path) -> list[str]:
        return trial_argv("localapp", meta, [], workdir=w)

    seen = await _trial_sandbox(monkeypatch, argv, pipx_home, editable_roots=[pipx_home / "src"])
    assert checkout in seen["write_dirs"]
    assert not any((venvs / "localapp").is_relative_to(d) for d in seen["write_dirs"])
    with pytest.raises(CapturedRunError, match=r"editable_roots"):
        await _trial_sandbox(monkeypatch, argv, pipx_home, editable_roots=[pipx_home / "elsewhere"])


async def test_local_find_links_is_bound_for_trial_and_apply(pipx_home: Path,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.config import AppConfig
    from packagealert.sandbox.runner import SandboxRunner, _Context, _try_parse

    wheels = pipx_home / "wheels"
    wheels.mkdir()
    meta = read_metadata(json.dumps(_meta(_pkg("httpie", "httpie", ["--find-links", f"file://{wheels}"]))))
    seen = await _trial_sandbox(monkeypatch, lambda w: trial_argv("httpie", meta, [("urllib3", "1.26.20")], workdir=w),
                                pipx_home, editable_roots=[pipx_home])
    assert wheels in seen["home_ro_dirs"]
    assert not any(wheels.is_relative_to(d) for d in seen["write_dirs"])

    apply = apply_argv("httpie", meta, [("urllib3", "1.26.20")])
    cfg = AppConfig()
    cfg.sandbox.editable_roots = [pipx_home]
    cwd = pipx_home / "work"
    cwd.mkdir()
    ctx = _Context(argv=apply, parsed=_try_parse(apply), cwd=cwd)
    asm = SandboxRunner(cfg)._assemble_sandbox(ctx, apply, {}, None, on_extra_write=None, read_only=False)
    assert asm is not None
    assert wheels in asm.home_ro
    assert not any(wheels.is_relative_to(d) for d in asm.write_dirs)


_PIP_VARS = ("HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "VIRTUAL_ENV", "PIP_CONFIG_FILE")


def _pip_config_seen(env: dict[str, str], visible: list[Path], home: Path, venv: Path) -> tuple[Any, ...]:
    """The pip-relevant environment and which of pip's config files the command can read."""
    candidates = [Path("/etc/pip.conf"), Path("/etc/xdg/pip/pip.conf"), home / ".pip" / "pip.conf",
                  home / ".config" / "pip" / "pip.conf", venv / "pip.conf"]
    readable = [c for c in candidates if not c.is_relative_to(home) or any(c.is_relative_to(d) for d in visible)]
    pip_env = {k: v for k, v in env.items() if k.startswith("PIP_") or k in _PIP_VARS}
    return pip_env, readable


async def test_trial_and_apply_see_the_same_pip_configuration(pipx_home: Path,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.config import AppConfig
    from packagealert.languages.python_fix.pipx_app import config_problem
    from packagealert.sandbox.runner import SandboxRunner, _Context, _try_parse

    (pipx_home / ".config" / "pip").mkdir(parents=True)
    (pipx_home / ".config" / "pip" / "pip.conf").write_text("[global]\n")
    (pipx_home / ".pip").mkdir()
    monkeypatch.setenv("PIP_INDEX_URL", "https://pypi.example/simple")
    venv = pipx_home / ".local" / "pipx" / "venvs" / "httpie"
    meta = read_metadata((venv / "pipx_metadata.json").read_text())
    seen = await _trial_sandbox(monkeypatch, lambda w: trial_argv("httpie", meta, [("urllib3", "1.26.20")], workdir=w),
                                pipx_home)
    trial = _pip_config_seen(seen["env"], [*seen["home_ro_dirs"], *seen["write_dirs"]], pipx_home, venv)

    apply = apply_argv("httpie", meta, [("urllib3", "1.26.20")])
    cwd = pipx_home / "work"
    cwd.mkdir()
    ctx = _Context(argv=apply, parsed=_try_parse(apply), cwd=cwd)
    asm = SandboxRunner(AppConfig())._assemble_sandbox(ctx, apply, {}, None, on_extra_write=None, read_only=False)
    assert asm is not None
    assert trial == _pip_config_seen(asm.env, [*asm.home_ro, *asm.write_dirs], pipx_home, venv)
    assert trial[0]["PIP_INDEX_URL"] == "https://pypi.example/simple"
    assert pipx_home / ".config" / "pip" / "pip.conf" in trial[1]
    assert config_problem([], []) is None


def test_a_pip_setting_only_the_fix_passes_is_a_configuration_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.languages.python_fix.pipx_app import config_problem

    monkeypatch.setenv("PIP_CONFIG_FILE", "/srv/pip.conf")
    monkeypatch.setenv("PIP_INDEX_URL", "https://pypi.example/simple")
    assert config_problem([], []) is None
    assert config_problem(["PIP_CONFIG_FILE"], ["PIP_CONFIG_FILE"]) is None
    assert config_problem([], ["PIP_CONFIG_FILE"]) == (
        "the fix would run with different pip settings from its trial (PIP_CONFIG_FILE); plan again with the "
        "same --env")


# ---- fix round 1 -----------------------------------------------------------------------------

_CONTAINER = ("could not verify: the pipx trial needs bubblewrap's read-only mounts, which container isolation "
              "does not provide")


async def test_container_isolation_does_not_run_the_trial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Container isolation has no mount namespace, so it cannot keep the app's venv read-only."""
    monkeypatch.setenv("PA_SANDBOX_ISOLATION", "container")
    a = _adapter(_httpie_doc())
    result = await a.trial([("urllib3", "1.26.20")], [], cast("TrialRunner", _NoRun()))
    assert (result.status, result.detail) == ("inconclusive", _CONTAINER)
    assert await a.baseline(cast("TrialRunner", _NoRun())) is None


async def test_run_captured_refuses_a_pipx_trial_under_container_isolation(
        pipx_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.sandbox import isolation
    from packagealert.sandbox.runner import CapturedRunError

    def no_container(*a: Any, **k: Any) -> Any:
        raise AssertionError("the trial ran under container isolation")

    monkeypatch.setattr(isolation, "run_container", no_container)
    monkeypatch.setenv("PA_SANDBOX_ISOLATION", "container")
    venvs = pipx_home / ".local" / "pipx" / "venvs"
    meta = read_metadata((venvs / "httpie" / "pipx_metadata.json").read_text())
    with pytest.raises(CapturedRunError, match="container isolation does not provide"):
        await _trial_sandbox(monkeypatch, lambda w: trial_argv("httpie", meta, [], workdir=w), pipx_home)
    assert not (venvs / ".httpie.lock").exists(), "refused before anything was written"


def _local_doc(checkout: Path) -> dict[str, Any]:
    return _meta(_pkg("localapp", str(checkout), ["--editable"]))


@pytest.mark.parametrize("where", ["venvs/localapp", "venvs", "shared", "home", "parent"])
async def test_a_checkout_overlapping_pipx_home_is_inconclusive(where: str) -> None:
    home = _VENVS.parent
    checkout = {"venvs/localapp": _VENVS / "localapp", "venvs": _VENVS, "shared": home / "shared" / "x",
                "home": home, "parent": home.parent}[where]
    a = _adapter(_local_doc(checkout), {"localapp": "1.0"}, name="localapp")
    result = await a.trial([("idna", "3.7")], [], cast("TrialRunner", _NoRun()))
    assert result.status == "inconclusive"
    assert result.detail == (f"the app's checkout {checkout} is, holds or lies in pipx's home {home}, which the "
                             "trial keeps read-only")


async def test_a_checkout_in_pipx_home_is_never_bound_writable(pipx_home: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    """Even with sandbox.editable_roots broad enough to allow it, the sandbox side refuses too."""
    venvs = pipx_home / ".local" / "pipx" / "venvs"
    (venvs / "localapp").mkdir()
    doc = _local_doc(venvs / "localapp")
    (venvs / "localapp" / "pipx_metadata.json").write_text(json.dumps(doc))
    meta = read_metadata(json.dumps(doc))
    seen = await _trial_sandbox(monkeypatch, lambda w: trial_argv("localapp", meta, [], workdir=w), pipx_home,
                                editable_roots=[pipx_home])
    assert seen["write_dirs"] == [seen["cwd"]]


async def test_other_scratch_commands_gain_no_extra_writable_path(pipx_home: Path,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    """Only a command that writes in place (the pipx trial) has its plugin's extra writable paths
    bound; for any other scratch command they are dropped as before, refused ones included."""
    from packagealert.config import AppConfig
    from packagealert.languages.python import PythonLanguage
    from packagealert.sandbox.runner import SandboxRunner

    allowed, refused = pipx_home / "src" / "a", pipx_home / "elsewhere" / "b"
    allowed.mkdir(parents=True)
    refused.mkdir(parents=True)
    monkeypatch.setattr(PythonLanguage, "sandbox_extra_write_paths", lambda self, argv, cwd: [allowed, refused])
    seen: dict[str, Any] = {}

    def fake_build_cmd(argv: list[str], write_dirs: list[Path], **kw: Any) -> list[str]:
        seen.update(kw, write_dirs=list(write_dirs))
        return ["true"]

    monkeypatch.setattr("packagealert.sandbox.runner.build_cmd", fake_build_cmd)
    cfg = AppConfig()
    cfg.sandbox.editable_roots = [pipx_home / "src"]
    cwd = _scratch(pipx_home)
    await SandboxRunner(cfg).run_captured(["uv", "lock", "--upgrade-package", "urllib3==2.8.0"], cwd=cwd, scratch=True)
    assert seen["write_dirs"] == [cwd]
    assert not seen.get("write_files")


async def test_the_trial_files_must_be_in_the_scratch_copy_it_runs_in(pipx_home: Path,
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    from packagealert.sandbox.runner import CapturedRunError

    venvs = pipx_home / ".local" / "pipx" / "venvs"
    meta = read_metadata((venvs / "httpie" / "pipx_metadata.json").read_text())
    other = _scratch(pipx_home)
    with pytest.raises(CapturedRunError, match="not in its scratch copy"):
        await _trial_sandbox(monkeypatch, lambda w: trial_argv("httpie", meta, [], workdir=other), pipx_home)
    assert not (venvs / ".httpie.lock").exists()


def test_the_command_note_says_pipx_can_undo_the_pins() -> None:
    assert _adapter(_httpie_doc()).command_note == (
        "A later pipx upgrade or pipx reinstall of httpie can undo these pins; pa scan-tools reports the "
        "packages again if it does.")


_TWO_CAUSES_ERR = ("ERROR: Cannot install botocore==1.29.0, requests==2.31.0 and urllib3==2.2.2 because these package "
                   "versions have conflicting dependencies.\n")
# What pip 26 prints for `pip install --dry-run urllib3==2.2.2 requests==2.31.0 botocore==1.29.0`: every requirement
# on urllib3 is listed, including requests', which 2.2.2 satisfies.
_TWO_CAUSES_OUT = ("\nThe conflict is caused by:\n    The user requested urllib3==2.2.2\n"
                   "    requests 2.31.0 depends on urllib3<3 and >=1.21.1\n"
                   "    botocore 1.29.0 depends on urllib3<1.27 and >=1.25.4\n\n")


def _two_causes(stdout: str = _TWO_CAUSES_OUT, pinned: dict[str, str] | None = None) -> TrialResult:
    return parse_pip_trial(1, None, _TWO_CAUSES_ERR, main="awscli", app="awscli",
                           pinned={"urllib3": "2.2.2"} if pinned is None else pinned, local=frozenset(),
                           installed=_HTTPIE, stdout=stdout)


def test_only_a_requirement_excluding_the_pin_blocks_it():
    result = _two_causes()
    assert result.blocker == Blocker("botocore", "urllib3<1.27 and >=1.25.4", "1.29.0")
    assert result.detail == "botocore 1.29.0 requires urllib3<1.27 and >=1.25.4"
    assert "requests" not in result.detail


def test_extras_and_markers_do_not_hide_a_blocking_requirement():
    out = ("The conflict is caused by:\n    The user requested urllib3==2.2.2\n"
           "    requests[socks] 2.31.0 depends on urllib3[socks]<3 and >=1.21.1\n"
           "    botocore 1.29.0 depends on urllib3[secure]<1.27,>=1.25.4; python_version >= \"3.8\"\n")
    result = _two_causes(out)
    assert result.blocker == Blocker("botocore", 'urllib3[secure]<1.27,>=1.25.4; python_version >= "3.8"', "1.29.0")
    assert "requests" not in result.detail


def test_no_requirement_excluding_the_pin_falls_back_to_pips_sentence():
    out = ("The conflict is caused by:\n    The user requested urllib3==2.2.2\n"
           "    requests 2.31.0 depends on urllib3<3 and >=1.21.1\n"
           "    odd 1.0 depends on urllib3<<<nonsense\n")
    result = _two_causes(out)
    assert result.blocker is None
    assert result.detail == ("Cannot install botocore==1.29.0, requests==2.31.0 and urllib3==2.2.2 because these "
                             "package versions have conflicting dependencies.")


def test_the_trials_own_directory_never_reaches_the_detail_even_with_a_space():
    work = Path("/home/u/.cache/package-alert/fix-scratch/my trial-1")
    stderr = (f"ERROR: Cannot install -r {work}/reqs.txt (line 1) and urllib3==1.26.19 because these package "
              "versions have conflicting dependencies.\n")
    result = parse_pip_trial(1, None, stderr, main="cappedapp", app="cappedapp", pinned={"urllib3": "1.26.19"},
                             local=frozenset(), installed=_HTTPIE, workdir=work)
    assert result.detail == ("Cannot install cappedapp's requirements and urllib3==1.26.19 because these "
                             "package versions have conflicting dependencies.")


async def test_the_trial_names_its_copy_as_the_apps_requirements(tmp_path: Path) -> None:
    a = _adapter(_httpie_doc())
    tmp = tmp_path / "a dir with spaces"
    tmp.mkdir()
    stderr = ("ERROR: Cannot install -r {copy}/reqs.txt (line 1) and urllib3==2.2.2 because these package versions "
              "have conflicting dependencies.\n")
    run = _Run({(): _BASE, ("urllib3==2.2.2",): None}, tmp, rc=1, stderr=stderr)
    result = await a.trial([("urllib3", "2.2.2")], [], cast("TrialRunner", run))
    assert result.status == "blocked"
    assert result.detail == ("Cannot install httpie's requirements and urllib3==2.2.2 "
                             "because these package versions have conflicting dependencies.")


def test_a_pre_release_pin_inside_a_range_does_not_block():
    out = ("The conflict is caused by:\n    The user requested urllib3==2.0.0rc1\n"
           "    requests 2.31.0 depends on urllib3<3 and >=1.21.1\n"
           "    botocore 1.29.0 depends on urllib3<1.27 and >=1.25.4\n")
    result = _two_causes(out, pinned={"urllib3": "2.0.0rc1"})
    assert result.blocker == Blocker("botocore", "urllib3<1.27 and >=1.25.4", "1.29.0")


def test_a_blocking_parent_with_extras_is_named_by_its_distribution():
    out = ("The conflict is caused by:\n    The user requested urllib3==2.2.2\n"
           "    botocore[crt] 1.29.0 depends on urllib3<1.27 and >=1.25.4\n")
    assert _two_causes(out).blocker == Blocker("botocore", "urllib3<1.27 and >=1.25.4", "1.29.0")


def test_a_report_nested_too_deeply_is_unreadable() -> None:
    """pip writes the report inside the sandbox, where build code could replace it."""
    result = parse_pip_trial(0, b"[" * 100_000, "", main="httpie", app="httpie", pinned={},
                             local=frozenset(), installed=_HTTPIE)
    assert (result.status, result.detail) == ("inconclusive", "pip wrote no readable report")


@pytest.mark.parametrize(("name", "version"), [("urllib3 --index-url=http://evil", "9"), ("urllib3", "9 --pre"),
                                               ("-e", "1"), ("urllib3", "")])
def test_a_report_entry_that_is_not_a_plain_pin_is_unreadable(name: str, version: str) -> None:
    """pip writes the report inside the sandbox, where code run by the trial could rewrite it."""
    report = json.dumps({"install": [{"metadata": {"name": name, "version": version},
                                      "download_info": {"url": "https://files.pythonhosted.org/x.whl"}}]}).encode()
    result = parse_pip_trial(0, report, "", main="httpie", app="httpie", pinned={}, local=frozenset(),
                             installed=_HTTPIE)
    assert (result.status, result.detail) == ("inconclusive", "pip's report has an entry this cannot read")


def test_a_pin_the_command_cannot_carry_is_the_pin_problem() -> None:
    a = _adapter(_httpie_doc(), _FIX_INSTALLED)
    plan = FixPlan(planned=[_fix("requests", "2.25.1", "2.32.0")],
                   verified_after={**_FIXED_AFTER, "requests": frozenset({"2.32.0 --pre"})})
    assert a.pin_problem(plan) == "not a plain name==version pin"
    assert a.apply_argv(plan) is None and a.commands(plan) == []
