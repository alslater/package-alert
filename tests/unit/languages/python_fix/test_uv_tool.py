"""pa fix for uv tool environments (#118): receipts, commands, the trial and its output."""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from packagealert.languages.python_fix import uv_tool
from packagealert.languages.python_fix.uv_tool import (
    ReceiptError,
    UvToolFixAdapter,
    install_argv,
    is_read_only_command,
    local_sources,
    parse_trial,
    read_receipt,
    trial_argv,
)
from packagealert.languages.python_tools import ToolEnv, ToolPackage
from packagealert.osv.remediation import group_findings
from packagealert.remediate import planner
from packagealert.remediate.adapter import Blocker, Change, Yank
from packagealert.remediate.planner import FixPlan, PlannedFix

if TYPE_CHECKING:
    from packagealert.remediate.adapter import TrialRunner

_FIX = Path(__file__).resolve().parents[3] / "fixtures" / "uv_trial"
_PY = Path("/home/user/.local/share/uv/tools/httpie/bin/python")


def _load(name: str) -> tuple[int, str]:
    header, _, body = (_FIX / f"{name}.txt").read_text().partition("\n")
    return int(header.rsplit("rc=", 1)[1]), body


def _receipt(requirements: str, extra: str = "") -> uv_tool.Receipt:
    return read_receipt(f"[tool]\nrequirements = [{requirements}]\nentrypoints = []\n{extra}")


HTTPIE = _receipt('{ name = "httpie", specifier = "==3.2.2" }, { name = "requests", specifier = "==2.25.1" }',
                  'python = "3.12"\n')


# ── the receipt ──────────────────────────────────────────────────────────────

def test_a_receipt_with_options_is_carried_over_to_both_commands():
    r = _receipt('{ name = "httpie" }', '''
[tool.options]
index-url = "https://mirror.example/simple"
extra-index-url = ["https://a.example/simple", "https://b.example/simple"]
resolution = "lowest-direct"
prerelease = "allow"
exclude-newer = "2026-10-01T23:00:00Z"
no-binary = true
''')
    assert r.unsupported == ()
    common = ["--index-url", "https://mirror.example/simple",
              "--extra-index-url", "https://a.example/simple", "--extra-index-url", "https://b.example/simple",
              "--resolution", "lowest-direct", "--prerelease", "allow", "--exclude-newer", "2026-10-01T23:00:00Z"]
    assert install_argv(r, [], "3.13") == ["uv", "tool", "install", "--force", "httpie", "--python", "3.13",
                                           *common, "--no-binary"]
    assert trial_argv(r, _PY) == ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", str(_PY),
                                  *common, "--no-binary", ":all:", "httpie"]


@pytest.mark.parametrize(("extra", "unsupported"), [
    ('constraints = [{ name = "idna", specifier = "<3" }]\n', "constraints"),
    ('overrides = [{ name = "idna", specifier = "<3" }]\n', "overrides"),
    ('[tool.options]\nconfig-settings = { a = "b" }\n', "option config-settings"),
    ('[tool.options]\nindex = [{ url = "https://x.example/simple" }]\n', "option index"),
    ('[tool.options]\nindex-url = 3\n', "option index-url"),
])
def test_what_cannot_be_carried_over_is_listed(extra, unsupported):
    r = _receipt('{ name = "httpie" }', extra)
    assert unsupported in r.unsupported


def test_a_requirement_pinned_to_an_index_cannot_be_carried_over():
    r = _receipt('{ name = "httpie" }, { name = "corp", index = "https://corp.example/simple" }')
    assert r.unsupported == ("corp's index",)


@pytest.mark.parametrize("text", ["", "[tool]\n", "[tool]\nrequirements = []\n", "not toml ["])
def test_a_file_that_is_not_a_receipt_is_refused(text):
    with pytest.raises(ReceiptError):
        read_receipt(text)


def test_sourced_requirements_become_pep508_with_their_source():
    r = _receipt(
        '{ name = "app", editable = "/src/app" }, '
        '{ name = "lib", directory = "/src/lib" }, '
        '{ name = "whl", path = "/wheels/whl-1.0-py3-none-any.whl" }, '
        '{ name = "remote", url = "https://example.org/remote-1.0.zip", subdirectory = "pkg" }, '
        '{ name = "vcs", git = "https://github.com/o/vcs?rev=v2&subdirectory=sub#0123abcd" }, '
        '{ name = "six", marker = "python_full_version >= \'3\'", specifier = ">=1.16" }, '
        '{ name = "rich", extras = ["jupyter"] }')
    assert [req.pep508() for req in r.requirements] == [
        "app @ file:///src/app",
        "lib @ file:///src/lib",
        "whl @ file:///wheels/whl-1.0-py3-none-any.whl",
        "remote @ https://example.org/remote-1.0.zip#subdirectory=pkg",
        "vcs @ git+https://github.com/o/vcs@v2#subdirectory=sub",
        "six>=1.16 ; python_full_version >= '3'",
        "rich[jupyter]",
    ]


# ── commands ─────────────────────────────────────────────────────────────────

def test_a_pin_replaces_the_receipts_own_specifier_and_others_are_added():
    argv = install_argv(HTTPIE, [("requests", "2.31.0"), ("urllib3", "1.26.19")], "3.12")
    assert argv == ["uv", "tool", "install", "--force", "httpie==3.2.2", "--with", "requests==2.31.0",
                    "--with", "urllib3==1.26.19", "--python", "3.12"]


def test_the_tools_own_pin_replaces_its_specifier():
    assert install_argv(HTTPIE, [("httpie", "3.2.4")], "3.12")[4] == "httpie==3.2.4"


def test_an_editable_tool_keeps_its_source_and_is_never_pinned():
    """The #118 comment's case: an editable tool whose name is also on PyPI."""
    r = _receipt('{ name = "requests-toolbelt", editable = "/src/mytool" }, { name = "six", editable = "/src/six" }')
    assert install_argv(r, [("urllib3", "1.26.19")], "3.12") == [
        "uv", "tool", "install", "--force", "--editable", "/src/mytool",
        "--with-editable", "/src/six", "--with", "urllib3==1.26.19", "--python", "3.12"]
    assert trial_argv(r, _PY)[7:] == ["-e", "/src/mytool", "-e", "/src/six"]


def test_editable_extras_are_kept_and_a_marker_cannot_be_carried_over():
    r = _receipt('{ name = "app", extras = ["dev", "x"], editable = "/src/app" }, '
                 '{ name = "lib", editable = "/src/lib", marker = "sys_platform == \'linux\'" }')
    assert install_argv(r, [], "3.12")[4:6] == ["--editable", "/src/app[dev,x]"]
    assert trial_argv(r, _PY)[7:9] == ["-e", "/src/app[dev,x]"]
    assert r.unsupported == ("lib's marker",)


def test_the_sandbox_leaves_the_editable_requirements_as_written():
    """The sandbox's argv rewrite makes a relative -e/--editable value absolute against the
    directory the command runs in; a `name @ file://…` value would be read as one."""
    from packagealert.languages.python import PythonLanguage

    r = _receipt('{ name = "app", extras = ["dev"], editable = "/src/my app" }, '
                 '{ name = "lib", editable = "/src/lib" }')
    lang = PythonLanguage()
    for argv in (trial_argv(r, _PY), install_argv(r, [("urllib3", "1.26.19")], "3.12")):
        assert lang.prepare_sandbox_argv(argv, Path("/home/user/.local/share/uv/tools/app")) == argv


def test_the_reinstall_names_the_tools_interpreter_when_the_receipt_does_not():
    r = _receipt('{ name = "httpie" }')
    assert uv_tool.interpreter(r, "3.12.13") == "3.12.13"
    assert uv_tool.interpreter(HTTPIE, "3.13.1") == "3.12"


# ── the trial command is the only one approved ───────────────────────────────

def test_the_trial_is_approved_as_read_only():
    assert is_read_only_command(trial_argv(HTTPIE, _PY, [("urllib3", "1.26.19")]))
    editable = _receipt('{ name = "app", editable = "/src/app" }', '[tool.options]\nno-binary = true\n')
    assert is_read_only_command(trial_argv(editable, _PY))


@pytest.mark.parametrize("argv", [
    ["uv", "pip", "install", "--upgrade", "--python", str(_PY), "httpie"],
    ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", "python3", "httpie"],
    ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", str(_PY), "--target", "/tmp/x", "httpie"],
    ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", str(_PY), "--system", "httpie"],
    ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", str(_PY), "-r", "reqs.txt"],
    ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", str(_PY), "--no-binary", "x", "httpie"],
    ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", str(_PY), "--index-url"],
    ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", str(_PY)],
    ["uv", "tool", "install", "--force", "httpie"],
])
def test_anything_else_is_not(argv):
    assert not is_read_only_command(argv)


def test_the_trial_binds_its_local_sources():
    r = _receipt('{ name = "app", editable = "/src/my app" }, { name = "lib", directory = "/src/lib" }, '
                 '{ name = "six" }')
    assert local_sources(trial_argv(r, _PY)) == [Path("/src/my app"), Path("/src/lib")]
    editable = _receipt('{ name = "app", extras = ["dev"], editable = "/src/app" }, { name = "six" }')
    assert local_sources(trial_argv(editable, _PY)) == [Path("/src/app")]
    assert local_sources(["uv", "pip", "install", "/src/x"]) == []


# ── the trial's output (recorded with uv 0.13.5 through the sandbox) ─────────

def test_an_upgrade_is_read_relative_to_what_the_tool_has_installed():
    r = parse_trial(*_load("tool_upgrade"), pinned={"urllib3": "1.26.19"})
    assert r.status == "resolved"
    assert r.changes == (Change("update", "certifi", "2026.7.22", "2026.10.23"),
                         Change("update", "pygments", "2.15.0", "2.21.0"),
                         Change("update", "urllib3", "1.26.5", "1.26.19"))


def test_the_baseline_is_what_reinstalling_changes_with_nothing_pinned():
    r = parse_trial(*_load("tool_baseline"))
    assert [(c.package, c.new) for c in r.changes] == [
        ("certifi", "2026.10.23"), ("pygments", "2.21.0"), ("urllib3", "1.26.20")]


def test_a_pin_the_tools_own_pin_rejects_is_blocked_with_the_reason():
    r = parse_trial(*_load("tool_held_by_pin"), pinned={"urllib3": "2.2.2"})
    assert r.status == "blocked"
    assert r.blocker == Blocker("requests", "urllib3>=1.21.1,<1.27")
    assert "requests==2.25.1 depends on urllib3" in r.detail


def test_a_missing_version_is_blocked_without_a_parent():
    r = parse_trial(*_load("tool_no_such_version"), pinned={"defusedxml": "99.0"})
    assert r.status == "blocked"
    assert r.blocker is None
    assert "there is no version of defusedxml==99.0" in r.detail


def test_a_yanked_version_is_reported_once():
    r = parse_trial(*_load("tool_yanked"), pinned={"requests": "2.32.0"})
    assert r.yanked == (Yank("requests", "2.32.0", "Yanked due to conflicts with CVE-2024-35195 mitigation"),)


def test_an_sdist_only_dependency_resolves_from_its_metadata():
    r = parse_trial(*_load("tool_sdist_only"))
    assert Change("add", "pycrypto", None, "2.6.1") in r.changes


def test_no_changes():
    r = parse_trial(*_load("tool_no_changes"))
    assert (r.status, r.changes) == ("resolved", ())


def test_a_local_requirement_is_rebuilt_not_moved():
    rc, err = _load("tool_local_editable")
    assert parse_trial(rc, err, local={"requests-toolbelt"}).changes == ()
    unknown = parse_trial(rc, err)
    assert unknown.status == "inconclusive"
    assert "requests-toolbelt" in unknown.detail


@pytest.mark.parametrize(("stderr", "detail"), [
    ("Resolved 1 package in 1ms\nSomething new happened\n", "unrecognised uv output"),
    (" + urllib3==1.26.19\n", "no resolution summary"),
    ("Resolved 1 package in 1ms\nwarning: yanked releases are odd\n", "unrecognised uv yank warning"),
])
def test_an_unrecognised_format_is_inconclusive(stderr, detail):
    r = parse_trial(0, stderr)
    assert r.status == "inconclusive"
    assert detail in r.detail


def test_a_version_from_elsewhere_is_not_public():
    err = "Resolved 2 packages in 1ms\n + corp==1.0 (from https://corp.example/corp-1.0.whl)\n"
    assert parse_trial(0, err).non_public == frozenset({("corp", "1.0")})


def test_the_version_a_private_one_replaces_is_not_public_either():
    err = ("Resolved 2 packages in 1ms\n - corp==1.0 (from https://corp.example/corp-1.0.whl)\n"
           " + corp==2.0 (from https://corp.example/corp-2.0.whl)\n")
    assert parse_trial(0, err).non_public == frozenset({("corp", "1.0"), ("corp", "2.0")})


def test_a_private_version_reinstalled_unchanged_is_not_public_either():
    """The trial's end state keeps it, and a baseline upgrade it keeps back is reported from it."""
    err = "Resolved 2 packages in 1ms\n ~ corp==1.0 (from https://corp.example/corp-1.0.whl)\n"
    result = parse_trial(0, err)
    assert result.changes == () and result.non_public == frozenset({("corp", "1.0")})


def test_a_failed_build_or_timeout_is_inconclusive():
    assert parse_trial(1, "error: Failed to build `pycrypto==2.6.1`\n").status == "inconclusive"
    assert parse_trial(0, "", timed_out=True).detail == "the trial resolve timed out"


# ── the adapter ──────────────────────────────────────────────────────────────

def _env(packages: dict[str, str], *, public: bool = True, site: Path | None = None, name: str = "httpie") -> ToolEnv:
    return ToolEnv("uv", name, Path("/home/user/.local/share/uv/tools") / name, "3.12.13", site, [],
                   {"kind": "pypi"}, packages=[ToolPackage(n, v, public) for n, v in packages.items()])


def _adapter(receipt_text: str, packages: dict[str, str], **kw) -> UvToolFixAdapter:
    """An adapter for the tool's own environment (named after its requirement, as uv names it)."""
    receipt = read_receipt(receipt_text)
    return UvToolFixAdapter(_env(packages, name=uv_tool._norm(receipt.tool.name), **kw), receipt,
                            receipt_text.encode())


_HTTPIE_TEXT = ('[tool]\nrequirements = [{ name = "httpie", specifier = "==3.2.2" }, '
                '{ name = "requests", specifier = "==2.25.1" }]\npython = "3.12"\nentrypoints = []\n')


def _site(tmp_path: Path, requires: dict[str, list[str]]) -> Path:
    site = tmp_path / "site-packages"
    for dist, reqs in requires.items():
        info = site / f"{dist}-1.0.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: x\n"
                                       + "".join(f"Requires-Dist: {r}\n" for r in reqs))
    return site


def test_the_graph_comes_from_the_receipt_and_requires_dist(tmp_path):
    site = _site(tmp_path, {"httpie": ["requests[socks]>=2.22", "colorama; sys_platform == 'win32'"],
                            "requests": ["urllib3<3", "PySocks!=1.5.7; extra == 'socks'", "chardet; extra == 'x'"],
                            "urllib3": [], "pysocks": [], "chardet": [], "colorama": []})
    a = _adapter(_HTTPIE_TEXT, {"httpie": "3.2.2", "requests": "2.25.1", "urllib3": "1.26.5"}, site=site)
    g = a.load_graph(Path("uv-receipt.toml"))
    assert g.members == {"uv:httpie"}
    assert g.direct == {"httpie", "requests"}
    assert g.deps["requests"] == {"urllib3", "pysocks"}
    assert "colorama" not in g.deps["httpie"]
    assert g.path_to("pysocks") == ["uv:httpie", "requests", "pysocks"]


def test_a_local_tool_is_held_as_a_local_source():
    text = '[tool]\nrequirements = [{ name = "requests-toolbelt", editable = "/src/mytool" }]\nentrypoints = []\n'
    a = _adapter(text, {"requests-toolbelt": "0.0.1", "urllib3": "1.26.5"})
    g = a.load_graph(Path("uv-receipt.toml"))
    assert g.local_source == {"requests-toolbelt"}
    findings = [{"package": "requests-toolbelt", "version": "0.0.1", "ecosystem": "PyPI", "advisory_id": "GHSA-x",
                 "aliases": [], "summary": "", "severity": None, "fixed_versions": ["1.0.0"], "is_malicious": False}]
    plan = planner.plan_fixes(group_findings(findings), g, ages={}, cooldown_days=0, allow_major=frozenset(),
                              allow_cooldown=False)
    assert [(h.package, h.reason) for h in plan.held] == [("requests-toolbelt", planner.LOCAL_SOURCE)]


def _fix(package, version, target, *, by_relock=False, parent=None):
    return PlannedFix(package=package, version=version, target=target, direct=False, path=[], advisories=["A"],
                      left_open=[], cooldown_checked=True, verified=True, by_relock=by_relock, parent=parent)


def test_upgrade_alone_when_every_fix_comes_with_the_reinstall():
    a = _adapter(_HTTPIE_TEXT, {"httpie": "3.2.2"})
    assert a.apply_argv(FixPlan(planned=[_fix("certifi", "1", "2", by_relock=True)])) == [
        "uv", "tool", "upgrade", "httpie"]
    assert a.apply_argv(FixPlan()) is None


def test_a_tool_with_a_local_source_is_reinstalled_rather_than_upgraded():
    """`uv tool upgrade` names no path, so the sandbox could not bind the checkout it rebuilds."""
    text = ('[tool]\nrequirements = [{ name = "app", directory = "/home/user/src/app" }, '
            '{ name = "six" }]\npython = "3.12"\nentrypoints = []\n')
    a = _adapter(text, {"app": "0.1", "six": "1.16.0"})
    argv = a.apply_argv(FixPlan(planned=[_fix("six", "1.16.0", "1.17.0", by_relock=True)]))
    assert argv == ["uv", "tool", "install", "--force", "app @ file:///home/user/src/app", "--with", "six",
                    "--python", "3.12"]
    assert local_sources(argv or []) == [Path("/home/user/src/app")]


def test_pins_cover_parents_and_a_separate_plans_first_item_only():
    a = _adapter(_HTTPIE_TEXT, {"httpie": "3.2.2"})
    plan = FixPlan(planned=[_fix("urllib3", "1.26.5", "1.26.19", parent=("requests", "2.31.0")),
                            _fix("certifi", "1", "2")], separate=True)
    assert a.pins(plan) == [("certifi", "2")]
    plan.separate = False
    assert a.pins(plan) == [("certifi", "2"), ("urllib3", "1.26.19"), ("requests", "2.31.0")]


async def test_an_unsupported_receipt_holds_every_trial():
    text = _HTTPIE_TEXT + 'constraints = [{ name = "idna", specifier = "<3" }]\n'
    a = _adapter(text, {"httpie": "3.2.2"})
    result = await a.trial([("urllib3", "1.26.19")], [], run=cast("TrialRunner", None))
    assert result.status == "inconclusive"
    assert "constraints" in result.detail
    assert await a.baseline(run=cast("TrialRunner", None)) is None


class _Run:
    """Answers the no-pin dry run with the baseline fixture and any pinned one with *pinned*."""

    project_dir = Path("/x")

    def __init__(self, pinned: str = "tool_upgrade") -> None:
        self.pinned, self.seen = pinned, []

    async def read_only(self, argv):
        from packagealert.remediate.adapter import CommandResult

        self.seen.append(argv)
        rc, err = _load("tool_baseline" if argv == trial_argv(HTTPIE, _PY) else self.pinned)
        return CommandResult(rc, "", err)


_INSTALLED = {"httpie": "3.2.2", "requests": "2.25.1", "urllib3": "1.26.5", "certifi": "2026.7.22",
              "pygments": "2.15.0"}


def _httpie_adapter(installed=None) -> UvToolFixAdapter:
    a = _adapter(_HTTPIE_TEXT, installed or _INSTALLED)
    a.env.venv_root = _PY.parent.parent
    return a


async def test_a_trial_is_judged_against_the_baseline():
    """verify_plan judges trials against the no-pin baseline: what reinstalling changes anyway
    (certifi, pygments) is not this pin's change, and urllib3 1.26.19 keeps back the baseline's
    1.26.20 rather than downgrading the tool."""
    a, run = _httpie_adapter(), _Run()
    result = await a.trial([("urllib3", "1.26.19")], [], run)
    assert result.changes == (Change("update", "urllib3", "1.26.5", "1.26.19"),)
    assert result.declined == (Change("update", "urllib3", "1.26.20", "1.26.19"),)
    # The whole end state is kept for --apply's check.
    assert result.after == {"httpie": {"3.2.2"}, "requests": {"2.25.1"}, "urllib3": {"1.26.19"},
                            "certifi": {"2026.10.23"}, "pygments": {"2.21.0"}}
    await a.trial([("urllib3", "1.26.19")], [], run)
    assert run.seen.count(trial_argv(HTTPIE, _PY)) == 1, "the baseline runs once"


async def test_a_pin_on_the_baseline_version_changes_nothing_of_its_own():
    """So verification can see that reinstalling alone reaches the target (by_relock)."""
    a = _httpie_adapter()
    result = await a.trial([("pygments", "2.21.0")], [], _Run("tool_baseline"))
    assert (result.changes, result.declined) == ((), ())


async def test_without_a_baseline_changes_are_measured_from_what_is_installed():
    class Failing(_Run):
        async def read_only(self, argv):
            from packagealert.remediate.adapter import CommandResult
            if argv == trial_argv(HTTPIE, _PY):
                return CommandResult(1, "", "error: something broke\n")
            return await super().read_only(argv)

    result = await _httpie_adapter().trial([("urllib3", "1.26.19")], [], Failing())
    assert len(result.changes) == 3 and result.declined == ()


async def test_a_trials_old_versions_keep_their_provenance():
    """Changes are measured from what is installed and from the baseline: their private
    versions are not sent to public lookups."""
    from packagealert.remediate.adapter import CommandResult

    class Private(_Run):
        async def read_only(self, argv):
            if argv == trial_argv(HTTPIE, _PY):
                return CommandResult(0, "", "Resolved 3 packages in 1ms\n - corp==1.0\n"
                                            " + corp==2.0 (from https://corp.example/corp-2.0.whl)\n")
            return CommandResult(0, "", "Resolved 3 packages in 1ms\n - urllib3==1.26.5\n + urllib3==1.26.19\n")

    a = _adapter(_HTTPIE_TEXT, {"httpie": "3.2.2", "urllib3": "1.26.5", "corp": "1.0"}, public=False)
    a.env.venv_root = _PY.parent.parent
    result = await a.trial([("urllib3", "1.26.19")], [], Private())
    assert result.status == "resolved", result.detail
    assert {("urllib3", "1.26.5"), ("corp", "1.0"), ("corp", "2.0")} <= result.non_public


async def test_a_private_package_name_is_not_sent_for_its_release_cadence(monkeypatch):
    from packagealert.languages.python_fix import release_cadence
    from packagealert.remediate.adapter import CommandResult

    asked: list[str] = []

    async def cadences(names):
        asked.extend(names)
        return dict.fromkeys(names, "frequent")

    monkeypatch.setattr(release_cadence, "cadences", cadences)

    class Private(_Run):
        async def read_only(self, argv):
            return CommandResult(0, "", "Resolved 3 packages in 1ms\n"
                                        " + corp==2.0 (from https://corp.example/corp-2.0.whl)\n")

    a = _adapter(_HTTPIE_TEXT, {"httpie": "3.2.2", "requests": "2.25.1", "inhouse": "1.0"})
    a.env.packages[-1] = ToolPackage("inhouse", "1.0", False)
    a.__init__(a.env, a.receipt, _HTTPIE_TEXT.encode())
    a.env.venv_root = _PY.parent.parent
    await a.trial([("requests", "2.31.0")], [], Private())
    found = await a.cadences(["corp", "inhouse", "requests"])
    assert asked == ["requests"]
    assert found == {"corp": None, "inhouse": None, "requests": "frequent"}


@pytest.mark.parametrize("stderr", [
    "error: Failed to fetch: `https://user:s3cret@pypi.corp/simple/urllib3/`\n",
    " ? corp from https://h.example/corp.zip?token=s3cret\n",
])
async def test_a_trial_detail_hides_credentials_from_uv_output(stderr):
    """The detail is shown in the report; uv quotes source URLs in its errors."""
    class Quoting(_Run):
        async def read_only(self, argv):
            from packagealert.remediate.adapter import CommandResult
            return CommandResult(1 if stderr.startswith("error") else 0, "", stderr)

    result = await _httpie_adapter().trial([("urllib3", "1.26.19")], [], Quoting())
    assert result.status == "inconclusive"
    assert "s3cret" not in result.detail and "REDACTED" in result.detail


@pytest.mark.parametrize(("baseline", "trial", "changes", "declined"), [
    ({"a": "2.0"}, {"a": "1.0"}, [], [("update", "a", "2.0", "1.0")]),            # keeps the upgrade back
    ({"a": "2.0"}, {"a": "1.5"}, [("update", "a", "1.0", "1.5")], [("update", "a", "2.0", "1.5")]),
    ({"a": "1.0"}, {"a": "0.9"}, [("update", "a", "1.0", "0.9")], []),            # below installed: a downgrade
    ({"a": "2.0"}, {"a": "3.0"}, [("update", "a", "2.0", "3.0")], []),
    ({"a": "1.0", "b": "1.0"}, {"a": "1.0"}, [("remove", "b", "1.0", None)], []),
    ({"a": "1.0"}, {"a": "1.0", "c": "1.0"}, [("add", "c", None, "1.0")], []),
    ({"a": "1.0", "n": "2.0"}, {"a": "1.0", "n": "1.0"}, [("add", "n", None, "1.0")], [("update", "n", "2.0", "1.0")]),
])
def test_diff_from_baseline(baseline, trial, changes, declined):
    def state(d):
        return {k: frozenset({v}) for k, v in d.items()}

    got = uv_tool.diff_from_baseline(state({"a": "1.0"}), state(baseline), state(trial))
    assert got == (tuple(Change(*c) for c in changes), tuple(Change(*c) for c in declined))


def test_find_links_directories_are_local_sources():
    r = _receipt('{ name = "app" }', '[tool.options]\nno-index = true\n'
                 'find-links = ["/home/u/wheels", "file:///home/u/more%20wheels", "https://example.org/l", "rel"]\n')
    for argv in (trial_argv(r, _PY), install_argv(r, [], "3.12")):
        assert local_sources(argv) == [Path("/home/u/wheels"), Path("/home/u/more wheels")]


def test_local_git_repositories_and_indexes_are_local_sources():
    r = _receipt('{ name = "app", git = "file:///home/u/app?rev=main&subdirectory=pkg#0123abcd" }, '
                 '{ name = "lib", git = "file:///home/u/my%20lib#0123abcd" }, '
                 '{ name = "far", git = "https://example.org/far.git?rev=v1#0123abcd" }',
                 '[tool.options]\nindex-url = "file:///srv/index"\n'
                 'extra-index-url = ["/srv/extra", "https://example.org/simple"]\n')
    for argv in (trial_argv(r, _PY), install_argv(r, [], "3.12")):
        assert set(local_sources(argv)) == {Path("/home/u/app"), Path("/home/u/my lib"),
                                            Path("/srv/index"), Path("/srv/extra")}


async def test_a_git_tools_trial_is_judged_on_its_dependencies():
    """uv fetches the repository first and prints the git requirement without a version:
    like a local checkout, it is rebuilt from its source and never moved (recorded in the
    real sandbox from a git+file:// tool)."""
    from packagealert.remediate.adapter import CommandResult

    text = '[tool]\nrequirements = [{ name = "gtool", git = "file:///home/user/src/gtool?rev=main#4d8a69ca" }]\n'
    a = _adapter(text + 'entrypoints = []\n', {"gtool": "0.1"})

    class Git(_Run):
        async def read_only(self, argv):
            rc, err = _load("tool_git_file")
            return CommandResult(rc, "", err)

    result = await a.trial([], [], Git())
    assert result.status == "resolved", result.detail
    assert result.after == {"gtool": {"0.1"}, "six": {"1.17.0"}}
    assert parse_trial(*_load("tool_git_file")).status == "inconclusive"  # without the receipt


@pytest.mark.parametrize(("git", "repo"), [
    ("file:///home/u/app?branch=feature/security-fix#0123abcd", "/home/u/app"),
    ("file:///home/u/a%40b?rev=v1#0123abcd", "/home/u/a@b"),
    ("file:///home/u/app?rev=feature%40alice#0123abcd", "/home/u/app"),
    ("file:///home/u/a%40b?rev=x%23y#0123abcd", "/home/u/a@b"),
])
def test_a_local_git_repository_is_found_whatever_its_revision(git, repo):
    """A branch can contain "/", "@" or "#"; an encoded "@" belongs to the path."""
    r = _receipt(f'{{ name = "app", git = "{git}" }}')
    assert local_sources(trial_argv(r, _PY)) == [Path(repo)]


@pytest.mark.parametrize(("rev", "arg"), [("feature%40alice", "app@feature%40alice"), ("x%23y", "app@x%23y"),
                                          ("feature/fix", "app@feature/fix")])
def test_a_git_revision_stays_encoded_as_uv_needs_it(rev, arg):
    """Measured with uv 0.13.5: `…/app@feature@alice` is "Ambiguous Git URL"; `…/app@feature%40alice`
    installs that branch."""
    r = _receipt(f'{{ name = "app", git = "file:///home/u/app?rev={rev}#0123abcd" }}')
    assert f"app @ git+file:///home/u/{arg}" in trial_argv(r, _PY)
    assert f"app @ git+file:///home/u/{arg}" in install_argv(r, [], "3.12")


def _with_entrypoints(requirements: str, *froms: str) -> uv_tool.Receipt:
    entries = ", ".join(f'{{ name = "e{i}", install-path = "/b/e{i}", from = "{f}" }}' for i, f in enumerate(froms))
    return read_receipt(f"[tool]\nrequirements = [{requirements}]\nentrypoints = [{entries}]\n")


def test_executables_from_another_requirement_are_carried_over():
    """Measured with uv 0.13.5: `uv tool install --force` without `--with-executables-from`
    removes that requirement's executables; the receipt records it only in `entrypoints.from`."""
    r = _with_entrypoints('{ name = "pycowsay" }, { name = "pyjokes", specifier = ">=0.5" }, { name = "six" }',
                          "pycowsay", "PyJokes")
    assert r.unsupported == () and r.providers == {"pyjokes"}
    argv = install_argv(r, [("pyjokes", "0.6.0")], "3.12")
    assert argv[4:9] == ["pycowsay", "--with-executables-from", "pyjokes==0.6.0", "--with", "six"]
    assert "pyjokes==0.6.0" in trial_argv(r, _PY, [("pyjokes", "0.6.0")])


@pytest.mark.parametrize(("requirements", "froms"), [
    ('{ name = "pycowsay" }', ("pycowsay", "pyjokes")),                       # nothing to pass
    ('{ name = "pycowsay" }, { name = "pyjokes", editable = "/src/pyjokes" }', ("pyjokes",)),
])
def test_executables_from_what_cannot_be_passed_hold_the_tool(requirements, froms):
    assert _with_entrypoints(requirements, *froms).unsupported == ("executables from pyjokes",)


@pytest.mark.parametrize("entrypoints", [
    'entrypoints = [{ name = "e", install-path = "/b/e", from = [] }]',
    'entrypoints = [{ name = "e", install-path = "/b/e", from = { a = 1 } }]',
    'entrypoints = [{ name = "e", install-path = "/b/e", from = 1 }]',
    'entrypoints = ["e"]',
    'entrypoints = "e"',
    "",                                                      # absent: providers unknown
    # Incomplete: --apply restores the executables the receipt names, so each needs both.
    'entrypoints = [{ name = "e", from = "a" }]',
    'entrypoints = [{ name = "e", install-path = "b/e", from = "a" }]',
    'entrypoints = [{ install-path = "/b/e", from = "a" }]',
    'entrypoints = [{ name = 1, install-path = "/b/e" }]',
])
def test_malformed_entrypoints_hold_the_tool_rather_than_crash(entrypoints):
    """Each tool is planned in one run: a crash here would stop every other tool's plan."""
    r = read_receipt(f'[tool]\nrequirements = [{{ name = "a" }}, {{ name = "b" }}]\n{entrypoints}\n')
    assert r.unsupported == ("entrypoints",) and r.providers == frozenset()


@pytest.mark.parametrize("field", [
    'requirements = [{ name = "t" }, { name = "a", editable = "/s\\u0000rc" }]',
    'requirements = [{ name = "t" }, { name = "a", git = "file:///s\\u0000rc" }]',
    'requirements = [{ name = "t" }]\nentrypoints = [{ name = "e", install-path = "/b\\u0000/e" }]',
    'requirements = [{ name = "t" }]\n[tool.options]\nfind-links = ["/l\\u0000"]',
])
def test_a_nul_anywhere_makes_the_receipt_unusable(field):
    """No path, URL or name can hold one; os.path raises ValueError on it (a source would be
    bound into the sandbox, an install-path restored)."""
    with pytest.raises(uv_tool.ReceiptError, match="NUL"):
        read_receipt(f"[tool]\n{field}\n")


_DEEP = "x = " + "[" * 1500 + "]" * 1500 + "\n"   # tomllib recurses once per level


def test_a_receipt_nested_too_deeply_is_a_receipt_error():
    """tomllib raises RecursionError for it: a build can leave such a receipt behind."""
    from packagealert.languages.python_fix import uv_tool as fix_tools

    text = f'[tool]\nrequirements = [{{ name = "a" }}]\n{_DEEP}'
    with pytest.raises(uv_tool.ReceiptError, match="nested too deeply"):
        read_receipt(text)
    assert fix_tools.readable_receipt(text.encode()) is False
    assert fix_tools.entrypoint_paths(text.encode()) == set()


def test_configuration_nested_too_deeply_counts_as_configuration(tmp_path):
    """What cannot be read is taken as setting what it might (fail closed)."""
    (tmp_path / "pyproject.toml").write_text(f"[tool.uv]\n{_DEEP}")
    assert uv_tool._pip_table(tmp_path / "pyproject.toml") is True
    (tmp_path / "pyproject.toml").write_text(_DEEP)
    assert uv_tool.project_config(tmp_path / "venv") == tmp_path / "pyproject.toml"


def test_a_receipt_that_still_trips_the_parser_is_a_receipt_error(monkeypatch):
    """Whatever slips past the shape checks is reported as an unusable receipt, never another
    exception: --apply re-reads the new receipt between the reinstall and its rollback."""
    from packagealert.languages.python_fix import uv_tool as fix_tools

    def unhashable(*_):
        raise TypeError("cannot use 'list' as a set element")

    monkeypatch.setattr(uv_tool, "_providers", unhashable)
    with pytest.raises(uv_tool.ReceiptError):
        read_receipt('[tool]\nrequirements = [{ name = "a" }]\nentrypoints = []\n')
    assert fix_tools.readable_receipt(b'[tool]\nrequirements = [{ name = "a" }]\nentrypoints = []\n') is False


def test_a_pin_only_a_conditional_requirement_names_is_also_added_unconditionally():
    """uv ignores a requirement whose marker is false (six on 3.12 under `python_full_version < '3'`),
    so the pin on it alone leaves the installed transitive six free."""
    r = _receipt('{ name = "pycowsay" }, { name = "six", marker = "python_full_version < \'3\'" }')
    for argv in (trial_argv(r, _PY, [("six", "1.16.0")]), install_argv(r, [("six", "1.16.0")], "3.12")):
        assert [a for a in argv if a.lower().startswith("six")] == [
            "six==1.16.0 ; python_full_version < '3'", "six==1.16.0"]


def test_a_tool_whose_python_version_is_not_recorded_is_held():
    """uv tool install --force ignores the tool's interpreter (measured with uv 0.13.5): with no
    --python to pass, the reinstall could move it to another version than the trial ran on."""
    text = _HTTPIE_TEXT.replace('python = "3.12"\n', "")
    receipt = read_receipt(text)
    unknown = UvToolFixAdapter(dataclasses.replace(_env({"httpie": "3.2.2"}), python=None), receipt, text.encode())
    assert "Python version" in (unknown.held_reason() or "")
    assert _adapter(text, {"httpie": "3.2.2"}).held_reason() is None   # pyvenv.cfg's is enough


def test_an_entrypoint_without_from_is_the_tools_own():
    """Older receipts record no `from`."""
    r = read_receipt('[tool]\nrequirements = [{ name = "a" }]\nentrypoints = [{ name = "a", install-path = "/b/a" }]\n')
    assert r.unsupported == () and r.providers == frozenset()


def test_a_repeated_requirement_is_pinned_on_every_occurrence():
    """uv records `--with 'six; marker' --with 'six>=1.10'` as two requirements; a pin on only
    the first left the active one free, so the trial missed the fix."""
    r = _receipt('{ name = "pycowsay" }, { name = "six", marker = "python_full_version < \'3\'" }, '
                 '{ name = "Six", specifier = ">=1.10" }, { name = "idna", extras = ["x"] }')
    for argv in (trial_argv(r, _PY, [("six", "1.16.0")]), install_argv(r, [("six", "1.16.0")], "3.12")):
        assert [a for a in argv if a.lower().startswith("six")] == [
            "six==1.16.0 ; python_full_version < '3'", "Six==1.16.0"]
    # Covered by the receipt, so not added again; a pin it has no requirement for is.
    argv = install_argv(r, [("SIX", "1.16.0"), ("certifi", "2")], "3.12")
    assert "SIX==1.16.0" not in argv and argv[argv.index("certifi==2") - 1] == "--with"


def test_a_local_git_tool_is_reinstalled_rather_than_upgraded():
    """`uv tool upgrade` names no path, so the sandbox could not bind the repository."""
    text = '[tool]\nrequirements = [{ name = "app", git = "file:///home/u/app#0123abcd" }]\nentrypoints = []\n'
    a = _adapter(text, {"app": "0.1"})
    argv = a.apply_argv(FixPlan(planned=[_fix("certifi", "1", "2", by_relock=True)]))
    assert argv is not None and argv[:4] == ["uv", "tool", "install", "--force"]


@pytest.mark.parametrize("program", ["uv", "/usr/bin/uv", "/home/user/.local/bin/uv.__pa_real"])
def test_local_sources_are_found_whichever_uv_runs(program):
    """The sandbox swaps a `pa setup` shim for its `uv.__pa_real` original before its path hooks run."""
    r = _receipt('{ name = "app", editable = "/src/app" }, { name = "lib", directory = "/src/lib" }')
    for argv in (trial_argv(r, _PY), install_argv(r, [], "3.12")):
        assert local_sources([program, *argv[1:]]) == [Path("/src/app"), Path("/src/lib")]
    assert is_read_only_command([program, *trial_argv(r, _PY)[1:]])


@pytest.mark.parametrize("program", ["uvx", "/usr/bin/uvx.__pa_real", "/usr/bin/notuv", "uv.__pa_real.bak"])
def test_another_program_is_not_uv(program):
    r = _receipt('{ name = "app", editable = "/src/app" }')
    for argv in (trial_argv(r, _PY), install_argv(r, [], "3.12")):
        assert local_sources([program, *argv[1:]]) == []


def test_the_command_pins_what_the_combined_trial_verified():
    """Every planned item, a baseline-provided one included, and a shared parent once at its highest."""
    a = _adapter(_HTTPIE_TEXT, {"httpie": "3.2.2"})
    plan = FixPlan(planned=[_fix("certifi", "1", "2", by_relock=True),
                            _fix("urllib3", "1.26.5", "1.26.19", parent=("requests", "2.31.0")),
                            _fix("idna", "2.10", "2.11", parent=("requests", "2.32.3"))])
    assert a.pins(plan) == [("certifi", "2"), ("idna", "2.11"), ("urllib3", "1.26.19"), ("requests", "2.32.3")]
    assert "--with" in (a.apply_argv(plan) or [])


def test_a_local_find_links_tool_is_reinstalled_rather_than_upgraded():
    text = _HTTPIE_TEXT + '[tool.options]\nfind-links = ["/home/user/wheels"]\n'
    a = _adapter(text, {"httpie": "3.2.2"})
    argv = a.apply_argv(FixPlan(planned=[_fix("certifi", "1", "2", by_relock=True)]))
    assert argv is not None and argv[:4] == ["uv", "tool", "install", "--force"]
    assert local_sources(argv) == [Path("/home/user/wheels")]


def test_an_unsupported_receipt_prints_no_command():
    a = _adapter(_HTTPIE_TEXT + 'constraints = [{ name = "idna", specifier = "<3" }]\n', {"httpie": "3.2.2"})
    assert a.commands(FixPlan(planned=[_fix("certifi", "1", "2")])) == []


def test_the_uv_configuration_each_phase_reads(tmp_path, monkeypatch):
    """uv tool ignores project configuration wherever it runs, so any project file the trial
    (uv pip, from the venv up) would read is one the reinstall does not."""
    from packagealert.sandbox import runner as sandbox_runner

    venv = tmp_path / "tools" / "app"
    venv.mkdir(parents=True)
    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "cache" / "scratch")  # as under ~
    assert uv_tool.config_mismatch(venv) is None
    (venv / "pyproject.toml").write_text("[project]\nname = 'x'\n")   # no [tool.uv]: not configuration
    assert uv_tool.config_mismatch(venv) is None
    (venv / "pyproject.toml").write_text("[tool.uv]\nresolution = 'lowest'\n")
    assert str(venv / "pyproject.toml") in (uv_tool.config_mismatch(venv) or "")
    (venv / "pyproject.toml").unlink()
    # An ancestor the scratch directory shares (~/uv.toml) is still read by the trial alone.
    (tmp_path / "uv.toml").write_text("")
    assert str(tmp_path / "uv.toml") in (uv_tool.config_mismatch(venv) or "")


async def test_a_trial_that_would_read_other_configuration_is_inconclusive(tmp_path, monkeypatch):
    from packagealert.sandbox import runner as sandbox_runner

    monkeypatch.setattr(sandbox_runner, "SCRATCH_ROOT", tmp_path / "scratch")
    a = _httpie_adapter()
    a.env.venv_root = tmp_path / "httpie"
    a.env.venv_root.mkdir()
    (a.env.venv_root / "uv.toml").write_text('index-url = "https://mirror.example/simple"\n')
    run = _Run()
    result = await a.trial([("urllib3", "1.26.19")], [], run)
    assert result.status == "inconclusive" and "uv.toml" in result.detail
    assert run.seen == []


def test_python_full_version_markers_use_the_full_version(tmp_path):
    venv = tmp_path / "httpie"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.13\n")
    site = _site(tmp_path, {"httpie": ["new-dep; python_full_version >= '3.12.5'"], "new_dep": []})
    assert uv_tool.full_python(venv) == "3.12.13"
    a = _adapter(_HTTPIE_TEXT, {"httpie": "3.2.2", "new-dep": "1.0"}, site=site)
    a.env.venv_root = venv
    a.env.python = "3.12"  # what python_tools reads from pyvenv.cfg: X.Y only
    assert a.load_graph(Path("uv-receipt.toml")).deps["httpie"] == {"new-dep"}
    # X.Y alone cannot judge it, so it is kept rather than judged against "3.12".
    assert uv_tool.dependency_edges(site, a.receipt, "3.12")["httpie"] == {"new-dep"}


_NO_VERSION = "home = /usr/bin\n"
_NO_VERSION_CPYTHON = "home = /usr/bin\nimplementation = CPython\n"


@pytest.mark.parametrize(("cfg", "fallback", "marker"), [
    *[(cfg, None, m) for cfg in (_NO_VERSION, _NO_VERSION_CPYTHON)
      for m in ("python_version < '3.10'", "python_full_version < '3.10.1'", "implementation_version < '3.10'")],
    # X.Y decides python_version, not the full version or the implementation's.
    (_NO_VERSION_CPYTHON, "3.12", "python_full_version < '3.10.1'"),
    (_NO_VERSION_CPYTHON, "3.12", "implementation_version < '3.10'"),
])
def test_an_unknown_interpreter_version_keeps_what_may_be_required(tmp_path, cfg, fallback, marker):
    """pa's own version is not the tool's: a pyvenv.cfg without one (or only X.Y) leaves the
    version markers it cannot judge holding, so a dependency they guard stays required."""
    venv = tmp_path / "app"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text(cfg)
    site = _site(tmp_path, {"httpie": [f"old-dep; {marker}"]})
    assert uv_tool.required_packages(site, HTTPIE, uv_tool.tool_interpreter(venv, fallback)) >= {"old-dep"}


def test_a_prerelease_interpreter_keeps_its_full_version(tmp_path):
    """uv records a pre-release's suffix (python_full_version): 3.14 alone misjudges markers on it."""
    venv = tmp_path / "app"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.14.0rc3\n")
    assert uv_tool.full_python(venv) == "3.14.0rc3"
    site = _site(tmp_path, {"httpie": ["rc-only; python_full_version == '3.14.0rc3'"]})
    assert uv_tool.required_packages(site, HTTPIE, uv_tool.tool_interpreter(venv, "3.14")) >= {"rc-only"}


def test_required_packages_include_what_is_not_installed(tmp_path):
    site = _site(tmp_path, {"httpie": ["requests>=2", "colorama; sys_platform == 'win32'"]})
    assert uv_tool.required_packages(site, HTTPIE, "3.12.13") == {"httpie", "requests"}


@pytest.fixture
def uv_config(tmp_path, monkeypatch):
    """uv's user configuration directory, isolated from this machine's."""
    from packagealert.languages import python_tools as pt

    for name in ("UV_CONFIG_FILE", "UV_NO_CONFIG", "UV_NO_SYSTEM_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CONFIG_DIRS", str(tmp_path / "etc-xdg"))
    monkeypatch.setattr(pt, "_UV_SYSTEM_CONFIG", tmp_path / "etc" / "uv" / "uv.toml")
    (tmp_path / "config" / "uv").mkdir(parents=True)
    return tmp_path / "config" / "uv" / "uv.toml"


def test_pip_settings_hold_the_trial(tmp_path, uv_config):
    """[pip] applies to uv pip install (the trial) but not to uv tool install (the reinstall)."""
    venv = tmp_path / "tools" / "app"
    venv.mkdir(parents=True)
    uv_config.write_text('resolution = "highest"\n')          # top level: read by both
    assert uv_tool.config_mismatch(venv) is None
    uv_config.write_text('[pip]\nresolution = "lowest-direct"\n')
    assert "[pip] settings" in (uv_tool.config_mismatch(venv) or "")
    uv_config.unlink()
    (tmp_path / "uv.toml").write_text('[pip]\nprerelease = "allow"\n')   # a shared project file
    assert str(tmp_path / "uv.toml") in (uv_tool.config_mismatch(venv) or "")


def test_receipt_markers_decide_what_is_required(tmp_path):
    site = _site(tmp_path, {"httpie": [], "colorama": ["never-installed"]})
    r = _receipt('{ name = "httpie" }, { name = "colorama", marker = "sys_platform == \'win32\'" }, '
                 '{ name = "six", marker = "python_full_version >= \'3.12.5\'" }')
    assert [x.name for x in uv_tool.applicable(r, "3.12.13")] == (
        ["httpie", "six"] if __import__("sys").platform != "win32" else ["httpie", "colorama", "six"])
    assert uv_tool.required_packages(site, r, "3.12.13") == {"httpie", "six"}
    assert uv_tool.required_packages(site, r, "3.12.1") == {"httpie"}


def test_configuration_is_judged_in_the_sandboxs_environment(tmp_path, uv_config, monkeypatch):
    """The trial and reinstall run with the sandbox's settled environment, not this process's."""
    from packagealert.parsers.process_args import SANDBOX_ENV

    venv = tmp_path / "tools" / "app"
    venv.mkdir(parents=True)
    uv_config.write_text('[pip]\nresolution = "lowest-direct"\n')
    monkeypatch.setenv("UV_NO_CONFIG", "1")                  # set here, not passed to the sandbox
    assert uv_tool.config_mismatch(venv) is None
    token = SANDBOX_ENV.set({"XDG_CONFIG_HOME": str(uv_config.parent.parent)})
    try:
        assert "[pip] settings" in (uv_tool.config_mismatch(venv) or "")
    finally:
        SANDBOX_ENV.reset(token)
    token = SANDBOX_ENV.set({"XDG_CONFIG_HOME": str(uv_config.parent.parent), "UV_NO_CONFIG": "1"})
    try:
        assert uv_tool.config_mismatch(venv) is None
    finally:
        SANDBOX_ENV.reset(token)


@pytest.mark.parametrize(("implementation", "required"), [
    ("CPython", {"httpie", "cffi"}),
    ("PyPy", {"httpie", "pypy-only"}),
    (None, {"httpie", "cffi", "pypy-only"}),                 # not recorded: kept
])
def test_interpreter_markers_follow_the_tools_interpreter(tmp_path, implementation, required):
    venv = tmp_path / "httpie"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.13\n"
                                     + (f"implementation = {implementation}\n" if implementation else ""))
    site = _site(tmp_path, {"httpie": ["pypy-only; implementation_name == 'pypy'",
                                       "cffi; platform_python_implementation != 'PyPy'"]})
    interp = uv_tool.tool_interpreter(venv)
    assert interp == uv_tool.Interpreter("3.12.13", implementation)
    assert uv_tool.required_packages(site, HTTPIE, interp) == required | {"requests"}


def test_a_relative_uv_config_file_names_different_files_for_each_phase(tmp_path, uv_config):
    from packagealert.parsers.process_args import SANDBOX_ENV

    venv = tmp_path / "tools" / "app"
    venv.mkdir(parents=True)
    for named, ok in (("uv.toml", False), (str(tmp_path / "shared.toml"), True)):
        token = SANDBOX_ENV.set({"UV_CONFIG_FILE": named})
        try:
            assert (uv_tool.config_mismatch(venv) is None) is ok
        finally:
            SANDBOX_ENV.reset(token)


def test_printed_commands_hide_credentials_but_apply_keeps_them():
    text = ('[tool]\nrequirements = [{ name = "httpie" }, '
            '{ name = "corp", url = "https://h.example/corp-1.0.zip?token=abc" }]\n'
            'entrypoints = []\n[tool.options]\nindex-url = "https://user:secret@pypi.corp/simple"\n')
    a = _adapter(text, {"httpie": "3.2.2"})
    plan = FixPlan(planned=[_fix("certifi", "1", "2")])
    (printed,) = a.commands(plan)
    shown = " ".join(printed)
    assert "secret" not in shown and "token=abc" not in shown
    assert "https://REDACTED@pypi.corp/simple" in printed
    assert "https://user:secret@pypi.corp/simple" in (a.apply_argv(plan) or [])


def test_printed_commands_carry_the_tool_directories_chosen_by_the_environment(monkeypatch):
    a = _adapter(_HTTPIE_TEXT, {"httpie": "3.2.2"})
    plan = FixPlan(planned=[_fix("certifi", "1", "2")])
    monkeypatch.delenv("UV_TOOL_DIR", raising=False)
    monkeypatch.delenv("UV_TOOL_BIN_DIR", raising=False)
    assert a.commands(plan)[0][:2] == ["uv", "tool"]
    monkeypatch.setenv("UV_TOOL_DIR", "tools")
    monkeypatch.setenv("UV_TOOL_BIN_DIR", "/opt/bin")
    assert a.commands(plan)[0][:4] == ["env", f"UV_TOOL_DIR={a.env.venv_root.parent}",
                                       "UV_TOOL_BIN_DIR=/opt/bin", "uv"]


def test_a_malformed_git_url_is_a_bad_requirement_not_a_crash():
    r = _receipt('{ name = "httpie" }, { name = "vcs", git = "https://[broken" }')
    assert r.unsupported == ("vcs's git source",)


@pytest.mark.parametrize("arg", ["https://user:secret tail@mirror.example/simple",
                                 "--index-url=https://user:secret tail@mirror.example/simple"])
def test_a_credential_with_a_space_is_hidden_whole(arg):
    from packagealert.safe_output import redacted

    (shown,) = redacted([arg])
    assert "secret" not in shown and "tail" not in shown
    assert shown.endswith("https://REDACTED@mirror.example/simple")


@pytest.mark.parametrize("text", ["error: `https://github.com/o/{t}` failed", " + corp==1.0 (from https://h.example/{t})",
                                  'see "https://h.example/{t}".', "'https://h.example/{t}'",
                                  "app @ git+https://git.example/{t}@main",
                                  "error: 'https://mirror.example/{t}': request failed",
                                  "fetching https://h.example/{t}; retrying"])
def test_a_quoted_url_ending_in_a_token_is_hidden(text):
    """What closes a quoted URL is not part of it, so a token ending its path is still found."""
    from packagealert.safe_output import redacted_text

    shown = redacted_text(text.format(t="ghp_" + "a" * 36))
    assert "ghp_" not in shown and "REDACTED-URL" in shown


@pytest.mark.parametrize("text", ["app @ git+https://github.com/example/tool@4d8a69ca971fb513da4a632ba322d961d8f94a38",
                                  " + app==1.0 (from git+https://github.com/example/tool@4d8a69ca971fb513da4a632ba322d961d8f94a38)"])
def test_a_git_commit_revision_is_shown_as_it_is(text):
    """A commit hash looks like a token, but it is the revision a printed command needs."""
    from packagealert.safe_output import redacted_text

    assert redacted_text(text) == text


def test_a_credential_with_a_semicolon_is_hidden_whole():
    from packagealert.safe_output import redacted

    assert redacted(["--index-url", "https://user:secret;tail@mirror.example/simple"]) == [
        "--index-url", "https://REDACTED@mirror.example/simple"]
    assert redacted(["x @ https://h.example/x.zip?a=1;tok=2 ; python_version >= '3'"]) == [
        "x @ https://h.example/x.zip?REDACTED ; python_version >= '3'"]
