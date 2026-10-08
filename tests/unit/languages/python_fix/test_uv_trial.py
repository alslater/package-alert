from __future__ import annotations

from pathlib import Path

import pytest

from packagealert.languages.python_fix.uv_trial import (
    Blocker,
    Change,
    parse_trial,
    trial_argv,
)

_FIX = Path(__file__).resolve().parents[3] / "fixtures" / "uv_trial"


def _load(name: str) -> tuple[int, str]:
    text = (_FIX / f"{name}.txt").read_text()
    header, _, body = text.partition("\n")
    rc = int(header.rsplit("rc=", 1)[1])
    return rc, body


def test_trial_argv_pins_exactly_and_floats_parents():
    assert trial_argv([("pip", "26.2.0")], ["chalice"]) == [
        "uv", "lock", "--dry-run",
        "--upgrade-package", "pip==26.2.0", "--upgrade-package", "chalice",
    ]


def test_resolved_update():
    r = parse_trial(*_load("resolved_update"))
    assert r.status == "resolved"
    assert r.changes == (Change("update", "urllib3", "2.2.1", "2.8.0"),)


def test_no_changes_is_resolved_with_nothing_changed():
    r = parse_trial(*_load("no_changes"))
    assert (r.status, r.changes) == ("resolved", ())


def test_downgrade_lists_every_change():
    r = parse_trial(*_load("downgrade"))
    assert r.status == "resolved"
    assert Change("update", "chalice", "1.33.0", "0.10.1") in r.changes
    assert Change("add", "virtualenv", None, "15.2.0") in r.changes
    assert Change("remove", "pip", "26.1.2", None) in r.changes
    assert len(r.changes) == 18


def test_blocked_names_the_parent_and_its_real_constraint():
    rc, err = _load("blocked_parent")
    r = parse_trial(rc, err, pinned={"pip": "26.2.0"})
    assert r.status == "blocked"
    # The LAST real constraint wins: newest parent releases are explained last.
    assert r.blocker == Blocker("chalice", "pip>=9,<26.2")


def test_blocked_detail_is_uvs_first_explanation_line():
    rc, err = _load("blocked_parent")
    r = parse_trial(rc, err, pinned={"pip": "26.2.0"})
    assert r.detail.startswith("Because chalice==1.32.0 depends on")


def test_blocked_detail_strips_tty_marker_and_falls_back():
    tty = "  × No solution found when resolving dependencies:\n  ╰─▶ Because a depends on b.\n"
    assert parse_trial(1, tty).detail == "Because a depends on b."
    bare = "error: No solution found when resolving dependencies\n"
    assert parse_trial(1, bare).detail == "error: No solution found when resolving dependencies"


def test_blocked_multi_chain_form():
    rc, err = _load("no_such_version")
    r = parse_trial(rc, err, pinned={"urllib3": "9.9.9"})
    assert r.status == "blocked"
    assert r.blocker == Blocker("requests", "urllib3>=1.26,<3")


@pytest.mark.parametrize(("rc", "err", "timed_out"), [
    (0, "Using CPython 3.13.13\nResolved 3 packages\nSomething new v1 -> v2\n", False),
    (2, "error: Failed to fetch: network unreachable\n", False),
    (1, "error: some other failure\n", False),
    (0, "", True),
])
def test_anything_unrecognised_is_inconclusive(rc, err, timed_out):
    r = parse_trial(rc, err, timed_out=timed_out)
    assert r.status == "inconclusive"
    assert r.detail  # names what went wrong, for the held item's message


def test_tty_style_no_solution_header_is_also_blocked():
    err = (
        "  × No solution found when resolving dependencies:\n"
        "  ╰─▶ Because chalice>=1.33.0 depends on pip>=9,<26.2 and pip==26.2.0, we can conclude that chalice>=1.33.0 cannot be used.\n"
    )
    r = parse_trial(1, err, pinned={"pip": "26.2.0"})
    assert r.blocker == Blocker("chalice", "pip>=9,<26.2")


def test_blocked_without_a_nameable_parent():
    err = "error: No solution found when resolving dependencies\n  cause: Because your project depends on pip==26.2.0 and pip<26, we can conclude that your project's requirements are unsatisfiable.\n"
    r = parse_trial(1, err, pinned={"pip": "26.2.0"})
    assert (r.status, r.blocker) == ("blocked", None)


@pytest.mark.parametrize(("err",), [
    ("",),
    ("Using CPython 3.13.13\n",),
    ("warning: something\n",),
])
def test_rc_zero_without_resolution_summary_is_inconclusive(err):
    r = parse_trial(0, err)
    assert r.status == "inconclusive"
    assert r.detail == "no resolution summary in uv output"


def test_forked_update_lines_are_parsed():
    rc, err = _load("forked_update")
    r = parse_trial(rc, err)
    assert r.status == "resolved"
    assert r.changes == (
        Change("update", "aiohttp", "3.14.1", "3.14.4", ("3.14.1", "3.14.4")),
        Change("update", "litellm", "1.88.1", "1.88.6"),
        Change("update", "yarl", "1.22.0", "1.25.1", ("1.22.0", "1.25.1")),
    )


@pytest.mark.parametrize("line, expected", [
    ("Add x v1.0, v2.0", (Change("add", "x", None, "1.0", ("1.0", "2.0")), Change("add", "x", None, "2.0", ("1.0", "2.0")))),
    ("Remove x v1.0, v2.0", (Change("remove", "x", "1.0", None), Change("remove", "x", "2.0", None))),
    ("Update x v1.0, v2.0 -> v2.0", (Change("update", "x", "1.0", "2.0"),)),
    # Each introduced version pairs with the old version just below it, so a lower fork moving up is an upgrade.
    ("Update x v1.0, v2.0 -> v1.5, v2.0", (Change("update", "x", "1.0", "1.5", ("1.5", "2.0")),)),
    ("Update numpy v1.26.4, v2.2.0 -> v1.26.5, v2.2.0",
     (Change("update", "numpy", "1.26.4", "1.26.5", ("1.26.5", "2.2.0")),)),
    # A dropped fork is paired with where it went, so its major jump is checked too.
    ("Update x v1.9, v2.0 -> v2.1", (Change("update", "x", "2.0", "2.1"), Change("update", "x", "1.9", "2.1"))),
    # A new version below every old one is still a downgrade.
    ("Update x v2.0 -> v1.0, v2.0", (Change("update", "x", "2.0", "1.0", ("1.0", "2.0")),)),
])
def test_multi_version_change_shapes(line, expected):
    r = parse_trial(0, f"Resolved 2 packages in 1ms\n{line}\n")
    assert r.status == "resolved" and r.changes == expected


@pytest.mark.parametrize("line", ["Update x v1.0 (abc1234) -> v1.0 (def5678)", "Update x (dynamic) -> v1.0",
                                  "Add x (dynamic)"])
def test_git_or_dynamic_versions_are_inconclusive(line):
    r = parse_trial(0, f"Resolved 2 packages in 1ms\n{line}\n")
    assert r.status == "inconclusive" and "x" in r.detail


def test_yank_warnings_are_recorded():
    from packagealert.remediate.adapter import Yank

    rc, err = _load("forked_update")
    assert parse_trial(rc, err).yanked == (Yank(
        "pypdfium2", "5.12.0",
        "Setup blunder breaking some bindgen codepaths (system-search / fallback). "
        "Wheels are valid and effectively identical to 5.12.1"),)
    r = parse_trial(0, "Resolved 1 package in 1ms\nwarning: `Foo_Bar==1.0` is yanked\nNo lockfile changes detected\n")
    assert r.yanked == (Yank("foo-bar", "1.0", None),)


def test_build_failure_reports_the_failing_package_and_its_error():
    rc, err = _load("build_failure")
    r = parse_trial(rc, err)
    assert r.status == "inconclusive"
    assert r.detail == ("Failed to build `causal-conv1d==1.5.0.post8` "
                        "(NameError: name 'bare_metal_version' is not defined)")


def test_error_line_without_a_traceback_is_reported_alone():
    r = parse_trial(2, "Using CPython 3.13.13\nerror: Failed to fetch: `https://example.invalid/simple/x/`\n"
                       "  Caused by: dns error\nhint: something generic\n")
    assert r.detail == "Failed to fetch: `https://example.invalid/simple/x/`"


@pytest.mark.parametrize("line", [
    "warning: `x==1.0` is now yanked",
    "warning: Yanked release selected: x 1.0",
    "warning: `x==1.0` was YANKED by its maintainer",
])
def test_unrecognised_yank_warning_is_inconclusive(line):
    r = parse_trial(0, f"Resolved 2 packages in 1ms\n{line}\nUpdate x v0.9 -> v1.0\n")
    assert r.status == "inconclusive" and "yank" in r.detail.lower()


@pytest.mark.parametrize("line", [
    "warning: The `tool.uv.dev-dependencies` field (used in `pyproject.toml`) is deprecated",
    "warning: `VIRTUAL_ENV=/x/.venv` does not match the project environment path `.venv` and will be ignored",
])
def test_routine_warnings_are_still_ignored(line):
    r = parse_trial(0, f"Resolved 2 packages in 1ms\n{line}\nUpdate x v0.9 -> v1.0\n")
    assert r.status == "resolved" and r.changes == (Change("update", "x", "0.9", "1.0"),)
