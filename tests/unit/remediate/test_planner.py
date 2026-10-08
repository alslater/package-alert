from __future__ import annotations

import dataclasses

import pytest

from packagealert.osv.remediation import group_findings
from packagealert.remediate import planner
from packagealert.remediate.graph import DependencyGraph

_R = lambda fixed: [[{"introduced": "0"}, {"fixed": fixed}]]


def _f(pkg, ver, adv, fixed, ranges=None, **extra):
    return {"package": pkg, "ecosystem": "PyPI", "version": ver, "advisory_id": adv,
            "is_malicious": False, "severity": "HIGH", "summary": "s",
            "fixed_versions": fixed, "affected_ranges": ranges if ranges is not None else [],
            **extra}


def _graph(**overrides):
    base = {
        "members": frozenset({"proj"}),
        "direct": frozenset({"django", "requests"}),
        "deps": {"proj": frozenset({"django", "requests"}), "requests": frozenset({"urllib3"})},
        "versions": {"django": frozenset({"5.2.15"}), "urllib3": frozenset({"2.7.0"}),
                     "requests": frozenset({"2.31.0"})},
        "non_registry": frozenset(),
    }
    base.update(overrides)
    return DependencyGraph(**base)


def _plan(findings, graph=None, **kw):
    kw.setdefault("ages", {})
    kw.setdefault("cooldown_days", 7)
    return planner.plan_fixes(group_findings(findings), graph or _graph(), **kw)


def test_direct_and_transitive_fixes_are_planned_exactly():
    plan = _plan([
        _f("django", "5.2.15", "GHSA-1", ["5.2.17"], _R("5.2.17")),
        _f("urllib3", "2.7.0", "GHSA-2", ["2.8.0"], _R("2.8.0")),
    ])
    assert plan.held == []
    by = {p.package: p for p in plan.planned}
    assert (by["django"].target, by["django"].direct, by["django"].path) == ("5.2.17", True, ["proj", "django"])
    assert (by["urllib3"].target, by["urllib3"].direct) == ("2.8.0", False)
    assert by["urllib3"].path == ["proj", "requests", "urllib3"]
    assert by["urllib3"].advisories == ["GHSA-2"]
    # plan_fixes() items are unverified until a trial resolve sets `verified`.
    assert not plan.complete


@pytest.mark.parametrize(("findings", "graph_kw", "reason"), [
    ([_f("evil", "1.0", "MAL-1", [], is_malicious=True)], {}, planner.MALICIOUS),
    ([_f("django", "5.2.15", "GHSA-1", [], [[{"introduced": "0"}]])], {}, planner.NO_FIX),
    ([_f("django", "not!a!version", "GHSA-1", ["5.2.17"])], {}, planner.NOT_COMPARABLE),
    ([_f("mylib", "1.0", "GHSA-1", ["1.1"], _R("1.1"))],
     {"non_registry": frozenset({"mylib"})}, planner.NON_REGISTRY),
    ([_f("numpy", "2.0.0", "GHSA-1", ["2.0.1"], _R("2.0.1"))],
     {"versions": {"numpy": frozenset({"2.0.0", "2.3.0"})}}, planner.MULTIPLE_VERSIONS),
    ([_f("django", "5.2.15", "GHSA-1", ["6.0.8"], _R("6.0.8"))], {}, planner.MAJOR),
    ([_f("django", "5.2.15", "GHSA-1", ["5.2.17"])], {}, planner.UNVERIFIED),
])
def test_each_hold_reason(findings, graph_kw, reason):
    plan = _plan(findings, _graph(**graph_kw))
    assert plan.planned == []
    [held] = plan.held
    assert held.reason == reason
    assert not plan.complete


def test_cooldown_is_held_unless_allowed():
    f = [_f("django", "5.2.15", "GHSA-1", ["5.2.17"], _R("5.2.17"))]
    ages = {("PyPI", "django", "5.2.17"): 2.0}
    assert _plan(f, ages=ages).held[0].reason == planner.COOLDOWN
    assert _plan(f, ages=ages, allow_cooldown=True).planned[0].target == "5.2.17"
    # An age past the period, or no known age, is not a cooldown hold.
    assert _plan(f, ages={("PyPI", "django", "5.2.17"): 30.0}).planned
    assert _plan(f, ages={}).planned


def test_major_upgrade_is_planned_when_allowed():
    f = [_f("django", "5.2.15", "GHSA-1", ["6.0.8"], _R("6.0.8"))]
    [p] = _plan(f, allow_major=frozenset({"*"})).planned
    assert p.target == "6.0.8"


def test_major_upgrade_is_held_by_default():
    f = [_f("django", "5.2.15", "GHSA-1", ["6.0.8"], _R("6.0.8"))]
    assert _plan(f).held[0].reason == planner.MAJOR


def test_named_package_allows_only_that_package_major():
    f = [_f("django", "5.2.15", "GHSA-1", ["6.0.8"], _R("6.0.8")),
         _f("urllib3", "2.7.0", "GHSA-2", ["3.0.0"], _R("3.0.0"))]
    plan = _plan(f, allow_major=frozenset({"django"}))
    assert [p.package for p in plan.planned] == ["django"]
    assert [(h.package, h.reason) for h in plan.held] == [("urllib3", planner.MAJOR)]


def test_wildcard_allows_every_package_major():
    f = [_f("django", "5.2.15", "GHSA-1", ["6.0.8"], _R("6.0.8")),
         _f("urllib3", "2.7.0", "GHSA-2", ["3.0.0"], _R("3.0.0"))]
    plan = _plan(f, allow_major=frozenset({"*"}))
    assert plan.held == [] and len(plan.planned) == 2


def test_unverified_has_no_override():
    f = [_f("django", "5.2.15", "GHSA-1", ["5.2.17"])]
    plan = _plan(f, allow_major=frozenset({"*"}), allow_cooldown=True)
    assert plan.held[0].reason == planner.UNVERIFIED
    assert plan.held[0].target == "5.2.17"


def test_partial_fix_is_planned_with_its_open_advisories():
    plan = _plan([
        _f("django", "5.2.15", "GHSA-1", ["5.2.17"], _R("5.2.17")),
        _f("django", "5.2.15", "GHSA-2", [], [[{"introduced": "0"}]]),
    ])
    [p] = plan.planned
    assert (p.target, p.left_open) == ("5.2.17", ["GHSA-2"])
    assert not plan.complete


def test_structural_holds_beat_opt_in_flags():
    plan = _plan([_f("mylib", "1.0", "GHSA-1", ["2.0"], _R("2.0"))],
                 _graph(non_registry=frozenset({"mylib"})), allow_major=frozenset({"*"}))
    assert plan.held[0].reason == planner.NON_REGISTRY


def test_workspace_member_is_held_and_no_flag_overrides():
    f = [_f("proj", "0.1.0", "GHSA-1", ["0.2.0"], _R("0.2.0"))]
    plan = _plan(f, allow_major=frozenset({"*"}), allow_cooldown=True)
    assert plan.planned == []
    assert plan.held[0].reason == planner.WORKSPACE_MEMBER == "workspace member"


def test_cooldown_checked_reflects_whether_the_age_is_known():
    f = [_f("django", "5.2.15", "GHSA-1", ["5.2.17"], _R("5.2.17"))]
    assert _plan(f, ages={("PyPI", "django", "5.2.17"): 30.0}).planned[0].cooldown_checked is True
    assert _plan(f, ages={}).planned[0].cooldown_checked is False


def test_unverified_planned_items_make_the_plan_incomplete():
    from packagealert.remediate.planner import FixPlan, PlannedFix

    p = PlannedFix(package="a", version="1", target="2", direct=True, path=["a"], advisories=["X"],
                   left_open=[], cooldown_checked=True)
    assert not FixPlan(planned=[p]).complete
    assert FixPlan(planned=[dataclasses.replace(p, verified=True)]).complete


def test_new_hold_reason_strings():
    assert (planner.BLOCKED, planner.WOULD_DOWNGRADE, planner.WOULD_ADD, planner.COULD_NOT_VERIFY) == (
        "blocked", "would downgrade", "would add advisories", "could not verify",
    )


def test_separate_plan_is_never_complete():
    from packagealert.remediate.planner import FixPlan, PlannedFix

    p = PlannedFix(package="a", version="1", target="2", direct=True, path=["a"], advisories=["X"],
                   left_open=[], cooldown_checked=True, verified=True)
    assert not FixPlan(planned=[p], separate=True).complete
