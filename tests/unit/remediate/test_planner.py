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


def test_pins_every_copy_merges_a_packages_versions_into_one_item():
    # qs locked at 6.7.0 and 6.10.0, both vulnerable: one item from the lowest version.
    groups = group_findings([
        _f("qs", "6.7.0", "GHSA-a", ["6.14.0"], _R("6.14.0"), ecosystem="npm"),
        _f("qs", "6.10.0", "GHSA-b", ["6.14.1"], _R("6.14.1"), ecosystem="npm"),
    ])
    graph = _graph(versions={"qs": frozenset({"6.7.0", "6.10.0", "6.15.0"})})
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True)
    [item] = plan.planned
    assert (item.version, item.target) == ("6.7.0", "6.14.1")
    assert set(item.advisories) == {"GHSA-a", "GHSA-b"}
    assert plan.held == []
    held = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0).held
    assert [h.reason for h in held] == [planner.MULTIPLE_VERSIONS] * 2


_SEMVER_RANGES = [[{"introduced": "0"}, {"fixed": "5.7.2"}],
                  [{"introduced": "6.0.0"}, {"fixed": "6.3.1"}],
                  [{"introduced": "7.0.0"}, {"fixed": "7.5.2"}]]


def _semver(ver):
    return _f("semver", ver, "GHSA-c2qf", ["5.7.2", "6.3.1", "7.5.2"], _SEMVER_RANGES, ecosystem="npm")


def test_merged_copies_target_the_version_that_fixes_every_copy():
    # A direct dependency is installed once (npm install semver@X), so its copies stay one item.
    groups = group_findings([_semver("5.7.1"), _semver("7.5.0")])
    graph = _graph(versions={"semver": frozenset({"5.7.1", "7.5.0"})}, direct=frozenset({"semver"}))
    # 5.7.1 → 7.5.2 crosses majors, so it needs --allow-major.
    held = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True).held
    assert [(h.reason, h.version, h.target) for h in held] == [(planner.MAJOR, "5.7.1", "7.5.2")]
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True,
                              allow_major=frozenset({"*"}))
    [item] = plan.planned
    assert (item.version, item.target, item.advisories, item.left_open) == ("5.7.1", "7.5.2", ["GHSA-c2qf"], [])


def test_a_transitive_package_on_several_major_lines_is_planned_once_per_line():
    # Each line gets its own target and its own override window, so neither needs a major upgrade.
    groups = group_findings([_semver("5.7.1"), _semver("7.5.0"), _semver("7.4.0")])
    graph = _graph(versions={"semver": frozenset({"5.7.1", "7.4.0", "7.5.0"})})
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True)
    assert plan.held == []
    assert sorted((p.package, p.version, p.target) for p in plan.planned) == [
        ("semver", "5.7.1", "5.7.2"), ("semver", "7.4.0", "7.5.2")]


def test_a_line_without_a_fix_on_it_is_held_as_a_major_upgrade_on_its_own():
    ranges = [[{"introduced": "0"}, {"fixed": "7.5.2"}]]
    groups = group_findings([_f("semver", v, "GHSA-c2qf", ["7.5.2"], ranges, ecosystem="npm")
                             for v in ("5.7.1", "7.5.0")])
    graph = _graph(versions={"semver": frozenset({"5.7.1", "7.5.0"})})
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True)
    assert [(p.version, p.target) for p in plan.planned] == [("7.5.0", "7.5.2")]
    assert [(h.reason, h.version, h.target) for h in plan.held] == [(planner.MAJOR, "5.7.1", "7.5.2")]


def test_merged_copies_with_a_range_not_covering_the_lowest_copy_are_verified():
    groups = group_findings([
        _f("qs", "6.7.0", "GHSA-a", ["6.14.0"], _R("6.14.0"), ecosystem="npm"),
        _f("qs", "6.10.0", "GHSA-b", ["6.14.1"], [[{"introduced": "6.10.0"}, {"fixed": "6.14.1"}]],
           ecosystem="npm"),
    ])
    graph = _graph(versions={"qs": frozenset({"6.7.0", "6.10.0"})})
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True)
    assert plan.held == []
    [item] = plan.planned
    assert (item.version, item.target, item.left_open) == ("6.7.0", "6.14.1", [])
    assert set(item.advisories) == {"GHSA-a", "GHSA-b"}


def test_merged_copies_report_what_the_target_leaves_open():
    # The 6.10.0 copy's GHSA-c has no fixed version; the target fixes the rest.
    groups = group_findings([
        _f("qs", "6.7.0", "GHSA-a", ["6.14.0"], _R("6.14.0"), ecosystem="npm"),
        _f("qs", "6.10.0", "GHSA-a", ["6.14.0"], _R("6.14.0"), ecosystem="npm"),
        _f("qs", "6.10.0", "GHSA-c", [], [[{"introduced": "6.10.0"}]], ecosystem="npm"),
    ])
    graph = _graph(versions={"qs": frozenset({"6.7.0", "6.10.0"})})
    [item] = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True).planned
    assert (item.target, item.left_open) == ("6.14.0", ["GHSA-c"])


def test_merged_copies_held_when_a_copy_has_no_fix():
    groups = group_findings([
        _f("qs", "6.7.0", "GHSA-a", ["6.14.0"], _R("6.14.0"), ecosystem="npm"),
        _f("qs", "6.10.0", "GHSA-c", [], [[{"introduced": "6.10.0"}]], ecosystem="npm"),
    ])
    graph = _graph(versions={"qs": frozenset({"6.7.0", "6.10.0"})})
    held = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True).held
    assert [(h.reason, h.version) for h in held] == [(planner.NO_FIX, "6.7.0")]


def test_merged_copies_held_when_a_copy_cannot_be_ordered():
    groups = group_findings([
        _f("qs", "6.7.0", "GHSA-a", ["6.14.0"], _R("6.14.0"), ecosystem="npm"),
        _f("qs", "not!a!version", "GHSA-a", ["6.14.0"], _R("6.14.0"), ecosystem="npm"),
    ])
    graph = _graph(versions={"qs": frozenset({"6.7.0", "not!a!version"})})
    held = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True).held
    assert [h.reason for h in held] == [planner.NOT_COMPARABLE]


def test_merged_copies_left_open_uses_every_copys_ranges():
    # GHSA-d: 6.10.0's copy is fixed at 6.14.1, but the range reopens at 6.14.1
    # for the other line, so the target (6.14.1) still has it.
    groups = group_findings([
        _f("qs", "6.7.0", "GHSA-a", ["6.14.1"], _R("6.14.1"), ecosystem="npm"),
        _f("qs", "6.10.0", "GHSA-d", ["6.11.0"],
           [[{"introduced": "6.10.0"}, {"fixed": "6.11.0"}], [{"introduced": "6.14.0"}]], ecosystem="npm"),
    ])
    graph = _graph(versions={"qs": frozenset({"6.7.0", "6.10.0"})})
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True)
    [item] = plan.planned
    assert (item.target, item.left_open) == ("6.14.1", ["GHSA-d"])


def test_lines_converging_on_one_allowed_target_are_one_item():
    # 5.x has no fix of its own; with the major upgrade allowed both lines target 7.5.2, which must be one
    # item (one override window), not two items whose pins collide.
    ranges = [[{"introduced": "0"}, {"fixed": "7.5.2"}]]
    groups = group_findings([_f("semver", v, "GHSA-c2qf", ["7.5.2"], ranges, ecosystem="npm")
                             for v in ("5.7.1", "7.5.0")])
    graph = _graph(versions={"semver": frozenset({"5.7.1", "7.5.0"})})
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True,
                              allow_major=frozenset({"semver"}))
    assert [(p.package, p.version, p.target) for p in plan.planned] == [("semver", "5.7.1", "7.5.2")]
    assert plan.held == []


def _psp_groups(version="6.1.2"):
    def f(adv, fixed):
        return _f("postcss-selector-parser", version, adv, [fixed], [[{"introduced": "0"}, {"fixed": fixed}]],
                  ecosystem="npm")
    return group_findings([f("GHSA-rj75", "7.1.6"), f("GHSA-w9m9", "6.1.4")])


def test_a_held_major_falls_back_to_the_best_fix_on_the_installed_line():
    graph = _graph(versions={"postcss-selector-parser": frozenset({"6.1.2"})})
    plan = planner.plan_fixes(_psp_groups(), graph, ages={}, cooldown_days=0, pins_every_copy=True)
    [p] = plan.planned
    assert (p.version, p.target, p.left_open, p.fixes_all) == ("6.1.2", "6.1.4", ["GHSA-rj75"], "7.1.6")
    assert plan.held == []


def test_a_same_line_fallback_is_not_marked_cooldown_checked_by_the_major_targets_age():
    """The ages looked up are for the recommendation the fallback replaces, so verification must check it."""
    graph = _graph(versions={"postcss-selector-parser": frozenset({"6.1.2"})})
    plan = planner.plan_fixes(_psp_groups(), graph, ages={("npm", "postcss-selector-parser", "7.1.6"): 400.0},
                              cooldown_days=7, pins_every_copy=True)
    [p] = plan.planned
    assert p.target == "6.1.4" and p.cooldown_checked is False


def test_an_allowed_major_is_planned_whole():
    graph = _graph(versions={"postcss-selector-parser": frozenset({"6.1.2"})})
    plan = planner.plan_fixes(_psp_groups(), graph, ages={}, cooldown_days=0, pins_every_copy=True,
                              allow_major=frozenset({"postcss-selector-parser"}))
    [p] = plan.planned
    assert (p.target, p.left_open, p.fixes_all) == ("7.1.6", [], None)


def test_copies_on_one_line_fall_back_to_their_highest_same_line_fix():
    def f(version, adv, fixed):
        return _f("postcss-selector-parser", version, adv, [fixed], [[{"introduced": "0"}, {"fixed": fixed}]],
                  ecosystem="npm")
    groups = group_findings([f(v, a, x) for v in ("6.1.2", "6.1.3")
                             for a, x in (("GHSA-rj75", "7.1.6"), ("GHSA-w9m9", "6.1.4"))])
    graph = _graph(versions={"postcss-selector-parser": frozenset({"6.1.2", "6.1.3"})})
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True)
    [p] = plan.planned
    assert (p.version, p.target, p.left_open, p.fixes_all) == ("6.1.2", "6.1.4", ["GHSA-rj75"], "7.1.6")


def test_a_package_installed_under_an_alias_is_held():
    """A command for it would name the alias's real package and add it as a new dependency."""
    groups = group_findings([_f("bar", "1.2.0", "GHSA-bar", ["1.2.1"], [[{"introduced": "0"}, {"fixed": "1.2.1"}]],
                                ecosystem="npm")])
    graph = _graph(direct=frozenset({"bar"}), versions={"bar": frozenset({"1.2.0"})}, aliased=frozenset({"bar"}))
    plan = planner.plan_fixes(groups, graph, ages={}, cooldown_days=0, pins_every_copy=True)
    assert plan.planned == [] and [h.reason for h in plan.held] == [planner.ALIASED]
