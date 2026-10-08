from __future__ import annotations

import asyncio
import dataclasses

import pytest

from packagealert.remediate import planner
from packagealert.remediate.adapter import Blocker, Change, TrialResult, Yank
from packagealert.remediate.planner import FixPlan, PlannedFix
from packagealert.remediate.verify import verify_plan


def _item(pkg="pip", ver="26.1.2", target="26.2.0"):
    return PlannedFix(package=pkg, version=ver, target=target, direct=False, path=["proj", "chalice", pkg],
                      advisories=["GHSA-pip"], left_open=[], cooldown_checked=True)


_EXACT = frozenset({("pip", "26.2.0"), ("chalice", "1.34.0")})


def _trials(table):
    """table: {(frozenset(pins), frozenset(floats)): TrialResult}; records calls."""
    calls = []

    async def trial(pins, floats):
        calls.append((list(pins), list(floats)))
        return table[(frozenset(pins), frozenset(floats))]
    return trial, calls


def _advisories(table):
    async def advisories(pkgs):
        return {p: table.get(p, (frozenset(), False)) for p in pkgs}
    return advisories


async def _no_age(pkg, ver):
    return None


async def _run(plan, trial, advisories=None, age=_no_age, allow_cooldown=False, **kw):
    return await verify_plan(plan, ecosystem="PyPI", trial=trial, advisories=advisories or _advisories({}),
                             age=age, cooldown_days=7, allow_cooldown=allow_cooldown, **kw)


async def test_clean_resolution_is_planned_and_verified():
    ok = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"),))
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): ok})
    out = await _run(FixPlan(planned=[_item()]), trial)
    [p] = out.planned
    assert p.verified and p.changes == () and out.held == [] and out.complete


async def test_downgrade_is_held_with_the_downgrade_named():
    res = TrialResult("resolved", (
        Change("update", "chalice", "1.33.0", "0.10.1"), Change("remove", "pip", "26.1.2", None),
    ))
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): res})
    out = await _run(FixPlan(planned=[_item()]), trial)
    [h] = out.held
    assert (h.reason, h.detail) == (planner.WOULD_DOWNGRADE, "chalice 1.33.0 → 0.10.1")


async def test_new_advisories_are_held_and_named():
    res = TrialResult("resolved", (
        Change("update", "pip", "26.1.2", "26.2.0"), Change("add", "virtualenv", None, "15.2.0"),
    ))
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): res})
    adv = _advisories({("virtualenv", "15.2.0"): (frozenset({"GHSA-v1", "GHSA-v2"}), False)})
    out = await _run(FixPlan(planned=[_item()]), trial, adv)
    [h] = out.held
    assert h.reason == planner.WOULD_ADD and "virtualenv 15.2.0" in h.detail and "GHSA-v1" in h.detail


async def test_advisory_already_on_the_old_version_is_not_new():
    res = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"), Change("update", "x", "1.0", "1.1")))
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): res})
    adv = _advisories({("x", "1.0"): (frozenset({"GHSA-x"}), False), ("x", "1.1"): (frozenset({"GHSA-x"}), False)})
    out = await _run(FixPlan(planned=[_item()]), trial, adv)
    assert out.planned and out.planned[0].verified


async def test_degraded_lookup_cannot_verify():
    res = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"), Change("add", "y", None, "1.0")))
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): res})
    adv = _advisories({("y", "1.0"): (frozenset(), True)})
    out = await _run(FixPlan(planned=[_item()]), trial, adv)
    assert out.held[0].reason == planner.COULD_NOT_VERIFY


async def test_blocked_then_rescued_by_the_parent_retry():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip>=9,<26.2"))
    rescued = TrialResult("resolved", (
        Change("update", "pip", "26.1.2", "26.2.0"), Change("update", "chalice", "1.33.0", "1.34.0"),
    ))
    trial, calls = _trials({
        (frozenset({("pip", "26.2.0")}), frozenset()): blocked,
        (frozenset({("pip", "26.2.0")}), frozenset({"chalice"})): rescued,
        (_EXACT, frozenset()): rescued,
    })
    out = await _run(FixPlan(planned=[_item()]), trial)
    [p] = out.planned
    assert p.parent == ("chalice", "1.34.0") and p.verified
    assert ([("pip", "26.2.0")], ["chalice"]) in calls


async def test_parent_retry_that_downgrades_is_held_as_a_downgrade():
    # The real chalice case: floating the parent still resolves to 0.10.1.
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip>=9,<26.2"))
    worse = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"),
                                     Change("update", "chalice", "1.33.0", "0.10.1")))
    trial, _ = _trials({
        (frozenset({("pip", "26.2.0")}), frozenset()): blocked,
        (frozenset({("pip", "26.2.0")}), frozenset({"chalice"})): worse,
        (frozenset({("pip", "26.2.0"), ("chalice", "0.10.1")}), frozenset()): worse,
    })
    out = await _run(FixPlan(planned=[_item()]), trial)
    [h] = out.held
    assert h.reason == planner.WOULD_DOWNGRADE
    assert h.detail == "chalice requires pip>=9,<26.2; pinning chalice 0.10.1: chalice 1.33.0 → 0.10.1"


async def test_blocked_with_no_parent_named_is_held_without_a_retry():
    trial, calls = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): TrialResult("blocked")})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.held[0].reason == planner.BLOCKED and len(calls) == 1


async def test_parent_version_in_cooldown_is_held_unless_allowed():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    rescued = TrialResult("resolved", (
        Change("update", "pip", "26.1.2", "26.2.0"), Change("update", "chalice", "1.33.0", "1.34.0"),
    ))
    table = {
        (frozenset({("pip", "26.2.0")}), frozenset()): blocked,
        (frozenset({("pip", "26.2.0")}), frozenset({"chalice"})): rescued,
        (_EXACT, frozenset()): rescued,
    }

    async def young(pkg, ver):
        return 1.0 if pkg == "chalice" else None

    out = await _run(FixPlan(planned=[_item()]), _trials(table)[0], age=young)
    assert out.held[0].reason == planner.COOLDOWN
    out = await _run(FixPlan(planned=[_item()]), _trials(table)[0], age=young, allow_cooldown=True)
    assert out.planned[0].parent == ("chalice", "1.34.0")


async def test_inconclusive_is_could_not_verify_with_detail():
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()):
                        TrialResult("inconclusive", detail="the trial resolve timed out")})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert (out.held[0].reason, out.held[0].detail) == (planner.COULD_NOT_VERIFY, "the trial resolve timed out")


async def test_combined_conflict_falls_back_to_separate_commands():
    a, b = _item("a", "1", "2"), _item("b", "1", "2")
    ok_a = TrialResult("resolved", (Change("update", "a", "1", "2"),))
    ok_b = TrialResult("resolved", (Change("update", "b", "1", "2"),))
    trial, _ = _trials({
        (frozenset({("a", "2")}), frozenset()): ok_a,
        (frozenset({("b", "2")}), frozenset()): ok_b,
        (frozenset({("a", "2"), ("b", "2")}), frozenset()): TrialResult("blocked"),
    })
    out = await _run(FixPlan(planned=[a, b]), trial)
    assert out.separate and {p.package for p in out.planned} == {"a", "b"}


async def test_held_items_are_kept_and_a_single_item_needs_no_combined_trial():
    held = planner.HeldFix(package="z", version="1", target=None, reason=planner.NO_FIX, advisories=["Z"])
    ok = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"),))
    trial, calls = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): ok})
    out = await _run(FixPlan(planned=[_item()], held=[held]), trial)
    assert held in out.held and len(calls) == 1 and not out.separate


@pytest.mark.parametrize("new", ["0.9", "not!a!version"])
async def test_unorderable_or_lower_update_counts_as_downgrade(new):
    res = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"), Change("update", "q", "1.0", new)))
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): res})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.held[0].reason == planner.WOULD_DOWNGRADE


_PIN = frozenset({("pip", "26.2.0")})
_PIP_UP = Change("update", "pip", "26.1.2", "26.2.0")


async def test_resolved_without_moving_the_target_is_not_verified():
    trial, _ = _trials({(_PIN, frozenset()): TrialResult("resolved", ())})
    out = await _run(FixPlan(planned=[_item()]), trial)
    [h] = out.held
    assert (h.reason, h.detail) == (planner.COULD_NOT_VERIFY, "the trial did not move pip to 26.2.0")
    assert out.planned == []


async def test_retry_that_moves_the_parent_but_not_the_target_is_held():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    retry = TrialResult("resolved", (Change("update", "chalice", "1.33.0", "1.34.0"),))
    trial, _ = _trials({(_PIN, frozenset()): blocked, (_PIN, frozenset({"chalice"})): retry})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.held[0].reason == planner.COULD_NOT_VERIFY and out.planned == []


async def test_combined_trial_with_all_targets_is_not_separate():
    a, b = _item("a", "1", "2"), _item("b", "1", "2")
    ca, cb = Change("update", "a", "1", "2"), Change("update", "b", "1", "2")
    trial, _ = _trials({
        (frozenset({("a", "2")}), frozenset()): TrialResult("resolved", (ca,)),
        (frozenset({("b", "2")}), frozenset()): TrialResult("resolved", (cb,)),
        (frozenset({("a", "2"), ("b", "2")}), frozenset()): TrialResult("resolved", (ca, cb)),
    })
    out = await _run(FixPlan(planned=[a, b]), trial)
    assert not out.separate and all(p.verified for p in out.planned) and len(out.planned) == 2


async def test_combined_trial_missing_a_target_is_separate():
    a, b = _item("a", "1", "2"), _item("b", "1", "2")
    ca, cb = Change("update", "a", "1", "2"), Change("update", "b", "1", "2")
    trial, _ = _trials({
        (frozenset({("a", "2")}), frozenset()): TrialResult("resolved", (ca,)),
        (frozenset({("b", "2")}), frozenset()): TrialResult("resolved", (cb,)),
        (frozenset({("a", "2"), ("b", "2")}), frozenset()): TrialResult("resolved", (ca,)),
    })
    out = await _run(FixPlan(planned=[a, b]), trial)
    assert out.separate


async def test_parent_of_unknown_age_clears_cooldown_checked():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    retry = TrialResult("resolved", (_PIP_UP, Change("update", "chalice", "1.33.0", "1.34.0")))
    trial, _ = _trials({(_PIN, frozenset()): blocked, (_PIN, frozenset({"chalice"})): retry,
                        (_EXACT, frozenset()): retry})
    out = await _run(FixPlan(planned=[_item()]), trial)  # _no_age -> None
    assert out.planned[0].parent == ("chalice", "1.34.0") and out.planned[0].cooldown_checked is False


async def test_parent_retry_with_degraded_lookup_keeps_that_reason():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    retry = TrialResult("resolved", (_PIP_UP, Change("update", "chalice", "1.33.0", "1.34.0"),
                                     Change("add", "y", None, "1.0")))
    trial, _ = _trials({(_PIN, frozenset()): blocked, (_PIN, frozenset({"chalice"})): retry,
                        (_EXACT, frozenset()): retry})
    adv = _advisories({("y", "1.0"): (frozenset(), True)})
    out = await _run(FixPlan(planned=[_item()]), trial, adv)
    assert out.held[0].reason == planner.COULD_NOT_VERIFY and "chalice requires pip<26.2" in out.held[0].detail


async def test_blocked_without_parent_uses_uvs_explanation():
    trial, _ = _trials({(_PIN, frozenset()): TrialResult("blocked", detail="Because x depends on y")})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert (out.held[0].reason, out.held[0].detail) == (planner.BLOCKED, "Because x depends on y")


async def test_trial_error_on_a_later_item_keeps_earlier_holds():
    down = TrialResult("resolved", (
        Change("update", "chalice", "1.33.0", "0.10.1"), Change("update", "a", "1", "2"),
    ))

    async def trial(pins, floats):
        if ("a", "2") in pins:
            return down
        raise OSError("disk gone")

    plan = FixPlan(planned=[_item("a", "1", "2"), _item("b", "1", "2")])
    out = await _run(plan, trial)
    held = {h.package: h for h in out.held}
    assert held["a"].reason == planner.WOULD_DOWNGRADE
    assert held["b"].reason == planner.COULD_NOT_VERIFY and "verification failed: disk gone" in held["b"].detail
    assert out.planned == []


async def test_combined_trial_error_makes_the_plan_separate():
    ok_a = TrialResult("resolved", (Change("update", "a", "1", "2"),))
    ok_b = TrialResult("resolved", (Change("update", "b", "1", "2"),))

    async def trial(pins, floats):
        if len(pins) > 1:
            raise OSError("boom")
        return ok_a if pins[0][0] == "a" else ok_b

    out = await _run(FixPlan(planned=[_item("a", "1", "2"), _item("b", "1", "2")]), trial)
    assert out.separate and len(out.planned) == 2


async def test_single_item_with_a_parent_trials_the_printed_pins_in_verify_one():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26"), detail="x")
    floated = TrialResult("resolved", (
        Change("update", "pip", "25.0", "26.2.0"), Change("update", "chalice", "1.0", "1.1"),
    ))
    exact_pins = frozenset({("pip", "26.2.0"), ("chalice", "1.1")})
    trial, calls = _trials({
        (frozenset({("pip", "26.2.0")}), frozenset()): blocked,
        (frozenset({("pip", "26.2.0")}), frozenset({"chalice"})): floated,
        (exact_pins, frozenset()): floated,
    })
    out = await _run(FixPlan(planned=[_item("pip", "25.0", "26.2.0")]), trial)
    assert out.planned and not out.separate
    assert calls[-1] == ([("pip", "26.2.0"), ("chalice", "1.1")], [])
    assert [c for c in calls if len(c[0]) > 1] == [calls[-1]]
    assert len(calls) == 3


_RESCUE_BLOCKED = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
_RESCUE = TrialResult("resolved", (_PIP_UP, Change("update", "chalice", "1.33.0", "1.34.0")))


async def test_parent_retry_exact_pins_blocked_holds_the_item():
    trial, _ = _trials({
        (_PIN, frozenset()): _RESCUE_BLOCKED, (_PIN, frozenset({"chalice"})): _RESCUE,
        (_EXACT, frozenset()): TrialResult("blocked"),
    })
    out = await _run(FixPlan(planned=[_item()]), trial)
    [h] = out.held
    assert h.reason == planner.COULD_NOT_VERIFY
    assert "pinning chalice 1.34.0 exactly did not resolve cleanly" in h.detail
    assert "chalice requires pip<26.2" in h.detail
    assert out.planned == [] and not out.separate


async def test_parent_retry_exact_pins_adding_advisories_is_would_add():
    exact = TrialResult("resolved", (_PIP_UP, Change("update", "chalice", "1.33.0", "1.34.0"),
                                      Change("add", "virtualenv", None, "15.2.0")))
    trial, _ = _trials({
        (_PIN, frozenset()): _RESCUE_BLOCKED, (_PIN, frozenset({"chalice"})): _RESCUE,
        (_EXACT, frozenset()): exact,
    })
    adv = _advisories({("virtualenv", "15.2.0"): (frozenset({"GHSA-v1"}), False)})
    out = await _run(FixPlan(planned=[_item()]), trial, adv)
    [h] = out.held
    assert h.reason == planner.WOULD_ADD and "virtualenv 15.2.0" in h.detail
    assert out.planned == []


async def test_parent_retry_exact_pins_not_moving_the_target_is_held():
    exact = TrialResult("resolved", (Change("update", "chalice", "1.33.0", "1.34.0"),))
    trial, _ = _trials({
        (_PIN, frozenset()): _RESCUE_BLOCKED, (_PIN, frozenset({"chalice"})): _RESCUE,
        (_EXACT, frozenset()): exact,
    })
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.held[0].reason == planner.COULD_NOT_VERIFY and out.planned == []
    assert "pinning chalice 1.34.0 exactly" in out.held[0].detail


async def test_parent_retry_exact_pins_succeed_and_record_their_own_changes():
    extra = Change("add", "extra", None, "1.0")
    exact = TrialResult("resolved", (_PIP_UP, Change("update", "chalice", "1.33.0", "1.34.0"), extra))
    trial, _ = _trials({
        (_PIN, frozenset()): _RESCUE_BLOCKED, (_PIN, frozenset({"chalice"})): _RESCUE,
        (_EXACT, frozenset()): exact,
    })
    out = await _run(FixPlan(planned=[_item()]), trial)
    [p] = out.planned
    assert p.parent == ("chalice", "1.34.0") and p.verified and not out.separate
    assert extra in p.changes and Change("update", "chalice", "1.33.0", "1.34.0") in p.changes


async def test_a_single_planned_item_never_triggers_a_combined_trial():
    ok = TrialResult("resolved", (_PIP_UP,))
    trial, calls = _trials({(_PIN, frozenset()): ok})
    await _run(FixPlan(planned=[_item()]), trial)
    assert calls == [([("pip", "26.2.0")], [])]


async def test_equivalent_version_spellings_count_as_the_target():
    res = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"),))
    trial, _ = _trials({(frozenset({("pip", "26.2")}), frozenset()): res})
    out = await _run(FixPlan(planned=[_item("pip", "26.1.2", "26.2")]), trial)
    assert out.planned and out.planned[0].verified and out.planned[0].changes == ()


# --- major-version policy applies to every package a trial upgrades ---

_PIP = ("pip", "26.2.0")


def _parent_major_table():
    blocked = TrialResult("blocked", blocker=Blocker("parent", "pip<26.2"))
    rescued = TrialResult("resolved", (
        Change("update", "pip", "26.1.2", "26.2.0"), Change("update", "parent", "1.0", "2.0"),
    ))
    return {
        (frozenset({_PIP}), frozenset()): blocked,
        (frozenset({_PIP}), frozenset({"parent"})): rescued,
        (frozenset({_PIP, ("parent", "2.0")}), frozenset()): rescued,
    }


async def test_parent_moving_across_a_major_is_held_without_allow_major():
    out = await _run(FixPlan(planned=[_item()]), _trials(_parent_major_table())[0])
    assert out.planned == []
    [h] = out.held
    assert h.reason == planner.MAJOR and h.needs_major == ("parent",)
    assert "parent 1.0 → 2.0" in h.detail and h.detail.startswith("parent requires pip<26.2; ")


@pytest.mark.parametrize("allowed", [frozenset({"parent"}), frozenset({"*"})])
async def test_parent_major_is_planned_when_allowed(allowed):
    out = await _run(FixPlan(planned=[_item()]), _trials(_parent_major_table())[0], allow_major=allowed)
    [p] = out.planned
    assert p.verified and p.parent == ("parent", "2.0") and out.held == []


async def test_parent_minor_bump_is_unaffected():
    table = _parent_major_table()
    minor = TrialResult("resolved", (
        Change("update", "pip", "26.1.2", "26.2.0"), Change("update", "parent", "1.0", "1.1"),
    ))
    table[(frozenset({_PIP}), frozenset({"parent"}))] = minor
    table[(frozenset({_PIP, ("parent", "1.1")}), frozenset())] = minor
    out = await _run(FixPlan(planned=[_item()]), _trials(table)[0])
    assert out.planned and out.planned[0].parent == ("parent", "1.1")


async def test_single_trial_bumping_an_unrelated_package_across_a_major_is_held():
    res = TrialResult("resolved", (
        Change("update", "pip", "26.1.2", "26.2.0"), Change("update", "other", "1.9.0", "2.0.0"),
        Change("update", "third", "3.1", "4.0"),
    ))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    out = await _run(FixPlan(planned=[_item()]), trial)
    [h] = out.held
    assert h.reason == planner.MAJOR and h.needs_major == ("other", "third")
    assert h.detail == "would also upgrade other 1.9.0 → 2.0.0 (major); would also upgrade third 3.1 → 4.0 (major)"
    out = await _run(FixPlan(planned=[_item()]), trial, allow_major=frozenset({"other", "third"}))
    assert out.planned and not out.held
    out = await _run(FixPlan(planned=[_item()]), trial, allow_major=frozenset({"other"}))
    assert out.held[0].needs_major == ("third",)


async def test_the_targets_own_major_bump_is_not_held_again():
    item = _item(ver="26.1.2", target="27.0.0")
    res = TrialResult("resolved", (Change("update", "pip", "26.1.2", "27.0.0"),))
    trial, _ = _trials({(frozenset({("pip", "27.0.0")}), frozenset()): res})
    for allowed in (frozenset(), frozenset({"pip"})):
        out = await _run(FixPlan(planned=[item]), trial, allow_major=allowed)
        assert out.planned and not out.held


async def test_non_registry_style_names_are_matched_normalised():
    res = TrialResult("resolved", (
        Change("update", "pip", "26.1.2", "26.2.0"), Change("update", "zope-interface", "5.0", "6.0"),
    ))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    out = await _run(FixPlan(planned=[_item()]), trial, allow_major=frozenset({"zope-interface"}))
    assert out.planned


def _combined_table(extra_change):
    wheel = PlannedFix(package="wheel", version="0.45.0", target="0.46.0", direct=False, path=["proj", "wheel"],
                       advisories=["GHSA-w"], left_open=[], cooldown_checked=True)
    a = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"),))
    b = TrialResult("resolved", (Change("update", "wheel", "0.45.0", "0.46.0"),))
    both = TrialResult("resolved", (*a.changes, *b.changes, extra_change))
    table = {
        (frozenset({_PIP}), frozenset()): a,
        (frozenset({("wheel", "0.46.0")}), frozenset()): b,
        (frozenset({_PIP, ("wheel", "0.46.0")}), frozenset()): both,
    }
    return FixPlan(planned=[_item(), wheel]), table


async def test_combined_trial_with_a_disallowed_major_bump_is_separate():
    plan, table = _combined_table(Change("update", "other", "1.0", "2.0"))
    out = await _run(plan, _trials(table)[0])
    assert out.separate is True
    out = await _run(plan, _trials(table)[0], allow_major=frozenset({"other"}))
    assert out.separate is False


async def test_combined_trial_minor_bump_of_a_bystander_is_not_separate():
    plan, table = _combined_table(Change("update", "other", "1.0", "1.1"))
    assert (await _run(plan, _trials(table)[0])).separate is False


# --- cooldown applies to every new version a trial introduces ---

_UP = Change("update", "pip", "26.1.2", "26.2.0")
_INCIDENTAL = (Change("update", "certifi", "2026.1.1", "2026.10.5"), Change("add", "newdep", None, "0.1.0"))


def _ages(table, default=None):
    calls = []

    async def age(pkg, ver):
        calls.append((pkg, ver))
        return table.get((pkg, ver), default)

    return age, calls


def _incidental_trial():
    res = TrialResult("resolved", (_UP, *_INCIDENTAL))
    return _trials({(frozenset({_PIP}), frozenset()): res})[0]


async def test_incidental_young_versions_hold_the_item_and_are_named():
    age, calls = _ages({}, default=1.0)
    out = await _run(FixPlan(planned=[_item()]), _incidental_trial(), age=age)
    assert out.planned == []
    [h] = out.held
    assert h.reason == planner.COOLDOWN
    assert h.detail == ("would upgrade certifi to 2026.10.5 (1.0 days old); "
                        "would add newdep 0.1.0 (1.0 days old)")
    assert sorted(calls) == [("certifi", "2026.10.5"), ("newdep", "0.1.0")]


async def test_incidental_young_versions_are_planned_with_allow_cooldown():
    age, _ = _ages({}, default=1.0)
    out = await _run(FixPlan(planned=[_item()]), _incidental_trial(), age=age, allow_cooldown=True)
    assert out.planned and not out.held


async def test_incidental_old_versions_are_planned_and_cooldown_stays_checked():
    age, _ = _ages({}, default=30.0)
    [p] = (await _run(FixPlan(planned=[_item()]), _incidental_trial(), age=age)).planned
    assert p.verified and p.cooldown_checked is True


async def test_incidental_unknown_age_is_planned_with_cooldown_unchecked():
    age, _ = _ages({("certifi", "2026.10.5"): 30.0}, default=None)
    [p] = (await _run(FixPlan(planned=[_item()]), _incidental_trial(), age=age)).planned
    assert p.verified and p.cooldown_checked is False


async def test_removals_need_no_age_lookup():
    res = TrialResult("resolved", (_UP, Change("remove", "gone", "1.0", None)))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    age, calls = _ages({}, default=0.1)
    assert (await _run(FixPlan(planned=[_item()]), trial, age=age)).planned
    assert calls == []


async def test_young_incidental_addition_in_the_parent_retry_holds_the_item():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    rescued = TrialResult("resolved", (
        _UP, Change("update", "chalice", "1.33.0", "1.34.0"), Change("add", "newdep", None, "0.1.0"),
    ))
    trial, _ = _trials({
        (frozenset({_PIP}), frozenset()): blocked,
        (frozenset({_PIP}), frozenset({"chalice"})): rescued,
        (_EXACT, frozenset()): rescued,
    })
    age, _ = _ages({("newdep", "0.1.0"): 1.0}, default=30.0)
    out = await _run(FixPlan(planned=[_item()]), trial, age=age)
    [h] = out.held
    assert h.reason == planner.COOLDOWN
    assert h.detail == "chalice requires pip<26.2; pinning chalice 1.34.0: would add newdep 0.1.0 (1.0 days old)"


async def test_each_version_is_looked_up_once_per_item():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    rescued = TrialResult("resolved", (_UP, Change("update", "chalice", "1.33.0", "1.34.0")))
    trial, _ = _trials({
        (frozenset({_PIP}), frozenset()): blocked,
        (frozenset({_PIP}), frozenset({"chalice"})): rescued,
        (_EXACT, frozenset()): rescued,
    })
    age, calls = _ages({}, default=30.0)
    assert (await _run(FixPlan(planned=[_item()]), trial, age=age)).planned
    assert calls == [("chalice", "1.34.0")]


async def test_combined_trial_with_a_young_non_target_addition_is_separate():
    plan, table = _combined_table(Change("add", "newdep", None, "0.1.0"))
    young, _ = _ages({("newdep", "0.1.0"): 1.0}, default=30.0)
    assert (await _run(plan, _trials(table)[0], age=young)).separate is True
    old, _ = _ages({}, default=30.0)
    assert (await _run(plan, _trials(table)[0], age=old)).separate is False
    assert (await _run(plan, _trials(table)[0], age=young, allow_cooldown=True)).separate is False


async def test_combined_trial_unknown_age_marks_every_item_unchecked():
    plan, table = _combined_table(Change("add", "newdep", None, "0.1.0"))
    unknown, _ = _ages({("newdep", "0.1.0"): None}, default=30.0)
    out = await _run(plan, _trials(table)[0], age=unknown)
    assert out.separate is False
    assert [p.cooldown_checked for p in out.planned] == [False, False]
    known, _ = _ages({}, default=30.0)
    assert [p.cooldown_checked for p in (await _run(plan, _trials(table)[0], age=known)).planned] == [True, True]


# --- command_changes: what the printed command changes beyond the listed fixes ---

_GLUE = Change("add", "glue", None, "0.5.0")


async def test_combined_only_change_is_reported_in_command_changes():
    plan, table = _combined_table(_GLUE)
    out = await _run(plan, _trials(table)[0])
    assert out.separate is False
    assert out.command_changes == (_GLUE,)
    assert [p.changes for p in out.planned] == [(), ()]


async def test_single_item_command_changes_are_its_extra_changes():
    res = TrialResult("resolved", (_UP, _GLUE))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.command_changes == (_GLUE,)
    assert out.planned[0].changes == (_GLUE,)


async def test_single_item_command_changes_exclude_the_parent_pin():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    rescued = TrialResult("resolved", (_UP, Change("update", "chalice", "1.33.0", "1.34.0"), _GLUE))
    trial, _ = _trials({
        (frozenset({_PIP}), frozenset()): blocked,
        (frozenset({_PIP}), frozenset({"chalice"})): rescued,
        (_EXACT, frozenset()): rescued,
    })
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.planned[0].parent == ("chalice", "1.34.0")
    assert out.command_changes == (_GLUE,)


async def test_separate_mode_reports_the_first_sorted_items_own_changes():
    plan, table = _combined_table(Change("update", "other", "1.0", "2.0"))  # disallowed major -> separate
    table[(frozenset({_PIP}), frozenset())] = TrialResult("resolved", (_UP, _GLUE))
    out = await _run(plan, _trials(table)[0])
    assert out.separate is True
    assert out.command_changes == (_GLUE,)


async def test_nothing_planned_has_no_command_changes():
    trial, _ = _trials({})
    out = await _run(FixPlan(), trial)
    assert out.command_changes == ()


async def test_combined_command_changes_exclude_targets_and_a_parent_pin():
    plan, table = _combined_table(_GLUE)
    chalice = Change("update", "chalice", "1.33.0", "1.34.0")
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    rescued = TrialResult("resolved", (_UP, chalice))
    table[(frozenset({_PIP}), frozenset())] = blocked
    table[(frozenset({_PIP}), frozenset({"chalice"}))] = rescued
    table[(_EXACT, frozenset())] = rescued
    wheel_up = Change("update", "wheel", "0.45.0", "0.46.0")
    table[(frozenset({*_EXACT, ("wheel", "0.46.0")}), frozenset())] = TrialResult("resolved", (_UP, wheel_up, chalice, _GLUE))
    out = await _run(plan, _trials(table)[0])
    assert out.separate is False
    assert out.planned[0].parent == ("chalice", "1.34.0")
    assert out.command_changes == (_GLUE,)


async def _verify_npm(item, res):
    trial, _ = _trials({(frozenset({(item.package, item.target)}), frozenset()): res})
    return await verify_plan(FixPlan(planned=[item]), ecosystem="npm", trial=trial,
                             advisories=_advisories({}), age=_no_age, cooldown_days=7, allow_cooldown=False)


def _npm_item(pkg, ver, target):
    return PlannedFix(package=pkg, version=ver, target=target, direct=True, path=["app", pkg],
                      advisories=["GHSA-n"], left_open=[], cooldown_checked=True)


async def test_npm_names_keep_their_own_spelling():
    # npm does not collapse separators: socket-io is a different package from socket.io,
    # so its major bump is not exempt as "the planned target".
    item = _npm_item("socket.io", "4.0.0", "4.8.0")
    res = TrialResult("resolved", (Change("update", "socket.io", "4.0.0", "4.8.0"),
                                   Change("update", "socket-io", "1.0.0", "2.0.0")))
    [h] = (await _verify_npm(item, res)).held
    assert h.reason == planner.MAJOR and h.needs_major == ("socket-io",)


async def test_npm_major_bump_is_found_for_a_non_pep440_version():
    item = _npm_item("lib", "1.0.0", "1.0.1")
    res = TrialResult("resolved", (Change("update", "lib", "1.0.0", "1.0.1"),
                                   Change("update", "dep", "1.4.0", "2.0.0-next.foo")))
    [h] = (await _verify_npm(item, res)).held
    assert h.reason == planner.MAJOR and h.needs_major == ("dep",)


async def test_pypi_major_detection_is_unchanged():
    item = _item()
    res = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"),
                                   Change("update", "Other_Pkg", "1.0", "2.0")))
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): res})
    [h] = (await _run(FixPlan(planned=[item]), trial)).held
    assert h.reason == planner.MAJOR
    out = await _run(FixPlan(planned=[item]), trial, allow_major=frozenset({"other-pkg"}))
    assert out.planned and out.planned[0].verified


async def test_blocked_without_detail_names_no_particular_manager():
    trial, _ = _trials({(frozenset({("pip", "26.2.0")}), frozenset()): TrialResult("blocked")})
    [h] = (await _run(FixPlan(planned=[_item()]), trial)).held
    assert (h.reason, h.detail) == (planner.BLOCKED, "the package manager found no resolution")


_CHALICE_BLOCK = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))


async def test_parent_retry_that_is_itself_blocked_stays_blocked():
    trial, _ = _trials({
        (frozenset({_PIP}), frozenset()): _CHALICE_BLOCK,
        (frozenset({_PIP}), frozenset({"chalice"})): TrialResult("blocked", blocker=Blocker("app", "chalice<2")),
    })
    [h] = (await _run(FixPlan(planned=[_item()]), trial)).held
    assert (h.reason, h.detail) == (planner.BLOCKED, "chalice requires pip<26.2")


async def test_inconclusive_parent_retry_could_not_be_verified():
    trial, _ = _trials({
        (frozenset({_PIP}), frozenset()): _CHALICE_BLOCK,
        (frozenset({_PIP}), frozenset({"chalice"})): TrialResult("inconclusive", detail="the trial resolve timed out"),
    })
    [h] = (await _run(FixPlan(planned=[_item()]), trial)).held
    assert (h.reason, h.detail) == (
        planner.COULD_NOT_VERIFY, "chalice requires pip<26.2; letting chalice move: the trial resolve timed out")


@pytest.mark.parametrize("pip_age", [1.0, None])
async def test_combined_trial_exempts_a_target_spelled_differently(pip_age):
    # uv reports pip 26.2; the plan says 26.2.0. Same version, already age-checked.
    wheel = PlannedFix(package="wheel", version="0.45.0", target="0.46.0", direct=False, path=["proj", "wheel"],
                       advisories=["GHSA-w"], left_open=[], cooldown_checked=True)
    pip_short = Change("update", "pip", "26.1.2", "26.2")
    wheel_up = Change("update", "wheel", "0.45.0", "0.46.0")
    trial, _ = _trials({
        (frozenset({_PIP}), frozenset()): TrialResult("resolved", (pip_short,)),
        (frozenset({("wheel", "0.46.0")}), frozenset()): TrialResult("resolved", (wheel_up,)),
        (frozenset({_PIP, ("wheel", "0.46.0")}), frozenset()): TrialResult("resolved", (pip_short, wheel_up)),
    })

    async def age(pkg, ver):
        return pip_age if (pkg, ver) == ("pip", "26.2") else 30.0

    out = await _run(FixPlan(planned=[_item(), wheel]), trial, age=age)
    assert out.separate is False
    assert [p.cooldown_checked for p in out.planned] == [True, True]


async def test_verified_exact_pin_trial_is_not_checked_twice():
    rescued = TrialResult("resolved", (_UP, Change("update", "chalice", "1.33.0", "1.34.0")))
    trial, _ = _trials({
        (frozenset({_PIP}), frozenset()): _CHALICE_BLOCK,
        (frozenset({_PIP}), frozenset({"chalice"})): rescued,
        (_EXACT, frozenset()): rescued,
    })
    lookups = []

    async def advisories(pkgs):
        lookups.append(pkgs)
        degraded = len(lookups) > 1  # any lookup after the exact trial's fails
        return {p: (frozenset(), degraded) for p in pkgs}

    out = await _run(FixPlan(planned=[_item()]), trial, advisories)
    assert len(lookups) == 1  # only the exact trial is judged; the retry finds the parent version
    [p] = out.planned
    assert p.verified and p.parent == ("chalice", "1.34.0")


async def test_age_lookups_are_bounded():
    adds = tuple(Change("add", f"dep{i}", None, "1.0") for i in range(50))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): TrialResult("resolved", (_UP, *adds))})
    running = peak = 0

    async def age(pkg, ver):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0)
        running -= 1
        return 30.0

    out = await _run(FixPlan(planned=[_item()]), trial, age=age)
    assert out.planned and peak <= 10


async def test_trial_forking_the_target_is_held():
    forked = TrialResult("resolved", (
        Change("update", "pip", "26.1.2", "26.2.0", ("26.1.2", "26.2.0")),))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): forked})
    [h] = (await _run(FixPlan(planned=[_item()]), trial)).held
    assert (h.reason, h.detail) == (
        planner.MULTIPLE_VERSIONS, "the trial locks pip at several versions (26.1.2, 26.2.0)")


async def test_forked_bystander_is_checked_but_not_held():
    fork = ("3.14.1", "3.14.4")
    res = TrialResult("resolved", (_UP, Change("update", "aiohttp", "3.14.1", "3.14.4", fork)))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    seen = []

    async def advisories(pkgs):
        seen.extend(pkgs)
        return {p: (frozenset(), False) for p in pkgs}

    out = await _run(FixPlan(planned=[_item()]), trial, advisories)
    assert out.planned and ("aiohttp", "3.14.4") in seen


async def test_combined_trial_forking_a_target_is_separate():
    plan, table = _combined_table(Change("update", "pip", "26.1.2", "26.2.0", ("26.1.2", "26.2.0")))
    assert (await _run(plan, _trials(table)[0])).separate is True


_PDF = Yank("pypdfium2", "5.12.0", "Setup blunder")


async def test_trial_introducing_a_yanked_version_is_held():
    res = TrialResult("resolved", (_UP, Change("add", "pypdfium2", None, "5.12.0")), yanked=(_PDF,))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    [h] = (await _run(FixPlan(planned=[_item()]), trial)).held
    assert (h.reason, h.detail) == (
        planner.YANKED, "would install pypdfium2 5.12.0, which is yanked (Setup blunder)")


async def test_already_locked_yank_is_noted_not_held():
    res = TrialResult("resolved", (_UP,), yanked=(_PDF,))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.planned and out.planned[0].verified and out.yanked_locked == (_PDF,)


async def test_combined_trial_introducing_a_yanked_version_is_separate():
    plan, table = _combined_table(Change("add", "pypdfium2", None, "5.12.0"))
    both = (frozenset({_PIP, ("wheel", "0.46.0")}), frozenset())
    table[both] = dataclasses.replace(table[both], yanked=(_PDF,))
    assert (await _run(plan, _trials(table)[0])).separate is True



async def test_lower_fork_moving_up_is_not_a_downgrade():
    from packagealert.languages.python_fix.uv_trial import parse_trial

    res = parse_trial(0, "Resolved 3 packages in 1ms\nUpdate pip v26.1.2 -> v26.2.0\n"
                         "Update numpy v1.26.4, v2.2.0 -> v1.26.5, v2.2.0\n")
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.planned and out.planned[0].verified


async def test_dropped_fork_major_jump_is_held():
    from packagealert.languages.python_fix.uv_trial import parse_trial

    res = parse_trial(0, "Resolved 3 packages in 1ms\nUpdate pip v26.1.2 -> v26.2.0\n"
                         "Update other v1.9, v2.0 -> v2.1\n")
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    [h] = (await _run(FixPlan(planned=[_item()]), trial)).held
    assert h.reason == planner.MAJOR and h.needs_major == ("other",)


async def test_yank_the_printed_command_upgrades_away_is_not_noted():
    plan, table = _combined_table(Change("update", "pip", "26.1.2", "26.2.0"))
    wheel_only = (frozenset({("wheel", "0.46.0")}), frozenset())
    # The wheel trial leaves pip at 26.1.2, which is yanked; the printed command upgrades it.
    table[wheel_only] = dataclasses.replace(table[wheel_only], yanked=(Yank("pip", "26.1.2"),))
    out = await _run(plan, _trials(table)[0])
    assert out.separate is False and out.yanked_locked == ()


async def test_progress_reports_each_trial_with_counts():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    rescued = TrialResult("resolved", (_UP, Change("update", "chalice", "1.33.0", "1.34.0")))
    wheel = PlannedFix(package="wheel", version="0.45.0", target="0.46.0", direct=False, path=["proj", "wheel"],
                       advisories=["GHSA-w"], left_open=[], cooldown_checked=True)
    wheel_up = TrialResult("resolved", (Change("update", "wheel", "0.45.0", "0.46.0"),))
    trial, _ = _trials({
        (frozenset({_PIP}), frozenset()): blocked,
        (frozenset({_PIP}), frozenset({"chalice"})): rescued,
        (_EXACT, frozenset()): rescued,
        (frozenset({("wheel", "0.46.0")}), frozenset()): wheel_up,
        (_EXACT | {("wheel", "0.46.0")}, frozenset()): TrialResult("resolved", (*rescued.changes, *wheel_up.changes)),
    })
    messages = []
    await _run(FixPlan(planned=[_item(), wheel]), trial, progress=messages.append)
    assert messages == [
        "Verifying fixes: 1/2 — trial-resolving pip 26.2.0",
        "Verifying fixes: 1/2 — pip is blocked by chalice; retrying with chalice free to move",
        "Verifying fixes: 1/2 — confirming pip 26.2.0 with chalice 1.34.0",
        "Verifying fixes: 2/2 — trial-resolving wheel 0.46.0",
        "Trying all 2 verified fixes together",
    ]


async def test_a_failing_progress_callback_does_not_break_verification():
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): TrialResult("resolved", (_UP,))})

    def broken(message):
        raise RuntimeError("display gone")

    out = await _run(FixPlan(planned=[_item()]), trial, progress=broken)
    assert out.planned and out.planned[0].verified


_BUILD = TrialResult("inconclusive", detail="Failed to build `causal-conv1d==1.5.0.post8` (NameError: x)")


def _two_items():
    wheel = PlannedFix(package="wheel", version="0.45.0", target="0.46.0", direct=False, path=["proj", "wheel"],
                       advisories=["GHSA-w"], left_open=[], cooldown_checked=True)
    return FixPlan(planned=[_item(), wheel])


async def test_same_failure_for_every_trial_is_reported_once_on_the_plan():
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): _BUILD,
                        (frozenset({("wheel", "0.46.0")}), frozenset()): _BUILD})
    out = await _run(_two_items(), trial)
    assert out.trial_failure == _BUILD.detail
    assert [h.reason for h in out.held] == [planner.COULD_NOT_VERIFY] * 2


async def test_different_failures_are_not_summarised():
    other = TrialResult("inconclusive", detail="the trial resolve timed out")
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): _BUILD,
                        (frozenset({("wheel", "0.46.0")}), frozenset()): other})
    assert (await _run(_two_items(), trial)).trial_failure is None


async def test_a_verified_pin_means_no_plan_level_failure():
    # Two pins fail the same way, but a third resolves: the project can be re-resolved.
    ok = TrialResult("resolved", (Change("update", "zlib-ng", "1.0", "1.1"),))
    third = PlannedFix(package="zlib-ng", version="1.0", target="1.1", direct=True, path=["proj", "zlib-ng"],
                       advisories=["GHSA-z"], left_open=[], cooldown_checked=True)
    plan = _two_items()
    plan.planned.append(third)
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): _BUILD,
                        (frozenset({("wheel", "0.46.0")}), frozenset()): _BUILD,
                        (frozenset({("zlib-ng", "1.1")}), frozenset()): ok})
    assert (await _run(plan, trial)).trial_failure is None


async def test_a_single_failing_pin_is_not_summarised():
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): _BUILD})
    assert (await _run(FixPlan(planned=[_item()]), trial)).trial_failure is None


async def test_separate_reason_names_a_combined_conflict():
    plan, table = _combined_table(Change("update", "x", "1.0", "1.1"))
    table[(frozenset({_PIP, ("wheel", "0.46.0")}), frozenset())] = TrialResult("blocked")
    out = await _run(plan, _trials(table)[0])
    assert out.separate and out.separate_reason == "no resolution exists with all of them pinned"


async def test_separate_reason_names_a_combined_side_effect():
    plan, table = _combined_table(Change("update", "other", "2.0", "1.0"))
    out = await _run(plan, _trials(table)[0])
    assert out.separate and out.separate_reason == "together they would downgrade: other 2.0 → 1.0"


async def test_separate_reason_names_a_combined_major_bump():
    plan, table = _combined_table(Change("update", "other", "1.0", "2.0"))
    out = await _run(plan, _trials(table)[0])
    assert out.separate_reason == "together they would upgrade other to a new major version"


async def test_separate_reason_names_an_inconclusive_combined_trial():
    plan, table = _combined_table(Change("update", "x", "1.0", "1.1"))
    table[(frozenset({_PIP, ("wheel", "0.46.0")}), frozenset())] = TrialResult(
        "inconclusive", detail="the trial resolve timed out")
    out = await _run(plan, _trials(table)[0])
    assert out.separate_reason == "the combined trial was not conclusive (the trial resolve timed out)"


async def test_separate_reason_names_a_failed_combined_trial():
    plan, table = _combined_table(Change("update", "x", "1.0", "1.1"))
    del table[(frozenset({_PIP, ("wheel", "0.46.0")}), frozenset())]  # the fake trial raises KeyError
    out = await _run(plan, _trials(table)[0])
    assert out.separate and out.separate_reason is not None
    assert out.separate_reason.startswith("the combined trial failed")


async def test_no_separate_reason_when_the_fixes_go_together():
    plan, table = _combined_table(Change("update", "x", "1.0", "1.1"))
    out = await _run(plan, _trials(table)[0])
    assert out.separate is False and out.separate_reason is None


async def test_yank_kept_in_a_fork_is_still_noted():
    fork = Change("update", "other", "1.0", "1.1", ("1.0", "1.1"))
    old = Yank("other", "1.0", "broken")
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): TrialResult("resolved", (_UP, fork), yanked=(old,))})
    out = await _run(FixPlan(planned=[_item()]), trial)
    assert out.planned and out.yanked_locked == (old,)


async def test_registry_yanks_are_listed_unless_the_command_moves_them():
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): TrialResult("resolved", (_UP,))})
    kept, moved = Yank("other", "1.0", "broken"), Yank("pip", "26.1.2", "oops")
    out = await _run(FixPlan(planned=[_item()]), trial, locked_yanks=(kept, moved))
    assert out.yanked_locked == (kept,)


async def test_a_registry_yank_and_a_trial_yank_of_one_version_are_listed_once():
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): TrialResult(
        "resolved", (_UP,), yanked=(Yank("Other", "1.0", "from uv"),))})
    out = await _run(FixPlan(planned=[_item()]), trial, locked_yanks=(Yank("other", "1.0", "broken"),))
    assert out.yanked_locked == (Yank("other", "1.0", "broken"),)


_CHALICE_UP = Change("update", "chalice", "1.33.0", "1.34.0")


@pytest.mark.parametrize("incidental, age_of", [
    (Change("add", "y", None, "1.0"), {}),                      # an advisory
    (Change("update", "z", "1.0", "2.0"), {}),                   # a major upgrade
    (Change("update", "w", "1.0", "1.1"), {("w", "1.1"): 1.0}),  # inside the cooldown
])
async def test_only_the_exact_parent_trial_is_judged(incidental, age_of):
    # Floating the parent let uv move something else as well; pinning the parent
    # exactly (the printed command) does not, so the fix is safe to print.
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    retry = TrialResult("resolved", (_PIP_UP, _CHALICE_UP, incidental))
    exact = TrialResult("resolved", (_PIP_UP, _CHALICE_UP))
    trial, _ = _trials({(_PIN, frozenset()): blocked, (_PIN, frozenset({"chalice"})): retry,
                        (_EXACT, frozenset()): exact})

    async def age(pkg, ver):
        return age_of.get((pkg, ver), 100.0)

    adv = _advisories({("y", "1.0"): (frozenset({"GHSA-y"}), False)})
    out = await _run(FixPlan(planned=[_item()]), trial, adv, age=age)
    assert [p.parent for p in out.planned] == [("chalice", "1.34.0")] and out.held == []


async def test_a_problem_in_the_exact_parent_trial_is_held_with_its_context():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    resolved = TrialResult("resolved", (_PIP_UP, _CHALICE_UP, Change("add", "y", None, "1.0")))
    trial, _ = _trials({(_PIN, frozenset()): blocked, (_PIN, frozenset({"chalice"})): resolved,
                        (_EXACT, frozenset()): resolved})
    adv = _advisories({("y", "1.0"): (frozenset({"GHSA-y"}), False)})
    [h] = (await _run(FixPlan(planned=[_item()]), trial, adv)).held
    assert h.reason == planner.WOULD_ADD
    assert h.detail.startswith("chalice requires pip<26.2; pinning chalice 1.34.0: ")
