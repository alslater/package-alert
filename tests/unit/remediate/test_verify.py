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

    async def trial(pins, floats, *, force=(), lowest=None):
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


@pytest.mark.parametrize(("planner_checked", "age_days", "held"), [
    (False, 1.0, True),      # the planner never saw this target (a same-line fallback, a merged item): checked here
    (False, 30.0, False),
    (True, 1.0, False),      # the planner looked its age up already
])
async def test_a_target_the_planner_did_not_age_check_is_checked_by_the_trial(planner_checked, age_days, held):
    import dataclasses

    res = TrialResult("resolved", (_UP,))
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): res})
    age, calls = _ages({("pip", "26.2.0"): age_days})
    item = dataclasses.replace(_item(), cooldown_checked=planner_checked)
    out = await _run(FixPlan(planned=[item]), trial, age=age)
    assert [h.reason for h in out.held] == ([planner.COOLDOWN] if held else [])
    assert (("pip", "26.2.0") in calls) is not planner_checked
    if not held:
        [p] = out.planned
        assert p.cooldown_checked is True


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
        "Verifying fixes: 0 of 2 done — trial-resolving pip 26.2.0",
        "Verifying fixes: 0 of 2 done — pip is blocked by chalice; retrying with chalice free to move",
        "Verifying fixes: 0 of 2 done — confirming pip 26.2.0 with chalice 1.34.0",
        "Verifying fixes: 1 of 2 done — trial-resolving wheel 0.46.0",
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


def test_npm_zero_minor_bump_is_a_major_crossing():
    from packagealert.remediate.verify import _crosses_major
    assert _crosses_major("npm", "0.3.1", "0.4.0") and not _crosses_major("PyPI", "0.3.1", "0.4.0")


async def test_blocked_transitive_falls_back_to_a_forced_pin():
    blocked = TrialResult("blocked", blocker=Blocker("express", "qs@6.7.0"))
    still = TrialResult("blocked", blocker=Blocker("express", "qs@6.7.0"))
    forced = TrialResult("resolved", (Change("update", "qs", "6.7.0", "6.14.0"),))
    calls = []

    async def trial(pins, floats, *, force=(), lowest=None):
        calls.append((list(pins), list(floats), list(force)))
        if force:
            return forced
        return still if floats else blocked

    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, can_force=True, pins_every_copy=True)
    [p] = out.planned
    assert p.forced == ("express", "qs@6.7.0") and p.parent is None and p.verified
    assert ([("qs", "6.14.0")], [], [("qs", "6.14.0")]) in calls


async def test_forced_pin_that_downgrades_is_held_with_its_reason():
    blocked = TrialResult("blocked", blocker=Blocker("express", "qs@6.7.0"))
    worse = TrialResult("resolved", (Change("update", "qs", "6.7.0", "6.14.0"),
                                      Change("update", "express", "4.17.1", "3.0.0")))

    async def trial(pins, floats, *, force=()):
        return worse if force else blocked

    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, can_force=True)
    assert out.planned == []
    assert out.held[0].reason == planner.WOULD_DOWNGRADE and "forcing qs 6.14.0" in out.held[0].detail


async def test_without_force_a_blocked_parent_route_stays_held():
    blocked = TrialResult("blocked", blocker=Blocker("express", "qs@6.7.0"))

    async def trial(pins, floats, *, force=()):
        assert not force
        return blocked

    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial)
    assert out.held[0].reason == planner.BLOCKED


async def test_blocked_without_a_blocker_is_never_forced():
    async def trial(pins, floats, *, force=()):
        assert not force
        return TrialResult("blocked", detail="no such version")

    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, can_force=True)
    assert (out.held[0].reason, out.held[0].detail) == (planner.BLOCKED, "no such version")


async def test_a_verified_parent_route_is_not_forced():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26"))
    retry = TrialResult("resolved", (Change("update", "chalice", "1.33.0", "1.34.0"),))
    exact = TrialResult("resolved", (Change("update", "pip", "26.1.2", "26.2.0"),
                                      Change("update", "chalice", "1.33.0", "1.34.0")))

    async def trial(pins, floats, *, force=()):
        assert not force
        if floats:
            return retry
        return exact if len(pins) == 2 else blocked

    out = await _run(FixPlan(planned=[_item()]), trial, can_force=True)
    [p] = out.planned
    assert p.parent == ("chalice", "1.34.0") and p.forced is None


async def test_pins_every_copy_ignores_other_locked_versions_of_the_target():
    ok = TrialResult("resolved", (Change("update", "qs", "6.7.0", "6.14.0", fork_versions=("6.14.0", "6.15.0")),))
    trial, _ = _trials({(frozenset({("qs", "6.14.0")}), frozenset()): ok})
    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, pins_every_copy=True)
    assert out.planned and out.planned[0].verified
    held = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial)
    assert held.held[0].reason == planner.MULTIPLE_VERSIONS


async def test_combined_trial_passes_the_forced_packages():
    calls = []

    def up(n):
        return TrialResult("resolved", (Change("update", n, "1.0.0", "2.0.0"),))

    async def trial(pins, floats, *, force=()):
        calls.append((sorted(pins), tuple(force)))
        if len(pins) == 2:
            return TrialResult("resolved", (Change("update", "a", "1.0.0", "2.0.0"),
                                            Change("update", "b", "1.0.0", "2.0.0")))
        if pins == [("b", "2.0.0")] and not force:
            return TrialResult("blocked", blocker=Blocker("p", "b@1"))
        return up(pins[0][0])

    a, b = _item("a", "1.0.0", "2.0.0"), _item("b", "1.0.0", "2.0.0")
    out = await _run(FixPlan(planned=[a, b]), trial, can_force=True, allow_major=frozenset({"*"}))
    assert ([("a", "2.0.0"), ("b", "2.0.0")], (("b", "2.0.0"),)) in calls and not out.separate
    assert {p.package: p.forced for p in out.planned} == {"a": None, "b": ("p", "b@1")}


async def test_combined_trial_forces_only_the_window_that_needed_an_override():
    """One package fixed on two major lines, only one of them overridden: the combined trial forces that pin alone,
    as the printed commands will."""
    calls = []
    v5 = Change("update", "semver", "5.7.1", "5.7.2")
    v6 = Change("update", "semver", "6.3.0", "6.3.1")

    async def trial(pins, floats, *, force=(), lowest=None):
        calls.append((sorted(pins), sorted(force)))
        if len(pins) == 2:
            return TrialResult("resolved", (v5, v6))
        if pins == [("semver", "6.3.1")] and not force:
            return TrialResult("blocked", blocker=Blocker("p", "semver@~6.3.0"))
        return TrialResult("resolved", (v5,) if pins == [("semver", "5.7.2")] else (v6,))

    old, new = _item("semver", "5.7.1", "5.7.2"), _item("semver", "6.3.0", "6.3.1")
    out = await _run(FixPlan(planned=[old, new]), trial, can_force=True, pins_every_copy=True)
    assert ([("semver", "5.7.2"), ("semver", "6.3.1")], [("semver", "6.3.1")]) in calls
    assert {p.target: p.forced for p in out.planned} == {"5.7.2": None, "6.3.1": ("p", "semver@~6.3.0")}
    assert not out.separate


def _forced_after_parent_route(parent_exact, forced):
    """A trial whose pin is blocked, whose parent route ends held, then *forced*."""
    blocked = TrialResult("blocked", blocker=Blocker("express", "qs@6.7.0"))
    retry = TrialResult("resolved", (Change("update", "express", "4.17.1", "4.21.2"),))

    async def trial(pins, floats, *, force=()):
        if force:
            return forced
        if floats:
            return retry
        return parent_exact if len(pins) == 2 else blocked
    return trial


async def test_unknown_age_in_the_abandoned_parent_route_does_not_mark_the_forced_fix():
    # The parent route's exact trial adds body-parser of unknown age (checked
    # before the target) and then does not move qs, so it is held.
    parent_exact = TrialResult("resolved", (Change("update", "express", "4.17.1", "4.21.2"),
                                            Change("add", "body-parser", None, "1.0.0")))
    forced = TrialResult("resolved", (Change("update", "qs", "6.7.0", "6.14.0"),))
    trial = _forced_after_parent_route(parent_exact, forced)
    age, _ = _ages({("body-parser", "1.0.0"): None}, default=30.0)
    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, age=age, can_force=True)
    [p] = out.planned
    assert p.forced == ("express", "qs@6.7.0") and p.cooldown_checked


async def test_unknown_age_in_the_forced_trial_marks_the_forced_fix_unchecked():
    parent_exact = TrialResult("resolved", (Change("update", "qs", "6.7.0", "6.14.0"),
                                            Change("update", "debug", "2.0.0", "1.0.0")))
    forced = TrialResult("resolved", (Change("update", "qs", "6.7.0", "6.14.0"),
                                      Change("add", "side-channel", None, "1.0.0")))
    trial = _forced_after_parent_route(parent_exact, forced)
    age, _ = _ages({("side-channel", "1.0.0"): None}, default=30.0)
    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, age=age, can_force=True)
    [p] = out.planned
    assert p.forced == ("express", "qs@6.7.0") and not p.cooldown_checked


async def test_every_copy_adapter_is_told_the_lowest_copy_each_pin_moves():
    calls = []

    async def trial(pins, floats, *, force=(), lowest=None):
        calls.append((sorted(pins), tuple(force), dict(lowest or {})))
        if len(pins) == 2:
            return TrialResult("resolved", (Change("update", "a", "1.0.0", "1.2.0"),
                                            Change("update", "b", "1.1.0", "1.2.0")))
        if pins == [("b", "1.2.0")] and not force:
            return TrialResult("blocked", blocker=Blocker("p", "b@1.1"))
        if floats:
            return TrialResult("blocked", blocker=Blocker("p", "b@1.1"))
        n, v = pins[0]
        return TrialResult("resolved", (Change("update", n, "1.0.0" if n == "a" else "1.1.0", v),))

    a, b = _item("a", "1.0.0", "1.2.0"), _item("b", "1.1.0", "1.2.0")
    out = await _run(FixPlan(planned=[a, b]), trial, can_force=True, pins_every_copy=True)
    assert not out.held and not out.separate
    a_low, b_low = {("a", "1.2.0"): "1.0.0"}, {("b", "1.2.0"): "1.1.0"}
    assert ([("a", "1.2.0")], (), a_low) in calls
    assert ([("b", "1.2.0")], (), b_low) in calls                          # the blocked trial
    assert ([("b", "1.2.0")], (("b", "1.2.0"),), b_low) in calls          # the forced one
    assert ([("a", "1.2.0"), ("b", "1.2.0")], (("b", "1.2.0"),), {**a_low, **b_low}) in calls
    assert all(lowest for _, _, lowest in calls)


async def test_parent_trials_name_only_the_items_lowest_copy():
    blocked = TrialResult("blocked", blocker=Blocker("chalice", "pip<26.2"))
    rescued = TrialResult("resolved", (_UP, Change("update", "chalice", "1.33.0", "1.34.0")))
    seen = []

    async def trial(pins, floats, *, force=(), lowest=None):
        seen.append(dict(lowest or {}))
        return blocked if len(pins) == 1 and not floats else rescued

    out = await _run(FixPlan(planned=[_item()]), trial, pins_every_copy=True)
    assert out.planned and out.planned[0].parent == ("chalice", "1.34.0")
    assert seen == [{("pip", "26.2.0"): "26.1.2"}] * 3


async def test_drift_that_adds_an_advisory_holds_every_fix():
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): TrialResult("resolved", (_UP,))})
    drift = (Change("update", "z", "1.0.0", "1.1.0"),)
    adv = _advisories({("z", "1.1.0"): (frozenset({"GHSA-z"}), False)})
    out = await _run(FixPlan(planned=[_item()]), trial, adv, drift=drift)
    [h] = out.held
    assert h.reason == planner.WOULD_ADD and h.detail.startswith("re-locking the project as it stands would add")
    assert "would would" not in h.detail
    assert out.planned == [] and out.drift == drift


async def test_drift_that_crosses_a_major_only_warns():
    trial, _ = _trials({(frozenset({_PIP}), frozenset()): TrialResult("resolved", (_UP,))})
    drift = (Change("update", "ajv", "6.12.6", "8.20.0"),)
    out = await _run(FixPlan(planned=[_item()]), trial, drift=drift)
    assert [p.package for p in out.planned] == ["pip"] and out.drift == drift


def _router_trial(router_new):
    """@remix-run/router is blocked by react-router-dom; upgrading the parent moves the router to *router_new*."""
    blocked = TrialResult("blocked", blocker=Blocker("react-router-dom", "@remix-run/router@1.9.0"))
    moved = TrialResult("resolved", (Change("update", "react-router-dom", "6.16.0", "6.30.6"),
                                     Change("update", "@remix-run/router", "1.9.0", router_new)))

    async def trial(pins, floats, *, force=(), lowest=None):
        assert not force, "the parent route must win"
        return moved if floats or any(p == "react-router-dom" for p, _ in pins) else blocked

    return trial


_ROUTER = dataclasses.replace(_item("@remix-run/router", "1.9.0", "1.23.3"), advisories=["GHSA-r"])


async def test_a_parent_upgrade_that_overshoots_the_target_on_its_line_is_planned():
    out = await _run(FixPlan(planned=[_ROUTER]), _router_trial("1.23.4"), age=_ages({}, default=30.0)[0],
                     can_force=True, pins_every_copy=True)
    [p] = out.planned
    assert (p.target, p.parent, p.forced) == ("1.23.4", ("react-router-dom", "6.30.6"), None)


async def test_an_overshoot_that_is_still_vulnerable_is_held():
    adv = _advisories({("@remix-run/router", "1.23.4"): (frozenset({"GHSA-r"}), False),
                       ("@remix-run/router", "1.9.0"): (frozenset({"GHSA-r"}), False)})
    out = await _run(FixPlan(planned=[_ROUTER]), _router_trial("1.23.4"), adv, age=_ages({}, default=30.0)[0],
                     pins_every_copy=True)
    [h] = out.held
    assert h.reason == planner.COULD_NOT_VERIFY and "still has GHSA-r" in h.detail


async def test_an_overshoot_inside_the_cooldown_is_held():
    age, _ = _ages({("@remix-run/router", "1.23.4"): 1.0}, default=30.0)
    out = await _run(FixPlan(planned=[_ROUTER]), _router_trial("1.23.4"), age=age, pins_every_copy=True)
    [h] = out.held
    assert h.reason == planner.COOLDOWN and "1.23.4" in h.detail


async def test_an_overshoot_onto_another_major_line_is_not_accepted():
    out = await _run(FixPlan(planned=[_ROUTER]), _router_trial("2.0.0"), age=_ages({}, default=30.0)[0],
                     pins_every_copy=True)
    assert out.planned == [] and out.held[0].reason == planner.COULD_NOT_VERIFY


async def test_with_major_only_a_transitive_major_bump_does_not_hold_the_fix():
    # axios 1.20 needs proxy-from-env ^2: a package the project does not depend on directly.
    up = TrialResult("resolved", (Change("update", "axios", "1.5.1", "1.20.0"),
                                  Change("update", "proxy-from-env", "1.1.0", "2.1.0")))
    trial, _ = _trials({(frozenset({("axios", "1.20.0")}), frozenset()): up})
    item = _item("axios", "1.5.1", "1.20.0")
    held = await _run(FixPlan(planned=[item]), trial)
    assert held.held[0].reason == planner.MAJOR
    out = await _run(FixPlan(planned=[item]), trial, major_only=frozenset({"axios", "react"}))
    assert [p.package for p in out.planned] == ["axios"]


async def test_with_major_only_a_direct_major_bump_still_holds():
    up = TrialResult("resolved", (Change("update", "axios", "1.5.1", "1.20.0"),
                                  Change("update", "react", "17.0.2", "18.2.0")))
    trial, _ = _trials({(frozenset({("axios", "1.20.0")}), frozenset()): up})
    out = await _run(FixPlan(planned=[_item("axios", "1.5.1", "1.20.0")]), trial, major_only=frozenset({"axios", "react"}))
    assert out.held[0].reason == planner.MAJOR and "react" in out.held[0].detail


# --- the ladder: a held item retries with the newest version its dependents allow ---

_SQ = dataclasses.replace(_item("shell-quote", "1.8.1", "1.9.0"), advisories=["GHSA-sq"])


def _ladder_trial(newest="1.9.2"):
    """shell-quote is pinned by react-dev-utils, which cannot move; floating it reaches *newest*."""
    calls = []
    blocked = TrialResult("blocked", blocker=Blocker("react-dev-utils", "shell-quote@^1.7.3"))

    async def trial(pins, floats, *, force=(), lowest=None):
        calls.append((list(pins), list(floats), list(force)))
        if floats == ["shell-quote"] and not pins:
            return TrialResult("resolved", (Change("update", "shell-quote", "1.8.1", newest),))
        if floats:
            return blocked
        [(_pkg, version)] = pins
        if force:
            return TrialResult("resolved", (Change("update", "shell-quote", "1.8.1", version),))
        return blocked
    return trial, calls


_SQ_NEW_CVE = {("shell-quote", "1.9.0"): (frozenset({"GHSA-new"}), False)}


async def test_a_held_target_retries_with_the_newest_version_its_dependents_allow():
    trial, calls = _ladder_trial()
    out = await _run(FixPlan(planned=[_SQ]), trial, _advisories(_SQ_NEW_CVE), age=_ages({}, default=30.0)[0],
                     can_force=True, pins_every_copy=True)
    [p] = out.planned
    assert (p.target, p.forced) == ("1.9.2", ("react-dev-utils", "shell-quote@^1.7.3"))
    assert ([], ["shell-quote"], []) in calls


async def test_the_newest_version_is_held_when_it_is_in_the_cooldown_period():
    trial, _ = _ladder_trial()
    age, _ = _ages({("shell-quote", "1.9.2"): 1.0}, default=30.0)
    out = await _run(FixPlan(planned=[_SQ]), trial, _advisories(_SQ_NEW_CVE), age=age,
                     can_force=True, pins_every_copy=True)
    [h] = out.held
    assert h.reason == planner.WOULD_ADD
    assert "shell-quote 1.9.2 (the newest version its dependents allow): " in h.detail and "1.0 days old" in h.detail


async def test_the_newest_version_is_not_tried_when_it_keeps_the_advisory():
    trial, calls = _ladder_trial()
    adv = _advisories({**_SQ_NEW_CVE, ("shell-quote", "1.9.2"): (frozenset({"GHSA-sq"}), False)})
    out = await _run(FixPlan(planned=[_SQ]), trial, adv, age=_ages({}, default=30.0)[0],
                     can_force=True, pins_every_copy=True)
    [h] = out.held
    assert h.reason == planner.WOULD_ADD and "1.9.2 (the newest version its dependents allow) still has GHSA-sq" in h.detail
    assert not any(p == [("shell-quote", "1.9.2")] for p, _f, _force in calls)


async def test_no_newer_version_on_the_line_keeps_the_original_hold():
    trial, _ = _ladder_trial(newest="1.9.0")
    out = await _run(FixPlan(planned=[_SQ]), trial, _advisories(_SQ_NEW_CVE), age=_ages({}, default=30.0)[0],
                     can_force=True, pins_every_copy=True)
    [h] = out.held
    assert h.reason == planner.WOULD_ADD and "newest" not in h.detail


async def test_an_adapter_that_cannot_force_does_not_climb_the_ladder():
    trial, calls = _ladder_trial()
    out = await _run(FixPlan(planned=[_SQ]), trial, _advisories(_SQ_NEW_CVE), age=_ages({}, default=30.0)[0])
    assert out.planned == [] and ([], ["shell-quote"], []) not in calls


async def test_an_overshoot_ignores_copies_on_another_major_line():
    # A copy on the older 0.x line moves too; it is another item's concern, not this one's overshoot.
    moved = TrialResult("resolved", (Change("update", "react-router-dom", "6.16.0", "6.30.6"),
                                     Change("update", "@remix-run/router", "1.9.0", "1.23.4"),
                                     Change("update", "@remix-run/router", "0.2.0", "0.2.5")))
    blocked = TrialResult("blocked", blocker=Blocker("react-router-dom", "@remix-run/router@1.9.0"))

    async def trial(pins, floats, *, force=(), lowest=None):
        return moved if floats or any(p == "react-router-dom" for p, _ in pins) else blocked

    out = await _run(FixPlan(planned=[_ROUTER]), trial, age=_ages({}, default=30.0)[0], pins_every_copy=True)
    [p] = out.planned
    assert p.target == "1.23.4"


# --- parallel verification ---

def _concurrency_trial():
    """Every item resolves cleanly after a short wait; records the most trials running at once."""
    state = {"now": 0, "most": 0}

    async def trial(pins, floats, *, force=(), lowest=None):
        state["now"] += 1
        state["most"] = max(state["most"], state["now"])
        await asyncio.sleep(0.01)
        state["now"] -= 1
        return TrialResult("resolved", tuple(Change("update", p, "1.0.0", v) for p, v in pins))
    return trial, state


_MANY = [_item(f"p{i}", "1.0.0", "1.1.0") for i in range(6)]


@pytest.mark.parametrize("parallel, most", [(1, 1), (3, 3)])
async def test_items_are_verified_up_to_parallel_at_a_time(parallel, most):
    trial, state = _concurrency_trial()
    out = await _run(FixPlan(planned=list(_MANY)), trial, parallel=parallel)
    assert state["most"] == most
    assert [p.package for p in out.planned] == [f"p{i}" for i in range(6)]   # plan order kept


async def test_parallel_results_keep_plan_order_when_trials_finish_out_of_order():
    async def trial(pins, floats, *, force=(), lowest=None):
        if len(pins) == 1:
            await asyncio.sleep(0.01 * (6 - int(pins[0][0][1:])))   # later items finish first
        if pins[0][0] in ("p1", "p4") and len(pins) == 1:
            return TrialResult("blocked")
        return TrialResult("resolved", tuple(Change("update", p, "1.0.0", v) for p, v in pins))

    out = await _run(FixPlan(planned=list(_MANY)), trial, parallel=6)
    assert [p.package for p in out.planned] == ["p0", "p2", "p3", "p5"]
    assert [h.package for h in out.held] == ["p1", "p4"]


# --- the combined trial: another fix can carry a package past its own target ---

def _carried_trial(helpers_new):
    """core 7.29.6 brings helpers *helpers_new*; alone, each item reaches its own target."""
    async def trial(pins, floats, *, force=(), lowest=None):
        changes = []
        if ("core", "7.29.6") in pins:
            changes.append(Change("update", "core", "7.23.0", "7.29.6"))
            changes.append(Change("update", "helpers", "7.23.1", helpers_new))
        elif ("helpers", "7.26.10") in pins:
            changes.append(Change("update", "helpers", "7.23.1", "7.26.10"))
        return TrialResult("resolved", tuple(changes))
    return trial


_CORE = dataclasses.replace(_item("core", "7.23.0", "7.29.6"), advisories=["GHSA-core"])
_HELPERS = dataclasses.replace(_item("helpers", "7.23.1", "7.26.10"), advisories=["GHSA-h"])


async def test_a_package_carried_past_its_target_by_another_fix_is_combined():
    out = await _run(FixPlan(planned=[_CORE, _HELPERS]), _carried_trial("7.29.10"), pins_every_copy=True)
    assert not out.separate, out.separate_reason
    assert [p.package for p in out.planned] == ["core", "helpers"]


async def test_a_package_carried_to_a_version_that_keeps_its_advisory_is_separate():
    adv = _advisories({("helpers", "7.29.10"): (frozenset({"GHSA-h"}), False),
                       ("helpers", "7.23.1"): (frozenset({"GHSA-h"}), False)})
    out = await _run(FixPlan(planned=[_CORE, _HELPERS]), _carried_trial("7.29.10"), adv, pins_every_copy=True)
    assert out.separate and "helpers" in (out.separate_reason or "")


async def test_a_package_left_short_of_its_target_is_separate_and_named():
    out = await _run(FixPlan(planned=[_CORE, _HELPERS]), _carried_trial("7.24.0"), pins_every_copy=True)
    assert out.separate and out.separate_reason == "the combined trial did not move helpers to 7.26.10"


# --- declined baseline upgrades: not downgrades, but checked for advisories ---

def _declining_trial():
    """webpack moves; ajv stays at the project's 8.12.0 instead of the baseline's 8.20.0."""
    declined = (Change("update", "ajv", "8.20.0", "8.12.0"),)

    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", tuple(Change("update", p, "5.88.2", v) for p, v in pins), declined=declined)
    return trial


_WEBPACK = dataclasses.replace(_item("webpack", "5.88.2", "5.104.1"), advisories=["GHSA-w"])


async def test_declining_a_baseline_upgrade_that_fixes_an_advisory_holds_the_fix():
    adv = _advisories({("ajv", "8.12.0"): (frozenset({"GHSA-ajv"}), False)})
    out = await _run(FixPlan(planned=[_WEBPACK]), _declining_trial(), adv)
    [h] = out.held
    assert h.reason == planner.WOULD_ADD
    assert h.detail == "keeps ajv 8.12.0 (GHSA-ajv), which re-locking alone moves to 8.20.0"


async def test_declining_a_harmless_baseline_upgrade_is_not_a_downgrade():
    out = await _run(FixPlan(planned=[_WEBPACK]), _declining_trial())
    assert [p.package for p in out.planned] == ["webpack"]


async def test_a_version_installed_between_the_lock_and_the_baseline_is_checked_for_cooldown():
    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", (Change("update", "webpack", "5.88.2", "5.104.1"),
                                        Change("update", "ajv", "8.12.0", "8.15.0")),
                           declined=(Change("update", "ajv", "8.20.0", "8.15.0"),))

    age, calls = _ages({("ajv", "8.15.0"): 1.0}, default=30.0)
    out = await _run(FixPlan(planned=[_WEBPACK]), trial, age=age)
    [h] = out.held
    assert h.reason == planner.COOLDOWN and "ajv to 8.15.0 (1.0 days old)" in h.detail
    assert ("ajv", "8.15.0") in calls


# --- a parent's next major release can unblock an item ---

_JSPDF = dataclasses.replace(_item("jspdf", "2.5.2", "4.2.1"), advisories=["GHSA-j"])
_AUTOTABLE_UP = ("5.0.7", "^2 || ^3 || ^4")


def _autotable_trial():
    """jspdf-autotable 3.8.4 peer-depends on jspdf ^2.5.1; only its 5.x accepts jspdf 4, and npm keeps jspdf 2.5.2
    unless jspdf is also forced."""
    calls = []
    blocked = TrialResult("blocked", blocker=Blocker("jspdf-autotable", "jspdf@^2.5.1"))

    async def trial(pins, floats, *, force=(), lowest=None):
        calls.append((sorted(pins), list(floats), list(force)))
        if ("jspdf-autotable", "5.0.7") in pins:
            if "jspdf" not in {n for n, _v in force}:
                return TrialResult("blocked", blocker=Blocker("jspdf-autotable", "jspdf@^2 || ^3 || ^4"))
            return TrialResult("resolved", (Change("update", "jspdf-autotable", "3.8.4", "5.0.7"),
                                            Change("update", "jspdf", "2.5.2", "4.2.1")))
        if not pins:
            return TrialResult("resolved", ())
        return blocked
    return trial, calls


def _upgrade(found):
    seen = []

    async def parent_upgrade(parent, package, target):
        seen.append((parent, package, target))
        return found
    return parent_upgrade, seen


async def test_a_parents_major_release_that_admits_the_target_is_planned_when_allowed():
    trial, _ = _autotable_trial()
    upgrade, seen = _upgrade(_AUTOTABLE_UP)
    out = await _run(FixPlan(planned=[_JSPDF]), trial, can_force=True, pins_every_copy=True,
                     major_only=frozenset({"jspdf-autotable"}), allow_major=frozenset({"jspdf-autotable"}),
                     parent_upgrade=upgrade)
    [p] = out.planned
    assert p.parent == ("jspdf-autotable", "5.0.7")
    assert p.forced == ("jspdf-autotable", "jspdf@^2 || ^3 || ^4")
    assert seen == [("jspdf-autotable", "jspdf", "4.2.1")]


async def test_a_parents_major_release_not_allowed_says_which_to_allow():
    trial, _ = _autotable_trial()
    upgrade, _ = _upgrade(_AUTOTABLE_UP)
    out = await _run(FixPlan(planned=[_JSPDF]), trial, can_force=True, pins_every_copy=True,
                     major_only=frozenset({"jspdf-autotable"}), parent_upgrade=upgrade)
    [h] = out.held
    assert h.reason == planner.MAJOR and h.needs_major == ("jspdf-autotable",)
    assert "jspdf-autotable 5.0.7 declares jspdf@^2 || ^3 || ^4" in h.detail


async def test_without_a_qualifying_parent_release_the_item_stays_blocked():
    trial, _ = _autotable_trial()
    upgrade, _ = _upgrade(None)
    out = await _run(FixPlan(planned=[_JSPDF]), trial, can_force=True, pins_every_copy=True,
                     parent_upgrade=upgrade)
    [h] = out.held
    assert h.reason == planner.BLOCKED and "5.0.7" not in h.detail


async def test_a_failing_parent_upgrade_lookup_keeps_the_original_hold():
    trial, _ = _autotable_trial()

    async def upgrade(parent, package, target):
        raise RuntimeError("registry down")

    out = await _run(FixPlan(planned=[_JSPDF]), trial, can_force=True, pins_every_copy=True, parent_upgrade=upgrade)
    assert out.held[0].reason == planner.BLOCKED


def _two_parent_trial():
    """jspdf is pinned by jspdf-autotable and by react-to-pdf; only both upgraded (and jspdf forced) resolve."""
    async def trial(pins, floats, *, force=(), lowest=None):
        names = {p for p, _ in pins}
        if not pins:
            return TrialResult("resolved", ())
        if "jspdf-autotable" not in names:
            return TrialResult("blocked", blocker=Blocker("jspdf-autotable", "jspdf@^2.5.1"))
        if "react-to-pdf" not in names:
            return TrialResult("blocked", blocker=Blocker("react-to-pdf", "jspdf@^2.5.1"))
        if "jspdf" not in {n for n, _v in force}:
            return TrialResult("blocked", blocker=Blocker("jspdf-autotable", "jspdf@^2 || ^3 || ^4"))
        return TrialResult("resolved", (Change("update", "jspdf-autotable", "3.8.4", "5.0.7"),
                                        Change("update", "react-to-pdf", "1.0.1", "3.0.0"),
                                        Change("update", "jspdf", "2.5.2", "4.2.1")))
    return trial


async def test_every_parent_pinning_the_item_is_upgraded_together():
    releases = {"jspdf-autotable": ("5.0.7", "^2 || ^3 || ^4"), "react-to-pdf": ("3.0.0", "^4.0.0")}

    async def upgrade(parent, package, target):
        return releases.get(parent)

    out = await _run(FixPlan(planned=[_JSPDF]), _two_parent_trial(), can_force=True, pins_every_copy=True,
                     allow_major=frozenset({"*"}), parent_upgrade=upgrade)
    [p] = out.planned
    assert p.all_parents == (("jspdf-autotable", "5.0.7"), ("react-to-pdf", "3.0.0"))


async def test_a_second_parent_without_a_qualifying_release_keeps_the_hold():
    async def upgrade(parent, package, target):
        return ("5.0.7", "^2 || ^3 || ^4") if parent == "jspdf-autotable" else None

    out = await _run(FixPlan(planned=[_JSPDF]), _two_parent_trial(), can_force=True, pins_every_copy=True,
                     allow_major=frozenset({"*"}), parent_upgrade=upgrade)
    [h] = out.held
    assert h.reason == planner.BLOCKED and "react-to-pdf" in h.detail


async def test_two_fixes_needing_one_parent_share_its_highest_release():
    yaml = dataclasses.replace(_item("yaml", "2.3.1", "2.8.3"), advisories=["GHSA-y"],
                               parent=("lint-staged", "15.4.2"), verified=True)
    micromatch = dataclasses.replace(_item("micromatch", "4.0.5", "4.0.8"), advisories=["GHSA-m"],
                                     parent=("lint-staged", "15.2.5"), verified=True)
    from packagealert.remediate.verify import _combined_pins
    assert _combined_pins([yaml, micromatch], "npm") == [("yaml", "2.8.3"), ("micromatch", "4.0.8"),
                                                          ("lint-staged", "15.4.2")]


async def test_a_parent_upgrade_held_for_its_cooldown_reports_the_cooldown():
    trial, _ = _autotable_trial()
    upgrade, _ = _upgrade(_AUTOTABLE_UP)
    age, _ = _ages({("jspdf-autotable", "5.0.7"): 1.0}, default=30.0)
    out = await _run(FixPlan(planned=[_JSPDF]), trial, age=age, can_force=True, pins_every_copy=True,
                     allow_major=frozenset({"*"}), parent_upgrade=upgrade)
    [h] = out.held
    assert h.reason == planner.COOLDOWN and "jspdf-autotable to 5.0.7 (1.0 days old)" in h.detail


async def test_no_parent_upgrade_is_looked_up_for_a_hold_that_is_not_a_pinning_range():
    # The forced pin resolves but adds an advisory: a newer parent would not change that.
    async def trial(pins, floats, *, force=(), lowest=None):
        if force:
            return TrialResult("resolved", (Change("update", "jspdf", "2.5.2", "4.2.1"),
                                            Change("add", "evil", None, "1.0.0")))
        if not pins:
            return TrialResult("resolved", ())
        return TrialResult("blocked", blocker=Blocker("jspdf-autotable", "jspdf@^2.5.1"))

    upgrade, seen = _upgrade(_AUTOTABLE_UP)
    adv = _advisories({("evil", "1.0.0"): (frozenset({"GHSA-e"}), False)})
    out = await _run(FixPlan(planned=[_JSPDF]), trial, adv, can_force=True, pins_every_copy=True,
                     parent_upgrade=upgrade)
    assert out.held[0].reason == planner.WOULD_ADD and seen == []


async def test_parallel_progress_counts_finished_items_and_never_goes_back():
    import re

    trial, _ = _concurrency_trial()
    messages: list[str] = []
    await _run(FixPlan(planned=list(_MANY)), trial, parallel=3, progress=messages.append)
    counts = [int(m.group(1)) for x in messages if (m := re.match(r"Verifying fixes: (\d+) of 6 done", x))]
    assert counts and counts == sorted(counts) and counts[-1] >= 3


# --- lock drift is judged per trial: a fix that moves off a bad drift version is not held for it ---

def _drift_trial():
    """pkg is re-locked to 1.1.0 (yanked); pinning pkg 1.2.0 moves it off, pinning pip does not."""
    calls = []

    async def trial(pins, floats, *, force=(), lowest=None):
        calls.append(sorted(pins))
        changes = []
        if ("pkg", "1.2.0") in pins:
            changes.append(Change("update", "pkg", "1.1.0", "1.2.0"))
        if _PIP in pins:
            changes.append(_UP)
        return TrialResult("resolved", tuple(changes))
    return trial, calls


_PKG = dataclasses.replace(_item("pkg", "1.0.0", "1.2.0"), advisories=["GHSA-p"])
_DRIFT = (Change("update", "pkg", "1.0.0", "1.1.0"),)


async def test_a_fix_that_replaces_a_yanked_drift_version_is_planned():
    trial, calls = _drift_trial()
    out = await _run(FixPlan(planned=[_PKG, _item()]), trial, drift=_DRIFT,
                     drift_yanked=(Yank("pkg", "1.1.0", "bad release"),))
    assert [p.package for p in out.planned] == ["pkg"]
    [h] = out.held
    assert h.package == "pip" and h.reason == planner.YANKED
    assert h.detail.startswith("re-locking the project as it stands would install a yanked version")
    assert calls  # judged on its trial, not before it


async def test_a_fix_that_replaces_a_downgraded_drift_version_is_planned():
    trial, _ = _drift_trial()
    drift = (Change("update", "pkg", "1.0.0", "0.9.0"),)

    async def moves_off(pins, floats, *, force=(), lowest=None):
        result = await trial(pins, floats)
        if ("pkg", "1.2.0") in pins:
            return TrialResult("resolved", (Change("update", "pkg", "0.9.0", "1.2.0"),))
        return result

    out = await _run(FixPlan(planned=[_PKG, _item()]), moves_off, drift=drift)
    assert [p.package for p in out.planned] == ["pkg"]
    assert out.held[0].package == "pip" and out.held[0].reason == planner.WOULD_DOWNGRADE


async def test_moving_one_copy_off_a_yanked_drift_version_is_not_enough_when_another_keeps_it():
    async def trial(pins, floats, *, force=(), lowest=None):
        # One copy moves 1.1.0 -> 1.2.0; another copy stays on 1.1.0, so both are still locked.
        return TrialResult("resolved", (Change("update", "pkg", "1.1.0", "1.2.0", ("1.1.0", "1.2.0")),))

    out = await _run(FixPlan(planned=[_PKG]), trial, drift=_DRIFT, drift_yanked=(Yank("pkg", "1.1.0", "bad"),),
                     pins_every_copy=True)
    [h] = out.held
    assert h.reason == planner.YANKED and "pkg 1.1.0" in h.detail


async def test_declining_a_yanked_drift_upgrade_avoids_it():
    # The re-lock moves pkg 1.0.0 -> 1.1.0 (yanked); the trial keeps the project's 1.0.0, a declined upgrade.
    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", (_UP,), declined=(Change("update", "pkg", "1.1.0", "1.0.0"),))

    out = await _run(FixPlan(planned=[_item()]), trial, drift=_DRIFT, drift_yanked=(Yank("pkg", "1.1.0", "bad"),))
    assert [p.package for p in out.planned] == ["pip"] and out.held == []


async def test_declining_a_yanked_drift_upgrade_for_only_one_copy_does_not_avoid_it():
    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", (_UP,),
                           declined=(Change("update", "pkg", "1.1.0", "1.0.0", ("1.0.0", "1.1.0")),))

    out = await _run(FixPlan(planned=[_item()]), trial, drift=_DRIFT, drift_yanked=(Yank("pkg", "1.1.0", "bad"),))
    assert out.held[0].reason == planner.YANKED


# --- moving off a bad drift version is judged against the project's own version ---

def _downgrade_drift_trial(lands_on):
    """The re-lock downgrades q 1.4.0 -> 1.2.0; the fix's trial moves q off 1.2.0 to *lands_on*."""
    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", (_UP, Change("update", "q", "1.2.0", lands_on)))
    return trial


_Q_DRIFT = (Change("update", "q", "1.4.0", "1.2.0"),)


async def test_moving_off_a_drift_downgrade_to_a_version_still_below_the_project_is_held():
    out = await _run(FixPlan(planned=[_item()]), _downgrade_drift_trial("1.3.0"), drift=_Q_DRIFT)
    [h] = out.held
    assert h.reason == planner.WOULD_DOWNGRADE and "q 1.4.0 → 1.3.0" in h.detail


async def test_moving_off_a_drift_downgrade_back_to_the_projects_version_is_planned():
    out = await _run(FixPlan(planned=[_item()]), _downgrade_drift_trial("1.4.0"), drift=_Q_DRIFT)
    assert [p.package for p in out.planned] == ["pip"] and out.held == []


async def test_moving_off_a_yanked_drift_version_onto_another_yanked_one_is_held():
    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", (_UP, Change("update", "pkg", "1.1.0", "1.1.1")),
                           yanked=(Yank("pkg", "1.1.1", "also bad"),))

    out = await _run(FixPlan(planned=[_item()]), trial, drift=_DRIFT, drift_yanked=(Yank("pkg", "1.1.0", "bad"),))
    assert out.held[0].reason == planner.YANKED and "pkg 1.1.1" in out.held[0].detail


def test_a_parent_upgrade_supersedes_a_lower_pin_of_the_same_package():
    # postcss is fixed directly at 8.5.23, while nanoid's fix needs postcss 8.5.29 as its parent.
    from packagealert.remediate.verify import _combined_pins

    postcss = dataclasses.replace(_item("postcss", "8.5.14", "8.5.23"), direct=True, verified=True)
    nanoid = dataclasses.replace(_item("nanoid", "3.3.12", "3.3.20"), parent=("postcss", "8.5.29"), verified=True)
    assert _combined_pins([postcss, nanoid], "npm") == [("postcss", "8.5.29"), ("nanoid", "3.3.20")]


def test_pins_of_one_package_on_different_major_lines_are_both_kept():
    from packagealert.remediate.verify import _combined_pins

    five = _item("semver", "5.7.1", "5.7.2")
    seven = dataclasses.replace(_item("x", "1.0.0", "1.1.0"), parent=("semver", "7.5.2"))
    assert _combined_pins([five, seven], "npm") == [("semver", "5.7.2"), ("x", "1.1.0"), ("semver", "7.5.2")]


async def test_a_copy_the_combined_trial_leaves_behind_is_overridden_too():
    # Alone, autoprefixer 10.6.1 moved every browserslist copy; together with another fix npm nests it instead.
    browserslist = dataclasses.replace(_item("browserslist", "4.28.2", "4.29.3"), parent=("autoprefixer", "10.6.1"))
    other = _item("dompurify", "3.4.15", "3.4.16")
    forced_calls = []

    async def trial(pins, floats, *, force=(), lowest=None):
        if {"browserslist", "dompurify"} <= {p for p, _ in pins}:          # the combined trial
            forced_calls.append(sorted(force))
            if "browserslist" not in {n for n, _v in force}:
                return TrialResult("blocked", blocker=Blocker("autoprefixer", "browserslist@^4.28.9"),
                                   detail="browserslist 4.28.2 stays under autoprefixer")
        return TrialResult("resolved", tuple(Change("update", p, "1.0.0" if p == "autoprefixer" else
                                                    {"browserslist": "4.28.2", "dompurify": "3.4.15"}[p], v)
                                             for p, v in pins))

    out = await _run(FixPlan(planned=[browserslist, other]), trial, can_force=True, pins_every_copy=True)
    assert not out.separate, out.separate_reason
    b = next(p for p in out.planned if p.package == "browserslist")
    assert b.forced == ("autoprefixer", "browserslist@^4.28.9")
    assert forced_calls == [[], [("browserslist", "4.29.3")]]


# --- an explicitly pinned parent is always major-checked, even where only direct majors are ---

def _transitive_parent_trial():
    """q is pinned by the transitive p 3.8.4; only p 5.0.7 (a new major) admits q's fix."""
    async def trial(pins, floats, *, force=(), lowest=None):
        if ("p", "5.0.7") in pins and "q" in {n for n, _v in force}:
            return TrialResult("resolved", (Change("update", "p", "3.8.4", "5.0.7"),
                                            Change("update", "q", "1.0.0", "1.2.0")))
        if not pins:
            return TrialResult("resolved", ())
        return TrialResult("blocked", blocker=Blocker("p", "q@1.0.0"))
    return trial


async def _parent_upgrade_p(parent, package, target):
    return ("5.0.7", "^1.2.0") if parent == "p" else None


_Q = dataclasses.replace(_item("q", "1.0.0", "1.2.0"), advisories=["GHSA-q"])


async def test_a_transitive_parents_new_major_is_held_without_allow_major():
    out = await _run(FixPlan(planned=[_Q]), _transitive_parent_trial(), can_force=True, pins_every_copy=True,
                     major_only=frozenset({"scripts"}), parent_upgrade=_parent_upgrade_p)
    [h] = out.held
    assert h.reason == planner.MAJOR and h.needs_major == ("p",)


async def test_a_transitive_parents_new_major_is_planned_when_allowed():
    out = await _run(FixPlan(planned=[_Q]), _transitive_parent_trial(), can_force=True, pins_every_copy=True,
                     major_only=frozenset({"scripts"}), allow_major=frozenset({"p"}),
                     parent_upgrade=_parent_upgrade_p)
    [p] = out.planned
    assert p.parent == ("p", "5.0.7")


# --- a fix the plain re-lock already makes ---

_DRIFT_QS = Change("update", "qs", "6.7.0", "6.14.0")


async def test_an_item_the_re_lock_already_fixes_is_planned():
    """The baseline moves qs to the target, so the trial (judged against it) shows no change for qs."""
    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", ())

    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, drift=(_DRIFT_QS,),
                     pins_every_copy=True)
    assert [p.package for p in out.planned] == ["qs"] and out.held == []
    assert out.planned[0].by_relock


async def test_a_trial_that_moves_the_re_locked_target_elsewhere_is_not_taken_as_fixed():
    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", (Change("update", "qs", "6.14.0", "6.13.0"),))

    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, drift=(_DRIFT_QS,),
                     pins_every_copy=True)
    assert out.planned == []


async def test_without_the_drift_an_unmoved_target_is_still_held():
    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", ())

    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0")]), trial, pins_every_copy=True)
    assert out.planned == [] and out.held[0].reason == planner.COULD_NOT_VERIFY


async def test_a_re_lock_fixed_item_combines_with_the_other_fixes():
    other = Change("update", "a", "1.0.0", "1.1.0")

    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", (other,) if ("a", "1.1.0") in pins else ())

    out = await _run(FixPlan(planned=[_item("qs", "6.7.0", "6.14.0"), _item("a", "1.0.0", "1.1.0")]), trial,
                     drift=(_DRIFT_QS,), pins_every_copy=True)
    assert sorted(p.package for p in out.planned) == ["a", "qs"] and not out.separate, out.separate_reason
    assert {p.package: p.by_relock for p in out.planned} == {"a": False, "qs": True}


@pytest.mark.parametrize(("age_days", "held"), [(1.0, True), (30.0, False)])
async def test_a_target_the_re_lock_reaches_is_age_checked_when_the_planner_did_not(age_days, held):
    import dataclasses

    async def trial(pins, floats, *, force=(), lowest=None):
        return TrialResult("resolved", ())

    age, calls = _ages({("qs", "6.14.0"): age_days})
    item = dataclasses.replace(_item("qs", "6.7.0", "6.14.0"), cooldown_checked=False)
    out = await _run(FixPlan(planned=[item]), trial, drift=(_DRIFT_QS,), pins_every_copy=True, age=age)
    assert ("qs", "6.14.0") in calls
    assert [h.reason for h in out.held] == ([planner.COOLDOWN] if held else [])
    if not held:
        assert out.planned[0].cooldown_checked is True
