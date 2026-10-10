"""Verify planned pins by trial resolution before they are printed.

Manager-independent: the trial, advisory lookup and age lookup are injected,
so a manager adapter supplies only how to run one trial.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Protocol

from packagealert.models.events import normalise_package_name_for
from packagealert.osv.remediation import _key_for, _major_for
from packagealert.remediate import planner
from packagealert.remediate.adapter import Blocker, Change, TrialResult, Yank
from packagealert.remediate.planner import FixPlan, HeldFix, PlannedFix


class TrialFn(Protocol):
    async def __call__(
        self, pins: list[tuple[str, str]], floats: list[str], *, force: Sequence[tuple[str, str]] = (),
        lowest: Mapping[tuple[str, str], str] | None = None,
    ) -> TrialResult: ...
AdvisoryFn = Callable[
    [list[tuple[str, str]]], Awaitable[dict[tuple[str, str], tuple[frozenset[str], bool]]]
]
AgeFn = Callable[[str, str], Awaitable[float | None]]
# (parent, package, target) -> the lowest release of parent above its locked
# version whose declared range admits package at target, with that range; or None.
ParentUpgradeFn = Callable[[str, str, str], Awaitable["tuple[str, str] | None"]]

log = logging.getLogger(__name__)

# Each age lookup may open a database connection and an HTTP request; a
# resolver change set can introduce hundreds of versions at once.
_AGE_CONCURRENCY = 10


def _same_version(ecosystem: str, a: str | None, b: str | None) -> bool:
    if a is None or b is None:
        return a == b
    key = _key_for(ecosystem)
    ka, kb = key(a), key(b)
    return a == b if ka is None or kb is None else ka == kb


def _held(item: PlannedFix, reason: str, detail: str, needs_major: tuple[str, ...] = ()) -> HeldFix:
    return HeldFix(package=item.package, version=item.version, target=item.target,
                   reason=reason, advisories=list(item.advisories), detail=detail,
                   needs_major=needs_major)


def _name(ecosystem: str, package: str) -> str:
    return normalise_package_name_for(ecosystem, package)


def _crosses_major(ecosystem: str, old: str, new: str) -> bool:
    """True when *new* is on a higher major version; False when either cannot be read."""
    key = _key_for(ecosystem)
    old_k, new_k = key(old), key(new)
    if old_k is None or new_k is None:
        return False
    old_major, new_major = _major_for(ecosystem, old_k), _major_for(ecosystem, new_k)
    return old_major is not None and new_major is not None and old_major != new_major and new_k > old_k


def _major_bumps(
    changes: tuple[Change, ...], allow_major: frozenset[str], exempt: frozenset[str], ecosystem: str,
    only: frozenset[str] | None = None,
) -> list[Change]:
    """Updates that cross a major version for a package that is neither allowed nor exempt.

    *exempt* holds the packages the plan itself targets: the planner has
    already applied the major policy to them. Unreadable versions are left to
    ``_downgrades``. With *only*, a bump counts only for those packages (an
    adapter whose resolver keeps every transitive move inside the declared
    ranges passes the project's direct dependencies, so only those hold).
    """
    if "*" in allow_major:
        return []
    out = []
    for c in changes:
        if c.action != "update" or c.old is None or c.new is None:
            continue
        name = _name(ecosystem, c.package)
        if name in allow_major or name in exempt:
            continue
        if only is not None and name not in {_name(ecosystem, n) for n in only}:
            continue
        if _crosses_major(ecosystem, c.old, c.new):
            out.append(c)
    return out


def _major_hold(
    item: PlannedFix, changes: tuple[Change, ...], allow_major: frozenset[str], prefix: str = "",
    *, ecosystem: str, only: frozenset[str] | None = None,
) -> HeldFix | None:
    bumps = _major_bumps(changes, allow_major, frozenset({_name(ecosystem, item.package)}), ecosystem, only)
    if not bumps:
        return None
    detail = "; ".join(f"would also upgrade {c.package} {c.old} → {c.new} (major)" for c in bumps)
    return _held(item, planner.MAJOR, f"{prefix}{detail}", tuple(dict.fromkeys(c.package for c in bumps)))


def _downgrades(changes: tuple[Change, ...], ecosystem: str) -> list[Change]:
    key = _key_for(ecosystem)
    out = []
    for c in changes:
        if c.action != "update" or c.old is None or c.new is None:
            continue
        old_k, new_k = key(c.old), key(c.new)
        if old_k is None or new_k is None or new_k < old_k:
            out.append(c)
    return out


def _introduced_yanks(changes: tuple[Change, ...], yanked: tuple[Yank, ...], ecosystem: str) -> list[Yank]:
    """The yanked versions that *changes* install (rather than ones already locked)."""
    return [
        y for y in yanked
        if any(c.new is not None and _name(ecosystem, c.package) == _name(ecosystem, y.package)
               and _same_version(ecosystem, c.new, y.version) for c in changes)
    ]


async def _side_effects(
    changes: tuple[Change, ...], ecosystem: str, advisories: AdvisoryFn, *, yanked: tuple[Yank, ...] = (),
    declined: tuple[Change, ...] = (), drift_problem: tuple[str, str] | None = None,
) -> tuple[str, str] | None:
    """(reason, detail) if *changes* make anything worse, else None.

    *drift_problem* is the hold for lock drift the trial leaves in place
    (``TrialResult.drift_problem``), reported before anything else.

    *declined* are the baseline's upgrades the trial does not take
    (``TrialResult.declined``): only an advisory the kept version has and the
    baseline's version does not counts against them.
    """
    if drift_problem is not None:
        return drift_problem
    if hits := _introduced_yanks(changes, yanked, ecosystem):
        return planner.YANKED, "; ".join(
            f"would install {y.package} {y.version}, which is yanked" + (f" ({y.reason})" if y.reason else "")
            for y in hits)
    if down := _downgrades(changes, ecosystem):
        return planner.WOULD_DOWNGRADE, ", ".join(f"{c.package} {c.old} → {c.new}" for c in down)
    kept = [c for c in declined if c.old is not None and c.new is not None]
    new_versions = [(c.package, c.new) for c in (*changes, *kept) if c.new is not None]
    old_versions = [(c.package, c.old) for c in (*changes, *kept) if c.action == "update" and c.old is not None]
    if not new_versions:
        return None
    found = await advisories(list(dict.fromkeys(new_versions + old_versions)))
    added: list[str] = []
    for c in changes:
        if c.new is None:
            continue
        ids, degraded = found.get((c.package, c.new), (frozenset(), True))
        if degraded:
            return planner.COULD_NOT_VERIFY, f"advisory lookup unavailable for {c.package} {c.new}"
        before = found.get((c.package, c.old), (frozenset(), False))[0] if c.old else frozenset()
        if fresh := sorted(ids - before):
            added.append(f"{c.package} {c.new} ({', '.join(fresh)})")
    if added:
        return planner.WOULD_ADD, "; ".join(added)
    for c in kept:
        kept_version, baseline_version = c.new or "", c.old or ""
        ids, degraded = found.get((c.package, kept_version), (frozenset(), True))
        if degraded:
            return planner.COULD_NOT_VERIFY, f"advisory lookup unavailable for {c.package} {kept_version}"
        if fresh := sorted(ids - found.get((c.package, baseline_version), (frozenset(), False))[0]):
            added.append(f"keeps {c.package} {kept_version} ({', '.join(fresh)}), "
                         f"which re-locking alone moves to {baseline_version}")
    if added:
        return planner.WOULD_ADD, "; ".join(added)
    return None


def _moves_target(item: PlannedFix, changes: tuple[Change, ...], ecosystem: str,
                  drift: Sequence[Change] = ()) -> bool:
    """Whether a trial's *changes* leave *item*'s package at its target.

    Either the trial moves it there, or re-locking alone already does (*drift*,
    the baseline's changes) and the trial, judged against that baseline, leaves
    the package where the re-lock put it: every printed command re-locks too.
    """
    if any(c.action in ("update", "add") and c.package == item.package
           and _same_version(ecosystem, c.new, item.target) for c in changes):
        return True
    return bool(_relock_change(item, changes, ecosystem, drift))


def _relock_change(item: PlannedFix, changes: tuple[Change, ...], ecosystem: str,
                   drift: Sequence[Change]) -> tuple[Change, ...]:
    """The drift change that moves *item*'s package to its target, when the trial leaves the package alone.

    That change is what installs the target for this fix, so its age is
    checked with the trial's own changes.
    """
    own = _name(ecosystem, item.package)
    if any(_name(ecosystem, c.package) == own for c in changes):
        return ()
    return tuple(c for c in drift if c.action in ("update", "add") and _name(ecosystem, c.package) == own
                 and _same_version(ecosystem, c.new, item.target))[:1]


def _split_target(item: PlannedFix, changes: tuple[Change, ...], ecosystem: str) -> Change | None:
    """A change that leaves *item*'s package locked at several versions (a marker fork)."""
    own = _name(ecosystem, item.package)
    return next((c for c in changes if c.fork_versions and _name(ecosystem, c.package) == own), None)


def _split_hold(item: PlannedFix, split: Change, prefix: str = "") -> HeldFix:
    return _held(item, planner.MULTIPLE_VERSIONS,
                 f"{prefix}the trial locks {split.package} at several versions ({', '.join(split.fork_versions)})")


def _extra_changes(item: PlannedFix, changes: tuple[Change, ...], ecosystem: str) -> tuple[Change, ...]:
    return tuple(
        c for c in changes
        if not (c.package == item.package and _same_version(ecosystem, c.new, item.target))
    )


async def _cooldown_check(
    changes: tuple[Change, ...], exempt: Callable[[Change], bool], *, age: AgeFn, cache: dict,
    cooldown_days: int, allow_cooldown: bool,
) -> tuple[str, bool]:
    """(detail of too-young new versions, whether any age was unknown) for *changes*.

    Every ``add`` and ``update`` introduces a version that must have cleared
    the cooldown period, except changes *exempt* (the planned targets, whose
    age the planner already checked). Removals introduce nothing.
    """
    new = [(c, c.new) for c in changes if c.action in ("update", "add") and c.new is not None and not exempt(c)]
    fresh = list(dict.fromkeys((c.package, ver) for c, ver in new if (c.package, ver) not in cache))
    sem = asyncio.Semaphore(_AGE_CONCURRENCY)

    async def bounded(pkg: str, ver: str) -> float | None:
        async with sem:
            return await age(pkg, ver)

    ages = await asyncio.gather(*(bounded(pkg, ver) for pkg, ver in fresh))
    cache.update(zip(fresh, ages, strict=True))
    young: list[str] = []
    unknown = False
    for c, ver in new:
        days = cache[(c.package, ver)]
        if days is None:
            unknown = True
        elif days < cooldown_days and not allow_cooldown:
            verb = "add" if c.action == "add" else "upgrade"
            to = " " if c.action == "add" else " to "
            young.append(f"would {verb} {c.package}{to}{ver} ({days:.1f} days old)")
    return "; ".join(young), unknown


def _overshoot(item: PlannedFix, changes: tuple[Change, ...], ecosystem: str) -> str | None:
    """The version a parent upgrade moved *item*'s package to, when that is above the target on its major line.

    Every version the change installs for the package on the target's major
    line must be at or above the target; the lowest is returned. Versions on
    other lines belong to other items (a package is planned once per line).
    None otherwise (including when the package did not move on the line).
    """
    key = _key_for(ecosystem)
    own = _name(ecosystem, item.package)
    target = key(item.target)
    if target is None:
        return None
    keys = [(key(c.new), c.new) for c in changes
            if _name(ecosystem, c.package) == own and c.action in ("update", "add") and c.new
            and not _crosses_major(ecosystem, item.target, c.new) and not _crosses_major(ecosystem, c.new, item.target)]
    if not keys or any(k is None or k < target for k, _v in keys):
        return None
    return min(keys)[1]


def _lowest(item: PlannedFix) -> dict[tuple[str, str], str]:
    """The lowest vulnerable locked copy *item*'s pin is meant to move, keyed by (package, target)."""
    return {(item.package, item.target): item.version}


def _verified(
    item: PlannedFix, changes: tuple[Change, ...], ecosystem: str, parent: tuple[str, str] | None,
    cooldown_checked: bool,
) -> PlannedFix:
    return dataclasses.replace(
        item, verified=True, changes=_extra_changes(item, changes, ecosystem), parent=parent,
        cooldown_checked=cooldown_checked,
    )


async def _forced(
    item: PlannedFix, why: str, blocker: Blocker, *, trial: TrialFn, ecosystem: str, advisories: AdvisoryFn,
    allow_major: frozenset[str], too_young: Callable[[tuple[Change, ...], str], Awaitable[HeldFix | None]],
    major_only: frozenset[str] | None = None,
    cooldown_checked: Callable[[], bool], drift: Sequence[Change] = (),
) -> PlannedFix | HeldFix:
    """Trial *item* forced past *blocker*'s declared range, applying every check to that trial."""
    context = f"{why}; forcing {item.package} {item.target}: "
    pin = (item.package, item.target)
    result = await trial([pin], [], force=[pin], lowest=_lowest(item))
    if result.status != "resolved":
        return _held(item, planner.BLOCKED if result.status == "blocked" else planner.COULD_NOT_VERIFY,
                     f"{context}{result.detail or 'the forced trial did not resolve'}")
    if bad := await _side_effects(result.changes, ecosystem, advisories, yanked=result.yanked,
                                    declined=result.declined, drift_problem=result.drift_problem):
        return _held(item, bad[0], f"{context}{bad[1]}")
    if major := _major_hold(item, result.changes, allow_major, context, ecosystem=ecosystem, only=major_only):
        return major
    if young := await too_young((*result.changes, *_relock_change(item, result.changes, ecosystem, drift)), context):
        return young
    if not _moves_target(item, result.changes, ecosystem, drift):
        return _held(item, planner.COULD_NOT_VERIFY, f"{context}the forced trial did not move it")
    return dataclasses.replace(_verified(item, result.changes, ecosystem, None, cooldown_checked()),
                               forced=(blocker.parent, blocker.constraint))


async def _parent_route(
    item: PlannedFix, why: str, blocker: Blocker, *, trial: TrialFn, ecosystem: str, advisories: AdvisoryFn,
    allow_major: frozenset[str], too_young: Callable[..., Awaitable[HeldFix | None]],
    major_only: frozenset[str] | None = None,
    cooldown_checked: Callable[[], bool], pins_every_copy: bool, say: Callable[[str], None],
) -> PlannedFix | HeldFix:
    """Fix *item* by also pinning the version of *blocker*'s parent that lets it move.

    The parent may move the package past its target (``_overshoot``); the
    planned fix then records the version the parent actually brings.
    """
    pins = [(item.package, item.target)]
    say(f"{item.package} is blocked by {blocker.parent}; retrying with {blocker.parent} free to move")
    retry = await trial(pins, [blocker.parent], lowest=_lowest(item))
    if retry.status == "blocked":
        return _held(item, planner.BLOCKED, why)
    if retry.status != "resolved":
        # Only an inconclusive retry gets here: it says nothing about
        # whether moving the parent would work, so it is not "blocked".
        return _held(item, planner.COULD_NOT_VERIFY,
                     f"{why}; letting {blocker.parent} move: {retry.detail or 'trial was not conclusive'}")
    # The retry only finds the parent version to pin. What it changes besides
    # can differ from the exact trial, which is the printed command, so only
    # the exact trial is judged.
    moved = next((c for c in retry.changes if c.package == blocker.parent and c.new), None)
    if moved is None or moved.new is None:
        return _held(item, planner.BLOCKED, why)
    parent = (blocker.parent, moved.new)
    say(f"confirming {item.package} {item.target} with {parent[0]} {parent[1]}")
    exact = await trial([*pins, parent], [], lowest=_lowest(item))
    if exact.status != "resolved":
        return _held(item, planner.COULD_NOT_VERIFY,
                     f"{why}; pinning {parent[0]} {parent[1]} exactly did not resolve cleanly")
    return await _judge_parent(item, why, f"{why}; pinning {parent[0]} {parent[1]}: ", exact, parent,
                               ecosystem=ecosystem, advisories=advisories, allow_major=allow_major,
                               too_young=too_young, major_only=major_only, cooldown_checked=cooldown_checked,
                               pins_every_copy=pins_every_copy)


async def _judge_parent(
    item: PlannedFix, why: str, context: str, exact: TrialResult, parent: tuple[str, str], *, ecosystem: str,
    advisories: AdvisoryFn, allow_major: frozenset[str], too_young: Callable[..., Awaitable[HeldFix | None]],
    major_only: frozenset[str] | None, cooldown_checked: Callable[[], bool], pins_every_copy: bool,
    also_pinned: Sequence[str] = (), drift: Sequence[Change] = (),
) -> PlannedFix | HeldFix:
    """Apply every check to *exact*, a resolved trial pinning *item* together with *parent*.

    The pinned parents (*parent*, and *also_pinned*) are always major-checked,
    even where *major_only* limits the check to direct dependencies: they are
    upgrades the fix chooses, not side effects of resolution.

    The parent may move the package past its target (``_overshoot``); the
    planned fix then records the version the parent actually brings.
    """
    if bad := await _side_effects(exact.changes, ecosystem, advisories, yanked=exact.yanked,
                                    declined=exact.declined, drift_problem=exact.drift_problem):
        return _held(item, bad[0], f"{context}{bad[1]}")
    only = None if major_only is None else major_only | {parent[0], *also_pinned}
    if major := _major_hold(item, exact.changes, allow_major, context, ecosystem=ecosystem, only=only):
        return major
    if young := await too_young((*exact.changes, *_relock_change(item, exact.changes, ecosystem, drift)), context):
        return young
    if not pins_every_copy and (split := _split_target(item, exact.changes, ecosystem)):
        return _split_hold(item, split, context)
    if not _moves_target(item, exact.changes, ecosystem, drift):
        # The parent may bring a newer release of the package than the target:
        # acceptable when it is on the target's major line, fixes the item's
        # advisories, and is itself out of the cooldown period.
        over = _overshoot(item, exact.changes, ecosystem)
        if over is None:
            return _held(item, planner.COULD_NOT_VERIFY,
                         f"{why}; pinning {parent[0]} {parent[1]} exactly did not resolve cleanly")
        found = await advisories([(item.package, over)])
        ids, degraded = found.get((item.package, over), (frozenset(), True))
        if degraded:
            return _held(item, planner.COULD_NOT_VERIFY,
                         f"{context}advisory lookup unavailable for {item.package} {over}")
        if still := sorted(ids & (set(item.advisories) - set(item.left_open))):
            return _held(item, planner.COULD_NOT_VERIFY,
                         f"{context}it moves {item.package} to {over}, which still has {', '.join(still)}")
        own = _name(ecosystem, item.package)
        if young := await too_young(tuple(c for c in exact.changes if _name(ecosystem, c.package) == own),
                                    context, own_too=True):
            return young
        item = dataclasses.replace(item, target=over)
    # The exact trial has passed every check above; checking it again would
    # only repeat the OSV lookup.
    return _verified(item, exact.changes, ecosystem, parent, cooldown_checked())


# The most packages pinning one item that a fix upgrades together.
_MAX_PARENT_UPGRADES = 3


async def _parent_upgrade_route(
    item: PlannedFix, why: str, blocker: Blocker, held: HeldFix, *, parent_upgrade: ParentUpgradeFn,
    trial: TrialFn, can_force: bool, say: Callable[[str], None],
    judge: Callable[[PlannedFix, str, str, TrialResult, tuple[str, str], list[str]],
                    Awaitable[PlannedFix | HeldFix]],
) -> PlannedFix | HeldFix:
    """Retry a *held* item with a release of *blocker*'s parent beyond its declared range that admits the target.

    The parent is pinned at the lowest such release (``parent_upgrade``), and
    so is each further package the trial is then blocked by (up to
    ``_MAX_PARENT_UPGRADES``). When *can_force*, the item is also forced
    (which the new ranges admit): the package manager may otherwise keep its
    old version, which can still satisfy them. Once the parents resolve, the
    trial's own hold is returned (a new major release of a parent, held
    unless allowed and naming it for ``--allow-major``; a version in its
    cooldown); before that, *held* stands with what the lookup ran into appended.
    """
    parents: list[tuple[str, str]] = []
    labels: list[str] = []
    pinner = blocker.parent
    forced: tuple[str, str] | None = None
    exact: TrialResult | None = None
    uses_force = False
    # Several packages can pin the item (jspdf under jspdf-autotable and
    # react-to-pdf): each one the trial is still blocked by gets its own release.
    for _ in range(_MAX_PARENT_UPGRADES):
        try:
            found = await parent_upgrade(pinner, item.package, item.target)
        except Exception:
            log.warning("Looking up a release of %s for %s failed", pinner, item.package, exc_info=True)
            found = None
        if not (isinstance(found, tuple) and len(found) == 2 and all(isinstance(x, str) for x in found)):
            if not parents:
                return held
            return dataclasses.replace(held, detail=f"{held.detail}; {'; '.join(labels)}; but {pinner} also "
                                                    f"pins it, and no release of {pinner} admits {item.package} "
                                                    f"{item.target}")
        version, spec = found
        parents.append((pinner, version))
        labels.append(f"{pinner} {version} declares {item.package}@{spec}")
        if forced is None:
            forced = (pinner, f"{item.package}@{spec}")
        pins = [(item.package, item.target), *parents]
        say(f"retrying {item.package} {item.target} with " + ", ".join(f"{n} {v}" for n, v in parents))
        # Overridden whenever the adapter can: npm moves a copy no package asks
        # it to move only as a side effect of the parent's exact release, which
        # a combined command can change (two fixes needing the same parent).
        uses_force = can_force
        exact = await trial(pins, [], force=[(item.package, item.target)] if can_force else (),
                            lowest=_lowest(item))
        nxt = exact.blocker.parent if exact.status == "blocked" and exact.blocker else None
        if nxt is None or nxt in {n for n, _v in parents}:
            break
        pinner = nxt
    assert exact is not None
    label = "; ".join(labels)
    if exact.status != "resolved":
        return dataclasses.replace(
            held, detail=f"{held.detail}; {label}, but pinning it: {exact.detail or 'the trial was not conclusive'}")
    pinned = ", ".join(f"{n} {v}" for n, v in parents)
    out = await judge(item, why, f"{why}; {label}; pinning {pinned}: ", exact, parents[0],
                      [n for n, _v in parents])
    if isinstance(out, PlannedFix):
        return dataclasses.replace(out, more_parents=tuple(parents[1:]), forced=forced if uses_force else None)
    # The upgraded parents resolve; what holds the fix now (a major version
    # to allow, a version in its cooldown) is the useful reason to report.
    return out


async def _verify_one(
    item: PlannedFix, *, ecosystem: str, trial: TrialFn, advisories: AdvisoryFn,
    age: AgeFn, cooldown_days: int, allow_cooldown: bool, allow_major: frozenset[str],
    say: Callable[[str], None] = lambda _message: None, can_force: bool = False, pins_every_copy: bool = False,
    major_only: frozenset[str] | None = None, target_aged: bool = True,
    parent_upgrade: ParentUpgradeFn | None = None, drift: Sequence[Change] = (),
) -> PlannedFix | HeldFix:
    """Trial *item*; a pin its parent blocks tries the parent route, then (if *can_force*) a forced pin,
    then (with *parent_upgrade*) a release of the parent beyond its declared range.

    With *pins_every_copy* the pin moves every locked copy, so a trial that
    leaves the package at several versions is not a reason to hold it.
    Without *target_aged* the planner has not checked the target's age, so
    the cooldown check covers the item's own package too.
    """
    pins = [(item.package, item.target)]
    say(f"trial-resolving {item.package} {item.target}")
    result = await trial(pins, [], lowest=_lowest(item))
    # Without target_aged each route looks the target's age up itself; an unknown age clears this.
    checked_from = item.cooldown_checked or not target_aged
    cooldown_checked = checked_from
    ages: dict[tuple[str, str], float | None] = {}
    own = _name(ecosystem, item.package)

    async def too_young(changes: tuple[Change, ...], prefix: str = "", *, own_too: bool = False) -> HeldFix | None:
        """A COOLDOWN hold if *changes* introduce a version still inside the cooldown period.

        The item's own target is exempt (the planner checked its age) unless
        *own_too*: a parent upgrade can move the package past its target.
        """
        nonlocal cooldown_checked
        detail, unknown = await _cooldown_check(
            changes, lambda c: target_aged and not own_too and _name(ecosystem, c.package) == own, age=age, cache=ages,
            cooldown_days=cooldown_days, allow_cooldown=allow_cooldown)
        if detail:
            return _held(item, planner.COOLDOWN, f"{prefix}{detail}")
        if unknown:
            cooldown_checked = False
        return None

    def checked() -> bool:
        return cooldown_checked

    if result.status == "blocked":
        blocker = result.blocker
        if blocker is None:
            return _held(item, planner.BLOCKED, result.detail or "the package manager found no resolution")
        why = f"{blocker.parent} requires {blocker.constraint}"
        route = await _parent_route(
            item, why, blocker, trial=trial, ecosystem=ecosystem, advisories=advisories,
            allow_major=allow_major, too_young=too_young, cooldown_checked=checked,
            pins_every_copy=pins_every_copy, say=say, major_only=major_only)
        if isinstance(route, HeldFix) and can_force:
            say(f"forcing {item.package} {item.target} past {blocker.parent}")
            # The forced trial's own checks start from the planner's cooldown state.
            cooldown_checked = checked_from
            route = await _forced(item, why, blocker, trial=trial, ecosystem=ecosystem, advisories=advisories,
                                  allow_major=allow_major, too_young=too_young, cooldown_checked=checked,
                                  major_only=major_only, drift=drift)
        # Only a package pinning the item calls for a release beyond its range;
        # a fix held for its cooldown or an advisory is not helped by one.
        if isinstance(route, HeldFix) and route.reason == planner.BLOCKED and parent_upgrade is not None:
            cooldown_checked = checked_from

            async def judge(fix: PlannedFix, why: str, context: str, exact: TrialResult,
                            parent: tuple[str, str], also: list[str]) -> PlannedFix | HeldFix:
                return await _judge_parent(fix, why, context, exact, parent, ecosystem=ecosystem,
                                           advisories=advisories, allow_major=allow_major, too_young=too_young,
                                           major_only=major_only, cooldown_checked=checked,
                                           pins_every_copy=pins_every_copy, also_pinned=also, drift=drift)

            route = await _parent_upgrade_route(item, why, blocker, route, parent_upgrade=parent_upgrade,
                                                trial=trial, can_force=can_force, say=say, judge=judge)
        return route
    if result.status != "resolved":
        return _held(item, planner.COULD_NOT_VERIFY, result.detail or "trial was not conclusive")
    if (bad := await _side_effects(result.changes, ecosystem, advisories, yanked=result.yanked,
                                    declined=result.declined, drift_problem=result.drift_problem)) is not None:
        return _held(item, *bad)
    if major := _major_hold(item, result.changes, allow_major, ecosystem=ecosystem, only=major_only):
        return major
    relock = _relock_change(item, result.changes, ecosystem, drift)
    if young := await too_young((*result.changes, *relock)):
        return young
    if not pins_every_copy and (split := _split_target(item, result.changes, ecosystem)):
        return _split_hold(item, split)
    if not _moves_target(item, result.changes, ecosystem, drift):
        return _held(item, planner.COULD_NOT_VERIFY, f"the trial did not move {item.package} to {item.target}")
    out = _verified(item, result.changes, ecosystem, None, cooldown_checked)
    # Reached only because the re-lock already moves it there (see _moves_target).
    return dataclasses.replace(out, by_relock=bool(relock))


# Holds a newer version of the package might avoid (not a cooldown, which a
# newer release only makes worse, nor a major upgrade or a planner hold).
_LADDER_REASONS = frozenset({planner.BLOCKED, planner.WOULD_DOWNGRADE, planner.WOULD_ADD, planner.YANKED,
                             planner.COULD_NOT_VERIFY})


async def _newest_allowed(item: PlannedFix, *, trial: TrialFn, ecosystem: str) -> str | None:
    """The version floating *item*'s package reaches above its target on the target's major line, or None.

    A float moves the package as far as its dependents' declared ranges allow;
    of the versions it moves the item's copies to, the lowest above the target is taken.
    """
    result = await trial([], [item.package], lowest=_lowest(item))
    if result.status != "resolved":
        return None
    key = _key_for(ecosystem)
    target = key(item.target)
    own = _name(ecosystem, item.package)
    found = []
    for c in result.changes:
        if (_name(ecosystem, c.package) != own or c.action != "update" or not c.old or not c.new
                or _crosses_major(ecosystem, item.version, c.old) or _crosses_major(ecosystem, item.target, c.new)):
            continue
        k = key(c.new)
        if k is not None and target is not None and k > target:
            found.append((k, c.new))
    return min(found)[1] if found else None


async def _ladder(item: PlannedFix, held: HeldFix, *, advisories: AdvisoryFn, verify: Callable[
        [PlannedFix], Awaitable[PlannedFix | HeldFix]], trial: TrialFn, ecosystem: str,
        say: Callable[[str], None]) -> PlannedFix | HeldFix:
    """Retry a *held* item with the newest version its dependents allow, when that still fixes it.

    The target is the lowest fixed version, which a newer release can improve
    on: one deprecated as a bad release, or one bringing a vulnerable
    dependency the newer release does not. *held* stands, with what the
    newer version ran into appended, when it does not verify.
    """
    say(f"looking for a newer {item.package} than {item.target}")
    over = await _newest_allowed(item, trial=trial, ecosystem=ecosystem)
    if over is None:
        return held
    label = f"{item.package} {over} (the newest version its dependents allow)"
    found = await advisories([(item.package, over)])
    ids, degraded = found.get((item.package, over), (frozenset(), True))
    if degraded:
        return dataclasses.replace(held, detail=f"{held.detail}; {label}: advisory lookup unavailable")
    if still := sorted(ids & (set(item.advisories) - set(item.left_open))):
        return dataclasses.replace(held, detail=f"{held.detail}; {label} still has {', '.join(still)}")
    out = await verify(dataclasses.replace(item, target=over))
    if isinstance(out, PlannedFix):
        return out
    return dataclasses.replace(held, detail=f"{held.detail}; {label}: {out.detail}")


async def verify_plan(
    plan: FixPlan, *, ecosystem: str, trial: TrialFn, advisories: AdvisoryFn, age: AgeFn,
    cooldown_days: int, allow_cooldown: bool, allow_major: frozenset[str] = frozenset(),
    progress: Callable[[str], object] | None = None, locked_yanks: tuple[Yank, ...] = (),
    drift: Sequence[Change] = (), drift_yanked: Sequence[Yank] = (),
    can_force: bool = False, pins_every_copy: bool = False, major_only: frozenset[str] | None = None,
    parallel: int = 1, parent_upgrade: ParentUpgradeFn | None = None,
) -> FixPlan:
    """Trial each planned pin alone, then all survivors together; see the spec.

    *parent_upgrade*, when given, finds the lowest release of a blocking parent
    beyond its declared range that admits an item's target (see
    ``_parent_upgrade_route``).

    Up to *parallel* items are verified at once (each item's own trials stay
    in sequence); the plan lists them in their original order regardless.

    *allow_major* has the planner's meaning; here it governs every package a
    trial upgrades other than the planned targets themselves.

    *progress*, if given, is told what is happening before each trial (a
    one-line message for a status display); a failing callback is ignored.

    *major_only*, when given, limits the major-version check of the
    incidental changes a trial makes to those packages (the project's direct
    dependencies, for an adapter whose resolver only moves a transitive
    package inside its dependents' declared ranges).

    *drift* is what re-locking the project changes with nothing pinned (the
    adapter's baseline): every printed command makes those changes too,
    unless it moves the package elsewhere. A drift change that installs a
    yanked version, downgrades or adds an advisory holds every item whose
    trial leaves it in place; a major or young version in it is only
    reported (``FixPlan.drift``). Trials are
    judged against the baseline, so drift is not blamed on any pin.
    *drift_yanked* are the yanked versions in the baseline's resolution.

    *locked_yanks* are locked versions the registry reports as yanked. They are
    listed on the plan with the yanks trials observed, except those the printed
    command moves off.

    *can_force* lets a pin its parent blocks fall back to a forced pin when
    the parent route is held, and lets a held item retry with the newest
    version its dependents allow (``_ladder``); *pins_every_copy* skips the marker-fork split
    check, since such an adapter's pin moves every locked copy, and passes
    each trial ``lowest``: every planned item's (package, target) mapped to
    the lowest vulnerable copy it is meant to move (parents are not
    included), so one package can be planned once per major line.
    """
    drift = tuple(drift)
    # The drift changes that would hold a fix (a yanked version, a downgrade,
    # a new advisory), each with its hold. A fix is held for one only when its
    # trial leaves that version in place: one that moves off it avoids it.
    bad_drift: list[tuple[Change, tuple[str, str]]] = []
    for c in drift:
        if bad := await _side_effects((c,), ecosystem, advisories, yanked=tuple(drift_yanked)):
            bad_drift.append((c, bad))
    # Every trial reports the yanked versions in its whole resolution; the ones
    # it did not introduce are already locked and are reported on the plan.
    seen: list[TrialResult] = []

    async def recording(
        pins: list[tuple[str, str]], floats: list[str], *, force: Sequence[tuple[str, str]] = (),
        lowest: Mapping[tuple[str, str], str] | None = None,
    ) -> TrialResult:
        # Keywords are passed only when they say something, so a trial that
        # cannot force or move several copies may take just (pins, floats).
        extra: dict = {}
        if force:
            extra["force"] = force
        if lowest and pins_every_copy:
            extra["lowest"] = dict(lowest)
        result = await trial(pins, floats, **extra)
        seen.append(result)
        if result.status == "resolved" and bad_drift:
            problem = await _drift_problem(result, bad_drift, ecosystem=ecosystem, advisories=advisories,
                                           yanked=(*tuple(drift_yanked), *result.yanked))
            if problem is not None:
                reason, detail = problem
                result = dataclasses.replace(
                    result, drift_problem=(reason, f"re-locking the project as it stands {reason}: {detail}"))
        return result

    planned: list[PlannedFix] = []
    held = list(plan.held)
    def report(message: str) -> None:
        """Tell *progress* what is happening; a failing display never stops verification."""
        if progress is None:
            return
        try:
            progress(message)
        except Exception:
            log.debug("Progress callback failed", exc_info=True)

    total = len(plan.planned)
    # Items are independent (each trial resolves in its own copy), so up to
    # *parallel* are verified at once; results keep the plan's order.
    slots = asyncio.Semaphore(max(1, parallel))
    # Progress counts finished items, which only goes up however the items
    # interleave; each message names the package it is about.
    done = 0

    async def verify_item(item: PlannedFix) -> PlannedFix | HeldFix:
        nonlocal done

        def say(message: str) -> None:
            report(f"Verifying fixes: {done} of {total} done — {message}")

        def verify(fix: PlannedFix, target_aged: bool = True) -> Awaitable[PlannedFix | HeldFix]:
            return _verify_one(fix, ecosystem=ecosystem, trial=recording, advisories=advisories, age=age,
                               cooldown_days=cooldown_days, allow_cooldown=allow_cooldown,
                               allow_major=allow_major, say=say, can_force=can_force,
                               pins_every_copy=pins_every_copy, major_only=major_only, target_aged=target_aged,
                               parent_upgrade=parent_upgrade, drift=drift)

        async with slots:
            try:
                # A target whose age the planner did not look up (a same-line fallback or a
                # merged item's target, which replace the recommendation it checked) is
                # checked against the cooldown here, by the trial.
                out = await verify(item, target_aged=item.cooldown_checked)
                if isinstance(out, HeldFix) and can_force and out.reason in _LADDER_REASONS:
                    out = await _ladder(item, out, advisories=advisories, trial=recording, ecosystem=ecosystem,
                                        say=say, verify=lambda fix: verify(fix, target_aged=False))
            except Exception as exc:
                log.warning("Verification of %s failed", item.package, exc_info=True)
                out = _held(item, planner.COULD_NOT_VERIFY, f"verification failed: {exc}")
        done += 1
        return out

    for out in await asyncio.gather(*(verify_item(item) for item in plan.planned)):
        if isinstance(out, PlannedFix):
            planned.append(out)
        else:
            held.append(out)
    separate = False
    separate_reason: str | None = None
    combined_changes: tuple[Change, ...] | None = None
    if len(planned) > 1:
        checked = {(_name(ecosystem, p.package), p.target) for p in planned}
        pins = _combined_pins(planned, ecosystem)
        checked |= {(_name(ecosystem, n), v) for n, v in pins}
        try:
            report(f"Trying all {len(planned)} verified fixes together")
            # Forced pins are identified by (package, version), not by name: one package
            # can be planned on several major lines, and only the windows whose items are
            # forced get an override in the printed commands. pins[i] is planned[i]'s pin
            # (raised when a parent upgrade needs a higher version on the same line).
            force = [pins[i] for i, p in enumerate(planned) if p.forced]
            lowest = {pins[i]: p.version for i, p in enumerate(planned)}
            combined = await recording(pins, [], force=force, lowest=lowest)
            # A fix that moved every copy alone can leave one behind together
            # (npm nests a copy it hoisted before): that package is overridden as
            # well, which its dependents' ranges are checked to admit. The blocker
            # names only the package, so each of its unforced windows is overridden
            # and marked forced, keeping the trial and the printed commands alike.
            newly_forced: dict[int, tuple[str, str]] = {}
            while can_force and combined.status == "blocked" and combined.blocker is not None:
                blocker = combined.blocker
                left = [i for i, p in enumerate(planned) if pins[i] not in force and not p.direct
                        and blocker.constraint.startswith(f"{p.package}@")]
                if not left:
                    break
                report(f"Trying all {len(planned)} verified fixes together, "
                       f"overriding {planned[left[0]].package} as well")
                force = [*force, *(pins[i] for i in left)]
                newly_forced.update((i, (blocker.parent, blocker.constraint)) for i in left)
                combined = await recording(pins, [], force=force, lowest=lowest)
            if newly_forced and combined.status == "resolved":
                planned = [dataclasses.replace(p, forced=newly_forced[i]) if i in newly_forced else p
                           for i, p in enumerate(planned)]
            combined_changes = combined.changes if combined.status == "resolved" else None
            separate_reason = await _combined_problem(
                combined, planned, ecosystem=ecosystem, advisories=advisories, allow_major=allow_major,
                pins_every_copy=pins_every_copy, major_only=major_only, drift=drift)
            if separate_reason is None:
                young, unknown = await _cooldown_check(
                    combined.changes,
                    # Equivalent spellings (PyPI 26.2 / 26.2.0) are the same checked version.
                    lambda c: any(n == _name(ecosystem, c.package) and _same_version(ecosystem, c.new, v)
                                  for n, v in checked),
                    age=age, cache={}, cooldown_days=cooldown_days, allow_cooldown=allow_cooldown)
                if young:
                    separate_reason = f"together they {young}"
                elif unknown:
                    # The printed command introduces a version of unknown age,
                    # so no item in it can claim a checked cooldown.
                    planned = [dataclasses.replace(p, cooldown_checked=False) for p in planned]
        except Exception as exc:
            log.warning("Combined trial failed", exc_info=True)
            separate_reason = f"the combined trial failed ({exc})"
        separate = separate_reason is not None
    # What the printed command moves off: its packages' old versions.
    printed = planned if not separate else sorted(planned, key=lambda f: f.package)[:1]
    if combined_changes is not None and not separate and len(planned) > 1:
        moved = [(c.package, c.old) for c in combined_changes if _leaves(c, ecosystem)]
    else:
        moved = [(c.package, c.old) for p in printed for c in p.changes if _leaves(c, ecosystem)]
    moved += [(p.package, p.version) for p in printed]
    changed = {(_name(ecosystem, pkg), ver) for pkg, ver in moved if ver is not None}
    candidates = list(locked_yanks)
    candidates += [y for r in seen if r.status == "resolved"
                   for y in r.yanked if not _introduced_yanks(r.changes, (y,), ecosystem)]
    locked: dict[tuple[str, str], Yank] = {}
    for y in candidates:
        if any(n == _name(ecosystem, y.package) and _same_version(ecosystem, v, y.version)
               for n, v in changed):
            continue  # the printed command upgrades it away
        locked.setdefault((_name(ecosystem, y.package), y.version), y)
    # Several pins that all failed to resolve the same way point at the project
    # or machine (a dependency that will not build here), not at the pins.
    tried = held[len(plan.held):]
    details = {h.detail for h in tried}
    shared = (details.pop() if not planned and len(tried) > 1 and len(details) == 1
              and all(h.reason == planner.COULD_NOT_VERIFY for h in tried) else None)
    return FixPlan(planned=planned, held=held, separate=separate, separate_reason=separate_reason,
                   trial_failure=shared,
                   command_changes=_command_changes(planned, combined_changes, separate, ecosystem),
                   yanked_locked=tuple(locked[k] for k in sorted(locked)), drift=drift)


async def _drift_problem(
    result: TrialResult, bad_drift: list[tuple[Change, tuple[str, str]]], *, ecosystem: str,
    advisories: AdvisoryFn, yanked: tuple[Yank, ...],
) -> tuple[str, str] | None:
    """The hold for bad lock drift *result* leaves in place, or None.

    A drift change the trial does not move off keeps its own hold. One it
    does move off is judged again from the project's own version to where the
    trial leaves the package (re-locking downgrades q 1.0.0 to 0.9.0 and the
    fix moves it to 0.9.5: still a downgrade of the project).
    """
    moved = (*result.changes, *result.declined)
    for drifted, bad in bad_drift:
        if not _moves_off(drifted, moved, ecosystem):
            return bad
        own = _name(ecosystem, drifted.package)
        for c in moved:
            if (_name(ecosystem, c.package) != own or c.action not in ("update", "remove") or c.new is None
                    or not _same_version(ecosystem, c.old, drifted.new)):
                continue
            from_project = (Change("update", drifted.package, drifted.old, c.new) if drifted.old is not None
                            else Change("add", drifted.package, None, c.new))
            if again := await _side_effects((from_project,), ecosystem, advisories, yanked=yanked):
                return again
    return None


def _moves_off(drifted: Change, changes: tuple[Change, ...], ecosystem: str) -> bool:
    """Whether *changes* (a trial's, judged against the baseline) leave no copy at the version *drifted* installs.

    *changes* include the trial's declined upgrades: keeping the project's own
    version instead of the baseline's is a move off the baseline's version.

    One copy moving off it is not enough: a change's ``fork_versions`` lists
    every version of the package the trial still locks, and the drifted
    version must not be among them for any change of the package.
    """
    own = _name(ecosystem, drifted.package)
    mine = [c for c in changes if _name(ecosystem, c.package) == own]
    moved = any(c.action in ("update", "remove") and _same_version(ecosystem, c.old, drifted.new) for c in mine)
    kept = any(_same_version(ecosystem, v, drifted.new) for c in mine for v in c.fork_versions)
    return moved and not kept


def _combined_pins(planned: list[PlannedFix], ecosystem: str) -> list[tuple[str, str]]:
    """Every planned pin, then every parent upgrade once, so no package is pinned twice on one major line.

    A parent several fixes need is pinned at its highest release; a parent
    upgrade of a package that is also pinned as a fix on the same major line
    leaves one pin, the higher (postcss fixed at 8.5.23 while nanoid's fix
    needs postcss 8.5.29). Pins on different major lines stay separate.
    """
    key = _key_for(ecosystem)

    def higher(a: str, b: str) -> bool:
        return (key(a) or ()) > (key(b) or ())

    parents: dict[str, tuple[str, str]] = {}
    for p in planned:
        for name, version in p.all_parents:
            own = _name(ecosystem, name)
            held = parents.get(own)
            if held is None or higher(version, held[1]):
                parents[own] = (name, version)
    pins = [(p.package, p.target) for p in planned]
    extra: list[tuple[str, str]] = []
    for own, (name, version) in parents.items():
        same = next((i for i, (n, v) in enumerate(pins) if _name(ecosystem, n) == own
                     and not _crosses_major(ecosystem, v, version) and not _crosses_major(ecosystem, version, v)), None)
        if same is None:
            extra.append((name, version))
        elif higher(version, pins[same][1]):
            pins[same] = (pins[same][0], version)
    return pins + extra


def _leaves(c: Change, ecosystem: str) -> bool:
    """Whether *c* moves its package off its old version (a fork can keep it locked)."""
    return not any(_same_version(ecosystem, c.old, v) for v in c.fork_versions)


async def _combined_problem(
    combined: TrialResult, planned: list[PlannedFix], *, ecosystem: str, advisories: AdvisoryFn,
    allow_major: frozenset[str], pins_every_copy: bool = False, major_only: frozenset[str] | None = None,
    drift: Sequence[Change] = (),
) -> str | None:
    """Why the combined trial cannot be printed as one command, or None if it can (cooldown aside)."""
    if combined.status == "blocked":
        return "no resolution exists with all of them pinned" + (f" ({combined.detail})" if combined.detail else "")
    if combined.status != "resolved":
        return f"the combined trial was not conclusive ({combined.detail or 'no detail'})"
    for p in planned:
        if _moves_target(p, combined.changes, ecosystem, drift):
            continue
        # Another fix can carry the package past its own target on the same
        # line (@babel/core needing a newer @babel/helpers); that is fine when
        # it no longer has the item's advisories. Its age and any advisory it
        # adds are checked with the rest of the combined trial.
        over = _overshoot(p, combined.changes, ecosystem)
        if over is None:
            return f"the combined trial did not move {p.package} to {p.target}"
        found = await advisories([(p.package, over)])
        ids, degraded = found.get((p.package, over), (frozenset(), True))
        if degraded:
            return f"the combined trial could not be checked: advisory lookup unavailable for {p.package} {over}"
        if still := sorted(ids & (set(p.advisories) - set(p.left_open))):
            return f"together they move {p.package} to {over}, which still has {', '.join(still)}"
    if not pins_every_copy and (
            split := next((s for p in planned if (s := _split_target(p, combined.changes, ecosystem))), None)):
        return f"together they lock {split.package} at several versions ({', '.join(split.fork_versions)})"
    if bad := await _side_effects(combined.changes, ecosystem, advisories, yanked=combined.yanked,
                                    declined=combined.declined, drift_problem=combined.drift_problem):
        reason, detail = bad
        if reason == planner.COULD_NOT_VERIFY:
            return f"the combined trial could not be checked: {detail}"
        return f"together they {reason}: {detail}"
    targets = frozenset(_name(ecosystem, p.package) for p in planned)
    # Pinned parents are upgrades the plan chooses: always major-checked.
    only = None if major_only is None else major_only | {n for p in planned for n, _v in p.all_parents}
    if bumps := _major_bumps(combined.changes, allow_major, targets, ecosystem, only):
        names = ", ".join(dict.fromkeys(c.package for c in bumps))
        return f"together they would upgrade {names} to a new major version"
    return None


def _command_changes(
    planned: list[PlannedFix], combined: tuple[Change, ...] | None, separate: bool, ecosystem: str,
) -> tuple[Change, ...]:
    """Changes of the trial matching the printed command, minus the pins the plan itself lists."""
    if not planned:
        return ()
    pins = _combined_pins(planned, ecosystem)

    def beyond(changes: tuple[Change, ...], pins: list[tuple[str, str]]) -> tuple[Change, ...]:
        return tuple(
            c for c in changes
            if not any(c.action in ("update", "add") and _name(ecosystem, c.package) == _name(ecosystem, pkg)
                       and _same_version(ecosystem, c.new, ver) for pkg, ver in pins)
        )

    if len(planned) == 1:
        return beyond(planned[0].changes, [p for p in pins if p[0] != planned[0].package])
    if separate or combined is None:
        first = min(planned, key=lambda f: f.package)
        return beyond(first.changes, list(first.all_parents))
    return beyond(combined, pins)
