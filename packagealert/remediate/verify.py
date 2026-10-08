"""Verify planned pins by trial resolution before they are printed.

Manager-independent: the trial, advisory lookup and age lookup are injected,
so a manager adapter supplies only how to run one trial.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import Awaitable, Callable

from packagealert.models.events import normalise_package_name_for
from packagealert.osv.remediation import _key_for, _major
from packagealert.remediate import planner
from packagealert.remediate.adapter import Change, TrialResult, Yank
from packagealert.remediate.planner import FixPlan, HeldFix, PlannedFix

TrialFn = Callable[[list[tuple[str, str]], list[str]], Awaitable[TrialResult]]
AdvisoryFn = Callable[
    [list[tuple[str, str]]], Awaitable[dict[tuple[str, str], tuple[frozenset[str], bool]]]
]
AgeFn = Callable[[str, str], Awaitable[float | None]]

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
    old_major, new_major = _major(old_k), _major(new_k)
    return old_major is not None and new_major is not None and new_major > old_major


def _major_bumps(
    changes: tuple[Change, ...], allow_major: frozenset[str], exempt: frozenset[str], ecosystem: str,
) -> list[Change]:
    """Updates that cross a major version for a package that is neither allowed nor exempt.

    *exempt* holds the packages the plan itself targets: the planner has
    already applied the major policy to them. Unreadable versions are left to
    ``_downgrades``.
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
        if _crosses_major(ecosystem, c.old, c.new):
            out.append(c)
    return out


def _major_hold(
    item: PlannedFix, changes: tuple[Change, ...], allow_major: frozenset[str], prefix: str = "",
    *, ecosystem: str,
) -> HeldFix | None:
    bumps = _major_bumps(changes, allow_major, frozenset({_name(ecosystem, item.package)}), ecosystem)
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
) -> tuple[str, str] | None:
    """(reason, detail) if *changes* make anything worse, else None."""
    if hits := _introduced_yanks(changes, yanked, ecosystem):
        return planner.YANKED, "; ".join(
            f"would install {y.package} {y.version}, which is yanked" + (f" ({y.reason})" if y.reason else "")
            for y in hits)
    if down := _downgrades(changes, ecosystem):
        return planner.WOULD_DOWNGRADE, ", ".join(f"{c.package} {c.old} → {c.new}" for c in down)
    new_versions = [(c.package, c.new) for c in changes if c.new is not None]
    old_versions = [(c.package, c.old) for c in changes if c.action == "update" and c.old is not None]
    if not new_versions:
        return None
    found = await advisories(new_versions + old_versions)
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
    return None


def _moves_target(item: PlannedFix, changes: tuple[Change, ...], ecosystem: str) -> bool:
    return any(
        c.action in ("update", "add") and c.package == item.package
        and _same_version(ecosystem, c.new, item.target)
        for c in changes
    )


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


def _verified(
    item: PlannedFix, changes: tuple[Change, ...], ecosystem: str, parent: tuple[str, str] | None,
    cooldown_checked: bool,
) -> PlannedFix:
    return dataclasses.replace(
        item, verified=True, changes=_extra_changes(item, changes, ecosystem), parent=parent,
        cooldown_checked=cooldown_checked,
    )


async def _verify_one(
    item: PlannedFix, *, ecosystem: str, trial: TrialFn, advisories: AdvisoryFn,
    age: AgeFn, cooldown_days: int, allow_cooldown: bool, allow_major: frozenset[str],
    say: Callable[[str], None] = lambda _message: None,
) -> PlannedFix | HeldFix:
    pins = [(item.package, item.target)]
    say(f"trial-resolving {item.package} {item.target}")
    result = await trial(pins, [])
    parent: tuple[str, str] | None = None
    cooldown_checked = item.cooldown_checked
    ages: dict[tuple[str, str], float | None] = {}
    own = _name(ecosystem, item.package)

    async def too_young(changes: tuple[Change, ...], prefix: str = "") -> HeldFix | None:
        nonlocal cooldown_checked
        detail, unknown = await _cooldown_check(
            changes, lambda c: _name(ecosystem, c.package) == own, age=age, cache=ages,
            cooldown_days=cooldown_days, allow_cooldown=allow_cooldown)
        if detail:
            return _held(item, planner.COOLDOWN, f"{prefix}{detail}")
        if unknown:
            cooldown_checked = False
        return None

    if result.status == "blocked":
        blocker = result.blocker
        if blocker is None:
            return _held(item, planner.BLOCKED, result.detail or "the package manager found no resolution")
        why = f"{blocker.parent} requires {blocker.constraint}"
        say(f"{item.package} is blocked by {blocker.parent}; retrying with {blocker.parent} free to move")
        retry = await trial(pins, [blocker.parent])
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
        exact = await trial([*pins, parent], [])
        if exact.status != "resolved":
            return _held(item, planner.COULD_NOT_VERIFY,
                         f"{why}; pinning {parent[0]} {parent[1]} exactly did not resolve cleanly")
        context = f"{why}; pinning {parent[0]} {parent[1]}: "
        if bad := await _side_effects(exact.changes, ecosystem, advisories, yanked=exact.yanked):
            return _held(item, bad[0], f"{context}{bad[1]}")
        if major := _major_hold(item, exact.changes, allow_major, context, ecosystem=ecosystem):
            return major
        if young := await too_young(exact.changes, context):
            return young
        if split := _split_target(item, exact.changes, ecosystem):
            return _split_hold(item, split, context)
        if not _moves_target(item, exact.changes, ecosystem):
            return _held(item, planner.COULD_NOT_VERIFY,
                         f"{why}; pinning {parent[0]} {parent[1]} exactly did not resolve cleanly")
        # The exact trial has passed every check above; checking it again would
        # only repeat the OSV lookup.
        return _verified(item, exact.changes, ecosystem, parent, cooldown_checked)
    if result.status != "resolved":
        return _held(item, planner.COULD_NOT_VERIFY, result.detail or "trial was not conclusive")
    if (bad := await _side_effects(result.changes, ecosystem, advisories, yanked=result.yanked)) is not None:
        return _held(item, *bad)
    if major := _major_hold(item, result.changes, allow_major, ecosystem=ecosystem):
        return major
    if young := await too_young(result.changes):
        return young
    if split := _split_target(item, result.changes, ecosystem):
        return _split_hold(item, split)
    if not _moves_target(item, result.changes, ecosystem):
        return _held(item, planner.COULD_NOT_VERIFY, f"the trial did not move {item.package} to {item.target}")
    return _verified(item, result.changes, ecosystem, parent, cooldown_checked)


async def verify_plan(
    plan: FixPlan, *, ecosystem: str, trial: TrialFn, advisories: AdvisoryFn, age: AgeFn,
    cooldown_days: int, allow_cooldown: bool, allow_major: frozenset[str] = frozenset(),
    progress: Callable[[str], object] | None = None, locked_yanks: tuple[Yank, ...] = (),
) -> FixPlan:
    """Trial each planned pin alone, then all survivors together; see the spec.

    *allow_major* has the planner's meaning; here it governs every package a
    trial upgrades other than the planned targets themselves.

    *progress*, if given, is told what is happening before each trial (a
    one-line message for a status display); a failing callback is ignored.

    *locked_yanks* are locked versions the registry reports as yanked. They are
    listed on the plan with the yanks trials observed, except those the printed
    command moves off.
    """
    # Every trial reports the yanked versions in its whole resolution; the ones
    # it did not introduce are already locked and are reported on the plan.
    seen: list[TrialResult] = []

    async def recording(pins: list[tuple[str, str]], floats: list[str]) -> TrialResult:
        result = await trial(pins, floats)
        seen.append(result)
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
    for index, item in enumerate(plan.planned, start=1):
        def say(message: str, index: int = index) -> None:
            report(f"Verifying fixes: {index}/{total} — {message}")

        try:
            out = await _verify_one(item, ecosystem=ecosystem, trial=recording, advisories=advisories, age=age,
                                    cooldown_days=cooldown_days, allow_cooldown=allow_cooldown,
                                    allow_major=allow_major, say=say)
        except Exception as exc:
            log.warning("Verification of %s failed", item.package, exc_info=True)
            out = _held(item, planner.COULD_NOT_VERIFY, f"verification failed: {exc}")
        if isinstance(out, PlannedFix):
            planned.append(out)
        else:
            held.append(out)
    separate = False
    separate_reason: str | None = None
    combined_changes: tuple[Change, ...] | None = None
    if len(planned) > 1:
        checked = {(_name(ecosystem, p.package), p.target) for p in planned}
        checked |= {(_name(ecosystem, p.parent[0]), p.parent[1]) for p in planned if p.parent}
        pins = [(p.package, p.target) for p in planned] + [p.parent for p in planned if p.parent]
        try:
            report(f"Trying all {len(planned)} verified fixes together")
            combined = await recording(pins, [])
            combined_changes = combined.changes if combined.status == "resolved" else None
            separate_reason = await _combined_problem(
                combined, planned, ecosystem=ecosystem, advisories=advisories, allow_major=allow_major)
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
                   yanked_locked=tuple(locked[k] for k in sorted(locked)))


def _leaves(c: Change, ecosystem: str) -> bool:
    """Whether *c* moves its package off its old version (a fork can keep it locked)."""
    return not any(_same_version(ecosystem, c.old, v) for v in c.fork_versions)


async def _combined_problem(
    combined: TrialResult, planned: list[PlannedFix], *, ecosystem: str, advisories: AdvisoryFn,
    allow_major: frozenset[str],
) -> str | None:
    """Why the combined trial cannot be printed as one command, or None if it can (cooldown aside)."""
    if combined.status == "blocked":
        return "no resolution exists with all of them pinned"
    if combined.status != "resolved":
        return f"the combined trial was not conclusive ({combined.detail or 'no detail'})"
    if not all(_moves_target(p, combined.changes, ecosystem) for p in planned):
        return "the combined trial did not move every package to its planned version"
    if split := next((s for p in planned if (s := _split_target(p, combined.changes, ecosystem))), None):
        return f"together they lock {split.package} at several versions ({', '.join(split.fork_versions)})"
    if bad := await _side_effects(combined.changes, ecosystem, advisories, yanked=combined.yanked):
        reason, detail = bad
        if reason == planner.COULD_NOT_VERIFY:
            return f"the combined trial could not be checked: {detail}"
        return f"together they {reason}: {detail}"
    targets = frozenset(_name(ecosystem, p.package) for p in planned)
    if bumps := _major_bumps(combined.changes, allow_major, targets, ecosystem):
        names = ", ".join(dict.fromkeys(c.package for c in bumps))
        return f"together they would upgrade {names} to a new major version"
    return None


def _command_changes(
    planned: list[PlannedFix], combined: tuple[Change, ...] | None, separate: bool, ecosystem: str,
) -> tuple[Change, ...]:
    """Changes of the trial matching the printed command, minus the pins the plan itself lists."""
    if not planned:
        return ()
    pins = [(p.package, p.target) for p in planned] + [p.parent for p in planned if p.parent]

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
        return beyond(first.changes, [first.parent] if first.parent else [])
    return beyond(combined, pins)
