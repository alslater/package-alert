"""Turn per-package fix recommendations into a plan; no manager knowledge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from packagealert.osv.remediation import FixRecommendation, PackageFindings
from packagealert.remediate.graph import DependencyGraph

if TYPE_CHECKING:
    from packagealert.remediate.adapter import Change, Yank

MALICIOUS = "malicious"
WORKSPACE_MEMBER = "workspace member"
NO_FIX = "no fix known"
NOT_COMPARABLE = "version not comparable"
NON_REGISTRY = "not a registry package"
ALIASED = "installed under an alias"
MULTIPLE_VERSIONS = "multiple locked versions"
MAJOR = "major upgrade"
UNVERIFIED = "unverified"
COOLDOWN = "in cooldown"
BLOCKED = "blocked"
WOULD_DOWNGRADE = "would downgrade"
WOULD_ADD = "would add advisories"
COULD_NOT_VERIFY = "could not verify"
YANKED = "would install a yanked version"


@dataclass(frozen=True)
class PlannedFix:
    package: str
    version: str
    target: str
    direct: bool
    path: list[str]
    advisories: list[str]
    left_open: list[str]
    cooldown_checked: bool
    verified: bool = False
    changes: tuple[Change, ...] = ()
    parent: tuple[str, str] | None = None
    forced: tuple[str, str] | None = None
    """(parent, the range it declares for the package) when the fix is an override under that parent."""
    fixes_all: str | None = None
    """When the target leaves advisories open that only a new major version
    fixes: that version (a major upgrade not allowed, so not planned)."""
    more_parents: tuple[tuple[str, str], ...] = ()
    """Further (package, version) upgrades the fix needs beside ``parent``: every
    package that pins the vulnerable one, when more than one does."""
    by_relock: bool = False
    """Re-locking the project alone moves the package to the target (it is in
    the lock drift); the printed commands re-lock, so nothing pins it."""

    @property
    def all_parents(self) -> tuple[tuple[str, str], ...]:
        """``parent`` (if any) followed by ``more_parents``."""
        return ((self.parent,) if self.parent else ()) + self.more_parents


@dataclass(frozen=True)
class HeldFix:
    package: str
    version: str | None
    target: str | None
    reason: str
    advisories: list[str]
    detail: str = ""
    needs_major: tuple[str, ...] = ()
    """Packages whose --allow-major entry would lift a ``major upgrade`` hold."""


@dataclass
class FixPlan:
    planned: list[PlannedFix] = field(default_factory=list)
    held: list[HeldFix] = field(default_factory=list)
    separate: bool = False
    separate_reason: str | None = None
    """Why the fixes were not verified as one command, when ``separate``."""
    command_changes: tuple[Change, ...] = ()
    """What the printed command changes beyond the planned targets and parent pins."""
    yanked_locked: tuple[Yank, ...] = ()
    """Locked versions the registry (or a trial) reports as yanked that the printed commands do not change."""
    trial_failure: str | None = None
    """The error every trial resolve failed with, when they all failed the same way."""
    drift: tuple[Change, ...] = ()
    """What re-locking the project changes with nothing pinned (an out-of-date lock): every printed command makes these too."""

    @property
    def complete(self) -> bool:
        """Everything vulnerable is planned, verified, fully fixed by its pin, and applicable in one go."""
        return (
            not self.separate
            and not self.held
            and all(p.verified for p in self.planned)
            and not any(p.left_open for p in self.planned)
        )


def _hold_reason(
    group: PackageFindings,
    graph: DependencyGraph,
    *,
    ages: dict[tuple[str, str, str], float],
    cooldown_days: int,
    allow_major: frozenset[str],
    allow_cooldown: bool,
    pins_every_copy: bool = False,
) -> str | None:
    """Why *group* cannot be planned, or None.

    Structural reasons come before policy ones so an opt-in flag can never
    override them: a package with no registry version, or locked once per
    marker fork (an exact pin constrains every fork), cannot be pinned safely.
    The multiple-versions hold applies only to adapters whose pin cannot move
    every copy (*pins_every_copy* False).
    """
    if any(a.is_malicious for a in group.advisories):
        return MALICIOUS
    if group.package in graph.members:
        return WORKSPACE_MEMBER
    rec = group.recommendation
    if rec is None:
        return NOT_COMPARABLE
    if rec.version is None:
        return NO_FIX
    if group.package in graph.non_registry:
        return NON_REGISTRY
    if group.package in graph.aliased:
        return ALIASED
    if not pins_every_copy and len(graph.versions.get(group.package, ())) > 1:
        return MULTIPLE_VERSIONS
    if rec.major_upgrade and "*" not in allow_major and _allow_name(group) not in allow_major:
        return MAJOR
    if not rec.verified:
        return UNVERIFIED
    age = ages.get((group.ecosystem, group.package, rec.version))
    if age is not None and age < cooldown_days and not allow_cooldown:
        return COOLDOWN
    return None


def _allow_name(group: PackageFindings) -> str:
    """*group*'s package as ``allow_major`` names it: normalised by its ecosystem's own rule.

    allow_major holds normalised names, while a lock file keeps the name as
    written (npm's legacy mixed-case names, such as ``Haraka``).
    """
    from packagealert.models.events import normalise_package_name_for

    return normalise_package_name_for(group.ecosystem, group.package)


def _merge_copies(groups: list[PackageFindings], direct: frozenset[str],
                  allow_major: frozenset[str] = frozenset()) -> list[PackageFindings]:
    """One group per package and major line, for an adapter whose pin moves every locked copy.

    A direct dependency's copies make one group: it is installed at one
    version. A transitive package's copies are grouped per major line, since
    each line can be moved on its own (an override scoped to that line), so
    a line with a fix on it is not held back by an older line without one.
    Lines whose recommendations reach the same target are one group again,
    unless that target is a major upgrade *allow_major* does not allow (it
    is then held on its own line): one item, with one override window from
    its lowest copy, rather than two pins of the same version.
    Each copy keeps its own recommendation (from its own findings); see
    ``_merged_recommendation`` for how they combine. A merged group's version
    is its lowest copy's and it holds every one of its copies' findings.
    """
    from packagealert.osv.remediation import _key_for, _major_for

    by_line: dict[tuple[str, str, object], list[PackageFindings]] = {}
    for g in groups:
        k = _key_for(g.ecosystem)(g.version) if g.version and g.package not in direct else None
        line = _major_for(g.ecosystem, k) if k is not None else None
        by_line.setdefault((g.ecosystem, g.package, line), []).append(g)

    def merge(eco: str, name: str, gs: list[PackageFindings]) -> PackageFindings:
        if len(gs) == 1:
            return gs[0]
        key = _key_for(eco)
        lowest = min((g.version for g in gs if g.version), key=lambda v: (key(v) is None, key(v) or ()), default=None)
        group = PackageFindings(package=name, ecosystem=eco, version=lowest)
        group.findings = [f for g in gs for f in g.findings]
        group.recommendation = _merged_recommendation(gs, eco)
        return group

    # Lines of one package that converge on one plannable target share an
    # item, placed where the first of them was.
    slots: list[PackageFindings | tuple[str, str, str]] = []
    by_target: dict[tuple[str, str, str], list[PackageFindings]] = {}
    for (eco, name, _line), gs in by_line.items():
        line_group = merge(eco, name, gs)
        rec = line_group.recommendation
        allowed = rec is not None and (not rec.major_upgrade or "*" in allow_major
                                       or _allow_name(line_group) in allow_major)
        if name in direct or rec is None or rec.version is None or not allowed:
            slots.append(line_group)
            continue
        target = (eco, name, rec.version)
        if target not in by_target:
            slots.append(target)
        by_target.setdefault(target, []).extend(gs)
    return [merge(s[0], s[1], by_target[s]) if isinstance(s, tuple) else s for s in slots]


def _merged_recommendation(copies: list[PackageFindings], ecosystem: str) -> FixRecommendation | None:
    """One recommendation that fixes every copy, or the reason none can.

    None (not comparable) when any copy's version cannot be ordered; no
    version (no fix) when any copy has no fix. Otherwise the target is the
    highest copy's recommendation; it is a major upgrade if it leaves the
    major line of any copy, verified only if every copy's is, and it leaves
    open every advisory whose OSV data still covers the target for some copy.
    """
    from packagealert.osv.remediation import _key_for, _major_for, open_advisories

    recs = [c.recommendation for c in copies]
    ids = list(dict.fromkeys(f.get("advisory_id") or "?" for c in copies for f in c.findings))
    if any(c.version is None or r is None for c, r in zip(copies, recs, strict=True)):
        return None
    if any(r is None or r.version is None for r in recs):
        return FixRecommendation(version=None, unfixed=tuple(ids), major_upgrade=False,
                                 verified=all(r is not None and r.verified for r in recs))
    key = _key_for(ecosystem)
    versions = [r.version for r in recs if r is not None and r.version is not None]
    target = max(versions, key=lambda v: key(v))
    target_major = _major_for(ecosystem, key(target))
    unfixed: list[str] = []
    for c in copies:
        still = open_advisories(c.version, c.findings, ecosystem, target) if c.version else None
        if still is None:
            return None
        unfixed.extend(still)
    major_upgrade = any(_major_for(ecosystem, key(c.version)) != target_major for c in copies if c.version)
    same_line, same_unfixed = None, ()
    lines = {_major_for(ecosystem, key(c.version)) for c in copies if c.version}
    alternatives = [(r.same_line_version if r.major_upgrade else r.version) for r in recs if r is not None]
    if major_upgrade and len(lines) == 1 and alternatives and all(alternatives):
        # Every copy has a fix on the one installed line: the highest of them.
        candidate = max((v for v in alternatives if v), key=lambda v: key(v))
        left: list[str] = []
        for c in copies:
            open_ = open_advisories(c.version, c.findings, ecosystem, candidate) if c.version else None
            if open_ is None:
                candidate = None
                break
            left.extend(open_)
        if candidate is not None and len(set(left)) < len(ids):
            same_line, same_unfixed = candidate, tuple(dict.fromkeys(left))
    return FixRecommendation(
        version=target,
        unfixed=tuple(dict.fromkeys(unfixed)),
        major_upgrade=major_upgrade,
        verified=all(r is not None and r.verified for r in recs),
        same_line_version=same_line,
        same_line_unfixed=same_unfixed,
    )


def plan_fixes(
    groups: list[PackageFindings],
    graph: DependencyGraph,
    *,
    ages: dict[tuple[str, str, str], float],
    cooldown_days: int,
    allow_major: frozenset[str] = frozenset(),
    allow_cooldown: bool = False,
    pins_every_copy: bool = False,
) -> FixPlan:
    """One planned or held item per vulnerable package group.

    A planned target is exactly the recommended version — never a range — so
    the manager cannot pick a newer release than the one checked here.

    *allow_major* holds normalised package names whose major upgrades may be
    planned; ``"*"`` allows every package.

    *pins_every_copy* is set by adapters whose pin moves every locked copy of a
    package: its findings across locked versions become one item (one per
    major line for a transitive package), planned from the lowest vulnerable version.
    """
    if pins_every_copy:
        groups = _merge_copies(groups, graph.direct, allow_major)
    plan = FixPlan()
    for group in groups:
        rec = group.recommendation
        fixes_all = None
        if (rec is not None and rec.major_upgrade and rec.same_line_version is not None
                and "*" not in allow_major and _allow_name(group) not in allow_major):
            # The full fix needs a major upgrade that is not allowed: plan the best
            # the installed major line offers, leaving the rest open.
            fixes_all = rec.version
            rec = group.recommendation = FixRecommendation(
                version=rec.same_line_version, unfixed=rec.same_line_unfixed, major_upgrade=False,
                verified=rec.verified)
        target = rec.version if rec is not None else None
        ids = [a.id for a in group.advisories]
        reason = _hold_reason(
            group, graph, ages=ages, cooldown_days=cooldown_days,
            allow_major=allow_major, allow_cooldown=allow_cooldown, pins_every_copy=pins_every_copy,
        )
        if reason is not None or target is None:
            plan.held.append(HeldFix(
                package=group.package, version=group.version, target=target,
                reason=reason or NO_FIX, advisories=ids,
                needs_major=(group.package,) if reason == MAJOR else (),
            ))
            continue
        plan.planned.append(PlannedFix(
            package=group.package,
            version=group.version or "",
            target=target,
            direct=group.package in graph.direct,
            path=graph.path_to(group.package),
            advisories=ids,
            left_open=[a.id for a in group.unfixed_advisories()],
            cooldown_checked=(group.ecosystem, group.package, target) in ages,
            fixes_all=fixes_all,
        ))
    return plan
