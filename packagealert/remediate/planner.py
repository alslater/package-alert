"""Turn per-package fix recommendations into a plan; no manager knowledge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from packagealert.osv.remediation import PackageFindings
from packagealert.remediate.graph import DependencyGraph

if TYPE_CHECKING:
    from packagealert.remediate.adapter import Change, Yank

MALICIOUS = "malicious"
WORKSPACE_MEMBER = "workspace member"
NO_FIX = "no fix known"
NOT_COMPARABLE = "version not comparable"
NON_REGISTRY = "not a registry package"
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
) -> str | None:
    """Why *group* cannot be planned, or None.

    Structural reasons come before policy ones so an opt-in flag can never
    override them: a package with no registry version, or locked once per
    marker fork (an exact pin constrains every fork), cannot be pinned safely.
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
    if len(graph.versions.get(group.package, ())) > 1:
        return MULTIPLE_VERSIONS
    if rec.major_upgrade and "*" not in allow_major and group.package not in allow_major:
        return MAJOR
    if not rec.verified:
        return UNVERIFIED
    age = ages.get((group.ecosystem, group.package, rec.version))
    if age is not None and age < cooldown_days and not allow_cooldown:
        return COOLDOWN
    return None


def plan_fixes(
    groups: list[PackageFindings],
    graph: DependencyGraph,
    *,
    ages: dict[tuple[str, str, str], float],
    cooldown_days: int,
    allow_major: frozenset[str] = frozenset(),
    allow_cooldown: bool = False,
) -> FixPlan:
    """One planned or held item per vulnerable package group.

    A planned target is exactly the recommended version — never a range — so
    the manager cannot pick a newer release than the one checked here.

    *allow_major* holds normalised package names whose major upgrades may be
    planned; ``"*"`` allows every package.
    """
    plan = FixPlan()
    for group in groups:
        rec = group.recommendation
        target = rec.version if rec is not None else None
        ids = [a.id for a in group.advisories]
        reason = _hold_reason(
            group, graph, ages=ages, cooldown_days=cooldown_days,
            allow_major=allow_major, allow_cooldown=allow_cooldown,
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
        ))
    return plan
