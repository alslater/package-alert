"""Risk-score gating for `package-alert run`.

Mirrors the shape of `packagealert.sandbox.cooldown`: a pure decision function
with no I/O, taking `is_tty` as a parameter so the non-interactive escalation
rule is directly testable.

Two triggers are evaluated independently and the highest-ranked action wins:
a typosquat match on the package name, and a risk score at or above the
configured threshold. Thresholds are separate from HeuristicsConfig's because
pre-flight scoring sees only metadata signals (see PreflightRiskConfig).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from packagealert.config import CooldownAction
from packagealert.languages.base import PackageSpec
from packagealert.sandbox.escalation import escalate_if_prompt

if TYPE_CHECKING:
    from packagealert.config import PreflightRiskConfig
    from packagealert.heuristics.typosquat import TyposquatResult
    from packagealert.models.risk import RiskReport

# An alias, not a parallel Literal: the values assigned to these fields come from
# PreflightRiskConfig, so the two cannot be allowed to diverge. Kept under the local
# name because it reads better at the use sites here, and because "cooldown" is the
# wrong word for a pre-flight risk decision.
RiskAction = CooldownAction

# Keyed on RiskAction rather than str so a type checker rejects an unranked action at
# the lookup sites instead of raising KeyError inside `max()` at runtime. The concrete
# risk is drift between this Literal and `config.CooldownAction`, which is declared
# separately with the same members and supplies every configured action
# (PreflightRiskConfig.on_typosquat and friends). Adding a member to one alone would
# produce a value with no rank; see test_action_rank_covers_every_cooldown_action.
ACTION_RANK: dict[RiskAction, int] = {"allow": 0, "warn": 1, "prompt": 2, "block": 3}


@dataclass
class RiskDecision:
    action: RiskAction
    reason: str
    package: PackageSpec
    score: int


def decide_risk(
    package: PackageSpec,
    *,
    report: RiskReport,
    typo: TyposquatResult,
    cfg: PreflightRiskConfig,
    is_tty: bool,
) -> RiskDecision:
    """Decide what to do about a package's risk profile. Pure; no I/O."""
    if not cfg.enabled:
        return RiskDecision(
            action="allow",
            reason="Pre-flight risk checks disabled",
            package=package,
            score=report.score,
        )

    actions: list[RiskAction] = []
    reasons: list[str] = []

    if typo.is_typosquat:
        # Gate on the *scored* strength of the match, not the bare boolean. The
        # risk engine reduces the score only where the suspect's own adoption
        # corroborates the resemblance being coincidental, so an established
        # package (httpx2: 29k dependents, scores 3) reports without gating while
        # a real squat — including a version-suffixed one like a newly published
        # requests2 — arrives here at full score and gates.
        strong_enough = typo.score >= cfg.typosquat_min_score
        within_distance = (
            typo.distance is not None and typo.distance <= cfg.typosquat_max_distance
        )
        # on_typosquat only decides the action for a *qualifying* match — see
        # config.py's PreflightRiskConfig.typosquat_max_distance and README.md's
        # [sandbox.preflight_risk] section, both of which document a
        # non-qualifying match as always reported via an informational "warn",
        # independent of on_typosquat (including on_typosquat="allow"). This is
        # not the same axis as gating strictness: "warn" here never blocks or
        # prompts — it prints and the install proceeds — so a weaker match
        # warning while a stronger match is allowed is not a stricter outcome
        # for a weaker signal, just a visibility notice that survives even when
        # gating itself is switched off.
        actions.append(cfg.on_typosquat if (strong_enough and within_distance) else "warn")
        if typo.closest_match:
            # Omit the distance clause when it is unknown rather than rendering
            # "distance None". The gating check above already tolerates a missing
            # distance, so the message has to as well; the impersonated package
            # name is the actionable part and is kept either way.
            detail = f" (distance {typo.distance})" if typo.distance is not None else ""
            reasons.append(f"possible typosquat of '{typo.closest_match}'{detail}")
        else:
            reasons.append("possible typosquat of a popular package")

    if report.score >= cfg.risk_threshold:
        actions.append(cfg.on_high_risk)
        reasons.append(f"risk score {report.score} (threshold {cfg.risk_threshold})")

    if not actions:
        return RiskDecision(
            action="allow",
            reason="No risk signals above threshold",
            package=package,
            score=report.score,
        )

    # Escalate prompt → configured action in non-interactive contexts, matching
    # cooldown.decide. Only a fired trigger is escalated; allow paths return above.
    # Each fired action is substituted *before* the ranking, not after: substituting
    # only the ranked winner let one policy erase another — with on_typosquat="prompt",
    # on_high_risk="warn" and non_interactive_escalation="allow", "prompt" won the
    # ranking and was then downgraded to "allow", discarding the independently fired
    # high-risk warn. cooldown.decide fires at most one action, so post-substitution
    # is equivalent there; here the triggers are independent.
    actions = [
        escalate_if_prompt(a, is_tty=is_tty, non_interactive_escalation=cfg.non_interactive_escalation)
        for a in actions
    ]

    action: RiskAction = max(actions, key=lambda a: ACTION_RANK[a])

    return RiskDecision(
        action=action,
        reason="; ".join(reasons),
        package=package,
        score=report.score,
    )


def worst(decisions: list[RiskDecision]) -> RiskDecision | None:
    """Return the decision with the highest-ranked action, or None if empty."""
    if not decisions:
        return None
    return max(decisions, key=lambda d: ACTION_RANK[d.action])
