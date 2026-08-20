"""Shared non-interactive escalation rule for risk/cooldown decisions.

Every gate in the run flow (pre-flight typosquat/high-risk, cooldown, and
post-install risk) needs the same substep: a configured "prompt" action is
meaningless where nobody can answer — a coding agent or a CI run has no TTY —
so it must be escalated to a configured fallback instead of silently hanging
or silently keeping a flagged package. Kept as one function so the rule can
only drift in one place rather than three independently-maintained copies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packagealert.config import CooldownAction, NonInteractiveAction


def escalate_if_prompt(
    action: CooldownAction, *, is_tty: bool, non_interactive_escalation: NonInteractiveAction
) -> CooldownAction:
    """Escalate *action* to *non_interactive_escalation* if it is "prompt" and
    *is_tty* is False. Any other action passes through unchanged.
    """
    if action == "prompt" and not is_tty:
        return non_interactive_escalation
    return action
