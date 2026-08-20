import pytest
from pydantic import ValidationError

from packagealert.config import PreflightRiskConfig
from packagealert.heuristics.typosquat import TyposquatResult
from packagealert.languages.base import PackageSpec
from packagealert.models.risk import RiskReport


def _cfg(**kw):
    return PreflightRiskConfig(**kw)


def _pkg(name="reqeusts", version="1.0.0", ecosystem="pypi"):
    return PackageSpec(name=name, version=version, ecosystem=ecosystem)


def _report(score=0, signals=None):
    return RiskReport(
        package_name="reqeusts",
        ecosystem="pypi",
        score=score,
        signals=signals or [],
    )


def _typo(is_typosquat=False, closest_match=None, distance=None, score=0, affix=False):
    return TyposquatResult(
        is_typosquat=is_typosquat,
        closest_match=closest_match,
        distance=distance,
        score=score,
        affix_variant=affix,
    )


# --- no triggers -------------------------------------------------------------


def test_no_signals_allows():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(_pkg(), report=_report(0), typo=_typo(), cfg=_cfg(), is_tty=True)
    assert d.action == "allow"
    assert d.score == 0


def test_score_below_threshold_allows():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(_pkg(), report=_report(24), typo=_typo(), cfg=_cfg(risk_threshold=25), is_tty=True)
    assert d.action == "allow"


# --- disabled ----------------------------------------------------------------


def test_disabled_always_allows_even_with_typosquat():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(90),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(enabled=False),
        is_tty=True,
    )
    assert d.action == "allow"
    assert "disabled" in d.reason.lower()


# --- typosquat trigger -------------------------------------------------------


def test_typosquat_fires_configured_action():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(20),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="prompt", risk_threshold=25),
        is_tty=True,
    )
    assert d.action == "prompt"
    assert "requests" in d.reason
    assert "distance 1" in d.reason


def test_distance_1_typosquat_gates():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(20),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert d.action == "block"


def test_distance_2_typosquat_gates_at_full_score():
    """An unreduced distance-2 match is a real squat shape (reqeusts, cryptografy)
    and must still gate — the earlier distance cap wrongly let these through."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(15),
        typo=_typo(True, "requests", 2, 15),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert d.action == "block"


def test_typosquat_max_distance_is_configurable():
    """Lowering the cap to 1 excludes distance-2 matches from gating."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("respx"),
        report=_report(15),
        typo=_typo(True, "regex", 2, 15),
        cfg=_cfg(on_typosquat="block", typosquat_max_distance=1),
        is_tty=True,
    )
    assert d.action == "warn"


# --- score-based gating (signals 1 + 2) --------------------------------------


def test_adoption_reduced_typosquat_does_not_gate():
    """httpx2-shaped: 29k dependents plus a version suffix reduce the score to 3,
    which must not trip the gate (typosquat_min_score is 15).

    3 is the value the engine actually produces for httpx2's real metadata — see
    test_documented_httpx2_calibration_is_exact in test_risk_engine.py.
    """
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("httpx2"),
        report=_report(3),
        typo=_typo(True, "httpx", 1, 3, affix=True),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert d.action == "warn"
    assert "httpx" in d.reason


def test_partially_reduced_distance_2_does_not_gate():
    """respx-shaped: 52 dependents reduce 15 -> 14, below the default min score."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("respx"),
        report=_report(14),
        typo=_typo(True, "regex", 2, 14),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert d.action == "warn"


def test_typosquat_min_score_is_configurable():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("httpx2"),
        report=_report(1),
        typo=_typo(True, "httpx", 1, 1, affix=True),
        cfg=_cfg(on_typosquat="block", typosquat_min_score=1),
        is_tty=True,
    )
    assert d.action == "block"


def test_brand_new_version_suffixed_squat_still_gates():
    """REGRESSION: the detector used to score every version-suffixed name at 5,
    so appending a digit to a popular name bypassed the gate. A newly published
    requests2 has no adoption, so the engine applies no reduction and it arrives
    here at full score."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("requests2"),
        report=_report(20),
        typo=_typo(True, "requests", 1, 20, affix=True),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert d.action == "block"


def test_brand_new_version_suffixed_squat_escalates_in_ci():
    """The default on_typosquat=prompt must escalate to block without a TTY."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("requests2"),
        report=_report(20),
        typo=_typo(True, "requests", 1, 20, affix=True),
        cfg=_cfg(),
        is_tty=False,
    )
    assert d.action == "block"


def test_reason_does_not_claim_a_suffix_excused_anything():
    """A version suffix is not an exoneration; the gate must not imply it is."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("requests2"),
        report=_report(20),
        typo=_typo(True, "requests", 1, 20, affix=True),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert "version suffix" not in d.reason
    assert "requests" in d.reason


def test_weak_typosquat_still_surfaces_the_finding():
    """Reduction must downgrade the action, never silence the report."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("httpx2"),
        report=_report(1),
        typo=_typo(True, "httpx", 1, 1, affix=True),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert d.action != "allow"
    assert "httpx" in d.reason


def test_typosquat_without_distance_warns_rather_than_gating():
    """An unknown distance is not evidence strong enough to block on."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(0),
        typo=_typo(True, None, None, 15),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert d.action == "warn"
    assert "typosquat" in d.reason.lower()


def test_on_typosquat_allow_still_warns_on_a_reduced_match():
    """config.py's PreflightRiskConfig.typosquat_max_distance and README.md's
    [sandbox.preflight_risk] section both document a non-qualifying match as
    always reported via an informational warning, independent of
    on_typosquat — including on_typosquat="allow". "warn" never blocks or
    prompts, so this is a visibility notice, not a stricter gate than
    "allow" would be for a qualifying match."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("httpx2"),
        report=_report(1),
        typo=_typo(True, "httpx", 1, 1, affix=True),  # reduced score, does not gate
        cfg=_cfg(on_typosquat="allow"),
        is_tty=True,
    )
    assert d.action == "warn"


def test_on_typosquat_allow_still_warns_on_an_out_of_distance_match():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(0),
        typo=_typo(True, "somepkg", 5, 20),  # far beyond typosquat_max_distance
        cfg=_cfg(on_typosquat="allow"),
        is_tty=True,
    )
    assert d.action == "warn"


def test_on_typosquat_allow_still_warns_when_distance_is_unknown():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(0),
        typo=_typo(True, None, None, 15),
        cfg=_cfg(on_typosquat="allow"),
        is_tty=True,
    )
    assert d.action == "warn"


def test_on_typosquat_allow_skips_gating_only_for_a_qualifying_match():
    """on_typosquat only decides the action for a match that clears BOTH the
    score and distance thresholds — that is the one case "allow" actually
    suppresses gating for."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg("reqeusts"),
        report=_report(20),
        typo=_typo(True, "requests", 1, 20),  # full score, within distance: qualifies
        cfg=_cfg(on_typosquat="allow"),
        is_tty=True,
    )
    assert d.action == "allow"


# --- score trigger -----------------------------------------------------------


def test_score_at_threshold_fires_inclusive():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(25),
        typo=_typo(),
        cfg=_cfg(risk_threshold=25, on_high_risk="warn"),
        is_tty=True,
    )
    assert d.action == "warn"
    assert "25" in d.reason


# --- action ranking ----------------------------------------------------------


def test_highest_ranked_action_wins_when_both_trigger():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(90),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="warn", on_high_risk="block", risk_threshold=25),
        is_tty=True,
    )
    assert d.action == "block"


def test_highest_ranked_action_wins_reversed():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(90),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="block", on_high_risk="warn", risk_threshold=25),
        is_tty=True,
    )
    assert d.action == "block"


def test_both_triggers_reported_in_reason():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(90),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(risk_threshold=25),
        is_tty=True,
    )
    assert "typosquat" in d.reason.lower()
    assert "90" in d.reason


# --- TTY escalation ----------------------------------------------------------


def test_prompt_escalates_when_not_tty():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(0),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="prompt", non_interactive_escalation="block"),
        is_tty=False,
    )
    assert d.action == "block"


def test_prompt_escalation_target_is_configurable():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(0),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="prompt", non_interactive_escalation="warn"),
        is_tty=False,
    )
    assert d.action == "warn"


def test_allow_is_not_escalated_when_not_tty():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(_pkg(), report=_report(0), typo=_typo(), cfg=_cfg(), is_tty=False)
    assert d.action == "allow"


def test_warn_is_not_escalated_when_not_tty():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(50),
        typo=_typo(),
        cfg=_cfg(risk_threshold=25, on_high_risk="warn"),
        is_tty=False,
    )
    assert d.action == "warn"


# Escalation is applied to each fired action *before* the ranking. Substituting only
# the ranked winner let one policy erase another: with on_typosquat="prompt",
# on_high_risk="warn" and non_interactive_escalation="allow", "prompt" won the ranking
# and was then downgraded to "allow", discarding the independently fired warn.


def test_escalation_to_allow_cannot_erase_an_independent_warn():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(30),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(
            on_typosquat="prompt",
            on_high_risk="warn",
            non_interactive_escalation="allow",
            risk_threshold=25,
        ),
        is_tty=False,
    )
    assert d.action == "warn"
    # Both fired signals stay in the reason alongside the surviving action.
    assert "typosquat" in d.reason.lower()
    assert "risk score 30" in d.reason


def test_escalation_to_allow_with_only_prompt_fired_allows():
    """With no independent trigger, escalating to allow is the whole decision."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(0),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="prompt", non_interactive_escalation="allow"),
        is_tty=False,
    )
    assert d.action == "allow"


def test_escalation_to_allow_downgrades_both_fired_prompts():
    """When every fired trigger is a prompt, each is substituted and allow stands."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(30),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(
            on_typosquat="prompt",
            on_high_risk="prompt",
            non_interactive_escalation="allow",
            risk_threshold=25,
        ),
        is_tty=False,
    )
    assert d.action == "allow"


def test_tty_keeps_prompt_over_an_independent_warn():
    """Interactive contexts are untouched: prompt still outranks warn on a TTY."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(30),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(
            on_typosquat="prompt",
            on_high_risk="warn",
            non_interactive_escalation="allow",
            risk_threshold=25,
        ),
        is_tty=True,
    )
    assert d.action == "prompt"


# --- worst() -----------------------------------------------------------------


def test_worst_returns_none_for_empty():
    from packagealert.sandbox.preflight_risk import worst
    assert worst([]) is None


def test_worst_picks_highest_ranked():
    from packagealert.sandbox.preflight_risk import decide_risk, worst
    allow = decide_risk(_pkg("a"), report=_report(0), typo=_typo(), cfg=_cfg(), is_tty=True)
    block = decide_risk(
        _pkg("b"),
        report=_report(0),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    warn = decide_risk(
        _pkg("c"),
        report=_report(50),
        typo=_typo(),
        cfg=_cfg(risk_threshold=25, on_high_risk="warn"),
        is_tty=True,
    )
    assert worst([allow, warn, block]).action == "block"
    assert worst([allow, warn]).action == "warn"
    assert worst([allow]).action == "allow"


def test_unknown_distance_is_not_rendered_as_none():
    """A None distance must not leak into the reason as the literal "None".

    The gating logic at line 69 already anticipates distance=None, so the message
    has to as well. The built-in detector always sets a distance alongside a match,
    but TyposquatResult is a public dataclass on the plugin-visible surface.
    """
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(20),
        typo=_typo(True, "requests", None, 20),
        cfg=_cfg(),
        is_tty=True,
    )
    assert "None" not in d.reason
    # The actionable part — which package it resembles — must survive.
    assert "requests" in d.reason


def test_known_distance_is_still_reported():
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(20),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(),
        is_tty=True,
    )
    assert "distance 1" in d.reason


def test_unknown_distance_does_not_gate():
    """An unknown distance cannot satisfy typosquat_max_distance, so it only warns."""
    from packagealert.sandbox.preflight_risk import decide_risk
    d = decide_risk(
        _pkg(),
        report=_report(20),
        typo=_typo(True, "requests", None, 20),
        cfg=_cfg(on_typosquat="block"),
        is_tty=True,
    )
    assert d.action == "warn"


# --- ACTION_RANK must cover every action that can reach it ----------------------
#
# ACTION_RANK was annotated dict[str, int], so a type checker could not object to
# ranking an action with no entry. Worse, the gate action was declared as three
# independent Literals with the same members — config.CooldownAction,
# preflight_risk.RiskAction, and an anonymous one inside cooldown.CooldownDecision.
# Because decide_risk() feeds configured values into ACTION_RANK, adding a member to
# one copy alone produced a value with no rank and a KeyError inside max() that aborted
# the gate.
#
# The copies are now converged: config.CooldownAction is the single definition and
# RiskAction is an alias of it. These tests hold that line — the aliasing tests below
# fail if a parallel Literal is ever reintroduced, and the coverage tests fail if a
# member is added without a rank. This project has no type checker in CI, so the
# annotation alone would not catch either.


def test_action_rank_covers_every_risk_action():
    import typing

    from packagealert.sandbox.preflight_risk import ACTION_RANK, RiskAction

    assert set(ACTION_RANK) == set(typing.get_args(RiskAction))


def test_action_rank_covers_every_cooldown_action():
    """The real drift risk: config supplies CooldownAction values to this table.

    If CooldownAction gains a member, every ACTION_RANK lookup becomes a latent
    KeyError. Failing here points at the fix (add a rank, or converge the Literals)
    rather than surfacing as a crashed pre-flight gate.
    """
    import typing

    from packagealert.config import CooldownAction
    from packagealert.sandbox.preflight_risk import ACTION_RANK

    missing = set(typing.get_args(CooldownAction)) - set(ACTION_RANK)
    assert not missing, (
        f"config.CooldownAction members have no ACTION_RANK entry: {sorted(missing)}"
    )


def test_risk_action_resolves_to_the_shared_cooldown_action():
    """The two names must denote the same type.

    Note this cannot *prove* convergence: `typing` caches Literal instances, so two
    separate `Literal["allow", "warn", "prompt", "block"]` declarations are already
    `is`-identical. That makes this a necessary-but-insufficient check — the guarantee
    that only one declaration exists comes from
    test_the_gate_action_literal_is_defined_exactly_once below.
    """
    from packagealert.config import CooldownAction
    from packagealert.sandbox.preflight_risk import RiskAction

    assert RiskAction is CooldownAction


def test_cooldown_decision_uses_the_shared_action_literal():
    """The third copy: CooldownDecision.action was an inline Literal."""
    import typing

    from packagealert.config import CooldownAction
    from packagealert.sandbox.cooldown import CooldownDecision

    hints = typing.get_type_hints(CooldownDecision)
    assert hints["action"] == CooldownAction


def test_risk_decision_uses_the_shared_action_literal():
    import typing

    from packagealert.config import CooldownAction
    from packagealert.sandbox.preflight_risk import RiskDecision

    hints = typing.get_type_hints(RiskDecision)
    assert hints["action"] == CooldownAction


def test_the_gate_action_literal_is_defined_exactly_once():
    """No module may declare its own copy of the action literal.

    Greps the source rather than the runtime objects: a fresh inline
    `Literal["allow", "warn", "prompt", "block"]` anywhere would type-check and pass
    every other test here, while reopening the drift this converge closed.
    """
    from pathlib import Path

    root = Path(__file__).parent.parent.parent / "packagealert"
    literal = '"allow", "warn", "prompt", "block"'
    offenders = [
        str(p.relative_to(root))
        for p in root.rglob("*.py")
        if literal in p.read_text()
    ]
    assert offenders == ["config.py"], (
        f"the action literal must be declared only in config.py, found in: {offenders}"
    )


def test_action_rank_is_a_strict_total_order():
    """Distinct ranks, ordered allow < warn < prompt < block.

    `worst()` and the runner's sort both rely on this; equal ranks would make the
    selected decision depend on list order.
    """
    from packagealert.sandbox.preflight_risk import ACTION_RANK

    assert len(set(ACTION_RANK.values())) == len(ACTION_RANK)
    assert (
        ACTION_RANK["allow"]
        < ACTION_RANK["warn"]
        < ACTION_RANK["prompt"]
        < ACTION_RANK["block"]
    )


def test_every_configurable_action_field_is_rankable():
    """End to end over the actual defaults, not just the type declarations."""
    from packagealert.config import PreflightRiskConfig
    from packagealert.sandbox.preflight_risk import ACTION_RANK

    cfg = PreflightRiskConfig()
    for field in (
        "on_typosquat",
        "on_high_risk",
        "non_interactive_escalation",
        "on_post_install_risk",
    ):
        value = getattr(cfg, field)
        assert value in ACTION_RANK, f"{field}={value!r} has no ACTION_RANK entry"


# --- the escalation target must not be "prompt" ----------------------------------
#
# non_interactive_escalation was typed CooldownAction, so "prompt" was configurable.
# decide_risk escalates `prompt` to that value when stdin is not a TTY, so the
# escalation became a no-op: the action stayed `prompt` and all four gates
# (direct install, lockfile shell, post-install, cooldown) then call Confirm.ask()
# against a stdin nothing is attached to — hanging or failing CI, which is the exact
# outcome the setting exists to prevent. It is now typed NonInteractiveAction.


@pytest.mark.parametrize("cls_name", ["CooldownConfig", "PreflightRiskConfig"])
def test_non_interactive_escalation_rejects_prompt(cls_name):
    import packagealert.config as config_module

    cls = getattr(config_module, cls_name)
    with pytest.raises(ValidationError):
        cls(non_interactive_escalation="prompt")


@pytest.mark.parametrize("cls_name", ["CooldownConfig", "PreflightRiskConfig"])
@pytest.mark.parametrize("action", ["allow", "warn", "block"])
def test_non_interactive_escalation_accepts_the_meaningful_actions(cls_name, action):
    import packagealert.config as config_module

    cls = getattr(config_module, cls_name)
    assert cls(non_interactive_escalation=action).non_interactive_escalation == action


def test_non_interactive_action_excludes_only_prompt():
    """The narrower type must drop exactly one member, not diverge further."""
    import typing

    from packagealert.config import CooldownAction, NonInteractiveAction

    assert set(typing.get_args(NonInteractiveAction)) == set(
        typing.get_args(CooldownAction)
    ) - {"prompt"}


def test_every_non_interactive_action_is_rankable():
    """Whatever survives must still be usable by the gate's ordering."""
    import typing

    from packagealert.config import NonInteractiveAction
    from packagealert.sandbox.preflight_risk import ACTION_RANK

    for action in typing.get_args(NonInteractiveAction):
        assert action in ACTION_RANK


@pytest.mark.parametrize("escalation", ["allow", "warn", "block"])
def test_a_non_tty_decision_never_stays_prompt(escalation):
    """The property that matters, exercised through decide_risk itself.

    Whatever the escalation target, a non-interactive run must not come back with an
    action any gate would answer by calling Confirm.ask().
    """
    from packagealert.sandbox.preflight_risk import decide_risk

    d = decide_risk(
        _pkg("reqeusts"),
        report=_report(0),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="prompt", non_interactive_escalation=escalation),
        is_tty=False,
    )
    assert d.action != "prompt"
    assert d.action == escalation


def test_an_interactive_run_still_prompts():
    """The escalation must not leak into TTY sessions."""
    from packagealert.sandbox.preflight_risk import decide_risk

    d = decide_risk(
        _pkg("reqeusts"),
        report=_report(0),
        typo=_typo(True, "requests", 1, 20),
        cfg=_cfg(on_typosquat="prompt", non_interactive_escalation="block"),
        is_tty=True,
    )
    assert d.action == "prompt"
