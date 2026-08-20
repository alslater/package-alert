from packagealert.sandbox.escalation import escalate_if_prompt


def test_prompt_escalates_when_not_tty():
    assert escalate_if_prompt("prompt", is_tty=False, non_interactive_escalation="block") == "block"


def test_prompt_escalates_to_configured_target():
    assert escalate_if_prompt("prompt", is_tty=False, non_interactive_escalation="allow") == "allow"
    assert escalate_if_prompt("prompt", is_tty=False, non_interactive_escalation="warn") == "warn"


def test_prompt_passes_through_when_tty():
    assert escalate_if_prompt("prompt", is_tty=True, non_interactive_escalation="block") == "prompt"


def test_non_prompt_actions_pass_through_regardless_of_tty():
    for action in ("allow", "warn", "block"):
        assert escalate_if_prompt(action, is_tty=False, non_interactive_escalation="block") == action
        assert escalate_if_prompt(action, is_tty=True, non_interactive_escalation="block") == action
