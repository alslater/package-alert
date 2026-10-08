from pathlib import Path

from packagealert.languages.python_fix.uv import commands
from packagealert.remediate.planner import FixPlan, HeldFix, PlannedFix


def _p(pkg, target):
    return PlannedFix(package=pkg, version="1", target=target, direct=True, path=[pkg],
                      advisories=["A"], left_open=[], cooldown_checked=True)


def test_one_lock_command_with_exact_pins_then_sync():
    plan = FixPlan(planned=[_p("urllib3", "2.8.0"), _p("django", "5.2.17")])
    assert commands(plan) == [
        ["uv", "lock", "--upgrade-package", "django==5.2.17", "--upgrade-package", "urllib3==2.8.0"],
        ["uv", "sync"],
    ]


def test_nothing_planned_means_no_commands():
    held = HeldFix(package="x", version="1", target=None, reason="no fix known", advisories=["A"])
    assert commands(FixPlan(held=[held])) == []


def test_parent_pin_is_exact_and_beside_its_item():
    item = PlannedFix(package="pip", version="25.0", target="26.2.0", direct=False, path=["pip"],
                      advisories=["A"], left_open=[], cooldown_checked=True,
                      verified=True, parent=("chalice", "2.0.0"))
    assert commands(FixPlan(planned=[item])) == [
        ["uv", "lock", "--upgrade-package", "pip==26.2.0", "--upgrade-package", "chalice==2.0.0"],
        ["uv", "sync"],
    ]


def test_separate_plan_prints_only_the_first_lock():
    a = PlannedFix(package="a", version="1", target="2", direct=True, path=["a"], advisories=["X"],
                   left_open=[], cooldown_checked=True, verified=True)
    b = PlannedFix(package="b", version="1", target="3", direct=True, path=["b"], advisories=["Y"],
                   left_open=[], cooldown_checked=True, verified=True)
    assert commands(FixPlan(planned=[b, a], separate=True)) == [
        ["uv", "lock", "--upgrade-package", "a==2"],
        ["uv", "sync"],
    ]


def _verified(pkg, target, parent=None):
    return PlannedFix(package=pkg, version="1", target=target, direct=True, path=[pkg], advisories=["A"],
                      left_open=[], cooldown_checked=True, verified=True, parent=parent)


def test_combined_mode_puts_each_parent_pin_beside_its_own_item():
    plan = FixPlan(planned=[_verified("b", "3", ("pb", "9")), _verified("a", "2", ("pa", "8"))])
    assert commands(plan) == [
        ["uv", "lock", "--upgrade-package", "a==2", "--upgrade-package", "pa==8",
         "--upgrade-package", "b==3", "--upgrade-package", "pb==9"],
        ["uv", "sync"],
    ]


def test_separate_mode_keeps_the_first_items_parent_pin_only():
    plan = FixPlan(planned=[_verified("b", "3", ("pb", "9")), _verified("a", "2", ("pa", "8"))], separate=True)
    assert commands(plan) == [
        ["uv", "lock", "--upgrade-package", "a==2", "--upgrade-package", "pa==8"],
        ["uv", "sync"],
    ]


def test_another_project_is_named_in_both_commands():
    plan = FixPlan(planned=[_p("urllib3", "2.8.0")])
    assert commands(plan, Path("/srv/my project")) == [
        ["uv", "--directory", "/srv/my project", "lock", "--upgrade-package", "urllib3==2.8.0"],
        ["uv", "--directory", "/srv/my project", "sync"],
    ]


def test_sync_flags_are_appended_to_the_sync_command():
    plan = FixPlan(planned=[_p("urllib3", "2.8.0")])
    assert commands(plan, Path("/p"), ("--extra", "dev"))[1] == ["uv", "--directory", "/p", "sync", "--extra", "dev"]
