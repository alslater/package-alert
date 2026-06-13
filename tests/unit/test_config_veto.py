"""Tests for _apply_config_veto: the --config override veto logic in app.py."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock


def _make_cls(name: str, vetoes: bool) -> type:
    cls = MagicMock()
    cls.name = name
    cls.refuses_config_override.return_value = vetoes
    return cls


def _veto(config, default_enabled, candidate_enabled, default_classes, candidate_classes):
    """Run _apply_config_veto with fully controlled read_enabled_plugins and load_entry_points."""
    from packagealert.cli.app import _apply_config_veto

    def read_enabled_plugins(path):
        return default_enabled if path is None else candidate_enabled

    def load_entry_points(only):
        if only == set(default_enabled):
            return {cls.name: cls for cls in default_classes}
        return {cls.name: cls for cls in candidate_classes}

    return _apply_config_veto(config, read_enabled_plugins, load_entry_points)


_CFG = Path("/tmp/candidate.toml")


def test_no_veto_returns_config():
    cls_a = _make_cls("plugin-a", vetoes=False)
    result = _veto(_CFG, ["plugin-a"], ["plugin-a"], [cls_a], [])
    assert result == _CFG


def test_default_veto_returns_none():
    cls_v = _make_cls("pa-central", vetoes=True)
    result = _veto(_CFG, ["pa-central"], ["pa-central"], [cls_v], [])
    assert result is None


def test_default_veto_prevents_candidate_plugin_import():
    """Candidate-only plugin must not be loaded when default plugin vetoes."""
    cls_v = _make_cls("pa-central", vetoes=True)
    candidate_imported = []

    def read_enabled_plugins(path):
        return ["pa-central"] if path is None else ["pa-central", "evil-plugin"]

    def load_entry_points(only):
        if "evil-plugin" in only:
            candidate_imported.append(True)
        if only == {"pa-central"}:
            return {"pa-central": cls_v}
        return {}

    from packagealert.cli.app import _apply_config_veto
    result = _apply_config_veto(_CFG, read_enabled_plugins, load_entry_points)

    assert result is None
    assert candidate_imported == [], "candidate-only plugin was imported despite default veto"


def test_candidate_only_veto_returns_none():
    """A veto plugin introduced only in the candidate config is still honoured."""
    cls_v = _make_cls("new-veto", vetoes=True)
    result = _veto(_CFG, [], ["new-veto"], [], [cls_v])
    assert result is None


def test_candidate_only_non_veto_returns_config():
    cls_a = _make_cls("new-plugin", vetoes=False)
    result = _veto(_CFG, [], ["new-plugin"], [], [cls_a])
    assert result == _CFG


def test_refuses_config_override_exception_treated_as_veto():
    cls_err = _make_cls("broken-plugin", vetoes=False)
    cls_err.refuses_config_override.side_effect = RuntimeError("boom")
    result = _veto(_CFG, ["broken-plugin"], [], [cls_err], [])
    assert result is None


def test_default_veto_plugin_not_rechecked_in_second_pass():
    """Default-config plugins should not appear in the candidate-only set."""
    cls_v = _make_cls("pa-central", vetoes=False)  # does NOT veto
    second_pass_names = []

    def read_enabled_plugins(path):
        return ["pa-central"]

    def load_entry_points(only):
        second_pass_names.extend(only)
        return {"pa-central": cls_v} if "pa-central" in only else {}

    from packagealert.cli.app import _apply_config_veto
    result = _apply_config_veto(_CFG, read_enabled_plugins, load_entry_points)

    assert result == _CFG
    # pa-central appears in first pass; second pass set should exclude it
    assert second_pass_names.count("pa-central") == 1
