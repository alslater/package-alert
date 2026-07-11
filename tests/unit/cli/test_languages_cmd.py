from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from packagealert.cli.app import app
from packagealert.languages import registry as _registry_module

runner = CliRunner()


def test_languages_list_shows_all_languages():
    result = runner.invoke(app, ["languages", "list"])
    assert result.exit_code == 0, result.output
    assert "python" in result.output
    assert "node" in result.output
    assert "php" in result.output


def test_languages_list_shows_ecosystems():
    result = runner.invoke(app, ["languages", "list"])
    assert result.exit_code == 0, result.output
    assert "PyPI" in result.output
    assert "npm" in result.output
    assert "Packagist" in result.output


def test_languages_info_python():
    result = runner.invoke(app, ["languages", "info", "python"])
    assert result.exit_code == 0, result.output
    assert "PyPI" in result.output
    assert "pip" in result.output


def test_languages_info_unknown():
    result = runner.invoke(app, ["languages", "info", "notarealname"])
    assert result.exit_code != 0
    assert "Unknown language" in result.output


def test_languages_info_shows_top_packages_url():
    result = runner.invoke(app, ["languages", "info", "python"])
    assert result.exit_code == 0, result.output
    assert "hugovk" in result.output


class _BadLang:
    """Minimal language stub whose every property/method raises."""

    name = "badlang"

    @property
    def ecosystems(self):
        raise RuntimeError("ecosystems boom")

    @property
    def process_names(self):
        raise RuntimeError("process_names boom")

    def lockfile_patterns(self):
        raise RuntimeError("lockfile_patterns boom")

    def cache_paths(self):
        raise RuntimeError("cache_paths boom")

    def top_packages_url(self):
        raise RuntimeError("top_packages_url boom")

    author = "external"


def test_languages_list_skips_buggy_plugin_row():
    """languages list must not crash when a plugin property raises; show [error] instead."""
    _registry_module.load()
    original = _registry_module.all_languages()
    patched = list(original) + [_BadLang()]

    with patch.object(_registry_module, "all_languages", return_value=patched):
        result = runner.invoke(app, ["languages", "list"])

    assert result.exit_code == 0, result.output
    # Good languages still appear
    assert "python" in result.output
    # The bad plugin row is present (with error placeholders) instead of crashing
    assert "badlang" in result.output
    assert "[error]" in result.output


def test_languages_info_buggy_lockfile_patterns():
    """languages info must not crash when lockfile_patterns() raises."""
    _registry_module.load()
    lang = _registry_module.get("python")
    assert lang is not None

    with patch.object(lang, "lockfile_patterns", side_effect=RuntimeError("boom")):
        result = runner.invoke(app, ["languages", "info", "python"])

    assert result.exit_code == 0, result.output
    assert "[error]" in result.output


def test_languages_info_buggy_cache_paths():
    """languages info must not crash when cache_paths() raises."""
    _registry_module.load()
    lang = _registry_module.get("python")
    assert lang is not None

    with patch.object(lang, "cache_paths", side_effect=RuntimeError("boom")):
        result = runner.invoke(app, ["languages", "info", "python"])

    assert result.exit_code == 0, result.output
    assert "[error]" in result.output


def test_languages_info_buggy_top_packages_url():
    """languages info must not crash when top_packages_url() raises."""
    _registry_module.load()
    lang = _registry_module.get("python")
    assert lang is not None

    with patch.object(lang, "top_packages_url", side_effect=RuntimeError("boom")):
        result = runner.invoke(app, ["languages", "info", "python"])

    assert result.exit_code == 0, result.output
    assert "[error]" in result.output


def test_languages_info_shows_available_flags():
    """languages info renders a flags table when available_flags() returns valid entries."""
    _registry_module.load()
    lang = _registry_module.get("python")
    assert lang is not None

    with patch.object(lang, "available_flags", return_value=[("uv-auth", "Snapshot uv credentials")]):
        result = runner.invoke(app, ["languages", "info", "python"])

    assert result.exit_code == 0, result.output
    assert "Available flags:" in result.output
    assert "python:uv-auth" in result.output
    assert "Snapshot uv credentials" in result.output


def test_languages_info_empty_available_flags():
    """languages info prints 'none' when available_flags() returns an empty list."""
    _registry_module.load()
    lang = _registry_module.get("python")
    assert lang is not None

    with patch.object(lang, "available_flags", return_value=[]):
        result = runner.invoke(app, ["languages", "info", "python"])

    assert result.exit_code == 0, result.output
    assert "Available flags: none" in result.output


def test_languages_info_invalid_flag_entries_show_error():
    """languages info shows [error] when all available_flags() entries are invalid."""
    _registry_module.load()
    lang = _registry_module.get("python")
    assert lang is not None

    with patch.object(lang, "available_flags", return_value=["not-a-tuple", 42, (1, 2)]):
        result = runner.invoke(app, ["languages", "info", "python"])

    assert result.exit_code == 0, result.output
    assert "[error]" in result.output


def test_languages_info_available_flags_raises():
    """languages info shows [error] and does not crash when available_flags() raises."""
    _registry_module.load()
    lang = _registry_module.get("python")
    assert lang is not None

    with patch.object(lang, "available_flags", side_effect=RuntimeError("flags boom")):
        result = runner.invoke(app, ["languages", "info", "python"])

    assert result.exit_code == 0, result.output
    assert "[error]" in result.output
