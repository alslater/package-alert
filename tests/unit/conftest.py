"""Unit-test configuration: load built-in language modules into the registry so
tests that call scan_project() / scan_installed() via the registry dispatch path
get real language implementations rather than an empty registry."""
from __future__ import annotations

import pytest
from packagealert.languages import registry as lang_registry


@pytest.fixture(autouse=True)
def _load_language_registry():
    """Ensure built-in languages are registered for each test."""
    lang_registry.load()
    yield


@pytest.fixture(autouse=True)
def _reset_plugin_registry():
    """Reset the plugin registry singleton before each test.

    Prevents loaded plugins (including pa-central) from firing real HTTP calls
    during tests that don't explicitly configure the registry.
    """
    from packagealert.plugins.registry import plugin_registry

    def _reset():
        for task in list(plugin_registry._alert_tasks):
            task.cancel()
        plugin_registry._alert_tasks = []
        plugin_registry._plugins = []
        plugin_registry._classes = None

    _reset()
    yield
    _reset()
