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


@pytest.fixture(autouse=True)
def _no_npm_registry_lookups(monkeypatch):
    """pa fix's npm parent-upgrade lookup reads the live registry; a unit test must stub it."""
    from packagealert.languages.node_fix import npm_trial

    async def _refuse(name):
        # pytest.fail is a BaseException, so verification's own error handling cannot swallow it.
        pytest.fail(f"a unit test reached the npm registry for {name}; stub fetch_package_document")

    monkeypatch.setattr(npm_trial, "fetch_package_document", _refuse)


@pytest.fixture(autouse=True)
def _no_user_npmrc(monkeypatch, tmp_path):
    """The Node plugin reads the user's ~/.npmrc and npm_config_* variables for registry provenance;
    tests must not depend on either."""
    import os

    from packagealert.languages import node

    monkeypatch.setattr(node, "_user_npmrc", lambda: tmp_path / "no-user-npmrc")
    for key in [k for k in os.environ if k.lower().startswith("npm_config_")]:
        monkeypatch.delenv(key)
