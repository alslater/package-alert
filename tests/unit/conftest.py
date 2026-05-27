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
