from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    LanguageBase,
    SandboxPaths,
    Snapshot,
)
from packagealert.languages import registry as reg


@dataclass(eq=False)
class MockLanguage:
    name: str = "mock"
    ecosystems: list[str] = field(default_factory=lambda: ["Mock"])
    process_names: list[str] = field(default_factory=lambda: ["mocktool"])
    contract_version: int = CURRENT_CONTRACT_VERSION

    def parse_process_install(self, args): return None
    def parse_lockfile(self, path): return []
    def inspect_package(self, path): return None
    def cache_paths(self): return []
    def classify_cache_file(self, path): return None
    def heuristics(self): return []
    def lockfile_patterns(self): return []
    def detect_installed_packages(self, root): return []
    def sandbox_paths(self): return SandboxPaths()
    def snapshot(self, install_root): return Snapshot({})
    def detect_post_install(self, before, after): return []


@pytest.fixture(autouse=True)
def clear_registry(_load_language_registry):
    reg._registry.clear()
    reg._loaded = False
    yield
    reg._registry.clear()
    reg._loaded = False


def test_register_and_get():
    lang = MockLanguage()
    reg.register(lang)
    assert reg.get("mock") is lang


def test_all_returns_all_registered():
    a = MockLanguage(name="a", ecosystems=["A"], process_names=["a"])
    b = MockLanguage(name="b", ecosystems=["B"], process_names=["b"])
    reg.register(a)
    reg.register(b)
    assert set(reg.all_languages()) == {a, b}


def test_for_process_lookup():
    lang = MockLanguage(process_names=["pip", "pip3"])
    reg.register(lang)
    assert reg.for_process("pip") is lang
    assert reg.for_process("pip3") is lang
    assert reg.for_process("unknown") is None


def test_for_process_version_suffixed_variants():
    """for_process must resolve versioned/platform executable names to the canonical entry."""
    from packagealert.languages.registry import _normalise_process_name

    lang = MockLanguage(process_names=["pip", "pip3", "python", "python3", "npm"])
    reg.register(lang)

    # Version-suffixed executables
    assert reg.for_process("pip3.12") is lang      # pip3.12 -> pip3
    assert reg.for_process("pip-3.11") is lang     # pip-3.11 -> pip
    assert reg.for_process("python3.11") is lang   # python3.11 -> python3
    assert reg.for_process("python3.11.exe") is lang  # Windows + version

    # npm ships as npm-cli.js inside node
    assert reg.for_process("npm-cli.js") is lang

    # Windows .exe stripping
    assert reg.for_process("pip.exe") is lang
    assert reg.for_process("npm.exe") is lang

    # Uppercase / mixed case
    assert reg.for_process("PIP") is lang
    assert reg.for_process("NPM") is lang

    # Normalisation unit tests
    assert _normalise_process_name("Python3.11") == "python3"
    assert _normalise_process_name("pip-3.12") == "pip"
    assert _normalise_process_name("npm-cli.js") == "npm"
    assert _normalise_process_name("pip.exe") == "pip"
    assert _normalise_process_name("node.exe") == "node"


def test_for_ecosystem_lookup():
    lang = MockLanguage(ecosystems=["PyPI"])
    reg.register(lang)
    assert reg.for_ecosystem("PyPI") is lang
    assert reg.for_ecosystem("npm") is None


def test_duplicate_name_warns_and_overwrites(caplog):
    first = MockLanguage(name="dup")
    second = MockLanguage(name="dup")
    reg.register(first)
    with caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"):
        reg.register(second)
    assert "dup" in caplog.text
    assert reg.get("dup") is second


def test_older_contract_version_warns_and_registers(caplog):
    """A plugin with an older contract_version should warn but still register.

    v1 is the initial version so there are no shims to apply for pre-v1 plugins,
    but the warning machinery must still fire. When v2 is introduced, add shim
    entries to _VERSION_SHIMS and extend this test to verify the new defaults.
    """
    old = MockLanguage(contract_version=0)
    with caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"):
        reg.register(old)
    assert "contract version" in caplog.text.lower()
    assert reg.get("mock") is old


def test_newer_contract_version_warns_but_registers(caplog):
    new = MockLanguage(contract_version=999)
    with caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"):
        reg.register(new)
    assert "contract version" in caplog.text.lower()
    assert reg.get("mock") is not None


def test_missing_contract_version_treated_as_one(caplog):
    # Build a plain non-dataclass object with no contract_version to simulate
    # an old plugin that predates the contract_version field.
    class NoVersionLanguage:
        name = "mock"
        ecosystems = ["Mock"]
        process_names = ["mocktool"]

        def parse_process_install(self, args): return None
        def parse_lockfile(self, path): return []
        def inspect_package(self, path): return None
        def cache_paths(self): return []
        def classify_cache_file(self, path): return None
        def heuristics(self): return []
        def lockfile_patterns(self): return []
        def detect_installed_packages(self, root): return []
        def sandbox_paths(self): return SandboxPaths()
        def snapshot(self, install_root): return Snapshot({})
        def detect_post_install(self, before, after): return []

    lang = NoVersionLanguage()
    assert not hasattr(lang, "contract_version"), "test setup: attribute should be absent"
    with caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"):
        reg.register(lang)
    assert "contract_version" in caplog.text


def test_failed_plugin_load_warns_and_continues(caplog):
    good = MockLanguage(name="good", ecosystems=["Good"], process_names=["good"])

    bad_ep = MagicMock()
    bad_ep.name = "bad"
    bad_ep.load.side_effect = ImportError("missing dep")

    good_ep = MagicMock()
    good_ep.name = "good"
    good_ep.load.return_value = lambda: good

    with patch("importlib.metadata.entry_points", return_value=[bad_ep, good_ep]):
        with caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"):
            reg._load_plugins()

    assert "bad" in caplog.text
    assert reg.get("good") is good


def test_load_registers_builtins():
    reg.load()
    assert reg.get("python") is not None
    assert reg.get("node") is not None
    assert reg.get("php") is not None


def test_load_idempotent_with_existing_language(caplog):
    """load() must register built-ins even when a language was pre-registered."""
    pre = MockLanguage(name="pre")
    reg.register(pre)
    # _loaded is False and _registry is non-empty; old guard would have bailed here
    reg.load()
    assert reg.get("python") is not None


def test_load_retries_after_failure(monkeypatch, caplog):
    """If load() raises during registration, _loaded stays False so the next call retries."""
    call_count = 0
    real_register = reg.register

    def failing_register(lang):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("simulated registration failure")
        real_register(lang)

    monkeypatch.setattr(reg, "register", failing_register)
    with caplog.at_level("ERROR"):
        reg.load()
    assert not reg._loaded

    monkeypatch.undo()
    reg.load()
    assert reg.get("python") is not None
    assert reg._loaded


def test_for_process_buggy_plugin_skipped(caplog):
    """for_process() must skip a language whose process_names raises and return the good one."""
    good = MockLanguage(name="good", process_names=["pip"])

    class BrokenProcessNames:
        name = "bad"
        contract_version = 1

        @property
        def process_names(self):
            raise RuntimeError("boom")

        ecosystems = ["Bad"]
        def lockfile_patterns(self): return []
        def parse_lockfile(self, p): return []
        def parse_process_install(self, a): return None
        def inspect_package(self, p): return None
        def cache_paths(self): return []
        def classify_cache_file(self, p): return None
        def heuristics(self): return []
        def detect_installed_packages(self, r): return []
        def sandbox_paths(self): return SandboxPaths()
        def snapshot(self, r): return Snapshot({})
        def detect_post_install(self, b, a): return []

    reg.register(BrokenProcessNames())
    reg.register(good)

    with caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"):
        result = reg.for_process("pip")

    assert result is good
    assert "bad" in caplog.text


def test_for_ecosystem_buggy_plugin_skipped(caplog):
    """for_ecosystem() must skip a language whose ecosystems raises and return the good one."""
    good = MockLanguage(name="good", ecosystems=["PyPI"])

    class BrokenEcosystems:
        name = "bad"
        contract_version = 1
        process_names = ["bad"]

        @property
        def ecosystems(self):
            raise RuntimeError("boom")

        def lockfile_patterns(self): return []
        def parse_lockfile(self, p): return []
        def parse_process_install(self, a): return None
        def inspect_package(self, p): return None
        def cache_paths(self): return []
        def classify_cache_file(self, p): return None
        def heuristics(self): return []
        def detect_installed_packages(self, r): return []
        def sandbox_paths(self): return SandboxPaths()
        def snapshot(self, r): return Snapshot({})
        def detect_post_install(self, b, a): return []

    reg.register(BrokenEcosystems())
    reg.register(good)

    with caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"):
        result = reg.for_ecosystem("PyPI")

    assert result is good
    assert "bad" in caplog.text


def test_for_lockfile_buggy_plugin_skipped(caplog):
    """for_lockfile() must skip a language whose lockfile_patterns() raises and return the good one."""
    good = MockLanguage(name="good")
    good.lockfile_patterns = lambda: ["requirements.txt"]
    bad = MockLanguage(name="bad")
    bad.lockfile_patterns = MagicMock(side_effect=RuntimeError("patterns boom"))

    reg.register(bad)
    reg.register(good)

    with caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"):
        result = reg.for_lockfile("requirements.txt")

    assert result is good
    assert "bad" in caplog.text


class TestForLockfile:
    def setup_method(self):
        reg.load()

    def test_matches_bare_filename(self):
        lang = reg.for_lockfile("package-lock.json")
        assert lang is not None
        assert lang.name == "node"

    def test_matches_absolute_path_with_basename(self):
        lang = reg.for_lockfile(Path("/some/project/package-lock.json"))
        assert lang is not None
        assert lang.name == "node"

    def test_matches_subdir_pattern_via_absolute_path(self):
        lang = reg.for_lockfile(Path("/project/requirements/base.txt"))
        assert lang is not None
        assert lang.name == "python"

    def test_matches_subdir_pattern_via_relative_path(self):
        lang = reg.for_lockfile(Path("myapp/requirements/base.txt"))
        assert lang is not None
        assert lang.name == "python"

    def test_bare_filename_does_not_match_subdir_pattern(self):
        # "base.txt" alone must NOT match "requirements/base.txt"
        assert reg.for_lockfile("base.txt") is None

    def test_returns_none_for_unknown_file(self):
        assert reg.for_lockfile("unknown-lockfile.xyz") is None


def test_publication_date_url_python():
    from packagealert.languages import registry
    registry.load()
    lang = registry.for_ecosystem("PyPI")
    assert lang is not None
    url = lang.publication_date_url("requests", "2.31.0")
    assert url == "https://pypi.org/pypi/requests/2.31.0/json"


def test_publication_date_url_node():
    from packagealert.languages import registry
    registry.load()
    lang = registry.for_ecosystem("npm")
    assert lang is not None
    url = lang.publication_date_url("lodash", "4.17.21")
    assert url == "https://registry.npmjs.org/lodash"


def test_publication_date_url_node_scoped():
    from packagealert.languages import registry
    registry.load()
    lang = registry.for_ecosystem("npm")
    assert lang is not None
    url = lang.publication_date_url("@scope/pkg", "1.0.0")
    assert url == "https://registry.npmjs.org/@scope%2Fpkg"


def test_latest_version_url_node_scoped():
    from packagealert.languages.node import NodeLanguage
    lang = NodeLanguage()
    url = lang.latest_version_url("@types/node")
    assert url == "https://registry.npmjs.org/@types%2Fnode/latest"


def test_publication_date_url_php():
    from packagealert.languages import registry
    registry.load()
    lang = registry.for_ecosystem("Packagist")
    assert lang is not None
    url = lang.publication_date_url("monolog/monolog", "3.5.0")
    assert url == "https://repo.packagist.org/p2/monolog/monolog.json"


def test_publication_date_url_base_default_returns_none():
    # The default implementation on LanguageBase must return None
    # Use a mock that doesn't override publication_date_url
    from unittest.mock import MagicMock
    mock_lang = MagicMock(spec=LanguageBase)
    # Call the actual default method from LanguageBase directly
    result = LanguageBase.publication_date_url(mock_lang, "requests", "1.0.0")
    assert result is None


def test_php_latest_version_url():
    from packagealert.languages.php import PhpLanguage
    lang = PhpLanguage()
    assert lang.latest_version_url("monolog/monolog") == "https://repo.packagist.org/p2/monolog/monolog.json"


def test_php_latest_version_url_no_slash_returns_none():
    from packagealert.languages.php import PhpLanguage
    lang = PhpLanguage()
    assert lang.latest_version_url("invalidpackage") is None


def test_php_latest_version_parse_returns_first_entry():
    from packagealert.languages.php import PhpLanguage
    lang = PhpLanguage()
    data = {
        "packages": {
            "monolog/monolog": [
                {"version": "3.10.0", "time": "2026-01-02T08:56:05+00:00"},
                {"version": "3.9.0",  "time": "2025-03-24T10:02:05+00:00"},
            ]
        }
    }
    # First entry (newest) should be returned
    assert lang.latest_version_parse(data, "monolog/monolog") == "3.10.0"


def test_php_latest_version_parse_empty_returns_none():
    from packagealert.languages.php import PhpLanguage
    lang = PhpLanguage()
    assert lang.latest_version_parse({}, "monolog/monolog") is None
