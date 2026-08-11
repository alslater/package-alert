"""
Proves the full third-party plugin discovery path:
  importlib.metadata (DistributionFinder) → entry_points() → register() →
  popularity_ecosystem() → PopularityClient ecosystem map.

A synthetic DistributionFinder is inserted into sys.meta_path so that
importlib.metadata.entry_points() returns a real EntryPoint for the stub
language class — no pip install required.
"""
from __future__ import annotations

import importlib.metadata
import sys
from importlib.metadata import DistributionFinder
from pathlib import Path
from typing import ClassVar

import pytest

from packagealert.languages import registry as lang_registry
from packagealert.osv.popularity import PopularityClient


class _StubLanguage:
    name = "stub_lang"
    ecosystems: ClassVar[list[str]] = ["stubeco"]
    process_names: ClassVar[list[str]] = []
    contract_version = 3
    author = "test"
    repository = ""

    def popularity_ecosystem(self) -> str | None:
        return "STUBECO"

    def parse_process_install(self, args): return None
    def parse_lockfile(self, path): return []
    def inspect_package(self, path): return None
    def cache_paths(self): return []
    def classify_cache_file(self, path): return None
    def cache_file_globs(self): return ["**/*"]
    def heuristics(self): return []
    def lockfile_patterns(self): return []
    def detect_installed_packages(self, root): return []
    def sandbox_paths(self):
        from packagealert.languages.base import SandboxPaths
        return SandboxPaths()
    def sandbox_env(self): return []
    def top_packages_url(self): return None
    async def fetch_top_packages(self, client, url): return None
    def top_packages_fallback(self): return []
    def snapshot(self, root):
        from packagealert.languages.base import Snapshot
        return Snapshot(data={})
    def detect_post_install(self, before, after): return []


class _StubDistribution(importlib.metadata.Distribution):
    """Synthetic in-process distribution exposing one entry point."""

    def read_text(self, filename: str) -> str | None:
        if filename == "METADATA":
            return "Metadata-Version: 2.1\nName: stub-lang-plugin\nVersion: 0.1.0\n"
        if filename == "entry_points.txt":
            module = _StubLanguage.__module__
            qualname = _StubLanguage.__qualname__
            return (
                "[package_alert.languages]\n"
                f"stub_lang = {module}:{qualname}\n"
            )
        return None

    def locate_file(self, path):
        return Path(__file__).parent / path


class _StubFinder(DistributionFinder):
    """sys.meta_path finder that exposes _StubDistribution."""

    def find_distributions(
        self, context: DistributionFinder.Context = DistributionFinder.Context()  # noqa: B008 — matches base class's real signature
    ):
        yield _StubDistribution()


@pytest.fixture()
def stub_plugin_installed():
    """Insert the synthetic distribution into sys.meta_path for the test."""
    finder = _StubFinder()
    sys.meta_path.append(finder)
    # Invalidate importlib.metadata caches so our finder is seen
    importlib.metadata.PathDistribution.__init_subclass__()
    try:
        # Python 3.12+: clear the entry_points cache
        importlib.metadata.packages_distributions.cache_clear()  # type: ignore[attr-defined]
    except AttributeError:
        pass
    yield
    sys.meta_path.remove(finder)


@pytest.fixture(autouse=True)
def _reset_registry():
    original_registry = dict(lang_registry._registry)
    original_loaded = lang_registry._loaded
    lang_registry._registry.clear()
    lang_registry._loaded = False
    yield
    lang_registry._registry.clear()
    lang_registry._registry.update(original_registry)
    lang_registry._loaded = original_loaded


@pytest.mark.integration
def test_third_party_plugin_popularity_ecosystem_registered(stub_plugin_installed):
    """Full discovery path: DistributionFinder → entry_points() → registry map."""
    lang_registry.load()

    eco_map = lang_registry.popularity_ecosystem_map()
    assert eco_map.get("stubeco") == "STUBECO", (
        f"Expected 'stubeco' -> 'STUBECO' in ecosystem map, got: {eco_map}"
    )


@pytest.mark.integration
def test_popularity_client_uses_ecosystem_map_from_plugin(stub_plugin_installed):
    """PopularityClient built from the registry map routes fetches using the plugin's system name."""
    lang_registry.load()

    eco_map = lang_registry.popularity_ecosystem_map()
    client = PopularityClient(eco_map)

    assert client.supports_ecosystem("stubeco")
    assert not client.supports_ecosystem("packagist")

    # Verify the system name fed to the HTTP layer is what the plugin declared.
    # We inspect _ecosystem_map directly rather than making a live network call.
    assert client._ecosystem_map.get("stubeco") == "STUBECO"
