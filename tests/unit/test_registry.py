from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

from packagealert.languages import registry as reg
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    LanguageBase,
    PreRunResult,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
)


@dataclass(eq=False)
class MockLanguage:
    name: str = "mock"
    ecosystems: list[str] = field(default_factory=lambda: ["Mock"])
    process_names: list[str] = field(default_factory=lambda: ["mocktool"])
    contract_version: int = CURRENT_CONTRACT_VERSION
    author: str = "mock"
    repository: str = "mock"

    def parse_process_install(self, args): return None
    def parse_package_spec(self, raw): return raw, None
    def serialise_package_spec(self, name, version): return f"{name}=={version}" if version else name
    def parse_lockfile(self, path): return []
    def inspect_package(self, path): return None
    def cache_paths(self): return []
    def classify_cache_file(self, path): return None
    def cache_file_globs(self): return []
    def heuristics(self): return []
    def lockfile_patterns(self): return []
    def detect_installed_packages(self, root): return []
    def sandbox_paths(self): return SandboxPaths()
    def sandbox_env(self): return []
    def available_flags(self): return []
    def top_packages_url(self): return None
    async def fetch_top_packages(self, client, url): return None
    def top_packages_fallback(self): return []
    def publication_date_url(self, name, version): return None
    def publication_date_parse(self, data, version): return None
    def osv_ecosystem(self): return None
    def normalise_name(self, name): return name.lower()
    def popularity_ecosystem(self): return None
    def prepare_sandbox_argv(self, argv, cwd): return argv
    def sandbox_extra_ro_paths(self, argv, cwd): return []
    def sandbox_extra_write_paths(self, argv, cwd): return []
    def post_run_scan_targets(self, parsed, cwd): return []
    def pre_run_check(self, parsed, cwd, flags=frozenset()): return PreRunResult(ok=True)
    def configure_sandbox(self, parsed, cwd, flags, targets, home_ro, sandbox_env): return None
    def configure_sandbox_writable(self, parsed, cwd, flags, targets): return []
    def configure_sandbox_writable_warning(self, parsed, cwd, flags, targets): return None
    def resolve_sandbox_targets(self, parsed, cwd): return SandboxTargets()
    def prepare_sandbox_env(self, parsed, cwd, env): return []
    def shell_environment(self, cwd): return ShellEnvironment()
    def detect_new_packages(self, new_paths, walk_root): return []
    def home_ro_paths(self): return []
    def resolve_package_dir(self, package_name, project_path, site_packages_dir, version=None): return []
    def resolve_package_dir_manifest_warning(self, package_name, project_path, site_packages_dir, version=None): return None
    def latest_version_url(self, name): return None
    def latest_version_parse(self, data, name): return None
    def package_manager_names(self): return []
    def project_shim_names(self): return self.package_manager_names()
    def interpreter_names(self): return []
    def interpreter_shim_script(self, real, pa): return None
    def project_bin_dirs(self, root): return []
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
    # Identity is not asserted: a plugin missing post-v0 contract methods is served
    # through a _ShimmedLanguage proxy rather than being mutated, so `is old` would
    # fail. What must hold is that the registered object behaves as the plugin.
    registered = reg.get("mock")
    assert registered is not None
    assert registered.name == old.name
    assert registered.ecosystems == old.ecosystems


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
        ecosystems: ClassVar[list[str]] = ["Mock"]
        process_names: ClassVar[list[str]] = ["mocktool"]

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
        # Deliberately missing contract_version and other newer LanguageBase
        # members to exercise the "predates contract_version" registration path.
        reg.register(lang)  # type: ignore[reportArgumentType]
    assert "contract_version" in caplog.text


def test_failed_plugin_load_warns_and_continues(caplog):
    good = MockLanguage(name="good", ecosystems=["Good"], process_names=["good"])

    bad_ep = MagicMock()
    bad_ep.name = "bad"
    bad_ep.load.side_effect = ImportError("missing dep")

    good_ep = MagicMock()
    good_ep.name = "good"
    good_ep.load.return_value = lambda: good

    with (
        patch("importlib.metadata.entry_points", return_value=[bad_ep, good_ep]),
        caplog.at_level(logging.WARNING, logger="packagealert.languages.registry"),
    ):
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

        ecosystems: ClassVar[list[str]] = ["Bad"]
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

    # Deliberately missing several LanguageBase members to exercise the
    # "buggy plugin is skipped" path — must stay incomplete.
    reg.register(BrokenProcessNames())  # type: ignore[reportArgumentType]
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
        process_names: ClassVar[list[str]] = ["bad"]

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

    # Deliberately missing several LanguageBase members to exercise the
    # "buggy plugin is skipped" path — must stay incomplete.
    reg.register(BrokenEcosystems())  # type: ignore[reportArgumentType]
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


# --- version shims must be attached as bound methods ---------------------------
#
# _VERSION_SHIMS entries are `lambda self, ...` callables, which is only correct
# because _apply_shims attaches them with types.MethodType(fn, lang) so `self` is
# injected. A plain setattr would leave them unbound and every call would raise
# TypeError — silently disabling the shimmed capability for older plugins, since
# every call site guards with try/except. Nothing pinned that coupling.


class _V4Plugin:
    """A plugin predating every v5 hook."""

    name = "shimtest"
    ecosystems: ClassVar[list[str]] = ["shimtest-eco"]
    process_names: ClassVar[list[str]] = ["shimtool"]
    contract_version = 4
    author = "third-party"
    repository = "example.com"


def _register_v4(monkeypatch) -> LanguageBase:
    from packagealert.languages import registry as reg

    monkeypatch.setattr(reg, "_registry", dict(reg._registry))
    plugin = _V4Plugin()
    # Deliberately predates every v5 hook to exercise the shim machinery below.
    reg.register(plugin)  # type: ignore[reportArgumentType]
    lang = reg.for_ecosystem("shimtest-eco")
    assert lang is not None
    return lang


def test_shimmed_methods_are_callable_with_the_real_signatures(monkeypatch):
    lang = _register_v4(monkeypatch)
    # Each is called exactly as its production call site does — no explicit self.
    assert lang.publication_date_parse({"any": 1}, "1.0") is None
    assert lang.osv_ecosystem() is None
    assert lang.normalise_name("A.B_c") == "a.b_c"


def test_shims_are_bound_methods_not_bare_functions(monkeypatch):
    """Pins the MethodType attachment: a bare setattr would break the calls above."""
    import inspect

    lang = _register_v4(monkeypatch)
    for name in ("publication_date_parse", "osv_ecosystem", "normalise_name"):
        attr = getattr(lang, name)
        assert inspect.ismethod(attr), f"{name} is not bound — self will not be injected"
        # Bound to the *wrapped plugin*, not the proxy serving the shim: a shim that
        # calls another contract method must reach the real implementation.
        assert attr.__self__ is getattr(lang, "_lang", lang)


def test_shimmed_plugin_works_through_the_cooldown_call_site(monkeypatch):
    from packagealert.sandbox.cooldown import _parse_publication_date

    _register_v4(monkeypatch)
    # Fails open (no publication date) rather than raising.
    assert _parse_publication_date({"x": 1}, ecosystem="shimtest-eco", version="1.0") is None


def test_shimmed_plugin_still_gets_fixed_versions(monkeypatch):
    """osv_ecosystem() shimmed to None must fall back to the raw ecosystem name."""
    from packagealert.osv.client import _extract_fixed_versions

    _register_v4(monkeypatch)
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "shimtest-eco", "name": "serde"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ]
    }
    assert _extract_fixed_versions(vuln, "serde", "shimtest-eco") == ["1.2.3"]


def test_a_plugin_implementing_a_hook_is_not_shimmed(monkeypatch):
    """Shims must never override a real implementation."""
    from packagealert.languages import registry as reg

    class _V4WithHook(_V4Plugin):
        ecosystems: ClassVar[list[str]] = ["shimtest-impl"]

        def osv_ecosystem(self):
            return "MyRegistry"

    monkeypatch.setattr(reg, "_registry", dict(reg._registry))
    # _V4Plugin (and thus _V4WithHook) deliberately predates every v5 hook.
    reg.register(_V4WithHook())  # type: ignore[reportArgumentType]
    lang = reg.for_ecosystem("shimtest-impl")
    assert lang is not None
    assert lang.osv_ecosystem() == "MyRegistry"


def test_raising_descriptor_does_not_abort_registration(monkeypatch):
    """REGRESSION: both `hasattr` and `getattr(obj, name, default)` only
    suppress AttributeError. A legacy plugin exposing a v5 hook through a
    descriptor/property that raises something else must still be treated as
    "missing" and shimmed — not left to blow up registration, contrary to
    every call site's fail-open convention elsewhere for exactly this kind of
    lookup failure."""
    from packagealert.languages import registry as reg

    class _RaisesOnLookup(_V4Plugin):
        ecosystems: ClassVar[list[str]] = ["shimtest-raises"]

        @property
        def osv_ecosystem(self):
            raise RuntimeError("plugin exploded on attribute access")

    monkeypatch.setattr(reg, "_registry", dict(reg._registry))
    # _V4Plugin (and thus _RaisesOnLookup) deliberately predates every v5 hook;
    # the raising `osv_ecosystem` property on top must not abort registration.
    reg.register(_RaisesOnLookup())  # type: ignore[reportArgumentType]  # must not raise
    lang = reg.for_ecosystem("shimtest-raises")
    assert lang is not None
    # The shim default was installed despite the raising descriptor, and the
    # other two v5-only hooks were still shimmed normally alongside it.
    assert lang.osv_ecosystem() is None
    assert lang.publication_date_parse({"any": 1}, "1.0") is None
    assert lang.normalise_name("A.B_c") == "a.b_c"


# --- resolve_package_dir's return-type adapter must not double-wrap -------------
#
# REGRESSION: _adapt_resolve_package_dir_to_list wrapped any non-None result in a
# list unconditionally. A pre-5 plugin is only obligated to return `Path | None`,
# but nothing stops one from already returning a list or tuple ahead of its
# declared contract version — and wrapping that again produced `[[Path, Path]]`,
# which breaks every downstream `Path` method (`.exists()` etc. raise
# AttributeError on the inner list) and is silently swallowed as "no heuristics"
# by every caller's fail-open handling.


def test_return_adapter_wraps_a_bare_path():
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    adapted = _adapt_resolve_package_dir_to_list(lambda *a, **kw: Path("/a"))
    assert adapted() == [Path("/a")]


def test_return_adapter_wraps_none_as_empty_list():
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    adapted = _adapt_resolve_package_dir_to_list(lambda *a, **kw: None)
    assert adapted() == []


def test_return_adapter_passes_through_an_existing_list_unchanged():
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    paths = [Path("/a"), Path("/b")]
    adapted = _adapt_resolve_package_dir_to_list(lambda *a, **kw: paths)
    result = adapted()
    assert result == paths
    assert all(isinstance(p, Path) for p in result), "must not double-wrap into [[Path, Path]]"


def test_return_adapter_passes_through_an_existing_tuple_as_a_list():
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    adapted = _adapt_resolve_package_dir_to_list(
        lambda *a, **kw: (Path("/a"), Path("/b"))
    )
    result = adapted()
    assert result == [Path("/a"), Path("/b")]
    assert all(isinstance(p, Path) for p in result)


def test_return_adapter_passes_through_an_empty_list_unchanged():
    """An empty list must stay [], not become [[]]."""
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    adapted = _adapt_resolve_package_dir_to_list(lambda *a, **kw: [])
    assert adapted() == []


# --- return adapter must not forward non-Path values into the list[Path] contract
#
# REGRESSION: a buggy pre-5 plugin returning a bare str (e.g. "/sp/pkg" instead of
# Path("/sp/pkg")) was wrapped as ["/sp/pkg"] — a str, not a Path — and a list
# already containing a stray None or str alongside real Paths passed through
# entirely unfiltered. Both reach RiskEngine._run_heuristics, which calls
# `.exists()` on every entry and raises AttributeError on anything that is not a
# Path — silently disabling every source-code heuristic for that plugin's
# packages, since every caller's fail-open handling swallows the exception.


def test_return_adapter_rejects_a_bare_str_result(caplog):
    """A str is iterable, so treating it as a sequence would expand it into one
    bogus single-character 'path' per character — it must be rejected outright."""
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    adapted = _adapt_resolve_package_dir_to_list(lambda *a, **kw: "/sp/pkg")
    with caplog.at_level("WARNING"):
        result = adapted()
    assert result == []
    assert "str" in caplog.text


def test_return_adapter_drops_non_path_entries_from_a_mixed_list(caplog):
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    good = Path("/sp/good")
    adapted = _adapt_resolve_package_dir_to_list(
        lambda *a, **kw: [good, None, "/sp/bad"]
    )
    with caplog.at_level("WARNING"):
        result = adapted()
    assert result == [good], "only the real Path must survive"
    assert all(isinstance(p, Path) for p in result)
    assert "non-Path" in caplog.text


def test_return_adapter_rejects_other_non_path_types(caplog):
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    for bad in (42, {"a": 1}, object()):
        adapted = _adapt_resolve_package_dir_to_list(lambda *a, _bad=bad, **kw: _bad)
        with caplog.at_level("WARNING"):
            result = adapted()
        assert result == [], f"expected [] for {type(bad).__name__}, got {result}"


def test_pre_v5_plugin_returning_a_bad_shape_end_to_end_is_not_crash(monkeypatch):
    """End-to-end through the real registry and _ShimmedLanguage proxy: a v4
    plugin's buggy resolve_package_dir returning a bare str must not reach a
    caller as anything but a real, usable list[Path]."""

    class _V4ReturningStr(_V4Plugin):
        ecosystems: ClassVar[list[str]] = ["shimtest-strreturn"]

        def resolve_package_dir(self, package_name, project_path, site_packages_dir, version=None):
            return "/sp/pkg"

    monkeypatch.setattr(reg, "_registry", dict(reg._registry))
    # _V4Plugin deliberately predates every v5 hook.
    reg.register(_V4ReturningStr())  # type: ignore[reportArgumentType]
    lang = reg.for_ecosystem("shimtest-strreturn")
    assert lang is not None

    result = lang.resolve_package_dir("foo", None, None)
    assert result == []
    assert isinstance(result, list)


def test_pre_v5_plugin_returning_a_list_early_is_not_double_wrapped(monkeypatch):
    """End-to-end through the real registry and _ShimmedLanguage proxy: a v4
    plugin that already returns list[Path] (ahead of its declared contract) must
    not have its result nested."""

    class _V4ReturningList(_V4Plugin):
        ecosystems: ClassVar[list[str]] = ["shimtest-listreturn"]

        def resolve_package_dir(self, package_name, project_path, site_packages_dir, version=None):
            return [Path("/venv/foo"), Path("/venv/bar")]

    monkeypatch.setattr(reg, "_registry", dict(reg._registry))
    # _V4Plugin deliberately predates every v5 hook.
    reg.register(_V4ReturningList())  # type: ignore[reportArgumentType]
    lang = reg.for_ecosystem("shimtest-listreturn")
    assert lang is not None

    result = lang.resolve_package_dir("foo", None, None)
    assert result == [Path("/venv/foo"), Path("/venv/bar")]
    assert all(isinstance(p, Path) for p in result)


# --- return adapter must preserve the wrapped method's signature ------------------
#
# REGRESSION: the adapter closure's own signature is `(*args, **kwargs)`. Without
# preserving the original's signature, sandbox/runner.py's _version_passing_style
# (which inspects the callable it's about to call) sees **kwargs and concludes
# "accepts version by keyword" for every adapted plugin — even a genuine pre-v5
# plugin whose real resolve_package_dir takes only three arguments. That version=
# then reaches the plugin's own method and raises TypeError, which callers' fail-
# open handling swallows as "skip source heuristics" for that package.


def test_return_adapter_preserves_the_original_signature():
    import inspect

    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list

    def original(package_name, project_path, site_packages_dir):
        return None

    adapted = _adapt_resolve_package_dir_to_list(original)
    assert inspect.signature(adapted) == inspect.signature(original)


def test_version_passing_style_is_none_for_an_adapted_legacy_plugin():
    """The exact mechanism the bug relied on: a wrapped legacy method must be
    classified the same way as the bare method it wraps."""
    from packagealert.languages.registry import _adapt_resolve_package_dir_to_list
    from packagealert.sandbox.runner import _version_passing_style

    def original(package_name, project_path, site_packages_dir):
        return None

    adapted = _adapt_resolve_package_dir_to_list(original)
    assert _version_passing_style(adapted) == "none"


def test_pre_v5_plugin_without_version_param_resolves_through_adapter_end_to_end(
    monkeypatch,
):
    """End-to-end through the real registry, _ShimmedLanguage proxy, and
    call_resolve_package_dir: a v4 plugin with a genuine three-argument
    resolve_package_dir (no `version`) must not raise TypeError when a caller
    passes a version — it must simply be resolved without it."""
    from packagealert.sandbox.runner import call_resolve_package_dir

    class _V4NoVersionParam(_V4Plugin):
        ecosystems: ClassVar[list[str]] = ["shimtest-noversion"]

        def resolve_package_dir(self, package_name, project_path, site_packages_dir):
            return Path("/sp") / package_name

    monkeypatch.setattr(reg, "_registry", dict(reg._registry))
    # _V4Plugin deliberately predates every v5 hook.
    reg.register(_V4NoVersionParam())  # type: ignore[reportArgumentType]
    lang = reg.for_ecosystem("shimtest-noversion")
    assert lang is not None

    result = call_resolve_package_dir(
        lang.resolve_package_dir, "foo", None, None, version="1.2.3"
    )
    assert result == [Path("/sp/foo")]


# --- shims must not require the plugin to accept new attributes -------------------
#
# REGRESSION: _apply_shims used setattr on the plugin instance. That assumes a
# third-party object accepts arbitrary attributes, which a __slots__ class or a frozen
# dataclass does not — registration raised AttributeError/FrozenInstanceError. Those
# plugins registered fine before v5 added the first shims, so the compatibility
# mechanism became a hard failure for exactly the older plugins it exists to support.


class _SlotsV4:
    __slots__ = ()
    name = "slotsv4"
    ecosystems: ClassVar[list[str]] = ["slotsv4eco"]
    process_names: ClassVar[list[str]] = []
    contract_version = 4
    author = "third-party"
    repository = "example"

    def top_packages_fallback(self):
        return ["alpha"]


@dataclass(frozen=True)
class _FrozenV4:
    name: str = "frozenv4"
    ecosystems: ClassVar[list[str]] = ["frozenv4eco"]
    process_names: ClassVar[list[str]] = []
    contract_version: int = 4
    author: str = "third-party"
    repository: str = "example"


@pytest.mark.parametrize("cls", [_SlotsV4, _FrozenV4])
def test_immutable_v4_plugins_still_register(cls, monkeypatch):
    """A plugin that cannot accept new attributes must still register."""
    monkeypatch.setattr(reg, "_registry", {})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        reg.register(cls())  # must not raise
    assert reg.get(cls.name) is not None


@pytest.mark.parametrize("cls", [_SlotsV4, _FrozenV4])
def test_immutable_v4_plugins_get_the_shim_defaults(cls, monkeypatch):
    monkeypatch.setattr(reg, "_registry", {})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        # _SlotsV4/_FrozenV4 deliberately predate every v5 hook.
        reg.register(cls())  # type: ignore[reportArgumentType]
    lang = reg.get(cls.name)
    assert lang is not None
    assert lang.publication_date_parse({}, "1.0") is None
    assert lang.osv_ecosystem() is None
    assert lang.normalise_name("Foo.Bar") == "foo.bar"


def test_shimming_does_not_mutate_the_plugin_instance(monkeypatch):
    """The plugin object must be left exactly as the author wrote it."""
    monkeypatch.setattr(reg, "_registry", {})

    class Plain:
        name = "plainv4"
        ecosystems: ClassVar[list[str]] = ["plainv4eco"]
        process_names: ClassVar[list[str]] = []
        contract_version = 4
        author = "x"
        repository = "x"

    plugin = Plain()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        # Plain deliberately predates every v5 hook.
        reg.register(plugin)  # type: ignore[reportArgumentType]

    for name in ("publication_date_parse", "osv_ecosystem", "normalise_name"):
        assert name not in plugin.__dict__, f"{name} was written onto the plugin"


def test_shim_proxy_forwards_real_attributes(monkeypatch):
    """Everything the plugin does define must still reach it."""
    monkeypatch.setattr(reg, "_registry", {})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        # _SlotsV4 deliberately predates every v5 hook.
        reg.register(_SlotsV4())  # type: ignore[reportArgumentType]
    lang = reg.get("slotsv4")
    assert lang is not None
    assert lang.name == "slotsv4"
    assert lang.ecosystems == ["slotsv4eco"]
    assert lang.top_packages_fallback() == ["alpha"]
    assert lang.contract_version == 4


def test_a_plugins_own_implementation_is_never_replaced(monkeypatch):
    monkeypatch.setattr(reg, "_registry", {})

    class OwnImpl:
        name = "ownimpl"
        ecosystems: ClassVar[list[str]] = ["ownimpleco"]
        process_names: ClassVar[list[str]] = []
        contract_version = 4
        author = "x"
        repository = "x"

        def osv_ecosystem(self):
            return "MyEco"

        def normalise_name(self, name):
            return name.upper()

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        # OwnImpl deliberately predates the other v5 hooks it doesn't implement.
        reg.register(OwnImpl())  # type: ignore[reportArgumentType]
    lang = reg.get("ownimpl")
    assert lang is not None
    assert lang.osv_ecosystem() == "MyEco"
    assert lang.normalise_name("abc") == "ABC"
    # Only the genuinely missing one is defaulted.
    assert lang.publication_date_parse({}, "1.0") is None


def test_a_fully_implementing_plugin_is_not_wrapped(monkeypatch):
    """No proxy when nothing is missing — the plugin is registered as-is."""
    monkeypatch.setattr(reg, "_registry", {})

    class Complete:
        name = "completev4"
        ecosystems: ClassVar[list[str]] = ["completev4eco"]
        process_names: ClassVar[list[str]] = []
        contract_version = 4
        author = "x"
        repository = "x"

        def publication_date_parse(self, data, version):
            return 1.0

        def osv_ecosystem(self):
            return "Complete"

        def normalise_name(self, name):
            return name.lower()

        def resolve_package_dir_manifest_warning(self, package_name, project_path, site_packages_dir, version=None):
            return None

    plugin = Complete()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        # Complete implements every v4-and-earlier hook (the point of this test)
        # but, like any v4 plugin, deliberately lacks v5-only members.
        reg.register(plugin)  # type: ignore[reportArgumentType]
    assert reg.get("completev4") is plugin


def test_current_version_plugins_are_never_wrapped():
    """Built-ins declare the current version, so they must be registered directly."""
    from packagealert.languages.python import PythonLanguage

    reg.load()
    assert isinstance(reg.for_ecosystem("pypi"), PythonLanguage)


# --- contract assertions must not fail on a supported v4 plugin -------------------
#
# REGRESSION: tests named "builtin ... declares the current contract version" iterated
# all_languages(), which load() populates from third-party entry points too. A plugin
# legitimately staying on v4 — exactly what the compatibility shims exist for — turned
# a supported configuration into a test failure for anyone who had one installed.


class _LegacyV4Plugin:
    name = "legacyv4"
    ecosystems: ClassVar[list[str]] = ["legacyv4eco"]
    process_names: ClassVar[list[str]] = ["legacytool"]
    contract_version = 4
    author = "third-party"
    repository = "example"


def test_all_languages_includes_third_party_plugins(monkeypatch):
    """The premise: all_languages() is not a built-ins-only view."""
    monkeypatch.setattr(reg, "_registry", {})
    reg.load()
    builtins = {lang.name for lang in reg.all_languages()}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        # _LegacyV4Plugin deliberately stays on v4 to represent a legitimately
        # supported (not broken) older third-party plugin.
        reg.register(_LegacyV4Plugin())  # type: ignore[reportArgumentType]
    assert {lang.name for lang in reg.all_languages()} == builtins | {"legacyv4"}


def test_builtins_are_reachable_by_name_regardless_of_plugins(monkeypatch):
    """Scoping contract assertions by name is what keeps them plugin-independent."""
    monkeypatch.setattr(reg, "_registry", {})
    reg.load()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        # _LegacyV4Plugin deliberately stays on v4 to represent a legitimately
        # supported (not broken) older third-party plugin.
        reg.register(_LegacyV4Plugin())  # type: ignore[reportArgumentType]

    for name in ("python", "node", "php"):
        lang = reg.get(name)
        assert lang is not None, f"built-in {name!r} is not registered"
        assert lang.contract_version == CURRENT_CONTRACT_VERSION


def test_a_v4_plugin_is_a_supported_configuration(monkeypatch):
    """It registers, keeps its declared version, and gets the shim defaults."""
    monkeypatch.setattr(reg, "_registry", {})
    reg.load()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        # _LegacyV4Plugin deliberately stays on v4 to represent a legitimately
        # supported (not broken) older third-party plugin.
        reg.register(_LegacyV4Plugin())  # type: ignore[reportArgumentType]

    lang = reg.get("legacyv4")
    assert lang is not None
    assert lang.contract_version == 4, "the plugin's declared version must be preserved"
    # The shims make it usable despite lagging the contract.
    assert lang.osv_ecosystem() is None
    assert lang.publication_date_parse({}, "1.0") is None
