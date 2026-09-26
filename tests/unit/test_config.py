import re
import textwrap
import tomllib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from packagealert.config import (
    AppConfig,
    PreflightRiskConfig,
    SandboxConfig,
    SchedulerConfig,
    load_config,
    warn_missing_paths,
)
from packagealert.languages.base import PackageMetadata


@pytest.fixture(autouse=True)
def _no_real_config(tmp_path, monkeypatch):
    """Prevent load_config(None) from reading the developer's real config file."""
    monkeypatch.setattr("packagealert.config._DEFAULT_CONFIG", tmp_path / "no-config.toml")
    monkeypatch.setattr("packagealert.config._OVERLAY_PATH", tmp_path / "no-overlay.toml")


def test_defaults_load_without_file():
    cfg = load_config(None)
    assert cfg.osv.cache_ttl_hours == 24
    assert cfg.watch.enable_process_monitoring is True
    assert cfg.alerts.desktop_notifications is True
    assert cfg.heuristics.warning_threshold == 40


def test_toml_overrides_defaults(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(textwrap.dedent("""\
        [osv]
        cache_ttl_hours = 6

        [watch]
        enable_cache_monitoring = false

        [alerts]
        desktop_notifications = false
    """))
    cfg = load_config(cfg_file)
    assert cfg.osv.cache_ttl_hours == 6
    assert cfg.watch.enable_cache_monitoring is False
    assert cfg.alerts.desktop_notifications is False


def test_fleet_overlay_not_applied_when_plugin_disabled(tmp_path, monkeypatch):
    overlay_file = tmp_path / "central-overlay.toml"
    overlay_file.write_text("[heuristics]\nwarning_threshold = 99\n")
    monkeypatch.setattr("packagealert.config._OVERLAY_PATH", overlay_file)
    # No plugins.enabled in config — pa-central is disabled
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("")
    cfg = load_config(cfg_file)
    assert cfg.heuristics.warning_threshold == 40  # default, overlay ignored


def test_fleet_overlay_applied_when_plugin_enabled(tmp_path, monkeypatch):
    overlay_file = tmp_path / "central-overlay.toml"
    overlay_file.write_text("[heuristics]\nwarning_threshold = 99\n")
    monkeypatch.setattr("packagealert.config._OVERLAY_PATH", overlay_file)
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[plugins]\nenabled = ["pa-central"]\n')
    cfg = load_config(cfg_file)
    assert cfg.heuristics.warning_threshold == 99


def test_invalid_toml_raises(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("not valid toml ::::")
    with pytest.raises(tomllib.TOMLDecodeError):
        load_config(cfg_file)


def test_partial_section_keeps_defaults(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("[osv]\ncache_ttl_hours = 12\n")
    cfg = load_config(cfg_file)
    assert cfg.osv.cache_ttl_hours == 12
    assert cfg.osv.max_retries == 3  # default preserved


def test_scheduler_config_defaults():
    cfg = AppConfig()
    assert cfg.scheduler.enabled is True
    assert cfg.scheduler.daily_hour == 2
    assert cfg.scheduler.weekly_day == 6   # Sunday
    assert cfg.scheduler.weekly_hour == 2
    assert cfg.scheduler.max_scan_history == 5


def test_scheduler_config_from_toml(tmp_path):
    toml = tmp_path / "config.toml"
    toml.write_text("[scheduler]\nmax_scan_history = 10\ndaily_hour = 4\n")
    cfg = load_config(toml)
    assert cfg.scheduler.max_scan_history == 10
    assert cfg.scheduler.daily_hour == 4


def test_scheduler_config_rejects_invalid_values():
    with pytest.raises(ValidationError):
        SchedulerConfig(daily_hour=25)
    with pytest.raises(ValidationError):
        SchedulerConfig(weekly_day=7)
    with pytest.raises(ValidationError):
        SchedulerConfig(max_scan_history=0)


def test_sandbox_extra_tmpfs_accepts_absolute_paths():
    # Plain strings are valid at runtime: ExpandedPath coerces str -> Path via
    # a BeforeValidator, which pyright cannot see through.
    cfg = SandboxConfig(extra_tmpfs=["/tmp/custom", "/run/secrets"])  # type: ignore[arg-type]
    assert cfg.extra_tmpfs[0] == Path("/tmp/custom")
    assert cfg.extra_tmpfs[1] == Path("/run/secrets")


def test_sandbox_extra_tmpfs_rejects_relative_path():
    with pytest.raises(ValidationError, match="must be absolute"):
        SandboxConfig(extra_tmpfs=["relative/path"])  # type: ignore[arg-type]


def test_sandbox_extra_tmpfs_rejects_bare_name():
    with pytest.raises(ValidationError, match="must be absolute"):
        SandboxConfig(extra_tmpfs=["secrets"])  # type: ignore[arg-type]


def test_sandbox_extra_tmpfs_rejects_relative_via_toml(tmp_path):
    toml = tmp_path / "config.toml"
    toml.write_text('[sandbox]\nextra_tmpfs = ["relative/path"]\n')
    with pytest.raises(ValidationError, match="must be absolute"):
        load_config(toml)


def test_project_env_allowlist_defaults_empty():
    from packagealert.config import SandboxConfig
    cfg = SandboxConfig()
    assert cfg.project_env_allowlist == []


def test_project_env_allowlist_round_trips():
    import tomllib

    from packagealert.config import AppConfig
    toml = b'[sandbox]\nproject_env_allowlist = ["MY_TOKEN", "REGISTRY_URL"]\n'
    data = tomllib.loads(toml.decode())
    cfg = AppConfig.model_validate(data)
    assert cfg.sandbox.project_env_allowlist == ["MY_TOKEN", "REGISTRY_URL"]


def test_warn_missing_paths_skips_buggy_plugin():
    """A plugin that raises in cache_paths() must not abort warn_missing_paths()."""
    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.cache_paths.side_effect = RuntimeError("plugin exploded")

    cfg = load_config(None)
    with patch("packagealert.languages.registry.all_languages", return_value=[bad_lang]):
        warn_missing_paths(cfg)  # must not raise

    bad_lang.cache_paths.assert_called_once()


# --- _run_scan_cache exception isolation ---


def _make_fake_osv():
    """Return (fake_open_db, FakeOsvClient, FakeOsvCache) suitable for mocking _run_scan_cache."""
    fake_db = MagicMock()
    fake_db.close = AsyncMock(return_value=None)
    fake_osv_cache = MagicMock()
    fake_osv_cache.get = AsyncMock(return_value=None)
    fake_osv_cache.set = AsyncMock(return_value=None)
    FakeOsvCache = MagicMock(return_value=fake_osv_cache)
    fake_osv_client = MagicMock()
    fake_osv_client.batch_query = AsyncMock(return_value=[])
    fake_osv_client.aclose = AsyncMock(return_value=None)
    FakeOsvClient = MagicMock(return_value=fake_osv_client)
    return AsyncMock(return_value=fake_db), FakeOsvClient, FakeOsvCache


@pytest.mark.asyncio
async def test_run_scan_cache_skips_lang_when_cache_paths_raises():
    """cache_file_globs/cache_paths raising must not abort scan-cache for other languages."""
    from packagealert.cli.app import _run_scan_cache

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.cache_file_globs.side_effect = RuntimeError("plugin exploded")

    good_lang = MagicMock()
    good_lang.name = "good"
    good_lang.cache_file_globs.return_value = []  # no globs → skip inner loop cleanly

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[bad_lang, good_lang]),
    ):
        await _run_scan_cache(cfg)  # must not raise

    bad_lang.cache_file_globs.assert_called_once()
    good_lang.cache_file_globs.assert_called_once()


@pytest.mark.asyncio
async def test_run_scan_cache_scans_cache_paths_when_poll_only_cache_paths_raises(tmp_path):
    """Regression: poll_only_cache_paths() is an optional plugin hook (see
    LanguageBase's comment on it) — a bug in one plugin's implementation
    must degrade to "unavailable" (no extra roots), not discard the
    cache_paths() roots that same plugin already returned successfully.
    An earlier version of _run_scan_cache() wrapped cache_file_globs(),
    cache_paths(), AND poll_only_cache_paths() in one shared try/except, so
    a raising poll_only_cache_paths() skipped this language's scan
    entirely — confirmed empirically to discard a real, already-resolved
    cache_paths() artifact that should still have been found.
    """
    from packagealert.cli.app import _run_scan_cache

    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.cache_paths.return_value = [tmp_path]
    lang.poll_only_cache_paths.side_effect = RuntimeError("buggy plugin")
    lang.classify_cache_file.return_value = PackageMetadata(
        name="requests", version="2.31.0", ecosystem="PyPI"
    )

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
    ):
        await _run_scan_cache(cfg)  # must not raise

    lang.classify_cache_file.assert_called_once_with(whl)


@pytest.mark.asyncio
async def test_run_scan_cache_scans_cache_paths_when_poll_only_cache_paths_returns_none(tmp_path):
    """Regression: poll_only_cache_paths() is duck-typed, third-party-
    implementable, and optional — a plugin can return None instead of
    raising. cast("list[Path]", ...) is only a type-checker hint, not a
    runtime check, so an earlier version let None survive the try/except
    unflagged and only failed later, unguarded, at `cache_dirs +
    poll_only_dirs` (TypeError: list + None) — aborting the ENTIRE
    scan-cache command, not just this one language's scan, confirmed
    empirically. A malformed return must degrade to "unavailable" (no
    extra roots) exactly like a raised exception does, not crash the
    whole command.
    """
    from packagealert.cli.app import _run_scan_cache

    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.cache_paths.return_value = [tmp_path]
    lang.poll_only_cache_paths.return_value = None
    lang.classify_cache_file.return_value = PackageMetadata(
        name="requests", version="2.31.0", ecosystem="PyPI"
    )

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
    ):
        await _run_scan_cache(cfg)  # must not raise

    lang.classify_cache_file.assert_called_once_with(whl)


@pytest.mark.asyncio
async def test_run_scan_cache_scans_cache_paths_when_poll_only_cache_paths_returns_non_path_elements(
    tmp_path,
):
    """Regression: a plugin returning a list containing a non-Path element
    (e.g. a bare str) doesn't raise anywhere in _run_scan_cache()'s
    poll_only_cache_paths() try/except — list concatenation and iteration
    both work fine on a str element — so it silently passed straight
    through into `cache_dirs`, and only failed later, unguarded, at
    `cache_dir.exists()` (AttributeError: str has no such method) —
    aborting the entire scan-cache command. Confirmed empirically.
    """
    from packagealert.cli.app import _run_scan_cache

    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.cache_paths.return_value = [tmp_path]
    lang.poll_only_cache_paths.return_value = ["not-a-path-object"]
    lang.classify_cache_file.return_value = PackageMetadata(
        name="requests", version="2.31.0", ecosystem="PyPI"
    )

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
    ):
        await _run_scan_cache(cfg)  # must not raise

    lang.classify_cache_file.assert_called_once_with(whl)


@pytest.mark.asyncio
async def test_run_scan_cache_skips_entry_when_classify_raises(tmp_path):
    """classify_cache_file raising for one entry must not abort scan of remaining entries."""
    from packagealert.cli.app import _run_scan_cache

    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()

    # spec= constrains which attributes this mock has at all: without it, a
    # bare MagicMock() auto-creates poll_only_cache_paths() too (matching
    # callable(getattr(lang, "poll_only_cache_paths", None))'s guard), whose
    # return value is itself a MagicMock rather than a list — cache_paths()
    # + poll_only_cache_paths() then raises inside _run_scan_cache()'s own
    # try/except, silently skipping this plugin entirely rather than
    # exercising the classify_cache_file() failure this test is for.
    lang = MagicMock(spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file"])
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.cache_paths.return_value = [tmp_path]
    lang.classify_cache_file.side_effect = RuntimeError("plugin exploded")

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
    ):
        await _run_scan_cache(cfg)  # must not raise

    lang.classify_cache_file.assert_called_once_with(whl)


@pytest.mark.asyncio
async def test_run_scan_cache_dedups_same_package_version_across_paths(tmp_path):
    """Regression: classify_cache_file() deliberately classifies a
    source-build wheel as its own event even when its
    sdists-v*/pypi/<name>/<version> ANCESTOR directory also independently
    classifies (see that method's own dual-classification comment in
    languages/python.py) — a single uv sdist build therefore glob-matches
    as TWO different paths that both classify to the SAME
    (ecosystem, name, version). The per-cache_dir `seen` set only
    deduplicates by glob-matched PATH, so it can never catch this — both
    paths are genuinely different paths. Without command-level dedup by
    (ecosystem, name, version), a single malicious package was queried
    and alerted on TWICE: alert_malicious() called twice, `found`
    incremented twice, and the printed "N malicious package(s) found"
    count overstated how many distinct malicious packages were actually
    found — confirmed empirically.
    """
    from packagealert.cli.app import _run_scan_cache

    version_dir = tmp_path / "pypi" / "mypkg" / "1.0.0"
    rev_dir = version_dir / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    wheel = rev_dir / "mypkg-1.0.0-py3-none-any.whl"
    wheel.touch()

    # Two DIFFERENT paths (the version-dir itself, and the wheel file
    # nested under it) both classify to the identical package/version —
    # mirroring classify_cache_file()'s real dual-classification behavior
    # for a uv sdist build, without needing the real PythonLanguage glob
    # patterns to match both shapes.
    lang = MagicMock(spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file"])
    lang.name = "python"
    lang.cache_file_globs.return_value = ["**/*"]
    lang.cache_paths.return_value = [tmp_path]

    def classify(path):
        if path in (version_dir, wheel):
            return PackageMetadata(name="mypkg", version="1.0.0", ecosystem="PyPI")
        return None

    lang.classify_cache_file.side_effect = classify

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    fake_osv_cache = FakeOsvCache.return_value
    fake_osv_cache.get = AsyncMock(return_value=None)
    fake_osv_client = FakeOsvClient.return_value
    malicious_result = MagicMock(has_malicious=True, degraded=False)
    fake_osv_client.batch_query = AsyncMock(return_value=[malicious_result])

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
        patch("packagealert.alerts.terminal.alert_malicious") as mock_alert,
    ):
        await _run_scan_cache(cfg)

    assert mock_alert.call_count == 1, (
        f"expected the same (ecosystem, name, version) found via two "
        f"different paths to alert exactly once, got {mock_alert.call_count} calls"
    )
    assert fake_osv_client.batch_query.call_count == 1, (
        "expected only one OSV query for the deduplicated package, not one "
        "per glob-matched path"
    )


@pytest.mark.asyncio
async def test_run_scan_cache_dedups_across_name_spellings(tmp_path):
    """Regression: the command-level dedup key is described as canonical
    (ecosystem, name, version), but used `metadata.name` RAW.
    PackageMetadata is a plain dataclass with no validation, so a plugin
    may return any spelling — PythonLanguage normalises its own, but
    NodeLanguage's cacache index-key branch returns the key unlowercased.
    PackageEvent, meanwhile, normalises `package_name` through the shared
    ecosystem-specific helper, so two spellings of ONE package missed each
    other in seen_packages and were queried and alerted TWICE — with both
    alerts displaying the same normalised name, since the event normalised
    what the key had not. Confirmed empirically.

    The name is now normalised once, up front, and that canonical value is
    used for the key, both OSV lookups and the event.
    """
    from packagealert.cli.app import _run_scan_cache

    a = tmp_path / "a.entry"
    b = tmp_path / "b.entry"
    a.touch()
    b.touch()

    lang = MagicMock(
        spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file", "normalise_name"]
    )
    lang.name = "node"
    lang.cache_file_globs.return_value = ["*.entry"]
    lang.cache_paths.return_value = [tmp_path]
    # npm's rule: lowercase only, never collapse separators (so "socket.io"
    # survives intact — see normalise_package_name_for()'s own docstring).
    lang.normalise_name.side_effect = lambda n: n.lower()

    def classify(path):
        # Two cache entries for the SAME npm package, differing only in
        # case — exactly what an unnormalised index key can yield.
        if path == a:
            return PackageMetadata(name="Express", version="1.0.0", ecosystem="npm")
        if path == b:
            return PackageMetadata(name="express", version="1.0.0", ecosystem="npm")
        return None

    lang.classify_cache_file.side_effect = classify

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    fake_osv_cache = FakeOsvCache.return_value
    fake_osv_cache.get = AsyncMock(return_value=None)
    fake_osv_client = FakeOsvClient.return_value
    malicious_result = MagicMock(has_malicious=True, degraded=False)
    fake_osv_client.batch_query = AsyncMock(return_value=[malicious_result])

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
        patch("packagealert.languages.registry.for_ecosystem", return_value=lang),
        patch("packagealert.alerts.terminal.alert_malicious") as mock_alert,
    ):
        await _run_scan_cache(cfg)

    assert mock_alert.call_count == 1, (
        f"expected two spellings of one package to alert exactly once, got "
        f"{mock_alert.call_count} calls"
    )
    assert fake_osv_client.batch_query.call_count == 1, (
        "expected only one OSV query once the two spellings normalise to "
        "the same name"
    )
    queried = fake_osv_client.batch_query.call_args[0][0]
    assert queried == [("npm", "express", "1.0.0")], (
        f"expected the canonical (normalised) name to be queried, got {queried}"
    )


@pytest.mark.asyncio
async def test_run_scan_cache_skips_entry_with_malformed_metadata_types(tmp_path):
    """Regression: PackageMetadata is a plain dataclass and
    classify_cache_file() is a duck-typed, third-party-implementable
    hook, so a plugin can return a non-string name/ecosystem/version.

    normalise_package_name_for() documents itself as never raising, but
    that only holds for a string: with a non-string the plugin's own
    normalise_name hook raises (caught and logged, as designed) and then
    the FALLBACK raises on the same value and escapes. That TypeError
    propagated out of _run_scan_cache() and aborted the WHOLE command —
    every remaining language and cache dir went unscanned, confirmed
    empirically. The per-entry try/except around classify_cache_file()
    cannot help, because the malformed value escapes it later.

    The types are now validated at that boundary, so only the offending
    entry is skipped and the rest of the scan still runs.
    """
    from packagealert.cli.app import _run_scan_cache

    bad_name = tmp_path / "bad_name.entry"
    bad_eco = tmp_path / "bad_eco.entry"
    good = tmp_path / "good.entry"
    for f in (bad_name, bad_eco, good):
        f.touch()

    lang = MagicMock(spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file"])
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.entry"]
    lang.cache_paths.return_value = [tmp_path]

    def classify(path):
        # Deliberately violating the annotations: PackageMetadata is a
        # plain dataclass, so a third-party plugin really can return
        # these at runtime — that is the whole point of the fix.
        if path == bad_name:
            return PackageMetadata(name=None, version="1.0.0", ecosystem="PyPI")  # type: ignore[reportArgumentType]
        if path == bad_eco:
            return PackageMetadata(name="pkg", version="1.0.0", ecosystem=123)  # type: ignore[reportArgumentType]
        return PackageMetadata(name="goodpkg", version="1.0.0", ecosystem="PyPI")

    lang.classify_cache_file.side_effect = classify

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    fake_osv_cache = FakeOsvCache.return_value
    fake_osv_cache.get = AsyncMock(return_value=None)
    fake_osv_client = FakeOsvClient.return_value
    fake_osv_client.batch_query = AsyncMock(return_value=[MagicMock(has_malicious=True, degraded=False)])

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
        patch("packagealert.alerts.terminal.alert_malicious") as mock_alert,
    ):
        # Must not raise: a malformed entry cannot abort the whole command.
        await _run_scan_cache(cfg)

    alerted = [c.args[0].package_name for c in mock_alert.call_args_list]
    assert alerted == ["goodpkg"], (
        f"expected the well-formed package to still be scanned and alerted "
        f"after the malformed entries were skipped, got {alerted}"
    )


@pytest.mark.asyncio
async def test_run_scan_cache_skips_entry_with_non_metadata_shaped_return(tmp_path):
    """Regression: classify_cache_file() is duck-typed, so a third-party
    plugin can return an object that is not metadata-shaped at ALL —
    missing name/ecosystem/version outright, not merely holding the wrong
    value types.

    The version field was dereferenced (to skip unversioned entries)
    BEFORE any shape validation, so such an object raised AttributeError
    right there. The per-entry try/except around classify_cache_file()
    guards the CALL, not the returned value, so it escaped and aborted
    the WHOLE command — every remaining entry, cache dir and language
    went unscanned, confirmed empirically.

    All three fields are now checked via getattr() before any is
    dereferenced, so only the offending entry is skipped.
    """
    from packagealert.cli.app import _run_scan_cache

    no_version = tmp_path / "no_version.entry"
    no_name = tmp_path / "no_name.entry"
    unversioned = tmp_path / "unversioned.entry"
    good = tmp_path / "good.entry"
    for f in (no_version, no_name, unversioned, good):
        f.touch()

    class NoVersionAttr:
        """No .version at all — the shape that aborted the command."""
        name = "evil"
        ecosystem = "PyPI"

    class NoNameAttr:
        """No .name at all."""
        version = "1.0.0"
        ecosystem = "PyPI"

    lang = MagicMock(spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file"])
    lang.name = "python"
    lang.cache_file_globs.return_value = ["*.entry"]
    lang.cache_paths.return_value = [tmp_path]

    def classify(path):
        if path == no_version:
            return NoVersionAttr()
        if path == no_name:
            return NoNameAttr()
        if path == unversioned:
            # version=None is legitimate (PackageMetadata.version is
            # `str | None`) — skipped quietly, never treated as malformed.
            return PackageMetadata(name="unversioned", version=None, ecosystem="PyPI")
        return PackageMetadata(name="goodpkg", version="1.0.0", ecosystem="PyPI")

    lang.classify_cache_file.side_effect = classify

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    FakeOsvClient.return_value.batch_query = AsyncMock(
        return_value=[MagicMock(has_malicious=True, degraded=False)]
    )

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
        patch("packagealert.alerts.terminal.alert_malicious") as mock_alert,
    ):
        # Must not raise: a non-metadata-shaped return cannot abort the command.
        await _run_scan_cache(cfg)

    alerted = [c.args[0].package_name for c in mock_alert.call_args_list]
    assert alerted == ["goodpkg"], (
        f"expected the well-formed package to still be scanned after the "
        f"shape-invalid entries were skipped, got {alerted}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "label,cache_paths_ret,globs_ret",
    [
        ("cache_paths returns None", None, ["*.entry"]),
        ("cache_paths returns [str]", ["/tmp/notapath"], ["*.entry"]),
        ("cache_file_globs returns [int]", "USE_TMP", [123]),
        ("cache_file_globs returns a bare str", "USE_TMP", "notalist"),
    ],
)
async def test_run_scan_cache_isolates_malformed_required_hook_returns(
    tmp_path, label, cache_paths_ret, globs_ret
):
    """Regression: cache_paths()/cache_file_globs() were caught if they RAISED
    but not validated if they returned a malformed shape.

    Both are duck-typed, third-party-implementable hooks. A malformed return
    survived the try/except (it is not an exception) and only failed later,
    unguarded: cache_paths() -> None at `cache_dirs + poll_only_dirs`
    (TypeError), a non-Path element at `cache_dir.exists()` (AttributeError),
    and a non-str glob inside cache_dir.glob() (TypeError). Each aborted the
    WHOLE scan-cache command, leaving every other language unscanned —
    confirmed empirically. Mirrors the validation
    CacheMonitor._discover_dirs_by() already performs.
    """
    from packagealert.cli.app import _run_scan_cache

    (tmp_path / "good.entry").touch()

    bad = MagicMock(spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file"])
    bad.name = "buggy"
    bad.cache_file_globs.return_value = globs_ret
    bad.cache_paths.return_value = (
        [tmp_path] if cache_paths_ret == "USE_TMP" else cache_paths_ret
    )

    good = MagicMock(spec=["name", "cache_file_globs", "cache_paths", "classify_cache_file"])
    good.name = "python"
    good.cache_file_globs.return_value = ["*.entry"]
    good.cache_paths.return_value = [tmp_path]
    good.classify_cache_file.return_value = PackageMetadata(
        name="goodpkg", version="1.0.0", ecosystem="PyPI"
    )

    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    FakeOsvClient.return_value.batch_query = AsyncMock(
        return_value=[MagicMock(has_malicious=True, degraded=False)]
    )

    cfg = load_config(None)
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.languages.registry.all_languages", return_value=[bad, good]),
        patch("packagealert.alerts.terminal.alert_malicious") as mock_alert,
    ):
        # Must not raise: one malformed plugin cannot abort the whole command.
        await _run_scan_cache(cfg)

    alerted = [c.args[0].package_name for c in mock_alert.call_args_list]
    assert alerted == ["goodpkg"], (
        f"{label}: the well-formed plugin must still be scanned after the "
        f"malformed one was skipped, got {alerted}"
    )


def test_cooldown_config_defaults():
    from packagealert.config import AppConfig
    cfg = AppConfig()
    assert cfg.sandbox.cooldown.period_days == 7
    assert cfg.sandbox.cooldown.on_new_medium_risk == "prompt"
    assert cfg.sandbox.cooldown.on_new_low_risk == "warn"
    assert cfg.sandbox.cooldown.non_interactive_escalation == "block"


def test_cooldown_config_from_toml(tmp_path):
    from packagealert.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("[sandbox.cooldown]\nperiod_days = 14\non_new_low_risk = \"block\"\n")
    cfg = load_config(cfg_file)
    assert cfg.sandbox.cooldown.period_days == 14
    assert cfg.sandbox.cooldown.on_new_low_risk == "block"
    assert cfg.sandbox.cooldown.on_new_medium_risk == "prompt"  # default preserved


def test_cooldown_config_allow_cooldown_allow_default():
    from packagealert.config import CooldownConfig
    cfg = CooldownConfig()
    assert cfg.allow_cooldown_allow is True


def test_cooldown_config_allow_cooldown_allow_false():
    from packagealert.config import CooldownConfig
    cfg = CooldownConfig(allow_cooldown_allow=False)
    assert cfg.allow_cooldown_allow is False


def test_plugins_config_defaults():
    from packagealert.config import PluginsConfig
    cfg = PluginsConfig()
    assert cfg.enabled == []
    assert cfg.pa_central.api_key == ""
    assert cfg.pa_central.server_url == ""
    assert cfg.pa_central.heartbeat_interval_seconds == 300
    assert cfg.pa_central.config_fetch_interval_seconds == 3600


def test_app_config_has_plugins():
    from packagealert.config import AppConfig
    cfg = AppConfig()
    assert hasattr(cfg, "plugins")
    assert cfg.plugins.enabled == []


def test_load_config_remaps_pa_central_key(tmp_path):
    from packagealert.config import load_config
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[plugins]\nenabled = ["pa-central"]\n\n[plugins.pa-central]\napi_key = "sk-test"\nserver_url = "https://example.com"\n')
    cfg = load_config(cfg_file)
    assert "pa-central" in cfg.plugins.enabled
    assert cfg.plugins.pa_central.api_key == "sk-test"
    assert cfg.plugins.pa_central.server_url == "https://example.com"


def test_preflight_risk_defaults():
    pr = AppConfig().sandbox.preflight_risk
    assert pr.enabled is True
    assert pr.risk_threshold == 25
    assert pr.on_typosquat == "prompt"
    assert pr.on_high_risk == "warn"
    assert pr.non_interactive_escalation == "block"
    assert pr.post_install_threshold == 30
    assert pr.on_post_install_risk == "warn"


def test_preflight_risk_rejects_unknown_action():
    from packagealert.config import PreflightRiskConfig
    with pytest.raises(ValidationError):
        PreflightRiskConfig(on_typosquat="explode")  # type: ignore[arg-type]


def test_preflight_risk_threshold_must_be_non_negative():
    from packagealert.config import PreflightRiskConfig
    with pytest.raises(ValidationError):
        PreflightRiskConfig(risk_threshold=-1)


EXAMPLE_CONFIG = Path(__file__).parent.parent.parent / "config.example.toml"


def _uncomment_documented_keys(text: str) -> str:
    """Strip the leading '# ' from commented-out `key = value` lines.

    config.example.toml documents every setting commented out, so parsing it as
    shipped exercises almost nothing — the live tables are nearly empty. Activating
    the documented keys is what actually checks they still exist on the models and
    still accept the documented values.

    Only lines whose comment body looks like a bare assignment are touched, so
    prose comments and commented-out `[table]` headers are left alone.

    The comment marker must be at column 0. Indented comments are continuation
    prose that often contains an illustrative `Example: extra_tmpfs = [...]`;
    activating those would duplicate the real key above them and make the file
    invalid TOML.
    """
    out = []
    for line in text.splitlines():
        if line.startswith("#"):
            body = line[1:].lstrip()
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", body):
                out.append(body)
                continue
        out.append(line)
    return "\n".join(out)


def test_example_config_loads_through_the_real_loader(tmp_path):
    """config.example.toml must load via load_config(), not merely be valid TOML.

    An `isinstance(raw, dict)` check on tomllib output passes for any syntactically
    valid file — including an empty one — so it could not catch a key that no longer
    exists, a default that drifted, or a value the model now rejects.

    An explicit path is passed because load_config(None) falls back to
    ~/.config/package-alert/config.toml and would read the developer's real config.
    """
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(EXAMPLE_CONFIG.read_text())
    cfg = load_config(cfg_path)
    assert isinstance(cfg, AppConfig)
    # Spot-check that the live (uncommented) tables actually populate the model.
    assert isinstance(cfg.sandbox.preflight_risk, PreflightRiskConfig)


def test_example_config_documented_keys_all_still_exist(tmp_path):
    """Every commented-out key in the example file must still validate.

    This is the drift guard. Because every config model uses extra="ignore", a key
    that was renamed or removed from the model is silently dropped rather than
    raising — so this test uncomments the documented settings and asserts the values
    actually landed on the model. Validation succeeding is not sufficient evidence.
    """
    activated = _uncomment_documented_keys(EXAMPLE_CONFIG.read_text())
    # Guard the helper itself: if the example file is reformatted such that nothing
    # is uncommented, this test would silently stop checking anything.
    raw = tomllib.loads(activated)
    assert len(raw) >= 8, "expected the documented tables to be activated"

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(activated)
    cfg = load_config(cfg_path)

    # The documented values must reach the model, not be ignored as unknown keys.
    pr = cfg.sandbox.preflight_risk
    assert pr.enabled is True
    assert pr.risk_threshold == 25
    assert pr.on_typosquat == "prompt"
    assert pr.typosquat_max_distance == 2
    assert pr.typosquat_min_score == 15
    assert pr.on_high_risk == "warn"
    assert pr.non_interactive_escalation == "block"
    assert pr.post_install_threshold == 30
    assert pr.on_post_install_risk == "warn"


def _walk_documented_keys(table: dict, path: tuple[str, ...] = ()):
    """Yield (dotted_path, key) for every leaf assignment in a parsed TOML table."""
    for key, value in table.items():
        if isinstance(value, dict):
            yield from _walk_documented_keys(value, (*path, key))
        else:
            yield ".".join(path), key


def test_no_documented_key_is_silently_ignored(tmp_path):
    """Every key in config.example.toml must be a real field on its model.

    This is the guard that value assertions cannot provide. Every config model uses
    extra="ignore", so a misspelled key (post_install_threshhold) validates cleanly
    and leaves the field at its default — meaning a test that asserts
    `post_install_threshold == 30` still passes while the example file quietly
    documents a setting that does nothing. Only checking key names against
    model_fields catches that class of drift.
    """
    activated = _uncomment_documented_keys(EXAMPLE_CONFIG.read_text())
    raw = tomllib.loads(activated)

    defaults = AppConfig()
    unknown: list[str] = []
    for dotted, key in _walk_documented_keys(raw):
        model = defaults
        for part in [p for p in dotted.split(".") if p]:
            # plugins uses extra="allow" and free-form plugin tables, so its
            # subtables are not model-backed and cannot be checked this way.
            model = getattr(model, part, None)
            if model is None:
                break
        if model is None or not hasattr(type(model), "model_fields"):
            continue
        if key not in type(model).model_fields:
            unknown.append(f"{dotted}.{key}" if dotted else key)

    assert not unknown, (
        "config.example.toml documents keys that no longer exist on the config "
        f"models (they are silently ignored at load time): {unknown}"
    )


def test_example_config_documented_defaults_match_the_model_defaults(tmp_path):
    """The commented-out values must be the real defaults.

    Otherwise the example file is documentation that lies: a user uncommenting a
    line verbatim would silently change behaviour. Compares the activated file
    against a default-constructed AppConfig field by field.
    """
    activated = _uncomment_documented_keys(EXAMPLE_CONFIG.read_text())
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(activated)
    from_example = load_config(cfg_path)
    defaults = AppConfig()

    for section in ("preflight_risk", "cooldown"):
        documented = getattr(from_example.sandbox, section)
        expected = getattr(defaults.sandbox, section)
        for field in type(expected).model_fields:
            assert getattr(documented, field) == getattr(expected, field), (
                f"config.example.toml documents sandbox.{section}.{field} as "
                f"{getattr(documented, field)!r} but the model default is "
                f"{getattr(expected, field)!r}"
            )


def test_uncomment_helper_leaves_prose_and_tables_alone():
    """The helper must not activate prose, table headers, or indented examples."""
    src = (
        "# Some prose about risk.\n"
        "# [sandbox.disabled_table]\n"
        "# risk_threshold = 25\n"
        "extra_tmpfs = []\n"
        "          #   extra_tmpfs = [\"/etc/ssh/other\"]\n"
        "enabled = true\n"
    )
    out = _uncomment_documented_keys(src)
    assert "# Some prose about risk." in out
    assert "# [sandbox.disabled_table]" in out
    assert "\nrisk_threshold = 25" in out
    # The indented illustrative example must stay commented: activating it would
    # duplicate the real extra_tmpfs key and break TOML parsing.
    assert '#   extra_tmpfs = ["/etc/ssh/other"]' in out
    assert tomllib.loads(out)["extra_tmpfs"] == []


def test_preflight_risk_typosquat_gating_defaults():
    """Distance cap is the detector's own threshold; false positives are handled
    by scoring (typosquat_min_score), not by refusing to look at distance 2."""
    pr = AppConfig().sandbox.preflight_risk
    assert pr.typosquat_max_distance == 2
    assert pr.typosquat_min_score == 15


def test_preflight_risk_typosquat_min_score_non_negative():
    from packagealert.config import PreflightRiskConfig
    with pytest.raises(ValidationError):
        PreflightRiskConfig(typosquat_min_score=-1)


def test_preflight_risk_defaults_match_the_documented_example():
    """Guard against config defaults drifting from the documented example.

    config.example.toml's commented-out `# key = value` lines are the
    authoritative, committed documentation of these defaults (the design spec
    that originally motivated them lives under docs/superpowers/, which is
    gitignored and never reaches a clean checkout). When a default legitimately
    changes, amend config.example.toml in the same commit — this test fails
    otherwise, which is the point: silently diverging from the documented
    default and updating only README/tests has happened before.
    """
    example = Path(__file__).parent.parent.parent / "config.example.toml"
    text = example.read_text()

    pr = AppConfig().sandbox.preflight_risk
    for key, actual in (
        ("risk_threshold", pr.risk_threshold),
        ("post_install_threshold", pr.post_install_threshold),
    ):
        # Match the commented-out example line: # key = value
        row = re.search(rf"^#\s*{key}\s*=\s*(\d+)\s*$", text, re.MULTILINE)
        assert row, f"{key} missing from config.example.toml"
        assert int(row.group(1)) == actual, (
            f"{key}: code default is {actual} but config.example.toml says "
            f"{row.group(1)} — amend config.example.toml or restore the default"
        )


# --- documented action semantics must match the code -----------------------------
#
# config.example.toml claimed "prompt and block both roll the install back". Only block
# does so unconditionally; prompt keeps the packages when the user accepts. A user
# reading that would pick prompt expecting block's guarantee, which is the more
# dangerous direction to be wrong in. Behaviour is covered by
# test_post_scan_prompt_accepted_keeps_install / _declined_ in test_runner_risk.py —
# this pins the *description*, which nothing else would catch.


def test_example_config_does_not_claim_prompt_always_rolls_back():
    text = EXAMPLE_CONFIG.read_text()
    assert '"prompt" and "block" both roll the install back' not in text
    assert "both roll the install back" not in text


def test_example_config_documents_prompt_as_conditional():
    """The distinction must be stated, not merely not-misstated."""
    text = EXAMPLE_CONFIG.read_text()
    # Anchor on the setting itself, not its earlier cross-reference in the
    # post_install_threshold comment.
    start = text.find('# on_post_install_risk = ')
    assert start != -1, "the commented-out setting is no longer in the example file"
    section = text[max(0, start - 700) : start].lower()
    assert "decline" in section, "the rollback condition for prompt is not documented"
    assert "always roll back" in section or "unconditional" in section, (
        "block's unconditional rollback is not distinguished from prompt's"
    )


def test_readme_action_table_matches_the_code():
    """The README table is the fullest statement of these semantics."""
    from pathlib import Path

    readme = (Path(__file__).parent.parent.parent / "README.md").read_text()
    assert "declining rolls the install back" in readme, (
        "the README no longer states that prompt rolls back only on decline"
    )
