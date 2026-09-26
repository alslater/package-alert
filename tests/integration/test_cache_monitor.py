import asyncio
import contextlib
import itertools
import os
import shutil
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest
from watchdog.observers.api import BaseObserver

from packagealert.config import WatchConfig
from packagealert.languages.base import PackageMetadata
from packagealert.languages.python import PythonLanguage
from packagealert.monitors.cache import (
    _SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS,
    CacheMonitor,
    _BackfillDedup,
    _classify_cache_path,
    _classify_distinfo_dir,
    _file_identity,
    _Handler,
    _still_watching,
    _TrackedWatch,
)
from tests.integration.conftest import requires_inotify_headroom


def _python_only_lang(cache_dir: Path):
    """Return a PythonLanguage instance whose cache_paths() returns only
    cache_dir, and whose poll_only_cache_paths() returns nothing — without
    the latter override, the real PythonLanguage.poll_only_cache_paths()
    would glob this machine's actual ~/.cache/uv/sdists-v* (see
    _poll_cache_dirs()), leaking real, arbitrarily numerous package events
    from the developer's own cache into what's meant to be an isolated test.
    """
    lang = PythonLanguage()
    lang.cache_paths = lambda: [cache_dir]
    lang.poll_only_cache_paths = list
    return lang


def _backdate(*paths: Path, seconds: float = 5.0) -> None:
    """Set each path's mtime `seconds` in the past.

    Used for a poll-only-root fixture meant to represent content that
    existed BEFORE the daemon session started: _seed_poll_only_baseline()
    excludes any entry whose mtime isn't safely before its startup cutoff
    (see _SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS's own docstring in
    cache.py for why an exact, unpadded comparison isn't safe), so a
    fixture created with no artificial delay right before start() can
    otherwise fall inside that margin and be wrongly treated as created
    DURING the seed. Every path sharing an artifact's tree must be
    backdated, not just the leaf file — classify_cache_file() classifies
    an ancestor directory independently too (see its own dual-
    classification docstring), so an unbackdated ancestor would still
    leak through on its own.
    """
    old_time = time.time() - seconds
    for path in paths:
        os.utime(path, (old_time, old_time))


@pytest.fixture(autouse=True)
def _fast_backfill_dedup_grace():
    """Shrink _BACKFILL_DEDUP_GRACE_SECONDS for every test in this file.

    _reschedule_missing_watch() now awaits this grace period after every
    backfill scan before closing that watch's _BackfillDedup window (see
    its docstring) — production-correct, but most tests here call
    _rescan_cache_paths()/_run_maintenance_if_due() several times and don't
    care about that specific timing, so waiting out the real (1s)
    production value in each of them would make the whole suite far slower
    for no benefit. The handful of tests that actually exercise the grace
    period's behavior (test_backfill_and_live_event_for_same_artifact_are_deduplicated,
    test_reinstall_after_backfill_race_still_produces_an_event) override it
    back to a real, meaningful value themselves.
    """
    with patch("packagealert.monitors.cache._BACKFILL_DEDUP_GRACE_SECONDS", 0.01):
        yield


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_detects_new_wheel(tmp_path):
    watch_dir = tmp_path / "pip_cache"
    watch_dir.mkdir()
    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    events = []

    async def collect():
        async for ev in monitor.events():
            events.append(ev)
            await monitor.stop()
            break

    async def drop_file():
        await asyncio.sleep(0.4)
        (watch_dir / "requests-2.31.0-py3-none-any.whl").touch()

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        try:
            await asyncio.gather(
                asyncio.wait_for(collect(), timeout=6.0),
                drop_file(),
            )
        except TimeoutError:
            await monitor.stop()

    assert len(events) == 1
    assert events[0].package_name == "requests"
    assert events[0].version == "2.31.0"
    assert events[0].ecosystem == "pypi"
    assert events[0].source == "cache"


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_ignores_non_wheel_files(tmp_path):
    watch_dir = tmp_path / "pip_cache2"
    watch_dir.mkdir()
    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    async def drop_non_wheel():
        await asyncio.sleep(0.2)
        (watch_dir / "somefile.txt").touch()
        await asyncio.sleep(0.2)
        (watch_dir / "requests-2.31.0-py3-none-any.whl").touch()

    events = []
    async def collect():
        async for ev in monitor.events():
            events.append(ev)
            await monitor.stop()
            break

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        try:
            await asyncio.gather(
                asyncio.wait_for(collect(), timeout=6.0),
                drop_non_wheel(),
            )
        except TimeoutError:
            await monitor.stop()

    # Only the wheel should be detected
    assert len(events) == 1
    assert events[0].package_name == "requests"


# --- Unit tests for dist-info classification ---

def test_classify_distinfo_dir_simple():
    ev = _classify_distinfo_dir(Path("/site-packages/django-5.0.4.dist-info"))
    assert ev is not None
    assert ev.package_name == "django"
    assert ev.version == "5.0.4"
    assert ev.ecosystem == "pypi"
    assert ev.source == "cache"


def test_classify_distinfo_dir_normalizes_underscores():
    ev = _classify_distinfo_dir(Path("/site-packages/opencv_python-4.9.0.80.dist-info"))
    assert ev is not None
    assert ev.package_name == "opencv-python"
    assert ev.version == "4.9.0.80"


def test_classify_distinfo_dir_transitive_dep():
    ev = _classify_distinfo_dir(Path("/site-packages/asgiref-3.8.1.dist-info"))
    assert ev is not None
    assert ev.package_name == "asgiref"
    assert ev.version == "3.8.1"


def test_classify_distinfo_dir_not_distinfo():
    assert _classify_distinfo_dir(Path("/site-packages/requests")) is None
    assert _classify_distinfo_dir(Path("/site-packages/requests-2.31.0.data")) is None


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_detects_distinfo_dir_in_site_packages(tmp_path):
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    cfg = WatchConfig(
        site_packages_dirs=[site_packages],
        enable_cache_monitoring=True,
    )
    monitor = CacheMonitor(cfg)

    events = []

    async def collect():
        async for ev in monitor.events():
            events.append(ev)
            await monitor.stop()
            break

    async def drop_distinfo():
        await asyncio.sleep(0.4)
        (site_packages / "sqlparse-0.5.0.dist-info").mkdir()

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(tmp_path / "nonexistent")],
    ):
        await monitor.start()
        try:
            await asyncio.gather(
                asyncio.wait_for(collect(), timeout=6.0),
                drop_distinfo(),
            )
        except TimeoutError:
            await monitor.stop()

    assert len(events) == 1
    assert events[0].package_name == "sqlparse"
    assert events[0].version == "0.5.0"


# --- Unit tests for _Handler exception isolation ---

def _make_file_created_event(path: Path):
    from watchdog.events import FileCreatedEvent
    return FileCreatedEvent(str(path))


def test_on_created_skips_buggy_plugin_and_continues(tmp_path):
    """A language plugin that raises in classify_cache_file must not crash the handler thread."""
    queue = MagicMock()
    loop = MagicMock()
    handler = _Handler(queue, loop, MagicMock(), MagicMock(), tmp_path, 0, _BackfillDedup())

    good_lang = MagicMock()
    good_lang.name = "good"
    good_lang.classify_cache_file.return_value = None

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.classify_cache_file.side_effect = RuntimeError("plugin exploded")

    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()

    with patch("packagealert.languages.registry.all_languages", return_value=[bad_lang, good_lang]):
        handler.on_created(_make_file_created_event(whl))

    # bad_lang raised but good_lang was still called
    bad_lang.classify_cache_file.assert_called_once()
    good_lang.classify_cache_file.assert_called_once()
    # No event was queued (good_lang returned None)
    loop.call_soon_threadsafe.assert_not_called()


def test_classify_cache_path_isolates_invalid_metadata_and_falls_through(tmp_path):
    """Regression: classify_cache_file() being wrapped in try/except is not
    enough — converting its return value into a PackageEvent must be
    isolated too. PackageEvent validates ecosystem against a known
    registry, so a plugin returning PackageMetadata with an unregistered
    ecosystem (or otherwise malformed data) raises at construction time, not
    inside classify_cache_file(). Left unguarded, that exception escapes
    _classify_cache_path() entirely instead of being treated as this one
    plugin's failure — the next plugin in the loop never gets a chance to
    classify the same path.
    """
    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.classify_cache_file.return_value = PackageMetadata(
        name="foo", version="1.0", ecosystem="not-a-real-ecosystem"
    )

    good_lang = MagicMock()
    good_lang.name = "good"
    good_lang.classify_cache_file.return_value = PackageMetadata(
        name="requests", version="2.31.0", ecosystem="PyPI"
    )

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[bad_lang, good_lang],
    ):
        result = _classify_cache_path(tmp_path / "whatever")

    bad_lang.classify_cache_file.assert_called_once()
    good_lang.classify_cache_file.assert_called_once()
    assert result is not None
    assert result.package_name == "requests"
    assert result.version == "2.31.0"


def test_on_created_survives_plugin_returning_invalid_metadata(tmp_path):
    """End-to-end version of the fix, from the watchdog handler's side: an
    uncaught PackageEvent ValidationError here doesn't just fail one
    classification — it escapes watchdog's event dispatch loop entirely.
    watchdog's BaseObserver.run() only catches queue.Empty, so an
    uncaught exception from on_created() kills the observer thread
    outright, silently ending ALL cache monitoring, not just this one path.
    """
    queue = MagicMock()
    loop = MagicMock()
    handler = _Handler(queue, loop, MagicMock(), MagicMock(), tmp_path, 0, _BackfillDedup())

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.classify_cache_file.return_value = PackageMetadata(
        name="foo", version="1.0", ecosystem="not-a-real-ecosystem"
    )

    whl = tmp_path / "requests-2.31.0-py3-none-any.whl"
    whl.touch()

    with patch("packagealert.languages.registry.all_languages", return_value=[bad_lang]):
        handler.on_created(_make_file_created_event(whl))  # must not raise

    bad_lang.classify_cache_file.assert_called_once()
    loop.call_soon_threadsafe.assert_not_called()


@pytest.mark.asyncio
async def test_backfill_scan_survives_one_entry_with_invalid_metadata(tmp_path):
    """A backfill scan must not abandon every remaining artifact just
    because one entry's plugin returned metadata that fails PackageEvent
    validation — see test_classify_cache_path_isolates_invalid_metadata_and_falls_through
    for why the failure must be isolated at classify time, not just caught
    around the whole scan.
    """
    (tmp_path / "a.whl").touch()
    (tmp_path / "b.whl").touch()
    (tmp_path / "c.whl").touch()

    lang = MagicMock()
    lang.name = "flaky"

    def classify(p: Path):
        if p.name == "b.whl":
            return PackageMetadata(name="b", version="1.0", ecosystem="not-a-real-ecosystem")
        return PackageMetadata(name=p.stem, version="1.0", ecosystem="PyPI")

    lang.classify_cache_file.side_effect = classify

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        monitor._backfill_scan(tmp_path, ["*.whl"], _BackfillDedup())

    events = monitor.drain()
    names = sorted(e.package_name for e in events)
    assert names == ["a", "c"]


def test_backfill_scan_retries_overlapping_pattern_after_transient_classify_failure(
    tmp_path,
):
    """Regression: _backfill_scan()'s `globbed` set (which stops a path
    matched by more than one of the merged plugin patterns from being
    queued once per pattern) was marked BEFORE classification was
    attempted, so a path was only ever tried under whichever overlapping
    pattern happened to be visited first. A TRANSIENT classification
    failure there — _classify_cache_path() catches a raising plugin and
    returns None, indistinguishable at that call site from "no plugin
    recognises this", and NodeLanguage's own classify_cache_file() opens
    and json-parses an index-v5 entry, so a partially-written file really
    can do this — then skipped every later pattern that would have
    matched the same path too. For PRE-EXISTING content there is no live
    creation event left to fall back on, making it a permanent miss.
    Confirmed empirically (one classification attempt, zero events).

    `globbed` is now only recorded after classification SUCCEEDS, so a
    failed attempt stays retryable by a later overlapping pattern, while
    a successful one is still recorded and therefore still queued exactly
    once no matter how many patterns match it.
    """
    entry = tmp_path / "pypi" / "evilpkg" / "1.0.0-py3-none-any"
    entry.parent.mkdir(parents=True)
    entry.touch()

    attempts: list[Path] = []

    def flaky_classify(path: Path):
        if path != entry:
            return None
        attempts.append(path)
        if len(attempts) == 1:
            # Transient: the plugin raised (already caught and logged by
            # _classify_cache_path()) on a still-being-written file.
            return None
        return PackageMetadata(name="evilpkg", version="1.0.0", ecosystem="PyPI")

    lang = MagicMock()
    lang.name = "flaky"
    lang.classify_cache_file.side_effect = flaky_classify

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)

    # Two overlapping patterns both match `entry` — the real shape of a
    # root shared by two plugins (see _discover_cache_dirs()).
    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        monitor._backfill_scan(tmp_path, ["pypi/*/*", "**/*"], _BackfillDedup())

    events = monitor.drain()

    assert len(attempts) == 2, (
        f"expected the second overlapping pattern to retry a path whose "
        f"first classification transiently failed, got {len(attempts)} "
        f"attempt(s)"
    )
    assert [(e.package_name, e.version) for e in events] == [("evilpkg", "1.0.0")], (
        f"expected exactly one event once the retry classified "
        f"successfully, got {events}"
    )


def test_backfill_scan_queues_overlapping_pattern_match_only_once(tmp_path):
    """The companion to the retry behaviour above: a path matched by more
    than one merged pattern whose classification SUCCEEDS the first time
    must still be classified and queued exactly once, not once per
    matching pattern — that is what `globbed` exists to guarantee, and
    deferring its recording until after a successful classification must
    not weaken it.
    """
    entry = tmp_path / "pypi" / "goodpkg" / "2.0.0-py3-none-any"
    entry.parent.mkdir(parents=True)
    entry.touch()

    attempts: list[Path] = []

    def classify(path: Path):
        if path != entry:
            return None
        attempts.append(path)
        return PackageMetadata(name="goodpkg", version="2.0.0", ecosystem="PyPI")

    lang = MagicMock()
    lang.name = "steady"
    lang.classify_cache_file.side_effect = classify

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        monitor._backfill_scan(tmp_path, ["pypi/*/*", "**/*"], _BackfillDedup())

    events = monitor.drain()

    assert len(attempts) == 1, (
        f"expected a successfully classified path to be attempted once "
        f"across overlapping patterns, got {len(attempts)}"
    )
    assert [(e.package_name, e.version) for e in events] == [("goodpkg", "2.0.0")], (
        f"expected exactly one event for one artifact, got {events}"
    )


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_backfill_and_live_event_for_same_artifact_are_deduplicated(tmp_path):
    """Regression: a watch goes live (via _schedule_watch()) before its
    backfill scan runs, so an artifact created in that exact window can be
    observed by BOTH — the real inotify emitter thread AND the backfill
    scan's own glob(), which still runs moments later and would find that
    same, already-present file. Each independently classifies and queues a
    PackageEvent.

    daemon._consume()'s per-batch dedup only combines events already
    sitting in the queue at one drain() call — it cannot help here, because
    the live handler hands its event off via
    asyncio.run_coroutine_threadsafe() from a different OS thread, whose
    callback can land on the loop at an arbitrary later time relative to
    the backfill scan's synchronous queue.put_nowait() calls, i.e. in a
    separate, later _consume() iteration entirely. Exactly one PackageEvent
    must result across both possible drains, not two.

    Also exercises _BACKFILL_DEDUP_GRACE_SECONDS itself: this test overrides
    the file's autouse near-zero value back to something real, so
    _reschedule_missing_watch() actually waits past the artificial 0.05s
    "live inotify pipeline catch-up" delay below before closing the
    dedup window — proving the grace period, not just the in-window claim
    collision, is what prevents the duplicate here.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [watch_dir]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.return_value = PackageMetadata(
        name="somepkg", version="1.0.0", ecosystem="PyPI"
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        wheel = watch_dir / "somepkg-1.0.0-py3-none-any.whl"

        # Write the wheel file exactly inside the race window: the watch is
        # already live (schedule_watch() has already returned by the time
        # _backfill_scan() is called) but the backfill glob() hasn't run
        # yet, so both the live inotify emitter thread and this scan get a
        # real chance to independently observe the same creation.
        real_backfill_scan = monitor._backfill_scan

        def racy_backfill_scan(cache_dir, globs, backfill_dedup, *, exclude=None):
            wheel.touch()
            time.sleep(0.05)  # let the live inotify emitter thread catch up
            return real_backfill_scan(cache_dir, globs, backfill_dedup, exclude=exclude)

        with (
            patch.object(monitor, "_backfill_scan", side_effect=racy_backfill_scan),
            patch("packagealert.monitors.cache._BACKFILL_DEDUP_GRACE_SECONDS", 0.3),
        ):
            await monitor._rescan_cache_paths()

        # Simulate daemon._consume()'s first drain, happening immediately —
        # whichever of the two (backfill or live) already landed in the
        # queue synchronously.
        batch1 = monitor.drain()

        # Give the live handler's run_coroutine_threadsafe() callback time
        # to land on the loop — simulating _consume() coming back around for
        # a separate, later iteration.
        deadline = time.monotonic() + 5.0
        while monitor._queue.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        batch2 = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    total = batch1 + batch2
    assert len(total) == 1, (
        f"expected exactly 1 PackageEvent for one artifact across both possible "
        f"drains, got {len(total)}: {total}"
    )
    assert total[0].package_name == "somepkg"
    assert total[0].version == "1.0.0"


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_reinstall_after_backfill_race_still_produces_an_event(tmp_path):
    """Regression: _BackfillDedup's per-path claim tracking must only cover
    the narrow window a single _backfill_scan() call is actually active for
    — not the watch's entire remaining lifetime. A path claimed once during
    that scan (see test_backfill_and_live_event_for_same_artifact_are_deduplicated
    above) must NOT be permanently remembered: a later, genuine reinstall of
    the exact same package at the exact same path (delete + recreate — a
    completely normal `pip install --force-reinstall`/rebuild pattern, not
    an edge case) must still produce its own PackageEvent, deduplicated
    against nothing.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [watch_dir]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.return_value = PackageMetadata(
        name="somepkg", version="1.0.0", ecosystem="PyPI"
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        await monitor._rescan_cache_paths()  # registers watch_dir; empty, so no backfill hits

        wheel = watch_dir / "somepkg-1.0.0-py3-none-any.whl"

        wheel.touch()
        deadline = time.monotonic() + 5.0
        while monitor._queue.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        first_install = monitor.drain()

        # Delete and recreate at the same path — a genuine reinstall.
        wheel.unlink()
        await asyncio.sleep(0.2)
        wheel.touch()
        deadline = time.monotonic() + 5.0
        while monitor._queue.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        reinstall = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(first_install) == 1, f"expected 1 event for the first install, got {first_install}"
    assert len(reinstall) == 1, (
        f"expected 1 event for the reinstall at the same path, got {reinstall} — "
        f"a permanently-growing dedup set would wrongly suppress this"
    )
    assert reinstall[0].package_name == "somepkg"
    assert reinstall[0].version == "1.0.0"


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_atomic_replace_of_existing_cache_key_still_produces_an_event(tmp_path):
    """Regression: uv's Unix replace_symlink() — used whenever a cache key
    that already exists is being replaced, e.g. a same-version reinstall or
    rebuild landing on an identical wheels-v*/sdists-v* index entry — does
    not unlink and recreate the index entry in place. It creates a fresh
    temporary symlink alongside it and renames that temp symlink over the
    destination. inotify (and watchdog 6 on top of it) reports an atomic
    rename onto an already-existing path as a single move event, dispatched
    to on_moved() with the final path as event.dest_path — never as
    on_created(), which only fires for the temporary symlink's own,
    unclassifiable creation. Without an on_moved() handler, this
    replacement was never classified or queued at all: not a duplicate, not
    delayed, a silent and permanent miss, confirmed empirically with a real
    inotify watch. With archive-v0 no longer watched (see the cache-layout
    audit notes in CLAUDE.md) there is no other event that could ever catch
    this instead.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    wheel = watch_dir / "somepkg-1.0.0-py3-none-any.whl"
    wheel.symlink_to("/nonexistent/archive-v0/aaaaaaaaaaaaaaaa")

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[_python_only_lang(watch_dir)]):
        await monitor.start()

        # Let the initial backfill (if any) drain before the replacement,
        # so it can't be mistaken for the event under test.
        await asyncio.sleep(0.3)
        monitor.drain()

        # uv's replace_symlink(): a temp symlink alongside the real entry,
        # atomically renamed over it — the exact pattern that fires
        # on_moved() rather than on_created() for the final path.
        tmp_link = watch_dir / ".somepkg-1.0.0-py3-none-any.whl.deadbeef.tmp"
        tmp_link.symlink_to("/nonexistent/archive-v0/bbbbbbbbbbbbbbbb")
        os.rename(str(tmp_link), str(wheel))

        deadline = time.monotonic() + 5.0
        events: list = []
        while time.monotonic() < deadline:
            events.extend(monitor.drain())
            if events:
                break
            await asyncio.sleep(0.05)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1, (
        f"expected exactly 1 PackageEvent for the atomic-replace reinstall, "
        f"got {len(events)}: {events}"
    )
    assert events[0].package_name == "somepkg"
    assert events[0].version == "1.0.0"


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_move_out_of_watched_root_does_not_produce_an_install_event(tmp_path):
    """on_moved() classifies `event.dest_path` unconditionally, which would
    be wrong if watchdog ever delivered a move whose DESTINATION is outside
    the watched tree — removing a cached artifact would then be reported as
    an install at wherever it landed.

    It does not, on Linux/inotify: a rename out of the watch emits only
    IN_MOVED_FROM (no IN_MOVED_TO inside the watch), which watchdog
    surfaces as on_deleted(), so on_moved() never fires and no dest_path is
    ever classified. Confirmed empirically across all three directions —
    move out -> deleted; move in -> created; rename within -> moved, with
    BOTH paths inside the root (uv's replace_symlink() pattern, covered by
    the sibling test above).

    This pins that platform assumption: if a watchdog/inotify change ever
    started delivering move-out as on_moved(), the destination would need
    an explicit containment check against the watch root.
    """
    watch_dir = tmp_path / "wheels-v6"
    entry_dir = watch_dir / "pypi" / "somepkg"
    entry_dir.mkdir(parents=True)
    entry = entry_dir / "1.0.0-py3-none-any"
    entry.touch()

    # The destination is a plausible cache-entry shape, so a naive
    # dest_path classification would produce a false install event.
    outside = tmp_path / "elsewhere" / "wheels-v6" / "pypi" / "somepkg"
    outside.mkdir(parents=True)

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        monitor.drain()

        shutil.move(str(entry), str(outside / "1.0.0-py3-none-any"))

        # Give the observer time to deliver whatever it is going to.
        deadline = time.monotonic() + 2.0
        events: list = []
        while time.monotonic() < deadline:
            events.extend(monitor.drain())
            await asyncio.sleep(0.05)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert events == [], (
        f"moving an artifact OUT of the watched root is a removal, not an "
        f"install — it must never produce an event, got "
        f"{[(e.package_name, e.version) for e in events]}"
    )


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_reinstall_during_grace_period_still_produces_an_event(tmp_path):
    """Regression: unlike test_reinstall_after_backfill_race_still_produces_an_event
    above (whose reinstall happens well after the dedup window has closed),
    this reinstalls at the exact same path WHILE _BackfillDedup is still
    open — inside the _BACKFILL_DEDUP_GRACE_SECONDS window that runs after
    _backfill_scan() returns but before close(). _BackfillDedup.claim() used
    to key its `_seen` set by path alone, so it treated any second creation
    at that path during the whole still-open window as the same artifact
    already claimed by the first — even though a real delete+recreate in
    between means it's a different file. A genuine reinstall landing in
    that window must still produce its own PackageEvent.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    wheel = watch_dir / "somepkg-1.0.0-py3-none-any.whl"

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[_python_only_lang(watch_dir)]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        # First install: the wheel is created right as the watch registers
        # and its backfill scan runs, targeting the same race window
        # _BackfillDedup exists to arbitrate.
        real_backfill_scan = monitor._backfill_scan

        def racy_backfill_scan(cache_dir, globs, backfill_dedup, *, exclude=None):
            wheel.touch()
            time.sleep(0.05)  # let the live inotify emitter thread catch up
            return real_backfill_scan(cache_dir, globs, backfill_dedup, exclude=exclude)

        with (
            patch.object(monitor, "_backfill_scan", side_effect=racy_backfill_scan),
            patch("packagealert.monitors.cache._BACKFILL_DEDUP_GRACE_SECONDS", 1.0),
        ):
            rescan_task = asyncio.ensure_future(monitor._rescan_cache_paths())

            # While _rescan_cache_paths() is still awaiting its grace period
            # (the dedup window is still open), delete and recreate the same
            # wheel — a genuine, fast reinstall landing inside that window.
            await asyncio.sleep(0.2)
            wheel.unlink()
            wheel.touch()

            await rescan_task

        deadline = time.monotonic() + 5.0
        events: list = []
        while time.monotonic() < deadline:
            events.extend(monitor.drain())
            if len(events) >= 2:
                break
            await asyncio.sleep(0.05)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 2, (
        f"expected 2 events (initial install + reinstall, both real, both "
        f"during the still-open grace window), got {len(events)}: {events}"
    )
    for event in events:
        assert event.package_name == "somepkg"
        assert event.version == "1.0.0"


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_reinstall_during_grace_period_via_same_target_symlink_still_produces_an_event(tmp_path):
    """Regression: uv's actual wheels-v*/sdists-v* index leaves are usually
    symlinks into its content-addressed archive-v0 store, not regular
    files (see test_reinstall_during_grace_period_still_produces_an_event
    above, which uses a plain file and so doesn't exercise this). If a
    reinstall recreates that index symlink pointing at the SAME target —
    which happens whenever uv already has the identical wheel content
    cached under a different install — _BackfillDedup.claim() must still
    treat it as a new artifact. Identity used to be resolved via stat(),
    which follows the symlink to the target's inode: recreating a symlink
    at an unchanged target then reports an unchanged identity even though
    the index entry itself was genuinely deleted and recreated, wrongly
    suppressing the live reinstall event.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    archive_dir = tmp_path / "archive-v0"
    archive_dir.mkdir()
    target = archive_dir / "deadbeefcafef00d"
    target.mkdir()
    (target / "somepkg-1.0.0.dist-info").mkdir()

    index_entry = watch_dir / "somepkg-1.0.0-py3-none-any.whl"

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[_python_only_lang(watch_dir)]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        real_backfill_scan = monitor._backfill_scan

        def racy_backfill_scan(cache_dir, globs, backfill_dedup, *, exclude=None):
            index_entry.symlink_to(target)
            time.sleep(0.05)  # let the live inotify emitter thread catch up
            return real_backfill_scan(cache_dir, globs, backfill_dedup, exclude=exclude)

        with (
            patch.object(monitor, "_backfill_scan", side_effect=racy_backfill_scan),
            patch("packagealert.monitors.cache._BACKFILL_DEDUP_GRACE_SECONDS", 1.0),
        ):
            rescan_task = asyncio.ensure_future(monitor._rescan_cache_paths())

            # While the dedup window is still open, recreate the index
            # symlink pointing at the SAME target — a content-deduplicated
            # reinstall of the identical wheel.
            await asyncio.sleep(0.2)
            index_entry.unlink()
            index_entry.symlink_to(target)

            await rescan_task

        deadline = time.monotonic() + 5.0
        events: list = []
        while time.monotonic() < deadline:
            events.extend(monitor.drain())
            if len(events) >= 2:
                break
            await asyncio.sleep(0.05)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 2, (
        f"expected 2 events (initial install + same-target-symlink reinstall, "
        f"both during the still-open grace window), got {len(events)}: {events}"
    )
    for event in events:
        assert event.package_name == "somepkg"
        assert event.version == "1.0.0"


@pytest.mark.asyncio
async def test_backfill_dedup_is_open_before_watch_goes_live(tmp_path):
    """Regression: when the observer is already alive (true for every
    _schedule_watch() call except start()'s own initial batch),
    BaseObserver.schedule() starts the watch's emitter SYNCHRONOUSLY, inside
    the call itself — a real filesystem creation can be dispatched to
    on_created() the instant schedule() returns, before the caller
    (_reschedule_missing_watch()) gets a chance to open() the returned
    _TrackedWatch's backfill_dedup.

    A live creation landing in that gap is claimed while `_active` is still
    False, so claim() succeeds unconditionally WITHOUT recording the path in
    `_seen`. If backfill_dedup were then opened only afterwards (clearing
    `_seen` at that point, same as it was already empty), the backfill
    scan's own glob() would find and claim that same path again — `_seen`
    never having recorded the live claim — producing a duplicate
    PackageEvent for one artifact.

    _schedule_watch() must instead open() the dedup itself, before calling
    Observer.schedule(), whenever the caller says it will backfill
    afterwards — checked here by inspecting `_active` at the exact moment
    Observer.schedule() runs.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [watch_dir]
    lang.cache_file_globs.return_value = ["*.whl"]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    observed_active_at_schedule_time = []
    real_schedule = BaseObserver.schedule

    def traced_schedule(self, handler, path, **kwargs):
        observed_active_at_schedule_time.append(handler._backfill_dedup._active)
        return real_schedule(self, handler, path, **kwargs)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        with patch.object(BaseObserver, "schedule", traced_schedule):
            await monitor._rescan_cache_paths()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert observed_active_at_schedule_time == [True], (
        "backfill_dedup must already be open by the moment Observer.schedule() "
        "makes the watch live — found inactive, which leaves a gap for a "
        "duplicate live+backfill event"
    )


@pytest.mark.asyncio
async def test_non_backfilled_registrations_leave_dedup_inactive(tmp_path):
    """The fix for the previous regression (backfill_dedup opened before
    Observer.schedule() rather than after) must only apply to registrations
    that are actually about to be backfill-scanned. start()'s own initial
    batch and add_site_packages_watch() never call _backfill_scan() or
    close() — if _schedule_watch() opened backfill_dedup unconditionally for
    them too, it would stay open (and _seen growing) for the rest of that
    watch's lifetime, wrongly suppressing a later, genuine reinstall
    forever (the exact bug test_reinstall_after_backfill_race_still_produces_an_event
    above guards against).
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [watch_dir]
    lang.cache_file_globs.return_value = ["*.whl"]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        await monitor.start()
        tracked = monitor._cache_root_watches[watch_dir]
        assert tracked.backfill_dedup._active is False, (
            "start()'s registrations must not be left open — nothing ever closes them"
        )

        site_packages = tmp_path / "site-packages"
        site_packages.mkdir()
        monitor.add_site_packages_watch(site_packages)
        sp_tracked = monitor._site_package_watches[site_packages]
        assert sp_tracked.backfill_dedup._active is False, (
            "add_site_packages_watch()'s registrations must not be left open"
        )

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


@pytest.mark.asyncio
async def test_backfill_scan_does_not_claim_transiently_unclassifiable_path(tmp_path):
    """Regression: _backfill_scan() must only call backfill_dedup.claim()
    AFTER classification has already succeeded for a path, never before or
    regardless of the outcome — matching _Handler.on_created(), which
    already does this in the correct order.

    A glob() match is not necessarily classifiable the instant it's found:
    an artifact can exist on disk (matching the glob) while still being
    written, so classify_cache_file() transiently returns None for it (the
    reviewer's example: an npm index file that already matches the glob
    while still empty). If claim() ran before that classification attempt,
    the path would be marked seen even though nothing was queued — and if
    the live watch's own on_created() for that same path fires later, once
    the write has actually completed and classification would now
    succeed, claim() would wrongly reject it as already seen. The real
    install would then produce zero events at all: worse than a duplicate,
    a silent true miss.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    entry = watch_dir / "somepkg-1.0.0-py3-none-any.whl"
    entry.touch()

    call_count = {"n": 0}

    def flaky_classify(path):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return None  # the backfill scan's own attempt: transiently unclassifiable
        return PackageMetadata(name="somepkg", version="1.0.0", ecosystem="PyPI")

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [watch_dir]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.side_effect = flaky_classify

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        # Simulate the live handler firing for the same path WHILE the
        # backfill's dedup window is still open (i.e. during the grace
        # period after the scan itself, before close() runs) — the real
        # window this race can land in. Calling on_created() directly,
        # right after the real backfill scan, avoids depending on actual
        # inotify dispatch timing to hit this specific ordering reliably.
        assert monitor._loop is not None, "start() must have set the event loop"
        loop = monitor._loop
        real_backfill_scan = monitor._backfill_scan

        def scan_then_live_dispatch(cache_dir, globs, backfill_dedup, *, exclude=None):
            result = real_backfill_scan(cache_dir, globs, backfill_dedup, exclude=exclude)
            tracked = monitor._cache_root_watches[watch_dir]
            handler = _Handler(
                monitor._queue, loop, monitor._invalidated_roots,
                monitor._activity, watch_dir, tracked.generation, tracked.backfill_dedup,
            )
            handler.on_created(_make_file_created_event(entry))
            return result

        with patch.object(monitor, "_backfill_scan", side_effect=scan_then_live_dispatch):
            await monitor._rescan_cache_paths()

        await asyncio.sleep(0.2)
        events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    # The backfill's own failed attempt, the live handler's successful
    # retry, and the post-backfill _snapshot_root_baseline() refresh —
    # which also classifies now, so that it never records a path nothing
    # could classify (see that method's own classify gate).
    assert call_count["n"] == 3, (
        f"expected the backfill's failed attempt, the live handler's retry "
        f"and the post-backfill snapshot's own classify, got {call_count['n']}"
    )
    assert len(events) == 1, (
        f"expected 1 event once classification succeeded on the live retry, got {events} — "
        f"a claim()-before-classify ordering would wrongly drop this real install entirely"
    )
    assert events[0].package_name == "somepkg"
    assert events[0].version == "1.0.0"


@pytest.mark.asyncio
async def test_snapshot_baseline_does_not_exclude_unclassifiable_glob_match(tmp_path):
    """Regression: _snapshot_root_baseline() recorded every glob MATCH,
    without classifying. That snapshot becomes `_TrackedWatch.known_content`,
    which _backfill_new_contributors() passes as _backfill_scan()'s
    `exclude` — and the exclude check runs BEFORE classification.

    A root's merged `globs` is the UNION across every contributing plugin
    (see _discover_cache_dirs()), so one plugin's BROAD pattern can match
    a path only a DIFFERENT plugin can classify. Recording that match
    marked it "already accounted for" when nothing ever accounted for it:
    once the other plugin appeared as a new contributor, its catch-up
    backfill skipped the path at the exclude check and it was never
    reported, on that rescan or any later one — a permanent silent miss.
    Confirmed empirically.

    _snapshot_root_baseline() now only records a path that actually
    classifies, mirroring _seed_poll_only_baseline_sync()'s own gate.
    """
    watch_dir = tmp_path / "wheels-v6"
    watch_dir.mkdir()
    artifact = watch_dir / "evil-1.0.0.special"
    artifact.touch()

    recovered = {"yes": False}

    class _Broad:
        """Established contributor: its broad glob matches the artifact,
        but it cannot classify it."""

        name = "broad"

        def cache_file_globs(self):
            return ["**/*"]

        def cache_paths(self):
            return [watch_dir]

        def poll_only_cache_paths(self):
            return []

        def classify_cache_file(self, path):
            return None

    class _Narrow:
        """Contributor that is absent (and classifies nothing) until it
        recovers — then it CAN classify what the broad plugin could not."""

        name = "narrow"

        def cache_file_globs(self):
            return ["*.special"] if recovered["yes"] else []

        def cache_paths(self):
            return [watch_dir] if recovered["yes"] else []

        def poll_only_cache_paths(self):
            return []

        def classify_cache_file(self, path):
            if not recovered["yes"] or path.suffix != ".special":
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="1.0.0", ecosystem="PyPI"
            )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_Broad(), _Narrow()],
    ):
        await monitor.start()
        monitor.drain()

        tracked = monitor._cache_root_watches.get(watch_dir)
        assert tracked is not None, "precondition: the root must be watched"
        assert (
            tracked.known_content is None
            or artifact not in tracked.known_content.entries
        ), (
            "a glob match that NO plugin could classify must not be recorded "
            "as already-accounted-for — that is what makes the later miss "
            "permanent"
        )

        recovered["yes"] = True
        await monitor._rescan_cache_paths()
        first = monitor.drain()
        await monitor._rescan_cache_paths()
        second = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert [e.package_name for e in first] == ["evil"], (
        f"expected the recovering contributor's catch-up backfill to report "
        f"the artifact it can now classify, got {[e.package_name for e in first]}"
    )
    assert [e.package_name for e in second] == [], (
        f"expected no replay on a later rescan, got "
        f"{[e.package_name for e in second]}"
    )


@pytest.mark.asyncio
async def test_failed_schedule_baseline_does_not_swallow_artifact_created_during_it(
    tmp_path,
):
    """Regression: when the initial _schedule_watch() fails (e.g. ENOSPC),
    _reschedule_missing_watch() still records a baseline so a LATER
    successful retry excludes stale content rather than replaying it. That
    snapshot was unbounded — and precisely BECAUSE scheduling failed,
    there is no watch observing the root while the (recursive, real-time)
    glob walk runs. An artifact created during the walk was therefore
    recorded as stale and then permanently excluded from the retry's own
    backfill: reported on no scan, ever. Confirmed empirically.

    The failure-path snapshot is now bounded by the startup cutoff, so it
    can only ever claim content that predates the daemon. The SUCCESS path
    deliberately stays unbounded — there the watch is already live and
    backfill_dedup is open, so anything created during that walk is caught
    by on_created() instead.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    # Genuinely predates the daemon — must stay suppressed on the retry.
    stale_wheel = watch_dir / "stalepkg-1.0.0-py3-none-any.whl"
    stale_wheel.touch()
    _backdate(stale_wheel, watch_dir)

    racy_wheel = watch_dir / "racypkg-2.0.0-py3-none-any.whl"

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)
    real_snapshot = CacheMonitor._snapshot_root_baseline

    def slow_snapshot(cache_dir, globs, cutoff=None):
        # A real install lands WHILE the watchless baseline walk runs.
        if not racy_wheel.exists():
            racy_wheel.touch()
            time.sleep(_SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS)
        return real_snapshot(cache_dir, globs, cutoff)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        # start(): scheduling fails, so the failure-path snapshot runs.
        with (
            patch.object(CacheMonitor, "_schedule_watch", return_value=None),
            patch.object(
                CacheMonitor, "_snapshot_root_baseline", staticmethod(slow_snapshot)
            ),
        ):
            await monitor.start()
        monitor.drain()

        baseline = monitor._known_cache_roots.get(watch_dir)
        assert baseline is not None, "precondition: the root must be marked known"
        assert racy_wheel not in baseline.entries, (
            "an artifact created DURING the watchless baseline walk must not "
            "be recorded as stale — nothing observed it, so excluding it from "
            "the retry's backfill loses the install permanently"
        )

        # Watch budget pressure subsides: the retry succeeds and backfills.
        await monitor._rescan_cache_paths()
        first = monitor.drain()
        await monitor._rescan_cache_paths()
        second = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    names = [e.package_name for e in first]
    assert "racypkg" in names, (
        f"expected the artifact created during the baseline walk to be "
        f"backfilled on the successful retry, got {names}"
    )
    assert "stalepkg" not in names, (
        f"expected genuinely pre-daemon content to stay suppressed, got {names}"
    )
    assert [e.package_name for e in second] == [], (
        f"expected no replay on a later rescan, got "
        f"{[e.package_name for e in second]}"
    )


@pytest.mark.asyncio
async def test_version_dir_not_re_reported_as_its_build_progresses(tmp_path):
    """Regression: `_entry_identity()` folds `st_ctime_ns` in so a
    delete+recreate is distinguishable even if the inode is reused. For a
    DIRECTORY that is wrong: ctime changes whenever an entry is added or
    removed directly beneath it, and uv's
    `sdists-v*/pypi/<name>/<version>` version dir — which itself
    classifies — gains a revision shard, then a `src/` tree, then the
    built wheel as ONE build progresses.

    Including ctime there made each step look like a new
    `(path, identity)` to `_poll_cache_dirs_sync()`, so the same install
    was re-reported on poll after poll — each a separate `store_alert()`
    row and notification. Confirmed empirically (three events for one
    build).

    `_entry_identity()` now drops the ctime component for directories
    only, exactly as `_root_identity()` does for watch roots. Symlinks are
    unaffected: `lstat()` reports a symlink-to-directory as a link, so
    uv's index leaves keep the component that the recreate case needs.

    The version dir and the finished `.whl` still produce one event each —
    that dual classification is deliberate, and `daemon.py`'s dedup layer
    collapses them into a single alert.
    """
    sdists_root = tmp_path / "sdists-v9"
    sdists_root.mkdir()

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()
        monitor.drain()

        version_dir = sdists_root / "pypi" / "mypkg" / "1.0.0"
        version_dir.mkdir(parents=True)
        first = await _drain_after_poll(monitor)

        revision = version_dir / "abcdef0123456789"
        revision.mkdir()
        after_revision = await _drain_after_poll(monitor)

        (revision / "src").mkdir()
        after_src = await _drain_after_poll(monitor)

        (revision / "mypkg-1.0.0-py3-none-any.whl").touch()
        after_wheel = await _drain_after_poll(monitor)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert [(e.package_name, e.version) for e in first] == [("mypkg", "1.0.0")], (
        f"expected the version dir to be reported once when it appears, got {first}"
    )
    assert after_revision == [], (
        f"adding a revision shard beneath the version dir must not re-report "
        f"the same install, got {[(e.package_name, e.version) for e in after_revision]}"
    )
    assert after_src == [], (
        f"unpacking src/ beneath the build must not re-report the same "
        f"install, got {[(e.package_name, e.version) for e in after_src]}"
    )
    # The completed wheel is its own deliberate classification (collapsed
    # with the version-dir event by daemon.py's dedup layer), so exactly
    # one event here — never a second one for the version dir itself.
    assert [(e.package_name, e.version) for e in after_wheel] == [("mypkg", "1.0.0")], (
        f"expected only the built wheel's own event, got "
        f"{[(e.package_name, e.version) for e in after_wheel]}"
    )


@pytest.mark.asyncio
async def test_start_reports_artifact_created_before_the_watch_went_live(tmp_path):
    """Regression: `start()`'s success-path baseline snapshot was left
    UNBOUNDED on the reasoning that "the watch is live during the
    snapshot". That is true but answers the wrong question: the live watch
    only covers from the moment `_schedule_watch()` made it live, NOT the
    window between the daemon's own startup cutoff and that moment, during
    which nothing observes the root at all.

    An artifact created in that window was therefore seen by nothing live,
    then swept up by the unbounded snapshot as stale, and `_backfill_scan()`
    excluded it — reported on no scan, ever. Confirmed empirically.

    The success path is now bounded by the startup cutoff too, so the
    snapshot can only ever claim content that genuinely predates the
    daemon. (`_backfill_new_contributors()` and the post-backfill
    `known_content` refresh stay unbounded and are correct: both act only
    on roots ALREADY in `watches`, so the watch has been live continuously
    since registration and there is no uncovered window.)
    """
    watch_dir = tmp_path / "wheels-v6"
    entry_dir = watch_dir / "pypi" / "evilpkg"
    entry_dir.mkdir(parents=True)
    artifact = entry_dir / "1.0.0-py3-none-any"

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)
    real_schedule = CacheMonitor._schedule_watch

    def slow_schedule(self, path, **kwargs):
        # A real install lands AFTER the startup cutoff but BEFORE the
        # watch is scheduled — the window nothing observes.
        if not artifact.exists():
            artifact.touch()
            time.sleep(_SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS)
        return real_schedule(self, path, **kwargs)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        with patch.object(CacheMonitor, "_schedule_watch", slow_schedule):
            await monitor.start()

        deadline = time.monotonic() + 3.0
        events: list = []
        while time.monotonic() < deadline:
            events.extend(monitor.drain())
            if events:
                break
            await asyncio.sleep(0.05)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert [e.package_name for e in events] == ["evilpkg"], (
        f"expected the artifact created before the watch went live to be "
        f"backfilled — nothing observed it live, so excluding it from the "
        f"backfill loses the install permanently, got "
        f"{[e.package_name for e in events]}"
    )


@pytest.mark.asyncio
async def test_root_returned_by_both_hooks_is_polled_not_watched(tmp_path):
    """Regression: `cache_paths()` and `poll_only_cache_paths()` are
    independent duck-typed hooks with no cross-validation, so a plugin can
    return the same Path from both. That combination is incoherent rather
    than supported — `poll_only_cache_paths()`'s own contract says such
    roots are "scanned periodically INSTEAD OF watched with a recursive
    inotify watch", precisely because a recursive watch there "would risk
    exhausting the inotify watch budget".

    Honouring both gave such a root a recursive watch AS WELL AS the
    periodic walk: confirmed empirically, a shared root holding 251
    subdirectories was scheduled with `is_recursive=True` — reintroducing
    the exact watch exhaustion this whole mechanism exists to prevent — and
    the same install was emitted TWICE, once live and once from the poll.

    Poll-only wins: a polled root is still fully covered, just with more
    latency, whereas dropping the poll instead would leave a root that must
    not be watched with no coverage at all.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()

    class _Overlapping:
        name = "overlap"

        def cache_file_globs(self):
            return ["*.tar.gz"]

        def cache_paths(self):
            return [shared_root]

        def poll_only_cache_paths(self):
            return [shared_root]

        def classify_cache_file(self, path):
            if not path.name.endswith(".tar.gz"):
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="1.0.0", ecosystem="PyPI"
            )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages", return_value=[_Overlapping()]
    ):
        await monitor.start()
        monitor.drain()

        assert shared_root not in monitor._cache_root_watches, (
            "a root a plugin also declared poll-only must NOT get a recursive "
            "inotify watch — that is the exhaustion poll-only exists to avoid"
        )

        # It must still be COVERED, via the poll.
        await asyncio.sleep(0.2)
        (shared_root / "evilpkg-1.0.0.tar.gz").touch()
        await asyncio.sleep(0.4)
        live = monitor.drain()

        await monitor._poll_cache_dirs()
        polled = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert [e.package_name for e in live] == [], (
        f"no live watch should exist for this root, got "
        f"{[e.package_name for e in live]}"
    )
    assert [e.package_name for e in polled] == ["evilpkg"], (
        f"the root must still be covered by the poll — dropping the poll "
        f"instead would leave it unmonitored, got "
        f"{[e.package_name for e in polled]}"
    )


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_overlap_root_stays_covered_when_poll_only_hook_later_fails(tmp_path):
    """Regression: dropping a root from the watched set must never be able to
    leave it with NO coverage at all.

    _watched_paths() excludes a root a plugin returned from BOTH hooks, based
    on its own poll_only_cache_paths() call. But
    _discover_poll_only_cache_dirs() calls that duck-typed hook AGAIN,
    independently — and if that second call raises (or stops reporting the
    root), the root is dropped from watching AND absent from polling, i.e.
    monitored by nothing. Confirmed empirically.

    Calling the hook twice inside _watched_paths() only narrows the window
    (the poll-side call is a third invocation that can fail on its own), so
    the exclusion is instead recorded and folded back in on the poll side.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()
    calls = itertools.count()

    class _FlakyPollOnly:
        name = "flaky"

        def cache_file_globs(self):
            return ["*.tar.gz"]

        def cache_paths(self):
            return [shared_root]

        def poll_only_cache_paths(self):
            # Succeeds for _watched_paths()' overlap check, then fails for
            # every later call, including _discover_poll_only_cache_dirs()'.
            if next(calls) == 0:
                return [shared_root]
            raise RuntimeError("transient plugin failure")

        def classify_cache_file(self, path):
            if not path.name.endswith(".tar.gz"):
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="1.0.0", ecosystem="PyPI"
            )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages", return_value=[_FlakyPollOnly()]
    ):
        await monitor.start()
        monitor.drain()

        # Still not watched recursively — the exhaustion guard must hold.
        assert shared_root not in monitor._cache_root_watches, (
            "an overlap root must never get a recursive inotify watch"
        )

        # Must land strictly after the startup cutoff, which is backdated by
        # _SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS (0.5s) — an artifact
        # inside that margin is correctly withheld as possibly-pre-existing.
        await asyncio.sleep(_SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS + 0.3)
        (shared_root / "evilpkg-1.0.0.tar.gz").touch()
        await asyncio.sleep(0.2)

        await monitor._poll_cache_dirs()
        polled = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert [e.package_name for e in polled] == ["evilpkg"], (
        f"the root must still be polled even though poll_only_cache_paths() "
        f"failed on the discovery call — otherwise it has neither a watch nor "
        f"a poll, got {[e.package_name for e in polled]}"
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_malformed_poll_only_declaration_still_suppresses_the_watch(tmp_path):
    """Regression: a root declared poll-only via a MALFORMED return must still
    not be recursively watched.

    poll_only_cache_paths() is duck-typed, so a plugin can return list[str]
    instead of list[Path]. A str never compares equal to a Path, so the overlap
    check silently found nothing and left the root in the recursively watched
    set — while _discover_dirs_by()'s own validation rejected that same return
    and dropped the root from polling entirely. The result was the exact
    failure this hook exists to prevent: a root the plugin explicitly declared
    poll-only, holding 40 subdirectories, recursively watched AND polled by
    nothing. Confirmed empirically.

    The declaration is now honoured on a normalised basis, so the watch is
    suppressed and the exclusion-reconciliation still guarantees the poll.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()
    for i in range(5):
        (shared_root / f"sub{i}").mkdir()

    class _MalformedPollOnly:
        name = "malformed"

        def cache_file_globs(self):
            return ["*.tar.gz"]

        def cache_paths(self):
            return [shared_root]

        def poll_only_cache_paths(self):
            # Violates the list[Path] contract — the whole point of the test.
            return [str(shared_root)]

    monitor = CacheMonitor(WatchConfig(enable_cache_monitoring=True))
    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_MalformedPollOnly()],
    ):
        watched, _owning = monitor._discover_cache_dirs()
        polled, _failed, *_rest = monitor._discover_poll_only_cache_dirs()

    assert shared_root not in {d for d, _ in watched}, (
        "a root declared poll-only must not be recursively watched, even when "
        "the declaration itself is malformed — that is the inotify exhaustion "
        "this whole mechanism exists to prevent"
    )
    assert shared_root in {d for d, _ in polled}, (
        "it must still be polled, or the malformed declaration costs the root "
        "all coverage instead of just its watch"
    )


# --- Dynamic cache-root discovery (versioned uv cache dirs created after start()) ---

@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_detects_wheel_in_cache_dir_created_after_start(tmp_path):
    """A cache_paths() root that doesn't exist at start() (e.g. wheels-v7 from
    a uv upgrade) must still be picked up once _rescan_cache_paths() runs,
    without requiring a daemon restart.
    """
    cache_root = tmp_path / "uv_cache"
    watch_dir = cache_root / "wheels-v7"
    # Deliberately does NOT exist yet when monitor.start() runs.
    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir not in monitor._cache_root_watches

        watch_dir.mkdir(parents=True)
        await monitor._rescan_cache_paths()
        assert watch_dir in monitor._cache_root_watches

        events = []

        async def collect():
            async for ev in monitor.events():
                events.append(ev)
                await monitor.stop()
                break

        async def drop_file():
            await asyncio.sleep(0.4)
            (watch_dir / "requests-2.31.0-py3-none-any.whl").touch()

        try:
            await asyncio.gather(
                asyncio.wait_for(collect(), timeout=6.0),
                drop_file(),
            )
        except TimeoutError:
            await monitor.stop()

    assert len(events) == 1
    assert events[0].package_name == "requests"
    assert events[0].version == "2.31.0"


@pytest.mark.asyncio
async def test_rescan_backfills_artifact_that_existed_before_watch(tmp_path):
    """A cache root can be created with its first artifact already inside it
    in one operation (e.g. uv's first-ever run creates wheels-v6 and writes
    a wheel entry before the daemon's watch exists). Scheduling the watch
    alone only sees *future* filesystem events, so the pre-existing artifact
    must be picked up by an explicit backfill scan, not just the watch.
    """
    watch_dir = tmp_path / "wheels-v7"
    # Does NOT exist yet when monitor.start() runs.
    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir not in monitor._cache_root_watches

        # Root AND its first artifact created together, before any watch
        # exists — mirrors uv creating the whole tree in one operation.
        watch_dir.mkdir(parents=True)
        (watch_dir / "requests-2.31.0-py3-none-any.whl").touch()

        await monitor._rescan_cache_paths()
        assert watch_dir in monitor._cache_root_watches

        events = monitor.drain()
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1
    assert events[0].package_name == "requests"
    assert events[0].version == "2.31.0"


@pytest.mark.asyncio
async def test_rescan_backfill_scan_is_empty_for_freshly_created_root(tmp_path):
    """A root that's newly discovered by the rescan (didn't exist at
    start()) but is empty at that point must produce zero backfill events —
    only real pre-existing artifacts should be synthesised.

    watch_dir must not exist until after start() — otherwise start() itself
    watches it and adds it to _cache_root_watches, so _rescan_cache_paths()
    skips it via the "already watched" check and _backfill_scan() is never
    reached, defeating the point of this test.
    """
    watch_dir = tmp_path / "wheels-v7"
    # Does NOT exist yet when monitor.start() runs.

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir not in monitor._cache_root_watches

        watch_dir.mkdir(parents=True)  # exists but empty at rescan time

        with patch.object(monitor, "_backfill_scan", wraps=monitor._backfill_scan) as mock_backfill:
            await monitor._rescan_cache_paths()
            mock_backfill.assert_called_once_with(
                watch_dir, mock_backfill.call_args[0][1], mock_backfill.call_args[0][2], exclude=None
            )

        events = monitor.drain()
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert events == []


@pytest.mark.asyncio
async def test_rescan_backfill_ignores_unrecognised_files(tmp_path):
    """watch_dir must not exist until after start() — see the docstring on
    test_rescan_backfill_scan_is_empty_for_freshly_created_root for why an
    already-watched root would skip _backfill_scan() entirely and make this
    test pass without exercising it.
    """
    watch_dir = tmp_path / "wheels-v7"
    # Does NOT exist yet when monitor.start() runs.

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir not in monitor._cache_root_watches

        watch_dir.mkdir(parents=True)
        (watch_dir / "README.md").touch()

        with patch.object(monitor, "_backfill_scan", wraps=monitor._backfill_scan) as mock_backfill:
            await monitor._rescan_cache_paths()
            mock_backfill.assert_called_once()

        events = monitor.drain()
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert events == []


@pytest.mark.asyncio
async def test_discover_cache_dirs_merges_globs_for_shared_path(tmp_path):
    """Two plugins can legitimately return the same cache_paths() entry (a
    shared parent cache dir). _discover_cache_dirs() must union their globs
    rather than keeping only the first plugin's — otherwise the backfill
    scan below only ever sees artifacts the first plugin's patterns match.
    """
    shared_dir = tmp_path / "shared_cache"

    lang_a = MagicMock()
    lang_a.name = "a"
    lang_a.cache_paths.return_value = [shared_dir]
    lang_a.cache_file_globs.return_value = ["*.whl"]

    lang_b = MagicMock()
    lang_b.name = "b"
    lang_b.cache_paths.return_value = [shared_dir]
    lang_b.cache_file_globs.return_value = ["*.tgz"]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang_a, lang_b]):
        result, owning_plugins = monitor._discover_cache_dirs()

    assert len(result) == 1
    path, globs = result[0]
    assert path == shared_dir
    assert set(globs) == {"*.whl", "*.tgz"}
    assert owning_plugins[shared_dir] == frozenset({"a", "b"})


@pytest.mark.asyncio
async def test_discover_cache_dirs_isolates_plugin_returning_none_instead_of_a_list(tmp_path):
    """Regression: cache_paths()/cache_file_globs() are duck-typed,
    third-party-implementable hooks — nothing stops a plugin from
    returning None instead of raising. Before validation was added inside
    the per-plugin try/except, `for p in paths:` (outside the try) raised
    an unhandled TypeError the instant it reached such a plugin's None
    result, escaping _discover_dirs_by() entirely and preventing every
    OTHER, well-behaved plugin's roots from being discovered too —
    confirmed empirically. A malformed plugin must be isolated exactly
    like a raising one: skipped, logged, `failed=True`, with every other
    plugin's roots still reported normally.
    """
    good_dir = tmp_path / "wheels-v6"

    good_lang = MagicMock()
    good_lang.name = "good"
    good_lang.cache_paths.return_value = [good_dir]
    good_lang.cache_file_globs.return_value = ["*.whl"]

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.cache_paths.return_value = None
    bad_lang.cache_file_globs.return_value = ["*.whl"]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages", return_value=[good_lang, bad_lang]
    ):
        result, owning_plugins = monitor._discover_cache_dirs()

    assert result == [(good_dir, ["*.whl"])], (
        f"expected the malformed plugin to be skipped while the healthy "
        f"plugin's own root is still reported, got {result}"
    )
    assert owning_plugins == {good_dir: frozenset({"good"})}


@pytest.mark.asyncio
async def test_discover_cache_dirs_isolates_plugin_returning_non_path_elements(tmp_path):
    """Regression: a plugin returning a list containing a non-Path element
    (e.g. a bare str) doesn't raise inside _discover_dirs_by() itself —
    `p not in globs_by_path`/`.setdefault()` both work fine on a str key
    — so it silently passed through as a "path" and only blew up later,
    outside any of this method's own isolation, the first time a caller
    called `.exists()` on it (start()/_rescan_cache_paths() both do, and
    neither wraps that call in a try/except) — an unhandled AttributeError
    confirmed empirically to escape all the way out of _discover_dirs_by()'s
    per-plugin isolation and into the caller. Element types must be
    validated inside the guarded block, before such a value is ever mixed
    into the returned path list.
    """
    good_dir = tmp_path / "wheels-v6"

    good_lang = MagicMock()
    good_lang.name = "good"
    good_lang.cache_paths.return_value = [good_dir]
    good_lang.cache_file_globs.return_value = ["*.whl"]

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.cache_paths.return_value = ["not-a-path-object"]
    bad_lang.cache_file_globs.return_value = ["*.whl"]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages", return_value=[good_lang, bad_lang]
    ):
        result, owning_plugins = monitor._discover_cache_dirs()

    assert result == [(good_dir, ["*.whl"])], (
        f"expected the malformed plugin to be skipped while the healthy "
        f"plugin's own root is still reported, got {result}"
    )
    assert owning_plugins == {good_dir: frozenset({"good"})}


@pytest.mark.asyncio
async def test_discover_cache_dirs_isolates_plugin_returning_non_string_globs(tmp_path):
    """Regression: cache_file_globs() returning something other than
    list[str] (e.g. a list containing a non-str, or a non-list entirely)
    must be treated the same as a raised exception, not passed through to
    Path.glob() — which raises its own, differently-shaped error deep
    inside _backfill_scan()'s per-glob try/except (a different, narrower
    isolation boundary not meant for a fundamentally malformed hook
    contract) rather than being caught here at the source.
    """
    good_dir = tmp_path / "wheels-v6"

    good_lang = MagicMock()
    good_lang.name = "good"
    good_lang.cache_paths.return_value = [good_dir]
    good_lang.cache_file_globs.return_value = ["*.whl"]

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.cache_paths.return_value = [tmp_path / "other-root"]
    bad_lang.cache_file_globs.return_value = "*.whl"  # a str, not list[str]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages", return_value=[good_lang, bad_lang]
    ):
        result, owning_plugins = monitor._discover_cache_dirs()

    assert result == [(good_dir, ["*.whl"])], (
        f"expected the malformed plugin to be skipped while the healthy "
        f"plugin's own root is still reported, got {result}"
    )
    assert owning_plugins == {good_dir: frozenset({"good"})}


@pytest.mark.asyncio
async def test_rescan_backfill_uses_merged_globs_from_all_plugins_sharing_a_root(tmp_path):
    """End-to-end version of the glob-merging fix: a root shared by two
    plugins must be backfill-scanned with both plugins' patterns, so an
    artifact only the second plugin's glob matches is still found.
    """
    shared_dir = tmp_path / "shared_cache"

    python_lang = _python_only_lang(shared_dir)  # globs include **/*.whl

    other_lang = MagicMock()
    other_lang.name = "other"
    other_lang.cache_paths.return_value = [shared_dir]
    other_lang.cache_file_globs.return_value = ["*.tgz"]
    other_lang.classify_cache_file.side_effect = (
        lambda p: PackageMetadata(name="othertool", version="9.9.9", ecosystem="npm")
        if p.suffix == ".tgz" else None
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[python_lang, other_lang],
    ):
        await monitor.start()
        assert shared_dir not in monitor._cache_root_watches

        # Artifact only other_lang's glob (*.tgz) matches — python_lang's
        # globs (**/*.whl, **/*.dist-info, **/*.tar.gz, pypi/*/*, index/*/*/*)
        # never see it.
        shared_dir.mkdir(parents=True)
        (shared_dir / "othertool-9.9.9.tgz").touch()

        await monitor._rescan_cache_paths()
        events = monitor.drain()
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1
    assert events[0].package_name == "othertool"
    assert events[0].version == "9.9.9"


@pytest.mark.asyncio
async def test_watched_root_backfills_recovering_contributors_pre_existing_artifact(tmp_path):
    """Regression: a root shared by two plugins, where one plugin's
    cache_paths() call is still failing at the moment the OTHER plugin's
    call succeeds and the watch gets registered. Once the failing plugin
    recovers on a later rescan, its own pre-existing artifact — created
    before the daemon ever ran, sitting there the whole time — must still
    be backfilled exactly once: not silently lost forever (the root being
    "already watched" used to make _rescan_cache_paths() skip it outright
    via `if d in watches: continue`, with nothing else ever glob-scanning
    it), and not replayed again on a later pass once it's been reported.
    The already-known contributor's own new content must keep being
    detected normally throughout.
    """
    shared_dir = tmp_path / "wheels-v6"

    healthy_lang = MagicMock()
    healthy_lang.name = "healthy"
    healthy_lang.cache_paths.return_value = [shared_dir]
    healthy_lang.cache_file_globs.return_value = ["*.whl"]
    healthy_lang.classify_cache_file.side_effect = (
        lambda p: PackageMetadata(name=p.name.split("-")[0], version="1.0.0", ecosystem="PyPI")
        if p.suffix == ".whl" else None
    )

    recovering_lang = MagicMock()
    recovering_lang.name = "recovering"
    recovering_lang.cache_paths.side_effect = [
        RuntimeError("transiently fails while the watch is first registered"),
        RuntimeError("still failing on the first rescan"),
        [shared_dir],
        [shared_dir],
        [shared_dir],
    ]
    recovering_lang.cache_file_globs.return_value = ["*.tgz"]
    recovering_lang.classify_cache_file.side_effect = (
        lambda p: PackageMetadata(name=p.name.split("-")[0], version="2.0.0", ecosystem="npm")
        if p.suffix == ".tgz" else None
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[healthy_lang, recovering_lang],
    ):
        shared_dir.mkdir(parents=True)
        # Both plugins' artifacts already sit here before the watch is
        # ever registered — the recovering plugin's own artifact must
        # eventually surface once it recovers; the healthy plugin's must
        # never replay, since its own registration-time backfill already
        # covers it.
        (shared_dir / "healthypkg-1.0.0.whl").touch()
        (shared_dir / "recoveringpkg-2.0.0.tgz").touch()
        # Genuinely predates this daemon session — snapshots are bounded by
        # the startup cutoff, so a bare touch() reads as created after it.
        _backdate(
            shared_dir / "healthypkg-1.0.0.whl",
            shared_dir / "recoveringpkg-2.0.0.tgz",
            shared_dir,
        )

        await monitor.start()
        start_events = monitor.drain()
        assert shared_dir in monitor._cache_root_watches, (
            "expected the healthy plugin's own successful cache_paths() "
            "call to register the watch even though the other plugin "
            "sharing this root failed"
        )
        assert start_events == [], (
            "start() must never report pre-existing content as new"
        )

        # The recovering plugin's call still fails on this pass too — its
        # own pre-existing artifact must stay unreported.
        await monitor._rescan_cache_paths()
        assert monitor.drain() == []

        # The recovering plugin's call finally succeeds.
        await monitor._rescan_cache_paths()
        recovery_events = monitor.drain()

        # A further pass must not replay the same artifact again.
        await monitor._rescan_cache_paths()
        replay_events = monitor.drain()

        # Genuinely new content from BOTH plugins must still be detected
        # normally afterward, via the live watch.
        (shared_dir / "newhealthy-3.0.0.whl").touch()
        (shared_dir / "newrecovering-4.0.0.tgz").touch()
        await asyncio.sleep(1.0)
        followup_events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert [(e.package_name, e.version) for e in recovery_events] == [
        ("recoveringpkg", "2.0.0")
    ], (
        f"expected the recovering plugin's own pre-existing artifact to be "
        f"backfilled exactly once it recovers, without replaying the "
        f"healthy plugin's already-covered content, got {recovery_events}"
    )
    assert replay_events == [], (
        f"expected no re-report of already-backfilled content on a "
        f"subsequent rescan, got {replay_events}"
    )
    assert {e.package_name for e in followup_events} == {"newhealthy", "newrecovering"}, (
        f"expected genuinely new content from both plugins to still be "
        f"detected normally after recovery, got {followup_events}"
    )


@pytest.mark.asyncio
async def test_backfill_new_contributors_runs_backfill_scan_on_the_event_loop_thread(tmp_path):
    """Regression: _backfill_new_contributors() must call _backfill_scan()
    directly, synchronously on the event loop thread — NOT via
    asyncio.to_thread() — because _backfill_scan() calls
    self._queue.put_nowait() for every match it finds, and asyncio.Queue is
    not thread-safe to mutate from a different OS thread than the event
    loop's (see _Handler's own use of run_coroutine_threadsafe() for the
    same reason, and _poll_cache_dirs_sync()'s docstring on why THAT
    worker-thread function returns plain data instead of queuing directly).
    An earlier version of this method wrapped _backfill_scan() in
    asyncio.to_thread() too, matching _snapshot_root_baseline()'s own
    (correct, since that one does no queue mutation) off-thread call
    immediately below it in the same method — copying that pattern onto
    _backfill_scan() introduced the thread-safety violation.

    This can't be verified by asserting on queued events, since a
    put_nowait() race doesn't reliably corrupt output in a small,
    single-artifact test — it's a structural property, verified directly
    by recording which OS thread _backfill_scan() actually executes on.
    """
    shared_dir = tmp_path / "wheels-v6"
    shared_dir.mkdir(parents=True)

    healthy_lang = MagicMock()
    healthy_lang.name = "healthy"
    healthy_lang.cache_paths.return_value = [shared_dir]
    healthy_lang.cache_file_globs.return_value = ["*.whl"]
    healthy_lang.classify_cache_file.return_value = None

    recovering_lang = MagicMock()
    recovering_lang.name = "recovering"
    recovering_lang.cache_paths.side_effect = [
        RuntimeError("fails while the watch is first registered"),
        [shared_dir],
    ]
    recovering_lang.cache_file_globs.return_value = ["*.tgz"]
    recovering_lang.classify_cache_file.return_value = None

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    call_threads: list[int] = []
    real_backfill_scan = monitor._backfill_scan

    def recording_backfill_scan(*args, **kwargs):
        call_threads.append(threading.get_ident())
        return real_backfill_scan(*args, **kwargs)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[healthy_lang, recovering_lang],
    ):
        await monitor.start()
        assert shared_dir in monitor._cache_root_watches

        main_thread_id = threading.get_ident()
        with patch.object(monitor, "_backfill_scan", side_effect=recording_backfill_scan):
            await monitor._rescan_cache_paths()  # recovering_lang still fails
            await monitor._rescan_cache_paths()  # recovering_lang recovers here

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert call_threads == [main_thread_id], (
        f"expected _backfill_new_contributors()'s catch-up _backfill_scan() "
        f"call to run on the event loop thread ({main_thread_id}), same as "
        f"_reschedule_missing_watch()'s own call, not in a worker thread — "
        f"got calls from thread(s) {call_threads}"
    )


@pytest.mark.asyncio
async def test_poll_only_cache_paths_root_is_never_watched(tmp_path):
    """Regression: a poll_only_cache_paths() root (e.g. uv's sdists-v*, whose
    source-build shards unpack a full sdist src/ tree alongside the built
    wheel) must NEVER be scheduled as an inotify watch — that's the entire
    point of the split from cache_paths(). start() must not add it to
    _cache_root_watches even though the root already exists on disk (unlike
    cache_paths() roots, which start() DOES watch immediately if present).
    """
    sdists_root = tmp_path / "sdists-v9"
    sdists_root.mkdir()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = []
    lang.poll_only_cache_paths.return_value = [sdists_root]
    lang.cache_file_globs.return_value = ["**/*.whl"]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        assert sdists_root not in monitor._cache_root_watches
        assert sdists_root not in monitor._site_package_watches

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


@pytest.mark.asyncio
async def test_poll_cache_dirs_detects_wheel_without_any_watch(tmp_path):
    """End-to-end: _poll_cache_dirs() must classify a build wheel sitting
    under a poll_only_cache_paths() root purely via a glob() walk — no
    inotify watch involved at all, confirming detection survives even
    though the root is deliberately never watched (see
    test_poll_only_cache_paths_root_is_never_watched).

    The build happens AFTER start(), not before: start() seeds a baseline
    of whatever already exists (see test_poll_cache_dirs_does_not_replay_
    pre_existing_artifacts_after_startup) so a real install during the
    daemon's session is what this test needs to exercise.
    """
    sdists_root = tmp_path / "sdists-v9"
    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        assert sdists_root not in monitor._cache_root_watches

        # Real uv shape: sdists-v9/pypi/<name>/<version>/<revision-hash>/{src/, *.whl}.
        rev_dir = sdists_root / "pypi" / "mypkg" / "1.0.0" / "abcdef0123456789"
        (rev_dir / "src" / "mypkg").mkdir(parents=True)
        (rev_dir / "src" / "mypkg" / "__init__.py").touch()
        (rev_dir / "mypkg-1.0.0-py3-none-any.whl").touch()

        await monitor._poll_cache_dirs()
        events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) >= 1
    assert all(e.package_name == "mypkg" and e.version == "1.0.0" for e in events)


@pytest.mark.asyncio
async def test_poll_cache_dirs_does_not_reemit_already_seen_entries(tmp_path):
    """A poll_only_cache_paths() root has no live watch to arbitrate
    against, so its 'seen' state must persist across polls — otherwise every
    maintenance interval would re-report every artifact that's ever existed
    under the root, forever, rather than only genuinely new ones.
    """
    sdists_root = tmp_path / "sdists-v9"
    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        rev_dir = sdists_root / "pypi" / "mypkg" / "1.0.0" / "abcdef0123456789"
        rev_dir.mkdir(parents=True)
        (rev_dir / "mypkg-1.0.0-py3-none-any.whl").touch()

        await monitor._poll_cache_dirs()
        first = monitor.drain()

        await monitor._poll_cache_dirs()  # nothing changed on disk
        second = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(first) >= 1
    assert second == []


@pytest.mark.asyncio
async def test_poll_cache_dirs_does_not_replay_pre_existing_artifacts_after_startup(tmp_path):
    """Regression: artifacts already present under a poll_only_cache_paths()
    root BEFORE the daemon even started must never be reported at all — not
    even once. start() seeds self._poll_only_seen with a baseline of
    whatever already exists (without queuing events for it), so the first
    real _poll_cache_dirs() call only reports genuinely new artifacts.

    Without seeding, self._poll_only_seen.setdefault(cache_dir, set())
    inside _poll_cache_dirs() would create an empty baseline the first time
    it's called — and since _poll_cache_dirs() only ever runs from
    _run_maintenance_if_due(), never from start() itself, that first real
    poll would treat every pre-existing artifact as new, replaying the
    entire pre-existing sdist cache on every daemon restart even though
    nothing changed — the same "normal startup never backfills a watched
    root's existing contents" contract cache_paths() roots already have
    (see start()'s _known_cache_roots handling), just for a polled root.
    """
    sdists_root = tmp_path / "sdists-v9"
    # Pre-existing content from BEFORE this daemon session.
    version_dir = sdists_root / "pypi" / "oldpkg" / "1.0.0"
    rev_dir = version_dir / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    old_wheel = rev_dir / "oldpkg-1.0.0-py3-none-any.whl"
    old_wheel.touch()
    _backdate(old_wheel, version_dir)

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        after_start = monitor.drain()

        # Simulate the first routine maintenance interval elapsing with no
        # new activity at all.
        await monitor._poll_cache_dirs()
        first_poll = monitor.drain()

        # A genuinely new build during this session must still be detected.
        new_rev = sdists_root / "pypi" / "newpkg" / "2.0.0" / "fedcba9876543210"
        new_rev.mkdir(parents=True)
        (new_rev / "newpkg-2.0.0-py3-none-any.whl").touch()
        await monitor._poll_cache_dirs()
        second_poll = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert after_start == [], "start() must never queue events for pre-existing content"
    assert first_poll == [], (
        f"the first routine poll must not replay pre-existing content, got {first_poll}"
    )
    assert len(second_poll) >= 1
    assert all(e.package_name == "newpkg" and e.version == "2.0.0" for e in second_poll)


@pytest.mark.asyncio
async def test_poll_cache_dirs_detects_new_revision_under_same_version_dir(tmp_path):
    """A second, later build under an already-polled version directory (a
    hash mismatch or different platform tag forcing a rebuild — the same
    scenario that motivated always classifying a .whl on its own, see
    classify_cache_file()) must still be detected on a later poll: the
    'seen' set is keyed by (path, identity), not just the version directory,
    so a new revision-hash dir's own wheel is a genuinely new entry.
    """
    sdists_root = tmp_path / "sdists-v9"
    version_dir = sdists_root / "pypi" / "mypkg" / "1.0.0"

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        old_rev = version_dir / "oldrevisionhash12"
        old_rev.mkdir(parents=True)
        (old_rev / "mypkg-1.0.0-py3-none-any.whl").touch()

        await monitor._poll_cache_dirs()
        first = monitor.drain()

        new_rev = version_dir / "newrevisionhash34"
        new_rev.mkdir()
        (new_rev / "mypkg-1.0.0-py3-none-any.whl").touch()

        await monitor._poll_cache_dirs()
        second = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(first) >= 1
    assert len(second) >= 1, "the new revision's wheel must still be detected on a later poll"


@pytest.mark.asyncio
async def test_poll_cache_dirs_does_not_block_the_event_loop(tmp_path):
    """Regression: cache_file_globs()'s **/*.whl-style patterns are
    recursive, so scanning a poll_only_cache_paths() root necessarily
    traverses every unpacked `src/` subdirectory too — the same
    potentially large subtrees excluded from inotify in the first place,
    since glob() must still descend into a directory to learn it has no
    matches. Confirmed empirically to scale with cache size and run on
    every maintenance interval, forever. If that walk ran directly on the
    event loop, it would block every other daemon task (OSV lookups, DB
    writes, other monitors' event processing) for its entire duration on
    every single poll. _poll_cache_dirs() must run the actual glob/classify
    work (_poll_cache_dirs_sync()) in a worker thread via
    asyncio.to_thread(), not synchronously, so a concurrent coroutine can
    keep making progress while the walk is in flight.
    """
    sdists_root = tmp_path / "sdists-v9"
    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        # Simulate a slow glob/classify walk (a large real cache) with a
        # synchronous sleep — time.sleep(), not asyncio.sleep(), since the
        # whole point is to model work that blocks whichever thread it
        # runs on. If _poll_cache_dirs() awaited this directly on the
        # event loop instead of via asyncio.to_thread(), the sleep would
        # block the loop itself.
        real_sync_scan = monitor._poll_cache_dirs_sync

        def slow_sync_scan(cache_dirs, unseeded_roots, unseeded_globs=None,
                           seed_incomplete_cutoffs=None, startup_cutoff=None):
            time.sleep(0.3)
            return real_sync_scan(cache_dirs, unseeded_roots, unseeded_globs)

        ticks = 0

        async def tick_counter():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.02)
                ticks += 1

        with patch.object(monitor, "_poll_cache_dirs_sync", side_effect=slow_sync_scan):
            counter_task = asyncio.create_task(tick_counter())
            await monitor._poll_cache_dirs()
            counter_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await counter_task

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert ticks >= 5, (
        f"expected the event loop to keep processing other coroutines "
        f"(~15 ticks of 0.02s over the 0.3s scan) while the poll ran in a "
        f"worker thread, got only {ticks} — the event loop was blocked"
    )


@pytest.mark.asyncio
async def test_seed_poll_only_baseline_does_not_block_the_event_loop(tmp_path):
    """Regression: _seed_poll_only_baseline() does the exact same recursive
    glob/classify walk as _poll_cache_dirs() (see
    test_poll_cache_dirs_does_not_block_the_event_loop above) over a
    poll_only_cache_paths() root's pre-existing contents, but it runs once
    at startup instead of every maintenance interval. start() awaits it
    directly, and Daemon._run() awaits CacheMonitor.start() BEFORE
    installing signal handlers or creating consumer tasks — so if this
    walk ran synchronously, a populated sdists-v* tree would block not
    just this coroutine but the whole event loop (no SIGINT/SIGTERM
    handling, no event consumption) for the full scan duration, right at
    daemon startup. Confirmed empirically (0 event-loop ticks while a
    slowed-down synchronous walk ran inside start()).
    _seed_poll_only_baseline() must run the actual glob/classify work
    (_seed_poll_only_baseline_sync()) in a worker thread via
    asyncio.to_thread(), matching _poll_cache_dirs()'s own split.
    """
    sdists_root = tmp_path / "sdists-v9"
    sdists_root.mkdir()
    (sdists_root / "pypi" / "mypkg" / "1.0.0" / "abcdef0123456789").mkdir(parents=True)
    (
        sdists_root / "pypi" / "mypkg" / "1.0.0" / "abcdef0123456789" / "mypkg-1.0.0-py3-none-any.whl"
    ).touch()

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    # Simulate a slow glob/classify walk (a large real cache) with a
    # synchronous sleep — time.sleep(), not asyncio.sleep(), since the
    # whole point is to model work that blocks whichever thread it runs
    # on. If _seed_poll_only_baseline() awaited this directly on the event
    # loop instead of via asyncio.to_thread(), the sleep would block the
    # loop itself, and start() (awaited directly from this test, just like
    # Daemon._run() does) would appear to hang the whole event loop too.
    real_sync_scan = monitor._seed_poll_only_baseline_sync

    def slow_sync_scan(cache_dirs, cutoff):
        time.sleep(0.3)
        return real_sync_scan(cache_dirs, cutoff)

    ticks = 0

    async def tick_counter():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with (
            patch.object(monitor, "_discover_cache_dirs", return_value=([], {})),
            patch.object(monitor, "_seed_poll_only_baseline_sync", side_effect=slow_sync_scan),
        ):
            counter_task = asyncio.create_task(tick_counter())
            await monitor.start()
            counter_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await counter_task

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert ticks >= 5, (
        f"expected the event loop to keep processing other coroutines "
        f"(~15 ticks of 0.02s over the 0.3s scan) while start()'s baseline "
        f"seeding ran in a worker thread, got only {ticks} — the event "
        f"loop was blocked"
    )


def test_seed_poll_only_baseline_sync_excludes_entry_created_at_or_after_cutoff(tmp_path):
    """Regression, at the unit level: a poll-only root (e.g. uv's
    sdists-v*) is NEVER watched — that's the whole reason it's poll-only,
    not just periodically-plus-live like a cache_paths() root (see
    poll_only_cache_paths()'s own docstring) — so there is no live signal
    at all to catch an artifact created WHILE _seed_poll_only_baseline_sync()'s
    own recursive glob/classify walk is still in progress, the way
    will_backfill=True catches the analogous gap for a watched root in
    start(). A real sdist build finishing and landing in the tree at the
    exact moment this walk's glob() happens to pass through its directory
    used to be swallowed straight into the baseline as if it had existed
    all along — permanently missed, since every later poll only ever
    reports what's NOT already in the baseline — confirmed empirically.
    The fix excludes any entry whose own st_mtime is not strictly before
    the (margin-adjusted) cutoff passed in, so such an entry is simply
    absent from the returned baseline.
    """
    sdists_root = tmp_path / "sdists-v9"
    rev_dir = sdists_root / "pypi" / "mypkg" / "1.0.0" / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    wheel = rev_dir / "mypkg-1.0.0-py3-none-any.whl"
    wheel.touch()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    # A cutoff strictly BEFORE the wheel's real mtime: this simulates the
    # wheel having been created during (or after) the walk started,
    # exactly the race this fix exists to catch. Real wall-clock mtimes,
    # not a mocked stat(), so this exercises the actual comparison against
    # a real filesystem timestamp.
    mtime_of_wheel = wheel.lstat().st_mtime
    cutoff_before_wheel_existed = mtime_of_wheel - 10.0

    with patch("packagealert.languages.registry.all_languages", return_value=[PythonLanguage()]):
        baseline, _incomplete_roots = monitor._seed_poll_only_baseline_sync(
            [(sdists_root, ["**/*.whl", "pypi/*/*"])], cutoff_before_wheel_existed
        )

    baseline_paths = {path for path, _identity in baseline.get(sdists_root, set())}
    assert wheel not in baseline_paths, (
        f"expected the wheel (created after the cutoff) to be excluded "
        f"from the baseline, got {baseline_paths}"
    )

    # A cutoff strictly AFTER the wheel's real mtime: this is the ordinary,
    # non-racing case — the artifact genuinely predates the walk, and must
    # still be recorded as pre-existing exactly as before this fix.
    cutoff_after_wheel_existed = mtime_of_wheel + 10.0
    with patch("packagealert.languages.registry.all_languages", return_value=[PythonLanguage()]):
        baseline_after, _incomplete_roots_after = monitor._seed_poll_only_baseline_sync(
            [(sdists_root, ["**/*.whl", "pypi/*/*"])], cutoff_after_wheel_existed
        )
    baseline_after_paths = {path for path, _identity in baseline_after.get(sdists_root, set())}
    assert wheel in baseline_after_paths, (
        f"expected the wheel (created well before the cutoff) to still be "
        f"recorded as pre-existing, got {baseline_after_paths}"
    )


@pytest.mark.asyncio
async def test_start_seeds_poll_only_baseline_excluding_artifact_created_during_seed(
    tmp_path,
):
    """End-to-end: an artifact created strictly during
    _seed_poll_only_baseline()'s own walk (not before daemon startup) must
    still be reported by the next real _poll_cache_dirs() call, not
    silently and permanently swallowed into the startup baseline as if it
    had always existed. Confirmed empirically to fail without the cutoff
    fix (0 events instead of a fresh-install report).
    """
    sdists_root = tmp_path / "sdists-v9"
    sdists_root.mkdir()
    # A genuinely pre-existing artifact, created a realistic amount of
    # time before daemon startup — must stay suppressed.
    version_dir = sdists_root / "pypi" / "stalepkg" / "1.0.0"
    stale_dir = version_dir / "abcdef0123456789"
    stale_dir.mkdir(parents=True)
    stale_wheel = stale_dir / "stalepkg-1.0.0-py3-none-any.whl"
    stale_wheel.touch()
    _backdate(stale_wheel, version_dir)

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_glob = Path.glob

    def racy_glob(self, pattern, **kwargs):
        result = list(real_glob(self, pattern, **kwargs))
        if self == sdists_root and pattern == "**/*.whl":
            # A genuine new install lands in the gap WHILE this exact
            # glob call is scanning — e.g. uv creating a real sdist build
            # right as the daemon's baseline seed is in progress.
            fresh_dir = sdists_root / "pypi" / "freshpkg" / "2.0.0" / "fedcba9876543210"
            fresh_dir.mkdir(parents=True)
            fresh_wheel = fresh_dir / "freshpkg-2.0.0-py3-none-any.whl"
            fresh_wheel.touch()
            result.append(fresh_wheel)
        return iter(result)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with (
            patch.object(monitor, "_discover_cache_dirs", return_value=([], {})),
            patch.object(Path, "glob", racy_glob),
        ):
            await monitor.start()

        events = await _drain_after_poll(monitor)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    package_names = {event.package_name for event in events}
    assert "freshpkg" in package_names, (
        f"expected the artifact created during baseline seeding to be "
        f"reported on the first real poll, got {[e.package_name for e in events]}"
    )
    assert "stalepkg" not in package_names, (
        f"expected the genuinely pre-existing artifact to stay suppressed, "
        f"got {[e.package_name for e in events]}"
    )


@pytest.mark.asyncio
async def test_seed_baseline_reports_artifact_created_during_slow_discovery(tmp_path):
    """Regression: _seed_poll_only_baseline() used to take its own
    `cutoff` AFTER _discover_poll_only_cache_dirs() returned. That hook
    calls third-party plugin code (poll_only_cache_paths(),
    cache_file_globs()) and can take real time, so the cutoff was LATER
    than the moment the daemon actually started — and an artifact that
    landed while discovery was still running had an mtime safely before
    it, and was recorded into the baseline as "pre-existing".

    A poll-only root is never watched, so nothing else ever observes that
    artifact, and every later poll only reports what is NOT already in the
    baseline: the install was reported on no poll, ever. Confirmed
    empirically (zero events across every subsequent poll).

    The seed now reuses start()'s own cutoff, captured before any
    discovery or seeding runs, so nothing this session could be the first
    to observe can predate it.
    """
    sdists_root = tmp_path / "sdists-v9"
    sdists_root.mkdir()
    # Genuinely pre-existing content — must STAY suppressed.
    stale_rev = sdists_root / "pypi" / "stalepkg" / "1.0.0" / "abcdef0123456789"
    stale_rev.mkdir(parents=True)
    stale_wheel = stale_rev / "stalepkg-1.0.0-py3-none-any.whl"
    stale_wheel.touch()
    _backdate(
        stale_wheel, stale_rev, stale_rev.parent, stale_rev.parent.parent,
    )

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_discover = CacheMonitor._discover_poll_only_cache_dirs

    def slow_discover(self):
        # A genuine install lands at the START of a slow discovery hook —
        # after start()'s own cutoff, but early enough that a cutoff taken
        # AFTER discovery would consider it pre-existing.
        fresh_rev = sdists_root / "pypi" / "freshpkg" / "2.0.0" / "fedcba9876543210"
        if not fresh_rev.exists():
            fresh_rev.mkdir(parents=True)
            (fresh_rev / "freshpkg-2.0.0-py3-none-any.whl").touch()
            time.sleep(_SEED_BASELINE_CUTOFF_SAFETY_MARGIN_SECONDS * 3)
        return real_discover(self)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with (
            patch.object(monitor, "_discover_cache_dirs", return_value=([], {})),
            patch.object(
                CacheMonitor, "_discover_poll_only_cache_dirs", slow_discover
            ),
        ):
            await monitor.start()
        monitor.drain()

        events = await _drain_after_poll(monitor)
        followup = await _drain_after_poll(monitor)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    names = {e.package_name for e in events}
    assert "freshpkg" in names, (
        f"expected the artifact created during a slow discovery hook to be "
        f"reported — nothing else ever observes a poll-only root, so "
        f"baselining it loses the install permanently, got {sorted(names)}"
    )
    assert "stalepkg" not in names, (
        f"expected genuinely pre-existing content to stay suppressed, got "
        f"{sorted(names)}"
    )
    assert [e.package_name for e in followup] == [], (
        f"expected no replay on a later poll, got "
        f"{[e.package_name for e in followup]}"
    )


async def _drain_after_poll(monitor: CacheMonitor) -> list:
    await monitor._poll_cache_dirs()
    return monitor.drain()


@pytest.mark.asyncio
async def test_known_cache_roots_snapshot_does_not_block_the_event_loop(tmp_path):
    """Regression: the known-root baseline snapshot (_snapshot_root_baseline(),
    see CacheMonitor._known_cache_roots's docstring) does the same kind of
    recursive glob walk _seed_poll_only_baseline() already runs via
    asyncio.to_thread() (see test_seed_poll_only_baseline_does_not_block_the_event_loop
    above), but start() and _rescan_cache_paths() called it directly on the
    event loop instead. Daemon._run() awaits CacheMonitor.start() BEFORE
    installing signal handlers or creating consumer tasks, so a populated
    cache root would have blocked daemon startup itself (no SIGINT/SIGTERM
    handling, no event consumption) for the full scan duration. Confirmed
    empirically (0 event-loop ticks while a slowed-down synchronous walk
    ran inside start()). _snapshot_root_baseline() must be called via
    asyncio.to_thread() at every call site, matching _seed_poll_only_baseline()'s
    own split.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    (watch_dir / "somepkg-1.0.0-py3-none-any.whl").touch()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    # Simulate a slow glob walk (a large real cache) with a synchronous
    # sleep — time.sleep(), not asyncio.sleep(), since the whole point is
    # to model work that blocks whichever thread it runs on. If start()
    # called _snapshot_root_baseline() directly on the event loop instead
    # of via asyncio.to_thread(), the sleep would block the loop itself.
    real_snapshot_root_baseline = monitor._snapshot_root_baseline

    def slow_snapshot_root_baseline(cache_dir, globs, cutoff=None):
        time.sleep(0.3)
        return real_snapshot_root_baseline(cache_dir, globs)

    ticks = 0

    async def tick_counter():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    with patch("packagealert.languages.registry.all_languages", return_value=[_python_only_lang(watch_dir)]):
        with patch.object(monitor, "_snapshot_root_baseline", side_effect=slow_snapshot_root_baseline):
            counter_task = asyncio.create_task(tick_counter())
            await monitor.start()
            counter_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await counter_task

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert ticks >= 5, (
        f"expected the event loop to keep processing other coroutines "
        f"(~15 ticks of 0.02s over the 0.3s scan) while start()'s known-root "
        f"snapshot ran in a worker thread, got only {ticks} — the event "
        f"loop was blocked"
    )


@pytest.mark.asyncio
async def test_maintenance_schedules_next_deadline_from_completion_not_start(tmp_path):
    """Regression: _run_maintenance_if_due() used to capture `now` BEFORE
    running maintenance (_cleanup_dead_watches(), _rescan_cache_paths(),
    and the potentially slow _poll_cache_dirs() recursive glob walk over a
    large sdists-v* tree — see test_poll_cache_dirs_does_not_block_the_event_loop),
    then scheduled the next deadline as `now + _MAINTENANCE_INTERVAL_SECONDS`.
    If the maintenance pass itself took longer than
    _MAINTENANCE_INTERVAL_SECONDS, that deadline was already in the past
    the moment it was set — confirmed empirically. Since
    _run_maintenance_if_due() is checked on every events() loop iteration,
    the very next call would then immediately trigger another full
    maintenance pass, with no rest between them, letting an expensive scan
    repeat continuously instead of respecting the interval. The deadline
    must be computed from completion time instead.
    """
    sdists_root = tmp_path / "sdists-v9"
    sdists_root.mkdir()
    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        # Simulate a poll that takes LONGER than _MAINTENANCE_INTERVAL_SECONDS
        # (a huge real sdists-v* tree) with a synchronous sleep.
        real_sync_scan = monitor._poll_cache_dirs_sync

        def slow_sync_scan(cache_dirs, unseeded_roots, unseeded_globs=None,
                           seed_incomplete_cutoffs=None, startup_cutoff=None):
            time.sleep(0.3)
            return real_sync_scan(cache_dirs, unseeded_roots, unseeded_globs)

        monitor._next_maintenance_at = 0  # force due
        with (
            patch.object(monitor, "_poll_cache_dirs_sync", side_effect=slow_sync_scan),
            patch("packagealert.monitors.cache._MAINTENANCE_INTERVAL_SECONDS", 0.1),
        ):
            await monitor._run_maintenance_if_due()
            gap = monitor._next_maintenance_at - time.monotonic()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert gap > 0, (
        f"expected the next maintenance deadline to be scheduled a full "
        f"interval AFTER this pass completed (a positive gap from now), "
        f"got a gap of {gap:.3f}s — a maintenance pass slower than the "
        f"interval must not produce an already-expired deadline"
    )


@pytest.mark.asyncio
async def test_poll_cache_dirs_prunes_state_for_deleted_root(tmp_path):
    """Regression: self._poll_only_seen used to only ever grow — a root's
    entry, once created, was never removed even after the root itself was
    deleted (`uv cache clean`). poll_only_cache_paths() itself filters to
    currently-existing roots (see PythonLanguage.poll_only_cache_paths()),
    so a deleted root simply stops appearing in _discover_poll_only_cache_dirs()'s
    result — nothing inside the old per-root "vanished" check inside the
    glob loop could ever observe that, since the loop never iterates over
    a root missing from its own input in the first place. The fix
    reconciles self._poll_only_seen wholesale on every poll instead of
    only ever merging into it, so a root absent from this poll's result is
    dropped from state entirely.
    """
    sdists_root = tmp_path / "sdists-v9"
    rev_dir = sdists_root / "pypi" / "mypkg" / "1.0.0" / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    (rev_dir / "mypkg-1.0.0-py3-none-any.whl").touch()

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root] if sdists_root.exists() else []

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        await monitor._poll_cache_dirs()
        assert sdists_root in monitor._poll_only_seen

        shutil.rmtree(sdists_root)  # `uv cache clean`
        await monitor._poll_cache_dirs()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert sdists_root not in monitor._poll_only_seen, (
        "a fully deleted poll-only root must be dropped from state, not "
        "held onto forever"
    )


@pytest.mark.asyncio
async def test_poll_cache_dirs_reconciles_pruned_artifacts_without_root_deletion(tmp_path):
    """Regression: self._poll_only_seen accumulated one entry per
    historical artifact ever observed under a still-existing root, with
    nothing ever removing an individual entry short of the whole root
    being deleted. A long-lived root like sdists-v* is never deleted in
    normal use but does have individual build directories pruned or
    replaced over the daemon's lifetime — each such artifact must be
    reconciled out of state once it's actually gone, not accumulate
    forever. The fix rebuilds self._poll_only_seen's per-root set from
    what's still actually resolvable on disk on every poll, rather than
    only ever adding to it.
    """
    sdists_root = tmp_path / "sdists-v9"
    rev_dir = sdists_root / "pypi" / "mypkg" / "1.0.0" / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    wheel = rev_dir / "mypkg-1.0.0-py3-none-any.whl"
    wheel.touch()

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        await monitor._poll_cache_dirs()
        before = len(monitor._poll_only_seen.get(sdists_root, set()))
        assert before > 0

        # Prune just this one build's artifact (e.g. a disk-space cleanup
        # script removing old builds) — the root itself is untouched.
        wheel.unlink()

        await monitor._poll_cache_dirs()
        after = len(monitor._poll_only_seen.get(sdists_root, set()))

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert after < before, (
        f"expected the pruned wheel's entry to be reconciled out of state "
        f"(before={before}, after={after})"
    )


@pytest.mark.asyncio
async def test_poll_cache_dirs_survives_a_transient_discovery_failure(tmp_path):
    """Regression: _discover_poll_only_cache_dirs() (and _discover_dirs_by()
    underneath it) silently omits a language plugin's roots entirely from
    its return whenever that plugin's cache_file_globs()/
    poll_only_cache_paths() raises — indistinguishable, from
    _poll_cache_dirs()'s point of view, from that plugin's roots genuinely
    no longer existing. _poll_cache_dirs() used to wholesale-replace
    self._poll_only_seen from that result unconditionally, so a transient
    failure of the very plugin owning a root wiped that root's baseline
    entirely (not just failed to add to it). Once the plugin recovers,
    every pre-existing artifact under that root replays as a brand-new
    event — confirmed empirically, and especially dangerous once
    daemon.py's _DEDUP_WINDOW_SECONDS has elapsed, since nothing there
    would catch the replay as a duplicate either. The fix must preserve
    prior state for a root whose owning plugin's discovery failed, and
    only remove state for a root once a SUCCESSFUL discovery pass confirms
    it's actually gone.
    """
    sdists_root = tmp_path / "sdists-v9"
    version_dir = sdists_root / "pypi" / "mypkg" / "1.0.0"
    rev_dir = version_dir / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    wheel = rev_dir / "mypkg-1.0.0-py3-none-any.whl"
    wheel.touch()
    _backdate(wheel, version_dir)

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    working_poll_only_cache_paths = lambda: [sdists_root]
    lang.poll_only_cache_paths = working_poll_only_cache_paths

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        await monitor._poll_cache_dirs()
        before = monitor._poll_only_seen.get(sdists_root, set())
        assert before, "expected the root's baseline to be seeded"

        # The plugin's discovery hook fails transiently for one poll pass —
        # e.g. a bug or a transient environment issue, not the root
        # actually disappearing (sdists_root itself is untouched on disk).
        def flaky_poll_only_cache_paths():
            raise RuntimeError("transient plugin bug")

        lang.poll_only_cache_paths = flaky_poll_only_cache_paths
        await monitor._poll_cache_dirs()
        events_during_failure = monitor.drain()

        # The plugin recovers — reporting the SAME root as before, not a
        # genuinely different set of roots.
        lang.poll_only_cache_paths = working_poll_only_cache_paths
        await monitor._poll_cache_dirs()
        after = monitor._poll_only_seen.get(sdists_root, set())
        events_after_recovery = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert events_during_failure == [], (
        f"expected no events while the owning plugin's discovery failed, "
        f"got {events_during_failure}"
    )
    assert after == before, (
        f"expected the root's baseline to survive its own plugin's "
        f"transient discovery failure unchanged, before={before}, after={after}"
    )
    assert events_after_recovery == [], (
        f"expected no stale replay of the root's pre-existing artifact "
        f"once the plugin recovered, got {events_after_recovery}"
    )


@pytest.mark.asyncio
async def test_poll_only_root_is_not_replayed_after_a_transient_startup_seeding_failure(
    tmp_path,
):
    """Regression: the transient-failure protection in
    test_poll_cache_dirs_survives_a_transient_discovery_failure only
    covers a plugin failing during a RECURRING _poll_cache_dirs() call,
    where self._poll_only_seen already has a real baseline to preserve.
    _seed_poll_only_baseline() — the ONE-TIME startup seeding call in
    start() — has its own, separate version of this bug: if the owning
    plugin's poll_only_cache_paths() raises during THAT call, the root
    never gets a self._poll_only_seen entry at all, not merely a stale
    one. self._poll_only_seen.setdefault(cache_dir, set()).update(keys)
    only ran for roots actually returned by discovery, so an omitted root
    was — before this fix — silently left with NO baseline whatsoever.
    Once the plugin recovers on the first real _poll_cache_dirs() poll,
    that root's entire pre-existing contents (from before the daemon even
    started) looked exactly like a genuinely new root's first successful
    discovery, and replayed as brand-new install events — confirmed
    empirically (a pre-existing wheel fired as a new event, twice, purely
    because its root's plugin transiently failed during startup seeding,
    with nothing on disk actually having changed).
    """
    sdists_root = tmp_path / "sdists-v9"
    version_dir = sdists_root / "pypi" / "oldpkg" / "1.0.0"
    rev_dir = version_dir / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    old_wheel = rev_dir / "oldpkg-1.0.0-py3-none-any.whl"
    old_wheel.touch()
    _backdate(old_wheel, version_dir, rev_dir, sdists_root / "pypi" / "oldpkg", sdists_root / "pypi")

    lang = _python_only_lang(tmp_path / "unused-wheels-root")

    # poll_only_cache_paths() fails on its FIRST call only — the startup
    # seeding call inside _seed_poll_only_baseline() — and succeeds on
    # every subsequent call (the real _poll_cache_dirs() poll).
    call_count = 0

    def flaky_then_working_poll_only_cache_paths():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("simulated transient plugin failure during startup seeding")
        return [sdists_root]

    lang.poll_only_cache_paths = flaky_then_working_poll_only_cache_paths

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        after_start = monitor.drain()
        assert sdists_root not in monitor._poll_only_seen, (
            "expected no baseline recorded for the root while its owning "
            "plugin's startup seeding call was still failing"
        )

        # First routine poll, after the plugin has recovered.
        await monitor._poll_cache_dirs()
        first_poll = monitor.drain()

        # A genuinely new build during this session must still be detected
        # — the fix must not permanently suppress this root's events.
        new_rev = sdists_root / "pypi" / "newpkg" / "2.0.0" / "fedcba9876543210"
        new_rev.mkdir(parents=True)
        (new_rev / "newpkg-2.0.0-py3-none-any.whl").touch()
        await monitor._poll_cache_dirs()
        second_poll = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert after_start == [], "start() must never queue events for pre-existing content"
    assert first_poll == [], (
        f"expected no replay of the pre-existing artifact once the "
        f"plugin recovered on the first real poll, got {first_poll}"
    )
    assert len(second_poll) >= 1
    assert all(e.package_name == "newpkg" and e.version == "2.0.0" for e in second_poll), (
        f"expected the genuinely new artifact to still be detected after "
        f"recovery, got {second_poll}"
    )


@pytest.mark.asyncio
async def test_poll_only_root_is_not_replayed_after_a_partial_startup_glob_failure(tmp_path):
    """Regression: the fix in
    test_poll_only_root_is_not_replayed_after_a_transient_startup_seeding_failure
    only covers a WHOLE plugin hook (poll_only_cache_paths()/
    cache_file_globs()) raising during startup discovery. It has its own,
    narrower gap: _seed_poll_only_baseline_sync()'s per-glob-pattern
    try/except (one glob raising partway through its own results, e.g. a
    transient I/O error on part of a large tree — discovery itself
    succeeding fine) used to silently record whatever the walk DID manage
    to gather as if it were the root's COMPLETE baseline. The root still
    gets a self._poll_only_seen entry — just a PARTIAL one, missing every
    artifact only the failed pattern would have matched — and nothing
    protected this root's still-incomplete entry. Once the glob failure
    clears on the very next real _poll_cache_dirs() poll, the missing
    artifact replays as a brand-new event — confirmed empirically (a
    pre-existing wheel, matched only by the failed **/*.whl pattern during
    startup seeding, fired as a new event once that pattern started
    working again). self._poll_only_seed_incomplete_roots (a per-root set)
    is what actually protects this — see that set's own docstring.
    """
    sdists_root = tmp_path / "sdists-v9"
    version_dir = sdists_root / "pypi" / "oldpkg" / "1.0.0"
    rev_dir = version_dir / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    old_wheel = rev_dir / "oldpkg-1.0.0-py3-none-any.whl"
    old_wheel.touch()
    _backdate(
        old_wheel, version_dir, rev_dir,
        sdists_root / "pypi" / "oldpkg", sdists_root / "pypi", sdists_root,
    )

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_glob = Path.glob

    def flaky_glob(self, pattern, **kwargs):
        # Only the **/*.whl pattern (which would match old_wheel) fails,
        # and only DURING the one-time startup seed walk — discovery
        # itself (poll_only_cache_paths()) succeeds fine, so this is
        # narrower than the whole-hook failure the earlier test covers.
        if self == sdists_root and pattern == "**/*.whl":
            raise OSError("Input/output error (simulated transient failure)")
        return real_glob(self, pattern, **kwargs)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with (
            patch.object(monitor, "_discover_cache_dirs", return_value=([], {})),
            patch.object(Path, "glob", flaky_glob),
        ):
            await monitor.start()

        after_start = monitor.drain()
        assert after_start == [], "start() must never queue events for pre-existing content"
        assert sdists_root in monitor._poll_only_seen, (
            "expected a (partial) baseline to still be recorded for the "
            "root despite one glob pattern failing"
        )
        assert sdists_root in monitor._poll_only_seed_incomplete_roots, (
            "expected the per-root incomplete tracking to catch the "
            "partial baseline from the failed glob pattern"
        )

        # Glob now works fine (transient failure cleared) — first real poll.
        await monitor._poll_cache_dirs()
        first_poll = monitor.drain()

        # A genuinely new build during this session must still be detected
        # — the fix must not permanently suppress this root's events.
        new_rev = sdists_root / "pypi" / "newpkg" / "2.0.0" / "fedcba9876543210"
        new_rev.mkdir(parents=True)
        (new_rev / "newpkg-2.0.0-py3-none-any.whl").touch()
        await monitor._poll_cache_dirs()
        second_poll = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert first_poll == [], (
        f"expected no replay of the artifact missed by the failed glob "
        f"pattern once it recovered on the first real poll, got {first_poll}"
    )
    assert not monitor._poll_only_seed_incomplete_roots, (
        "expected the root to be dropped from incomplete tracking once "
        "its walk completed cleanly"
    )
    assert len(second_poll) >= 1
    assert all(e.package_name == "newpkg" and e.version == "2.0.0" for e in second_poll), (
        f"expected the genuinely new artifact to still be detected after "
        f"recovery, got {second_poll}"
    )


@pytest.mark.asyncio
async def test_incomplete_seed_recovery_still_reports_artifact_created_after_the_failure(
    tmp_path,
):
    """Regression: a root whose startup seed walk was incomplete (one glob
    pattern raised) used to be folded wholesale into `unseeded_roots` on
    every later poll until it walked cleanly — suppressing EVERY artifact
    found on the recovery pass, not just the pre-existing content the
    failed walk might have missed. An sdist created AFTER the failed seed
    but before that recovery poll has no other observer at all (a
    poll-only root is never watched, by design), so suppressing it also
    recorded it into current_snapshot — which becomes the new baseline —
    and it was therefore emitted on NO poll, ever. Confirmed empirically
    (zero events across the recovery poll and every later one).

    The fix records the seed walk's own wall-clock cutoff alongside the
    incomplete root, so suppression applies only to entries whose mtime
    predates the failed walk. Genuinely pre-existing content stays
    suppressed (covered by
    test_poll_cache_dirs_does_not_replay_partially_seeded_root above,
    whose `first_poll == []` assertion is the complementary direction);
    anything newer is still reported.
    """
    sdists_root = tmp_path / "sdists-v9"
    stale_rev = sdists_root / "pypi" / "stalepkg" / "1.0.0" / "abcdef0123456789"
    stale_rev.mkdir(parents=True)
    stale_wheel = stale_rev / "stalepkg-1.0.0-py3-none-any.whl"
    stale_wheel.touch()
    # Genuinely pre-existing content, from before this daemon session.
    _backdate(
        stale_wheel, stale_rev, stale_rev.parent, stale_rev.parent.parent,
    )

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_glob = Path.glob
    fail_whl_glob = {"on": True}

    def flaky_glob(self, pattern, **kwargs):
        if fail_whl_glob["on"] and self == sdists_root and pattern == "**/*.whl":
            raise OSError("Input/output error (simulated transient failure)")
        return real_glob(self, pattern, **kwargs)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with (
            patch.object(monitor, "_discover_cache_dirs", return_value=([], {})),
            patch.object(Path, "glob", flaky_glob),
        ):
            await monitor.start()
        monitor.drain()

        assert sdists_root in monitor._poll_only_seed_incomplete_roots, (
            "expected the failed seed walk to mark this root incomplete"
        )

        # A genuinely NEW build lands after the failed seed walk, before
        # the recovery poll — nothing has ever observed it.
        new_rev = sdists_root / "pypi" / "freshpkg" / "2.0.0" / "fedcba9876543210"
        new_rev.mkdir(parents=True)
        (new_rev / "freshpkg-2.0.0-py3-none-any.whl").touch()

        fail_whl_glob["on"] = False
        await monitor._poll_cache_dirs()
        recovery_poll = monitor.drain()

        await monitor._poll_cache_dirs()
        later_poll = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    recovered_names = {e.package_name for e in recovery_poll}
    assert "freshpkg" in recovered_names, (
        f"expected the artifact created after the failed seed walk to be "
        f"reported on the recovery poll — it has no other observer, so "
        f"suppressing it loses it permanently, got "
        f"{[e.package_name for e in recovery_poll]}"
    )
    assert "stalepkg" not in recovered_names, (
        f"expected genuinely pre-existing content to stay suppressed, got "
        f"{[e.package_name for e in recovery_poll]}"
    )
    assert [e.package_name for e in later_poll] == [], (
        f"expected no replay on a later poll, got "
        f"{[e.package_name for e in later_poll]}"
    )


@pytest.mark.asyncio
async def test_unseeded_root_still_reports_artifact_created_after_startup(tmp_path):
    """Regression: `unseeded_roots` suppressed EVERY artifact under a root
    the daemon had never cleanly discovered, unconditionally. That is the
    right instinct for content which might be pre-existing, but the
    suppressed entry is still recorded into `current_snapshot`, which
    `_poll_cache_dirs()` writes wholesale over `self._poll_only_seen` —
    the baseline later polls diff against. Suppressed AND baselined means
    the artifact is reported on NO poll, ever.

    A poll-only root is never watched, so an artifact created AFTER
    daemon startup has no other observer at all; it cannot be
    pre-existing content a past failure hid, and suppressing it is a
    permanent silent miss of a real (possibly malicious) install.
    Confirmed empirically: zero events across three polls.

    Suppression is now scoped by `self._poll_only_startup_cutoff`, so
    only content predating the daemon is ever withheld.
    """
    sdists_root = tmp_path / "sdists-v9"
    sdists_root.mkdir()
    # Genuinely pre-existing content — must STAY suppressed.
    stale = sdists_root / "stalepkg-1.0.0.tar.gz"
    stale.touch()
    _backdate(stale, sdists_root)

    class _Flaky:
        name = "python"
        calls = 0

        def cache_file_globs(self):
            return ["*.tar.gz"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            # Fails ONLY during start()'s seed, so the root never lands in
            # _poll_only_ever_cleanly_discovered and the plugin never lands
            # in _poll_only_ever_succeeded_plugins.
            _Flaky.calls += 1
            if _Flaky.calls == 1:
                raise RuntimeError("transient discovery failure at startup")
            return [sdists_root]

        def classify_cache_file(self, path):
            if not path.name.endswith(".tar.gz"):
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="9.9.9", ecosystem="PyPI"
            )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[_Flaky()]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()
        monitor.drain()

        assert sdists_root not in monitor._poll_only_ever_cleanly_discovered, (
            "precondition: the failed startup discovery must leave this "
            "root un-discovered, which is what puts it in unseeded_roots"
        )

        # A malicious install lands well after startup.
        await asyncio.sleep(0.05)
        (sdists_root / "malicious-9.9.9.tar.gz").touch()

        await monitor._poll_cache_dirs()
        first = monitor.drain()
        await monitor._poll_cache_dirs()
        second = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    names = [e.package_name for e in first]
    assert "malicious" in names, (
        f"expected the post-startup artifact to be reported — it has no "
        f"other observer, so suppressing it loses it permanently, got {names}"
    )
    assert "stalepkg" not in names, (
        f"expected genuinely pre-existing content to stay suppressed, got {names}"
    )
    assert [e.package_name for e in second] == [], (
        f"expected no replay on a later poll, got "
        f"{[e.package_name for e in second]}"
    )


@pytest.mark.asyncio
async def test_pending_reseed_globs_still_report_artifact_created_after_startup(tmp_path):
    """Regression: the sibling of the `unseeded_roots` gap above, for the
    per-contributor arm. When a shared root's contributor fails at seed
    time, its globs go into `_poll_only_pending_reseed_globs` and every
    entry matching ONLY that contributor's pattern was suppressed
    unconditionally on the recovery pass — and, being recorded into the
    baseline by the same pass, lost permanently.

    Scoped by the startup cutoff, so only pre-daemon content is withheld.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()
    stale = shared_root / "stale-2.0.0.tar.gz"
    stale.touch()
    _backdate(stale, shared_root)

    class _A:
        name = "plugin-a"

        def cache_file_globs(self):
            return ["*.whl"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            return [shared_root]

        def classify_cache_file(self, path):
            if path.suffix != ".whl":
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="1.0.0", ecosystem="PyPI"
            )

    class _B:
        name = "plugin-b"
        calls = 0

        def cache_file_globs(self):
            return ["*.tar.gz"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            _B.calls += 1
            if _B.calls == 1:
                raise RuntimeError("plugin B fails at startup seed")
            return [shared_root]

        def classify_cache_file(self, path):
            if not path.name.endswith(".tar.gz"):
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="2.0.0", ecosystem="PyPI"
            )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages", return_value=[_A(), _B()]
    ):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()
        monitor.drain()

        # Matches ONLY the recovering contributor's glob, created after
        # startup — the case the subset check at the classify loop cannot
        # rescue, since no established contributor's pattern matches it.
        await asyncio.sleep(0.05)
        (shared_root / "malicious-2.0.0.tar.gz").touch()

        await monitor._poll_cache_dirs()
        first = monitor.drain()
        await monitor._poll_cache_dirs()
        second = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    names = [e.package_name for e in first]
    assert "malicious" in names, (
        f"expected the post-startup artifact matching only the recovering "
        f"contributor's glob to be reported, got {names}"
    )
    assert "stale" not in names, (
        f"expected the contributor's genuinely pre-daemon content to stay "
        f"suppressed, got {names}"
    )
    assert [e.package_name for e in second] == [], (
        f"expected no replay on a later poll, got "
        f"{[e.package_name for e in second]}"
    )


@pytest.mark.asyncio
async def test_healthy_poll_only_root_not_suppressed_by_unrelated_permanently_broken_plugin(
    tmp_path,
):
    """Regression: an earlier version of the startup-seeding-failure fix
    tracked "has discovery ever succeeded cleanly" as a single, whole-
    daemon `self._poll_only_seed_incomplete: bool` flag — True from
    construction until SOME discovery pass reported EVERY registered
    plugin succeeding. _poll_cache_dirs() used it to suppress events for
    ANY root with no prior self._poll_only_seen entry for as long as that
    flag stayed True, conflating "this SPECIFIC root's own seeding might
    still be incomplete" with "SOME plugin, anywhere, is currently
    failing". A perfectly healthy plugin's own poll-only root — e.g. a
    Python sdists-v* directory a real `uv sync` creates for the first
    time this session — had its own first, genuinely new artifacts
    silently swallowed as "possibly stale startup content" for as long as
    an entirely UNRELATED plugin kept failing. For a plugin that never
    recovers (a genuine bug in that plugin, not a transient environment
    glitch), this was PERMANENT, not just delayed — confirmed empirically:
    a healthy root's very first sighting produced zero events regardless
    of how many later polls ran, solely because a different, unrelated
    plugin's poll_only_cache_paths() never stopped raising.

    The fix tracks "has THIS root's own contributing plugin(s) ever
    succeeded" per root (self._poll_only_ever_cleanly_discovered), not as
    a single whole-daemon flag — a root's mere presence in a discovery
    pass's own result already proves its own plugin call succeeded that
    pass, regardless of whether some OTHER plugin's call raised.
    """
    sdists_root = tmp_path / "sdists-v9"

    python_lang = _python_only_lang(tmp_path / "unused-wheels-root")
    python_lang.poll_only_cache_paths = lambda: [sdists_root]

    class _PermanentlyBrokenLang:
        """A second, entirely unrelated plugin whose poll_only_cache_paths()
        always raises — never recovers, unlike the transient-failure
        fixtures used elsewhere in this file.
        """

        name = "broken-plugin"

        def cache_file_globs(self):
            return ["**/*.whl"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            raise RuntimeError("permanently broken plugin -- never recovers")

        def classify_cache_file(self, path):
            return None

    broken_lang = _PermanentlyBrokenLang()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[python_lang, broken_lang],
    ):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            # sdists_root does not exist yet at startup -- the unrelated
            # plugin is already broken from the very first discovery call.
            await monitor.start()
        monitor.drain()

        # A real `uv sync` creates sdists-v9 for the first time this
        # session, with a genuinely new, first-ever install already in it
        # by the time this poll runs.
        version_dir = sdists_root / "pypi" / "firstpkg" / "1.0.0"
        rev_dir = version_dir / "abcdef0123456789"
        rev_dir.mkdir(parents=True)
        (rev_dir / "firstpkg-1.0.0-py3-none-any.whl").touch()

        await monitor._poll_cache_dirs()
        first_poll = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(first_poll) >= 1, (
        "expected the healthy plugin's own genuinely new root and its "
        "first-ever install to be reported, not silently suppressed "
        "purely because an unrelated plugin is permanently broken"
    )
    assert all(e.package_name == "firstpkg" and e.version == "1.0.0" for e in first_poll), (
        f"expected only firstpkg==1.0.0 events, got {first_poll}"
    )


@pytest.mark.asyncio
async def test_new_poll_only_root_reported_using_the_real_unmodified_discovery_hook(
    tmp_path, monkeypatch,
):
    """Regression: every other test in this file that exercises a
    poll-only root's "genuinely new root" case overrides
    poll_only_cache_paths() with an UNCONDITIONAL lambda (e.g. `lambda:
    [sdists_root]`), which reports that path regardless of whether it
    exists on disk. The REAL PythonLanguage.poll_only_cache_paths()
    implementation is not unconditional — it filters to `p.is_dir()`, so
    a root that hasn't been created yet is simply ABSENT from its
    return, indistinguishable at the result level from "this plugin's
    call raised and its report was lost". Using the real, unmodified
    hook is what actually exercises that distinction; the lambda-based
    tests never did.

    With the earlier per-root-only fix (self._poll_only_ever_cleanly_discovered
    populated only from roots that actually appeared in some PAST
    discovery pass), a root that didn't exist at startup — so it was
    never in any pass's `cache_dirs` — could never be added to that set
    no matter how many clean passes ran. Once uv genuinely creates the
    root and its first install lands in it, _poll_cache_dirs() found it
    "never cleanly discovered" and silently suppressed its first-ever
    content — confirmed empirically with the real hook, a gap the
    lambda-override tests structurally could not have caught. The fix
    additionally tracks self._poll_only_ever_succeeded_plugins (has this
    PLUGIN's own call ever raised, independent of which roots it
    happened to return) — a root whose owning plugin has a fully clean
    history is trusted immediately on its own first appearance, with no
    need for a prior pass to have already recorded that exact path.
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    (fake_home / ".cache" / "uv").mkdir(parents=True)
    monkeypatch.setattr("packagealert.languages.python.Path.home", lambda: fake_home)

    python_lang = PythonLanguage()
    python_lang.cache_paths = list
    # Deliberately NOT overriding poll_only_cache_paths() — using the
    # real, unmodified implementation, which filters to existing
    # directories under Path.home() / ".cache" / "uv".

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[python_lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            # No sdists-v* directory exists yet anywhere under the fake
            # ~/.cache/uv at startup.
            await monitor.start()

        after_start = monitor.drain()
        assert not monitor._poll_only_ever_cleanly_discovered, (
            "expected no root to be recorded yet — none existed to discover"
        )

        # A real `uv sync` creates sdists-v9 for the first time this
        # session, with a genuinely new, first-ever install already in it.
        sdists_root = fake_home / ".cache" / "uv" / "sdists-v9"
        version_dir = sdists_root / "pypi" / "malicious" / "1.0.0"
        rev_dir = version_dir / "abcdef0123456789"
        rev_dir.mkdir(parents=True)
        (rev_dir / "malicious-1.0.0-py3-none-any.whl").touch()

        await monitor._poll_cache_dirs()
        first_poll = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert after_start == [], "start() must never queue events for pre-existing content"
    assert len(first_poll) >= 1, (
        "expected the genuinely new root's first-ever install to be "
        "reported using the real, unmodified discovery hook, not "
        "silently suppressed as possibly-missed startup content"
    )
    assert all(e.package_name == "malicious" and e.version == "1.0.0" for e in first_poll), (
        f"expected only malicious==1.0.0 events, got {first_poll}"
    )


@pytest.mark.asyncio
async def test_poll_cache_dirs_merges_shared_root_entries_on_failed_discovery(tmp_path):
    """Regression: two plugins can legitimately share the same poll-only
    root (see _discover_cache_dirs()'s own docstring on this), each
    contributing different globs. When one of them fails transiently,
    _discover_poll_only_cache_dirs()'s result for that shared root only
    carries the HEALTHY plugin's narrower glob — the failed plugin's own
    glob is simply missing from the merged pattern list for that pass, so
    _poll_cache_dirs_sync()'s own current_snapshot[root] for that pass can
    genuinely be missing an entry the failed plugin previously
    contributed (most concretely: a root discovered for the first time on
    the very same pass a plugin sharing it happens to fail on — there is
    then no PRIOR self._poll_only_seen entry for that root at all for
    _poll_cache_dirs_sync()'s own identity-based carry-forward to rescue
    the failed plugin's artifact from). _poll_cache_dirs()'s
    discovery_failed merge used to be a plain top-level
    dict.update(root -> current_snapshot[root]), which replaces
    self._poll_only_seen[root] wholesale with whatever current_snapshot
    says for that root — dropping any entry the previous baseline had
    that current_snapshot's narrower pass doesn't also mention. The merge
    must instead union the per-root SETS
    (self._poll_only_seen.get(root, set()) | current_snapshot[root]), not
    replace the root's value outright, so an entry the current pass's
    narrower globs couldn't have found still survives if the previous
    baseline already had it — confirmed empirically by isolating this
    exact merge step from _poll_cache_dirs_sync()'s own (correct, but
    insufficient on its own for this exact case) carry-forward logic.
    """
    shared_root = tmp_path / "sdists-v9"
    entry_a = (shared_root / "pkg-a-1.0.0-py3-none-any.whl", (1, 100, 1))
    entry_b = (shared_root / "pkg-b-1.0.0.tar.gz", (1, 200, 2))

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    # A prior baseline already covers both plugins' entries for the shared
    # root (e.g. from a previous, fully successful poll).
    monitor._poll_only_seen = {shared_root: {entry_a, entry_b}}

    # This pass: discovery failed for the plugin owning entry_b, so its
    # glob is missing from cache_dirs for the shared root, and
    # _poll_cache_dirs_sync()'s own current_snapshot for it — built purely
    # from what it can classify this pass — only reflects the healthy
    # plugin's entry_a. Nothing on disk actually changed for entry_b.
    with (
        patch.object(
            monitor, "_discover_poll_only_cache_dirs",
            return_value=(
                [(shared_root, ["*.whl"])], True, frozenset({"healthy-plugin"}),
                {shared_root: frozenset({"healthy-plugin"})},
                {"healthy-plugin": frozenset({"*.whl"})},
            ),
        ),
        patch.object(
            monitor, "_poll_cache_dirs_sync",
            return_value=({shared_root: {entry_a}}, [], set()),
        ),
    ):
        await monitor._poll_cache_dirs()

    assert entry_b in monitor._poll_only_seen[shared_root], (
        f"expected the other plugin's pre-existing entry to survive a "
        f"different plugin's transient discovery failure on the same "
        f"shared root, got {monitor._poll_only_seen[shared_root]}"
    )
    assert entry_a in monitor._poll_only_seen[shared_root]


@pytest.mark.asyncio
async def test_shared_root_partial_plugin_failure_at_startup_does_not_replay_on_recovery(
    tmp_path,
):
    """Regression: two plugins sharing the same poll-only root, each
    contributing its own distinct glob pattern. If ONE of them (plugin A)
    succeeds during startup discovery while the OTHER (plugin B) fails,
    the root still lands in `cache_dirs` (via A alone) and used to get
    marked fully "cleanly discovered" in
    self._poll_only_ever_cleanly_discovered from that ONE pass — even
    though only A's globs were ever actually walked, so only A's own
    pre-existing artifacts were seeded into self._poll_only_seen. B's own
    pre-existing artifacts (matched only by B's glob pattern) were never
    seeded at all, yet the root's "cleanly discovered" status already
    being True meant _poll_cache_dirs()'s `unseeded_roots` check no
    longer caught it once B recovered — B's genuinely pre-existing
    content then replayed as a brand-new install the moment B's glob
    finally ran successfully against it, confirmed empirically. The fix
    additionally tracks, per root, which specific plugins have ever
    successfully contributed to it (self._poll_only_root_known_plugins);
    a root already trusted overall but missing a contributor it's never
    recorded before still gets that contributor's own reseed treatment
    before its artifacts are ever reported.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()

    # Plugin A's pre-existing artifact, matched by A's own glob
    # ("*.whl") — present before the daemon even starts.
    a_artifact = shared_root / "apkg-1.0.0-py3-none-any.whl"
    a_artifact.touch()
    # Plugin B's pre-existing artifact, matched only by B's own glob
    # ("*.tar.gz") — ALSO present before the daemon starts, but B's
    # discovery call will fail during startup.
    b_artifact = shared_root / "bpkg-2.0.0.tar.gz"
    b_artifact.touch()
    _backdate(a_artifact, b_artifact, shared_root)

    class _PluginA:
        name = "plugin-a"

        def cache_file_globs(self):
            return ["*.whl"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            return [shared_root]

        def classify_cache_file(self, path):
            if path.suffix != ".whl":
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="1.0.0", ecosystem="PyPI"
            )

    class _PluginB:
        name = "plugin-b"
        call_count = 0

        def cache_file_globs(self):
            return ["*.tar.gz"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            self.call_count += 1
            if self.call_count == 1:
                raise RuntimeError("plugin B transiently fails at startup")
            return [shared_root]

        def classify_cache_file(self, path):
            if path.suffix != ".gz":
                return None
            return PackageMetadata(
                name=path.name.split(".")[0].split("-")[0],
                version="2.0.0",
                ecosystem="PyPI",
            )

    plugin_a = _PluginA()
    plugin_b = _PluginB()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[plugin_a, plugin_b],
    ):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        after_start = monitor.drain()
        assert shared_root in monitor._poll_only_ever_cleanly_discovered, (
            "expected the shared root to be marked discovered from "
            "plugin A's own successful contribution"
        )
        assert "plugin-b" not in monitor._poll_only_root_known_plugins.get(
            shared_root, frozenset()
        ), "expected plugin B to not yet be recorded as a known contributor"

        # Plugin B recovers on the next poll — nothing on disk changed,
        # bpkg has been sitting there the whole time.
        await monitor._poll_cache_dirs()
        recovery_events = monitor.drain()

        # A genuinely new artifact from EACH plugin, created after B's
        # recovery, must still be detected normally on the poll after.
        (shared_root / "newa-3.0.0-py3-none-any.whl").touch()
        (shared_root / "newb-4.0.0.tar.gz").touch()
        await monitor._poll_cache_dirs()
        followup_events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert after_start == [], "start() must never queue events for pre-existing content"
    assert recovery_events == [], (
        f"expected plugin B's genuinely pre-existing artifact to stay "
        f"suppressed on its first successful discovery, not replay as a "
        f"new install, got {recovery_events}"
    )
    assert sorted(e.package_name for e in followup_events) == ["newa", "newb"], (
        f"expected genuinely new artifacts from BOTH plugins to still be "
        f"detected normally after recovery, got {followup_events}"
    )


@pytest.mark.asyncio
async def test_new_contributor_reseed_does_not_suppress_other_contributors_new_artifact(
    tmp_path,
):
    """Regression: the fix for the shared-root partial-plugin-failure gap
    (test_shared_root_partial_plugin_failure_at_startup_does_not_replay_on_recovery)
    originally folded the whole root into `unseeded_roots` on the pass a
    new/recovering contributor is detected — suppressing every entry
    matched by ANY glob under that root, not just the recovering
    contributor's own. Since a poll-only root's self._poll_only_seen
    entry is wholesale-replaced every pass, this meant a genuinely NEW
    artifact from the ALREADY-known, healthy contributor — created on the
    exact same poll the other contributor happens to recover — got
    silently recorded into the baseline without ever being reported, and
    every LATER poll then treated it as already-seen: a permanent,
    silent miss, not merely a delay. Confirmed empirically. The fix scopes
    suppression to only the recovering contributor's own glob patterns
    (see _roots_with_a_new_contributing_plugin()'s `unseeded_globs`
    return), so the healthy contributor's own new artifact is still
    reported normally on the very same recovery pass.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()

    class _PluginA:
        name = "plugin-a"

        def cache_file_globs(self):
            return ["*.whl"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            return [shared_root]

        def classify_cache_file(self, path):
            if path.suffix != ".whl":
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="1.0.0", ecosystem="PyPI"
            )

    class _PluginB:
        name = "plugin-b"
        call_count = 0

        def cache_file_globs(self):
            return ["*.tar.gz"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            self.call_count += 1
            if self.call_count == 1:
                raise RuntimeError("plugin B transiently fails at startup")
            return [shared_root]

        def classify_cache_file(self, path):
            if path.suffix != ".gz":
                return None
            return PackageMetadata(
                name=path.name.split(".")[0].split("-")[0],
                version="2.0.0",
                ecosystem="PyPI",
            )

    plugin_a = _PluginA()
    plugin_b = _PluginB()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[plugin_a, plugin_b],
    ):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()
        monitor.drain()

        # On the SAME poll plugin B recovers, a genuinely NEW artifact
        # from the ALREADY-known, healthy plugin A also appears.
        new_a_artifact = shared_root / "newpkg-3.0.0-py3-none-any.whl"
        new_a_artifact.touch()

        await monitor._poll_cache_dirs()
        recovery_events = monitor.drain()

        # Confirm it wasn't merely delayed but genuinely reported once —
        # a later poll must not report it again either.
        await monitor._poll_cache_dirs()
        followup_events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert [(e.package_name, e.version) for e in recovery_events] == [
        ("newpkg", "1.0.0")
    ], (
        f"expected the healthy plugin's own genuinely new artifact to be "
        f"reported on the same poll the other contributor recovers, not "
        f"silently suppressed and lost, got {recovery_events}"
    )
    assert followup_events == [], (
        f"expected no re-report of the already-reported artifact on a "
        f"later poll, got {followup_events}"
    )


@pytest.mark.asyncio
async def test_new_contributor_reseed_does_not_suppress_overlapping_glob_match(
    tmp_path,
):
    """Regression: the fix above (scoping suppression to `unseeded_globs`
    rather than the whole root) still decided suppression PER GLOB
    PATTERN, inside the same loop that walked each pattern's own
    `glob()` results and used a shared `globbed` set to skip re-
    evaluating a path once ANY pattern had already matched it. Two
    plugins sharing a root can contribute OVERLAPPING glob patterns —
    e.g. a broad "**/*" alongside a narrower, more specific one — both
    matching the SAME path. If the recovering contributor's own
    (currently suppressed) broader pattern happened to be walked BEFORE
    the already-known, healthy contributor's own narrower pattern also
    matching the identical path, the path was recorded into the
    baseline without an event under the suppressed pattern, and the
    healthy contributor's own later pattern never got a chance to
    independently re-decide it — its genuinely new artifact was
    silently, permanently lost. Confirmed empirically. Suppression must
    be decided per PATH after considering every glob pattern that
    matched it: only suppressed if EVERY matching pattern is itself
    suppressed, not merely because SOME suppressed pattern happened to
    match it too.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()

    class _PluginA:
        name = "plugin-a"

        def cache_file_globs(self):
            # Narrow, specific pattern — this plugin's own.
            return ["pypi/*"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            return [shared_root]

        def classify_cache_file(self, path):
            if path.parent.name != "pypi" or path.name.startswith("."):
                return None
            return PackageMetadata(name=path.name, version="1.0.0", ecosystem="PyPI")

    class _PluginB:
        name = "plugin-b"
        call_count = 0

        def cache_file_globs(self):
            # Broad pattern that also matches plugin A's own artifacts —
            # a genuine overlap, not a hypothetical one: both patterns
            # can match the exact same path under this shared root.
            return ["**/*"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            self.call_count += 1
            if self.call_count == 1:
                raise RuntimeError("plugin B transiently fails at startup")
            return [shared_root]

        def classify_cache_file(self, path):
            return None  # plugin B never itself classifies anything here

    plugin_a = _PluginA()
    plugin_b = _PluginB()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    # Plugin B (the recovering, suppressed, broader-glob contributor) is
    # registered BEFORE plugin A (the established, narrower-glob
    # contributor) deliberately: _discover_dirs_by() merges each root's
    # globs in plugin-registration order, so this ensures the suppressed
    # "**/*" pattern is walked BEFORE the established "pypi/*" pattern —
    # exactly the ordering the bug this test targets depends on. With
    # plugin A registered first instead, its own narrower, non-suppressed
    # glob would claim the path before plugin B's broader one is ever
    # reached, masking the bug regardless of whether the fix is applied.
    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[plugin_b, plugin_a],
    ):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()
        monitor.drain()

        # On the SAME poll plugin B recovers, a genuinely NEW artifact
        # from the ALREADY-known, healthy plugin A appears — matched by
        # BOTH plugin A's own "pypi/*" and plugin B's broader "**/*".
        (shared_root / "pypi").mkdir()
        (shared_root / "pypi" / "newpkg").touch()

        await monitor._poll_cache_dirs()
        recovery_events = monitor.drain()

        await monitor._poll_cache_dirs()
        followup_events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert [(e.package_name, e.version) for e in recovery_events] == [
        ("newpkg", "1.0.0")
    ], (
        f"expected the healthy plugin's own genuinely new artifact to be "
        f"reported despite the recovering plugin's broader, overlapping "
        f"glob also matching it, got {recovery_events}"
    )
    assert followup_events == [], (
        f"expected no re-report of the already-reported artifact on a "
        f"later poll, got {followup_events}"
    )


@pytest.mark.asyncio
async def test_new_contributor_reseed_reuses_discovery_globs_not_a_second_call(tmp_path):
    """Regression: _roots_with_a_new_contributing_plugin() used to
    re-invoke a recovering contributor's cache_file_globs() a SECOND time
    to scope unseeded_globs, even though that exact plugin's identical
    call had already succeeded moments earlier THIS SAME PASS, inside
    _discover_dirs_by() (that success is exactly what makes the plugin
    show up in owning_plugins/new_plugins_by_root in the first place). If
    the second, redundant call transiently raised, unseeded_globs got no
    patterns for that root, so the recovering plugin's pre-existing
    artifacts were reported as brand-new installs. Worse,
    self._poll_only_root_known_plugins is updated to include the plugin
    as a known contributor unconditionally, before the (possibly
    failing) reseed glob lookup — so the root was never flagged for
    reseed again on any later pass either, permanently losing the
    chance to suppress that stale content. Confirmed empirically. The
    fix has _discover_dirs_by() return each plugin's own glob result
    (globs_by_plugin) alongside its other return values, and
    _roots_with_a_new_contributing_plugin() reuses that instead of
    calling cache_file_globs() again — removing the second call (and
    the failure window it opened) entirely.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()

    class _PluginA:
        name = "plugin-a"

        def cache_file_globs(self):
            return ["*.whl"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            return [shared_root]

        def classify_cache_file(self, path):
            if path.suffix != ".whl":
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="1.0.0", ecosystem="PyPI"
            )

    class _PluginB:
        name = "plugin-b"
        poll_call_count = 0
        globs_call_count = 0

        def cache_file_globs(self):
            # Inside _discover_dirs_by(), cache_file_globs() and
            # poll_only_cache_paths() are called exactly once each, in
            # that order, per pass — so at the moment this runs for
            # pass N, poll_call_count must still read N-1 (not yet
            # bumped by this same pass's poll_only_cache_paths() call
            # a line later). If _roots_with_a_new_contributing_plugin()
            # ever calls this a SECOND time for the same pass (the bug
            # this test guards against), poll_call_count will still
            # read N from the pass's own already-completed first call,
            # so the counts would already be equal here rather than
            # off-by-one — fail loudly instead of silently succeeding
            # twice.
            self.globs_call_count += 1
            if self.globs_call_count != self.poll_call_count + 1:
                raise AssertionError(
                    "cache_file_globs() called more than once for the "
                    "same poll pass — the reseed path must reuse "
                    "_discover_dirs_by()'s own result, not re-invoke "
                    "this hook"
                )
            return ["*.tar.gz"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            self.poll_call_count += 1
            if self.poll_call_count == 1:
                raise RuntimeError("plugin B transiently fails at startup")
            return [shared_root]

        def classify_cache_file(self, path):
            if path.suffix != ".gz":
                return None
            return PackageMetadata(
                name=path.name.split(".")[0].split("-")[0],
                version="2.0.0",
                ecosystem="PyPI",
            )

    plugin_a = _PluginA()
    plugin_b = _PluginB()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[plugin_a, plugin_b],
    ):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()
        monitor.drain()

        # Plugin B recovers this poll (poll_only_cache_paths succeeds for
        # the first time). Its own pre-existing artifact is already
        # sitting in shared_root, created before the daemon ever started.
        preexisting_b_artifact = shared_root / "stale-9.0.0.tar.gz"
        preexisting_b_artifact.touch()
        # Genuinely predates this daemon session — suppression of
        # pre-existing content is scoped by mtime against the startup
        # cutoff, so a bare touch() here would (correctly) be treated as
        # a NEW artifact. See _backdate()'s own docstring.
        _backdate(preexisting_b_artifact, shared_root)

        await monitor._poll_cache_dirs()
        recovery_events = monitor.drain()

        # A later poll's genuinely NEW artifact from plugin B must still
        # be reported — the root must not have been permanently marked
        # as a fully-known contributor without ever actually seeding it.
        new_b_artifact = shared_root / "freshpkg-9.1.0.tar.gz"
        new_b_artifact.touch()
        await monitor._poll_cache_dirs()
        followup_events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert recovery_events == [], (
        f"expected the recovering plugin's pre-existing artifact to be "
        f"suppressed (not reported as a new install), got {recovery_events}"
    )
    assert [(e.package_name, e.version) for e in followup_events] == [
        ("freshpkg", "2.0.0")
    ], (
        f"expected the recovering plugin's genuinely new artifact to be "
        f"reported on a later poll, not permanently suppressed, got "
        f"{followup_events}"
    )


@pytest.mark.asyncio
async def test_new_contributor_reseed_survives_glob_failure_during_recovery_pass(
    tmp_path,
):
    """Regression: _roots_with_a_new_contributing_plugin() marks a
    new/recovering contributor as known for a root
    (self._poll_only_root_known_plugins[d] = known | this_pass) as soon
    as it appears in `owning_plugins` — BEFORE its globs have actually
    been walked. If one of that contributor's own globs then raises
    during the very recovery pass meant to seed it (a transient I/O
    error on part of a large tree), only THAT pass suppressed its
    artifacts: by the next pass the contributor is no longer "new", so
    nothing suppresses it any more, and its never-walked, genuinely
    pre-daemon artifacts replay as brand-new installs the moment the
    glob starts working. Confirmed empirically.

    The fix keeps the contributor's globs pending in
    self._poll_only_pending_reseed_globs until a pass actually reports a
    complete walk for that root (not in _poll_cache_dirs_sync()'s
    `incomplete_roots`), so suppression carries across passes instead of
    lapsing the instant the contributor was marked known. Suppression
    stays scoped to that contributor's OWN globs — deliberately NOT
    whole-root, which was tried and confirmed to permanently lose a
    healthy contributor's genuinely new artifacts.
    """
    shared_root = tmp_path / "sdists-v9"
    shared_root.mkdir()
    # Plugin B's own pre-existing, pre-daemon artifact — matched only by
    # B's glob, so only B's own walk could ever seed it.
    _stale_b = shared_root / "stale-9.0.0.tar.gz"
    _stale_b.touch()
    # Genuinely predates this daemon session — see _backdate()'s docstring
    # and the sibling test above for why a bare touch() is not enough.
    _backdate(_stale_b, shared_root)

    class _PluginA:
        name = "plugin-a"

        def cache_file_globs(self):
            return ["*.whl"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            return [shared_root]

        def classify_cache_file(self, path):
            if path.suffix != ".whl":
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="1.0.0", ecosystem="PyPI"
            )

    class _PluginB:
        name = "plugin-b"
        poll_call_count = 0

        def cache_file_globs(self):
            return ["*.tar.gz"]

        def cache_paths(self):
            return []

        def poll_only_cache_paths(self):
            self.poll_call_count += 1
            if self.poll_call_count == 1:
                raise RuntimeError("plugin B transiently fails at startup")
            return [shared_root]

        def classify_cache_file(self, path):
            if not path.name.endswith(".tar.gz"):
                return None
            return PackageMetadata(
                name=path.name.split("-")[0], version="2.0.0", ecosystem="PyPI"
            )

    plugin_a = _PluginA()
    plugin_b = _PluginB()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_glob = Path.glob
    fail_b_glob = {"on": False}

    def flaky_glob(self, pattern, **kwargs):
        if fail_b_glob["on"] and self == shared_root and pattern == "*.tar.gz":
            raise OSError("Input/output error (simulated transient failure)")
        return real_glob(self, pattern, **kwargs)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[plugin_a, plugin_b],
    ):
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()
        monitor.drain()

        # Pass 1: B recovers (its poll_only_cache_paths() now succeeds, so
        # it's flagged as a new contributor) but its OWN glob raises
        # during this very walk — nothing of B's actually gets seeded.
        fail_b_glob["on"] = True
        with patch.object(Path, "glob", flaky_glob):
            await monitor._poll_cache_dirs()
        recovery_events = monitor.drain()

        # Pass 2: the glob works again. B is no longer "new" (it was
        # marked known back in pass 1), so only the pending-reseed
        # tracking can still suppress its never-walked stale artifact.
        fail_b_glob["on"] = False
        await monitor._poll_cache_dirs()
        reseed_events = monitor.drain()

        # Pass 3: a genuinely NEW artifact from the same contributor must
        # still be reported — the fix must not over-suppress.
        (shared_root / "freshpkg-1.2.3.tar.gz").touch()
        await monitor._poll_cache_dirs()
        fresh_events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert recovery_events == [], (
        f"expected nothing reported on the failed recovery pass, got "
        f"{recovery_events}"
    )
    assert reseed_events == [], (
        f"expected the recovering contributor's pre-daemon artifact to "
        f"stay suppressed once its glob started working again, not "
        f"replayed as a fresh install, got "
        f"{[(e.package_name, e.version) for e in reseed_events]}"
    )
    assert [(e.package_name, e.version) for e in fresh_events] == [
        ("freshpkg", "2.0.0")
    ], (
        f"expected a genuinely new artifact from the recovered "
        f"contributor to still be reported, got {fresh_events}"
    )


@pytest.mark.asyncio
async def test_poll_cache_dirs_sync_reports_incomplete_root_on_glob_failure(tmp_path):
    """Regression: _poll_cache_dirs_sync() must report which root(s) had a
    glob PATTERN raise partway through iterating its results (e.g. a
    transient I/O error on part of a large tree), not just log a warning
    and silently move on. The caller (_poll_cache_dirs()) needs this to
    know current_snapshot[root] for that root is a PARTIAL accounting
    (only reflecting whatever the pattern managed to yield before it
    raised, or nothing at all if it raised on the very first entry), not
    the complete set of what's currently classifiable — the same
    "discovery might be incomplete" distinction _discover_dirs_by()'s own
    `failed` flag already makes one level up, just for a different failure
    mode (the glob() walk itself, not cache_file_globs()/
    poll_only_cache_paths()).
    """
    sdists_root = tmp_path / "sdists-v9"
    rev_dir = sdists_root / "pypi" / "mypkg" / "1.0.0" / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    (rev_dir / "mypkg-1.0.0-py3-none-any.whl").touch()

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_glob = Path.glob

    def flaky_glob(self, pattern, **kwargs):
        if self == sdists_root and pattern == "**/*.whl":
            raise OSError("Input/output error (simulated transient failure)")
        return real_glob(self, pattern, **kwargs)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        cache_dirs, discovery_failed, _succeeded_plugins, _owning_plugins, _globs_by_plugin = (
            monitor._discover_poll_only_cache_dirs()
        )
        assert discovery_failed is False, "expected discovery itself to succeed"

        with patch.object(Path, "glob", flaky_glob):
            _current_snapshot, _events, incomplete_roots = monitor._poll_cache_dirs_sync(
                cache_dirs, set()
            )

    assert sdists_root in incomplete_roots, (
        f"expected {sdists_root} to be reported incomplete after a glob "
        f"pattern raised partway through its scan, got {incomplete_roots}"
    )


@pytest.mark.asyncio
async def test_poll_cache_dirs_preserves_baseline_for_root_with_incomplete_glob_scan(
    tmp_path,
):
    """Regression: _poll_cache_dirs()'s merge used to trust
    current_snapshot[root] as complete for any root NOT affected by a
    whole-pass discovery failure — but a glob PATTERN for a root that WAS
    successfully discovered can still raise partway through iterating its
    own results (e.g. a transient I/O error on part of a large tree),
    leaving current_snapshot[root] missing whatever only that pattern
    would have (re)matched. Wholesale-replacing self._poll_only_seen[root]
    with that partial result drops a real, previously-recorded entry —
    confirmed empirically — and once the transient condition clears, it
    replays as a spurious duplicate (the artifact never actually changed).
    The fix must union current_snapshot[root] with the PRIOR baseline for
    any root _poll_cache_dirs_sync() reports as incomplete, exactly as
    already done for a whole-pass discovery failure.
    """
    root = tmp_path / "sdists-v9"
    entry_dir = (root / "pypi" / "mypkg" / "1.0.0", (1, 100, 1))
    entry_whl = (
        root / "pypi" / "mypkg" / "1.0.0" / "abc" / "mypkg-1.0.0-py3-none-any.whl",
        (1, 200, 2),
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    # A prior baseline already covers both entries (e.g. from an earlier,
    # fully successful poll).
    monitor._poll_only_seen = {root: {entry_dir, entry_whl}}

    # This pass: discovery itself succeeds, but the .whl glob pattern for
    # this root raised partway through — current_snapshot for it only has
    # the version-dir entry, and _poll_cache_dirs_sync() reports the root
    # as incomplete. Nothing on disk actually changed for entry_whl.
    with (
        patch.object(
            monitor, "_discover_poll_only_cache_dirs",
            return_value=(
                [(root, ["**/*.whl", "pypi/*/*"])], False, frozenset({"python"}),
                {root: frozenset({"python"})},
                {"python": frozenset({"**/*.whl", "pypi/*/*"})},
            ),
        ),
        patch.object(
            monitor, "_poll_cache_dirs_sync",
            return_value=({root: {entry_dir}}, [], {root}),
        ),
    ):
        await monitor._poll_cache_dirs()

    assert entry_whl in monitor._poll_only_seen[root], (
        f"expected the wheel entry to survive a glob pattern's transient "
        f"failure on the same root, got {monitor._poll_only_seen[root]}"
    )
    assert entry_dir in monitor._poll_only_seen[root]


@pytest.mark.asyncio
async def test_rescan_isolates_schedule_failure_per_root(tmp_path):
    """A root whose observer.schedule() raises (e.g. ENOSPC, or the dir
    vanishing between exists() and schedule()) must not prevent other roots
    from being watched, and must not propagate out of _rescan_cache_paths()
    — that method runs inside events()'s loop body, so an unhandled raise
    there would silently kill the daemon's cache-monitor consumer task.
    """
    good_dir = tmp_path / "wheels-v7"
    bad_dir = tmp_path / "sdists-v9"
    # Neither exists yet at start() — both must be discovered by the rescan.

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [bad_dir, good_dir]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.return_value = None

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        await monitor.start()
        assert monitor._observer is not None, "start() must have created an observer"
        good_dir.mkdir()
        bad_dir.mkdir()

        real_schedule = monitor._observer.schedule

        def flaky_schedule(handler, path, **kwargs):
            if path == str(bad_dir):
                raise OSError(28, "inotify watch limit reached")
            return real_schedule(handler, path, **kwargs)

        with patch.object(monitor._observer, "schedule", side_effect=flaky_schedule):
            await monitor._rescan_cache_paths()  # must not raise

        assert good_dir in monitor._cache_root_watches
        assert bad_dir not in monitor._cache_root_watches

        # Next rescan retries the failed root, this time succeeding.
        await monitor._rescan_cache_paths()
        assert bad_dir in monitor._cache_root_watches

        monitor._observer.stop()
        monitor._observer.join()


@pytest.mark.asyncio
async def test_start_survives_schedule_failure_for_one_root(tmp_path):
    """Regression: _schedule_watch() must catch observer.schedule()
    failures itself, not rely on each caller to guard the call. start()
    previously called it unguarded — an ENOSPC (inotify out of watches) or
    any other scheduling failure for even one cache root would have
    propagated straight out of start() and aborted daemon startup entirely,
    rather than just skipping that one root.
    """
    good_dir = tmp_path / "wheels-v7"
    bad_dir = tmp_path / "sdists-v9"
    good_dir.mkdir()
    bad_dir.mkdir()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [bad_dir, good_dir]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.return_value = None

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_schedule = BaseObserver.schedule

    def flaky_schedule(self, handler, path, **kwargs):
        if path == str(bad_dir):
            raise OSError(28, "inotify watch limit reached")
        return real_schedule(self, handler, path, **kwargs)

    with (
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
        patch.object(BaseObserver, "schedule", flaky_schedule),
    ):
        await monitor.start()  # must not raise

    assert monitor._running is True
    assert good_dir in monitor._cache_root_watches
    assert bad_dir not in monitor._cache_root_watches

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_start_survives_inotify_add_watch_failure_for_one_root(tmp_path):
    """Regression: BaseObserver.schedule() only allocates the real inotify
    watch descriptor synchronously when the observer is already running —
    the actual inotify_add_watch() call (where ENOSPC surfaces) happens
    inside InotifyBuffer's constructor, called from the emitter's
    on_thread_start(). If the observer isn't alive yet when schedule() is
    called, it just registers a dormant emitter and defers starting it (and
    therefore the real add_watch() and any failure from it) to the
    observer's own start() call — which runs entirely outside
    _schedule_watch()'s try/except.

    The sibling test above only mocks BaseObserver.schedule() itself
    raising, which does not exercise this path: it doesn't catch a
    regression where start() schedules all watches before starting the
    observer, letting a real add_watch() failure escape from
    self._observer.start() instead of from _schedule_watch(). This test
    patches InotifyBuffer.__init__ — the actual failure point — to make sure
    a bad root still can't prevent a good one from being watched, or abort
    daemon startup.
    """
    from watchdog.observers.inotify_buffer import InotifyBuffer

    good_dir = tmp_path / "wheels-v7"
    bad_dir = tmp_path / "sdists-v9"
    good_dir.mkdir()
    bad_dir.mkdir()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [bad_dir, good_dir]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.return_value = None

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_init = InotifyBuffer.__init__

    def flaky_init(self, path, **kwargs):
        if path == str(bad_dir).encode():
            raise OSError(28, "No space left on device")
        return real_init(self, path, **kwargs)

    with (
        patch("packagealert.languages.registry.all_languages", return_value=[lang]),
        patch.object(InotifyBuffer, "__init__", flaky_init),
    ):
        await monitor.start()  # must not raise

    assert monitor._running is True
    assert good_dir in monitor._cache_root_watches
    assert bad_dir not in monitor._cache_root_watches

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_failed_schedule_does_not_leak_handler_registration(tmp_path):
    """Regression: BaseObserver.schedule() registers the event handler
    against its ObservedWatch *before* starting that watch's emitter —
    see BaseObserver.schedule() in watchdog/observers/api.py. So when
    starting the emitter fails (e.g. ENOSPC), the handler this call just
    registered is left behind even though _schedule_watch() reports the
    registration as failed and returns None.

    Left alone, each failed retry for the same path adds one more leaked
    handler that's never removed. Once a later retry succeeds and the watch
    goes live, watchdog dispatches every filesystem event to *every*
    handler still registered for that watch — so a single real file would
    be classified and queued once per leaked handler, producing duplicate
    PackageEvents (and duplicate downstream alert/risk processing) for one
    install.

    Reproduces the reviewer's exact scenario: two failed schedule attempts
    for the same root, followed by a successful third, must leave exactly
    one handler registered and emit exactly one PackageEvent for one
    classified file written afterward.
    """
    from watchdog.observers.inotify_buffer import InotifyBuffer

    from packagealert.languages.base import PackageMetadata

    root = tmp_path / "wheels-v7"
    root.mkdir()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [root]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.return_value = PackageMetadata(
        name="somepkg", version="1.0.0", ecosystem="PyPI"
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        # No cache dirs discovered at startup, so `root` isn't watched yet —
        # _rescan_cache_paths() below is what discovers and (repeatedly)
        # tries to register it.
        with patch.object(monitor, "_discover_cache_dirs", return_value=([], {})):
            await monitor.start()

        real_init = InotifyBuffer.__init__
        fail_count = {"n": 0}

        def flaky_init(self, path, **kwargs):
            if path == str(root).encode() and fail_count["n"] < 2:
                fail_count["n"] += 1
                raise OSError(28, "No space left on device")
            return real_init(self, path, **kwargs)

        with patch.object(InotifyBuffer, "__init__", flaky_init):
            await monitor._rescan_cache_paths()  # attempt 1: fails
            await monitor._rescan_cache_paths()  # attempt 2: fails
        await monitor._rescan_cache_paths()  # attempt 3: succeeds

        assert root in monitor._cache_root_watches
        assert monitor._observer is not None, "start() must have created an observer"
        watch = monitor._cache_root_watches[root].watch
        handlers = monitor._observer._handlers.get(watch, set())
        assert len(handlers) == 1, (
            f"expected exactly 1 handler after 2 failed + 1 successful "
            f"registration, found {len(handlers)}"
        )

        (root / "somepkg-1.0.0-py3-none-any.whl").touch()
        deadline = time.monotonic() + 5.0
        while monitor._queue.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)

        events = []
        while not monitor._queue.empty():
            events.append(monitor._queue.get_nowait())
        assert len(events) == 1, (
            f"expected exactly 1 PackageEvent for one file write, got {len(events)}"
        )
        assert events[0].package_name == "somepkg"

        monitor._observer.stop()
        monitor._observer.join()


@pytest.mark.asyncio
async def test_add_site_packages_watch_survives_schedule_failure(tmp_path):
    """Regression: an unguarded observer.schedule() failure in
    add_site_packages_watch() would propagate out to the daemon's
    process-monitor consumer task — reachable from every process-monitor
    event carrying a site_packages_dir — and kill it outright, exactly the
    watch-budget-exhaustion scenario this module exists to survive.
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    assert monitor._observer is not None, "start() must have created an observer"
    with patch.object(
        monitor._observer, "schedule", side_effect=OSError(28, "inotify watch limit reached")
    ):
        monitor.add_site_packages_watch(site_packages, pid=12345)  # must not raise

    assert site_packages not in monitor._site_package_watches

    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_rescan_backfill_scan_failure_does_not_prevent_watch_or_propagate(tmp_path):
    """_backfill_scan() already guards its own body, so in practice it
    shouldn't raise — but _rescan_cache_paths() also wraps the call
    belt-and-braces, since a raise there runs inside events()'s loop body
    and would otherwise propagate and take down the cache-monitor consumer
    task. An unexpected _backfill_scan() failure must not propagate out of
    _rescan_cache_paths() and must not un-register the watch that was
    already scheduled — the watch stays live going forward even if this
    one backfill pass was incomplete.

    watch_dir must not exist until after start() — otherwise start() itself
    watches it and adds it to _cache_root_watches, so _rescan_cache_paths()
    skips it via the "already watched" check and the patched _backfill_scan
    is never reached, defeating the point of this test.

    _backfill_scan is called TWICE in this one _rescan_cache_paths() pass,
    not once: the main loop's own registration call fails first (raising,
    caught, treated as incomplete — see _reschedule_missing_watch()'s own
    return value docstring), which deliberately leaves tracked.known_plugins
    unset rather than marking this root's contributor as backfilled; the
    SAME pass's _backfill_new_contributors() call then immediately sees
    that contributor as still "new" (never marked known) and retries it —
    hitting the identically-mocked, still-raising _backfill_scan() again.
    Both calls must be caught the same way — neither may propagate or
    prevent the watch from being registered.
    """
    watch_dir = tmp_path / "wheels-v7"
    # Does NOT exist yet when monitor.start() runs.

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir not in monitor._cache_root_watches

        watch_dir.mkdir()

        with patch.object(monitor, "_backfill_scan", side_effect=RuntimeError("glob blew up")) as mock_backfill:
            await monitor._rescan_cache_paths()  # must not raise
            assert mock_backfill.call_count == 2, (
                f"expected the registration call and _backfill_new_contributors()'s "
                f"own retry within the same pass, got {mock_backfill.call_count} call(s)"
            )

        assert watch_dir in monitor._cache_root_watches
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


@pytest.mark.asyncio
async def test_rescan_retries_backfill_after_a_transient_glob_failure_instead_of_losing_content(
    tmp_path,
):
    """Regression: a glob PATTERN raising partway through _backfill_scan()'s
    own loop (a transient I/O error, not a malformed-pattern failure) used
    to still let the caller mark the whole registration as fully
    backfilled — tracked.known_plugins was set unconditionally after
    _reschedule_missing_watch() returned, regardless of whether the scan
    actually completed. Whatever ONLY the failed pattern would have
    matched was therefore never classified or queued, yet the SEPARATE
    tracked.known_content snapshot (a different glob() call moments
    later, which can succeed even when the scan's own call just failed)
    silently absorbed that same content as "already accounted for" —
    permanently missed, since nothing else ever re-backfills a root
    already in `_cache_root_watches`, and a live watch only ever fires
    for genuinely NEW creation, not pre-existing content it never
    observed in the first place. Confirmed empirically. _backfill_scan()
    now reports whether it completed, and a caller must not mark
    known_plugins/known_content on an incomplete scan — the SAME
    contributor is then retried on the NEXT rescan pass instead.
    """
    watch_dir = tmp_path / "wheels-v7"
    # Does NOT exist yet when monitor.start() runs.
    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir not in monitor._cache_root_watches

        # Root and its pre-existing artifact created together, before any
        # watch exists.
        watch_dir.mkdir(parents=True)
        artifact = watch_dir / "malicious-9.9.9-py3-none-any.whl"
        artifact.touch()

        # A real glob() failure, not a mocked _backfill_scan() — fails on
        # every Path.glob() call during this FIRST _rescan_cache_paths()
        # pass (both the main loop's own registration backfill AND
        # _backfill_new_contributors()'s own same-pass retry, which would
        # otherwise immediately succeed and mask the bug this test
        # targets), then succeeds on every call from a LATER pass onward.
        calls_in_first_pass = {"n": 0}
        first_pass_done = {"v": False}
        real_glob = Path.glob

        def flaky_glob(self, pattern, **kwargs):
            if not first_pass_done["v"]:
                calls_in_first_pass["n"] += 1
                raise OSError("transient I/O error during the first rescan pass")
            return real_glob(self, pattern, **kwargs)

        with patch.object(Path, "glob", flaky_glob):
            await monitor._rescan_cache_paths()
        first_pass_done["v"] = True

        assert calls_in_first_pass["n"] > 0, "expected the patched glob() to actually be exercised"
        first_pass_events = monitor.drain()
        tracked = monitor._cache_root_watches.get(watch_dir)
        assert tracked is not None, "expected the watch to still be registered"
        assert tracked.known_plugins == frozenset(), (
            "expected known_plugins to stay unset after every glob() call "
            "in this pass failed, so the next rescan retries this "
            "contributor rather than trusting it as fully accounted for"
        )

        # A later rescan pass, with nothing changed on disk — the
        # transient failure has cleared, so this retry should finally
        # succeed and report the artifact the first pass missed.
        await monitor._rescan_cache_paths()
        second_pass_events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    all_events = first_pass_events + second_pass_events
    assert [(e.package_name, e.version) for e in all_events] == [("malicious", "9.9.9")], (
        f"expected the artifact only the first pass's failed glob pattern "
        f"missed to be reported once it's retried on a later pass, not "
        f"permanently and silently lost, got {all_events}"
    )


@pytest.mark.asyncio
async def test_rescan_does_not_backfill_root_that_existed_but_failed_initial_scheduling(tmp_path):
    """Regression: a root that already existed at start() but failed its
    initial _schedule_watch() call (e.g. ENOSPC — inotify out of watches)
    must NOT be backfill-scanned once a later rescan's registration retry
    finally succeeds. Normal startup deliberately never backfills a root
    that already existed when start() ran (see
    test_rescan_backfill_scan_is_empty_for_freshly_created_root's sibling
    coverage for the "didn't exist yet" case) — treating a delayed
    registration retry the same as discovering a brand-new root would fire
    a burst of stale alerts for artifacts that have been sitting there
    since before this daemon session even began, purely because of how
    long the watch budget happened to stay exhausted.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    # Pre-existing artifacts from before this daemon session — must NOT
    # surface as alerts just because the watch registration was delayed.
    for i in range(3):
        stale = watch_dir / f"stalepkg{i}-1.0.0-py3-none-any.whl"
        stale.touch()
        # Genuinely predates this daemon session — the failed-scheduling
        # baseline is bounded by the startup cutoff, so a bare touch()
        # would (correctly) read as content created after the daemon
        # started. See _backdate()'s own docstring.
        _backdate(stale, watch_dir)

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        # Simulate ENOSPC during start(): the root exists, but scheduling
        # fails, so it's known-but-unwatched rather than never-attempted.
        with patch.object(CacheMonitor, "_schedule_watch", return_value=None):
            await monitor.start()
        assert watch_dir not in monitor._cache_root_watches
        assert watch_dir in monitor._known_cache_roots

        # Watch budget pressure subsides — the retry now succeeds.
        await monitor._rescan_cache_paths()
        assert watch_dir in monitor._cache_root_watches

        events = monitor.drain()

        # A genuinely NEW artifact created after the retry succeeds must
        # still be detected live — the fix must not disable the watch
        # itself, only its one-time backfill scan.
        fresh_wheel = watch_dir / "freshpkg-2.0.0-py3-none-any.whl"
        fresh_wheel.touch()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not events:
            events.extend(monitor.drain())
            if events:
                break
            await asyncio.sleep(0.05)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1, (
        f"expected only the post-retry live artifact, no stale pre-existing "
        f"ones, got {events}"
    )
    assert events[0].package_name == "freshpkg"
    assert events[0].version == "2.0.0"


@pytest.mark.asyncio
async def test_start_backfills_artifact_created_during_initial_schedule_gap(tmp_path):
    """Regression: start()'s own initial watch registration has the exact
    same gap _rescan_cache_paths()'s retry case does (see
    test_rescan_backfills_artifact_created_during_failed_watch_gap below),
    just one level earlier — start() used to take the known-root baseline
    snapshot, then call _schedule_watch() directly with will_backfill left
    at its default (False) and never run a backfill scan at all afterward.
    An artifact created strictly after the snapshot completes but before
    the watch actually goes live (a fast concurrent install landing right
    at daemon startup) was therefore in neither the baseline nor caught
    live, and — since start() never backfills — never scanned afterward
    either: a silent, permanent miss. The fix routes start()'s initial
    registration through the same _reschedule_missing_watch() coordination
    the retry case already uses (will_backfill=True, then a
    baseline-excluding backfill scan), so anything created in that gap is
    still caught, while a genuinely pre-existing artifact (present at
    snapshot time, in the baseline) stays correctly suppressed — normal
    startup must still never replay a root's existing contents.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    # Pre-existing artifact — must stay suppressed; only the artifact
    # created in the schedule gap below should produce an event.
    stale_wheel = watch_dir / "stalepkg-1.0.0-py3-none-any.whl"
    stale_wheel.touch()
    # Genuinely predates this daemon session — see the sibling test above
    # and _backdate()'s own docstring for why a bare touch() isn't enough.
    _backdate(stale_wheel, watch_dir)

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_snapshot = monitor._snapshot_root_baseline

    def racy_snapshot(cache_dir, globs, cutoff=None):
        result = real_snapshot(cache_dir, globs, cutoff)
        # A genuine install lands strictly after the baseline snapshot
        # completes but before _schedule_watch() (called right after,
        # inside _reschedule_missing_watch()) makes the watch live.
        (cache_dir / "racypkg-2.0.0-py3-none-any.whl").touch()
        return result

    with patch("packagealert.languages.registry.all_languages", return_value=[_python_only_lang(watch_dir)]):
        with patch.object(monitor, "_snapshot_root_baseline", side_effect=racy_snapshot):
            await monitor.start()

        deadline = time.monotonic() + 5.0
        events: list = []
        while time.monotonic() < deadline:
            events.extend(monitor.drain())
            if events:
                break
            await asyncio.sleep(0.05)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1, (
        f"expected only the artifact created during the initial schedule "
        f"gap, no stale pre-existing ones, got {events}"
    )
    assert events[0].package_name == "racypkg"
    assert events[0].version == "2.0.0"


@pytest.mark.asyncio
async def test_start_catches_artifact_created_during_own_baseline_snapshot_glob(tmp_path):
    """Regression: unlike
    test_start_backfills_artifact_created_during_initial_schedule_gap
    (an artifact created strictly AFTER the baseline snapshot completes
    but before the watch goes live), this covers an artifact created
    WHILE the snapshot's own glob() call is still executing — matched by
    that very glob() call, so it would have been silently absorbed into
    `exclude` as "pre-existing" under the old ordering. start() used to
    take this snapshot (_snapshot_root_baseline()) BEFORE
    _reschedule_missing_watch() was even called, i.e. before the watch
    existed at all — so such an artifact was neither in a live watch's
    view (nothing was watching yet) nor reported by the backfill scan
    that ran moments later (its own identity matched the snapshot's
    `exclude` set). A real install with zero events, not merely a delay
    — confirmed empirically. The fix takes this snapshot INSIDE
    _reschedule_missing_watch(), after the watch is already scheduled
    and its backfill_dedup already open, so a file created during the
    snapshot's own glob() walk is instead caught live by the watch, with
    _BackfillDedup's existing scan-vs-live-watch coordination correctly
    arbitrating it.
    """
    watch_dir = tmp_path / "wheels-v6"
    watch_dir.mkdir()
    # A genuinely pre-existing artifact, present before daemon startup —
    # must stay suppressed. Real uv wheel-index shape:
    # wheels-v*/pypi/<name>/<leaf> (see _uv_wheel_index_entry_to_metadata()).
    stale_entry = watch_dir / "pypi" / "stalepkg" / "1.0.0-py3-none-any"
    stale_entry.parent.mkdir(parents=True)
    stale_entry.touch()
    # Genuinely predates this daemon session — see _backdate()'s docstring.
    _backdate(stale_entry, stale_entry.parent, watch_dir)

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    racy_entry = watch_dir / "pypi" / "racypkg" / "2.0.0-py3-none-any"
    real_glob = Path.glob

    def racy_glob(self, pattern, **kwargs):
        result = list(real_glob(self, pattern, **kwargs))
        if self == watch_dir and pattern == "pypi/*/*":
            # A genuine new install lands WHILE this exact glob call is
            # scanning the root for _snapshot_root_baseline() — before
            # the watch even exists yet.
            racy_entry.parent.mkdir(parents=True, exist_ok=True)
            racy_entry.touch()
            result.append(racy_entry)
        return iter(result)

    with patch("packagealert.languages.registry.all_languages", return_value=[_python_only_lang(watch_dir)]):
        with patch.object(Path, "glob", racy_glob):
            await monitor.start()

        deadline = time.monotonic() + 5.0
        events: list = []
        while time.monotonic() < deadline:
            events.extend(monitor.drain())
            if events:
                break
            await asyncio.sleep(0.05)

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    package_names = {event.package_name for event in events}
    assert "racypkg" in package_names, (
        f"expected the artifact created during the baseline snapshot's "
        f"own glob() walk to be reported, not silently absorbed into the "
        f"exclude baseline, got {[e.package_name for e in events]}"
    )
    assert "stalepkg" not in package_names, (
        f"expected the genuinely pre-existing artifact to stay "
        f"suppressed, got {[e.package_name for e in events]}"
    )


@pytest.mark.asyncio
async def test_rescan_backfills_artifact_created_during_failed_watch_gap(tmp_path):
    """Regression: a real install landing in the gap between a root's
    failed initial _schedule_watch() (e.g. ENOSPC) and a later successful
    registration retry must still be detected. An earlier version of the
    known-root fix (see
    test_rescan_does_not_backfill_root_that_existed_but_failed_initial_scheduling)
    skipped the retry's backfill scan entirely once a root was marked known,
    which correctly suppressed stale pre-existing artifacts but also
    silently discarded any genuinely new artifact created during the gap —
    neither observed live (no watch existed yet) nor backfilled afterward
    (backfill was unconditionally skipped for a known root). The fix must
    instead snapshot the root's contents at the point it's first marked
    known and backfill only what's not in that snapshot on every retry.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    # Pre-existing artifact from before this daemon session — must NOT
    # surface as an alert just because the watch registration was delayed.
    stale_wheel = watch_dir / "stalepkg-1.0.0-py3-none-any.whl"
    stale_wheel.touch()
    # The failed-scheduling baseline is bounded by the startup cutoff (no
    # watch exists during that snapshot), so this must genuinely predate
    # the daemon rather than merely be created first — see _backdate().
    _backdate(stale_wheel, watch_dir)

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        # Simulate ENOSPC during start(): the root exists, but scheduling
        # fails, so it's known-but-unwatched rather than never-attempted.
        with patch.object(CacheMonitor, "_schedule_watch", return_value=None):
            await monitor.start()
        assert watch_dir not in monitor._cache_root_watches
        assert watch_dir in monitor._known_cache_roots

        # A genuine install lands in the gap: no watch exists yet to see it
        # live, and it happened after the known-root baseline was taken.
        fresh_wheel = watch_dir / "freshpkg-2.0.0-py3-none-any.whl"
        fresh_wheel.touch()

        # Watch budget pressure subsides — the retry now succeeds.
        await monitor._rescan_cache_paths()
        assert watch_dir in monitor._cache_root_watches

        events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1, (
        f"expected only the artifact created during the failed-watch gap, "
        f"no stale pre-existing ones, got {events}"
    )
    assert events[0].package_name == "freshpkg"
    assert events[0].version == "2.0.0"


@pytest.mark.asyncio
async def test_rescan_backfills_same_path_reinstall_during_failed_watch_gap(tmp_path):
    """Regression: the known-root baseline (_RootBaseline, recorded in
    self._known_cache_roots) used to exclude a retry's backfill scan by
    PATHNAME alone. A path present in the snapshot can be deleted and
    recreated at the exact same name while the watch is still unavailable
    (a same-version reinstall, or a rebuild landing on the same cache key)
    — no live watch exists for that whole gap to observe the replacement
    either — so a pathname-only exclude set could not tell the recreated
    entry apart from the stale one it was meant to suppress, silently and
    permanently losing the reinstall. The fix records each excluded
    entry's `_entry_identity()` (lstat) at snapshot time and only skips it
    on retry if that identity still matches; a changed identity at the
    same path is treated as new content, not the original stale artifact.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    wheel = watch_dir / "somepkg-1.0.0-py3-none-any.whl"
    wheel.symlink_to("/nonexistent/archive-v0/aaaaaaaaaaaaaaaa")

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        # Simulate ENOSPC during start(): the root exists, but scheduling
        # fails, so it's known-but-unwatched rather than never-attempted.
        with patch.object(CacheMonitor, "_schedule_watch", return_value=None):
            await monitor.start()
        assert watch_dir not in monitor._cache_root_watches
        assert watch_dir in monitor._known_cache_roots

        # A genuine reinstall lands in the gap, at the SAME path the
        # baseline already recorded — no live watch exists to see this
        # delete+recreate either.
        wheel.unlink()
        wheel.symlink_to("/nonexistent/archive-v0/bbbbbbbbbbbbbbbb")

        # Watch budget pressure subsides — the retry now succeeds.
        await monitor._rescan_cache_paths()
        assert watch_dir in monitor._cache_root_watches

        events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1, (
        f"expected the same-path reinstall landing in the failed-watch gap "
        f"to still be detected, got {events}"
    )
    assert events[0].package_name == "somepkg"
    assert events[0].version == "1.0.0"


@pytest.mark.asyncio
async def test_snapshot_root_baseline_glob_failure_does_not_replay_pre_existing_content(
    tmp_path,
):
    """Regression: _snapshot_root_baseline() takes the pre-watch snapshot
    passed as `exclude` to _backfill_scan() — the mechanism that keeps
    normal startup from backfilling a root's pre-existing contents (see
    that method's own docstring). If a glob PATTERN raised partway
    through this snapshot's own walk (a transient I/O error on part of a
    large tree, not a malformed-pattern failure — the analogous failure
    mode _poll_cache_dirs_sync()'s own incomplete_roots already handles
    on the polled-root side), the resulting `entries` dict was silently
    treated as a COMPLETE accounting of the root's pre-existing contents
    regardless. Whatever only that failed pattern would have matched was
    then simply absent from `exclude.entries` — so the real backfill
    scan that runs moments later (its own, SEPARATE glob() call, which
    can easily succeed even though the snapshot's identical-looking call
    just failed) does not find it in `exclude` and classifies it as a
    brand-new install, even though it's genuinely stale content that
    predates the daemon — confirmed empirically (a pre-existing wheel,
    missed only by the snapshot's own failed glob pattern, fired as a
    spurious "new install" event during start()'s own backfill).

    The fix retries a raising pattern (_ROOT_BASELINE_GLOB_RETRIES times)
    before giving up — this snapshot is a one-shot, at-registration-time
    operation, not a recurring poll, so paying a short retry cost here is
    worthwhile — and only marks the resulting _RootBaseline `incomplete`
    if every retry still fails, at which point _backfill_scan() treats
    an incomplete `exclude` as though it were `None` (excluding nothing)
    rather than trusting a known-partial baseline.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()

    # Pre-existing content from BEFORE this daemon session, matched by the
    # glob pattern that will fail during the snapshot specifically.
    old_wheel = watch_dir / "oldpkg-1.0.0-py3-none-any.whl"
    old_wheel.touch()
    # The snapshot is bounded by the startup cutoff, so this must genuinely
    # predate the daemon rather than merely be created first — see
    # _backdate()'s own docstring.
    _backdate(old_wheel, watch_dir)

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [watch_dir]
    lang.cache_file_globs.return_value = ["*.whl", "*.dist-info"]
    lang.classify_cache_file.return_value = PackageMetadata(
        name="oldpkg", version="1.0.0", ecosystem="PyPI"
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_glob = Path.glob
    calls = {"count": 0}

    def flaky_glob(self, pattern, **kwargs):
        # The "*.whl" pattern (which would find old_wheel) fails on its
        # FIRST call only — the pre-watch snapshot's own attempt — and
        # succeeds on every retry AND on the real backfill scan's own,
        # separate call moments later.
        if self == watch_dir and pattern == "*.whl":
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("Input/output error (simulated transient failure)")
        return real_glob(self, pattern, **kwargs)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(Path, "glob", flaky_glob):
            await monitor.start()

        events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert events == [], (
        f"expected the pre-existing artifact, missed only by the snapshot's "
        f"own transient glob failure, to stay suppressed via retry (or, "
        f"failing that, via the incomplete-baseline fallback) rather than "
        f"replay as a spurious new-install event, got {events}"
    )
    assert calls["count"] >= 2, (
        "expected the failed glob pattern to have been retried at least once"
    )


@pytest.mark.asyncio
async def test_snapshot_root_baseline_marks_incomplete_after_exhausting_retries(tmp_path):
    """Companion to test_snapshot_root_baseline_glob_failure_does_not_replay_
    pre_existing_content: if a glob pattern keeps failing across every
    retry attempt (not just a one-off transient blip the retry rescues),
    _RootBaseline.incomplete must still end up True. Isolated from the
    retry-succeeds case by failing only the SNAPSHOT's own glob() calls
    (every one of them, exhausting all retries) while leaving the real
    backfill scan's own, separate glob() call for the same pattern free
    to succeed.

    _backfill_scan() deliberately treats an incomplete `exclude` as
    `exclude=None` — excluding nothing, rather than trusting a
    known-partial baseline (see that method's own docstring for the
    reasoning: an occasional duplicate/stale alert over silently trusting
    inaccurate exclusion data). So the pre-existing artifact here IS
    reported once — the accepted cost for this specific, now-rare
    exhausted-every-retry case — which is the whole point of this test:
    proving the fallback engages (rather than the old code silently and
    permanently excluding it based on incomplete data forever, since the
    stale exclude entry was never allowed to be reconsidered).
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    old_wheel = watch_dir / "oldpkg-1.0.0-py3-none-any.whl"
    old_wheel.touch()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [watch_dir]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.return_value = PackageMetadata(
        name="oldpkg", version="1.0.0", ecosystem="PyPI"
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    real_snapshot_sync = monitor._snapshot_root_baseline

    def always_flaky_glob(self, pattern, **kwargs):
        raise OSError("Input/output error (persistent)")

    def snapshot_with_flaky_glob(cache_dir, globs, cutoff=None):
        # Only THIS call's own glob() is patched to always fail — the
        # backfill scan that runs afterward, inside start(), calls
        # cache_dir.glob() directly (not through this method), so it is
        # unaffected and free to succeed.
        with patch.object(Path, "glob", always_flaky_glob):
            return real_snapshot_sync(cache_dir, globs)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_snapshot_root_baseline", side_effect=snapshot_with_flaky_glob):
            await monitor.start()

        baseline = monitor._known_cache_roots.get(watch_dir)
        events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert baseline is not None
    assert baseline.incomplete is True, (
        "expected the baseline to be marked incomplete once every retry "
        "for the failing pattern was exhausted"
    )
    assert len(events) == 1 and events[0].package_name == "oldpkg", (
        f"expected the fallback to treat the incomplete baseline as "
        f"no-exclude (reporting the pre-existing artifact once, the "
        f"accepted cost), got {events}"
    )


@pytest.mark.asyncio
async def test_rescan_backfills_everything_when_known_root_itself_is_rebuilt(tmp_path):
    """Regression: a changed ROOT identity (not just an entry under it)
    must invalidate the WHOLE known-root baseline, not just fail to match
    individual stale pathnames one by one. If the entire cache-schema
    directory is deleted and recreated while unwatched (not merely one
    entry inside it), every path inside the new root is unconditionally
    new content — reusing the stale baseline's per-entry exclusions here
    would be wrong regardless of whether some new entry happens to share a
    pathname with a stale one, since those pathnames belong to a now-gone
    root.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    stale_wheel = watch_dir / "stalepkg-1.0.0-py3-none-any.whl"
    stale_wheel.touch()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        with patch.object(CacheMonitor, "_schedule_watch", return_value=None):
            await monitor.start()
        assert watch_dir not in monitor._cache_root_watches
        assert watch_dir in monitor._known_cache_roots

        # The entire root — not just one entry — is deleted and recreated
        # while unwatched (e.g. a full cache-schema directory rebuild).
        shutil.rmtree(watch_dir)
        watch_dir.mkdir()
        fresh_wheel = watch_dir / "freshpkg-2.0.0-py3-none-any.whl"
        fresh_wheel.touch()

        await monitor._rescan_cache_paths()
        assert watch_dir in monitor._cache_root_watches

        events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1, (
        f"expected the rebuilt root's contents to be fully backfilled, "
        f"got {events}"
    )
    assert events[0].package_name == "freshpkg"
    assert events[0].version == "2.0.0"


@pytest.mark.asyncio
async def test_rescan_still_backfills_genuinely_new_root_after_a_known_root_exists(tmp_path):
    """The known-root tracking that prevents a stale-alert burst on a
    registration retry (see
    test_rescan_does_not_backfill_root_that_existed_but_failed_initial_scheduling)
    must not accidentally suppress backfill for a DIFFERENT root that is
    genuinely new — e.g. uv creating wheels-v7 for the first time after an
    upgrade, with wheels-v6 already known from a previous session.
    """
    old_root = tmp_path / "wheels-v6"
    old_root.mkdir()
    new_root = tmp_path / "wheels-v7"
    # Does NOT exist yet when monitor.start() runs.

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with (
        patch.object(PythonLanguage, "cache_paths", return_value=[old_root, new_root]),
        patch(
            "packagealert.languages.registry.all_languages",
            return_value=[PythonLanguage()],
        ),
    ):
        await monitor.start()
        assert old_root in monitor._cache_root_watches
        assert new_root not in monitor._cache_root_watches
        assert old_root in monitor._known_cache_roots
        assert new_root not in monitor._known_cache_roots

        # uv upgrade: the new root appears with its first artifact
        # already inside it, before any watch exists for it.
        new_root.mkdir()
        (new_root / "newpkg-1.0.0-py3-none-any.whl").touch()

        await monitor._rescan_cache_paths()
        events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1
    assert events[0].package_name == "newpkg"
    assert events[0].version == "1.0.0"


@pytest.mark.asyncio
async def test_rescan_still_backfills_new_root_whose_first_schedule_attempt_fails(tmp_path):
    """Regression: _known_root_exclude() used to snapshot-and-record a
    baseline for a root with NO existing self._known_cache_roots entry —
    including a root FIRST DISCOVERED by a rescan (never seen at start(),
    since it didn't exist yet at daemon startup — see
    test_rescan_still_backfills_genuinely_new_root_after_a_known_root_exists
    for the successful-first-attempt case this test's sibling covers).

    If that root's very first _schedule_watch() call then fails (e.g.
    ENOSPC), _reschedule_missing_watch() returns BEFORE _backfill_scan()
    ever runs — nothing was ever scanned or reported for it. But the
    snapshot _known_root_exclude() already took (and stored) moments
    earlier was still there, and the NEXT rescan's retry reused it as
    `exclude` once scheduling finally succeeded — excluding content that
    had NEVER actually been backfilled, permanently losing any install
    present at (or created in the same operation as) the root's very
    first appearance. Confirmed empirically: a malicious install already
    sitting in a brand-new cache root produced zero events across a
    failed-then-successful schedule retry.

    Only start() has a legitimate "predates the daemon" baseline to
    exclude across retries (see that method's own docstring) — a root
    first discovered by a LATER rescan has nothing that predates the
    daemon's own attempt to watch it, so every retry for it must stay
    fully unfiltered until scheduling finally succeeds.
    """
    watch_dir = tmp_path / "wheels-v7"
    # Does NOT exist yet when monitor.start() runs.

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir not in monitor._cache_root_watches
        assert watch_dir not in monitor._known_cache_roots

        # The root is created for the first time, WITH a malicious
        # install already present — e.g. a uv cache-schema upgrade
        # immediately followed by an install into the new schema dir.
        watch_dir.mkdir()
        (watch_dir / "malicious-1.0.0-py3-none-any.whl").touch()

        # First rescan: discovers watch_dir for the first time, but its
        # schedule attempt fails (simulated ENOSPC).
        with patch.object(CacheMonitor, "_schedule_watch", return_value=None):
            await monitor._rescan_cache_paths()
        assert watch_dir not in monitor._cache_root_watches
        assert watch_dir not in monitor._known_cache_roots, (
            "expected no phantom baseline to be recorded for a root whose "
            "very first schedule attempt failed"
        )
        first_rescan_events = monitor.drain()

        # Watch budget pressure subsides — the retry now succeeds, with
        # NOTHING new added since the first attempt.
        await monitor._rescan_cache_paths()
        assert watch_dir in monitor._cache_root_watches
        second_rescan_events = monitor.drain()

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    events = first_rescan_events + second_rescan_events
    assert len(events) == 1, (
        f"expected the malicious install, present since the root's very "
        f"first discovery, to still be reported once scheduling finally "
        f"succeeds, got {events}"
    )
    assert events[0].package_name == "malicious"
    assert events[0].version == "1.0.0"


@pytest.mark.asyncio
async def test_backfill_scan_glob_failure_is_isolated(tmp_path):
    """_backfill_scan() itself must swallow a glob() failure rather than
    letting it propagate to the caller (_rescan_cache_paths()).
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch.object(Path, "glob", side_effect=OSError("directory vanished")):
        monitor._backfill_scan(watch_dir, ["*.whl"], _BackfillDedup())  # must not raise


@pytest.mark.asyncio
async def test_backfill_scan_isolates_glob_failure_per_pattern(tmp_path):
    """Regression: `globs` passed to _backfill_scan() is the UNION of every
    plugin sharing this cache root (see _discover_cache_dirs()) — one
    plugin's malformed pattern (e.g. an absolute glob, which Path.glob()
    rejects with NotImplementedError before it even starts matching, real
    and reproducible, not hypothetical) must not prevent every other
    pattern sharing this root from being scanned, including the built-in
    ones. A single try/except around the whole `for glob in globs` loop
    would abort the entire backfill the instant it reached the bad
    pattern, silently skipping every pattern after it in the merged list —
    regardless of whether those patterns belonged to the same plugin or a
    completely different, well-behaved one.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    wheel = watch_dir / "somepkg-1.0.0-py3-none-any.whl"
    wheel.touch()

    lang = MagicMock()
    lang.name = "python"
    lang.cache_paths.return_value = [watch_dir]
    lang.cache_file_globs.return_value = ["*.whl"]
    lang.classify_cache_file.side_effect = lambda p: (
        PackageMetadata(name="somepkg", version="1.0.0", ecosystem="PyPI")
        if p.name.endswith(".whl")
        else None
    )

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    # The malformed pattern is deliberately ordered BEFORE the valid one —
    # this is what actually exercises the bug: a single try/except around
    # the whole loop aborts on the first exception, so any pattern after
    # the bad one in iteration order is what gets skipped.
    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        monitor._backfill_scan(watch_dir, ["/absolute/glob", "*.whl"], _BackfillDedup())

    events = monitor.drain()
    assert len(events) == 1, (
        f"expected the valid '*.whl' pattern to still be scanned despite the "
        f"malformed '/absolute/glob' pattern earlier in the list, got {events}"
    )
    assert events[0].package_name == "somepkg"
    assert events[0].version == "1.0.0"


@pytest.mark.asyncio
async def test_maintenance_runs_under_sustained_busy_queue(tmp_path):
    """Regression: maintenance (_cleanup_dead_watches/_rescan_cache_paths)
    used to run only via a counter incremented on the queue-get TimeoutError
    branch. If events kept arriving faster than the 1s poll timeout, that
    branch never fired and a newly-created cache root (e.g. from a uv
    upgrade) went unwatched indefinitely — not just delayed. Maintenance
    must instead fire off a monotonic deadline checked after every
    iteration of events(), event or timeout alike.
    """
    from packagealert.models.events import PackageEvent

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    monitor._running = True

    with patch("packagealert.monitors.cache._MAINTENANCE_INTERVAL_SECONDS", 0.3):
        monitor._next_maintenance_at = time.monotonic() + 0.3
        maintenance_deadlines_seen: list[float] = []

        def fake_rescan():
            maintenance_deadlines_seen.append(time.monotonic())

        async def feeder():
            # Events every 0.05s — 6x faster than the 1.0s poll timeout that
            # gated maintenance under the old counter-based scheme.
            for i in range(20):
                await asyncio.sleep(0.05)
                await monitor._queue.put(PackageEvent(
                    ecosystem="pypi", package_name=f"pkg{i}", version="1.0",
                    source="cache", manager="unknown", project_path=None,
                    timestamp=datetime.now(UTC),
                ))
            monitor._running = False

        collected = []

        async def collect():
            async for ev in monitor.events():
                collected.append(ev)

        with (
            patch.object(monitor, "_cleanup_dead_watches"),
            patch.object(monitor, "_rescan_cache_paths", side_effect=fake_rescan),
        ):
            await asyncio.gather(collect(), feeder())

    assert len(collected) == 20
    assert len(maintenance_deadlines_seen) >= 2, (
        "maintenance must have fired multiple times over the ~1s busy run "
        "at a 0.3s interval, even though every queue.get() succeeded before "
        "its 1.0s timeout"
    )


@pytest.mark.asyncio
async def test_maintenance_runs_after_idle_timeout(tmp_path):
    """Baseline: maintenance still fires on an idle queue once the deadline
    has passed, via the TimeoutError path.
    """
    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    monitor._running = True
    monitor._next_maintenance_at = time.monotonic()  # already due

    with (
        patch.object(monitor, "_cleanup_dead_watches") as mock_cleanup,
        patch.object(monitor, "_rescan_cache_paths") as mock_rescan,
    ):
        gen = monitor.events()

        async def stop_soon():
            await asyncio.sleep(1.2)
            monitor._running = False

        collected = []

        async def collect():
            async for ev in gen:
                collected.append(ev)

        await asyncio.gather(collect(), stop_soon())

    assert collected == []
    mock_cleanup.assert_called()
    mock_rescan.assert_called()


@pytest.mark.asyncio
async def test_cleanup_detects_root_deleted_and_recreated_at_same_path(tmp_path):
    """Regression: `uv cache clean && uv sync` deletes a cache root and
    recreates it at the same pathname, all between two maintenance passes.
    inotify watches are bound to an inode, not a pathname, so the original
    watch silently stops seeing anything under the new directory — but
    Path.exists() is true throughout, so an existence-only staleness check
    never notices, the stale entry is never pruned, and
    _rescan_cache_paths() skips it forever (it's still "already watched").
    _cleanup_dead_watches() must detect the inode change and prune it so
    the next rescan re-registers against the new directory.

    This targets the fallback (device, inode) comparison specifically, not
    the primary event-based signal (see
    test_cleanup_detects_deletion_even_when_inode_is_reused below for that
    one) — cleanup is run immediately, before the real inotify
    IN_DELETE_SELF event has necessarily been dispatched and drained, so
    only _still_watching()'s identity check can be what prunes it here.

    Whether a real rmtree()+mkdir() actually produces a different inode is
    filesystem/allocator-dependent — the freed inode can be handed straight
    back out to the very next mkdir() on some filesystems (the same caveat
    _file_identity()'s own docstring documents), so asserting on that
    outcome would make this test's pass/fail depend on allocator behaviour
    rather than on _cleanup_dead_watches() itself. _file_identity() is
    mocked to deterministically report a different identity after the
    recreate, matching the established pattern used below for forcing the
    opposite (equal-identity) case.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir in monitor._cache_root_watches
        old_identity = monitor._cache_root_watches[watch_dir].identity
        new_identity = (old_identity[0], old_identity[1] + 1)

        # Delete and recreate at the same path — real filesystem behaviour,
        # but the resulting inode is not relied on (see docstring above).
        shutil.rmtree(watch_dir)
        watch_dir.mkdir()

        assert watch_dir.exists(), "path exists throughout — an exists()-only check would miss this"

        with patch(
            "packagealert.monitors.cache._file_identity",
            return_value=new_identity,
        ):
            monitor._cleanup_dead_watches()
        assert watch_dir not in monitor._cache_root_watches, (
            "stale watch (bound to the deleted inode) must be pruned even though the path exists"
        )

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_on_deleted_ignores_descendant_deletions(tmp_path):
    """Regression: for a recursive watch, inotify's IN_DELETE fires for
    every descendant deletion, not just the watch root's own IN_DELETE_SELF
    — deleting a real uv cache tree (`uv cache clean`) touches thousands of
    entries. Only the root's own deletion is a meaningful invalidation
    signal; each descendant deletion must be ignored rather than scheduling
    a wasted run_coroutine_threadsafe() call and queuing a useless item that
    sits in _invalidated_roots until the next maintenance pass (up to 60s
    later) — at real cache-tree scale this would flood the event loop and
    memory for no benefit.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    # A tree with several nested entries — deleting it must not produce one
    # invalidation per entry.
    for i in range(20):
        pkg_dir = watch_dir / f"pkg{i}"
        pkg_dir.mkdir()
        (pkg_dir / "file.whl").touch()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir in monitor._cache_root_watches

        # start() returns once BaseObserver.schedule() returns, which starts
        # the emitter thread but does not wait for it to reach
        # on_thread_start() and actually install the kernel inotify watch
        # (InotifyEmitter creates its InotifyBuffer, i.e. the real
        # inotify_add_watch(), only once its own thread starts running).
        # Deleting the tree before that watch is genuinely live means the
        # kernel never generates any inotify event for this deletion at
        # all — not a comparison bug, an environment/timing-dependent gap
        # between "schedule() returned" and "the watch actually exists".
        # A real, classifiable canary creation proves the watch is live
        # end-to-end (through on_created(), backfill_dedup.claim(), and the
        # queue) before the real test below relies on inotify catching the
        # deletion.
        canary = watch_dir / "canary-1.0.0-py3-none-any.whl"
        canary.touch()
        for _ in range(100):
            if monitor.drain():
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("watch never became active — canary creation was not observed")
        canary.unlink()

        shutil.rmtree(watch_dir)

        # Wait for the root's own IN_DELETE_SELF to land (the last event
        # inotify emits for this tree). A fixed 2.5s budget here was
        # confirmed flaky under real system load — not a logic bug: under
        # heavy CPU contention, delivery through watchdog's emitter thread
        # and its run_coroutine_threadsafe() hop to the event loop was
        # directly measured taking upwards of 12s, well past a "just bump it
        # a bit" budget. 30s is a generous empirical margin over that, not a
        # principled upper bound — there isn't one for real OS scheduling
        # delay — chosen so this loop fails only on an actual missing event,
        # not on this machine being busy.
        deadline = time.monotonic() + 30.0
        while monitor._invalidated_roots.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)

        assert monitor._invalidated_roots.qsize() == 1, (
            "deleting a whole tree of nested entries must produce exactly "
            "one invalidation (the root's own), not one per descendant"
        )
        invalidated = monitor._drain_invalidated_roots()
        assert {p for p, _gen in invalidated} == {watch_dir}

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


@requires_inotify_headroom
@pytest.mark.asyncio
@pytest.mark.integration
async def test_cleanup_detects_deletion_even_when_inode_is_reused(tmp_path):
    """Regression: (st_dev, st_ino) is not a stable directory-generation
    identifier by itself — after deletion, a filesystem may immediately
    reuse the same inode number on the same device for the replacement
    directory. In that case a bare identity comparison wrongly treats the
    recreated path as unchanged even though the original inotify watch is
    dead, so the stale entry would remain forever. The event-based signal
    (_Handler.on_deleted(), fired from real inotify IN_DELETE_SELF) must
    still detect the deletion correctly, independent of whatever the
    identity comparison would have concluded.

    This is simulated by forcing _file_identity() to report the same value
    both before and after the real delete+recreate, so the fallback
    identity check alone would wrongly report "still watching" — proving
    the fix does not rely solely on that comparison.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir in monitor._cache_root_watches

        # start() returns once BaseObserver.schedule() returns, which starts
        # the emitter thread but does not wait for it to reach
        # on_thread_start() and actually install the kernel inotify watch.
        # Deleting the tree before that watch is genuinely live means the
        # kernel never generates an IN_DELETE_SELF for it at all — an
        # environment/timing-dependent gap, not something the post-deletion
        # polling loop below can compensate for. A real, classifiable
        # canary creation proves the watch is live end-to-end first.
        canary = watch_dir / "canary-1.0.0-py3-none-any.whl"
        canary.touch()
        for _ in range(100):
            if monitor.drain():
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("watch never became active — canary creation was not observed")
        canary.unlink()

        # Real delete + recreate at the same path (as uv cache clean does).
        shutil.rmtree(watch_dir)
        watch_dir.mkdir()

        # Wait for watchdog's inotify emitter thread to observe and dispatch
        # the IN_DELETE_SELF event before running cleanup — on_deleted()
        # hands off to the event loop via run_coroutine_threadsafe(), which
        # needs a beat to land. Same 30s empirical margin and reasoning as
        # test_on_deleted_ignores_descendant_deletions's identical loop: a
        # fixed 2.5s budget here was confirmed flaky under real system load,
        # not a logic bug — real delivery was directly measured taking
        # upwards of 12s under contention.
        deadline = time.monotonic() + 30.0
        while monitor._invalidated_roots.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)

        with patch(
            "packagealert.monitors.cache._file_identity",
            return_value=monitor._cache_root_watches[watch_dir].identity,
        ):
            # With identity forced to compare equal, only the event-based
            # signal can detect the deletion.
            monitor._cleanup_dead_watches()

        assert watch_dir not in monitor._cache_root_watches, (
            "the delete event must invalidate the watch even though the "
            "(forced-equal) identity comparison alone would say unchanged"
        )

        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


@pytest.mark.asyncio
async def test_maintenance_reschedules_watch_after_root_recreated(tmp_path):
    """End-to-end version of the inode-tracking fix: a full maintenance pass
    (cleanup then rescan, as events() runs them together) must both prune
    the stale watch and re-register a fresh one against the recreated
    directory — and backfill-scan it, so an artifact written into the new
    directory before the new watch existed is still detected.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        old_tracked = monitor._cache_root_watches[watch_dir]

        # start() returns once BaseObserver.schedule() returns, before the
        # emitter thread has necessarily reached on_thread_start() and
        # actually installed the kernel inotify watch — see the identical
        # comment in test_cleanup_detects_deletion_even_when_inode_is_reused
        # above. Confirm the watch is genuinely live before relying on it to
        # observe the delete+recreate below.
        canary = watch_dir / "canary-1.0.0-py3-none-any.whl"
        canary.touch()
        for _ in range(100):
            if monitor.drain():
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("watch never became active — canary creation was not observed")
        canary.unlink()

        shutil.rmtree(watch_dir)
        watch_dir.mkdir()
        (watch_dir / "requests-2.31.0-py3-none-any.whl").touch()

        monitor._next_maintenance_at = 0  # force due
        await monitor._run_maintenance_if_due()

        new_tracked = monitor._cache_root_watches.get(watch_dir)
        assert new_tracked is not None
        # A delete+recreate cycle is allowed to hand the freed inode straight
        # back out — same-device inode reuse, not guaranteed to differ — so
        # comparing `identity` here would make this assertion's pass/fail
        # depend on allocator behaviour rather than on maintenance actually
        # having replaced the watch. `generation` is a token minted in-process
        # by _schedule_watch() (CacheMonitor._next_generation), independent of
        # any filesystem state, so a changed value directly and reliably
        # confirms a fresh registration regardless of what the real inode
        # ended up being.
        assert new_tracked.generation != old_tracked.generation

        events = monitor.drain()
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    assert len(events) == 1
    assert events[0].package_name == "requests"
    assert events[0].version == "2.31.0"


@pytest.mark.asyncio
async def test_cleanup_keeps_watch_when_path_unchanged(tmp_path):
    """A path that still exists at the same inode must not be pruned — the
    inode check must not be a stricter false-positive trigger than the old
    exists()-only check for the common, unchanged case.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        tracked_before = monitor._cache_root_watches[watch_dir]

        monitor._cleanup_dead_watches()

        assert watch_dir in monitor._cache_root_watches
        assert monitor._cache_root_watches[watch_dir] is tracked_before
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


def test_still_watching_rejects_matching_inode_on_different_device(tmp_path: Path):
    """Regression: st_ino alone is not a safe identity check — it is only
    guaranteed unique within a single device (e.g. /tmp and /proc can both
    report inode 1 on the same machine). A stale watch whose recorded inode
    happens to match a same-numbered inode on a *different* device must
    still be treated as dead, not as "the same directory, still fine."
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    real_stat = watch_dir.stat()

    tracked = _TrackedWatch(
        watch=MagicMock(),
        identity=(real_stat.st_dev + 1, real_stat.st_ino),
        generation=0,
        last_activity=time.monotonic(),
    )

    # Same st_ino as `tracked.identity`, but a different st_dev — must not
    # be considered "still the same watched directory".
    assert _still_watching(watch_dir, tracked) is False


def test_still_watching_accepts_matching_dev_and_inode(tmp_path: Path):
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    tracked = _TrackedWatch(
        watch=MagicMock(),
        identity=_file_identity(watch_dir),
        generation=0,
        last_activity=time.monotonic(),
    )

    assert _still_watching(watch_dir, tracked) is True


@pytest.mark.asyncio
async def test_cleanup_detects_site_packages_venv_recreated(tmp_path):
    """The same inode-tracking fix applies to _site_package_watches — a venv
    rebuilt with `rm -rf .venv && uv venv` has the identical failure mode.

    Whether a real rmtree()+mkdir() actually produces a different inode is
    filesystem/allocator-dependent — see
    test_cleanup_detects_root_deleted_and_recreated_at_same_path above,
    whose adjacent regression test
    (test_cleanup_detects_deletion_even_when_inode_is_reused) establishes
    that immediate reuse is a real possibility, not just a hypothetical one.
    Asserting on the real post-recreate identity — here, or on the identity
    add_site_packages_watch() re-registers with afterwards, which calls
    _schedule_watch() -> _file_identity() again — would make both
    assertions' pass/fail depend on allocator behaviour rather than on the
    cleanup/re-registration logic itself. _file_identity() is mocked to a
    deterministic value for the whole span from cleanup through
    re-registration (add_site_packages_watch() also runs its own internal
    _cleanup_dead_watches() first — see its docstring — so that call must
    see the same mocked value too), and both assertions check against that
    known value directly instead of merely "not equal to old".
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()
    monitor.add_site_packages_watch(site_packages)
    assert site_packages in monitor._site_package_watches
    old_identity = monitor._site_package_watches[site_packages].identity
    new_identity = (old_identity[0], old_identity[1] + 1)

    # Real delete + recreate at the same path — real filesystem behaviour,
    # but the resulting inode is not relied on (see docstring above).
    shutil.rmtree(site_packages)
    site_packages.mkdir()

    with patch(
        "packagealert.monitors.cache._file_identity",
        return_value=new_identity,
    ):
        monitor._cleanup_dead_watches()
        assert site_packages not in monitor._site_package_watches

        # add_site_packages_watch() is idempotent-by-path, so without the
        # cleanup above it would never re-register against the new identity.
        monitor.add_site_packages_watch(site_packages)
    assert site_packages in monitor._site_package_watches
    assert monitor._site_package_watches[site_packages].identity == new_identity

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_site_packages_watch_idles_out_with_no_owning_process(tmp_path):
    """A site-packages watch registered with no owning PID (the deferred/
    lockfile emission path — the process has already exited by the time the
    event fires) must be reclaimed once idle for
    _SITE_PACKAGES_WATCH_IDLE_SECONDS. Left unbounded, every distinct
    project a developer ever touches would accumulate a permanent watch for
    the lifetime of the daemon.
    """
    from packagealert.monitors.cache import _SITE_PACKAGES_WATCH_IDLE_SECONDS

    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    monitor.add_site_packages_watch(site_packages)
    assert site_packages in monitor._site_package_watches

    tracked = monitor._site_package_watches[site_packages]
    tracked.last_activity -= _SITE_PACKAGES_WATCH_IDLE_SECONDS + 1

    monitor._cleanup_dead_watches()
    assert site_packages not in monitor._site_package_watches

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_site_packages_watch_survives_idle_while_owning_process_alive(tmp_path):
    """A watch whose owning package-manager process is still running must
    not be idle-expired, however long that takes — a slow resolver (e.g.
    pipenv working through a large lockfile) can go well past the idle
    window before writing its first file, and must not lose its watch
    mid-install.
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    proc = subprocess.Popen(["sleep", "30"])  # noqa: ASYNC220 — need a real live PID; nothing else in this test awaits concurrently
    try:
        monitor.add_site_packages_watch(site_packages, pid=proc.pid)
        tracked = monitor._site_package_watches[site_packages]
        assert proc.pid in tracked.owning_pids

        tracked.last_activity -= 10_000  # far past any reasonable idle window

        monitor._cleanup_dead_watches()
        assert site_packages in monitor._site_package_watches, (
            "watch must survive while its owning process is still running, "
            "regardless of how long it's been idle"
        )
    finally:
        proc.terminate()
        proc.wait()

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_site_packages_watch_idles_out_after_owning_process_exits(tmp_path):
    """Once the owning process has exited, idle-expiry applies normally —
    the watch doesn't survive forever just because it once had an owner.
    """
    from packagealert.monitors.cache import _SITE_PACKAGES_WATCH_IDLE_SECONDS

    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    proc = subprocess.Popen(["true"])  # noqa: ASYNC220 — need a real exited PID; nothing else in this test awaits concurrently
    proc.wait()

    monitor.add_site_packages_watch(site_packages, pid=proc.pid)
    assert site_packages in monitor._site_package_watches
    tracked = monitor._site_package_watches[site_packages]
    assert tracked.owning_pids == {}, (
        "a PID that's already exited by registration time must not be recorded — "
        "the watch falls back to plain idle-timeout behaviour"
    )

    tracked.last_activity -= _SITE_PACKAGES_WATCH_IDLE_SECONDS + 1
    monitor._cleanup_dead_watches()
    assert site_packages not in monitor._site_package_watches

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_configured_site_packages_watch_survives_idle_expiry(tmp_path):
    """Regression: WatchConfig.site_packages_dirs entries — the user
    explicitly asking for a directory to be watched — must never be
    idle-expired. Unlike dynamically-detected watches, a configured entry
    has no owning process and nothing ever re-registers it (cache_paths()
    rescanning only covers _cache_root_watches), so once idle-expired it
    would stay silently unwatched for the rest of the daemon's lifetime.
    """
    from packagealert.monitors.cache import _SITE_PACKAGES_WATCH_IDLE_SECONDS

    configured = tmp_path / "my-project" / "site-packages"
    configured.mkdir(parents=True)

    cfg = WatchConfig(enable_cache_monitoring=True, site_packages_dirs=[configured])
    monitor = CacheMonitor(cfg)
    with patch("packagealert.languages.registry.all_languages", return_value=[]):
        await monitor.start()

    assert configured in monitor._site_package_watches
    tracked = monitor._site_package_watches[configured]
    assert tracked.exempt_from_idle is True
    assert tracked.owning_pids == {}, "a configured watch has no owning process at all"

    # Far past any reasonable idle window.
    tracked.last_activity -= _SITE_PACKAGES_WATCH_IDLE_SECONDS * 10

    monitor._cleanup_dead_watches()
    assert configured in monitor._site_package_watches, (
        "a user-configured site_packages_dirs entry must never be idle-expired — "
        "nothing would ever re-register it"
    )

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_dynamically_detected_site_packages_watch_is_not_idle_exempt(tmp_path):
    """Contrast case: a watch registered reactively via
    add_site_packages_watch() (not from WatchConfig.site_packages_dirs)
    must still idle-expire normally — the exemption is specifically for
    configured entries, not a blanket exemption for the whole dict.
    """
    from packagealert.monitors.cache import _SITE_PACKAGES_WATCH_IDLE_SECONDS

    dynamic = tmp_path / "other-project" / "site-packages"
    dynamic.mkdir(parents=True)

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    monitor.add_site_packages_watch(dynamic)
    tracked = monitor._site_package_watches[dynamic]
    assert tracked.exempt_from_idle is False

    tracked.last_activity -= _SITE_PACKAGES_WATCH_IDLE_SECONDS + 1
    monitor._cleanup_dead_watches()
    assert dynamic not in monitor._site_package_watches

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_add_site_packages_watch_tracks_all_concurrent_owners(tmp_path):
    """Regression: a second install starting against an already-watched
    site-packages directory (e.g. two overlapping installs into the same
    venv) must be ADDED to the set of tracked owners, not replace whichever
    was recorded before and not be silently discarded by the "already
    watched" early return. A single-owner model would lose the earlier
    install's tracking the moment a second one registered — and if that
    second one happened to exit first, the watch could be idle-expired
    while the first is still resolving or building, even though it's still
    genuinely running.
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    proc_a = subprocess.Popen(["sleep", "30"])  # noqa: ASYNC220 — need a real live PID; nothing else in this test awaits concurrently
    proc_b = subprocess.Popen(["sleep", "1"])  # noqa: ASYNC220 — same as above
    try:
        monitor.add_site_packages_watch(site_packages, pid=proc_a.pid)
        first_tracked = monitor._site_package_watches[site_packages]
        assert first_tracked.owning_pids == {proc_a.pid: first_tracked.owning_pids[proc_a.pid]}

        # Second install starts against the SAME already-watched path, while A
        # is still running.
        monitor.add_site_packages_watch(site_packages, pid=proc_b.pid)
        tracked = monitor._site_package_watches[site_packages]
        assert set(tracked.owning_pids) == {proc_a.pid, proc_b.pid}, (
            "both installers must be tracked as concurrent owners, not just the latest"
        )
        # No new watch/generation should have been created — same underlying
        # registration, just refreshed.
        assert tracked.generation == first_tracked.generation

        # B (the LATER-registered one) exits FIRST — A is still running.
        proc_b.wait()
        await asyncio.sleep(0.2)

        monitor._cleanup_dead_watches()
        assert site_packages in monitor._site_package_watches, (
            "watch must survive B exiting, since A is still running — with "
            "a single-owner model, B replacing A's tracking would have let "
            "this idle-expire the watch out from under A"
        )
        assert set(monitor._site_package_watches[site_packages].owning_pids) == {proc_a.pid}, (
            "B's now-dead entry must be pruned, leaving only the still-running A"
        )
    finally:
        proc_a.terminate()
        proc_b.terminate()
        proc_a.wait()
        proc_b.wait()

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_add_site_packages_watch_repeated_call_refreshes_activity(tmp_path):
    """Even without a pid, a repeated registration call is itself a real
    activity signal (the daemon just detected another install touching this
    venv) and must reset the idle clock.
    """
    from packagealert.monitors.cache import _SITE_PACKAGES_WATCH_IDLE_SECONDS

    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    monitor.add_site_packages_watch(site_packages)
    tracked = monitor._site_package_watches[site_packages]
    tracked.last_activity -= _SITE_PACKAGES_WATCH_IDLE_SECONDS - 1  # nearly expired

    monitor.add_site_packages_watch(site_packages)  # repeated call, no pid
    assert time.monotonic() - tracked.last_activity < 1.0, (
        "a repeated registration call must refresh last_activity even without a pid"
    )

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_add_site_packages_watch_repeated_call_with_no_pid_keeps_live_owner(tmp_path):
    """A repeated registration call with pid=None (the deferred/lockfile
    emission path, where that particular event's own process has already
    exited) must not clobber a *different*, still-running install's
    ownership — pid=None only means this event's process is gone, not that
    nothing about the watch is still active.
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    proc = subprocess.Popen(["sleep", "30"])  # noqa: ASYNC220 — need a real live PID; nothing else in this test awaits concurrently
    try:
        monitor.add_site_packages_watch(site_packages, pid=proc.pid)
        tracked = monitor._site_package_watches[site_packages]
        assert proc.pid in tracked.owning_pids

        monitor.add_site_packages_watch(site_packages, pid=None)
        assert proc.pid in monitor._site_package_watches[site_packages].owning_pids, (
            "an unrelated pid=None event must not clear a live owner's tracking"
        )
    finally:
        proc.terminate()
        proc.wait()

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_add_site_packages_watch_repeated_call_with_exited_pid_keeps_live_owner(tmp_path):
    """Regression: a repeated registration call with a non-None pid that has
    already exited by the time it's resolved (a delayed/stale event, or a
    fast-exiting `pip --version`-style subprocess the process monitor
    briefly glimpsed) must not clobber a *different*, still-running
    install's ownership either. pid=None was already guarded (see
    test_add_site_packages_watch_repeated_call_with_no_pid_keeps_live_owner)
    but a pid that merely *resolves* to nothing hit the same bug via a
    different path: `pid is not None` alone was treated as grounds to
    overwrite, without checking whether that pid actually resolved to a
    live process.
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    live_proc = subprocess.Popen(["sleep", "30"])  # noqa: ASYNC220 — need a real live PID; nothing else in this test awaits concurrently
    exited_proc = subprocess.Popen(["true"])  # noqa: ASYNC220 — need a real exited PID; nothing else in this test awaits concurrently
    exited_proc.wait()  # already exited before the repeated call below

    try:
        monitor.add_site_packages_watch(site_packages, pid=live_proc.pid)
        tracked = monitor._site_package_watches[site_packages]
        assert live_proc.pid in tracked.owning_pids

        # Delayed event carries a real, non-None pid — but one that has
        # already exited by the time it's resolved here.
        monitor.add_site_packages_watch(site_packages, pid=exited_proc.pid)
        assert set(monitor._site_package_watches[site_packages].owning_pids) == {live_proc.pid}, (
            "a pid that resolves to nothing must not clear a live owner's tracking, "
            "even though the pid itself was not None, and must not itself be added"
        )
    finally:
        live_proc.terminate()
        live_proc.wait()

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


def test_pid_still_running_detects_pid_reuse() -> None:
    """A recorded (pid, create_time) pair must not be fooled by an unrelated
    later process reusing the same PID number — psutil.pid_exists() alone
    would be, since PIDs are recycled by the OS.
    """
    from packagealert.monitors.cache import _pid_still_running

    me = psutil.Process()
    real_create_time = me.create_time()
    assert _pid_still_running(me.pid, real_create_time) is True

    wrong_create_time = real_create_time - 999_999
    assert _pid_still_running(me.pid, wrong_create_time) is False


def test_pid_still_running_false_for_dead_pid() -> None:
    from packagealert.monitors.cache import _pid_still_running

    # A PID vanishingly unlikely to exist.
    assert _pid_still_running(2**30, 0.0) is False


def test_pid_still_running_false_for_zombie() -> None:
    """Regression: a zombie process (exited, not yet reaped by its parent)
    keeps its PID and create_time() unchanged — psutil.Process(pid) doesn't
    raise for it, so both the PID-reuse guard and the plain liveness check
    above pass. But a zombie already called _exit() (or was killed) and can
    never do any more installation work; if _pid_still_running() reported it
    as running, a site-packages watch whose only "active" owner is a
    zombie would stay exempt from idle cleanup indefinitely whenever its
    parent is slow, buggy, or gone — defeating the idle-timeout this
    mechanism exists to enforce.
    """
    import os

    from packagealert.monitors.cache import _pid_still_running

    pid = os.fork()
    if pid == 0:
        os._exit(0)

    try:
        proc = psutil.Process(pid)
        deadline = time.monotonic() + 5.0
        while proc.status() != psutil.STATUS_ZOMBIE and time.monotonic() < deadline:
            time.sleep(0.01)
        assert proc.status() == psutil.STATUS_ZOMBIE, "child did not reach zombie state in time"

        create_time = proc.create_time()
        assert _pid_still_running(pid, create_time) is False
    finally:
        os.waitpid(pid, 0)


def test_resolve_owning_pid_with_create_time_confirms_matching_process() -> None:
    """When a caller supplies the create_time it itself observed for `pid`
    (as ProcessMonitor._scan_processes() now does), a still-live, matching
    process must resolve successfully.
    """
    from packagealert.monitors.cache import _resolve_owning_pid

    me = psutil.Process()
    real_create_time = me.create_time()
    assert _resolve_owning_pid(me.pid, real_create_time) == (me.pid, real_create_time)


def test_resolve_owning_pid_with_create_time_rejects_pid_reuse() -> None:
    """Regression: the caller-supplied create_time must be verified against
    the PID's *current* process, not trusted blindly — otherwise a stale
    create_time recorded for a since-exited process would be silently
    revalidated forever. This is the same PID-reuse guard
    _pid_still_running() already applies, exercised here through
    _resolve_owning_pid()'s create_time-supplied branch specifically.
    """
    from packagealert.monitors.cache import _resolve_owning_pid

    me = psutil.Process()
    real_create_time = me.create_time()
    wrong_create_time = real_create_time - 999_999
    assert _resolve_owning_pid(me.pid, wrong_create_time) == (None, None)


def test_resolve_owning_pid_without_create_time_samples_fresh() -> None:
    """The site_packages_dirs configured-watch path (_schedule_watch() with
    no pid at all) and any other caller with no prior observation of `pid`
    must fall back to sampling create_time() fresh — there is no earlier
    trustworthy value to verify against in that case.
    """
    from packagealert.monitors.cache import _resolve_owning_pid

    me = psutil.Process()
    assert _resolve_owning_pid(me.pid) == (me.pid, me.create_time())


@pytest.mark.asyncio
async def test_add_site_packages_watch_rejects_reused_pid_with_carried_create_time(tmp_path):
    """End-to-end regression for the PID-reuse race: add_site_packages_watch()
    must trust the create_time the caller observed at scan time over
    whatever process is now actually running at that PID number — a stale
    create_time (as if the original installer exited and the PID was reused
    by something else entirely) must not be recorded as an owner.
    """
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()

    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)
    await monitor.start()

    me = psutil.Process()
    stale_create_time = me.create_time() - 999_999

    monitor.add_site_packages_watch(site_packages, pid=me.pid, pid_create_time=stale_create_time)
    assert site_packages in monitor._site_package_watches
    tracked = monitor._site_package_watches[site_packages]
    assert tracked.owning_pids == {}, (
        "a PID whose current process doesn't match the carried create_time "
        "must not be recorded as an owner — it may have been reused"
    )

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_rescan_cache_paths_is_idempotent(tmp_path):
    """Calling _rescan_cache_paths() repeatedly must not re-schedule an
    already-watched root or raise.
    """
    watch_dir = tmp_path / "wheels-v7"
    watch_dir.mkdir()
    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        assert watch_dir in monitor._cache_root_watches
        watch_before = monitor._cache_root_watches[watch_dir]

        await monitor._rescan_cache_paths()
        await monitor._rescan_cache_paths()

        assert monitor._cache_root_watches[watch_dir] is watch_before
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


@pytest.mark.asyncio
async def test_rescan_cache_paths_noop_when_cache_monitoring_disabled(tmp_path):
    watch_dir = tmp_path / "wheels-v7"
    cfg = WatchConfig(enable_cache_monitoring=False)
    monitor = CacheMonitor(cfg)

    with patch(
        "packagealert.languages.registry.all_languages",
        return_value=[_python_only_lang(watch_dir)],
    ):
        await monitor.start()
        watch_dir.mkdir()
        await monitor._rescan_cache_paths()  # must not raise or schedule anything

    assert monitor._cache_root_watches == {}
    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_rescan_reregisters_pruned_configured_site_packages_watch(tmp_path):
    """Regression: WatchConfig.site_packages_dirs entries are documented as
    watched permanently, but _cleanup_dead_watches() still correctly prunes
    one if its directory is deleted and recreated (e.g. a venv rebuild) or
    its (device, inode) changes. Nothing calls add_site_packages_watch()
    for a path the user configured directly — that only fires reactively
    from a process-monitor event, which may never happen again for a path
    with no further install activity — so _rescan_cache_paths() must
    re-register a pruned configured watch itself, the same way it does for
    plugin cache roots, or the watch stays gone for the rest of the
    daemon's lifetime.
    """
    configured = tmp_path / "my-project" / "site-packages"
    configured.mkdir(parents=True)

    cfg = WatchConfig(enable_cache_monitoring=True, site_packages_dirs=[configured])
    monitor = CacheMonitor(cfg)
    with patch("packagealert.languages.registry.all_languages", return_value=[]):
        await monitor.start()

    assert configured in monitor._site_package_watches
    old_generation = monitor._site_package_watches[configured].generation

    # Venv rebuild: delete and recreate at the same path.
    shutil.rmtree(configured)
    configured.mkdir(parents=True)

    with patch("packagealert.languages.registry.all_languages", return_value=[]):
        monitor._cleanup_dead_watches()
        assert configured not in monitor._site_package_watches, (
            "the stale watch (bound to the deleted directory) must be pruned"
        )

        await monitor._rescan_cache_paths()

    assert configured in monitor._site_package_watches, (
        "a pruned configured site_packages_dirs entry must be re-registered "
        "by the next rescan — nothing else will ever re-add it"
    )
    new_tracked = monitor._site_package_watches[configured]
    assert new_tracked.generation != old_generation
    assert new_tracked.exempt_from_idle is True, (
        "re-registration must preserve the permanent/exempt-from-idle contract"
    )

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_rescan_backfills_configured_site_packages_watch_after_reregistration(tmp_path):
    """A rebuilt venv can have a package already installed into it (its
    .dist-info already written) before the rescan re-registers the watch —
    scheduling the watch alone would silently miss it, the same reasoning
    that already applies to plugin cache roots.
    """
    configured = tmp_path / "my-project" / "site-packages"
    configured.mkdir(parents=True)

    cfg = WatchConfig(enable_cache_monitoring=True, site_packages_dirs=[configured])
    monitor = CacheMonitor(cfg)
    with patch("packagealert.languages.registry.all_languages", return_value=[]):
        await monitor.start()

    shutil.rmtree(configured)
    configured.mkdir(parents=True)
    (configured / "requests-2.31.0.dist-info").mkdir()

    # A PythonLanguage whose cache_paths() is empty — no real cache roots
    # get discovered/backfilled, only the configured site-packages watch
    # under test — but classify_cache_file() still works normally so the
    # .dist-info backfill below is real.
    no_cache_roots_lang = _python_only_lang(tmp_path / "nonexistent")

    with patch("packagealert.languages.registry.all_languages", return_value=[no_cache_roots_lang]):
        monitor._cleanup_dead_watches()
        await monitor._rescan_cache_paths()

    events = monitor.drain()
    assert len(events) == 1
    assert events[0].package_name == "requests"
    assert events[0].version == "2.31.0"

    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_rescan_site_packages_noop_when_cache_monitoring_disabled(tmp_path):
    """The enable_cache_monitoring gate must also cover the configured
    site_packages_dirs half of the rescan, not just plugin cache roots.
    """
    configured = tmp_path / "my-project" / "site-packages"

    cfg = WatchConfig(enable_cache_monitoring=False, site_packages_dirs=[configured])
    monitor = CacheMonitor(cfg)
    await monitor.start()

    configured.mkdir(parents=True)
    await monitor._rescan_cache_paths()  # must not raise or schedule anything

    assert monitor._site_package_watches == {}
    assert monitor._observer is not None, "start() must have created an observer"
    monitor._observer.stop()
    monitor._observer.join()


@pytest.mark.asyncio
async def test_cache_monitor_start_skips_buggy_cache_paths_plugin(tmp_path):
    """A plugin that raises in cache_paths()/cache_file_globs() must not abort CacheMonitor.start()."""
    from packagealert.config import WatchConfig
    from packagealert.monitors.cache import CacheMonitor

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.cache_file_globs.side_effect = RuntimeError("plugin exploded")

    good_watch_dir = tmp_path / "pip_cache"
    good_watch_dir.mkdir()
    good_lang = MagicMock()
    good_lang.name = "good"
    good_lang.cache_file_globs.return_value = ["*.whl"]
    good_lang.cache_paths.return_value = [good_watch_dir]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[bad_lang, good_lang]):
        await monitor.start()  # must not raise
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()

    # cache_file_globs() is called once per discovery pass start() runs:
    # _discover_cache_dirs() (watched roots) and _seed_poll_only_baseline()'s
    # own _discover_poll_only_cache_dirs() call (polled roots) — see
    # start()'s docstring on _known_cache_roots / _seed_poll_only_baseline().
    # cache_paths() is only used by the first of those.
    assert bad_lang.cache_file_globs.call_count == 2
    assert good_lang.cache_file_globs.call_count == 2
    good_lang.cache_paths.assert_called_once()
