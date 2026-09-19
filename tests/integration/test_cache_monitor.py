import asyncio
import contextlib
import shutil
import subprocess
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
            await monitor.start()

        wheel = watch_dir / "somepkg-1.0.0-py3-none-any.whl"

        # Write the wheel file exactly inside the race window: the watch is
        # already live (schedule_watch() has already returned by the time
        # _backfill_scan() is called) but the backfill glob() hasn't run
        # yet, so both the live inotify emitter thread and this scan get a
        # real chance to independently observe the same creation.
        real_backfill_scan = monitor._backfill_scan

        def racy_backfill_scan(cache_dir, globs, backfill_dedup):
            wheel.touch()
            time.sleep(0.05)  # let the live inotify emitter thread catch up
            return real_backfill_scan(cache_dir, globs, backfill_dedup)

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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
            await monitor.start()

        # First install: the wheel is created right as the watch registers
        # and its backfill scan runs, targeting the same race window
        # _BackfillDedup exists to arbitrate.
        real_backfill_scan = monitor._backfill_scan

        def racy_backfill_scan(cache_dir, globs, backfill_dedup):
            wheel.touch()
            time.sleep(0.05)  # let the live inotify emitter thread catch up
            return real_backfill_scan(cache_dir, globs, backfill_dedup)

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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
            await monitor.start()

        real_backfill_scan = monitor._backfill_scan

        def racy_backfill_scan(cache_dir, globs, backfill_dedup):
            index_entry.symlink_to(target)
            time.sleep(0.05)  # let the live inotify emitter thread catch up
            return real_backfill_scan(cache_dir, globs, backfill_dedup)

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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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

        def scan_then_live_dispatch(cache_dir, globs, backfill_dedup):
            result = real_backfill_scan(cache_dir, globs, backfill_dedup)
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

    assert call_count["n"] == 2, "expected both the backfill's failed attempt and the live handler's retry"
    assert len(events) == 1, (
        f"expected 1 event once classification succeeded on the live retry, got {events} — "
        f"a claim()-before-classify ordering would wrongly drop this real install entirely"
    )
    assert events[0].package_name == "somepkg"
    assert events[0].version == "1.0.0"


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
                watch_dir, mock_backfill.call_args[0][1], mock_backfill.call_args[0][2]
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
        result = monitor._discover_cache_dirs()

    assert len(result) == 1
    path, globs = result[0]
    assert path == shared_dir
    assert set(globs) == {"*.whl", "*.tgz"}


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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
    rev_dir = sdists_root / "pypi" / "oldpkg" / "1.0.0" / "abcdef0123456789"
    rev_dir.mkdir(parents=True)
    (rev_dir / "oldpkg-1.0.0-py3-none-any.whl").touch()

    lang = _python_only_lang(tmp_path / "unused-wheels-root")
    lang.poll_only_cache_paths = lambda: [sdists_root]

    cfg = WatchConfig(enable_cache_monitoring=True)
    monitor = CacheMonitor(cfg)

    with patch("packagealert.languages.registry.all_languages", return_value=[lang]):
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
            await monitor.start()

        # Simulate a slow glob/classify walk (a large real cache) with a
        # synchronous sleep — time.sleep(), not asyncio.sleep(), since the
        # whole point is to model work that blocks whichever thread it
        # runs on. If _poll_cache_dirs() awaited this directly on the
        # event loop instead of via asyncio.to_thread(), the sleep would
        # block the loop itself.
        real_sync_scan = monitor._poll_cache_dirs_sync

        def slow_sync_scan(cache_dirs):
            time.sleep(0.3)
            return real_sync_scan(cache_dirs)

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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
            await monitor.start()

        # Simulate a poll that takes LONGER than _MAINTENANCE_INTERVAL_SECONDS
        # (a huge real sdists-v* tree) with a synchronous sleep.
        real_sync_scan = monitor._poll_cache_dirs_sync

        def slow_sync_scan(cache_dirs):
            time.sleep(0.3)
            return real_sync_scan(cache_dirs)

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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
        with patch.object(monitor, "_discover_cache_dirs", return_value=[]):
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
            mock_backfill.assert_called_once()

        assert watch_dir in monitor._cache_root_watches
        assert monitor._observer is not None, "start() must have created an observer"
        monitor._observer.stop()
        monitor._observer.join()


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
        (watch_dir / f"stalepkg{i}-1.0.0-py3-none-any.whl").touch()

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
        # inotify emits for this tree), same synchronisation as the
        # inode-reuse test above.
        for _ in range(50):
            if not monitor._invalidated_roots.empty():
                break
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
        # needs a beat to land.
        for _ in range(50):
            if not monitor._invalidated_roots.empty():
                break
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
