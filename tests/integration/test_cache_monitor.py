import asyncio
from unittest.mock import MagicMock, patch
import pytest
from packagealert.monitors.cache import CacheMonitor, _Handler, _classify_distinfo_dir
from packagealert.config import WatchConfig
from packagealert.languages.python import PythonLanguage
from pathlib import Path

from tests.integration.conftest import requires_inotify_headroom


def _python_only_lang(cache_dir: Path):
    """Return a PythonLanguage instance whose cache_paths() returns only cache_dir."""
    lang = PythonLanguage()
    lang.cache_paths = lambda: [cache_dir]
    return lang


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
        except asyncio.TimeoutError:
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
        except asyncio.TimeoutError:
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
        except asyncio.TimeoutError:
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
    handler = _Handler(queue, loop)

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


@pytest.mark.asyncio
async def test_cache_monitor_start_skips_buggy_cache_paths_plugin(tmp_path):
    """A plugin that raises in cache_paths()/cache_file_globs() must not abort CacheMonitor.start()."""
    from packagealert.monitors.cache import CacheMonitor
    from packagealert.config import WatchConfig

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
        monitor._observer.stop()
        monitor._observer.join()

    bad_lang.cache_file_globs.assert_called_once()
    good_lang.cache_file_globs.assert_called_once()
    good_lang.cache_paths.assert_called_once()
