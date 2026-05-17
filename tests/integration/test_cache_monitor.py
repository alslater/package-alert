import asyncio
import pytest
from packagealert.monitors.cache import CacheMonitor, _classify_distinfo_dir
from packagealert.config import WatchConfig
from pathlib import Path


@pytest.mark.asyncio
@pytest.mark.integration
async def test_detects_new_wheel(tmp_path):
    watch_dir = tmp_path / "pip_cache"
    watch_dir.mkdir()
    cfg = WatchConfig(
        pip_cache_dir=watch_dir,
        uv_cache_dir=tmp_path / "nope_uv",
        npm_cache_dir=tmp_path / "nope_npm",
        enable_cache_monitoring=True,
    )
    monitor = CacheMonitor(cfg)
    await monitor.start()

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
    except asyncio.TimeoutError:
        await monitor.stop()

    assert len(events) == 1
    assert events[0].package_name == "requests"
    assert events[0].version == "2.31.0"
    assert events[0].ecosystem == "pypi"
    assert events[0].source == "cache"


@pytest.mark.asyncio
@pytest.mark.integration
async def test_ignores_non_wheel_files(tmp_path):
    watch_dir = tmp_path / "pip_cache2"
    watch_dir.mkdir()
    cfg = WatchConfig(
        pip_cache_dir=watch_dir,
        uv_cache_dir=tmp_path / "nope_uv2",
        npm_cache_dir=tmp_path / "nope_npm2",
        enable_cache_monitoring=True,
    )
    monitor = CacheMonitor(cfg)
    await monitor.start()

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


@pytest.mark.asyncio
@pytest.mark.integration
async def test_detects_distinfo_dir_in_site_packages(tmp_path):
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    cfg = WatchConfig(
        pip_cache_dir=tmp_path / "nope_pip",
        uv_cache_dir=tmp_path / "nope_uv",
        npm_cache_dir=tmp_path / "nope_npm",
        site_packages_dirs=[site_packages],
        enable_cache_monitoring=True,
    )
    monitor = CacheMonitor(cfg)
    await monitor.start()

    events = []

    async def collect():
        async for ev in monitor.events():
            events.append(ev)
            await monitor.stop()
            break

    async def drop_distinfo():
        await asyncio.sleep(0.4)
        (site_packages / "sqlparse-0.5.0.dist-info").mkdir()

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
