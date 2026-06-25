import asyncio
from unittest.mock import MagicMock, patch
import pytest
from packagealert.monitors.process import ProcessMonitor
from packagealert.config import WatchConfig


@pytest.mark.asyncio
@pytest.mark.integration
async def test_process_monitor_starts_and_stops():
    """Smoke test: monitor starts, runs a scan cycle, and stops without error."""
    cfg = WatchConfig(process_poll_interval_seconds=0.1)
    monitor = ProcessMonitor(cfg)
    await monitor.start()
    assert monitor._running is True

    # Run one event cycle (with timeout)
    events = []
    async def collect_briefly():
        async for ev in monitor.events():
            events.append(ev)
            break  # take at most one

    # Stop after 0.5s regardless
    try:
        await asyncio.wait_for(collect_briefly(), timeout=0.5)
    except asyncio.TimeoutError:
        pass

    await monitor.stop()
    assert monitor._running is False
    assert isinstance(events, list)  # may be empty — that's fine


# --- Unit tests for plugin exception isolation ---

def _make_monitor():
    return ProcessMonitor(WatchConfig(process_poll_interval_seconds=1))


def test_try_parse_returns_none_when_plugin_raises():
    monitor = _make_monitor()
    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.process_names = frozenset(["pip"])
    bad_lang.parse_process_install.side_effect = RuntimeError("plugin exploded")

    with patch("packagealert.languages.registry.for_process", return_value=bad_lang):
        result = monitor._try_parse(["pip", "install", "flask"])

    assert result is None
    bad_lang.parse_process_install.assert_called_once()


@pytest.mark.asyncio
async def test_emit_from_lockfile_continues_on_parse_lockfile_exception(tmp_path):
    monitor = _make_monitor()

    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}")

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.lockfile_patterns.return_value = ["package-lock.json"]
    bad_lang.parse_lockfile.side_effect = RuntimeError("plugin exploded")

    from packagealert.monitors.process import _PendingInstall
    pending = _PendingInstall(
        manager="npm",
        registry_name="npm",
        cwd=tmp_path,
        site_pkgs=None,
        lockfile_hint=None,
    )

    with patch("packagealert.languages.registry.for_process", return_value=bad_lang):
        await monitor._emit_from_lockfile(pending)

    # parse_lockfile raised but no exception propagated; nothing queued
    bad_lang.parse_lockfile.assert_called_once()
    assert monitor._queue.empty()


@pytest.mark.asyncio
async def test_emit_from_lockfile_returns_on_lockfile_patterns_exception(tmp_path):
    """If lang.lockfile_patterns() raises, _emit_from_lockfile() must log and return cleanly."""
    monitor = _make_monitor()

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    bad_lang.lockfile_patterns.side_effect = RuntimeError("patterns boom")

    from packagealert.monitors.process import _PendingInstall
    pending = _PendingInstall(
        manager="npm",
        registry_name="npm",
        cwd=tmp_path,
        site_pkgs=None,
        lockfile_hint=None,
    )

    with patch("packagealert.languages.registry.for_process", return_value=bad_lang):
        await monitor._emit_from_lockfile(pending)

    bad_lang.lockfile_patterns.assert_called_once()
    bad_lang.parse_lockfile.assert_not_called()
    assert monitor._queue.empty()


@pytest.mark.asyncio
async def test_events_yields_before_sleep():
    """Queued events must be yielded before asyncio.sleep(), not after."""
    from packagealert.models.events import PackageEvent
    from datetime import datetime, timezone

    monitor = _make_monitor()
    dummy = PackageEvent(
        ecosystem="pypi", package_name="dummy", version="1.0", source="process",
        manager="pip", project_path=None, timestamp=datetime.now(timezone.utc),
    )
    await monitor._queue.put(dummy)

    sleep_called = False
    real_sleep = asyncio.sleep

    async def tracking_sleep(t):
        nonlocal sleep_called
        sleep_called = True
        await real_sleep(0)

    async def fake_scan():
        pass

    gen = monitor.events()
    with patch.object(monitor, "_scan_processes", fake_scan), \
         patch("asyncio.sleep", tracking_sleep):
        await monitor.start()
        event = await asyncio.wait_for(gen.__anext__(), timeout=2.0)
        yielded_before_sleep = not sleep_called

    await monitor.stop()
    await gen.aclose()

    assert event.package_name == "dummy"
    assert yielded_before_sleep, "sleep was called before the queued event was yielded"


def test_package_managers_skips_buggy_plugin():
    """A plugin that raises accessing process_names must not abort _package_managers()."""
    from packagealert.monitors.process import _package_managers
    from packagealert.languages import registry as lang_registry
    lang_registry.load()

    bad_lang = MagicMock()
    bad_lang.name = "bad"
    type(bad_lang).process_names = property(lambda self: (_ for _ in ()).throw(RuntimeError("exploded")))

    real_all = lang_registry.all_languages

    with patch("packagealert.languages.registry.all_languages", return_value=[bad_lang] + real_all()):
        result = _package_managers()

    # Built-in managers still present despite bad plugin
    assert "pip" in result
    assert "npm" in result
