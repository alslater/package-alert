import asyncio
import subprocess
import sys
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
