import asyncio
from datetime import UTC
from unittest.mock import MagicMock, patch

import pytest

from packagealert.config import WatchConfig
from packagealert.monitors.process import ProcessMonitor


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
    except TimeoutError:
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
    from datetime import datetime

    from packagealert.models.events import PackageEvent

    monitor = _make_monitor()
    dummy = PackageEvent(
        ecosystem="pypi", package_name="dummy", version="1.0", source="process",
        manager="pip", project_path=None, timestamp=datetime.now(UTC),
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
    from packagealert.languages import registry as lang_registry
    from packagealert.monitors.process import _package_managers
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


@pytest.mark.asyncio
async def test_scan_processes_immediate_install_carries_pid(tmp_path):
    """The immediate-parse path (a non-deferred install, e.g. `pip install
    flask` with the package named directly on the command line) must stamp
    the detecting process's PID — and its create_time() — onto the emitted
    PackageEvent.

    CacheMonitor.add_site_packages_watch() uses this PID to know a
    site-packages watch's install is still in flight, keeping it alive past
    the idle timeout for as long as the process runs — without it, the
    watch could be idled out mid-install for a slow package manager.

    create_time() must come from this same process_iter() scan, not be
    re-sampled later: the event can sit behind OSV lookups and risk
    analysis before the daemon's consumer reaches it, long enough for this
    PID to have been reused by an unrelated process by then. Carrying the
    create_time observed here lets the consumer verify the PID still refers
    to the process actually observed running the install, rather than
    trusting whatever now holds that PID number — see
    CacheMonitor._resolve_owning_pid().
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()

    fake_proc = MagicMock()
    fake_proc.info = {
        "pid": 424242,
        "ppid": 1,
        "cmdline": ["pip", "install", "flask"],
        "cwd": str(tmp_path),
        "create_time": 1700000000.5,
    }

    good_lang = MagicMock()
    good_lang.name = "pip"
    good_lang.process_names = frozenset(["pip"])

    parsed = ProcessInstall(
        manager="pip",
        packages=[PackageSpec(name="flask", version="3.0.0", ecosystem="PyPI")],
        defer_to_lockfile=False,
    )

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[fake_proc]),
        patch.object(monitor, "_pm_names", frozenset(["pip"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
    ):
        await monitor._scan_processes()

    assert not monitor._queue.empty()
    event = monitor._queue.get_nowait()
    assert event.pid == 424242
    assert event.pid_create_time == 1700000000.5
    assert event.package_name == "flask"


@pytest.mark.asyncio
async def test_scan_processes_does_not_carry_pid_when_create_time_unavailable(tmp_path):
    """Regression: psutil.Process.as_dict() (which process_iter() uses
    internally) has PER-ATTRIBUTE error handling — AccessDenied or
    ZombieProcess raised fetching one specific attribute is caught and
    replaced with `ad_value` (None by default) for just that attribute,
    without the whole as_dict() call raising. So `info["pid"]` can be a
    real, valid PID while `info["create_time"]` is None for that same
    process, in the same scan.

    If that None were carried through as event.pid=<real pid>,
    event.pid_create_time=None, CacheMonitor._resolve_owning_pid(pid, None)
    can't tell "no process was ever observed" (its own no-pid-known caller)
    apart from "a process WAS observed here, but create_time specifically
    couldn't be read" — it treats None as licence to sample
    psutil.Process(pid).create_time() itself, fresh, at consume time. If
    this pid has since been reused by an unrelated process, that silently
    binds the watch to the wrong process's create_time — exactly the
    PID-reuse race pid_create_time exists to prevent, just reopened one
    level up. So a pid observed without a matching create_time must not be
    carried on the event at all.
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()

    fake_proc = MagicMock()
    fake_proc.info = {
        "pid": 555555,
        "ppid": 1,
        "cmdline": ["pip", "install", "flask"],
        "cwd": str(tmp_path),
        "create_time": None,  # as_dict()'s ad_value for this one attribute
    }

    good_lang = MagicMock()
    good_lang.name = "pip"
    good_lang.process_names = frozenset(["pip"])

    parsed = ProcessInstall(
        manager="pip",
        packages=[PackageSpec(name="flask", version="3.0.0", ecosystem="PyPI")],
        defer_to_lockfile=False,
    )

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[fake_proc]),
        patch.object(monitor, "_pm_names", frozenset(["pip"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
    ):
        await monitor._scan_processes()

    assert not monitor._queue.empty()
    event = monitor._queue.get_nowait()
    assert event.pid is None, "pid must not be carried when its create_time couldn't be read"
    assert event.pid_create_time is None
    assert event.package_name == "flask"


@pytest.mark.asyncio
async def test_scan_processes_deferred_lockfile_install_carries_pid(tmp_path):
    """Regression: a DEFERRED install (e.g. `uv sync` with no package named
    directly on the command line — the common case defer_to_lockfile
    exists for, not an edge case) used to have its PackageEvent constructed
    with no pid/pid_create_time at all: _PendingInstall stored neither
    value, and _emit_from_lockfile() built its PackageEvent without them.

    Daemon._occurrence_key() falls back to the resolved version alone when
    no pid is available, which cannot distinguish two SEPARATE installs of
    the same declared version — e.g. two `uv sync` runs of a git/path
    dependency whose content changed without a version bump, exactly the
    scenario that dedup logic exists to preserve (see
    TestUnresolvedVersionDedup.test_resolved_version_from_different_processes_both_processed
    in test_daemon.py). Since every deferred event had pid=None
    unconditionally, that protection never actually applied to this path
    at all — confirmed empirically.

    This test drives the real _scan_processes() flow end to end: the
    install-detecting process is observed once (recording a
    _PendingInstall with this scan's pid/create_time, mirroring the
    immediate-parse path's own event_pid/create_time sampling), then
    disappears from a later scan (empty process_iter()), triggering
    _emit_from_lockfile() for the now-finished install. The resulting
    PackageEvent must carry the SAME pid/create_time observed when the
    install was first detected, not None.
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()

    lockfile = tmp_path / "uv.lock"
    lockfile.write_text("")

    fake_proc = MagicMock()
    fake_proc.info = {
        "pid": 424242,
        "ppid": 1,
        "cmdline": ["uv", "sync"],
        "cwd": str(tmp_path),
        "create_time": 1700000000.5,
    }

    parsed = ProcessInstall(manager="uv-project", packages=[], defer_to_lockfile=True)

    lang = MagicMock()
    lang.name = "uv"
    lang.lockfile_patterns.return_value = ["uv.lock"]
    lang.parse_lockfile.return_value = [
        PackageSpec(name="mypackage", version="1.0.0", ecosystem="PyPI")
    ]

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[fake_proc]),
        patch.object(monitor, "_pm_names", frozenset(["uv"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
        patch(
            "packagealert.monitors.process.manager_registry_name",
            return_value="uv",
        ),
    ):
        await monitor._scan_processes()

    assert (424242, 1700000000.5) in monitor._pending
    assert monitor._pending[(424242, 1700000000.5)].pid == 424242
    assert monitor._pending[(424242, 1700000000.5)].pid_create_time == 1700000000.5
    assert monitor._queue.empty(), "a deferred install must not queue an event on its own"

    # The install-detecting process is gone by the next scan — the pending
    # install has finished, triggering the lockfile scan.
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[]),
        patch("packagealert.languages.registry.for_process", return_value=lang),
    ):
        await monitor._scan_processes()

    assert not monitor._queue.empty()
    event = monitor._queue.get_nowait()
    assert event.pid == 424242, (
        "expected the deferred event to carry the pid observed when the "
        "install was first detected, got pid=None"
    )
    assert event.pid_create_time == 1700000000.5
    assert event.package_name == "mypackage"


@pytest.mark.asyncio
async def test_scan_processes_pid_reuse_does_not_lose_the_replacement_process(tmp_path):
    """Regression: _seen_processes/_pending/current_processes bookkeeping
    used to be keyed by bare pid, not (pid, create_time). If a
    package-manager process exits and the OS reuses its pid for a
    COMPLETELY UNRELATED later invocation before the next
    _scan_processes() poll — routine under normal system load, not a rare
    edge case — the bare-pid `if pid in self._seen_pids: continue` check
    wrongly treated the new process as "already seen" (it's the SAME pid
    number as the finished one), silently skipping it before _try_parse()
    was ever reached. Its own install was therefore missed entirely —
    confirmed empirically.
    """
    from packagealert.languages.base import ProcessInstall

    monitor = _make_monitor()

    # Poll 1: process A (pid=1000, create_time=100.0) starts a DEFERRED
    # install — it never queues an event on its own, only registers a
    # _PendingInstall, exactly the state a finished-but-not-yet-detected
    # install would be in when its pid gets reused.
    proc_a = MagicMock()
    proc_a.info = {
        "pid": 1000, "ppid": 1, "cmdline": ["uv", "sync"],
        "cwd": str(tmp_path), "create_time": 100.0,
    }
    parsed_a = ProcessInstall(manager="uv-project", packages=[], defer_to_lockfile=True)

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_a]),
        patch.object(monitor, "_pm_names", frozenset(["uv"])),
        patch.object(monitor, "_try_parse", return_value=parsed_a),
        patch("packagealert.monitors.process.manager_registry_name", return_value="uv"),
    ):
        await monitor._scan_processes()

    assert (1000, 100.0) in monitor._pending

    # Process A exits; the OS reuses pid 1000 for a genuinely different
    # process B, an IMMEDIATE (non-deferred) install this time, observed
    # in the very next poll.
    from packagealert.languages.base import PackageSpec

    proc_b = MagicMock()
    proc_b.info = {
        "pid": 1000, "ppid": 1, "cmdline": ["npm", "install", "lodash"],
        "cwd": str(tmp_path), "create_time": 999.0,
    }
    parsed_b = ProcessInstall(
        manager="npm",
        packages=[PackageSpec(name="lodash", version="4.0.0", ecosystem="npm")],
        defer_to_lockfile=False,
    )

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_b]),
        patch.object(monitor, "_pm_names", frozenset(["npm"])),
        patch.object(monitor, "_try_parse", return_value=parsed_b),
    ):
        await monitor._scan_processes()

    events = []
    while not monitor._queue.empty():
        events.append(monitor._queue.get_nowait())

    assert any(e.package_name == "lodash" for e in events), (
        f"expected process B's own install to be detected despite reusing "
        f"process A's exited pid, got {[e.package_name for e in events]}"
    )
    lodash_event = next(e for e in events if e.package_name == "lodash")
    assert lodash_event.pid == 1000
    assert lodash_event.pid_create_time == 999.0


@pytest.mark.asyncio
async def test_scan_processes_pid_reuse_still_completes_the_original_pending_install(
    tmp_path,
):
    """Regression: the companion bug to
    test_scan_processes_pid_reuse_does_not_lose_the_replacement_process —
    `finished = self._pending.keys() - current_pids` used to compare
    _pending's bare-pid keys against a bare-pid current_pids snapshot, so
    a pid reused by an unrelated LATER process still "looked" present in
    current_pids and the ORIGINAL pending install was therefore never
    recognised as finished — its lockfile scan was delayed indefinitely
    (until whatever eventually freed that pid number again, at which
    point it would run using stale, unrelated state) — confirmed
    empirically.
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text("")

    proc_a = MagicMock()
    proc_a.info = {
        "pid": 1000, "ppid": 1, "cmdline": ["uv", "sync"],
        "cwd": str(tmp_path), "create_time": 100.0,
    }
    parsed_a = ProcessInstall(manager="uv-project", packages=[], defer_to_lockfile=True)

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_a]),
        patch.object(monitor, "_pm_names", frozenset(["uv"])),
        patch.object(monitor, "_try_parse", return_value=parsed_a),
        patch("packagealert.monitors.process.manager_registry_name", return_value="uv"),
    ):
        await monitor._scan_processes()

    assert (1000, 100.0) in monitor._pending

    # Process A exits; the OS reuses pid 1000 for an unrelated process B
    # that is NOT a package-manager invocation at all (so it doesn't
    # itself get tracked) — the bug is specifically about the ORIGINAL
    # pending install being stuck, independent of what the replacement
    # process is.
    proc_b = MagicMock()
    proc_b.info = {
        "pid": 1000, "ppid": 1, "cmdline": ["some-other-program"],
        "cwd": str(tmp_path), "create_time": 999.0,
    }

    lang = MagicMock()
    lang.name = "uv"
    lang.lockfile_patterns.return_value = ["uv.lock"]
    lang.parse_lockfile.return_value = [
        PackageSpec(name="mypackage", version="1.0.0", ecosystem="PyPI")
    ]

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_b]),
        patch.object(monitor, "_pm_names", frozenset(["uv"])),
        patch("packagealert.languages.registry.for_process", return_value=lang),
    ):
        await monitor._scan_processes()

    assert (1000, 100.0) not in monitor._pending, (
        "expected process A's pending install to be recognized as finished "
        "once its pid was reused by an unrelated process, not left stuck"
    )
    assert not monitor._queue.empty(), (
        "expected the completed install's lockfile scan to have run"
    )
    event = monitor._queue.get_nowait()
    assert event.package_name == "mypackage"


@pytest.mark.asyncio
async def test_scan_processes_transient_create_time_failure_does_not_finish_pending_install(
    tmp_path,
):
    """Regression: process_identity = (pid, create_time) used to be formed
    fresh from THIS poll's create_time reading alone. A still-running
    process can have create_time come back None on just one poll — a
    transient AccessDenied/ZombieProcess race hitting only that attribute
    within process_iter()'s oneshot() collection, not the whole process
    lookup (see _scan_processes()'s own comment on event_pid/create_time) —
    without actually exiting. That produced a DIFFERENT identity, (pid,
    None), from whatever (pid, real_create_time) the same still-running
    process was tracked under in _pending. Since (pid, real_create_time)
    then no longer appeared in current_processes (only (pid, None) did),
    `finished = self._pending.keys() - current_processes` wrongly included
    it, and the still-running installer's lockfile was scanned and emitted
    prematurely — confirmed empirically.
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()

    proc_a = MagicMock()
    proc_a.info = {
        "pid": 1000, "ppid": 1, "cmdline": ["uv", "sync"],
        "cwd": str(tmp_path), "create_time": 100.0,
    }
    parsed_a = ProcessInstall(manager="uv-project", packages=[], defer_to_lockfile=True)

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_a]),
        patch.object(monitor, "_pm_names", frozenset(["uv"])),
        patch.object(monitor, "_try_parse", return_value=parsed_a),
        patch("packagealert.monitors.process.manager_registry_name", return_value="uv"),
    ):
        await monitor._scan_processes()

    assert (1000, 100.0) in monitor._pending

    # Same physical process, still running — but create_time fails to read
    # on this one poll.
    proc_a_glitch = MagicMock()
    proc_a_glitch.info = {
        "pid": 1000, "ppid": 1, "cmdline": ["uv", "sync"],
        "cwd": str(tmp_path), "create_time": None,
    }

    lang = MagicMock()
    lang.name = "uv"
    lang.lockfile_patterns.return_value = ["uv.lock"]
    lang.parse_lockfile.return_value = [
        PackageSpec(name="mypackage", version="1.0.0", ecosystem="PyPI")
    ]

    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_a_glitch]),
        patch.object(monitor, "_pm_names", frozenset(["uv"])),
        patch("packagealert.languages.registry.for_process", return_value=lang),
    ):
        await monitor._scan_processes()

    assert (1000, 100.0) in monitor._pending, (
        "expected the still-running install to remain pending across a "
        "transient create_time read failure, not be treated as finished"
    )
    assert monitor._queue.empty(), (
        "expected no premature lockfile scan while the installer is still running"
    )


@pytest.mark.asyncio
async def test_scan_processes_create_time_recovery_for_pending_install_does_not_read_mid_write_lockfile(
    tmp_path,
):
    """A DEFERRED (pending) install first observed with create_time=None
    is tracked as (pid, None) in self._pending. If create_time becomes
    readable on a later poll for that same still-running pid, the new reading
    forms a NEW identity (reconciliation is one-directional, so PID reuse
    stays detectable), and _scan_processes() MIGRATES the pending entry onto
    it — correlated on cwd, which the same process keeps. Without the
    migration the old (pid, None) entry is absent from this poll's
    current_processes, is treated as finished, and _emit_from_lockfile()
    reads the lock file while the installer may still be writing it.

    A real lock file is required: _emit_from_lockfile() silently no-ops
    without one, which would let the premature scan go unnoticed.
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()
    (tmp_path / "uv.lock").write_text("")

    proc_glitch = MagicMock()
    proc_glitch.info = {
        "pid": 4000, "ppid": 1, "cmdline": ["uv", "sync"],
        "cwd": str(tmp_path), "create_time": None,
    }
    parsed = ProcessInstall(manager="uv-project", packages=[], defer_to_lockfile=True)
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_glitch]),
        patch.object(monitor, "_pm_names", frozenset(["uv"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
        patch("packagealert.monitors.process.manager_registry_name", return_value="uv"),
    ):
        await monitor._scan_processes()

    assert (4000, None) in monitor._pending

    # Same physical process, STILL RUNNING (uv sync hasn't finished writing
    # its lockfile yet) — but create_time now reads as a real value.
    proc_recovered = MagicMock()
    proc_recovered.info = {
        "pid": 4000, "ppid": 1, "cmdline": ["uv", "sync"],
        "cwd": str(tmp_path), "create_time": 555.0,
    }
    lang = MagicMock()
    lang.name = "uv"
    lang.lockfile_patterns.return_value = ["uv.lock"]
    lang.parse_lockfile.return_value = [
        PackageSpec(name="mypackage", version="1.0.0", ecosystem="PyPI")
    ]
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_recovered]),
        patch.object(monitor, "_pm_names", frozenset(["uv"])),
        patch("packagealert.languages.registry.for_process", return_value=lang),
    ):
        await monitor._scan_processes()

    # Still pending under the new identity. Note this alone does not prove
    # the migration: without it the parse further down re-adds the install
    # here too. The queue assertion below is what catches the orphaned
    # (4000, None) entry being scanned as finished.
    assert (4000, 555.0) in monitor._pending, (
        f"expected the still-running deferred install to remain pending "
        f"under its newly-readable identity, got {list(monitor._pending)}"
    )
    assert monitor._queue.empty(), (
        "expected no lockfile scan while the installer is still running, "
        "even though create_time just became readable"
    )


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_deferred_install_not_emitted_when_create_time_becomes_readable(tmp_path):
    """Regression: a DEFERRED install first tracked as (pid, None), whose
    create_time becomes readable on a later poll while the process is still
    running, must not have its lock file scanned yet.

    The reverse flip deliberately forms a NEW identity (that is what keeps PID
    reuse detectable — see the test below), but the pending entry was left
    behind under the old (pid, None) key. It therefore no longer appeared in
    that poll's current_processes, so `finished = self._pending.keys() -
    current_processes` treated it as exited and ran _emit_from_lockfile()
    while the installer was still very much alive and possibly still writing
    the lock file. Confirmed empirically: a real uv.lock was scanned and its
    package emitted one poll after the create_time became readable.

    A REAL lock file is essential here — _emit_from_lockfile() silently no-ops
    without one, so a fixture that omits it passes on an empty queue even
    though the premature scan happened.
    """
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "evilpkg"\nversion = "6.6.6"\n'
    )

    pid = 4242
    polls = iter([None, 555.0, 555.0])

    def fake_process_iter(attrs=None):
        create_time = next(polls, None)
        proc = MagicMock()
        proc.info = {
            "pid": pid, "ppid": 1, "cmdline": ["uv", "sync"],
            "cwd": str(proj), "create_time": create_time,
        }
        return [proc]

    monitor = _make_monitor()
    with patch("psutil.process_iter", fake_process_iter):
        await monitor._scan_processes()
        assert (pid, None) in monitor._pending, "the deferred install must be tracked"

        await monitor._scan_processes()
        assert (pid, 555.0) in monitor._pending, (
            "the pending entry must migrate onto the new identity, not be orphaned"
        )
        assert (pid, None) not in monitor._pending

    assert [e.package_name for e in monitor.drain()] == [], (
        "the lock file must NOT be scanned while the process is still running"
    )


@pytest.mark.asyncio
async def test_pid_reuse_does_not_overwrite_an_earlier_pending_install(tmp_path):
    """Regression: the (pid, None) -> (pid, create_time) migration must not
    fire on genuine PID reuse.

    Process A is pending with an unreadable create_time. Its pid is then reused
    by a DIFFERENT deferred installer B whose create_time reads fine. An
    unconditional migration moves A onto B's key, and the parsing block further
    down then assigns B's own _PendingInstall to that same key — overwriting A,
    whose install is never emitted at all. Confirmed empirically: only pkgB was
    reported.

    That is a silent miss, strictly worse than the duplicate the migration
    exists to prevent, and it exceeds the documented residual risk (which
    additionally requires B's own create_time read to fail). The migration is
    therefore correlated on cwd: the same process keeps the cwd its pending
    install was recorded with, while a reused pid running a different install
    does not.
    """
    proj_a = tmp_path / "projA"
    proj_a.mkdir()
    (proj_a / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "pkga"\nversion = "1.0"\n'
    )
    proj_b = tmp_path / "projB"
    proj_b.mkdir()
    (proj_b / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "pkgb"\nversion = "2.0"\n'
    )

    pid = 5555
    # (create_time, cwd): A with an unreadable create_time, then B on the same
    # pid with a readable one.
    polls = iter([(None, str(proj_a)), (777.0, str(proj_b))])

    def fake_process_iter(attrs=None):
        nxt = next(polls, None)
        if nxt is None:
            return []
        create_time, cwd = nxt
        proc = MagicMock()
        proc.info = {
            "pid": pid, "ppid": 1, "cmdline": ["uv", "sync"],
            "cwd": cwd, "create_time": create_time,
        }
        return [proc]

    monitor = _make_monitor()
    with patch("psutil.process_iter", fake_process_iter):
        await monitor._scan_processes()
        await monitor._scan_processes()
        await monitor._scan_processes()  # both processes gone

    emitted = sorted(e.package_name for e in monitor.drain())
    assert emitted == ["pkga", "pkgb"], (
        f"both installs must be reported — a pid reused by a different "
        f"installer must not overwrite the earlier pending entry, got {emitted}"
    )


@pytest.mark.asyncio
async def test_migrated_pending_entry_carries_the_recovered_pid(tmp_path):
    """Regression: migrating the pending entry must refresh the identity the
    eventual PackageEvent is built from, not just the dict key.

    _emit_from_lockfile() reads pid/pid_create_time off the _PendingInstall
    object. Normally the entry is rebuilt further down the same loop iteration
    (the new identity isn't in _seen_processes, so it re-parses) and the stale
    values never survive — but several `continue` guards sit between the
    migration and that rebuild. A poll where create_time recovers while a
    DIFFERENT attribute fails (here an empty cmdline — the same per-attribute
    read failure on another field) migrates the entry and never reaches the
    rebuild, so it emitted a pid-less event on exit. _occurrence_key() cannot
    use that to tell two separate installs of the same declared version apart.
    """
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "evilpkg"\nversion = "6.6.6"\n'
    )

    pid = 4242
    # (create_time, cmdline) per poll; then the process exits.
    polls = iter([(None, ["uv", "sync"]), (555.0, [])])

    def fake_process_iter(attrs=None):
        nxt = next(polls, None)
        if nxt is None:
            return []
        create_time, cmdline = nxt
        proc = MagicMock()
        proc.info = {
            "pid": pid, "ppid": 1, "cmdline": cmdline,
            "cwd": str(proj), "create_time": create_time,
        }
        return [proc]

    monitor = _make_monitor()
    with patch("psutil.process_iter", fake_process_iter):
        await monitor._scan_processes()
        await monitor._scan_processes()  # migrates, but skips the rebuild
        await monitor._scan_processes()  # the process exits

    events = monitor.drain()
    assert [e.package_name for e in events] == ["evilpkg"]
    assert events[0].pid == pid, (
        "the migrated entry must carry the recovered pid, or occurrence dedup "
        "cannot distinguish two separate installs"
    )
    assert events[0].pid_create_time == 555.0


@pytest.mark.asyncio
async def test_deferred_install_still_emitted_once_the_process_exits(tmp_path):
    """The migration above must not prevent the eventual, genuine emission."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "evilpkg"\nversion = "6.6.6"\n'
    )

    pid = 4242
    polls = iter([None, 555.0])

    def fake_process_iter(attrs=None):
        create_time = next(polls, "gone")
        if create_time == "gone":
            return []
        proc = MagicMock()
        proc.info = {
            "pid": pid, "ppid": 1, "cmdline": ["uv", "sync"],
            "cwd": str(proj), "create_time": create_time,
        }
        return [proc]

    monitor = _make_monitor()
    with patch("psutil.process_iter", fake_process_iter):
        await monitor._scan_processes()
        await monitor._scan_processes()
        await monitor._scan_processes()  # the process has now exited

    events = monitor.drain()
    assert [e.package_name for e in events] == ["evilpkg"], (
        f"the install must still be reported once the process genuinely exits, "
        f"got {[e.package_name for e in events]}"
    )
    assert events[0].pid == pid
    assert events[0].pid_create_time == 555.0, (
        "the emitted event must carry the reconciled create_time"
    )


async def test_scan_processes_detects_pid_reuse_after_unreadable_create_time(tmp_path):
    """Regression: the create_time reconciliation used to be
    bi-directional — it also fired when the PRIOR reading was None and the
    current one was readable. That silently hid PID REUSE: the
    replacement's own perfectly good create_time was overwritten with
    None, so its identity collapsed onto the previous process's
    (pid, None) entry in _seen_processes, `if process_identity in
    self._seen_processes` matched, and its install was skipped entirely.

    Confirmed empirically: a pid first seen with an unreadable
    create_time, then reused by a DIFFERENT install whose create_time read
    fine, produced no event at all. That is strictly broader than the
    accepted residual risk, which additionally requires the replacement's
    own read to fail.

    Reconciliation is now one-directional (only when THIS poll's read
    failed). The cost is a duplicate when it really was the same process
    recovering — the two are indistinguishable from the available data —
    and this module explicitly prefers a duplicate over a silent miss.
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()

    def _parsed(name: str) -> ProcessInstall:
        return ProcessInstall(
            manager="pip",
            packages=[PackageSpec(name=name, version="1.0.0", ecosystem="PyPI")],
            defer_to_lockfile=False,
        )

    first = MagicMock()
    first.info = {
        "pid": 3100, "ppid": 1, "cmdline": ["pip", "install", "innocent==1.0.0"],
        "cwd": str(tmp_path), "create_time": None,
    }
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[first]),
        patch.object(monitor, "_pm_names", frozenset(["pip"])),
        patch.object(monitor, "_try_parse", return_value=_parsed("innocent")),
    ):
        await monitor._scan_processes()

    first_events = []
    while not monitor._queue.empty():
        first_events.append(monitor._queue.get_nowait())
    assert [e.package_name for e in first_events] == ["innocent"], (
        "precondition: the first install must be observed"
    )

    # The pid is REUSED by a genuinely different install, and this time
    # create_time reads fine.
    reused = MagicMock()
    reused.info = {
        "pid": 3100, "ppid": 1, "cmdline": ["pip", "install", "evilpkg==9.9.9"],
        "cwd": str(tmp_path), "create_time": 999.0,
    }
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[reused]),
        patch.object(monitor, "_pm_names", frozenset(["pip"])),
        patch.object(monitor, "_try_parse", return_value=_parsed("evilpkg")),
    ):
        await monitor._scan_processes()

    second_events = []
    while not monitor._queue.empty():
        second_events.append(monitor._queue.get_nowait())

    assert [e.package_name for e in second_events] == ["evilpkg"], (
        f"expected the pid-reusing install to be observed — collapsing it "
        f"onto the previous process's (pid, None) identity skips it "
        f"entirely, got {[e.package_name for e in second_events]}"
    )
    assert second_events[0].pid == 3100
    assert second_events[0].pid_create_time == 999.0, (
        "the replacement's own create_time must be carried, not overwritten"
    )


@pytest.mark.asyncio
async def test_scan_processes_create_time_recovery_reconciles_immediate_install(
    tmp_path,
):
    """An IMMEDIATE (non-deferred) install first observed with
    create_time=None is tracked in _seen_processes as (pid, None). If
    create_time later reads as a real value for that pid,
    _scan_processes() deliberately does NOT reconcile onto the old
    identity — it forms a distinct one, so the install is re-emitted.

    That costs a duplicate when it really is the same process recovering
    from a failed read. It is the correct trade-off, because the two
    cases are INDISTINGUISHABLE from the data available: "same process,
    read recovered" and "pid reused by a different process whose read
    works" present the identical observation (prior None, now a real
    value), and telling them apart would need exactly the value that
    failed to read. Reconciling here — which an earlier version did —
    overwrote the replacement's own good create_time with None, collapsed
    it onto the previous process's (pid, None) entry, and skipped its
    install entirely (confirmed empirically). A duplicate alert is
    explicitly preferred over a silent miss.
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()
    parsed = ProcessInstall(
        manager="pip",
        packages=[PackageSpec(name="mypackage", version="1.0.0", ecosystem="PyPI")],
        defer_to_lockfile=False,
    )

    proc_glitch = MagicMock()
    proc_glitch.info = {
        "pid": 2000, "ppid": 1, "cmdline": ["pip", "install", "mypackage==1.0.0"],
        "cwd": str(tmp_path), "create_time": None,
    }
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_glitch]),
        patch.object(monitor, "_pm_names", frozenset(["pip"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
    ):
        await monitor._scan_processes()

    first_events = []
    while not monitor._queue.empty():
        first_events.append(monitor._queue.get_nowait())
    assert len(first_events) == 1

    # Same physical process, still running — create_time recovers to a
    # real value on this poll.
    proc_recovered = MagicMock()
    proc_recovered.info = {
        "pid": 2000, "ppid": 1, "cmdline": ["pip", "install", "mypackage==1.0.0"],
        "cwd": str(tmp_path), "create_time": 500.0,
    }
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_recovered]),
        patch.object(monitor, "_pm_names", frozenset(["pip"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
    ):
        await monitor._scan_processes()

    second_events = []
    while not monitor._queue.empty():
        second_events.append(monitor._queue.get_nowait())

    assert [e.package_name for e in second_events] == ["mypackage"], (
        f"expected re-emission once create_time reads as a real value: it is "
        f"indistinguishable from PID reuse, and a duplicate is preferred over "
        f"a missed install, got {[e.package_name for e in second_events]}"
    )


@pytest.mark.asyncio
async def test_scan_processes_pid_reuse_across_polls_is_tracked_separately(tmp_path):
    """PID reuse between polls is rare on Linux (PIDs are allocated
    sequentially with wraparound, not handed back out eagerly — see
    ProcessMonitor.__init__'s own comment), so it's tracked correctly in
    the ordinary case: a pid whose original process genuinely exits, and
    is reused by an unrelated process — BOTH with normally-readable
    create_time values on every poll — is treated as two separate
    installs, not merged. The narrower case where a create_time read
    ALSO happens to glitch on the exact same poll a reused pid first
    appears is a separate, accepted residual risk (see
    _scan_processes()'s own reconciliation comment) — not covered by
    this test, since it would require asserting a false negative as
    "working as intended," which isn't a useful regression signal.
    """
    from packagealert.languages.base import PackageSpec, ProcessInstall

    monitor = _make_monitor()
    parsed_first = ProcessInstall(
        manager="pip",
        packages=[PackageSpec(name="mypackage", version="1.0.0", ecosystem="PyPI")],
        defer_to_lockfile=False,
    )

    proc_a = MagicMock()
    proc_a.info = {
        "pid": 3000, "ppid": 1, "cmdline": ["pip", "install", "mypackage==1.0.0"],
        "cwd": str(tmp_path), "create_time": 100.0,
    }
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_a]),
        patch.object(monitor, "_pm_names", frozenset(["pip"])),
        patch.object(monitor, "_try_parse", return_value=parsed_first),
    ):
        await monitor._scan_processes()

    first_events = []
    while not monitor._queue.empty():
        first_events.append(monitor._queue.get_nowait())
    assert len(first_events) == 1

    # pid 3000's original process has exited; the OS reused it for a
    # genuinely different, unrelated pip install, with its own real,
    # readable create_time (no glitch on this poll).
    parsed_second = ProcessInstall(
        manager="pip",
        packages=[PackageSpec(name="otherpackage", version="2.0.0", ecosystem="PyPI")],
        defer_to_lockfile=False,
    )
    proc_reused = MagicMock()
    proc_reused.info = {
        "pid": 3000, "ppid": 1, "cmdline": ["pip", "install", "otherpackage==2.0.0"],
        "cwd": str(tmp_path), "create_time": 999.0,
    }
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[proc_reused]),
        patch.object(monitor, "_pm_names", frozenset(["pip"])),
        patch.object(monitor, "_try_parse", return_value=parsed_second),
    ):
        await monitor._scan_processes()

    second_events = []
    while not monitor._queue.empty():
        second_events.append(monitor._queue.get_nowait())

    assert len(second_events) == 1 and second_events[0].package_name == "otherpackage", (
        f"expected the genuinely different install to be detected despite "
        f"reusing the same pid number, got {[e.package_name for e in second_events]}"
    )
