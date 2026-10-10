"""Packages not from the public registry are never looked up publicly by the daemon either."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from packagealert.config import AppConfig, WatchConfig
from packagealert.languages import registry as lang_registry
from packagealert.languages.base import PackageSpec, ProcessInstall
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport
from packagealert.monitors.process import ProcessMonitor, _PendingInstall


def _proc(cwd: Path, cmdline: list[str]):
    proc = MagicMock()
    proc.info = {"pid": 4242, "ppid": 1, "cmdline": cmdline, "cwd": str(cwd), "create_time": 1700000000.5}
    return proc


async def _explicit_events(tmp_path: Path, specs: list[PackageSpec]) -> list[PackageEvent]:
    lang_registry.load()
    monitor = ProcessMonitor(WatchConfig(process_poll_interval_seconds=1))
    parsed = ProcessInstall(manager="npm", packages=specs, defer_to_lockfile=False)
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[_proc(tmp_path, ["npm", "install"])]),
        patch.object(monitor, "_pm_names", frozenset(["npm"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
    ):
        await monitor._scan_processes()
    # The install exits: events held until then (private packages) are emitted too.
    with patch("packagealert.monitors.process.psutil.process_iter", return_value=[]):
        await monitor._scan_processes()
    events = []
    while not monitor._queue.empty():
        events.append(monitor._queue.get_nowait())
    return events


async def test_an_explicit_package_carries_its_provenance_to_the_event(tmp_path):
    (tmp_path / ".npmrc").write_text("@corp:registry=https://npm.corp.example/\n")
    events = await _explicit_events(tmp_path, [
        PackageSpec(name="pub", version="1.0.0", ecosystem="npm"),
        PackageSpec(name="evil", version=None, ecosystem="npm", from_public_registry=False),   # a git spec, say
        PackageSpec(name="@corp/x", version="1.0.0", ecosystem="npm"),                          # a private scope
    ])
    assert {e.package_name: e.from_public_registry for e in events} == {"pub": True, "evil": False, "@corp/x": False}


async def test_a_package_from_the_lock_carries_its_provenance_to_the_event(tmp_path):
    lang_registry.load()
    monitor = ProcessMonitor(WatchConfig(process_poll_interval_seconds=1))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"pub": "^1.0.0", "priv": "^1.0.0"}},
        "node_modules/pub": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz"},
        "node_modules/priv": {"version": "1.0.0", "resolved": "https://npm.corp.example/priv/-/priv-1.0.0.tgz"},
    }}))
    pending = _PendingInstall(manager="npm", registry_name="npm", cwd=tmp_path, site_pkgs=None,
                              lockfile_hint="package-lock.json")
    await monitor._emit_from_lockfile(pending)
    events = []
    while not monitor._queue.empty():
        events.append(monitor._queue.get_nowait())
    assert {e.package_name: e.from_public_registry for e in events} == {"pub": True, "priv": False}


def _event(public: bool) -> PackageEvent:
    return PackageEvent(ecosystem="npm", package_name="priv", version="1.0.0", source="process", manager="npm",
                        project_path=None, timestamp=datetime.now(UTC), from_public_registry=public)


async def test_the_daemon_looks_nothing_up_publicly_for_a_non_public_package():
    from packagealert.daemon import Daemon

    lang_registry.load()
    daemon = Daemon(AppConfig())
    osv_client, osv_cache = MagicMock(), MagicMock()
    osv_client.batch_query = AsyncMock(side_effect=AssertionError("no OSV query for a private package"))
    osv_cache.get = AsyncMock(side_effect=AssertionError("no OSV cache lookup for a private package"))
    engine = MagicMock()
    engine.analyze = AsyncMock(return_value=RiskReport(package_name="priv", ecosystem="npm", score=0, signals=[]))
    with patch("packagealert.daemon._resolve_package_dir", return_value=([], None)):
        assert await daemon._batch_prefetch([_event(False)], osv_client, osv_cache) == {}
        authoritative = await daemon._process_event(_event(False), osv_client, osv_cache, engine, db=MagicMock())
    assert authoritative is True
    assert engine.analyze.await_args.kwargs.get("local_only") is True


async def test_a_private_copys_evaluation_never_stands_in_for_a_public_copy():
    """Same name, version and project: the private copy's completed evaluation must not suppress the public one."""
    from packagealert.daemon import Daemon

    lang_registry.load()
    daemon = Daemon(AppConfig())

    def event(public: bool) -> PackageEvent:
        return PackageEvent(ecosystem="npm", package_name="x", version="1.0.0", source="process", manager="npm",
                            project_path=Path("/proj"), timestamp=datetime.now(UTC), pid=7, pid_create_time=1.0,
                            from_public_registry=public)

    osv_client, osv_cache = MagicMock(), MagicMock()
    engine = MagicMock()
    engine.analyze = AsyncMock(return_value=RiskReport(package_name="x", ecosystem="npm", score=0, signals=[]))
    with patch("packagealert.daemon._resolve_package_dir", return_value=([], None)):
        assert await daemon._claim_for_processing(event(False)) is True
        await daemon._process_claimed_event(event(False), osv_client, osv_cache, engine, db=MagicMock())
    assert await daemon._claim_for_processing(event(True)) is True        # still evaluated publicly


async def test_a_deferred_install_judges_url_less_entries_by_its_own_registry(tmp_path):
    """npm install --registry <private> writing URL-less entries (omit-lockfile-registry-resolved): the lock scan
    after the process exits applies that registry, as it would during the command."""
    lang_registry.load()
    monitor = ProcessMonitor(WatchConfig(process_poll_interval_seconds=1))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app", "dependencies": {"evil": "^1.0.0"}},
        "node_modules/evil": {"version": "1.0.0"},
    }}))
    pending = _PendingInstall(manager="npm", registry_name="npm", cwd=tmp_path, site_pkgs=None,
                              lockfile_hint="package-lock.json",
                              registries={"registry": "https://npm.corp.example/"})
    await monitor._emit_from_lockfile(pending)
    events = []
    while not monitor._queue.empty():
        events.append(monitor._queue.get_nowait())
    assert [(e.package_name, e.from_public_registry) for e in events] == [("evil", False)]


async def test_a_deferred_install_records_the_commands_registries(tmp_path):
    lang_registry.load()
    monitor = ProcessMonitor(WatchConfig(process_poll_interval_seconds=1))
    parsed = ProcessInstall(manager="npm", packages=[], defer_to_lockfile=True,
                            registries={"registry": "https://npm.corp.example/"})
    with (
        patch("packagealert.monitors.process.psutil.process_iter", return_value=[_proc(tmp_path, ["npm", "install"])]),
        patch.object(monitor, "_pm_names", frozenset(["npm"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
    ):
        await monitor._scan_processes()
    [pending] = monitor._pending.values()
    assert pending.registries == {"registry": "https://npm.corp.example/"}


def test_the_hook_receives_the_package_as_its_own_language_writes_it(tmp_path):
    from packagealert.monitors.process import _named_package_public

    seen: list = []
    lang = MagicMock()
    lang.serialise_package_spec = lambda name, version: f"{name}=={version}"
    lang.explicit_package_public = lambda raw, parsed, project_dir: seen.append(raw) or True
    spec = PackageSpec(name="thing", version="1.0", ecosystem="npm")
    with patch("packagealert.monitors.process.lang_registry.for_ecosystem", return_value=lang):
        assert _named_package_public(spec, ProcessInstall(manager="x", packages=[spec]), tmp_path) is True
    assert seen == ["thing==1.0"]


async def test_a_private_packages_event_waits_for_the_install_to_finish(tmp_path):
    """It is judged on its source alone, so it is emitted once the install has written it, not when the command is
    first seen; a public package's event is emitted at once, as before."""
    lang_registry.load()
    monitor = ProcessMonitor(WatchConfig(process_poll_interval_seconds=1))
    specs = [PackageSpec(name="pub", version="1.0.0", ecosystem="npm"),
             PackageSpec(name="evil", version=None, ecosystem="npm", from_public_registry=False)]
    parsed = ProcessInstall(manager="npm", packages=specs, defer_to_lockfile=False)

    def drain():
        out = []
        while not monitor._queue.empty():
            out.append(monitor._queue.get_nowait())
        return out

    running = _proc(tmp_path, ["npm", "install", "pub", "github:o/evil"])
    with (
        patch.object(monitor, "_pm_names", frozenset(["npm"])),
        patch.object(monitor, "_try_parse", return_value=parsed),
    ):
        with patch("packagealert.monitors.process.psutil.process_iter", return_value=[running]):
            await monitor._scan_processes()
        assert [e.package_name for e in drain()] == ["pub"]                     # the private one waits
        with patch("packagealert.monitors.process.psutil.process_iter", return_value=[running]):
            await monitor._scan_processes()
        assert drain() == []                                                    # still running
        with patch("packagealert.monitors.process.psutil.process_iter", return_value=[]):
            await monitor._scan_processes()
        assert [(e.package_name, e.from_public_registry) for e in drain()] == [("evil", False)]
