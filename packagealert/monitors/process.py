from __future__ import annotations

import asyncio
import logging
import os
import shlex
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import psutil

from packagealert.config import WatchConfig
from packagealert.languages import registry as lang_registry
from packagealert.languages.base import ProcessInstall
from packagealert.languages.registry import _normalise_process_name
from packagealert.managers import manager_registry_name
from packagealert.models.events import PackageEvent, normalise_ecosystem
from packagealert.monitors.base import AbstractMonitor
from packagealert.parsers.process_args import derive_site_packages

log = logging.getLogger(__name__)

def _package_managers() -> frozenset[str]:
    """Return the set of process short-names that may be package manager invocations."""
    lang_registry.load()
    names: set[str] = set()
    for lang in lang_registry.all_languages():
        try:
            names.update(lang.process_names)
        except Exception:
            log.warning(
                "process_names raised unexpectedly for lang=%s — skipping",
                getattr(lang, "name", "?"), exc_info=True,
            )
    return frozenset(names)


@dataclass
class _PendingInstall:
    manager: str          # original invocation manager (e.g. "uv-project"); used for logs/events
    registry_name: str    # language-registry lookup key (e.g. "uv"); may differ from manager
    cwd: Path
    site_pkgs: Path | None
    lockfile_hint: str | None = None
    # The same (pid, create_time) sampling _scan_processes() carries onto an
    # immediate PackageEvent (see its own comment on event_pid/create_time
    # there) — carried through here too so a DEFERRED, lockfile-driven event
    # (_emit_from_lockfile(), below) gets it as well. Daemon._occurrence_key()
    # falls back to a resolved version alone when no pid is available, which
    # cannot distinguish two SEPARATE installs of the same declared version
    # (e.g. two `uv sync` runs of a git/path dependency whose content changed
    # without a version bump) — exactly the scenario that dedup logic exists
    # to preserve. Without this, EVERY deferred event had pid=None
    # unconditionally, silently defeating that protection for what is actually
    # the common case (most package-manager invocations that defer to a
    # lockfile scan, not just an edge case)
    pid: int | None = None
    pid_create_time: float | None = None


class ProcessMonitor(AbstractMonitor):
    def __init__(self, cfg: WatchConfig) -> None:
        self._cfg = cfg
        # Keyed by (pid, create_time), NOT bare pid: on Linux, PIDs are
        # allocated sequentially with wraparound (not reused eagerly the
        # moment they free up), so reuse of any specific PID is rare in
        # practice — but bare-pid bookkeeping would get it silently wrong
        # whenever it does happen: the new process at that pid would be
        # silently skipped by _seen_pids (its own install never even parsed),
        # AND the original process's entry in _pending would never be
        # recognised as finished (it still "looks" alive, since the pid is
        # technically present in the next current_pids snapshot) create_time
        # can be None for a pid whose create_time attribute specifically
        # failed to read this poll (see _scan_processes()'s own comment on
        # event_pid/create_time) — such a pid still needs SOME identity to
        # track for this one poll cycle, so it falls back to (pid, None).
        self._seen_processes: set[tuple[int, float | None]] = set()
        self._pending: dict[tuple[int, float | None], _PendingInstall] = {}
        self._running = False
        self._queue: asyncio.Queue[PackageEvent] = asyncio.Queue()
        self._pm_names: frozenset[str] = _package_managers()

    async def start(self) -> None:
        self._running = True
        log.info("Process monitor started (poll interval %.1fs)", self._cfg.process_poll_interval_seconds)

    async def stop(self) -> None:
        self._running = False

    async def events(self) -> AsyncGenerator[PackageEvent, None]:
        while self._running:
            try:
                await self._scan_processes()
            except Exception:
                log.exception("Error scanning processes")
            while not self._queue.empty():
                yield self._queue.get_nowait()
            await asyncio.sleep(self._cfg.process_poll_interval_seconds)

    async def _scan_processes(self) -> None:
        current_processes: set[tuple[int, float | None]] = set()
        pm_names = self._pm_names
        # Reverse index of this poll's *starting* state — pid -> the
        # create_time it was already tracked under in _pending or
        # _seen_processes, if any (including None, when that pid's very first
        # sighting itself had an unreadable create_time).
        #
        # Used below to reconcile a create_time that fails to read THIS poll
        # back onto the identity that pid is already known under, so a
        # transient read failure for a still-running process isn't mistaken
        # for it exiting and an unrelated one taking its place. Two different
        # tuples for the same still-running pid would otherwise let a pending
        # install show up in `finished` below (its old key vanishes from
        # current_processes), or let an already-seen immediate install's
        # cmdline be reparsed and re-emitted.
        #
        # Reconciliation is ONE-directional — see its own comment below.
        # Only a now-unreadable create_time is reconciled; the reverse
        # (previously unreadable, now readable) deliberately forms a NEW
        # identity, because collapsing it would overwrite a replacement
        # process's own good create_time and hide genuine PID reuse.
        #
        # A pid that genuinely exits is handled correctly either way:
        # _seen_processes/_pending are pruned to current_processes' exact keys
        # at the end of every poll (see `finished` and the `&=` below), so
        # once a pid stops appearing at all, no stale entry is left here for
        # some later, unrelated process at that same pid number to be
        # reconciled onto.
        known_create_time_by_pid: dict[int, float | None] = dict(self._pending.keys())
        known_create_time_by_pid.update(self._seen_processes)
        for proc in psutil.process_iter(["pid", "ppid", "cmdline", "cwd", "create_time"]):
            try:
                info = proc.info
                pid = info["pid"]
                # Sampled from the same process_iter() snapshot as `pid`
                # itself, so it's guaranteed to correspond to the exact
                # process instance identified below — not a separate
                # psutil.Process(pid).create_time() call, which could observe
                # a different (PID-reused) process if made any later than
                # this. Carried on the emitted PackageEvent so a consumer
                # arbitrarily far in the future (behind OSV lookups, batching,
                # etc.) can still verify `pid` refers to the same process,
                # rather than trusting whatever now holds that PID — see
                # CacheMonitor._resolve_owning_pid().
                #
                # process_iter()'s per-attribute error handling
                # (psutil.Process.as_dict(), ad_value=None by default) can
                # populate `pid` successfully while `create_time` specifically
                # comes back None — an AccessDenied or ZombieProcess race
                # hitting just that one attribute within the same oneshot()
                # collection, not the whole process lookup. If that's carried
                # through as event_pid=pid, event_pid_create_time=None,
                # _resolve_owning_pid(pid, None) can't tell "no process was
                # ever really observed" (its own no-pid-known caller —
                # add_site_packages_watch() with no process at all) apart from
                # "a process WAS observed here but its create_time couldn't be
                # read" — it treats None as licence to sample create_time()
                # itself, fresh, at whatever later moment it actually runs.
                # That would reopen the same PID-reuse risk pid_create_time
                # exists to mitigate: if this pid has since been reused,
                # _resolve_owning_pid would silently bind the watch to the
                # new, unrelated process's create_time. So a pid observed
                # without its create_time is not carried at all — event_pid
                # stays None, which _resolve_owning_pid already treats as "no
                # process to track" without ever reaching that fallback.
                create_time = info.get("create_time")
                event_pid = pid if create_time is not None else None
                # process_identity — (pid, create_time) — is this poll's local
                # bookkeeping key for
                # _seen_processes/_pending/current_processes, distinct from
                # event_pid above (which is specifically what gets carried on
                # an emitted PackageEvent, and is deliberately None rather
                # than a guess when create_time is unavailable). See
                # ProcessMonitor.__init__'s own comment on why bare pid is
                # unreliable for this bookkeeping.
                #
                # If create_time became UNREADABLE this poll for a pid already
                # tracked from an earlier one, reconcile onto the already-
                # known identity instead of forming a new, differently-keyed
                # one; treating what's still the same process as a distinct
                # identity would misattribute it (see
                # known_create_time_by_pid's own comment above).
                #
                # Deliberately ONE-directional: only when THIS poll's read
                # failed. An earlier version also reconciled the reverse
                # (prior None, current readable), which silently hid PID REUSE
                # — it overwrote the replacement's own perfectly good
                # create_time with None, so its identity collapsed onto the
                # previous process's (pid, None) entry in _seen_processes and
                # its install was skipped entirely. That is strictly broader
                # than the accepted residual risk below, which needs the
                # REPLACEMENT's own read to fail too.
                #
                # The residual risk that remains: if a pid is reused AND the
                # new process's create_time also fails to read on this exact
                # poll, this still reconciles onto the old identity and the
                # new install can be missed. That relies on PID reuse being
                # rare (as established above) and on both conditions
                # coinciding — accepted, not ruled out. A pid whose first-ever
                # sighting has an unreadable create_time is simply tracked as
                # (pid, None) until a later poll can read it, at which point
                # it is correctly treated as a distinct identity.
                if pid in known_create_time_by_pid and create_time is None:
                    create_time = known_create_time_by_pid[pid]
                    event_pid = pid if create_time is not None else None
                process_identity = (pid, create_time)

                # The reverse flip — first sighted as (pid, None), now
                # readable — deliberately forms a NEW identity above (that is
                # what keeps PID reuse detectable). But any DEFERRED install
                # already tracked under the old (pid, None) key would then be
                # orphaned: it no longer appears in current_processes, so the
                # `finished` calculation at the end of this poll treats it as
                # exited and runs its lockfile scan while that same process is
                # very much still alive and may still be writing the lock
                # file. Migrate the pending entry onto the new identity
                # instead. Only ever from a None prior reading: two real
                # values that DISAGREE are exactly what PID reuse looks like,
                # and must keep the old entry so it is correctly recognised as
                # finished. Correlated on cwd: the same process keeps the cwd
                # its pending install was recorded with, whereas a pid reused
                # by a DIFFERENT installer is almost certainly running
                # somewhere else. Without this check the migration also fires
                # on genuine PID reuse, and the rebuild further down then
                # assigns the NEW install to the very key the old one was just
                # moved to — overwriting it, so the original install is never
                # emitted at all. That is a silent miss, strictly worse than
                # the duplicate this migration exists to prevent, so an
                # uncorrelated pair is deliberately left alone: the old entry
                # keeps its (pid, None) key and is still recognised as
                # finished, exactly as it was before the migration existed.
                _pending_same_pid = self._pending.get((pid, None))
                _same_cwd = (
                    _pending_same_pid is not None
                    and (info.get("cwd") or None) is not None
                    and str(_pending_same_pid.cwd) == info.get("cwd")
                )
                if create_time is not None and _same_cwd:
                    migrated = self._pending.pop((pid, None))
                    # Refresh the identity the eventual PackageEvent is built
                    # from, not just the dict key. The entry is normally
                    # rebuilt further down this same iteration (the new
                    # identity isn't in _seen_processes, so it re-parses),
                    # which would refresh these anyway — but several
                    # `continue` guards sit between here and there, so a poll
                    # where create_time recovers while a DIFFERENT attribute
                    # fails (an empty cmdline, say — the same per-attribute
                    # read failure, just on another field) migrates the entry
                    # and never reaches the rebuild. It then emitted a pid-
                    # less event on exit, which _occurrence_key() cannot use
                    # to tell two separate installs apart.
                    migrated.pid = event_pid
                    migrated.pid_create_time = create_time
                    self._pending[process_identity] = migrated

                cmdline: list[str] = info.get("cmdline") or []
                current_processes.add(process_identity)

                if process_identity in self._seen_processes:
                    continue
                if not cmdline:
                    continue
                # Node.js can pack the full invocation into cmdline[0] as a
                # single space-separated string (e.g. "npm install react")
                # with empty trailing slots. Only unpack when all remaining
                # slots are empty so that legitimate executable paths
                # containing spaces are not split.
                if " " in cmdline[0] and not any(a for a in cmdline[1:] if a):
                    try:
                        cmdline = shlex.split(cmdline[0])
                    except ValueError:
                        cmdline = cmdline[0].split()

                # Use exact basename matching to avoid false positives from
                # substring hits (e.g. "node" matching "electron", "nodemon";
                # "php" matching "phpstorm"). Check argv[0] basename and, for
                # runtimes like python/node that run scripts, argv[1]
                # basename.
                argv0 = _normalise_process_name(os.path.basename(cmdline[0]))
                argv1 = _normalise_process_name(os.path.basename(cmdline[1])) if len(cmdline) > 1 else ""
                if argv0 not in pm_names and argv1 not in pm_names:
                    continue

                parsed = self._try_parse(cmdline)
                if parsed is None:
                    continue

                self._seen_processes.add(process_identity)
                cwd_str = info.get("cwd")
                project_path = Path(cwd_str) if cwd_str else None
                site_pkgs = derive_site_packages(parsed.venv_exe) if parsed.venv_exe else None
                if parsed.defer_to_lockfile:
                    if project_path:
                        self._pending[process_identity] = _PendingInstall(
                            manager=parsed.manager,
                            registry_name=manager_registry_name(parsed.manager),
                            cwd=project_path,
                            site_pkgs=site_pkgs,
                            lockfile_hint=parsed.lockfile_hint,
                            pid=event_pid,
                            pid_create_time=create_time,
                        )
                        ppid = info.get("ppid")
                        parent_name = ""
                        parent_cmdline = ""
                        if ppid:
                            try:
                                parent = psutil.Process(ppid)
                                parent_name = parent.name()
                                parent_cmdline = shlex.join(parent.cmdline()[:6])
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                parent_name = f"({ppid})"
                        parent_suffix = f" (via {parent_name})" if parent_name else ""
                        log.info("Tracking %s install pid=%d in %s%s", parsed.manager, pid, project_path, parent_suffix)
                        log.debug("  cmdline: %s  cwd: %s  parent cmdline: %s", shlex.join(cmdline), project_path, parent_cmdline)
                    continue

                for spec in parsed.packages:
                    try:
                        eco = normalise_ecosystem(spec.ecosystem)
                    except ValueError:
                        log.debug("Skipping package with unknown ecosystem %r: %s", spec.ecosystem, spec.name)
                        continue
                    event = PackageEvent(
                        ecosystem=eco,
                        package_name=spec.name,
                        version=spec.version,
                        source="process",
                        manager=parsed.manager,
                        project_path=project_path,
                        timestamp=datetime.now(UTC),
                        site_packages_dir=site_pkgs,
                        pid=event_pid,
                        pid_create_time=create_time,
                    )
                    log.info(
                        "Detected install: %s %s@%s via %s",
                        event.ecosystem, event.package_name, event.version, event.manager,
                    )
                    await self._queue.put(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Check for completed pending installs. The reconciliation above keeps
        # a still-running process under its ORIGINAL identity across a
        # create_time readability flip, so a genuinely still-running deferred
        # install's key stays present in current_processes and is correctly
        # excluded from `finished` here — without that reconciliation, its old
        # key would vanish from current_processes the instant create_time's
        # readability simply changed, wrongly treating it as finished and
        # reading its lockfile while the installer may still be mid-write.
        finished = self._pending.keys() - current_processes
        for process_identity in finished:
            pending = self._pending.pop(process_identity)
            await self._emit_from_lockfile(pending)

        self._seen_processes &= current_processes  # gc dead processes

    async def _emit_from_lockfile(self, pending: _PendingInstall) -> None:
        lang = lang_registry.for_process(pending.registry_name)
        if lang is None:
            log.debug("No language registered for registry_name='%s' (manager='%s'), skipping lockfile scan", pending.registry_name, pending.manager)
            return

        hint = pending.lockfile_hint
        try:
            lang_patterns = lang.lockfile_patterns()
        except Exception:
            log.warning(
                "lockfile_patterns raised unexpectedly for lang=%s — skipping lockfile scan",
                getattr(lang, "name", "?"), exc_info=True,
            )
            return
        patterns: list[str] = [hint, *lang_patterns] if hint else list(lang_patterns)
        seen: set[str] = set()
        packages = []
        for pattern in patterns:
            if pattern in seen:
                continue
            seen.add(pattern)
            candidate = pending.cwd / pattern
            if candidate.exists():
                try:
                    packages = lang.parse_lockfile(candidate)
                except Exception:
                    log.warning(
                        "parse_lockfile raised unexpectedly for lang=%s path=%s",
                        getattr(lang, "name", "?"), candidate, exc_info=True,
                    )
                    continue
                if packages:
                    break

        if not packages:
            log.debug("No lock file found in %s after %s install", pending.cwd, pending.manager)
            return
        log.info("%s install finished in %s, scanning %d package(s) from lock file", pending.manager, pending.cwd, len(packages))
        for spec in packages:
            try:
                eco = normalise_ecosystem(spec.ecosystem)
            except ValueError:
                log.debug("Skipping package with unknown ecosystem %r: %s", spec.ecosystem, spec.name)
                continue
            event = PackageEvent(
                ecosystem=eco,
                package_name=spec.name,
                version=spec.version,
                source="process",
                manager=pending.manager,
                project_path=pending.cwd,
                timestamp=datetime.now(UTC),
                site_packages_dir=pending.site_pkgs,
                pid=pending.pid,
                pid_create_time=pending.pid_create_time,
            )
            await self._queue.put(event)

    def drain(self) -> list[PackageEvent]:
        events: list[PackageEvent] = []
        while not self._queue.empty():
            events.append(self._queue.get_nowait())
        return events

    def _try_parse(self, cmdline: list[str]) -> ProcessInstall | None:
        cmd = os.path.basename(cmdline[0])
        lang = lang_registry.for_process(cmd)
        if lang is None:
            return None
        try:
            return lang.parse_process_install(cmdline)
        except Exception:
            log.warning(
                "parse_process_install raised unexpectedly for lang=%s cmdline=%r",
                getattr(lang, "name", "?"), cmdline, exc_info=True,
            )
            return None
