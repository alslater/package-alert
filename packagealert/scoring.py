"""Bounded-concurrency risk scoring for package sets.

Shared by `scan-project` and the sandbox runner's lock-file paths. Both need to
score a potentially large package list with a cap on concurrent network calls,
and both must degrade gracefully: a scoring failure for one package must never
abort the surrounding scan.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from packagealert.models.events import PackageEvent, normalise_ecosystem

if TYPE_CHECKING:
    from packagealert.analyzers.risk import RiskEngine
    from packagealert.models.risk import RiskReport

log = logging.getLogger(__name__)

PackageKey = tuple[str, str, str | None]

# One candidate group: either a single directory, or several directories that
# belong together as one distribution's own files (see score_packages's
# docstring). Path alone is included so a one-directory group needs no nesting.
_PackageDirGroup = Path | list[Path] | tuple[Path, ...]

# The nested list-of-groups arm, spelled out as concrete list/tuple forms rather
# than Sequence[_PackageDirGroup]: Sequence's covariance would type-check a
# custom collections.abc.Sequence subclass, but resolve_dirs()' runtime shape
# check only accepts an actual list or tuple, so a custom Sequence is silently
# degraded to metadata-only scoring — a type-checker must not promise a shape
# the runtime rejects (see test_custom_sequence_resolver_return_degrades_to_metadata_only).
# Each concrete form here is still needed because list is invariant: a resolver
# that legitimately narrows its own return type to list[list[Path]] or
# list[tuple[Path, ...]] (rather than the fully mixed list[_PackageDirGroup])
# must still type-check — see _installed_dir_resolver in cli/app.py.
_PackageDirGroups = (
    list[_PackageDirGroup]
    | tuple[_PackageDirGroup, ...]
    | list[list[Path]]
    | list[tuple[Path, ...]]
    | tuple[list[Path], ...]
    | tuple[tuple[Path, ...], ...]
)

DEFAULT_CONCURRENCY = 10

# How many packages are scheduled as pending tasks at once. Two orders of magnitude
# above any sane `concurrency`, so the semaphore — not this — governs throughput: a
# batch this large keeps the worker slots saturated continuously, and the next batch
# is scheduled the moment the previous one drains. Its only job is to stop a
# pathological input from materialising a task per package up front.
_SCHEDULE_BATCH = 1000


@dataclass
class ScoreOutcome:
    reports: dict[PackageKey, RiskReport] = field(default_factory=dict)
    failures: int = 0


def _dedupe_keys(packages: list[PackageKey]) -> list[PackageKey]:
    """Return *packages* with duplicates removed, preserving order."""
    return list(dict.fromkeys(packages))


async def score_packages(
    engine: RiskEngine,
    packages: list[PackageKey],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    progress_cb: Callable[[], None] | None = None,
    # Spelled out as concrete list/tuple forms (_PackageDirGroup, _PackageDirGroups)
    # rather than Sequence[Path] deliberately: the runtime shape check in
    # resolve_dirs() admits only list and tuple, so Sequence[Path] would
    # type-check a custom sequence that is then rejected at runtime and silently
    # degraded to metadata-only scoring. Sequence[str] would also admit a bare
    # str, the exact mistake that check exists to catch. _PackageDirGroups
    # enumerates several list/tuple shapes rather than one, because list is
    # invariant: a resolver (e.g. _installed_dir_resolver) that legitimately
    # narrows its own return type to list[list[Path]] or list[tuple[Path, ...]]
    # — rather than the fully mixed list[_PackageDirGroup] — would otherwise be
    # rejected by a type-checker despite being a valid resolver at runtime.
    package_dir_resolver: Callable[
        [str, str, str | None],
        _PackageDirGroup | _PackageDirGroups | None,
    ] | None = None,
    # Deliberately a *separate* resolver rather than folding the warning into
    # package_dir_resolver's return shape: _PackageDirGroup/_PackageDirGroups
    # already disambiguates several list/tuple forms by shape (see the type
    # comments above), and pairing each group with a warning would add a new
    # shape a genuine 2-element tuple[Path, ...] candidate group could be
    # mistaken for. A package-level (not per-environment) aggregate is also
    # sufficient: the unverifiable_manifest signal it produces is a fact about
    # the distribution, not about whichever candidate group happens to win the
    # score competition, so it does not need to travel with one specific group.
    manifest_warning_resolver: Callable[[str, str, str | None], str | None] | None = None,
) -> ScoreOutcome:
    """Score *packages* with at most *concurrency* concurrent engine calls.

    Without *package_dir_resolver*, `package_dirs` is `[]`: the pre-flight call
    sites run before installation, so no extracted source tree exists and only
    metadata signals (typosquat, low_popularity) can fire.

    *package_dir_resolver* is for call sites where the source *is* on disk —
    notably `scan-project --scan-installed`, which enumerates packages from a real
    venv/site-packages or node_modules. Supplying it lets the full source-code
    heuristics (install scripts, eval, subprocess in setup.py, embedded binaries)
    contribute. Returning None, an empty list, or raising degrades that package
    to metadata-only scoring rather than failing it, since the metadata signals
    still produce a valid score.

    The return shape distinguishes two things a resolver may need to say:

    - A bare `Path`: the one directory to score.
    - A flat `list[Path]`/`tuple[Path, ...]`: each element is a separate
      *candidate*, scored independently — typically a distinct installed copy
      in a different environment — and the highest-scoring report is kept.
      This matters when the same name and version is installed in more than
      one environment: nothing about (ecosystem, name, version) distinguishes
      the copies, so inspecting only one would let a compromised copy
      elsewhere be reported clean.
    - A `list`/`tuple` whose elements are themselves `list[Path]`/`tuple[Path, ...]`
      (or bare `Path`s, each still its own one-directory group): each inner
      group is one candidate, and every `Path` within a group is scored
      *together* in a single `engine.analyze()` call — this is how a
      namespace-package distribution's several owned directories (e.g.
      `google/auth` and `google/oauth2`) are kept as one distribution's own
      files rather than treated as independent candidates racing for the max.
      A bare `list[Path]` at the top level and a list-of-one-Path-groups are
      indistinguishable by shape, which is why the flat form always means
      "independent candidates" — a resolver that wants several directories
      merged as one candidate must nest them in an inner list/tuple, even for
      just that one candidate. (The annotation enumerates several concrete
      list/tuple shapes for this arm, rather than one mixed-element type, so a
      resolver whose own return type is narrower — `list[list[Path]]`, say —
      still type-checks despite `list`'s invariance; see `_PackageDirGroups`.)

    The return shape is validated: anything that is not one of these forms is
    rejected with a warning rather than iterated, so returning a `str` path
    cannot silently expand into one entry per character.

    `_installed_dir_resolver` in cli/app.py returns the list-of-groups form,
    grouping each environment's owned directories together so a namespace
    package's several directories are scored as one unit while independent
    copies in different environments still compete for the max.

    *manifest_warning_resolver*, when given, is called once per package (not
    once per candidate group) and its result — a manifest-integrity warning,
    or None — is passed to every `engine.analyze()` call for that package, so
    it survives regardless of which candidate group's *other* signals win the
    score competition (see LanguageBase.resolve_package_dir_manifest_warning).
    Without this, a distribution with a corrupt, unverifiable manifest in one
    environment resolves to no directories there and would otherwise be scored
    purely on whichever other environment's group happened to win the max —
    silently dropping the corrupt copy's own risk signal, and letting a
    healthy copy elsewhere conceal it. A raising resolver degrades to no
    warning for that package rather than failing it.

    Duplicate keys in *packages* are scored once. `scan_installed()` emits the same
    (ecosystem, name, version) once per environment it finds the package in, so
    duplicates are routine rather than a caller error.

    Failures are counted, never raised — with one exception: *concurrency* below 1
    raises `ValueError`, since it is a programming error rather than a per-package
    problem, and `asyncio.Semaphore(0)` would otherwise hang silently forever.

    `progress_cb` fires once per item in *packages* — including duplicates — so a
    progress bar sized from the caller's list still completes. A callback that
    raises is logged and ignored: reporting must not be able to break scoring, and
    later ticks still fire.

    Tasks are scheduled in batches of `_SCHEDULE_BATCH` so that peak memory is
    bounded by the batch size rather than by `len(packages)`. This does not change
    the observable result or the effective parallelism — `concurrency` still governs
    how many engine calls run at once.
    """
    # Validate before anything else: asyncio.Semaphore(0) never releases, so every
    # task would block forever — a silent hang rather than an error. Negative values
    # raise inside Semaphore, but only after the caller has been handed a coroutine.
    # Checked ahead of the empty-list short-circuit so an invalid argument is not
    # masked by there being no work to do.
    if concurrency < 1:
        raise ValueError(f"concurrency must be at least 1, got {concurrency}")

    outcome = ScoreOutcome()
    if not packages:
        return outcome

    # Score each distinct package once: duplicates would otherwise repeat the same
    # work and race to write the same key. Order is preserved for stable progress
    # reporting; the count of dropped duplicates is replayed to progress_cb below.
    unique: list[PackageKey] = _dedupe_keys(packages)
    duplicate_count = len(packages) - len(unique)

    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()

    def _tick() -> None:
        """Advance the caller's progress callback, swallowing any failure.

        progress_cb is caller-supplied (a Rich Progress bar today), so a fault in it
        is a reporting problem, not a scoring one. The per-task call site sits in a
        `finally`, which runs *after* the per-package `except` — so an unguarded
        raise escaped that handler, propagated out of asyncio.gather, and aborted the
        whole pass, discarding reports that had already been computed. Failures are
        logged once per occurrence and never counted as scoring failures.
        """
        if progress_cb is None:
            return
        try:
            progress_cb()
        except Exception:
            log.warning("Progress callback raised — continuing", exc_info=True)

    def _as_group(value: object, ecosystem: str, name: str) -> list[Path] | None:
        """Coerce one candidate-group entry to list[Path], or None if unusable."""
        if isinstance(value, Path):
            return [value]
        if isinstance(value, (list, tuple)):
            usable = [p for p in value if isinstance(p, Path)]
            if len(usable) != len(value):
                log.warning(
                    "Package directory resolver returned %d non-Path entr%s in a "
                    "candidate group for %s/%s — ignoring them",
                    len(value) - len(usable),
                    "y" if len(value) - len(usable) == 1 else "ies",
                    ecosystem, name,
                )
            return usable
        return None

    def resolve_dirs(ecosystem: str, name: str, version: str | None) -> list[list[Path]]:
        """Resolve the package's on-disk directory candidates. Never raises.

        Always returns at least one group; `[[]]` means "score from metadata
        alone", so callers can iterate uniformly. Each group is scored together
        as one candidate in a single `engine.analyze()` call, and the
        highest-scoring report across groups is kept — see `score_packages`'s
        docstring for the flat-vs-list-of-groups shape this normalises.
        """
        if package_dir_resolver is None:
            return [[]]
        try:
            resolved = package_dir_resolver(ecosystem, name, version)
        except Exception:
            # Degrade to metadata-only rather than failing the package.
            log.warning(
                "Resolving the package directory failed for %s/%s — scoring without "
                "source-code signals", ecosystem, name, exc_info=True,
            )
            return [[]]
        if resolved is None:
            return [[]]
        if isinstance(resolved, Path):
            return [[resolved]]
        # Validate the shape rather than trusting any iterable. A str or bytes is
        # the realistic plugin mistake — returning "/sp/foo" instead of
        # Path("/sp/foo") — and both are iterable, so `list()` would expand them
        # into one bogus single-character entry per character. Each would then fail
        # inside the engine and be swallowed by the per-candidate handler, leaving
        # the package silently scored metadata-only: a false negative, not an error.
        if not isinstance(resolved, (list, tuple)):
            log.warning(
                "Package directory resolver returned %s for %s/%s — expected a Path, "
                "a list/tuple of Paths, or a list of such groups; scoring without "
                "source-code signals",
                type(resolved).__name__, ecosystem, name,
            )
            return [[]]
        # `resolved` is a flat list/tuple of independent candidates. Each element
        # is coerced to its own one-candidate group: a bare Path becomes a
        # single-directory group (unchanged from the pre-list-of-groups
        # behaviour), while a nested list/tuple element becomes a multi-directory
        # group — this is how `_installed_dir_resolver` expresses "these
        # directories are one distribution's own, score them together" without
        # a separate top-level shape. An individual element failing to coerce is
        # dropped rather than discarding the whole call — one malformed group
        # must not hide the others' findings.
        groups = [
            g for g in (_as_group(item, ecosystem, name) for item in resolved) if g
        ]
        return groups or [[]]

    def resolve_manifest_warning(ecosystem: str, name: str, version: str | None) -> str | None:
        """Resolve the package-level manifest-integrity warning. Never raises."""
        if manifest_warning_resolver is None:
            return None
        try:
            return manifest_warning_resolver(ecosystem, name, version)
        except Exception:
            log.warning(
                "Resolving the manifest warning failed for %s/%s — scoring without it",
                ecosystem, name, exc_info=True,
            )
            return None

    async def one(key: PackageKey) -> None:
        raw_ecosystem, name, version = key
        try:
            async with sem:
                # Normalise once and use it for everything downstream. Scoring and
                # resolution must agree: passing the raw string to a caller-supplied
                # resolver while the engine scored under the normalised one left a
                # third-party resolver free to mis-route on case or alias and return
                # nothing, silently dropping source-code signals.
                #
                # Raises only for an ecosystem no registered language claims, which is
                # a genuine caller error rather than a plugin limitation: a registered
                # plugin ecosystem resolves here like any built-in.
                ecosystem = normalise_ecosystem(raw_ecosystem)
                event = PackageEvent(
                    ecosystem=ecosystem,
                    package_name=name,
                    version=version,
                    source="process",
                    manager="scan",
                    project_path=None,
                    timestamp=datetime.now(UTC),
                )
                candidates = resolve_dirs(ecosystem, name, version)
                # Resolved once per package, not per candidate group: it is a
                # fact about the distribution's manifest, independent of which
                # environment's directories happen to win the score
                # competition below — so every group's engine.analyze() call
                # gets the same warning rather than only whichever group wins.
                manifest_warning = resolve_manifest_warning(ecosystem, name, version)
                # Score every candidate group and keep the highest-risk result.
                # When the same name and version is installed in more than one
                # environment the key cannot distinguish the copies, so taking
                # the first would let a compromised copy pass as clean. Each
                # group is passed to the engine whole, so a distribution's
                # several owned directories within one group are scored
                # together rather than as competing candidates.
                report = None
                errors = 0
                for group in candidates:
                    try:
                        current = await engine.analyze(event, group, manifest_warning)
                    except Exception:
                        # One unreadable tree must not discard a sibling's finding.
                        errors += 1
                        log.warning(
                            "Risk scoring failed for %s/%s at %s — trying any "
                            "remaining copies", ecosystem, name, group, exc_info=True,
                        )
                        continue
                    if report is None or current.score > report.score:
                        report = current
                if report is None:
                    # Every candidate failed; count the package once, as before.
                    raise RuntimeError(
                        f"all {errors} candidate director{'y' if errors == 1 else 'ies'} "
                        f"failed to score"
                    )
            async with lock:
                # Merge rather than assign. Deduplication above means this
                # normally sees each key once, but keeping the higher score makes
                # the result independent of task scheduling — a straight
                # assignment let whichever task finished last win, discarding a
                # malicious finding if that task had partially failed.
                existing = outcome.reports.get(key)
                if existing is None or report.score > existing.score:
                    outcome.reports[key] = report
        except Exception:
            # Log the caller's own ecosystem string: it is always bound, and it is
            # what they will recognise. `ecosystem` is unbound if normalisation
            # itself raised.
            log.warning(
                "Risk scoring failed for %s/%s — skipping",
                raw_ecosystem, name, exc_info=True,
            )
            async with lock:
                outcome.failures += 1
        finally:
            _tick()

    # Schedule in bounded batches rather than one task per package up front. The
    # semaphore already caps *execution*, so this is purely about the memory held by
    # pending tasks: roughly 1.35 KB each, which is 3 MB for a 2,500-package
    # lockfile (the largest shape measured) but 330 MB for a pathological 250k
    # input. Batching caps that at O(_SCHEDULE_BATCH) regardless of input size.
    #
    # Deliberately still gather() per batch rather than a worker pool: `one()`
    # handles every exception internally and never propagates, so gather() cannot
    # partially abort the pass, and the per-package fail-open logic stays exactly as
    # it is. A queue-and-workers rewrite would move that error handling for no
    # measurable gain — at realistic sizes the scaffolding is under 0.03% of the
    # scoring work it wraps.
    for start in range(0, len(unique), _SCHEDULE_BATCH):
        await asyncio.gather(*(one(k) for k in unique[start : start + _SCHEDULE_BATCH]))
    # Account for the duplicates that were not scheduled, so a progress bar sized
    # from the caller's list reaches 100%.
    for _ in range(duplicate_count):
        _tick()
    return outcome
