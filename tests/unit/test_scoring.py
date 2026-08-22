import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from packagealert.models.risk import RiskReport
from packagealert.scoring import PackageKey


def _report(name, score):
    return RiskReport(package_name=name, ecosystem="pypi", score=score, signals=[])


@pytest.mark.asyncio
async def test_scores_all_packages():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 30)

    pkgs: list[PackageKey] = [("pypi", "a", "1.0"), ("pypi", "b", "2.0")]
    out = await score_packages(engine, pkgs)

    assert out.failures == 0
    assert set(out.reports) == {("pypi", "a", "1.0"), ("pypi", "b", "2.0")}
    assert out.reports[("pypi", "a", "1.0")].score == 30


@pytest.mark.asyncio
async def test_package_dir_is_none_at_preflight():
    """Nothing is installed at pre-flight, so no source-code signals are possible."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    await score_packages(engine, [("pypi", "a", "1.0")])

    assert engine.analyze.await_args.args[1] == []


@pytest.mark.asyncio
async def test_single_failure_does_not_abort_the_pass():
    from packagealert.scoring import score_packages

    async def analyze(ev, d, w=None):
        if ev.package_name == "boom":
            raise RuntimeError("deps.dev exploded")
        return _report(ev.package_name, 10)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await score_packages(
        engine, [("pypi", "ok", "1.0"), ("pypi", "boom", "1.0"), ("pypi", "ok2", "1.0")]
    )

    assert out.failures == 1
    assert set(out.reports) == {("pypi", "ok", "1.0"), ("pypi", "ok2", "1.0")}


@pytest.mark.asyncio
async def test_unregistered_ecosystem_counts_as_failure_not_crash():
    """An ecosystem no registered language claims is a caller error.

    Uses a deliberately unregistered name: a *plugin* ecosystem is fully supported (see
    tests/unit/test_plugin_ecosystems.py), so this must not use one.
    """
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    out = await score_packages(engine, [("nonesuch-ecosystem", "serde", "1.0")])

    assert out.failures == 1
    assert out.reports == {}


@pytest.mark.asyncio
async def test_concurrency_is_bounded():
    from packagealert.scoring import score_packages

    live = 0
    peak = 0

    async def analyze(ev, d, w=None):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0)
        live -= 1
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    pkgs: list[PackageKey] = [("pypi", f"p{i}", "1.0") for i in range(25)]
    out = await score_packages(engine, pkgs, concurrency=4)

    assert peak <= 4
    assert len(out.reports) == 25


@pytest.mark.asyncio
async def test_progress_callback_fires_once_per_package_including_failures():
    from packagealert.scoring import score_packages

    async def analyze(ev, d, w=None):
        if ev.package_name == "boom":
            raise RuntimeError("nope")
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    calls = []
    await score_packages(
        engine,
        [("pypi", "a", "1.0"), ("pypi", "boom", "1.0")],
        progress_cb=lambda: calls.append(1),
    )

    assert len(calls) == 2


@pytest.mark.asyncio
async def test_empty_input_returns_empty_outcome():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    out = await score_packages(engine, [])
    assert out.reports == {}
    assert out.failures == 0
    engine.analyze.assert_not_awaited()


@pytest.mark.asyncio
async def test_unpinned_version_is_scored():
    """A None version is valid: typosquat and popularity are name-based."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 20)

    out = await score_packages(engine, [("pypi", "reqeusts", None)])

    assert out.failures == 0
    assert out.reports[("pypi", "reqeusts", None)].score == 20


# --- optional package_dir resolution -----------------------------------------
#
# score_packages hardcoded package_dir=None, which is correct for pre-flight (the
# package is not installed yet) but wrong for `scan-project --scan-installed`,
# where the source is on disk in a venv or node_modules. Source-code heuristics
# could not fire in the one scan mode where they are valid. See the spec section
# "Signal availability depends on the scan mode".


@pytest.mark.asyncio
async def test_resolver_supplies_package_dir():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 60)

    seen: dict = {}

    def resolver(ecosystem, name, version):
        seen[(ecosystem, name, version)] = True
        return Path(f"/sp/{name}")

    out = await score_packages(
        engine, [("pypi", "evil", "1.0")], package_dir_resolver=resolver
    )
    assert out.failures == 0
    assert engine.analyze.await_args.args[1] == [Path("/sp/evil")]
    assert seen == {("pypi", "evil", "1.0"): True}


@pytest.mark.asyncio
async def test_without_resolver_package_dir_stays_none():
    """Default behaviour is unchanged for every pre-flight call site."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    await score_packages(engine, [("pypi", "a", "1.0")])
    assert engine.analyze.await_args.args[1] == []


@pytest.mark.asyncio
async def test_resolver_returning_none_falls_back_to_metadata_only():
    """An unresolvable package is still scored, just without source signals."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 20)

    out = await score_packages(
        engine, [("pypi", "a", "1.0")], package_dir_resolver=lambda e, n, v: None
    )
    assert out.failures == 0
    assert out.reports[("pypi", "a", "1.0")].score == 20
    assert engine.analyze.await_args.args[1] == []


@pytest.mark.asyncio
async def test_resolver_exception_does_not_fail_the_package():
    """Per spec: a resolver failure degrades to metadata-only, and must NOT be
    counted as a scoring failure — the metadata signals still produced a score."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 20)

    def boom(ecosystem, name, version):
        raise RuntimeError("resolver exploded")

    out = await score_packages(
        engine, [("pypi", "a", "1.0")], package_dir_resolver=boom
    )
    assert out.failures == 0
    assert out.reports[("pypi", "a", "1.0")].score == 20
    assert engine.analyze.await_args.args[1] == []


# --- duplicate packages across environments -----------------------------------
#
# REGRESSION: with foo==1.0.0 in BOTH .venv and env, the resolver returned the
# first match and both scoring tasks inspected the same tree. Results also
# collapsed under one (ecosystem, name, version) key, so a compromised copy in
# the second environment was reported clean. Version-awareness cannot help here:
# the versions are identical, so only inspecting *every* candidate can.


@pytest.mark.asyncio
async def test_multi_dir_resolver_scores_every_candidate_and_keeps_the_worst():
    from packagealert.scoring import score_packages

    benign = Path("/venv-a/foo")
    evil = Path("/venv-b/foo")

    async def analyze(ev, d, w=None):
        return _report(ev.package_name, 60 if evil in d else 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await score_packages(
        engine,
        [("pypi", "foo", "1.0.0")],
        package_dir_resolver=lambda e, n, v: [benign, evil],
    )
    assert out.failures == 0
    # The highest-risk report must win, not whichever was scanned first.
    assert out.reports[("pypi", "foo", "1.0.0")].score == 60
    assert engine.analyze.await_count == 2, "every candidate must be inspected"


@pytest.mark.asyncio
async def test_multi_dir_resolver_order_does_not_matter():
    """Same set, reversed: the worst score still wins."""
    from packagealert.scoring import score_packages

    evil = Path("/venv-b/foo")

    async def analyze(ev, d, w=None):
        return _report(ev.package_name, 60 if evil in d else 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await score_packages(
        engine,
        [("pypi", "foo", "1.0.0")],
        package_dir_resolver=lambda e, n, v: [evil, Path("/venv-a/foo")],
    )
    assert out.reports[("pypi", "foo", "1.0.0")].score == 60


# ---------------------------------------------------------------------------
# manifest_warning_resolver
#
# REGRESSION: a distribution with a corrupt, unverifiable manifest in one
# environment resolved to no directories there and lost the
# unverifiable_manifest signal entirely if a healthy copy in another
# environment happened to score higher and win the max — the corrupt copy's
# own risk was silently dropped, concealed behind the healthy sibling.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_manifest_warning_reaches_every_candidate_group():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    await score_packages(
        engine,
        [("pypi", "acme", "1.0.0")],
        package_dir_resolver=lambda e, n, v: [Path("/venv-a/acme"), Path("/venv-b/acme")],
        manifest_warning_resolver=lambda e, n, v: "RECORD unreadable",
    )

    assert engine.analyze.await_count == 2
    for call in engine.analyze.await_args_list:
        assert call.args[2] == "RECORD unreadable"


@pytest.mark.asyncio
async def test_manifest_warning_survives_a_healthy_copy_winning_the_max():
    """The exact reported scenario: a corrupt copy resolves to no directories
    (score 0 from metadata alone) while a healthy copy elsewhere scores
    higher and wins — but the warning must still reach the winning report,
    not be discarded along with the corrupt copy's empty directory group."""
    from packagealert.scoring import score_packages

    # Simulates RiskEngine.analyze's real behaviour: the manifest warning adds
    # a fixed 20 regardless of directories, while source-code heuristics (here
    # stood in for by "any directories at all") add their own, larger score —
    # so the healthy copy's group (60 + 20) beats the corrupt copy's (0 + 20).
    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(
        ev.package_name, (60 if d else 0) + (20 if w else 0)
    )

    out = await score_packages(
        engine,
        [("pypi", "acme", "1.0.0")],
        # The corrupt copy resolves to no directories (empty group); the
        # healthy copy elsewhere resolves to a real directory and scores 60.
        package_dir_resolver=lambda e, n, v: [[], [Path("/venv-b/acme")]],
        manifest_warning_resolver=lambda e, n, v: "RECORD unreadable",
    )

    assert out.reports[("pypi", "acme", "1.0.0")].score == 80
    # Both groups were called with the warning, including the winning one —
    # the corrupt copy's signal was not dropped just because it lost the max.
    for call in engine.analyze.await_args_list:
        assert call.args[2] == "RECORD unreadable"


@pytest.mark.asyncio
async def test_manifest_warning_resolver_not_supplied_defaults_to_none():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    await score_packages(engine, [("pypi", "a", "1.0")])

    assert engine.analyze.await_args.args[2] is None


@pytest.mark.asyncio
async def test_manifest_warning_resolver_exception_does_not_fail_the_package():
    from packagealert.scoring import score_packages

    def boom(e, n, v):
        raise RuntimeError("plugin exploded")

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 30)

    out = await score_packages(
        engine, [("pypi", "a", "1.0")], manifest_warning_resolver=boom
    )

    assert out.failures == 0
    assert out.reports[("pypi", "a", "1.0")].score == 30
    assert engine.analyze.await_args.args[2] is None


@pytest.mark.asyncio
async def test_single_path_resolver_still_supported():
    """A resolver returning one Path (not a list) keeps working."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 30)

    out = await score_packages(
        engine, [("pypi", "a", "1.0")], package_dir_resolver=lambda e, n, v: Path("/sp/a")
    )
    assert out.reports[("pypi", "a", "1.0")].score == 30
    assert engine.analyze.await_args.args[1] == [Path("/sp/a")]


@pytest.mark.asyncio
async def test_empty_candidate_list_falls_back_to_metadata_only():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 20)

    out = await score_packages(
        engine, [("pypi", "a", "1.0")], package_dir_resolver=lambda e, n, v: []
    )
    assert out.failures == 0
    assert engine.analyze.await_args.args[1] == []


@pytest.mark.asyncio
async def test_one_failing_candidate_does_not_lose_the_others():
    """A bad tree must not discard a sibling's real finding."""
    from packagealert.scoring import score_packages

    good = Path("/venv-b/foo")

    async def analyze(ev, d, w=None):
        if good not in d:
            raise RuntimeError("unreadable tree")
        return _report(ev.package_name, 60)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await score_packages(
        engine,
        [("pypi", "foo", "1.0.0")],
        package_dir_resolver=lambda e, n, v: [Path("/venv-a/foo"), good],
    )
    assert out.failures == 0
    assert out.reports[("pypi", "foo", "1.0.0")].score == 60


# --- duplicate keys must not overwrite the worst report ------------------------
#
# REGRESSION: outcome.reports[key] was a direct assignment. scan_installed() emits
# the same (ecosystem, name, version) once per environment, so two concurrent tasks
# raced on one key and the last writer won — discarding a malicious finding if the
# other task had partially failed and kept a lower score.


@pytest.mark.asyncio
async def test_duplicate_keys_keep_the_highest_score_regardless_of_order():
    from packagealert.scoring import score_packages

    scores = iter([60, 0])   # first task finds the threat, second sees benign

    async def analyze(ev, d, w=None):
        await asyncio.sleep(0)          # force interleaving
        return _report(ev.package_name, next(scores, 0))

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await score_packages(
        engine,
        [("pypi", "foo", "1.0.0"), ("pypi", "foo", "1.0.0")],
        concurrency=2,
    )
    assert out.reports[("pypi", "foo", "1.0.0")].score == 60


@pytest.mark.asyncio
async def test_lower_score_never_overwrites_a_higher_one_for_the_same_key(monkeypatch):
    """Defence in depth behind the deduplication.

    Dedup means one task per key in normal operation, so this path is only reached
    if duplicates are reintroduced. Bypass the dedup to exercise the merge itself:
    with a plain assignment, whichever task finished last won — discarding a
    malicious finding when that task had partially failed and kept a lower score.
    """
    from packagealert import scoring

    # Make the dedup a no-op so both tasks are scheduled for the same key.
    monkeypatch.setattr(
        scoring, "_dedupe_keys", lambda pkgs: list(pkgs), raising=True
    )

    scores = iter([60, 0])   # the threat is found first, the benign result last

    async def analyze(ev, d, w=None):
        await asyncio.sleep(0)   # force interleaving so the second task finishes last
        return _report(ev.package_name, next(scores, 0))

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await scoring.score_packages(
        engine,
        [("pypi", "foo", "1.0.0"), ("pypi", "foo", "1.0.0")],
        concurrency=2,
    )
    assert out.reports[("pypi", "foo", "1.0.0")].score == 60


@pytest.mark.asyncio
async def test_duplicate_keys_are_scored_once():
    """Deduplicating before scheduling avoids paying for the same work twice."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 10)

    out = await score_packages(
        engine,
        [("pypi", "foo", "1.0.0")] * 3,
        package_dir_resolver=lambda e, n, v: [Path("/a"), Path("/b")],
    )
    # 2 candidate dirs x 1 deduplicated key, not x3.
    assert engine.analyze.await_count == 2
    assert out.reports[("pypi", "foo", "1.0.0")].score == 10


@pytest.mark.asyncio
async def test_progress_fires_once_per_input_item_despite_dedup():
    """The bar is sized from the caller's list, so it must still complete."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    calls = []
    await score_packages(
        engine,
        [("pypi", "foo", "1.0.0")] * 3,
        progress_cb=lambda: calls.append(1),
    )
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_failure_count_is_not_inflated_by_duplicates():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = RuntimeError("boom")

    out = await score_packages(engine, [("pypi", "foo", "1.0.0")] * 3)
    assert out.failures == 1, "one distinct package failed, not three"


# --- concurrency validation ---------------------------------------------------
#
# asyncio.Semaphore(0) never releases, so every task blocks forever — a silent
# hang rather than an error. Negative values raise at construction, but only after
# the caller has already been handed a coroutine. Validate up front so an invalid
# value fails loudly at the call site.


@pytest.mark.parametrize("bad", [0, -1, -10])
@pytest.mark.asyncio
async def test_invalid_concurrency_raises_instead_of_hanging(bad):
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    with pytest.raises(ValueError, match="concurrency"):
        await score_packages(engine, [("pypi", "a", "1.0")], concurrency=bad)
    engine.analyze.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_concurrency_is_rejected_even_with_no_packages():
    """Validate the argument, not just the work — an empty list must not mask it."""
    from packagealert.scoring import score_packages

    with pytest.raises(ValueError, match="concurrency"):
        await score_packages(AsyncMock(), [], concurrency=0)


@pytest.mark.asyncio
async def test_concurrency_of_one_is_valid_and_serialises():
    """The boundary value must work, not be caught by an off-by-one guard."""
    from packagealert.scoring import score_packages

    live = 0
    peak = 0

    async def analyze(ev, d, w=None):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0)
        live -= 1
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await score_packages(
        engine, [("pypi", f"p{i}", "1.0") for i in range(5)], concurrency=1
    )
    assert peak == 1
    assert len(out.reports) == 5


# --- a raising progress callback must not break scoring ------------------------
#
# progress_cb is caller-supplied (a Rich Progress bar today) and was invoked
# unguarded in two places. The per-task call sits in a `finally`, so it runs AFTER
# the per-package except and escapes it — propagating out of asyncio.gather and
# aborting the whole pass, discarding reports that had already been computed. That
# contradicts the function's "degrade gracefully, never abort" contract.


@pytest.mark.asyncio
async def test_raising_progress_cb_does_not_abort_the_pass():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 40)

    def boom():
        raise RuntimeError("progress bar exploded")

    out = await score_packages(
        engine,
        [("pypi", "a", "1.0"), ("pypi", "b", "2.0")],
        progress_cb=boom,
    )
    # Both packages were scored; the broken callback changed nothing.
    assert out.failures == 0
    assert out.reports[("pypi", "a", "1.0")].score == 40
    assert out.reports[("pypi", "b", "2.0")].score == 40


@pytest.mark.asyncio
async def test_raising_progress_cb_does_not_inflate_the_failure_count():
    """A reporting fault is not a scoring failure."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 10)

    def boom():
        raise RuntimeError("nope")

    out = await score_packages(engine, [("pypi", "a", "1.0")], progress_cb=boom)
    assert out.failures == 0


@pytest.mark.asyncio
async def test_raising_progress_cb_in_the_duplicate_replay_is_contained():
    """The post-gather replay loop for deduplicated items is the second call site."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 25)

    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        # Succeed for the scheduled task, fail during the duplicate replay.
        if calls["n"] > 1:
            raise RuntimeError("bar closed early")

    out = await score_packages(
        engine, [("pypi", "a", "1.0")] * 3, progress_cb=flaky
    )
    assert out.failures == 0
    assert out.reports[("pypi", "a", "1.0")].score == 25


@pytest.mark.asyncio
async def test_progress_cb_failure_does_not_stop_later_callbacks():
    """One bad tick must not silence the rest of the reporting."""
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    seen = []

    def flaky():
        seen.append(len(seen))
        if len(seen) == 1:
            raise RuntimeError("first tick failed")

    await score_packages(
        engine,
        [("pypi", f"p{i}", "1.0") for i in range(4)],
        progress_cb=flaky,
        concurrency=1,
    )
    assert len(seen) == 4, f"callback stopped being invoked after a failure: {seen}"


# --- resolver return-type validation ------------------------------------------
#
# `return list(resolved)` accepted any iterable. A str is the realistic mistake —
# returning "/sp/foo" instead of Path("/sp/foo") — and str is iterable, so it
# expanded into one bogus single-character "path" per character. Each then failed
# inside the engine and was swallowed by the per-candidate handler, leaving the
# package silently scored metadata-only: a false negative, not a loud error.


@pytest.mark.asyncio
async def test_str_resolver_return_is_rejected_not_iterated():
    from packagealert.scoring import score_packages

    seen = []

    async def analyze(ev, d, w=None):
        seen.append(d)
        return _report(ev.package_name, 20)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await score_packages(
        engine,
        [("pypi", "a", "1.0")],
        package_dir_resolver=lambda e, n, v: "/sp/a",  # type: ignore[arg-type]  # deliberately invalid: str must be rejected, not iterated
    )
    # Exactly one metadata-only call, not one per character.
    assert seen == [[]], f"str was iterated into {seen}"
    assert out.failures == 0
    assert out.reports[("pypi", "a", "1.0")].score == 20


@pytest.mark.asyncio
async def test_bytes_resolver_return_is_rejected():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 20)

    await score_packages(
        engine,
        [("pypi", "a", "1.0")],
        package_dir_resolver=lambda e, n, v: b"/sp/a",  # type: ignore[arg-type]  # deliberately invalid: bytes must be rejected
    )
    assert engine.analyze.await_args.args[1] == []


@pytest.mark.parametrize("bad", [42, object(), {"a": 1}])
@pytest.mark.asyncio
async def test_non_iterable_resolver_return_degrades_to_metadata_only(bad):
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 15)

    out = await score_packages(
        engine, [("pypi", "a", "1.0")], package_dir_resolver=lambda e, n, v: bad
    )
    assert out.failures == 0
    assert engine.analyze.await_args.args[1] == []


@pytest.mark.asyncio
async def test_list_containing_non_paths_drops_the_bad_entries():
    """A partially valid list must keep its usable entries."""
    from packagealert.scoring import score_packages

    good = Path("/sp/good")
    seen = []

    async def analyze(ev, d, w=None):
        seen.append(d)
        return _report(ev.package_name, 30)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    await score_packages(
        engine,
        [("pypi", "a", "1.0")],
        # deliberately invalid: only the real Path must survive filtering.
        package_dir_resolver=lambda e, n, v: ["/sp/bad", good, None, 7],  # type: ignore[arg-type]
    )
    assert seen == [[good]], f"expected only the real Path, got {seen}"


@pytest.mark.asyncio
async def test_list_of_only_bad_entries_degrades_to_metadata_only():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 10)

    out = await score_packages(
        engine,
        [("pypi", "a", "1.0")],
        package_dir_resolver=lambda e, n, v: ["/a", "/b"],  # type: ignore[arg-type]  # deliberately invalid: no real Path entries
    )
    assert out.failures == 0
    assert engine.analyze.await_args.args[1] == []


@pytest.mark.asyncio
async def test_tuple_of_paths_is_accepted():
    """Any genuine sequence of Paths is fine — only non-Path elements are dropped."""
    from packagealert.scoring import score_packages

    a, b = Path("/sp/a"), Path("/sp/b")
    seen = []

    async def analyze(ev, d, w=None):
        seen.append(d)
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    await score_packages(
        engine, [("pypi", "a", "1.0")], package_dir_resolver=lambda e, n, v: (a, b)
    )
    assert seen == [[a], [b]]


# --- nested groups: a distribution's own several directories vs. independent
# copies ---------------------------------------------------------------------
#
# A namespace-package distribution (e.g. google-auth) can own more than one
# directory of a shared root (google/auth and google/oauth2), never the shared
# root itself. A resolver expresses "these belong together" by nesting them in
# an inner list/tuple; the outer list's elements otherwise mean "independent
# candidate, competing for the max score" (see test_tuple_of_paths_is_accepted
# and test_multi_dir_resolver_scores_every_candidate_and_keeps_the_worst
# above, where a bare list of Paths is exactly that).


@pytest.mark.asyncio
async def test_nested_group_is_scored_as_one_combined_candidate():
    """A resolver's inner list/tuple is one candidate, all its Paths merged into
    a single engine.analyze() call — not N candidates racing for the max."""
    from packagealert.scoring import score_packages

    auth_dir = Path("/sp/google/auth")
    oauth2_dir = Path("/sp/google/oauth2")
    seen = []

    async def analyze(ev, d, w=None):
        seen.append(d)
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    await score_packages(
        engine,
        [("pypi", "google-auth", "2.56.3")],
        package_dir_resolver=lambda e, n, v: [[auth_dir, oauth2_dir]],
    )
    assert seen == [[auth_dir, oauth2_dir]], (
        "both owned directories must reach the engine together in one call"
    )


@pytest.mark.asyncio
async def test_non_path_entries_in_a_nested_group_are_logged_with_package_context(
    caplog,
):
    """REGRESSION: the warning for a malformed nested group named neither the
    ecosystem nor the package, making it useless for identifying which resolver
    call misbehaved in a production log full of many packages."""
    from packagealert.scoring import score_packages

    good = Path("/sp/google/auth")

    async def analyze(ev, d, w=None):
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    with caplog.at_level("WARNING"):
        await score_packages(
            engine,
            [("pypi", "google-auth", "2.56.3")],
            # deliberately invalid: non-Path entries in a nested group must be logged.
            package_dir_resolver=lambda e, n, v: [[good, "/sp/bad", None]],  # type: ignore[arg-type]
        )

    assert "pypi/google-auth" in caplog.text, (
        f"warning is missing package identity: {caplog.text!r}"
    )
    assert "2 non-Path entries" in caplog.text


@pytest.mark.asyncio
async def test_nested_groups_from_different_environments_still_compete_for_the_max():
    """Two environments, each contributing its own multi-directory group: the
    groups compete against each other (independent copies), while directories
    *within* a group stay merged (one distribution's own files)."""
    from packagealert.scoring import score_packages

    benign_group = [Path("/venv-a/google/auth"), Path("/venv-a/google/oauth2")]
    evil_group = [Path("/venv-b/google/auth"), Path("/venv-b/google/oauth2")]

    async def analyze(ev, d, w=None):
        return _report(ev.package_name, 80 if d == evil_group else 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    out = await score_packages(
        engine,
        [("pypi", "google-auth", "2.56.3")],
        package_dir_resolver=lambda e, n, v: [benign_group, evil_group],
    )
    assert out.reports[("pypi", "google-auth", "2.56.3")].score == 80
    assert engine.analyze.await_count == 2, "each environment is its own candidate"


@pytest.mark.asyncio
async def test_single_directory_group_and_flat_list_element_are_equivalent():
    """A one-Path inner group and a bare Path at the top level must behave
    identically: both mean 'one candidate, one directory'."""
    from packagealert.scoring import score_packages

    solo = Path("/sp/foo")
    seen = []

    async def analyze(ev, d, w=None):
        seen.append(d)
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    await score_packages(
        engine, [("pypi", "foo", "1.0")], package_dir_resolver=lambda e, n, v: [[solo]]
    )
    assert seen == [[solo]]


# --- ecosystem normalisation must be consistent --------------------------------
#
# The PackageEvent was built with normalise_ecosystem(ecosystem) while the
# caller-supplied package_dir_resolver received the RAW string from the input
# tuple. The built-in resolver happens to be case-insensitive (it routes through
# lang_registry.for_ecosystem, which lowercases), but a third-party resolver has no
# reason to expect the value it gets to differ from the one scoring uses.


@pytest.mark.asyncio
async def test_resolver_receives_the_normalised_ecosystem():
    from packagealert.scoring import score_packages

    seen = []

    def resolver(ecosystem, name, version):
        seen.append(ecosystem)
        return []

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    await score_packages(
        engine, [("PyPI", "a", "1.0")], package_dir_resolver=resolver
    )
    assert seen == ["pypi"], f"resolver got the raw ecosystem: {seen}"


@pytest.mark.asyncio
async def test_resolver_and_event_agree_on_the_ecosystem():
    """Whatever the caller passes, both sides must see the same value."""
    from packagealert.scoring import score_packages

    seen_resolver = []
    seen_event = []

    async def analyze(ev, d, w=None):
        seen_event.append(ev.ecosystem)
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    await score_packages(
        engine,
        [("NPM", "a", "1.0")],
        package_dir_resolver=lambda e, n, v: seen_resolver.append(e),
    )
    assert seen_resolver == seen_event == ["npm"]


@pytest.mark.asyncio
async def test_mixed_case_ecosystem_is_still_scored():
    from packagealert.scoring import score_packages

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 30)

    out = await score_packages(engine, [("PyPI", "a", "1.0")])
    assert out.failures == 0
    # The report key is the caller's own tuple, so results stay findable.
    assert out.reports[("PyPI", "a", "1.0")].score == 30


@pytest.mark.asyncio
async def test_unregistered_ecosystem_fails_before_resolving():
    """normalise_ecosystem raises before the resolver is consulted, so an unrecognised
    ecosystem is one failure rather than a wasted lookup."""
    from packagealert.scoring import score_packages

    called = []

    engine = AsyncMock()
    engine.analyze.side_effect = lambda ev, d, w=None: _report(ev.package_name, 0)

    out = await score_packages(
        engine,
        [("nonesuch-ecosystem", "serde", "1.0")],
        package_dir_resolver=lambda e, n, v: called.append(e),
    )
    assert out.failures == 1
    assert called == [], "resolver was consulted for an unrecognised ecosystem"


# --- the declared type must match what the runtime accepts ----------------------
#
# test_tuple_of_paths_is_accepted covers the *behaviour*, but the annotation drifted
# from it anyway: it said Path | list[Path] | None while resolve_dirs() has always
# admitted tuples too, so plugin authors and type-checkers were told a tuple was
# invalid. Behavioural tests cannot catch that — nothing executes an annotation.


def test_resolver_annotation_matches_the_accepted_runtime_shapes():
    """The package_dir_resolver return type must name every accepted shape.

    Guards against the annotation and the isinstance() check in resolve_dirs()
    drifting apart in either direction.
    """
    import typing

    from packagealert import scoring as scoring_module
    from packagealert.analyzers.risk import RiskEngine
    from packagealert.scoring import score_packages

    # RiskEngine is imported under TYPE_CHECKING in scoring.py, so it is absent from
    # the module globals at runtime and get_type_hints() cannot resolve it unaided.
    hints = typing.get_type_hints(
        score_packages,
        globalns={**vars(scoring_module), "RiskEngine": RiskEngine},
    )
    resolver = hints["package_dir_resolver"]
    # Callable[[...], R] | None -> pull the return type out of the callable arm.
    callable_arm = next(
        arm for arm in typing.get_args(resolver) if arm is not type(None)
    )
    ret = typing.get_args(callable_arm)[1]
    arms = set(typing.get_args(ret))

    assert Path in arms, "a bare Path must remain documented"
    assert list[Path] in arms, "list[Path] must remain documented"
    assert tuple[Path, ...] in arms, (
        "resolve_dirs() accepts tuples via isinstance(resolved, (list, tuple)), so "
        "the annotation must say so"
    )
    assert type(None) in arms, "None means metadata-only and must stay documented"

    # REGRESSION: a nested list-of-groups arm annotated as Sequence[...] would
    # type-check a custom collections.abc.Sequence subclass — but resolve_dirs()'
    # runtime shape check only accepts an actual list or tuple, so that shape is
    # silently degraded to metadata-only scoring
    # (test_custom_sequence_resolver_return_degrades_to_metadata_only). No arm may
    # be a bare Sequence[...] — only concrete list/tuple forms are acceptable.
    for arm in arms:
        origin = typing.get_origin(arm)
        assert origin in (list, tuple, None), (
            f"{arm!r} is not a concrete list/tuple shape — a Sequence-based arm "
            "would type-check a custom Sequence that the runtime rejects"
        )

    # The mixed-element nested arm — a bare Path or list[Path]/tuple[Path, ...]
    # as each group — must remain documented, since a resolver may return several
    # heterogeneous groups (one single-directory, one multi-directory).
    mixed_arm = list[Path | list[Path] | tuple[Path, ...]]
    assert mixed_arm in arms, "the mixed-element nested list-of-groups arm must remain documented"
    inner_arms = set(typing.get_args(typing.get_args(mixed_arm)[0]))
    assert Path in inner_arms, (
        "a bare Path must be a valid element of the nested list-of-groups form, "
        "matching _as_group()'s runtime acceptance of it"
    )
    assert list[Path] in inner_arms
    assert tuple[Path, ...] in inner_arms

    # REGRESSION: list is invariant, so list[list[Path]] and list[tuple[Path, ...]]
    # — the shapes a resolver narrowing its own return type would use (see
    # _installed_dir_resolver in cli/app.py) — must be named explicitly; they are
    # not covered by the mixed-element arm above despite every element of theirs
    # satisfying it individually.
    assert list[list[Path]] in arms, (
        "a resolver returning list[list[Path]] (narrower than the mixed arm) "
        "must still type-check — list's invariance means it needs its own arm"
    )
    assert list[tuple[Path, ...]] in arms


def test_annotation_does_not_promise_shapes_the_runtime_rejects():
    """Sequence[Path] would be wrong here, and this records why.

    A custom collections.abc.Sequence type-checks against Sequence[Path] but fails
    resolve_dirs()' isinstance(resolved, (list, tuple)) check, so it is silently
    degraded to metadata-only scoring — a false negative rather than an error.
    """
    from collections.abc import Sequence

    class CustomSeq(Sequence):
        def __init__(self, items):
            self._items = items

        def __getitem__(self, key):
            return self._items[key]

        def __len__(self):
            return len(self._items)

    seq = CustomSeq([Path("/sp/a")])
    assert isinstance(seq, Sequence)
    # The precise mismatch that makes Sequence[Path] the wrong annotation.
    assert not isinstance(seq, (list, tuple))


@pytest.mark.asyncio
async def test_custom_sequence_resolver_return_degrades_to_metadata_only():
    """And the consequence, end to end: rejected with a warning, not iterated."""
    from collections.abc import Sequence

    from packagealert.scoring import score_packages

    class CustomSeq(Sequence):
        def __init__(self, items):
            self._items = items

        def __getitem__(self, key):
            return self._items[key]

        def __len__(self):
            return len(self._items)

    async def analyze(ev, d, w=None):
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    outcome = await score_packages(
        engine,
        [("pypi", "a", "1.0")],
        # deliberately invalid: a custom Sequence is not list/tuple and must degrade.
        package_dir_resolver=lambda e, n, v: CustomSeq([Path("/sp/a")]),  # type: ignore[arg-type]
    )
    # Scored metadata-only rather than failed.
    assert outcome.failures == 0
    assert engine.analyze.await_args.args[1] == []


# --- task scheduling is batched -------------------------------------------------
#
# The semaphore bounds *execution*, but asyncio.gather(*(one(k) for k in unique))
# materialised a task per package up front: ~1.35 KB each, so 3 MB for a realistic
# 2,500-package lockfile but ~330 MB for a pathological 250k input. Batching bounds
# that by _SCHEDULE_BATCH instead of by len(packages).
#
# gather() is deliberately retained per batch rather than replaced by a worker pool:
# one() swallows every exception, so gather() cannot partially abort the pass, and
# the fail-open behaviour tested throughout this file stays untouched.


@pytest.mark.asyncio
async def test_batch_size_is_far_above_default_concurrency():
    """Batching must not become the throughput limit — the semaphore is.

    If _SCHEDULE_BATCH ever dropped near `concurrency`, each batch would drain to
    empty before the next was scheduled, idling worker slots at every boundary.
    """
    from packagealert.scoring import _SCHEDULE_BATCH, DEFAULT_CONCURRENCY

    assert _SCHEDULE_BATCH >= DEFAULT_CONCURRENCY * 50


@pytest.mark.asyncio
async def test_every_package_is_scored_across_batch_boundaries():
    """The obvious way to break batching is to drop or duplicate a slice."""
    from packagealert.scoring import _SCHEDULE_BATCH, score_packages

    n = _SCHEDULE_BATCH * 2 + 7  # spans three batches, last one partial
    keys: list[PackageKey] = [("pypi", f"p{i}", "1.0") for i in range(n)]

    scored: list[str] = []

    async def analyze(ev, d, w=None):
        scored.append(ev.package_name)
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    outcome = await score_packages(engine, keys, concurrency=4)
    assert len(outcome.reports) == n
    assert outcome.failures == 0
    assert sorted(scored) == sorted(f"p{i}" for i in range(n))
    assert len(scored) == len(set(scored)), "a package was scored twice"


@pytest.mark.asyncio
async def test_effective_parallelism_is_unchanged_by_batching():
    """Concurrency still governs in-flight work, including across a boundary."""
    from packagealert.scoring import _SCHEDULE_BATCH, score_packages

    n = _SCHEDULE_BATCH + 50
    inflight = 0
    peak = 0

    async def analyze(ev, d, w=None):
        nonlocal inflight, peak
        inflight += 1
        peak = max(peak, inflight)
        await asyncio.sleep(0)
        inflight -= 1
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    await score_packages(
        engine, [("pypi", f"p{i}", "1.0") for i in range(n)], concurrency=6
    )
    assert peak == 6, f"expected the semaphore to cap in-flight work at 6, saw {peak}"


@pytest.mark.asyncio
async def test_a_failure_in_one_batch_does_not_stop_later_batches():
    """Fail-open must survive batching.

    A batch boundary is a new gather(); if an exception could escape one(), it would
    abort the remaining batches and silently discard their findings. This pins that
    a hard failure in batch 1 still leaves batch 2 fully scored.
    """
    from packagealert.scoring import _SCHEDULE_BATCH, score_packages

    n = _SCHEDULE_BATCH + 10
    keys: list[PackageKey] = [("pypi", f"p{i}", "1.0") for i in range(n)]

    async def analyze(ev, d, w=None):
        if ev.package_name == "p0":
            raise RuntimeError("engine exploded")
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    outcome = await score_packages(engine, keys, concurrency=4)
    assert outcome.failures == 1
    assert len(outcome.reports) == n - 1
    # Specifically: the final batch, scheduled after the failure, is intact.
    assert ("pypi", f"p{n - 1}", "1.0") in outcome.reports


@pytest.mark.asyncio
async def test_progress_fires_once_per_package_across_batches():
    from packagealert.scoring import _SCHEDULE_BATCH, score_packages

    n = _SCHEDULE_BATCH + 25
    ticks = 0

    def tick():
        nonlocal ticks
        ticks += 1

    async def analyze(ev, d, w=None):
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    await score_packages(
        engine,
        [("pypi", f"p{i}", "1.0") for i in range(n)],
        concurrency=4,
        progress_cb=tick,
    )
    assert ticks == n


@pytest.mark.asyncio
async def test_input_smaller_than_one_batch_still_works():
    """The single-batch path is the overwhelmingly common one."""
    from packagealert.scoring import score_packages

    async def analyze(ev, d, w=None):
        return _report(ev.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    outcome = await score_packages(
        engine, [("pypi", f"p{i}", "1.0") for i in range(3)], concurrency=4
    )
    assert len(outcome.reports) == 3
    assert outcome.failures == 0



# --- PackageEvent must not undo ecosystem-specific name normalisation -----------
#
# REGRESSION: PackageEvent.normalize_name applied the PEP 503 rule (collapse [-_.] runs)
# to every ecosystem. score_packages constructs a PackageEvent, so a real npm
# `socket.io` reached RiskEngine as `socket-io` — defeating the corrected
# TyposquatDetector and scoring the package as a typosquat of itself at 20, above
# typosquat_min_score (15) and therefore enough to gate `pa run`.
#
# It also queried deps.dev for the wrong name. `socket-io` is a genuinely different
# npm package (16 dependents vs socket.io's ~15k), so the adoption reduction that should
# have suppressed the false positive was computed from a near-unadopted package.
#
# These go through score_packages with a real RiskEngine. The detector-only tests in
# test_typosquat.py bypass the model transformation entirely and all passed throughout.


@pytest.mark.asyncio
async def test_scoring_preserves_npm_dotted_names_end_to_end():
    """The full path: score_packages -> PackageEvent -> RiskEngine -> detector."""
    from packagealert.analyzers.risk import RiskEngine
    from packagealert.config import HeuristicsConfig
    from packagealert.scoring import score_packages

    engine = RiskEngine(HeuristicsConfig())
    outcome = await score_packages(engine, [("npm", "socket.io", "4.7.5")])

    report = outcome.reports[("npm", "socket.io", "4.7.5")]
    typo = [s for s in report.signals if s.name == "typosquat"]
    assert typo == [], f"socket.io flagged as a typosquat of itself: {typo}"
    assert report.score == 0


@pytest.mark.asyncio
async def test_scoring_still_flags_a_real_npm_separator_squat():
    """Not a blanket exemption: socket-io really is a different package."""
    from packagealert.analyzers.risk import RiskEngine
    from packagealert.config import HeuristicsConfig
    from packagealert.scoring import score_packages

    engine = RiskEngine(HeuristicsConfig())
    outcome = await score_packages(engine, [("npm", "socket-io", "1.0.0")])

    report = outcome.reports[("npm", "socket-io", "1.0.0")]
    typo = next(s for s in report.signals if s.name == "typosquat")
    assert typo.score == 20
    assert "socket.io" in typo.reason


@pytest.mark.asyncio
async def test_scoring_passes_the_unmodified_name_to_the_engine():
    """Pins the mechanism, not just the outcome.

    Asserts on the PackageEvent the engine actually receives, so a future change that
    reintroduces name rewriting fails here with a clear cause even if the corpus shifts.
    """
    from packagealert.scoring import score_packages

    seen = []

    async def analyze(event, package_dir, warning=None):
        seen.append((event.ecosystem, event.package_name))
        return _report(event.package_name, 0)

    engine = AsyncMock()
    engine.analyze.side_effect = analyze

    await score_packages(engine, [
        ("npm", "socket.io", "4.7.5"),
        ("pypi", "typing_extensions", "4.0.0"),
    ])
    assert ("npm", "socket.io") in seen, "npm dots must survive the event model"
    assert ("pypi", "typing-extensions") in seen, "PyPI must still collapse separators"


@pytest.mark.asyncio
async def test_scoring_still_collapses_pypi_separators_end_to_end():
    """PEP 503 equivalence must survive the fix."""
    from packagealert.analyzers.risk import RiskEngine
    from packagealert.config import HeuristicsConfig
    from packagealert.scoring import score_packages

    engine = RiskEngine(HeuristicsConfig())
    outcome = await score_packages(engine, [("pypi", "typing_extensions", "4.0.0")])

    report = outcome.reports[("pypi", "typing_extensions", "4.0.0")]
    typo = [s for s in report.signals if s.name == "typosquat"]
    assert typo == [], "typing_extensions is PEP 503-equal to a real package"
