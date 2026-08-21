"""Risk gate tests for SandboxRunner.

The `publication_date_url` / unpinned-version tests are regressions for real
coverage holes: `_cooldown_check` skips the typosquat check in both cases, which
silently disabled typosquat detection for ecosystems without a publication-date
endpoint (e.g. Packagist) and for unpinned packages.
"""

import contextlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from packagealert.config import AppConfig, PreflightRiskConfig
from packagealert.heuristics.typosquat import TyposquatResult
from packagealert.models.risk import RiskReport
from packagealert.sandbox.runner import SandboxRunner, _Context
from tests.unit.dbmocks import make_mock_db


def _runner(**preflight_risk):
    cfg = AppConfig()
    if preflight_risk:
        cfg.sandbox.preflight_risk = PreflightRiskConfig(**preflight_risk)
    with patch("packagealert.sandbox.runner.build_backend"):
        return SandboxRunner(cfg)


def _ctx(packages, ecosystem="pypi", req_files=(), lockfile_hint=None):
    parsed = MagicMock()
    parsed.packages = packages
    parsed.ecosystem = ecosystem
    # Explicit, not left as MagicMock defaults: _resolve_query_packages checks
    # `if parsed.req_files:` and iterates it, and a bare MagicMock is truthy
    # and not iterable — every existing caller that only cares about explicit
    # packages needs these to behave like ParsedInstall's real "none" defaults.
    parsed.req_files = list(req_files)
    parsed.lockfile_hint = lockfile_hint
    return _Context(argv=["pip", "install", *packages], parsed=parsed, cwd=Path("/tmp"))


def _typo(is_typosquat=False, closest_match=None, distance=None, score=0, affix=False):
    return TyposquatResult(is_typosquat, closest_match, distance, score, affix)


def _report(score=0):
    return RiskReport(package_name="x", ecosystem="pypi", score=score, signals=[])


def _engine_patch(*, typo, report=None, analyze_raises=None, typo_raises=None):
    """Patch _build_risk_engine to return controlled engine/detector doubles."""
    engine = AsyncMock()
    if analyze_raises is not None:
        engine.analyze.side_effect = analyze_raises
    else:
        engine.analyze.return_value = report if report is not None else _report(0)

    detector = AsyncMock()
    if typo_raises is not None:
        detector.analyze.side_effect = typo_raises
    else:
        detector.analyze.return_value = typo

    pop_client = AsyncMock()
    return patch.object(
        SandboxRunner, "_build_risk_engine", return_value=(engine, detector, pop_client)
    )


def _db_patch():
    """Patch open_db with a connection whose execute() supports `async with`.

    A bare AsyncMock is wrong here: its execute() returns a coroutine, so
    `async with db.execute(...)` raises TypeError inside the cache readers. The
    fail-open handlers swallow it, leaving only a "coroutine ... was never awaited"
    warning while the test silently exercised the cache-miss path.
    """
    return patch(
        "packagealert.sandbox.runner.open_db",
        new_callable=AsyncMock,
        return_value=make_mock_db(),
    )


# --- basic gating ------------------------------------------------------------


@pytest.mark.asyncio
async def test_clean_package_allows_and_returns_score_map():
    r = _runner()
    with _db_patch(), _engine_patch(typo=_typo(), report=_report(0)):
        out = await r._risk_check(_ctx(["requests==2.31.0"]))
    assert out is not False
    assert out[("pypi", "requests")] == 0


@pytest.mark.asyncio
async def test_typosquat_blocks_when_configured():
    r = _runner(on_typosquat="block")
    with _db_patch(), _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out is False


@pytest.mark.asyncio
async def test_high_score_blocks_when_configured():
    r = _runner(on_high_risk="block", risk_threshold=25)
    with _db_patch(), _engine_patch(typo=_typo(), report=_report(40)):
        out = await r._risk_check(_ctx(["obscure==1.0.0"]))
    assert out is False


@pytest.mark.asyncio
async def test_warn_does_not_block():
    r = _runner(on_high_risk="warn", risk_threshold=25)
    with _db_patch(), _engine_patch(typo=_typo(), report=_report(40)):
        out = await r._risk_check(_ctx(["obscure==1.0.0"]))
    assert out is not False
    assert out[("pypi", "obscure")] == 40


@pytest.mark.asyncio
async def test_disabled_short_circuits_without_scoring():
    r = _runner(enabled=False)
    with (
        _db_patch(),
        patch.object(SandboxRunner, "_build_risk_engine") as build,
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out == {}
    build.assert_not_called()


@pytest.mark.asyncio
async def test_heuristics_disabled_short_circuits():
    """heuristics.enabled = false must disable risk scoring everywhere."""
    cfg = AppConfig()
    cfg.heuristics.enabled = False
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)
    with _db_patch(), patch.object(SandboxRunner, "_build_risk_engine") as build:
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out == {}
    build.assert_not_called()


@pytest.mark.asyncio
async def test_no_packages_returns_empty_map():
    r = _runner()
    with _db_patch(), patch.object(SandboxRunner, "_build_risk_engine") as build:
        out = await r._risk_check(_ctx([]))
    assert out == {}
    build.assert_not_called()


# --- concurrency ---------------------------------------------------------


@pytest.mark.asyncio
async def test_risk_check_scores_packages_concurrently():
    """REGRESSION: _risk_check must score the packages about to be installed
    with score_packages' bounded concurrency, not one engine.analyze() await
    per package in a sequential loop. A sequential loop can never have more
    than one call in flight at once; scoring several independent packages
    concurrently is exactly the gap between "1 in flight" and "> 1 in
    flight" this test catches — mirroring test_concurrency_is_bounded in
    test_scoring.py, and matching _risk_check_lockfiles, which already uses
    score_packages for the same reason."""
    import asyncio

    live = 0
    peak = 0

    async def analyze(ev, d, w=None):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0)
        live -= 1
        return _report(0)

    engine_double = AsyncMock()
    engine_double.analyze.side_effect = analyze
    detector_double = AsyncMock()
    detector_double.analyze.return_value = _typo()
    pop_client_double = AsyncMock()

    r = _runner()
    packages = [f"pkg{i}==1.0.0" for i in range(5)]
    with (
        _db_patch(),
        patch.object(
            SandboxRunner,
            "_build_risk_engine",
            return_value=(engine_double, detector_double, pop_client_double),
        ),
    ):
        out = await r._risk_check(_ctx(packages))

    assert peak > 1, "packages were scored one at a time instead of concurrently"
    assert len(out) == 5


# --- regression: the two coverage holes -------------------------------------


@pytest.mark.asyncio
async def test_typosquat_caught_when_no_publication_date_url():
    """REGRESSION: _cooldown_check skips typosquat when publication_date_url()
    returns None, so Packagist got no typosquat detection at all. _risk_check
    never consults publication_date_url, so the match is still reported."""
    r = _runner(on_typosquat="block")
    lang = MagicMock()
    lang.publication_date_url.return_value = None
    with (
        _db_patch(),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
        _engine_patch(typo=_typo(True, "monolog/monolog", 1, 20), report=_report(20)),
    ):
        out = await r._risk_check(_ctx(["monolog/monlog:1.0.0"], ecosystem="packagist"))
    assert out is False


@pytest.mark.asyncio
async def test_typosquat_caught_for_unpinned_package():
    """REGRESSION: _cooldown_check skips typosquat when the latest version cannot
    be resolved. A typosquat match depends only on the name."""
    r = _runner(on_typosquat="block")
    with _db_patch(), _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)):
        out = await r._risk_check(_ctx(["reqeusts"]))
    assert out is False


@pytest.mark.asyncio
async def test_unnamed_specs_are_skipped():
    """VCS URLs / local paths / editables have no registry name to compare."""
    r = _runner(on_typosquat="block")
    with _db_patch(), _engine_patch(typo=_typo(True, "requests", 1, 20)):
        out = await r._risk_check(_ctx(["git+https://github.com/psf/requests"]))
    assert out is not False
    assert out == {}


# --- prompting ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_prompt_declined_blocks():
    r = _runner(on_typosquat="prompt")
    with (
        _db_patch(),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=False),
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out is False


@pytest.mark.asyncio
async def test_prompt_accepted_allows():
    r = _runner(on_typosquat="prompt")
    with (
        _db_patch(),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=True),
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out is not False


@pytest.mark.asyncio
async def test_prompt_escalates_to_block_when_not_tty():
    r = _runner(on_typosquat="prompt", non_interactive_escalation="block")
    with (
        _db_patch(),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=False),
        patch("rich.prompt.Confirm.ask", return_value=True) as ask,
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out is False
    ask.assert_not_called()


@pytest.mark.asyncio
async def test_prompt_skipped_once_another_package_already_blocked():
    """REGRESSION: once one package in the same run is blocked, nothing a later
    "prompt" decision's answer could say changes the outcome — _risk_check
    returned False either way. Confirm.ask must not fire in that case, and the
    later package must not itself force a separate accepted/allowed path."""
    r = _runner(on_typosquat="block", on_high_risk="prompt", risk_threshold=25)

    def analyze(ev, d, w=None):
        # "reqeusts" is the typosquat (blocked); "obscure" only trips the
        # high-risk threshold (would otherwise prompt).
        return _report(40) if ev.package_name == "obscure" else _report(0)

    def typo_analyze(name, ecosystem):
        return _typo(True, "requests", 1, 20) if name == "reqeusts" else _typo()

    engine_double = AsyncMock()
    engine_double.analyze.side_effect = analyze
    detector_double = AsyncMock()
    detector_double.analyze.side_effect = typo_analyze
    pop_client_double = AsyncMock()

    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine",
            return_value=(engine_double, detector_double, pop_client_double),
        ),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=True) as ask,
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0", "obscure==1.0.0"]))

    assert out is False
    ask.assert_not_called()


@pytest.mark.asyncio
async def test_prompt_skipped_even_when_the_blocked_package_finishes_scoring_last():
    """REGRESSION: score_packages scores concurrently and inserts each report
    into outcome.reports as its own task completes (scoring.py's `one()`), so
    dict order is task-completion order, not query order. Iterating
    outcome.reports.items() directly made the already_blocked short-circuit a
    timing accident: if the prompted package's task happened to finish before
    the blocked package's task, this branch saw already_blocked == False and
    still called Confirm.ask, even though "reqeusts" (listed first) is the one
    that ultimately forces the block. This test makes "reqeusts" the SLOWEST
    task on purpose, so a naive dict-order iteration would see "obscure"
    (fast, prompts) complete and get processed before "reqeusts" (slow,
    blocks) — the exact inversion the fix must be immune to."""
    import asyncio

    r = _runner(on_typosquat="block", on_high_risk="prompt", risk_threshold=25)

    async def analyze(ev, d, w=None):
        if ev.package_name == "reqeusts":
            await asyncio.sleep(0.02)  # finishes LAST despite being listed first
            return _report(0)
        await asyncio.sleep(0)  # "obscure" finishes first
        return _report(40)

    def typo_analyze(name, ecosystem):
        return _typo(True, "requests", 1, 20) if name == "reqeusts" else _typo()

    engine_double = AsyncMock()
    engine_double.analyze.side_effect = analyze
    detector_double = AsyncMock()
    detector_double.analyze.side_effect = typo_analyze
    pop_client_double = AsyncMock()

    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine",
            return_value=(engine_double, detector_double, pop_client_double),
        ),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=True) as ask,
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0", "obscure==1.0.0"]))

    assert out is False
    # If this fails: outcome.reports' completion order put "obscure" (prompt)
    # ahead of "reqeusts" (block) — iteration must follow query order, not
    # completion order.
    ask.assert_not_called()


@pytest.mark.asyncio
async def test_duplicate_package_prompts_only_once():
    """REGRESSION: score_packages() dedupes its input internally (its own
    _dedupe_keys), so outcome.reports has exactly one entry per distinct
    package regardless of how many times it was requested. Iterating the raw,
    non-deduped `keys` list (to fix the ordering bug above) reintroduced the
    duplicate: a package repeated on the CLI or across requirement files was
    processed once per repetition, so a "prompt" decision interactively asked
    "Install anyway?" more than once for the SAME package in one run."""
    r = _runner(on_typosquat="prompt")
    with (
        _db_patch(),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=True) as ask,
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0", "reqeusts==1.0.0"]))

    assert out is not False
    ask.assert_called_once()


# --- fail open ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_typosquat_failure_does_not_block():
    r = _runner(on_typosquat="block", on_high_risk="block")
    with (
        _db_patch(),
        _engine_patch(typo=_typo(), typo_raises=RuntimeError("corpus unavailable")),
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out is not False


@pytest.mark.asyncio
async def test_scoring_failure_does_not_block():
    """A risk engine failure must fail open, not block the install."""
    r = _runner(on_typosquat="block", on_high_risk="block")
    with (
        _db_patch(),
        _engine_patch(typo=_typo(), analyze_raises=RuntimeError("deps.dev down")),
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out is not False
    assert out == {}


# --- lock-file / shell path --------------------------------------------------


def _project_scan(name="reqeusts", version="1.0.0", ecosystem="pypi"):
    from packagealert.parsers.lockfiles import LockedPackage, ProjectScan
    return ProjectScan(
        sources=["requirements.txt"],
        pinned=[LockedPackage(name=name, version=version, ecosystem=ecosystem)],
        unpinned=[],
    )


@pytest.mark.asyncio
async def test_lockfile_gate_blocks_when_configured():
    """Per the design spec: the gate decision on the shell path is the
    highest-ranked action across all scored packages. A configured block is a
    block — the shell path gets the same protection as a direct install."""
    r = _runner(on_typosquat="block")
    with (
        _db_patch(),
        patch("packagealert.parsers.lockfiles.scan_project", return_value=_project_scan()),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is False


@pytest.mark.asyncio
async def test_lockfile_gate_highest_ranked_action_wins():
    """A single blocking package governs the whole shell gate, even when other
    packages only warn."""
    from packagealert.parsers.lockfiles import LockedPackage, ProjectScan
    r = _runner(on_typosquat="block", on_high_risk="warn", risk_threshold=25)
    scan = ProjectScan(
        sources=["requirements.txt"],
        pinned=[
            LockedPackage(name="fine", version="1.0.0", ecosystem="pypi"),
            LockedPackage(name="reqeusts", version="1.0.0", ecosystem="pypi"),
        ],
        unpinned=[],
    )
    engine = AsyncMock()
    engine.analyze.return_value = _report(30)  # trips on_high_risk -> warn
    detector = AsyncMock()
    # Only the second package is a typosquat -> block.
    detector.analyze.side_effect = [
        _typo(),
        _typo(True, "requests", 1, 20),
    ]
    with (
        _db_patch(),
        patch("packagealert.parsers.lockfiles.scan_project", return_value=scan),
        patch.object(
            SandboxRunner, "_build_risk_engine",
            return_value=(engine, detector, AsyncMock()),
        ),
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is False


@pytest.mark.asyncio
async def test_lockfile_gate_prompt_declined_blocks():
    r = _runner(on_typosquat="prompt")
    with (
        _db_patch(),
        patch("packagealert.parsers.lockfiles.scan_project", return_value=_project_scan()),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=False),
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is False


@pytest.mark.asyncio
async def test_lockfile_gate_prompt_accepted_allows():
    r = _runner(on_typosquat="prompt")
    with (
        _db_patch(),
        patch("packagealert.parsers.lockfiles.scan_project", return_value=_project_scan()),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=True),
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is True


@pytest.mark.asyncio
async def test_lockfile_gate_prompt_escalates_when_not_tty():
    r = _runner(on_typosquat="prompt", non_interactive_escalation="block")
    with (
        _db_patch(),
        patch("packagealert.parsers.lockfiles.scan_project", return_value=_project_scan()),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=False),
        patch("rich.prompt.Confirm.ask", return_value=True) as ask,
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is False
    ask.assert_not_called()


@pytest.mark.asyncio
async def test_lockfile_gate_established_packages_do_not_block_in_practice():
    """The false positive that once motivated report-only behaviour is fixed at
    the source: adoption-corroborated scoring reduces httpx2 to 3, below
    typosquat_min_score (15), so it resolves to warn and the shell still starts.

    The fixture score is the value the engine actually produces for httpx2's real
    metadata (29k dependents, 14 versions, version suffix) — pinned by
    test_documented_httpx2_calibration_is_exact in test_risk_engine.py. Using a
    hand-picked number here would let this test keep passing under a calibration
    change that had started blocking real installs.
    """
    r = _runner()  # defaults: on_typosquat=prompt, typosquat_min_score=15
    with (
        _db_patch(),
        patch(
            "packagealert.parsers.lockfiles.scan_project",
            return_value=_project_scan("httpx2", "2.9.1"),
        ),
        _engine_patch(typo=_typo(True, "httpx", 1, 3, affix=True), report=_report(3)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=False),
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is True


@pytest.mark.asyncio
async def test_lockfile_gate_reports_findings_to_console():
    r = _runner(on_typosquat="block")
    with (
        _db_patch(),
        patch("packagealert.parsers.lockfiles.scan_project", return_value=_project_scan()),
        _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)),
        patch.object(r._console, "print") as pr,
    ):
        await r._risk_check_lockfiles(Path("/tmp"))
    printed = " ".join(str(c) for c in pr.call_args_list)
    assert "reqeusts" in printed
    assert "requests" in printed


@pytest.mark.asyncio
async def test_lockfile_gate_allows_clean_project():
    r = _runner(on_typosquat="block")
    with (
        _db_patch(),
        patch(
            "packagealert.parsers.lockfiles.scan_project",
            return_value=_project_scan("requests", "2.31.0"),
        ),
        _engine_patch(typo=_typo(), report=_report(0)),
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is True


@pytest.mark.asyncio
async def test_lockfile_gate_allows_when_scan_raises():
    r = _runner(on_typosquat="block")
    with patch("packagealert.parsers.lockfiles.scan_project", side_effect=OSError("boom")):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is True


@pytest.mark.asyncio
async def test_lockfile_gate_allows_when_no_pinned_packages():
    from packagealert.parsers.lockfiles import ProjectScan
    r = _runner(on_typosquat="block")
    empty = ProjectScan(sources=[], pinned=[], unpinned=[])
    with (
        patch("packagealert.parsers.lockfiles.scan_project", return_value=empty),
        patch.object(SandboxRunner, "_build_risk_engine") as build,
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is True
    build.assert_not_called()


@pytest.mark.asyncio
async def test_lockfile_gate_warn_does_not_block():
    r = _runner(on_high_risk="warn", risk_threshold=25)
    with (
        _db_patch(),
        patch("packagealert.parsers.lockfiles.scan_project", return_value=_project_scan()),
        _engine_patch(typo=_typo(), report=_report(40)),
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is True


@pytest.mark.asyncio
async def test_lockfile_gate_disabled_short_circuits():
    r = _runner(enabled=False)
    with patch.object(SandboxRunner, "_build_risk_engine") as build:
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is True
    build.assert_not_called()


# --- post-install scoring ----------------------------------------------------


def _post_report(score, signal_names=("install_script",)):
    from packagealert.models.risk import RiskSignal
    return RiskReport(
        package_name="evil",
        ecosystem="pypi",
        score=score,
        signals=[RiskSignal(name=n, score=score, reason="x") for n in signal_names],
    )


@contextlib.contextmanager
def _post_patches(report, *, resolve_raises=None):
    """Patch _post_scan_risk's collaborators: DB, engine, and language module."""
    engine = AsyncMock()
    engine.analyze.return_value = report
    lang = MagicMock()
    if resolve_raises is not None:
        lang.resolve_package_dir.side_effect = resolve_raises
    else:
        lang.resolve_package_dir.return_value = []
    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine", return_value=(engine, AsyncMock(), AsyncMock())
        ),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
    ):
        yield engine


@pytest.mark.asyncio
async def test_post_scan_blocks_on_high_score_when_configured():
    r = _runner(post_install_threshold=50, on_post_install_risk="block")
    with _post_patches(_post_report(80)):
        ok = await r._post_scan_risk([("pypi", "evil", "1.0.0", Path("/sp"))])
    assert ok is False


@pytest.mark.asyncio
async def test_post_scan_warns_but_allows_by_default():
    r = _runner(post_install_threshold=50, on_post_install_risk="warn")
    with _post_patches(_post_report(80)):
        ok = await r._post_scan_risk([("pypi", "risky", "1.0.0", Path("/sp"))])
    assert ok is True


@pytest.mark.asyncio
async def test_post_scan_ignores_scores_below_threshold():
    r = _runner(post_install_threshold=50, on_post_install_risk="block")
    with _post_patches(_post_report(30)):
        ok = await r._post_scan_risk([("pypi", "fine", "1.0.0", Path("/sp"))])
    assert ok is True


@pytest.mark.asyncio
async def test_post_scan_flags_an_unverifiable_manifest_below_threshold():
    """REGRESSION: unverifiable_manifest typically arrives alone at score 20
    (a corrupt manifest means no directories were resolved, so no other
    source-code heuristic ran) — well below post_install_threshold's default
    of 30. Without an independent trigger this silently kept an install whose
    own manifest could not be verified, despite the comments in
    RiskEngine.analyze classifying it as a probable scan-evasion attempt."""
    r = _runner(post_install_threshold=30, on_post_install_risk="block")
    report = _post_report(20, signal_names=("unverifiable_manifest",))
    with _post_patches(report):
        ok = await r._post_scan_risk([("pypi", "acme", "1.0.0", Path("/sp"))])
    assert ok is False


@pytest.mark.asyncio
async def test_post_scan_still_ignores_a_below_threshold_score_without_the_manifest_signal():
    """The new trigger is specific to unverifiable_manifest — an unrelated
    signal below threshold must still be ignored, exactly as before."""
    r = _runner(post_install_threshold=30, on_post_install_risk="block")
    report = _post_report(20, signal_names=("network_access",))
    with _post_patches(report):
        ok = await r._post_scan_risk([("pypi", "fine", "1.0.0", Path("/sp"))])
    assert ok is True


@pytest.mark.asyncio
async def test_post_scan_threshold_is_inclusive():
    r = _runner(post_install_threshold=50, on_post_install_risk="block")
    with _post_patches(_post_report(50)):
        ok = await r._post_scan_risk([("pypi", "edge", "1.0.0", Path("/sp"))])
    assert ok is False


@pytest.mark.asyncio
async def test_post_scan_risk_scores_packages_concurrently():
    """REGRESSION: _post_scan_risk must score newly installed packages with
    score_packages' bounded concurrency, not one engine.analyze() await per
    package in a sequential loop. A sequential loop can never have more than
    one call in flight at once; scoring several independent packages
    concurrently is exactly the gap between "1 in flight" and "> 1 in
    flight" this test catches — mirroring test_concurrency_is_bounded in
    test_scoring.py and test_risk_check_scores_packages_concurrently above,
    and matching _risk_check/_risk_check_lockfiles, which already score this
    way for the same reason."""
    import asyncio

    live = 0
    peak = 0

    async def analyze(ev, d, w=None):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0)
        live -= 1
        return _post_report(0)

    r = _runner(post_install_threshold=50)
    engine = AsyncMock()
    engine.analyze.side_effect = analyze
    lang = MagicMock()
    lang.resolve_package_dir.return_value = []

    packages = [("pypi", f"pkg{i}", "1.0.0", Path("/sp")) for i in range(5)]
    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine", return_value=(engine, AsyncMock(), AsyncMock())
        ),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
    ):
        ok = await r._post_scan_risk(packages)

    assert peak > 1, "packages were scored one at a time instead of concurrently"
    assert ok is True


@pytest.mark.asyncio
async def test_post_scan_survives_resolve_package_dir_raising():
    """Plugin hooks must never propagate — guarded per project convention."""
    r = _runner(post_install_threshold=50, on_post_install_risk="block")
    with _post_patches(_post_report(0), resolve_raises=RuntimeError("bad plugin")):
        ok = await r._post_scan_risk([("pypi", "x", "1.0.0", Path("/sp"))])
    assert ok is True


@pytest.mark.asyncio
async def test_post_scan_survives_engine_failure():
    r = _runner(post_install_threshold=50, on_post_install_risk="block")
    engine = AsyncMock()
    engine.analyze.side_effect = RuntimeError("engine down")
    lang = MagicMock()
    lang.resolve_package_dir.return_value = []
    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine", return_value=(engine, AsyncMock(), AsyncMock())
        ),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
    ):
        ok = await r._post_scan_risk([("pypi", "x", "1.0.0", Path("/sp"))])
    assert ok is True


@pytest.mark.asyncio
async def test_post_scan_disabled_short_circuits():
    r = _runner(enabled=False)
    with patch.object(SandboxRunner, "_build_risk_engine") as build:
        ok = await r._post_scan_risk([("pypi", "x", "1.0.0", Path("/sp"))])
    assert ok is True
    build.assert_not_called()


@pytest.mark.asyncio
async def test_post_scan_passes_resolved_package_dir_to_engine():
    """Post-install is the only point where source-code signals are possible, so
    the real package_dir must reach the engine."""
    r = _runner(post_install_threshold=50)
    engine = AsyncMock()
    engine.analyze.return_value = _post_report(0)
    lang = MagicMock()
    lang.resolve_package_dir.return_value = [Path("/site-packages/evil")]
    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine", return_value=(engine, AsyncMock(), AsyncMock())
        ),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
    ):
        await r._post_scan_risk([("pypi", "evil", "1.0.0", Path("/sp"))])
    assert engine.analyze.await_args.args[1] == [Path("/site-packages/evil")]


# --- post-install package_dir resolution -------------------------------------
#
# Regression: _resolve_installed_dir originally passed site_packages_dir=None,
# and PythonLanguage.resolve_package_dir returns None immediately in that case.
# Every source-code heuristic (install_script, eval_usage, embedded_binary) was
# therefore unreachable for PyPI packages, silently disabling post-install
# scoring and its rollback path for the whole ecosystem.


def test_resolve_installed_dir_passes_site_packages_for_python(tmp_path):
    """The scan target IS the site-packages dir for Python — it must be forwarded."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    site_packages = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    site_packages.mkdir(parents=True)
    lang = MagicMock()
    lang.resolve_package_dir.return_value = [site_packages / "evil"]

    with patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang):
        _resolve_installed_dir("pypi", "evil", tmp_path, site_packages)

    _name, project_path, sp_dir = lang.resolve_package_dir.call_args.args
    assert sp_dir == site_packages
    # project_path is derived from the scan root, not cwd — see
    # test_resolve_installed_dir_prefers_scan_root_parent_over_cwd.
    assert project_path == site_packages.parent


def _make_site_packages(root: Path) -> Path:
    """Build a minimal but realistic installed-package tree."""
    site_packages = root / "site-packages"
    (site_packages / "evil_pkg").mkdir(parents=True)
    dist_info = site_packages / "evil_pkg-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "top_level.txt").write_text("evil_pkg\n")
    return site_packages


def test_resolve_installed_dir_real_python_resolver_finds_package(tmp_path):
    """End-to-end through the real registry and real PythonLanguage — no patching
    of either, so this exercises the path the runner actually takes."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    site_packages = _make_site_packages(tmp_path)
    resolved, _warning = _resolve_installed_dir("pypi", "evil-pkg", tmp_path, site_packages)
    assert resolved == [site_packages / "evil_pkg"]


def test_resolve_installed_dir_loads_registry_itself(tmp_path):
    """REGRESSION: lang_registry.for_ecosystem() returns None on an unloaded
    registry, which silently disabled every source-code signal. This helper is
    module-level and must not depend on a caller having loaded it."""
    import packagealert.languages.registry as registry_mod
    from packagealert.sandbox.runner import _resolve_installed_dir

    site_packages = _make_site_packages(tmp_path)

    saved_registry = dict(registry_mod._registry)
    saved_loaded = registry_mod._loaded
    try:
        # Force the registry back to its unloaded state.
        registry_mod._registry = {}
        registry_mod._loaded = False

        resolved, _warning = _resolve_installed_dir("pypi", "evil-pkg", tmp_path, site_packages)
        assert resolved == [site_packages / "evil_pkg"]
    finally:
        registry_mod._registry = saved_registry
        registry_mod._loaded = saved_loaded


def test_resolve_installed_dir_real_node_resolver_finds_package(tmp_path):
    """Node needs project_path (node_modules' parent), not site_packages_dir.
    Real registry, real NodeLanguage."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    node_modules = tmp_path / "node_modules"
    (node_modules / "evil-pkg").mkdir(parents=True)

    resolved, _warning = _resolve_installed_dir("npm", "evil-pkg", tmp_path, node_modules)
    assert resolved == [node_modules / "evil-pkg"]


def test_resolve_installed_dir_without_hint_still_works_for_node(tmp_path):
    """A None scan-root hint must not break the ecosystem that only needs cwd."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    (tmp_path / "node_modules" / "evil-pkg").mkdir(parents=True)
    resolved, _warning = _resolve_installed_dir("npm", "evil-pkg", tmp_path, None)
    assert resolved == [tmp_path / "node_modules" / "evil-pkg"]


def test_resolve_installed_dir_prefers_scan_root_parent_over_cwd(tmp_path):
    """REGRESSION: project_path was hardcoded to Path.cwd(), so npm packages under
    a scan target outside the current directory (a venv elsewhere, a monorepo
    subdirectory) resolved to nothing and lost all source-code signals."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    project = tmp_path / "elsewhere"
    node_modules = project / "node_modules"
    (node_modules / "evil-pkg").mkdir(parents=True)

    unrelated_cwd = tmp_path / "some" / "other" / "dir"
    unrelated_cwd.mkdir(parents=True)

    resolved, _warning = _resolve_installed_dir("npm", "evil-pkg", unrelated_cwd, node_modules)
    assert resolved == [node_modules / "evil-pkg"]


def test_resolve_installed_dir_python_unaffected_by_cwd(tmp_path):
    """Python keys off site_packages_dir, so cwd is irrelevant to it."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    site_packages = _make_site_packages(tmp_path)
    resolved, _warning = _resolve_installed_dir(
        "pypi", "evil-pkg", Path("/nonexistent/cwd"), site_packages
    )
    assert resolved == [site_packages / "evil_pkg"]


@pytest.mark.asyncio
async def test_post_scan_risk_forwards_scan_root_to_resolver(tmp_path):
    """_post_scan_risk must thread the per-package scan root through, so source
    heuristics actually run."""
    r = _runner(post_install_threshold=50)
    engine = AsyncMock()
    engine.analyze.return_value = _post_report(0)
    site_packages = tmp_path / "site-packages"
    site_packages.mkdir()
    lang = MagicMock()
    lang.resolve_package_dir.return_value = [site_packages / "evil"]

    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine", return_value=(engine, AsyncMock(), AsyncMock())
        ),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
    ):
        await r._post_scan_risk([("pypi", "evil", "1.0.0", site_packages)])

    assert lang.resolve_package_dir.call_args.args[2] == site_packages
    assert engine.analyze.await_args.args[1] == [site_packages / "evil"]


@pytest.mark.asyncio
async def test_post_scan_risk_scores_each_scan_root_of_a_duplicate_key_independently(tmp_path):
    """REGRESSION: the same (ecosystem, name, version) can appear more than once
    in *packages* with different scan_roots — a monorepo install can place the
    same dependency under more than one node_modules/site-packages tree in a
    single run. score_packages dedupes by (ecosystem, name, version) alone, so
    naively passing it a flat key list would silently collapse two distinct
    installed copies into one scoring call — scoring only whichever scan_root's
    directory the resolver happened to return first, and letting a compromised
    copy under the other scan_root go completely unscanned. Both scan_roots'
    directories must reach the engine as independent candidate groups, so the
    higher-scoring (malicious) copy wins rather than being silently dropped."""
    clean_root = tmp_path / "clean" / "site-packages"
    evil_root = tmp_path / "evil" / "site-packages"
    clean_root.mkdir(parents=True)
    evil_root.mkdir(parents=True)
    clean_dir = clean_root / "dup"
    evil_dir = evil_root / "dup"

    def resolve_package_dir(name, project_path, scan_root, version=None):
        return [evil_dir] if scan_root == evil_root else [clean_dir]

    async def analyze(ev, dirs, warning=None):
        score = 80 if dirs == [evil_dir] else 0
        return _post_report(score)

    r = _runner(post_install_threshold=50, on_post_install_risk="block")
    engine = AsyncMock()
    engine.analyze.side_effect = analyze
    lang = MagicMock()
    lang.resolve_package_dir.side_effect = resolve_package_dir

    packages = [
        ("pypi", "dup", "1.0.0", clean_root),
        ("pypi", "dup", "1.0.0", evil_root),
    ]
    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine", return_value=(engine, AsyncMock(), AsyncMock())
        ),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
    ):
        ok = await r._post_scan_risk(packages)

    assert engine.analyze.await_count == 2, "both scan_roots' directories must be scored"
    assert ok is False, "the higher-scoring copy under the second scan_root must not be hidden"


@pytest.fixture
def nuget_plugin():
    """A plugin whose declared ecosystem spelling is not lowercase — matches
    the fixture of the same name in test_ecosystem_delegation.py."""
    import copy
    from typing import ClassVar

    from packagealert.languages import registry as lang_registry
    from packagealert.languages.base import CURRENT_CONTRACT_VERSION

    class NuGetLang:
        name = "dotnet"
        ecosystems: ClassVar[list[str]] = ["NuGet"]
        process_names: ClassVar[list[str]] = ["dotnet"]
        contract_version = CURRENT_CONTRACT_VERSION
        author = "third-party"
        repository = "example"

        def resolve_package_dir(self, name, project_path, scan_root, version=None):
            return [scan_root / name]

    lang_registry.load()
    saved = copy.copy(lang_registry._registry)
    lang_registry.register(NuGetLang())
    yield
    lang_registry._registry.clear()
    lang_registry._registry.update(saved)


@pytest.mark.asyncio
async def test_post_scan_risk_resolves_a_mixed_case_plugin_ecosystem(nuget_plugin, tmp_path):
    """REGRESSION: roots_by_key was keyed by the raw ecosystem string _try_parse
    produces, which always lowercases (e.g. "nuget" for a plugin declaring
    "NuGet"). score_packages.one() normalises each key's ecosystem before
    calling resolve_dirs/resolve_manifest_warning, so it looked resolve_dirs up
    with "NuGet" against a dict built with "nuget". The mismatch does not
    propagate as a hard failure — score_packages' own resolver wrapper catches
    any exception from the caller-supplied resolver and silently degrades to
    metadata-only scoring — so every source-code signal for a mixed-case
    plugin ecosystem went missing without any error being reported anywhere."""
    r = _runner(post_install_threshold=50, on_post_install_risk="block")
    engine = AsyncMock()

    async def analyze(event, package_dirs, manifest_warning=None):
        score = 80 if package_dirs else 0
        return _post_report(score, signal_names=("install_script",) if package_dirs else ())
    engine.analyze.side_effect = analyze

    scan_root = tmp_path / "packages"
    scan_root.mkdir()

    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine", return_value=(engine, AsyncMock(), AsyncMock())
        ),
    ):
        # Raw ecosystem string as _try_parse would produce it: lowercased.
        ok = await r._post_scan_risk([("nuget", "EvilPkg", "1.0.0", scan_root)])

    assert engine.analyze.await_args.args[1] != [], (
        "the resolved source directory was lost to a casing mismatch"
    )
    assert ok is False, "a high-scoring source-code signal was silently dropped"


def test_collect_new_packages_records_scan_root(tmp_path):
    """The walk root is the site-packages/node_modules dir that detected the
    package; it must be retained rather than discarded."""
    from packagealert.languages.base import PackageSpec
    from packagealert.sandbox.runner import _collect_new_packages

    target = tmp_path / "site-packages"
    target.mkdir()
    (target / "newpkg").mkdir()

    lang = MagicMock()
    lang.detect_new_packages.return_value = [
        PackageSpec(name="newpkg", version="1.0.0", ecosystem="pypi")
    ]
    with patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang):
        result = _collect_new_packages([target], {}, "pypi")

    assert result == [("pypi", "newpkg", "1.0.0", target)]


def test_post_install_threshold_catches_realistic_attack_combinations():
    """The default must gate the cheapest realistic malicious payloads.

    Scores come from the language heuristic tables: npm install_script=20,
    curl_in_script=15; PyPI subprocess_in_setup / network_in_setup /
    credential_in_setup=30 each. A threshold above 35 silently misses a
    postinstall hook that pipes curl into a shell.
    """
    threshold = AppConfig().sandbox.preflight_risk.post_install_threshold
    npm_postinstall_curl = 20 + 15
    pypi_single_setup_signal = 30
    assert threshold <= npm_postinstall_curl
    assert threshold <= pypi_single_setup_signal


@pytest.mark.asyncio
async def test_lockfile_gate_judges_engine_reduced_score_not_raw():
    """REGRESSION: _risk_check_lockfiles passed the detector's raw typosquat score
    to decide_risk, so the engine's adoption reduction never reached the shell
    gate and established packages (httpx2) blocked a developer's shell.

    The detector reports 20 (distance 1); the engine reduces it to 3 for httpx2's
    29k dependents and version suffix (pinned by
    test_documented_httpx2_calibration_is_exact). Only the reduced score is below
    typosquat_min_score (15), so judging the raw score would block.
    """
    from packagealert.models.risk import RiskSignal
    r = _runner(on_typosquat="block")
    reduced = RiskReport(
        package_name="httpx2", ecosystem="pypi", score=3,
        signals=[RiskSignal(name="typosquat", score=3, reason="reduced for adoption")],
    )
    engine = AsyncMock()
    engine.analyze.return_value = reduced
    detector = AsyncMock()
    detector.analyze.return_value = _typo(True, "httpx", 1, 20, affix=True)  # raw score
    with (
        _db_patch(),
        patch(
            "packagealert.parsers.lockfiles.scan_project",
            return_value=_project_scan("httpx2", "2.9.1"),
        ),
        patch.object(
            SandboxRunner, "_build_risk_engine",
            return_value=(engine, detector, AsyncMock()),
        ),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=False),
    ):
        ok = await r._risk_check_lockfiles(Path("/tmp"))
    assert ok is True, "engine-reduced score must govern, not the detector's raw score"


# --- lock file containment ---------------------------------------------------
#
# scan_project() follows symlinks unconditionally via read_text(), so every
# caller must first confirm the project's lock files resolve inside the project.
# _risk_check_lockfiles ran before _preflight_shell's containment check, so an
# untrusted repo could point requirements.txt at a file outside the project and
# have its package names read AND sent to deps.dev before the run was rejected.


@pytest.mark.asyncio
async def test_lockfile_gate_refuses_external_symlinked_lockfile(tmp_path):
    """REGRESSION: the risk pass must not read a lock file that resolves outside
    the project, nor leak its contents to deps.dev."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "requirements.txt"
    secret.write_text("internal-private-package==1.0.0\n")

    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").symlink_to(secret)

    r = _runner()
    with (
        _db_patch(),
        patch.object(SandboxRunner, "_build_risk_engine") as build,
        patch("packagealert.parsers.lockfiles.scan_project") as scan,
    ):
        ok = await r._risk_check_lockfiles(project)

    assert ok is False, "must refuse rather than scan an external lock file"
    scan.assert_not_called(), "the lock file must never be read"
    build.assert_not_called(), "no engine, so nothing reaches deps.dev"


@pytest.mark.asyncio
async def test_lockfile_gate_honours_allow_external_lockfiles(tmp_path):
    """The documented override must still work on this path."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "requirements.txt").write_text("somepkg==1.0.0\n")
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").symlink_to(outside / "requirements.txt")

    r = _runner()
    with (
        _db_patch(),
        patch(
            "packagealert.parsers.lockfiles.scan_project",
            return_value=_project_scan("somepkg", "1.0.0"),
        ) as scan,
        _engine_patch(typo=_typo(), report=_report(0)),
    ):
        ok = await r._risk_check_lockfiles(project, allow_external_lockfiles=True)

    assert ok is True
    scan.assert_called_once()


@pytest.mark.asyncio
async def test_lockfile_gate_allows_contained_lockfile(tmp_path):
    """A normal in-project lock file is unaffected."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n")

    r = _runner()
    with (
        _db_patch(),
        patch(
            "packagealert.parsers.lockfiles.scan_project",
            return_value=_project_scan("requests", "2.31.0"),
        ) as scan,
        _engine_patch(typo=_typo(), report=_report(0)),
    ):
        ok = await r._risk_check_lockfiles(project)

    assert ok is True
    scan.assert_called_once()


# --- shared resources between the risk and cooldown gates --------------------
#
# The design spec requires one DB connection, one TopPackagesCache and one
# RiskEngine "constructed once in run() and passed in". Each gate previously built
# its own, so a single install opened two DB connections and ran the O(corpus)
# typosquat scan twice per package.


@pytest.mark.asyncio
async def test_gates_share_one_db_connection():
    """One _open_gate_resources() call must serve both gates."""
    r = _runner()
    lang = MagicMock()
    lang.publication_date_url.return_value = None  # cooldown skips its DB reads
    with (
        patch("packagealert.sandbox.runner.open_db", new_callable=AsyncMock) as open_db,
        _engine_patch(typo=_typo(), report=_report(0)),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
    ):
        ctx = _ctx(["requests==2.31.0"])
        gates = await r._open_gate_resources()
        try:
            await r._risk_check(ctx, res=gates)
            await r._cooldown_check(ctx, res=gates)
        finally:
            await r._close_gate_resources(gates)
    assert open_db.await_count == 1, "both gates must share a single DB connection"


def test_run_wires_shared_resources_into_both_gates():
    """run() must construct gate resources once and pass them to both gates.

    Asserted against the source so the wiring cannot silently regress to each
    gate opening its own DB — which is what the spec forbids and what the
    duplication tests above would then no longer be exercising in production.
    """
    import inspect

    src = inspect.getsource(SandboxRunner.run)
    assert "_open_gate_resources()" in src
    assert "res=gate_res" in src.split("self._risk_check(")[1][:120]
    assert "res=gate_res" in src.split("_cooldown_check")[1][:120]
    assert "_close_gate_resources(gate_res)" in src


@pytest.mark.asyncio
async def test_typosquat_corpus_scanned_once_per_package_across_both_gates():
    """The corpus scan is the expensive part of the gate; it must not repeat.

    Counts the *underlying* scan (TyposquatDetector._analyze_uncached), not the
    memoised entry point, so this measures real work rather than call count.
    """
    import inspect

    import packagealert.heuristics.typosquat as ts

    r = _runner()
    lang = MagicMock()
    lang.publication_date_url.return_value = None  # cooldown skips its DB reads

    scans: list[str] = []
    orig = ts.TyposquatDetector._analyze_uncached

    # Signature is (self, normalized, candidates) and it is *synchronous*: analyze()
    # normalises the name and resolves the corpus, then hands both down so the scan is
    # a pure function of (name, corpus) — which is what makes memoising it safe.
    #
    # Deliberately not async: an async wrapper around a sync target returns a
    # never-awaited coroutine, and this test then silently counted zero scans while
    # still "passing" the assertion it exists to make.
    assert not inspect.iscoroutinefunction(orig), (
        "_analyze_uncached is now async — this wrapper must be updated to match"
    )

    def counting(self, *args, **kwargs):
        normalized = kwargs.get("normalized", args[0] if args else None)
        scans.append(normalized)
        return orig(self, *args, **kwargs)

    with (
        _db_patch(),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
        patch.object(ts.TyposquatDetector, "_analyze_uncached", counting),
    ):
        gates = await r._open_gate_resources()
        ctx = _ctx(["requests==2.31.0"])
        try:
            await r._risk_check(ctx, res=gates)
            await r._cooldown_check(ctx, res=gates)
        finally:
            await r._close_gate_resources(gates)

    assert scans == ["requests"], f"corpus scanned {len(scans)}x for one package: {scans}"


@pytest.mark.asyncio
async def test_gates_still_work_standalone_without_shared_resources():
    """Each gate must remain independently callable for testing and reuse."""
    r = _runner(on_typosquat="block")
    with _db_patch(), _engine_patch(typo=_typo(True, "requests", 1, 20), report=_report(20)):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out is False


@pytest.mark.asyncio
async def test_close_gate_resources_closes_db_and_client():
    r = _runner()
    with _db_patch(), _engine_patch(typo=_typo(), report=_report(0)):
        gates = await r._open_gate_resources()
        await r._close_gate_resources(gates)
    gates.db.close.assert_awaited_once()
    gates.pop_client.aclose.assert_awaited_once()


# --- lazy gate-resource construction -----------------------------------------
#
# REGRESSION: run() called _open_gate_resources() unconditionally before either
# gate could short-circuit, so a disabled gate or a command with no explicit
# packages (pip install -r ...) still opened a DB connection and an httpx client.
# Per the spec, construction must be skipped entirely when disabled: it is wasted
# work at best, and an installation that risk scoring does not even apply to must
# not be able to fail during resource initialisation.


def test_run_guards_gate_resource_construction():
    """run() must consult _gate_resources_needed before constructing resources."""
    import inspect

    src = inspect.getsource(SandboxRunner.run)
    assert "_gate_resources_needed(" in src, "predicate not consulted in run()"
    # The construction must be reachable only through the predicate, i.e. the
    # predicate appears no later than the open call it guards.
    assert src.index("_gate_resources_needed(") < src.index(
        "_close_gate_resources"
    ), "predicate must gate the construction, not follow it"


@pytest.mark.parametrize(
    ("preflight_enabled", "heuristics_enabled", "packages", "expected"),
    [
        (True, True, ["requests==2.31.0"], True),    # normal: both gates run
        (False, True, ["requests==2.31.0"], True),    # cooldown still runs
        (True, False, ["requests==2.31.0"], True),    # cooldown still runs
        (False, False, ["requests==2.31.0"], True),   # cooldown has no enable flag
        (True, True, [], False),                      # no packages: neither gate runs
        (False, False, [], False),
    ],
)
def test_gate_resources_needed(preflight_enabled, heuristics_enabled, packages, expected):
    cfg = AppConfig()
    cfg.sandbox.preflight_risk.enabled = preflight_enabled
    cfg.heuristics.enabled = heuristics_enabled
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)
    assert r._gate_resources_needed(_ctx(packages)) is expected


def test_gate_resources_not_needed_when_parsed_is_none():
    """A passthrough command has no ParsedInstall at all."""
    r = _runner()
    ctx = _Context(argv=["pip", "--version"], parsed=None, cwd=Path("/tmp"))
    assert r._gate_resources_needed(ctx) is False


@pytest.mark.asyncio
async def test_no_packages_opens_no_resources():
    """No explicit packages, no req_files, and no lock file on disk (cwd is a
    plain tmp dir with nothing in it): _resolve_query_packages's lock-file
    scan legitimately finds nothing, so the gates still short-circuit and
    nothing should be constructed — distinct from the case where a lock
    file DOES exist (see test_no_explicit_packages_still_scores_a_lockfile
    below), which must now open resources and score."""
    r = _runner()
    with (
        patch("packagealert.sandbox.runner.open_db", new_callable=AsyncMock) as open_db,
        patch.object(SandboxRunner, "_build_risk_engine") as build,
    ):
        ctx = _ctx([])
        assert r._gate_resources_needed(ctx) is False
        out = await r._risk_check(ctx)
        cool = await r._cooldown_check(ctx)
    assert out == {}
    assert cool == []
    open_db.assert_not_awaited()
    build.assert_not_called()


# ---------------------------------------------------------------------------
# REGRESSION: the risk/cooldown gates only iterated ctx.parsed.packages, so
# `pip install -r requirements.txt` and a bare `npm install` (packages=[])
# both skipped typosquat/high-risk scoring entirely, despite the OSV
# pre-flight check (_preflight) already expanding req_files and lock-file
# installs into the same query set. _resolve_query_packages now backs all
# three (_risk_check, _cooldown_check, _gate_resources_needed) with the same
# expansion _preflight already uses.
# ---------------------------------------------------------------------------


def test_no_explicit_packages_still_scores_a_lockfile(tmp_path):
    """A bare `npm install`-shaped ctx (packages=[], req_files=[],
    is_lockfile_install=True — matching what parse_npm_args actually
    produces for `npm install`/`ci`) with a real lock file on disk must be
    treated as having packages to gate — the exact surface
    `_gate_resources_needed` previously skipped."""
    from packagealert.parsers.process_args import ParsedInstall

    (tmp_path / "package-lock.json").write_text(
        '{"name": "proj", "lockfileVersion": 3, "packages": {'
        '"": {"name": "proj"}, '
        '"node_modules/lodash": {"version": "4.17.21"}'
        "}}"
    )
    parsed = ParsedInstall(manager="npm", packages=[], ecosystem="npm", is_lockfile_install=True)
    ctx = _Context(argv=["npm", "install"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    assert r._gate_resources_needed(ctx) is True


def test_uninstall_shaped_ctx_does_not_scan_the_lockfile(tmp_path):
    """REGRESSION (2nd pass): `npm uninstall lodash` produces the identical
    empty packages=[], req_files=[] shape as a bare `npm install` — but
    parse_npm_args correctly leaves is_lockfile_install=False for it. Without
    consulting that field, the gate would scan the *pre-removal* lock file
    (still containing lodash and everything else) and could block the
    uninstall itself over a risk signal on the very dependency being removed."""
    from packagealert.parsers.process_args import ParsedInstall

    (tmp_path / "package-lock.json").write_text(
        '{"name": "proj", "lockfileVersion": 3, "packages": {'
        '"": {"name": "proj"}, '
        '"node_modules/lodash": {"version": "4.17.21"}'
        "}}"
    )
    parsed = ParsedInstall(manager="npm", packages=[], ecosystem="npm")  # is_lockfile_install=False (default)
    ctx = _Context(argv=["npm", "uninstall", "lodash"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    assert r._gate_resources_needed(ctx) is False


def test_uv_remove_resolves_no_query_packages(tmp_path):
    """REGRESSION: unlike npm/yarn/pnpm, parse_uv_args used to put the removed
    package names directly into `packages` for `uv remove` (packages is
    non-empty), so _resolve_query_packages's `if parsed.packages:` branch
    unconditionally queried them as if they were being installed —
    is_lockfile_install=False alone did not help, since that only guards the
    empty-packages branch. `uv remove requests` must resolve to an empty
    query set, not one containing "requests". Goes through the real parser
    (not a hand-built ParsedInstall) so a regression in parse_uv_args itself
    is caught here too."""
    from packagealert.parsers.process_args import parse_uv_args

    parsed = parse_uv_args(["uv", "remove", "requests"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "remove", "requests"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_uv_lock_resolves_no_query_packages(tmp_path):
    """REGRESSION: `uv lock` only regenerates uv.lock from pyproject.toml (a
    fresh resolution) — it installs nothing and doesn't even read the
    existing lock file as its surface. It was grouped with `sync`
    (is_lockfile_install=True), so the gates would scan the current,
    about-to-be-replaced uv.lock as if it were the install surface. With a
    stale uv.lock on disk naming a package, `uv lock` must still resolve to
    no query packages."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
    )
    parsed = parse_uv_args(["uv", "lock"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "lock"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_pipenv_lock_resolves_no_query_packages(tmp_path):
    """REGRESSION: `pipenv lock` only regenerates Pipfile.lock from Pipfile —
    it installs nothing into the environment. It was grouped with
    `update`/`upgrade` (is_lockfile_install=True), so the gates would scan
    the current, about-to-be-replaced Pipfile.lock as if it were the install
    surface. With a stale Pipfile.lock on disk naming a package, `pipenv
    lock` must still resolve to no query packages."""
    from packagealert.parsers.process_args import parse_pipenv_args

    (tmp_path / "Pipfile.lock").write_text(
        '{"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}'
    )
    parsed = parse_pipenv_args(["pipenv", "lock"])
    assert parsed is not None
    ctx = _Context(argv=["pipenv", "lock"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_pipenv_upgrade_resolves_no_query_packages(tmp_path):
    """REGRESSION: unlike `update`, `pipenv upgrade` (pipenv's own
    routines.update.upgrade()) only re-resolves the named/modified packages
    and rewrites Pipfile.lock — cmd_upgrade calls upgrade() directly and
    never do_sync, so nothing is installed. It was grouped with `update`
    (is_lockfile_install=True), so the gates would scan the current,
    about-to-be-rewritten Pipfile.lock as if `upgrade` were installing its
    contents."""
    from packagealert.parsers.process_args import parse_pipenv_args

    (tmp_path / "Pipfile.lock").write_text(
        '{"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}'
    )
    parsed = parse_pipenv_args(["pipenv", "upgrade"])
    assert parsed is not None
    ctx = _Context(argv=["pipenv", "upgrade"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_pnpm_import_resolves_no_query_packages(tmp_path):
    """REGRESSION: `pnpm import` only generates pnpm-lock.yaml from a
    *different* manager's lockfile (package-lock.json/yarn.lock) — it never
    touches node_modules. It was grouped with `dedupe`/`fetch`
    (is_lockfile_install=True), so the gates would scan pnpm's own
    (unrelated) lock file as if `import` were installing its contents. With
    a pnpm-lock.yaml on disk naming a package, `pnpm import` must still
    resolve to no query packages."""
    from packagealert.parsers.process_args import parse_pnpm_args

    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '6.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n"
    )
    parsed = parse_pnpm_args(["pnpm", "import"])
    assert parsed is not None
    ctx = _Context(argv=["pnpm", "import"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_npm_install_dry_run_resolves_no_query_packages(tmp_path):
    """REGRESSION: `--dry-run` reports what install would do without
    installing anything (npm's own docs), but was ignored entirely — a
    package-less `npm install --dry-run` was indistinguishable from a real
    bare install and would scan the current package-lock.json as the
    install surface."""
    from packagealert.parsers.process_args import parse_npm_args

    (tmp_path / "package-lock.json").write_text(
        '{"name": "proj", "lockfileVersion": 3, "packages": {'
        '"": {"name": "proj"}, '
        '"node_modules/lodash": {"version": "4.17.21"}'
        "}}"
    )
    parsed = parse_npm_args(["npm", "install", "--dry-run"])
    assert parsed is not None
    ctx = _Context(argv=["npm", "install", "--dry-run"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_npm_install_explicit_package_dry_run_resolves_no_query_packages(tmp_path):
    """REGRESSION (P2 follow-up): the earlier dry-run fix only suppressed the
    empty-packages lock-file scan (is_lockfile_install=False), so `npm
    install lodash --dry-run` — the exact reported scenario — still had a
    non-empty `packages=["lodash"]`, which _resolve_query_packages's
    `if parsed.packages:` branch queried unconditionally, even though the
    command installs nothing. should_gate must short-circuit before that
    branch runs at all."""
    from packagealert.parsers.process_args import parse_npm_args

    parsed = parse_npm_args(["npm", "install", "lodash", "--dry-run"])
    assert parsed is not None
    assert parsed.packages == ["lodash"]
    ctx = _Context(argv=["npm", "install", "lodash", "--dry-run"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_uv_sync_check_resolves_no_query_packages(tmp_path):
    """REGRESSION (P2 follow-up): `uv sync --check` only reports whether the
    environment is synchronized with the project (uv's own docs) — it was
    still classified as a lockfile install with nothing suppressing the
    gate."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
    )
    parsed = parse_uv_args(["uv", "sync", "--check"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "sync", "--check"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_uv_pip_sync_resolves_the_requirements_file(tmp_path):
    """REGRESSION (P1): `uv pip sync requirements.txt` installs exactly the
    packages listed in that file (uv's own docs). It used to fall through to
    the runner/execute/read-only catch-all (matched on subcmd=="pip" alone,
    without checking the sub-subcommand) and return an empty ParsedInstall
    with no req_files at all — risk, cooldown, and OSV pre-flight all
    received zero queries for a real install. `uv pip sync` must resolve the
    named requirements file into the query set like a real install would."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    parsed = parse_uv_args(["uv", "pip", "sync", "requirements.txt"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "requirements.txt"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "requests", "2.31.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_pylock_toml_resolves_the_real_packages(tmp_path):
    """REGRESSION (P1): `uv pip sync pylock.toml` installs the packages
    listed in that PEP 751 lockfile (uv's own docs explicitly support both
    requirements.txt and pylock.toml as sync sources). Before the fix,
    _resolve_query_packages sent every uv pip sync source through
    collect_requirements_packages regardless of format, which read the TOML
    file line-by-line and matched syntax like `name = "requests"` against
    the requirements.txt regexes — producing bogus queries for packages
    literally named "name"/"version" while never querying the real,
    possibly-malicious dependency actually being installed."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n'
        'created-by = "uv"\n\n'
        '[[packages]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "pylock.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "requests", "2.31.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_pip_install_requirements_toml_is_not_misrouted_to_pylock_parser(tmp_path):
    """REGRESSION (P1 follow-up): the pylock dispatch was keyed on any
    `.toml` suffix rather than PEP 751's exact filename convention.
    `-r`/`--requirement` places no restriction on a requirements file's
    name, so `pip install -r requirements.toml` (a real requirements file
    that merely happens to be named with a .toml extension) was misrouted
    to the pylock TOML parser — which found no [[packages]] table and
    returned zero packages, silently bypassing risk/cooldown/OSV checks for
    a valid install."""
    from packagealert.parsers.process_args import parse_pip_args

    (tmp_path / "requirements.toml").write_text("requests==2.31.0\n")
    parsed = parse_pip_args(["pip", "install", "-r", "requirements.toml"])
    assert parsed is not None
    ctx = _Context(argv=["pip", "install", "-r", "requirements.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "requests", "2.31.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_pylock_excludes_unsatisfied_marker_packages(tmp_path):
    """REGRESSION (P1): PEP 751 requires installers to skip [[packages]]
    entries whose `marker` is unsatisfied. A universal pylock.toml (the
    common case for `uv pip compile --universal`) routinely contains
    mutually exclusive platform variants — verified against a real `uv pip
    compile --universal --format pylock.toml` run, which marks a
    Windows-only dependency with `marker = "sys_platform == 'win32'"`.
    Without evaluating markers, a vulnerable Windows-only package could
    incorrectly block `uv pip sync` on this (non-Windows-only) environment
    even though uv itself would never install it here. The unsatisfied
    entry (a nonexistent platform, portable across CI runners) must not
    appear in the resolved query set; the satisfied one must."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n\n'
        '[[packages]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n\n'
        '[[packages]]\n'
        'name = "windows-only-vulnerable-pkg"\n'
        'version = "9.9.9"\n'
        'marker = "sys_platform == \'nonexistent-platform-xyz\'"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "pylock.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "requests", "2.31.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_pylock_excludes_unselected_extra_packages(tmp_path):
    """REGRESSION (P2): a marker referencing PEP 751's `extras`/
    `dependency_groups` variables (e.g. `'dev' in extras`) must be
    evaluated with context="lock_file", where those variables default to
    the empty set per PEP 751's own install algorithm — matching a real
    `uv pip sync pylock.toml` with no --extra/--group flag, which installs
    none of those optional packages. Evaluating with the default context
    instead raised UndefinedEnvironmentName and the fail-open handler
    incorrectly retained the unselected-extra package, letting a risky
    dependency the sync will never actually install still gate the run."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n\n'
        '[[packages]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n\n'
        '[[packages]]\n'
        'name = "dev-only-vulnerable-pkg"\n'
        'version = "9.9.9"\n'
        'marker = "\'dev\' in extras"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "pylock.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "requests", "2.31.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_pylock_includes_default_group_package(tmp_path):
    """REGRESSION (P1): PEP 751's install algorithm requires
    "dependency_groups SHOULD be the set created from default-groups by
    default" — the top-level default-groups key represents what a *bare*
    sync (no --group flag at all) installs implicitly. Without seeding
    dependency_groups from it, a package marked `marker = "'runtime' in
    dependency_groups"` was omitted from every gate even though a bare `uv
    pip sync pylock.toml` genuinely installs it — contradicting the
    documented claim that a bare sync is fully scanned."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n'
        'default-groups = ["runtime"]\n\n'
        '[[packages]]\n'
        'name = "runtime-group-vulnerable-pkg"\n'
        'version = "9.9.9"\n'
        'marker = "\'runtime\' in dependency_groups"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "pylock.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "runtime-group-vulnerable-pkg", "9.9.9")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_pylock_undefined_comparison_marker_does_not_crash(tmp_path):
    """REGRESSION (P2): `python_version ~= 'dog'` parses successfully but
    raises UndefinedComparison on evaluation (packaging.markers.Marker's
    own documented behavior for an operator applied to an incomparable
    value) — only UndefinedEnvironmentName was caught, so this scenario
    propagated uncaught through _resolve_query_packages and aborted the
    whole pre-flight resolution instead of failing open on the one
    malformed marker and still gating the rest of the pylock normally."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n\n'
        '[[packages]]\n'
        'name = "bad-comparison-pkg"\n'
        'version = "1.0.0"\n'
        'marker = "python_version ~= \'dog\'"\n\n'
        '[[packages]]\n'
        'name = "requests"\n'
        'version = "2.31.0"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "pylock.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    # Must not raise — this call crashing is the exact reported failure mode.
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    names_versions = set(queries)
    assert ("pypi", "bad-comparison-pkg", "1.0.0") in names_versions
    assert ("pypi", "requests", "2.31.0") in names_versions
    assert blocked_reason is None


def test_uv_pip_sync_pylock_marker_evaluated_against_project_venv_not_own_interpreter(tmp_path, monkeypatch):
    """REGRESSION (P1): a bare `uv pip sync`/`uv pip install` (no
    --python/--python-version flag) does not target package-alert's own
    running interpreter — it targets VIRTUAL_ENV/CONDA_PREFIX or a
    discovered project .venv (verified empirically via `uv pip sync -v`).
    A package marked `python_version == '3.12'` must be evaluated against
    that *project's* venv version, not package-alert's own — simulated
    here via VIRTUAL_ENV pointing at a .venv whose pyvenv.cfg pins 3.12,
    with a control package gated on an arbitrary version guaranteed not to
    match (3.99) to prove the override actually takes effect rather than
    everything happening to pass regardless."""
    from packagealert.parsers.process_args import parse_uv_args

    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "pyvenv.cfg").write_text("version_info = 3.12\n")
    monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n\n'
        '[[packages]]\n'
        'name = "runs-on-3.12-pkg"\n'
        'version = "1.0.0"\n'
        'marker = "python_version == \'3.12\'"\n\n'
        '[[packages]]\n'
        'name = "runs-on-3.99-pkg"\n'
        'version = "2.0.0"\n'
        'marker = "python_version == \'3.99\'"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "pylock.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "runs-on-3.12-pkg", "1.0.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_pylock_active_conda_env_takes_precedence_over_project_venv(tmp_path, monkeypatch):
    """REGRESSION (P1): the exact reported scenario — an active conda
    environment (Python 3.11) alongside a project .venv pinning a
    different version (3.12). uv gives CONDA_PREFIX precedence over a
    discovered .venv (uv's own docs), and a real conda environment has no
    pyvenv.cfg at all (verified against a `micromamba create` environment)
    — its version instead lives in conda-meta/python-*.json. The discovery
    function used to call the venv-only pyvenv.cfg reader for CONDA_PREFIX
    too, so it silently found nothing there and fell through to the
    project .venv's 3.12, evaluating markers against the wrong Python
    version entirely despite uv actually installing for the active 3.11
    conda environment."""
    import json

    from packagealert.parsers.process_args import parse_uv_args

    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    conda_env = tmp_path / "conda_env"
    meta_dir = conda_env / "conda-meta"
    meta_dir.mkdir(parents=True)
    (meta_dir / "python-3.11.15-h8ab3286_2_cpython.json").write_text(
        json.dumps({"name": "python", "version": "3.11.15"})
    )
    monkeypatch.setenv("CONDA_PREFIX", str(conda_env))
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "pyvenv.cfg").write_text("version_info = 3.12\n")

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n\n'
        '[[packages]]\n'
        'name = "runs-on-3.11-conda-pkg"\n'
        'version = "1.0.0"\n'
        'marker = "python_version == \'3.11\'"\n\n'
        '[[packages]]\n'
        'name = "runs-on-3.12-venv-pkg"\n'
        'version = "2.0.0"\n'
        'marker = "python_version == \'3.12\'"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "pylock.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "runs-on-3.11-conda-pkg", "1.0.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_pylock_unreadable_conda_prefix_retains_version_marked_package(tmp_path, monkeypatch):
    """REGRESSION (P1): `_discover_target_python_version` could not
    distinguish "no target environment exists" from "the selected
    VIRTUAL_ENV/CONDA_PREFIX exists but its version metadata is unreadable"
    — both returned None, so a python_version/python_full_version marker
    was evaluated against package-alert's own running interpreter instead
    of failing open. A CONDA_PREFIX pointing at a directory with no
    conda-meta at all (corrupted/unusually-packaged environment) must not
    silently exclude a package uv might genuinely install for whatever
    that environment's real (unknown-to-us) Python version turns out to
    be — it must be retained, matching the fail-open policy already used
    for other unresolvable markers."""
    from packagealert.parsers.process_args import parse_uv_args

    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    broken_conda_env = tmp_path / "broken_conda_env"
    broken_conda_env.mkdir()  # no conda-meta directory at all
    monkeypatch.setenv("CONDA_PREFIX", str(broken_conda_env))

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n\n'
        '[[packages]]\n'
        'name = "unknown-target-version-pkg"\n'
        'version = "1.0.0"\n'
        'marker = "python_version == \'3.12\'"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "pip", "sync", "pylock.toml"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "unknown-target-version-pkg", "1.0.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_system_flag_retains_package_marked_for_a_different_version_than_active_venv(
    tmp_path, monkeypatch,
):
    """REGRESSION (P1): the exact reported scenario — an active Python 3.12
    venv (VIRTUAL_ENV set) alongside `uv pip sync --system pylock.toml`
    targeting the system Python (3.11 in the report's example). `--system`
    (or UV_SYSTEM_PYTHON) switches uv's own interpreter discovery to a
    PATH-walk/managed-installation search that explicitly ignores an
    active VIRTUAL_ENV (verified empirically via `uv pip sync -v`'s DEBUG
    output) — this was not among the previously-fixed --python-platform-
    style CLI-override gaps, since it's a same-platform target-selection
    case: parse_uv_args discarded --system entirely, and
    _discover_target_python_version kept prioritizing VIRTUAL_ENV, so a
    package marked for the system's real (unknown-to-us) version was
    evaluated against the active venv's 3.12 and silently excluded even
    though uv genuinely installs it into the system interpreter."""
    from packagealert.parsers.process_args import parse_uv_args

    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "pyvenv.cfg").write_text("version_info = 3.12\n")
    monkeypatch.setenv("VIRTUAL_ENV", str(venv_dir))

    (tmp_path / "pylock.toml").write_text(
        'lock-version = "1.0"\n\n'
        '[[packages]]\n'
        'name = "runs-on-system-3.11-pkg"\n'
        'version = "1.0.0"\n'
        'marker = "python_version == \'3.11\'"\n'
    )
    parsed = parse_uv_args(["uv", "pip", "sync", "pylock.toml", "--system"])
    assert parsed is not None
    assert parsed.is_system_python_target is True
    ctx = _Context(
        argv=["uv", "pip", "sync", "pylock.toml", "--system"], parsed=parsed, cwd=tmp_path
    )

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "runs-on-system-3.11-pkg", "1.0.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_no_index_still_resolves_the_requirements_file(tmp_path):
    """REGRESSION (P1): `--no-index` is a boolean flag with no value of its
    own (uv's own docs) — it was wrongly listed among value-consuming flags,
    so `uv pip sync --no-index requirements.txt` (the exact reported
    scenario) treated "requirements.txt" as --no-index's argument and
    skipped it, producing req_files=[] and bypassing risk/cooldown/OSV
    checks entirely despite this being a valid sync from a real
    requirements file."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    parsed = parse_uv_args(["uv", "pip", "sync", "--no-index", "requirements.txt"])
    assert parsed is not None
    assert parsed.req_files == ["requirements.txt"]
    ctx = _Context(
        argv=["uv", "pip", "sync", "--no-index", "requirements.txt"], parsed=parsed, cwd=tmp_path
    )

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == [("pypi", "requests", "2.31.0")]
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is True


def test_uv_pip_sync_dry_run_resolves_no_query_packages(tmp_path):
    """`uv pip sync requirements.txt --dry-run` resolves dependencies and
    prints the plan without actually installing anything (uv's own docs) —
    should_gate must suppress the query even though the requirements file
    is present and would otherwise be resolved."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    parsed = parse_uv_args(["uv", "pip", "sync", "requirements.txt", "--dry-run"])
    assert parsed is not None
    ctx = _Context(
        argv=["uv", "pip", "sync", "requirements.txt", "--dry-run"], parsed=parsed, cwd=tmp_path
    )

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_uv_sync_dry_run_resolves_no_query_packages(tmp_path):
    """REGRESSION (P2): `uv sync --dry-run` performs a dry run "without
    writing the lockfile or modifying the project environment" (uv's own
    docs) — only `--check` was recognised as report-only, so `--dry-run`
    was still classified as gating a real install and would scan the
    current uv.lock as the install surface."""
    from packagealert.parsers.process_args import parse_uv_args

    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
    )
    parsed = parse_uv_args(["uv", "sync", "--dry-run"])
    assert parsed is not None
    ctx = _Context(argv=["uv", "sync", "--dry-run"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_pip_install_dry_run_resolves_no_query_packages(tmp_path):
    """REGRESSION (P2 follow-up): `--dry-run` resolves dependencies and
    reports what would happen without actually installing anything (pip's
    own docs) — it was ignored entirely, so `pip install requests --dry-run`
    still had its explicit package queried unconditionally."""
    from packagealert.parsers.process_args import parse_pip_args

    parsed = parse_pip_args(["pip", "install", "requests", "--dry-run"])
    assert parsed is not None
    assert parsed.packages == ["requests"]
    ctx = _Context(argv=["pip", "install", "requests", "--dry-run"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_uv_pip_install_dry_run_resolves_no_query_packages(tmp_path):
    """REGRESSION (P2 follow-up): `uv pip install --dry-run` resolves
    dependencies and prints the plan without installing anything (uv's own
    docs)."""
    from packagealert.parsers.process_args import parse_uv_args

    parsed = parse_uv_args(["uv", "pip", "install", "requests", "--dry-run"])
    assert parsed is not None
    assert parsed.packages == ["requests"]
    ctx = _Context(argv=["uv", "pip", "install", "requests", "--dry-run"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_composer_require_dry_run_resolves_no_query_packages(tmp_path):
    """REGRESSION (P2 follow-up): `--dry-run` outputs the operations but
    executes nothing (Composer's own docs)."""
    from packagealert.parsers.process_args import parse_composer_args

    parsed = parse_composer_args(["composer", "require", "vendor/pkg", "--dry-run"])
    assert parsed is not None
    assert parsed.packages == ["vendor/pkg"]
    ctx = _Context(argv=["composer", "require", "vendor/pkg", "--dry-run"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_composer_install_dry_run_resolves_no_query_packages(tmp_path):
    """REGRESSION (P2 follow-up): `composer install --dry-run` outputs the
    operations but installs nothing — was still classified as a lockfile
    install with nothing suppressing the gate."""
    from packagealert.parsers.process_args import parse_composer_args

    (tmp_path / "composer.lock").write_text(
        '{"packages": [{"name": "vendor/pkg", "version": "1.0.0"}]}'
    )
    parsed = parse_composer_args(["composer", "install", "--dry-run"])
    assert parsed is not None
    ctx = _Context(argv=["composer", "install", "--dry-run"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_pnpm_dedupe_check_resolves_no_query_packages(tmp_path):
    """REGRESSION: `--check` reports whether dedupe would make changes
    "without installing packages or editing the lockfile" (pnpm's own
    docs), but was ignored entirely — `pnpm dedupe --check` was
    indistinguishable from a real dedupe and would scan the current
    pnpm-lock.yaml as the install surface."""
    from packagealert.parsers.process_args import parse_pnpm_args

    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '6.0'\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n"
    )
    parsed = parse_pnpm_args(["pnpm", "dedupe", "--check"])
    assert parsed is not None
    ctx = _Context(argv=["pnpm", "dedupe", "--check"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


def test_pipenv_update_dry_run_resolves_no_query_packages(tmp_path):
    """REGRESSION: `--dry-run` sets outdated=True in pipenv's own
    do_update(), routing entirely to do_outdated() — never locks or syncs.
    It was ignored entirely, so `pipenv update --dry-run` was
    indistinguishable from a real update and would scan the current
    Pipfile.lock as the install surface."""
    from packagealert.parsers.process_args import parse_pipenv_args

    (tmp_path / "Pipfile.lock").write_text(
        '{"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}'
    )
    parsed = parse_pipenv_args(["pipenv", "update", "--dry-run"])
    assert parsed is not None
    ctx = _Context(argv=["pipenv", "update", "--dry-run"], parsed=parsed, cwd=tmp_path)

    r = _runner()
    queries, blocked_reason, _source = r._resolve_query_packages(ctx)
    assert queries == []
    assert blocked_reason is None
    assert r._gate_resources_needed(ctx) is False


@pytest.mark.asyncio
async def test_requirements_file_install_is_scored_by_the_risk_gate(tmp_path):
    """REGRESSION: pip install -r requirements.txt must reach _risk_check's
    typosquat/high-risk scoring, not skip it via the packages=[] guard."""
    from packagealert.parsers.process_args import ParsedInstall

    (tmp_path / "requirements.txt").write_text("reqeusts==1.0.0\n")  # typo of "requests"
    parsed = ParsedInstall(
        manager="pip", packages=[], ecosystem="pypi", req_files=["requirements.txt"]
    )
    ctx = _Context(
        argv=["pip", "install", "-r", "requirements.txt"], parsed=parsed, cwd=tmp_path
    )

    r = _runner(on_typosquat="block")
    with _engine_patch(typo=_typo(True, "requests", 1, 20)):
        result = await r._risk_check(ctx)

    assert result is False  # blocked: a strong typosquat match with on_typosquat="block"


@pytest.mark.asyncio
async def test_requirements_file_install_is_scored_by_the_cooldown_gate(tmp_path):
    """The same requirements.txt surface must also reach the cooldown gate's
    per-package loop, not just the risk gate — verified by observing the
    loop actually call out for this specific package, not merely that the
    (unhelpful on its own) empty-list result is unchanged."""
    from packagealert.parsers.process_args import ParsedInstall

    (tmp_path / "requirements.txt").write_text("somepkg==1.0.0\n")
    parsed = ParsedInstall(
        manager="pip", packages=[], ecosystem="pypi", req_files=["requirements.txt"]
    )
    ctx = _Context(
        argv=["pip", "install", "-r", "requirements.txt"], parsed=parsed, cwd=tmp_path
    )

    r = _runner()
    with (
        _db_patch(),
        patch(
            "packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=None
        ) as for_ecosystem,
    ):
        await r._cooldown_check(ctx)

    # Old bug: the loop never started (ctx.parsed.packages == []), so
    # for_ecosystem was never called at all for "pypi".
    for_ecosystem.assert_any_call("pypi")


@pytest.mark.asyncio
async def test_disabled_risk_gate_opens_no_resources_standalone():
    """Called standalone with the gate disabled, _risk_check must not construct."""
    r = _runner(enabled=False)
    with (
        patch("packagealert.sandbox.runner.open_db", new_callable=AsyncMock) as open_db,
        patch.object(SandboxRunner, "_build_risk_engine") as build,
    ):
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]))
    assert out == {}
    open_db.assert_not_awaited()
    build.assert_not_called()


@pytest.mark.asyncio
async def test_cooldown_still_enforces_when_risk_scoring_disabled():
    """Cooldown is an age policy and must still run when preflight_risk is off.

    A bare TyposquatDetector is now built for cooldown's fallback even with
    preflight_risk.enabled=False (see test_cooldown_typosquat_score_not_zeroed_when_
    preflight_disabled for that classification-level regression). This test predates
    that and covers the older, separate regression: an earlier `continue` on a None
    typosquat result silently skipped every package regardless of age.
    """
    import time as _time

    cfg = AppConfig()
    cfg.sandbox.preflight_risk.enabled = False
    cfg.sandbox.cooldown.on_new_low_risk = "block"
    cfg.sandbox.cooldown.non_interactive_escalation = "block"
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)

    lang = MagicMock()
    lang.publication_date_url.return_value = "https://pypi.org/pypi/brandnew/1.0.0/json"
    fresh = _time.time()  # published just now -> inside the cooldown window

    with (
        _db_patch(),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
        patch(
            "packagealert.sandbox.runner.get_publication_date",
            new_callable=AsyncMock, return_value=fresh,
        ),
        patch(
            "packagealert.sandbox.runner.get_cooldown_cleared_at",
            new_callable=AsyncMock, return_value=None,
        ),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=False),
    ):
        out = await r._cooldown_check(_ctx(["brandnew==1.0.0"]))

    assert out is False, "cooldown must still block a brand-new package"


@pytest.mark.asyncio
async def test_cooldown_prompt_skipped_once_another_package_already_blocked():
    """REGRESSION: mirrors test_prompt_skipped_once_another_package_already_blocked
    for _cooldown_check. Once "blocked" already forces the whole check to
    return False, a later package's "prompt" decision cannot change that
    outcome and must not fire Confirm.ask."""
    import time as _time

    cfg = AppConfig()
    cfg.sandbox.cooldown.on_new_low_risk = "block"
    cfg.sandbox.cooldown.on_new_medium_risk = "prompt"
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)

    lang = MagicMock()
    lang.publication_date_url.side_effect = (
        lambda name, version: f"https://pypi.org/pypi/{name}/{version}/json"
    )
    fresh = _time.time()  # published just now -> inside the cooldown window

    async def fake_get_publication_date(db, *, ecosystem, package, version):
        return fresh

    with (
        _db_patch(),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
        patch(
            "packagealert.sandbox.runner.get_publication_date",
            side_effect=fake_get_publication_date,
        ),
        patch(
            "packagealert.sandbox.runner.get_cooldown_cleared_at",
            new_callable=AsyncMock, return_value=None,
        ),
        _engine_patch(typo=_typo()),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=True) as ask,
    ):
        # "lowrisk" has no risk score -> on_new_low_risk="block".
        # "medrisk" is pre-scored (via risk_scores) -> on_new_medium_risk="prompt".
        out = await r._cooldown_check(
            _ctx(["lowrisk==1.0.0", "medrisk==1.0.0"]),
            risk_scores={("pypi", "lowrisk"): 0, ("pypi", "medrisk"): 10},
        )

    assert out is False
    ask.assert_not_called()


@pytest.mark.asyncio
async def test_disabled_risk_scoring_builds_no_engine_or_http_client():
    """Cooldown needs only the DB and a bare detector, not the engine or httpx client.

    REGRESSION: detector was also None here, which forced cooldown's risk_score
    fallback to 0 for every package and could silently downgrade its classification
    (on_new_medium_risk -> on_new_low_risk) — weakening a gate the user never touched
    just by disabling the unrelated pre-flight gate.
    """
    cfg = AppConfig()
    cfg.sandbox.preflight_risk.enabled = False
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)
    with (
        _db_patch(),
        patch.object(SandboxRunner, "_build_risk_engine") as build,
    ):
        res = await r._open_gate_resources()
        await r._close_gate_resources(res)
    build.assert_not_called()
    assert res.engine is None
    assert res.detector is not None
    assert res.pop_client is None


# --- post-install action coverage --------------------------------------------
#
# REGRESSION: on_post_install_risk accepts the full CooldownAction literal, but
# enforcement only distinguished "block" from everything else, so a configured
# "prompt" never asked and never escalated in non-interactive contexts. The
# packages are already extracted at this point and False triggers a real
# snapshot rollback, so keep-or-roll-back is a genuine choice worth prompting on.


@pytest.mark.asyncio
async def test_post_scan_prompt_declined_rolls_back():
    r = _runner(post_install_threshold=50, on_post_install_risk="prompt")
    with (
        _post_patches(_post_report(80)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=False),
    ):
        ok = await r._post_scan_risk([("pypi", "evil", "1.0.0", Path("/sp"))])
    assert ok is False


@pytest.mark.asyncio
async def test_post_scan_prompt_accepted_keeps_install():
    r = _runner(post_install_threshold=50, on_post_install_risk="prompt")
    with (
        _post_patches(_post_report(80)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=True),
    ):
        ok = await r._post_scan_risk([("pypi", "evil", "1.0.0", Path("/sp"))])
    assert ok is True


@pytest.mark.asyncio
async def test_post_scan_prompt_escalates_when_not_tty():
    """CI and coding agents cannot answer, so prompt must escalate — otherwise a
    malicious package is silently kept."""
    cfg = AppConfig()
    cfg.sandbox.preflight_risk.post_install_threshold = 50
    cfg.sandbox.preflight_risk.on_post_install_risk = "prompt"
    cfg.sandbox.preflight_risk.non_interactive_escalation = "block"
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)
    with (
        _post_patches(_post_report(80)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=False),
        patch("rich.prompt.Confirm.ask", return_value=True) as ask,
    ):
        ok = await r._post_scan_risk([("pypi", "evil", "1.0.0", Path("/sp"))])
    assert ok is False
    ask.assert_not_called()


@pytest.mark.asyncio
async def test_post_scan_prompt_escalation_target_is_configurable():
    cfg = AppConfig()
    cfg.sandbox.preflight_risk.post_install_threshold = 50
    cfg.sandbox.preflight_risk.on_post_install_risk = "prompt"
    cfg.sandbox.preflight_risk.non_interactive_escalation = "warn"
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)
    with (
        _post_patches(_post_report(80)),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=False),
    ):
        ok = await r._post_scan_risk([("pypi", "evil", "1.0.0", Path("/sp"))])
    assert ok is True


@pytest.mark.asyncio
async def test_post_scan_allow_reports_nothing_and_keeps_install():
    """"allow" must be a genuine no-op, not a warning."""
    r = _runner(post_install_threshold=50, on_post_install_risk="allow")
    with _post_patches(_post_report(80)), patch.object(r._console, "print") as pr:
        ok = await r._post_scan_risk([("pypi", "evil", "1.0.0", Path("/sp"))])
    assert ok is True
    printed = " ".join(str(c) for c in pr.call_args_list)
    assert "risk threshold" not in printed


@pytest.mark.asyncio
async def test_post_scan_warn_reports_and_keeps_install():
    r = _runner(post_install_threshold=50, on_post_install_risk="warn")
    with _post_patches(_post_report(80)), patch.object(r._console, "print") as pr:
        ok = await r._post_scan_risk([("pypi", "evil", "1.0.0", Path("/sp"))])
    assert ok is True
    printed = " ".join(str(c) for c in pr.call_args_list)
    assert "risk threshold" in printed


def test_resolve_installed_dir_takes_project_path_explicitly(tmp_path):
    """project_path must be passed, not inferred from scan_root.parent.

    The inference was wrong for PyPI: a venv scan target is
    <venv>/lib/pythonX.Y/site-packages, whose parent is lib/pythonX.Y — not the
    project root. It only ever worked because PythonLanguage.resolve_package_dir
    ignores project_path. Node, whose scan target IS node_modules, happened to get
    a correct parent. Making the caller state both removes the coincidence.
    """
    from packagealert.sandbox.runner import _resolve_installed_dir

    site_packages = _make_site_packages(tmp_path / "venv" / "lib" / "python3.12")
    lang = MagicMock()
    lang.resolve_package_dir.return_value = []

    with patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang):
        _resolve_installed_dir(
            "pypi", "evil-pkg", tmp_path, site_packages, project_path=tmp_path
        )

    _name, project_path, sp_dir = lang.resolve_package_dir.call_args.args
    assert sp_dir == site_packages
    assert project_path == tmp_path, "explicit project_path must win over inference"


def test_resolve_installed_dir_node_uses_explicit_project_path(tmp_path):
    """Real NodeLanguage, project root given explicitly rather than inferred."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    node_modules = tmp_path / "node_modules"
    (node_modules / "evil-pkg").mkdir(parents=True)

    resolved, _warning = _resolve_installed_dir(
        "npm", "evil-pkg", Path("/nonexistent"), node_modules, project_path=tmp_path
    )
    assert resolved == [node_modules / "evil-pkg"]


def test_resolve_installed_dir_infers_project_path_when_omitted(tmp_path):
    """Backwards compatible: omitting project_path keeps the previous inference,
    which is correct for the runner's node_modules scan targets."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    node_modules = tmp_path / "node_modules"
    (node_modules / "evil-pkg").mkdir(parents=True)

    resolved, _warning = _resolve_installed_dir("npm", "evil-pkg", Path("/nonexistent"), node_modules)
    assert resolved == [node_modules / "evil-pkg"]


# --- risk construction must fail open ----------------------------------------
#
# REGRESSION: _open_gate_resources() opened the DB and then called
# _build_risk_engine() unguarded, and run() awaited it *before* its try block. A
# failure constructing the plugin ecosystem map, the httpx PopularityClient, or
# RiskEngine therefore (a) propagated out of run() and aborted the install, and
# (b) leaked the already-open DB connection. Risk scoring is additive: it must
# degrade to cooldown-only, never abort an install.


@pytest.mark.asyncio
async def test_engine_construction_failure_degrades_to_cooldown_only():
    r = _runner()
    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine",
            side_effect=RuntimeError("engine init exploded"),
        ),
    ):
        res = await r._open_gate_resources()
    # The DB is still available, so the cooldown gate can run.
    assert res.db is not None
    # ...but risk scoring is unavailable rather than fatal.
    assert res.engine is None
    # A bare detector is still attempted so cooldown's risk_score fallback survives
    # even when the full engine failed to construct.
    assert res.detector is not None
    assert res.pop_client is None


@pytest.mark.asyncio
async def test_engine_construction_failure_does_not_leak_the_db():
    """The DB opened before the failure must still be closable exactly once."""
    r = _runner()
    with (
        _db_patch() as open_db,
        patch.object(
            SandboxRunner, "_build_risk_engine",
            side_effect=RuntimeError("engine init exploded"),
        ),
    ):
        res = await r._open_gate_resources()
        await r._close_gate_resources(res)
    assert open_db.await_count == 1
    res.db.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_build_risk_engine_closes_its_client_when_engine_raises():
    """_build_risk_engine creates the httpx client before the engine, so it must
    release that client itself rather than leaking a socket on failure."""
    client = AsyncMock()
    r = _runner()
    with (
        patch("packagealert.osv.popularity.PopularityClient", return_value=client),
        patch(
            "packagealert.analyzers.risk.RiskEngine",
            side_effect=RuntimeError("engine init exploded"),
        ),
        pytest.raises(RuntimeError),
    ):
        await r._build_risk_engine(MagicMock())
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_real_engine_failure_degrades_and_leaks_nothing():
    """End-to-end through the real _build_risk_engine: a RiskEngine failure
    degrades to cooldown-only, closes the httpx client, and closes the DB."""
    client = AsyncMock()
    r = _runner()
    with (
        _db_patch(),
        patch("packagealert.osv.popularity.PopularityClient", return_value=client),
        patch(
            "packagealert.analyzers.risk.RiskEngine",
            side_effect=RuntimeError("engine init exploded"),
        ),
    ):
        res = await r._open_gate_resources()
        await r._close_gate_resources(res)
    assert res.engine is None
    assert res.db is not None
    client.aclose.assert_awaited_once()
    res.db.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_risk_check_with_failed_construction_allows_install():
    """A construction failure must not block: no scores, no verdict."""
    r = _runner(on_typosquat="block")
    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine",
            side_effect=RuntimeError("engine init exploded"),
        ),
    ):
        res = await r._open_gate_resources()
        try:
            out = await r._risk_check(_ctx(["reqeusts==1.0.0"]), res=res)
        finally:
            await r._close_gate_resources(res)
    assert out is not False, "construction failure must fail open"
    assert out == {}


@pytest.mark.asyncio
async def test_cooldown_still_enforces_after_construction_failure():
    """The whole point of degrading rather than aborting: cooldown still runs."""
    import time as _time

    cfg = AppConfig()
    cfg.sandbox.cooldown.on_new_low_risk = "block"
    cfg.sandbox.cooldown.non_interactive_escalation = "block"
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)

    lang = MagicMock()
    lang.publication_date_url.return_value = "https://pypi.org/pypi/brandnew/1.0.0/json"

    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine",
            side_effect=RuntimeError("engine init exploded"),
        ),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
        patch(
            "packagealert.sandbox.runner.get_publication_date",
            new_callable=AsyncMock, return_value=_time.time(),
        ),
        patch(
            "packagealert.sandbox.runner.get_cooldown_cleared_at",
            new_callable=AsyncMock, return_value=None,
        ),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=False),
    ):
        res = await r._open_gate_resources()
        try:
            out = await r._cooldown_check(_ctx(["brandnew==1.0.0"]), res=res)
        finally:
            await r._close_gate_resources(res)
    assert out is False, "cooldown must still block a brand-new package"


@pytest.mark.asyncio
async def test_post_scan_risk_survives_construction_failure():
    """Post-install: a construction failure must not trigger a rollback."""
    r = _runner(post_install_threshold=30, on_post_install_risk="block")
    with (
        _db_patch(),
        patch.object(
            SandboxRunner, "_build_risk_engine",
            side_effect=RuntimeError("engine init exploded"),
        ),
    ):
        ok = await r._post_scan_risk([("pypi", "x", "1.0.0", Path("/sp"))])
    assert ok is True, "a scoring-setup failure must not roll back a good install"


@pytest.mark.asyncio
async def test_db_open_failure_degrades_both_gates_rather_than_aborting():
    """open_db can fail (read-only FS, SQLite lock timeout). Neither gate is
    load-bearing for the install, so a DB failure must skip them, not abort."""
    from packagealert.sandbox.runner import GATE_RESOURCES_UNAVAILABLE

    r = _runner()
    with patch(
        "packagealert.sandbox.runner.open_db",
        new_callable=AsyncMock,
        side_effect=OSError("read-only file system"),
    ):
        res = await r._open_gate_resources()
    # The sentinel, not None: None would make the gates retry the failing open.
    assert res is GATE_RESOURCES_UNAVAILABLE


@pytest.mark.asyncio
async def test_gates_tolerate_none_resources():
    """With no resources both gates must no-op rather than crash."""
    r = _runner(on_typosquat="block")
    with patch(
        "packagealert.sandbox.runner.open_db",
        new_callable=AsyncMock,
        side_effect=OSError("read-only file system"),
    ):
        res = await r._open_gate_resources()
        out = await r._risk_check(_ctx(["reqeusts==1.0.0"]), res=res)
        cool = await r._cooldown_check(_ctx(["reqeusts==1.0.0"]), res=res)
        await r._close_gate_resources(res)
    assert out == {}
    assert cool == []


@pytest.mark.asyncio
async def test_post_scan_risk_survives_db_failure():
    r = _runner(post_install_threshold=30, on_post_install_risk="block")
    with patch(
        "packagealert.sandbox.runner.open_db",
        new_callable=AsyncMock,
        side_effect=OSError("read-only file system"),
    ):
        ok = await r._post_scan_risk([("pypi", "x", "1.0.0", Path("/sp"))])
    assert ok is True, "a DB failure must not roll back a good install"


# --- unavailable vs omitted resources ----------------------------------------
#
# REGRESSION: _open_gate_resources() returned None for "the DB could not be
# opened", but the gates' `res=None` default means "not supplied — open your own".
# run() passed the first into the second, so a locked DB was retried by each gate:
# three connection attempts, each able to burn SQLite's 10s lock timeout, for a
# subsystem that is purely advisory. GATE_RESOURCES_UNAVAILABLE distinguishes them.


@pytest.mark.asyncio
async def test_locked_db_is_attempted_once_per_run():
    """The whole point: one failed open must not become three."""
    r = _runner()
    attempts = 0

    async def failing(*a, **kw):
        nonlocal attempts
        attempts += 1
        raise OSError("database is locked")

    with patch("packagealert.sandbox.runner.open_db", side_effect=failing):
        ctx = _ctx(["requests==2.31.0"])
        res = await r._open_gate_resources()
        await r._risk_check(ctx, res=res)
        await r._cooldown_check(ctx, res=res)
        await r._close_gate_resources(res)

    assert attempts == 1, f"DB opened {attempts}x for one run"


@pytest.mark.asyncio
async def test_unavailable_sentinel_is_distinct_from_none():
    from packagealert.sandbox.runner import GATE_RESOURCES_UNAVAILABLE

    assert GATE_RESOURCES_UNAVAILABLE is not None


@pytest.mark.asyncio
async def test_open_gate_resources_returns_the_sentinel_on_db_failure():
    r = _runner()
    from packagealert.sandbox.runner import GATE_RESOURCES_UNAVAILABLE

    with patch(
        "packagealert.sandbox.runner.open_db",
        new_callable=AsyncMock,
        side_effect=OSError("read-only file system"),
    ):
        res = await r._open_gate_resources()
    assert res is GATE_RESOURCES_UNAVAILABLE


@pytest.mark.asyncio
async def test_gates_still_open_their_own_when_res_is_omitted():
    """Omitting res must keep working — the gates remain independently callable."""
    r = _runner()
    with _db_patch() as open_db, _engine_patch(typo=_typo(), report=_report(0)):
        out = await r._risk_check(_ctx(["requests==2.31.0"]))
    assert out == {("pypi", "requests"): 0}
    assert open_db.await_count == 1


@pytest.mark.asyncio
async def test_gates_skip_without_retrying_when_given_the_sentinel():
    from packagealert.sandbox.runner import GATE_RESOURCES_UNAVAILABLE

    r = _runner(on_typosquat="block")
    with patch("packagealert.sandbox.runner.open_db", new_callable=AsyncMock) as open_db:
        ctx = _ctx(["reqeusts==1.0.0"])
        out = await r._risk_check(ctx, res=GATE_RESOURCES_UNAVAILABLE)
        cool = await r._cooldown_check(ctx, res=GATE_RESOURCES_UNAVAILABLE)
    assert out == {}
    assert cool == []
    open_db.assert_not_awaited(), "the sentinel means skip, not retry"


@pytest.mark.asyncio
async def test_close_tolerates_the_sentinel():
    from packagealert.sandbox.runner import GATE_RESOURCES_UNAVAILABLE

    r = _runner()
    # Must not raise: there is nothing to release.
    await r._close_gate_resources(GATE_RESOURCES_UNAVAILABLE)


# --- keyword-only / **kwargs plugin hooks ------------------------------------
#
# REGRESSION: _accepts_version returned True for a keyword-only `version` (and for
# **kwargs), but the call passed it as a 4th POSITIONAL argument. The resulting
# TypeError was swallowed by the broad except, so a perfectly valid v5 plugin
# silently lost every source-code heuristic.


class _KwOnlyPlugin:
    name = "kwonly"
    ecosystems = ("crates",)

    def resolve_package_dir(
        self, package_name, project_path, site_packages_dir, *, version=None
    ):
        # Record what we were handed so the test can assert it arrived.
        self.seen_version = version
        return Path("/resolved") / package_name


class _KwargsPlugin:
    name = "kwargs"
    ecosystems = ("crates",)

    def resolve_package_dir(self, package_name, project_path, site_packages_dir, **kwargs):
        self.seen_version = kwargs.get("version")
        return Path("/resolved") / package_name


class _PositionalPlugin:
    name = "positional"
    ecosystems = ("crates",)

    def resolve_package_dir(self, package_name, project_path, site_packages_dir, version=None):
        self.seen_version = version
        return Path("/resolved") / package_name


class _LegacyPlugin:
    name = "legacy"
    ecosystems = ("crates",)

    def resolve_package_dir(self, package_name, project_path, site_packages_dir):
        return Path("/resolved") / package_name


class _VarArgsPlugin:
    name = "varargs"
    ecosystems = ("crates",)

    def resolve_package_dir(self, *args):
        self.seen_args = args
        return Path("/resolved") / args[0]


@pytest.mark.parametrize(
    "plugin_cls", [_KwOnlyPlugin, _KwargsPlugin, _PositionalPlugin, _VarArgsPlugin]
)
def test_version_reaches_every_hook_signature_style(plugin_cls):
    from packagealert.sandbox.runner import _resolve_installed_dir

    plugin = plugin_cls()
    with patch(
        "packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=plugin
    ):
        got, _warning = _resolve_installed_dir("crates", "serde", Path("/x"), version="1.0.0")

    assert got == Path("/resolved/serde"), f"{plugin_cls.__name__} resolution failed"
    if plugin_cls is _VarArgsPlugin:
        # *args cannot take a keyword, so it must still be passed positionally.
        assert plugin.seen_args[-1] == "1.0.0"
    else:
        assert plugin.seen_version == "1.0.0", f"{plugin_cls.__name__} got no version"


def test_legacy_three_arg_hook_still_resolves():
    """A pre-v5 plugin must keep working, without the version."""
    from packagealert.sandbox.runner import _resolve_installed_dir

    with patch(
        "packagealert.sandbox.runner.lang_registry.for_ecosystem",
        return_value=_LegacyPlugin(),
    ):
        got, _warning = _resolve_installed_dir("crates", "serde", Path("/x"), version="1.0.0")
    assert got == Path("/resolved/serde")


@pytest.mark.parametrize(
    ("plugin_cls", "expected"),
    [
        (_KwOnlyPlugin, "keyword"),
        (_KwargsPlugin, "keyword"),
        (_PositionalPlugin, "keyword"),
        (_VarArgsPlugin, "positional"),
        (_LegacyPlugin, "none"),
    ],
)
def test_version_passing_style_is_classified_correctly(plugin_cls, expected):
    from packagealert.sandbox.runner import _version_passing_style

    assert _version_passing_style(plugin_cls().resolve_package_dir) == expected


@pytest.mark.asyncio
async def test_cooldown_typosquat_score_not_zeroed_when_preflight_disabled():
    """REGRESSION: disabling the pre-flight gate silently downgraded cooldown.

    _open_gate_resources gated `detector=None` on `preflight_risk.enabled`, not on
    cooldown's own settings. With no detector, `_typo_for` always returned None,
    forcing cooldown's risk_score fallback to 0 — so on_new_medium_risk ("prompt")
    silently downgraded to on_new_low_risk ("warn") for a real, freshly-published
    typosquat, purely because the user disabled an unrelated gate.
    """
    import time as _time

    cfg = AppConfig()
    cfg.sandbox.preflight_risk.enabled = False
    cfg.sandbox.cooldown.on_new_medium_risk = "prompt"
    cfg.sandbox.cooldown.on_new_low_risk = "warn"
    cfg.sandbox.cooldown.non_interactive_escalation = "block"
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)

    lang = MagicMock()
    lang.publication_date_url.return_value = "https://pypi.org/pypi/reqeusts/1.0.0/json"
    fresh = _time.time()  # inside the cooldown window

    with (
        _db_patch(),
        patch("packagealert.sandbox.runner.lang_registry.for_ecosystem", return_value=lang),
        # Real corpus resolution would call lang.top_packages_url() over httpx; the
        # detector is under test here, not the network fetch, so give it the corpus
        # directly.
        patch(
            "packagealert.heuristics.top_packages.TopPackagesCache.resolve",
            new_callable=AsyncMock,
            return_value=["requests", "flask", "django"],
        ),
        patch(
            "packagealert.sandbox.runner.get_publication_date",
            new_callable=AsyncMock, return_value=fresh,
        ),
        patch(
            "packagealert.sandbox.runner.get_cooldown_cleared_at",
            new_callable=AsyncMock, return_value=None,
        ),
        patch("packagealert.sandbox.runner.sys.stdin.isatty", return_value=True),
        patch("rich.prompt.Confirm.ask", return_value=True) as ask,
    ):
        out = await r._cooldown_check(_ctx(["reqeusts==1.0.0"]))

    # A real typosquat (reqeusts -> requests) must still trigger on_new_medium_risk
    # ("prompt"), not fall through to on_new_low_risk ("warn"), just because
    # preflight_risk is off.
    ask.assert_called_once()
    assert out != []  # the prompt path returns cleared packages, not the [] warn path


@pytest.mark.asyncio
async def test_open_gate_resources_does_not_build_httpx_client_when_preflight_disabled():
    """The detector fix must not reintroduce the engine/httpx client it was meant
    to avoid building when the pre-flight gate is off."""
    cfg = AppConfig()
    cfg.sandbox.preflight_risk.enabled = False
    with patch("packagealert.sandbox.runner.build_backend"):
        r = SandboxRunner(cfg)
    with (
        _db_patch(),
        patch("packagealert.osv.popularity.PopularityClient") as pop_client_cls,
    ):
        res = await r._open_gate_resources()
        await r._close_gate_resources(res)
    pop_client_cls.assert_not_called()
    assert res.pop_client is None
    assert res.engine is None
    assert res.detector is not None
