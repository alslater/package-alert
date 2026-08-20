"""scan-project risk scoring: rendering, opt-out, and failure isolation."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from packagealert.cli.app import app
from packagealert.models.risk import RiskReport, RiskSignal
from packagealert.parsers.lockfiles import LockedPackage, ProjectScan

runner = CliRunner()


def _scan():
    return ProjectScan(
        sources=["requirements.txt"],
        pinned=[LockedPackage(name="reqeusts", version="1.0.0", ecosystem="pypi")],
        unpinned=[],
    )


def _report(score, signals):
    return RiskReport(
        package_name="reqeusts",
        ecosystem="pypi",
        score=score,
        signals=[RiskSignal(name=n, score=s, reason=r) for n, s, r in signals],
    )


def _outcome(report, failures=0):
    out = MagicMock()
    out.reports = {("pypi", "reqeusts", "1.0.0"): report} if report else {}
    out.failures = failures
    return out


@pytest.fixture
def env(monkeypatch):
    """Patch scan-project's collaborators: lockfile scan, OSV, and popularity."""
    osv_client = AsyncMock()
    osv_client.batch_query.return_value = []
    osv_cache = AsyncMock()
    osv_cache.get.return_value = None

    stack = [
        patch("packagealert.parsers.lockfiles.scan_project", return_value=_scan()),
        patch("packagealert.cli.app.plugin_registry.fire_on_scan_complete", new_callable=AsyncMock),
        patch("packagealert.osv.client.OsvClient", return_value=osv_client),
        patch("packagealert.osv.cache.OsvCache", return_value=osv_cache),
        patch("packagealert.osv.popularity.PopularityClient", return_value=AsyncMock()),
        patch("packagealert.analyzers.risk.RiskEngine", return_value=AsyncMock()),
    ]
    for p in stack:
        p.start()
    yield
    for p in stack:
        p.stop()


def _run(tmp_path, *args, report=None, failures=0):
    with patch(
        "packagealert.scoring.score_packages",
        new_callable=AsyncMock,
        return_value=_outcome(report, failures),
    ):
        return runner.invoke(app, ["scan-project", str(tmp_path), *args])


# --- rendering ---------------------------------------------------------------


def test_risk_section_rendered_in_text_output(tmp_path, env):
    report = _report(
        35,
        [("typosquat", 20, "possible typosquat of 'requests'"),
         ("low_popularity", 15, "few versions")],
    )
    res = _run(tmp_path, report=report)
    assert res.exit_code == 0
    assert "Risk signals" in res.output
    assert "reqeusts" in res.output
    assert "35" in res.output


def test_footer_reports_at_risk_count(tmp_path, env):
    report = _report(35, [("typosquat", 20, "typo")])
    res = _run(tmp_path, report=report)
    assert "1 at risk" in res.output


def test_json_output_has_risks_key(tmp_path, env):
    report = _report(35, [("typosquat", 20, "typo")])
    res = _run(tmp_path, "--format", "json", report=report)
    payload = json.loads(res.output)
    assert payload["risks"][0]["package"] == "reqeusts"
    assert payload["risks"][0]["score"] == 35
    # 35 is above the pre-flight risk_threshold (25), so it must not read as
    # "info" — see test_level_reflects_preflight_thresholds_not_daemon_ones.
    assert payload["risks"][0]["level"] == "warning"
    assert payload["risks"][0]["signals"][0]["name"] == "typosquat"


def test_findings_stay_advisory_shaped(tmp_path, env):
    """risks is a sibling list so finding_count keeps its meaning for plugins."""
    report = _report(35, [("typosquat", 20, "typo")])
    res = _run(tmp_path, "--format", "json", report=report)
    payload = json.loads(res.output)
    assert "findings" in payload
    for f in payload["findings"]:
        assert "advisory_id" in f
        assert "score" not in f


def test_html_output_includes_risk_table(tmp_path, env):
    report = _report(35, [("typosquat", 20, "typo")])
    res = _run(tmp_path, "--format", "html", report=report)
    assert "Risk signals" in res.output
    assert "reqeusts" in res.output
    assert "<th>Score</th>" in res.output


def test_html_omits_risk_table_when_no_risks(tmp_path, env):
    res = _run(tmp_path, "--format", "html", report=_report(0, []))
    assert "Risk signals" not in res.output


# --- opt-out -----------------------------------------------------------------


def test_no_risk_flag_skips_scoring(tmp_path, env):
    report = _report(35, [("typosquat", 20, "typo")])
    with patch(
        "packagealert.scoring.score_packages", new_callable=AsyncMock
    ) as sp:
        sp.return_value = _outcome(report)
        res = runner.invoke(app, ["scan-project", str(tmp_path), "--no-risk"])
    assert res.exit_code == 0
    sp.assert_not_awaited()
    assert "Risk signals" not in res.output


def test_no_risk_json_has_empty_risks(tmp_path, env):
    res = runner.invoke(app, ["scan-project", str(tmp_path), "--no-risk", "--format", "json"])
    payload = json.loads(res.output)
    assert payload["risks"] == []


# --- noise suppression -------------------------------------------------------


def test_low_signal_rows_suppressed_by_default(tmp_path, env):
    """A lone score-5 low_popularity is noise on a large lock file."""
    report = _report(5, [("low_popularity", 5, "few versions")])
    res = _run(tmp_path, report=report)
    assert res.exit_code == 0
    assert "low_popularity" not in res.output
    assert "low-signal row(s) hidden" in res.output


def test_low_signal_rows_shown_with_details(tmp_path, env):
    """--details unhides the suppressed row. Asserted on the package line and
    reason rather than the signal name: a single-signal row's breakdown is elided
    because it would repeat the summary verbatim."""
    report = _report(5, [("low_popularity", 5, "few versions")])
    res = _run(tmp_path, "--details", report=report)
    assert "reqeusts" in res.output
    assert "few versions" in res.output
    assert "low-signal row(s) hidden" not in res.output


def test_low_signal_row_still_counted_in_footer(tmp_path, env):
    """Suppression is display-only; the row is still real."""
    report = _report(5, [("low_popularity", 5, "few versions")])
    res = _run(tmp_path, report=report)
    assert "1 at risk" in res.output


def test_multi_signal_row_not_suppressed(tmp_path, env):
    """Only lone minimal low_popularity rows are noise; a row with a real signal
    alongside it stays visible. Asserted on the package line rather than the
    signal name, since the breakdown itself needs --details."""
    report = _report(25, [("low_popularity", 5, "few"), ("typosquat", 20, "typo")])
    res = _run(tmp_path, report=report)
    assert "reqeusts" in res.output
    assert "low-signal row(s) hidden" not in res.output


# --- failure isolation -------------------------------------------------------


def test_scoring_failure_does_not_fail_the_scan(tmp_path, env):
    res = _run(tmp_path, report=None, failures=3)
    assert res.exit_code == 0
    assert "Risk scoring unavailable for 3 package(s)" in res.output


def test_risk_pass_exception_does_not_fail_the_scan(tmp_path, env):
    """Even an unexpected error in the pass leaves the scan usable."""
    with patch(
        "packagealert.scoring.score_packages",
        new_callable=AsyncMock,
        side_effect=RuntimeError("engine exploded"),
    ):
        res = runner.invoke(app, ["scan-project", str(tmp_path)])
    assert res.exit_code == 0
    assert "Scan complete" in res.output


def test_zero_score_packages_are_not_listed(tmp_path, env):
    res = _run(tmp_path, report=_report(0, []))
    assert res.exit_code == 0
    assert "Risk signals" not in res.output
    assert "0 at risk" in res.output


# --- level calibration -------------------------------------------------------
#
# RiskReport.level uses 40/70, calibrated for the daemon's full-signal scoring.
# scan-project scores metadata-only (typosquat + low_popularity, ~40 ceiling), so
# copying that level labelled everything below 40 as "info" — including scores of
# 25-39 that DO gate `pa run` via risk_threshold. Displaying "info" beside a
# package that would be blocked actively misleads.


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (5, "info"),        # below risk_threshold: informational
        (24, "info"),       # just below
        (25, "warning"),    # at risk_threshold — gates pa run
        (35, "warning"),    # the spec's worked example
        (39, "warning"),
        (40, "warning"),    # daemon's warning boundary
        (70, "critical"),   # daemon's critical boundary
        (90, "critical"),
    ],
)
def test_level_reflects_preflight_thresholds_not_daemon_ones(tmp_path, env, score, expected):
    report = _report(score, [("typosquat", score, "typo")])
    res = _run(tmp_path, "--format", "json", report=report)
    payload = json.loads(res.output)
    assert payload["risks"][0]["level"] == expected, (
        f"score {score} should render as {expected}"
    )


def test_gating_scores_never_render_as_info(tmp_path, env):
    """Any score that would gate `pa run` must be visually distinguishable."""
    from packagealert.config import AppConfig
    threshold = AppConfig().sandbox.preflight_risk.risk_threshold
    report = _report(threshold, [("typosquat", threshold, "typo")])
    res = _run(tmp_path, "--format", "json", report=report)
    payload = json.loads(res.output)
    assert payload["risks"][0]["level"] != "info"


def test_level_respects_configured_risk_threshold(tmp_path, env):
    """A user who raises risk_threshold should see levels move with it."""
    from packagealert.config import AppConfig
    cfg = AppConfig()
    cfg.sandbox.preflight_risk.risk_threshold = 50
    report = _report(35, [("typosquat", 35, "typo")])
    with patch("packagealert.cli.app._load", return_value=(cfg, None)):
        res = _run(tmp_path, "--format", "json", report=report)
    payload = json.loads(res.output)
    # 35 no longer gates, so it is informational again.
    assert payload["risks"][0]["level"] == "info"


# --- failure isolation covers the whole pass ---------------------------------
#
# REGRESSION: _risk_pass documents "Never raises", but registry loading, client
# and engine construction, and pop_client.aclose() all sat outside the try. A
# broken plugin entry point or a resource init/close failure therefore prevented
# OSV findings from rendering — risk scoring is additive information and must
# never turn a working scan into a failed one.
#
# These exercise _risk_pass directly rather than through the CLI: the failure
# boundary is the unit under test, and injecting construction failures through a
# full scan-project invocation would leave real network clients unstubbed.


def _cfg_for_risk_pass():
    from packagealert.config import AppConfig
    return AppConfig()


def _to_query():
    return [LockedPackage(name="reqeusts", version="1.0.0", ecosystem="pypi")]


@pytest.mark.asyncio
async def test_risk_pass_survives_broken_language_plugin():
    """popularity_ecosystem_map() consults every language plugin during setup."""
    from packagealert.cli.app import _risk_pass

    with patch(
        "packagealert.languages.registry.popularity_ecosystem_map",
        side_effect=RuntimeError("plugin entry point exploded"),
    ):
        rows, failures = await _risk_pass(_cfg_for_risk_pass(), MagicMock(), _to_query())
    assert rows == []
    assert failures == 1


@pytest.mark.asyncio
async def test_risk_pass_survives_registry_load_failure():
    from packagealert.cli.app import _risk_pass

    with patch(
        "packagealert.languages.registry.load",
        side_effect=RuntimeError("entry point discovery exploded"),
    ):
        rows, failures = await _risk_pass(_cfg_for_risk_pass(), MagicMock(), _to_query())
    assert rows == []
    assert failures == 1


@pytest.mark.asyncio
async def test_risk_pass_survives_popularity_client_construction_failure():
    from packagealert.cli.app import _risk_pass

    with patch(
        "packagealert.osv.popularity.PopularityClient",
        side_effect=RuntimeError("cannot open httpx client"),
    ):
        rows, failures = await _risk_pass(_cfg_for_risk_pass(), MagicMock(), _to_query())
    assert rows == []
    assert failures == 1


@pytest.mark.asyncio
async def test_risk_pass_survives_engine_construction_failure():
    from packagealert.cli.app import _risk_pass

    with (
        patch("packagealert.osv.popularity.PopularityClient", return_value=AsyncMock()),
        patch(
            "packagealert.analyzers.risk.RiskEngine",
            side_effect=RuntimeError("engine init exploded"),
        ),
    ):
        rows, failures = await _risk_pass(_cfg_for_risk_pass(), MagicMock(), _to_query())
    assert rows == []
    assert failures == 1


@pytest.mark.asyncio
async def test_risk_pass_closes_client_when_engine_construction_fails():
    """A setup failure after the client exists must still release it."""
    from packagealert.cli.app import _risk_pass

    client = AsyncMock()
    with (
        patch("packagealert.osv.popularity.PopularityClient", return_value=client),
        patch(
            "packagealert.analyzers.risk.RiskEngine",
            side_effect=RuntimeError("engine init exploded"),
        ),
    ):
        await _risk_pass(_cfg_for_risk_pass(), MagicMock(), _to_query())
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_risk_pass_survives_client_close_failure():
    """aclose() sat in a finally block, so it propagated even on the success path."""
    from packagealert.cli.app import _risk_pass

    client = AsyncMock()
    client.aclose.side_effect = RuntimeError("close exploded")
    report = _report(35, [("typosquat", 35, "typo")])
    with (
        patch("packagealert.osv.popularity.PopularityClient", return_value=client),
        patch("packagealert.analyzers.risk.RiskEngine", return_value=AsyncMock()),
        patch(
            "packagealert.scoring.score_packages",
            new_callable=AsyncMock, return_value=_outcome(report),
        ),
    ):
        rows, failures = await _risk_pass(_cfg_for_risk_pass(), MagicMock(), _to_query())
    # Scores computed before the close failure survive it.
    assert failures == 0
    assert rows and rows[0]["package"] == "reqeusts"


@pytest.mark.asyncio
async def test_risk_pass_survives_malformed_report():
    """A third-party plugin's signals must not break row construction."""
    from packagealert.cli.app import _risk_pass

    broken = MagicMock()
    broken.score = 35
    type(broken).signals = property(
        lambda self: (_ for _ in ()).throw(RuntimeError("signals exploded"))
    )
    outcome = MagicMock()
    outcome.reports = {("pypi", "reqeusts", "1.0.0"): broken}
    outcome.failures = 0
    with (
        patch("packagealert.osv.popularity.PopularityClient", return_value=AsyncMock()),
        patch("packagealert.analyzers.risk.RiskEngine", return_value=AsyncMock()),
        patch(
            "packagealert.scoring.score_packages",
            new_callable=AsyncMock, return_value=outcome,
        ),
    ):
        rows, failures = await _risk_pass(_cfg_for_risk_pass(), MagicMock(), _to_query())
    assert rows == []
    assert failures == 1


@pytest.mark.asyncio
async def test_one_malformed_report_does_not_discard_the_valid_rows():
    """REGRESSION: the try wrapped the whole loop, so a single bad report returned
    `[], len(to_query)` — discarding every row already built and reporting every
    package as unscored, including genuinely high-scoring ones.

    scoring.py stores whatever engine.analyze returned without validating its type,
    so a plugin-supplied engine can put an arbitrary object in outcome.reports.
    """
    from packagealert.cli.app import _risk_pass
    from packagealert.models.risk import RiskReport, RiskSignal

    def good(name, score):
        return RiskReport(
            package_name=name, ecosystem="pypi", score=score,
            signals=[RiskSignal(name="typosquat", score=score, reason="x")],
        )

    broken = MagicMock()
    broken.score = 90
    type(broken).signals = property(
        lambda self: (_ for _ in ()).throw(RuntimeError("signals exploded"))
    )

    outcome = MagicMock()
    outcome.reports = {
        ("pypi", "alpha", "1.0"): good("alpha", 40),
        ("pypi", "evil", "1.0"): broken,
        ("pypi", "beta", "1.0"): good("beta", 60),
    }
    outcome.failures = 0

    with (
        patch("packagealert.osv.popularity.PopularityClient", return_value=AsyncMock()),
        patch("packagealert.analyzers.risk.RiskEngine", return_value=AsyncMock()),
        patch(
            "packagealert.scoring.score_packages",
            new_callable=AsyncMock, return_value=outcome,
        ),
    ):
        rows, failures = await _risk_pass(
            _cfg_for_risk_pass(), MagicMock(), _to_query()
        )

    assert [r["package"] for r in rows] == ["beta", "alpha"], (
        "valid rows were discarded, or lost their descending-score order"
    )
    assert failures == 1, "only the malformed package should count as a failure"


@pytest.mark.asyncio
async def test_row_failures_are_added_to_scoring_failures():
    """The two counts are distinct causes and must both reach the caller."""
    from packagealert.cli.app import _risk_pass

    broken = MagicMock()
    broken.score = 50
    type(broken).signals = property(
        lambda self: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    outcome = MagicMock()
    outcome.reports = {("pypi", "evil", "1.0"): broken}
    outcome.failures = 2  # two packages already failed during scoring

    with (
        patch("packagealert.osv.popularity.PopularityClient", return_value=AsyncMock()),
        patch("packagealert.analyzers.risk.RiskEngine", return_value=AsyncMock()),
        patch(
            "packagealert.scoring.score_packages",
            new_callable=AsyncMock, return_value=outcome,
        ),
    ):
        rows, failures = await _risk_pass(
            _cfg_for_risk_pass(), MagicMock(), _to_query()
        )
    assert rows == []
    assert failures == 3


# --- --details controls the signal breakdown ---------------------------------
#
# Spec: text output is "one line per package ... --details expands the per-signal
# breakdown". The breakdown was printed unconditionally, so the default output
# was several lines per package. HTML also received every risk row, so
# low-signal suppression was not applied there.


def test_default_text_output_is_one_line_per_package(tmp_path, env):
    """One line per package. The line carries every distinct reason (so nothing
    actionable is hidden), but no indented per-signal breakdown lines — those are
    what --details adds, along with signal names and individual scores."""
    report = _report(
        35,
        [("typosquat", 20, "resembles 'requests'"), ("low_popularity", 15, "few versions")],
    )
    res = _run(tmp_path, report=report)
    assert res.exit_code == 0
    assert "reqeusts" in res.output
    # Signal names and the indented breakdown are --details-only.
    assert "low_popularity" not in res.output
    assert "    - " not in res.output
    # Exactly one line mentions the package.
    risk_lines = [ln for ln in res.output.splitlines() if "reqeusts@" in ln]
    assert len(risk_lines) == 1


def test_default_text_output_includes_primary_reason_inline(tmp_path, env):
    """Per the spec's worked example, the single line carries the top reason."""
    report = _report(
        35,
        [("typosquat", 20, "resembles 'requests'"), ("low_popularity", 15, "few versions")],
    )
    res = _run(tmp_path, report=report)
    assert "resembles 'requests'" in res.output


def test_details_expands_the_signal_breakdown(tmp_path, env):
    report = _report(
        35,
        [("typosquat", 20, "resembles 'requests'"), ("low_popularity", 15, "few versions")],
    )
    res = _run(tmp_path, "--details", report=report)
    assert "typosquat" in res.output
    assert "low_popularity" in res.output
    assert "few versions" in res.output


def test_html_applies_low_signal_suppression(tmp_path, env):
    """A lone score-5 low_popularity row is noise in HTML too."""
    report = _report(5, [("low_popularity", 5, "few versions")])
    res = _run(tmp_path, "--format", "html", report=report)
    # Suppressed by default, so no risk table at all for this single noisy row.
    assert "Risk signals" not in res.output


def test_html_details_shows_suppressed_rows(tmp_path, env):
    report = _report(5, [("low_popularity", 5, "few versions")])
    res = _run(tmp_path, "--format", "html", "--details", report=report)
    assert "Risk signals" in res.output
    assert "reqeusts" in res.output


def test_html_keeps_multi_signal_rows_by_default(tmp_path, env):
    report = _report(35, [("typosquat", 20, "typo"), ("low_popularity", 15, "few")])
    res = _run(tmp_path, "--format", "html", report=report)
    assert "Risk signals" in res.output
    assert "reqeusts" in res.output


def test_json_is_unaffected_by_details(tmp_path, env):
    """JSON is a machine contract: it must always carry the full data."""
    report = _report(5, [("low_popularity", 5, "few versions")])
    plain = json.loads(_run(tmp_path, "--format", "json", report=report).output)
    detailed = json.loads(
        _run(tmp_path, "--format", "json", "--details", report=report).output
    )
    assert plain["risks"] == detailed["risks"]
    assert plain["risks"][0]["signals"][0]["name"] == "low_popularity"


def test_details_shows_breakdown_even_for_a_single_signal(tmp_path, env):
    """The breakdown carries the signal's name and score, which the summary line
    does not — so it is worth printing even when there is only one signal."""
    report = _report(20, [("typosquat", 20, "resembles 'requests'")])
    res = _run(tmp_path, "--details", report=report)
    assert "typosquat (20)" in res.output


def test_details_shows_breakdown_for_multi_signal_rows(tmp_path, env):
    report = _report(35, [("typosquat", 20, "typo reason"), ("low_popularity", 15, "pop reason")])
    res = _run(tmp_path, "--details", report=report)
    assert "typosquat" in res.output
    assert "low_popularity" in res.output
    assert "pop reason" in res.output


def test_default_line_names_the_impersonated_package(tmp_path, env):
    """REGRESSION: a real distance-2 squat scores low_popularity 20 > typosquat
    15, so selecting the summary reason by score alone hid *which* package is
    being impersonated — the most actionable fact in the row. Typosquat reasons
    take display priority over score."""
    report = _report(
        35,
        [
            ("typosquat", 15, "Package name resembles 'requests' (distance=2)"),
            ("low_popularity", 20, "Package not found on deps.dev and name resembles a known package"),
        ],
    )
    res = _run(tmp_path, report=report)
    assert "resembles 'requests'" in res.output


def test_default_line_shows_a_single_reason(tmp_path, env):
    """One clause keeps the line readable; --details carries the rest."""
    report = _report(
        35,
        [
            ("typosquat", 15, "Package name resembles 'requests' (distance=2)"),
            ("low_popularity", 20, "Package not found on deps.dev and name resembles a known package"),
        ],
    )
    res = _run(tmp_path, report=report)
    line = next(ln for ln in res.output.splitlines() if "reqeusts@" in ln)
    assert "not found on deps.dev" not in line
    assert len(line) < 100


def test_default_line_falls_back_to_low_popularity_when_alone(tmp_path, env):
    report = _report(5, [("low_popularity", 5, "Package has very low adoption")])
    res = _run(tmp_path, "--details", report=report)
    assert "very low adoption" in res.output


def test_details_adds_signal_names_and_scores(tmp_path, env):
    """With one reason on the summary line, the breakdown's value is the score
    attribution: which named signals summed to the composite score."""
    report = _report(
        35,
        [
            ("typosquat", 15, "Package name resembles 'requests' (distance=2)"),
            ("low_popularity", 20, "Package not found on deps.dev and name resembles a known package"),
        ],
    )
    res = _run(tmp_path, "--details", report=report)
    assert "typosquat (15)" in res.output
    assert "low_popularity (20)" in res.output


# --- --scan-installed gets source-code signals -------------------------------
#
# Per the spec section "Signal availability depends on the scan mode": lock-file
# mode describes what a project declares (no source on disk, metadata signals
# only), while --scan-installed enumerates what is actually present in a venv or
# node_modules, where the extracted source IS readable. Withholding package_dir
# blinded the one scan mode best placed to find installed malware.


def _installed_scan():
    return ProjectScan(
        sources=["python (installed)"],
        pinned=[LockedPackage(name="evil-pkg", version="1.0.0", ecosystem="pypi")],
        unpinned=[],
    )


def test_lockfile_mode_passes_no_resolver(tmp_path, env):
    """Default mode must keep package_dir=None: nothing is extracted."""
    with patch(
        "packagealert.scoring.score_packages", new_callable=AsyncMock
    ) as sp:
        sp.return_value = _outcome(_report(20, [("typosquat", 20, "typo")]))
        runner.invoke(app, ["scan-project", str(tmp_path)])
    assert sp.await_args.kwargs.get("package_dir_resolver") is None


def test_scan_installed_passes_a_resolver(tmp_path, env):
    """--scan-installed must supply a resolver so source signals can fire."""
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=_installed_scan()),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp,
    ):
        sp.return_value = _outcome(_report(60, [("subprocess_in_setup", 30, "subprocess")]))
        res = runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
    assert res.exit_code == 0
    assert callable(sp.await_args.kwargs.get("package_dir_resolver"))


def test_scan_installed_resolver_resolves_a_real_package(tmp_path, env):
    """The resolver must locate a package in a real site-packages tree."""
    sp_dir = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    (sp_dir / "evil_pkg").mkdir(parents=True)
    dist_info = sp_dir / "evil_pkg-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "top_level.txt").write_text("evil_pkg\n")

    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=_installed_scan()),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp,
    ):
        sp.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp.await_args.kwargs["package_dir_resolver"]

    resolved = captured["resolver"]("pypi", "evil-pkg", "1.0.0")
    assert resolved == [[sp_dir / "evil_pkg"]]


def test_scan_installed_resolver_returns_none_for_unknown_package(tmp_path, env):
    """An unresolvable package degrades to metadata-only, not an error."""
    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=_installed_scan()),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp,
    ):
        sp.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp.await_args.kwargs["package_dir_resolver"]

    assert captured["resolver"]("pypi", "nonexistent-xyz", "1.0.0") == []


def test_scan_installed_level_uses_post_install_threshold(tmp_path, env):
    """Per spec: with source signals available the score range matches the
    post-install scan, so `warning` starts at post_install_threshold (30) rather
    than risk_threshold (25)."""
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=_installed_scan()),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp,
    ):
        # 27: above risk_threshold (25) but below post_install_threshold (30).
        sp.return_value = _outcome(_report(27, [("low_popularity", 27, "obscure")]))
        res = runner.invoke(
            app, ["scan-project", str(tmp_path), "--scan-installed", "--format", "json"]
        )
    payload = json.loads(res.output)
    assert payload["risks"][0]["level"] == "info"


def test_lockfile_level_still_uses_risk_threshold(tmp_path, env):
    """The lock-file boundary is unchanged: 27 >= risk_threshold (25) is warning."""
    with patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp:
        sp.return_value = _outcome(_report(27, [("low_popularity", 27, "obscure")]))
        res = runner.invoke(app, ["scan-project", str(tmp_path), "--format", "json"])
    payload = json.loads(res.output)
    assert payload["risks"][0]["level"] == "warning"


# --- venv discovery must match detection -------------------------------------
#
# REGRESSION: _find_site_packages searched only .venv and venv, while
# PythonLanguage.detect_installed_packages also scans env and .env. Packages in
# those environments were detected but scored metadata-only, because the resolver
# could not find their directory — silently dropping every source-code signal.


@pytest.mark.parametrize("venv_name", [".venv", "venv", "env", ".env"])
def test_resolver_finds_packages_in_every_supported_venv_dir(tmp_path, env, venv_name):
    sp_dir = tmp_path / venv_name / "lib" / "python3.12" / "site-packages"
    (sp_dir / "evil_pkg").mkdir(parents=True)
    dist_info = sp_dir / "evil_pkg-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "top_level.txt").write_text("evil_pkg\n")

    scan = ProjectScan(
        sources=["python (installed)"],
        pinned=[LockedPackage(name="evil-pkg", version="1.0.0", ecosystem="pypi")],
        unpinned=[],
    )
    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=scan),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp,
    ):
        sp.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp.await_args.kwargs["package_dir_resolver"]

    resolved = captured["resolver"]("pypi", "evil-pkg", "1.0.0")
    assert resolved == [[sp_dir / "evil_pkg"]], f"{venv_name} not searched by the resolver"


def test_resolver_searches_a_second_venv(tmp_path, env):
    """REGRESSION: first-match-wins site-packages discovery scored a package 0
    when an earlier (empty) venv shadowed the one actually containing it."""
    (tmp_path / ".venv" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    sp_dir = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    (sp_dir / "evil_pkg").mkdir(parents=True)
    dist_info = sp_dir / "evil_pkg-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "top_level.txt").write_text("evil_pkg\n")

    scan = ProjectScan(
        sources=["python (installed)"],
        pinned=[LockedPackage(name="evil-pkg", version="1.0.0", ecosystem="pypi")],
        unpinned=[],
    )
    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=scan),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp,
    ):
        sp.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp.await_args.kwargs["package_dir_resolver"]

    assert captured["resolver"]("pypi", "evil-pkg", "1.0.0") == [[sp_dir / "evil_pkg"]]


def test_resolver_handles_node_without_an_ecosystem_branch(tmp_path, env):
    """One loop serves both ecosystems: each language module takes the hint it
    uses and ignores the other. Node must resolve whether or not a venv exists,
    and must not be affected by site-packages candidates being present."""
    (tmp_path / "node_modules" / "evil-npm").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)
    (tmp_path / "env" / "lib" / "python3.12" / "site-packages").mkdir(parents=True)

    scan = ProjectScan(
        sources=["node (installed)"],
        pinned=[LockedPackage(name="evil-npm", version="1.0.0", ecosystem="npm")],
        unpinned=[],
    )
    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=scan),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp,
    ):
        sp.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp.await_args.kwargs["package_dir_resolver"]

    assert captured["resolver"]("npm", "evil-npm", "1.0.0") == [
        [tmp_path / "node_modules" / "evil-npm"]
    ]


def test_resolver_handles_node_with_no_venv_present(tmp_path, env):
    """With zero site-packages candidates the loop must still run once."""
    (tmp_path / "node_modules" / "evil-npm").mkdir(parents=True)

    scan = ProjectScan(
        sources=["node (installed)"],
        pinned=[LockedPackage(name="evil-npm", version="1.0.0", ecosystem="npm")],
        unpinned=[],
    )
    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=scan),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp,
    ):
        sp.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp.await_args.kwargs["package_dir_resolver"]

    assert captured["resolver"]("npm", "evil-npm", "1.0.0") == [
        [tmp_path / "node_modules" / "evil-npm"]
    ]


def test_resolver_picks_the_venv_holding_the_requested_version(tmp_path, env):
    """REGRESSION: with foo==1 in .venv and foo==2 in env, both risk rows resolved
    to .venv's tree, so a malicious foo==2 was scored against benign source."""
    v1 = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    v2 = tmp_path / "env" / "lib" / "python3.12" / "site-packages"
    for sp, ver in ((v1, "1.0.0"), (v2, "2.0.0")):
        (sp / "foo").mkdir(parents=True)
        di = sp / f"foo-{ver}.dist-info"
        di.mkdir(parents=True)
        (di / "top_level.txt").write_text("foo\n")

    scan = ProjectScan(
        sources=["python (installed)"],
        pinned=[
            LockedPackage(name="foo", version="1.0.0", ecosystem="pypi"),
            LockedPackage(name="foo", version="2.0.0", ecosystem="pypi"),
        ],
        unpinned=[],
    )
    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=scan),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp_mock,
    ):
        sp_mock.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp_mock.await_args.kwargs["package_dir_resolver"]

    resolve = captured["resolver"]
    assert resolve("pypi", "foo", "1.0.0") == [[v1 / "foo"]]
    assert resolve("pypi", "foo", "2.0.0") == [[v2 / "foo"]], "wrong venv for foo==2.0.0"


def test_resolver_returns_every_copy_of_a_duplicated_package(tmp_path, env):
    """REGRESSION: foo==1.0.0 installed in BOTH .venv and env returned only the
    first directory, so a compromised copy in the second was scored as clean.
    Version-awareness cannot disambiguate identical versions — only returning
    every candidate can."""
    dirs = []
    for venv in (".venv", "env"):
        sp = tmp_path / venv / "lib" / "python3.12" / "site-packages"
        (sp / "foo").mkdir(parents=True)
        di = sp / "foo-1.0.0.dist-info"
        di.mkdir(parents=True)
        (di / "top_level.txt").write_text("foo\n")
        dirs.append(sp / "foo")

    scan = ProjectScan(
        sources=["python (installed)"],
        pinned=[LockedPackage(name="foo", version="1.0.0", ecosystem="pypi")],
        unpinned=[],
    )
    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=scan),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp_mock,
    ):
        sp_mock.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp_mock.await_args.kwargs["package_dir_resolver"]

    assert captured["resolver"]("pypi", "foo", "1.0.0") == [[d] for d in dirs]


def test_resolver_groups_a_namespace_packages_owned_directories_together(tmp_path, env):
    """REGRESSION: a namespace-package distribution owning several directories of
    a shared root (google/auth and google/oauth2, as the real google-auth does)
    must reach the engine as ONE combined candidate, not as several directories
    competing against each other for the max score — they are one distribution's
    own files, not independent copies."""
    sp_dir = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
    google = sp_dir / "google"
    (google / "auth").mkdir(parents=True)
    (google / "auth" / "__init__.py").write_text("x = 1\n")
    (google / "oauth2").mkdir(parents=True)
    (google / "oauth2" / "__init__.py").write_text("x = 1\n")
    # A sibling distribution's directory in the same shared namespace root —
    # must never appear in google-auth's resolved group.
    (google / "cloud").mkdir(parents=True)
    (google / "cloud" / "evil.py").write_text("import subprocess\n")

    di = sp_dir / "google_auth-2.56.3.dist-info"
    di.mkdir()
    (di / "METADATA").write_text("Name: google-auth\nVersion: 2.56.3\n")
    (di / "RECORD").write_text(
        "google/auth/__init__.py,,\n"
        "google/oauth2/__init__.py,,\n"
        f"{di.name}/METADATA,,\n"
    )

    scan = ProjectScan(
        sources=["python (installed)"],
        pinned=[LockedPackage(name="google-auth", version="2.56.3", ecosystem="pypi")],
        unpinned=[],
    )
    captured = {}
    with (
        patch("packagealert.parsers.lockfiles.scan_installed", return_value=scan),
        patch("packagealert.scoring.score_packages", new_callable=AsyncMock) as sp_mock,
    ):
        sp_mock.return_value = _outcome(None)
        runner.invoke(app, ["scan-project", str(tmp_path), "--scan-installed"])
        captured["resolver"] = sp_mock.await_args.kwargs["package_dir_resolver"]

    resolved = captured["resolver"]("pypi", "google-auth", "2.56.3")
    # Exactly one candidate group (one environment), containing both owned
    # directories together.
    assert len(resolved) == 1
    names = sorted(p.name for p in resolved[0])
    assert names == ["auth", "oauth2"]
    assert "cloud" not in names, "sibling distribution's directory must not be included"


# --- incomplete scoring must be visible to machine consumers ---------------------
#
# The JSON path dropped risk_failures, so a fully failed risk pass emitted
# "risks": [] — byte-identical to a clean scan. A CI job or plugin acting on "no risks
# found" would treat a broken scoring pass as a passing one. The text output has always
# warned about this; JSON, HTML and the plugin ScanResult could not see it.


def test_json_output_includes_risk_failures(tmp_path, env):
    """The key must be present even when nothing failed, so consumers can rely on it."""
    import json as jsonlib

    res = _run(tmp_path, "--format", "json", failures=0)
    payload = jsonlib.loads(res.stdout)
    assert "risk_failures" in payload
    assert payload["risk_failures"] == 0


def test_json_output_reports_a_failed_pass(tmp_path, env):
    """REGRESSION: indistinguishable from a clean scan."""
    import json as jsonlib

    res = _run(tmp_path, "--format", "json", failures=3)
    payload = jsonlib.loads(res.stdout)
    assert payload["risks"] == []
    assert payload["risk_failures"] == 3, (
        "an empty risks list with no failure count reads as a clean scan"
    )


def test_a_clean_scan_and_a_failed_pass_differ_in_json(tmp_path, env):
    """The property that matters, stated directly."""
    import json as jsonlib

    clean = jsonlib.loads(_run(tmp_path, "--format", "json", failures=0).stdout)
    failed = jsonlib.loads(_run(tmp_path, "--format", "json", failures=5).stdout)
    assert clean["risks"] == failed["risks"] == []
    assert clean != failed, "a broken scoring pass looks identical to a clean scan"


def test_scan_result_carries_the_failure_count():
    """Plugin on_scan_complete consumers need the same distinction."""
    from packagealert.models.scans import ScanResult

    assert ScanResult(
        project_path="/p", scan_type="project", finding_count=0,
        findings=[], sources=[], scanned_at=None,
    ).risk_failures == 0

    scan = ScanResult(
        project_path="/p", scan_type="project", finding_count=0,
        findings=[], sources=[], scanned_at=None, risk_failures=4,
    )
    assert scan.risks == []
    assert scan.risk_failures == 4


def test_html_reports_unscored_packages():
    from pathlib import Path

    from packagealert.cli.app import _render_html

    html = _render_html(
        Path("/p"), ["python (uv.lock)"], [], [],
        risks=[], risk_total=0, risk_failures=7,
    )
    assert "7 unscored" in html


def test_html_omits_the_badge_when_nothing_failed():
    """No badge on a clean scan — the warning must mean something when it appears."""
    from pathlib import Path

    from packagealert.cli.app import _render_html

    html = _render_html(
        Path("/p"), ["python (uv.lock)"], [], [],
        risks=[], risk_total=0, risk_failures=0,
    )
    assert "unscored" not in html
