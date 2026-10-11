from __future__ import annotations

import io

import pytest
from rich.console import Console

from packagealert.cli.app import _print_findings_by_package, _remediations_json
from packagealert.osv.client import (
    _extract_affected_ranges,
    _extract_affected_versions,
    _extract_fixed_versions,
)
from packagealert.osv.remediation import group_findings, merge_aliases, recommend_fix


def _f(adv_id, fixed, ranges=None, *, package="Django", version="5.2.15", eco="PyPI", **extra):
    return {
        "advisory_id": adv_id, "package": package, "ecosystem": eco, "version": version,
        "fixed_versions": fixed, "affected_ranges": ranges or [], "is_malicious": False,
        "severity": "HIGH", "summary": f"summary {adv_id}", "details": None,
        "url": f"https://osv.dev/vulnerability/{adv_id}", **extra,
    }


# Shapes as OSV returns them for Django (GHSA-q238-5cxm-5c9h / PYSEC-2026-3717).
_Q238 = [
    [{"introduced": "0"}, {"fixed": "5.2.17"}],
    [{"introduced": "6.0a1"}, {"fixed": "6.0.8"}],
    [{"introduced": "6.1a1"}, {"fixed": "6.1.1"}],
]
_TWO_LINES = [[{"introduced": "0"}, {"fixed": "5.2.16"}, {"introduced": "6.0"}, {"fixed": "6.0.7"}]]


def test_one_version_on_the_installed_release_line_fixes_everything():
    rec = recommend_fix("5.2.15", [
        _f("A", ["5.2.17", "6.0.8", "6.1.1"], _Q238),
        _f("B", ["5.2.16", "6.0.7"], _TWO_LINES),
    ], "PyPI")
    assert rec is not None
    assert (rec.version, rec.unfixed, rec.major_upgrade, rec.verified) == ("5.2.17", (), False, True)


def test_a_candidate_still_inside_another_advisorys_range_is_skipped():
    # 6.0.7 is fixed for B but A's 6.0 line is only fixed at 6.0.8; installed
    # on 6.0 the recommendation must be 6.0.8, not the lower 6.0.7.
    rec = recommend_fix("6.0.5", [
        _f("A", ["5.2.17", "6.0.8"], _Q238[:2]),
        _f("B", ["5.2.16", "6.0.7"], _TWO_LINES),
    ], "PyPI")
    assert rec is not None and rec.version == "6.0.8" and not rec.unfixed


def test_crossing_to_a_new_major_is_flagged_when_the_current_line_has_no_fix():
    rec = recommend_fix("5.2.15", [
        _f("A", ["6.0.8"], [[{"introduced": "0"}, {"fixed": "6.0.8"}]]),
        _f("B", ["5.2.17", "6.0.2"], [[{"introduced": "0"}, {"fixed": "5.2.17"}, {"introduced": "6.0"}, {"fixed": "6.0.2"}]]),
    ], "PyPI")
    assert rec is not None and rec.version == "6.0.8" and rec.major_upgrade and not rec.unfixed


def test_an_advisory_with_no_fix_is_reported_unfixed():
    rec = recommend_fix("1.0", [
        _f("A", ["1.1"], [[{"introduced": "0"}, {"fixed": "1.1"}]]),
        _f("B", [], [[{"introduced": "0"}]]),
    ], "PyPI")
    assert rec is not None and rec.version == "1.1" and rec.unfixed == ("B",)


def test_no_fix_at_all():
    rec = recommend_fix("1.0", [_f("A", [], [[{"introduced": "0"}]])], "PyPI")
    assert rec is not None and rec.version is None and rec.unfixed == ("A",)


def test_last_affected_closes_the_range_above_it():
    rec = recommend_fix("1.0", [
        _f("A", [], [[{"introduced": "0"}, {"last_affected": "1.2"}]]),
        _f("B", ["1.2", "1.3"], [[{"introduced": "0"}, {"fixed": "1.3"}]]),
    ], "PyPI")
    assert rec is not None and rec.version == "1.3" and not rec.unfixed


def test_without_ranges_the_nearest_fix_per_advisory_is_used_and_marked_unverified():
    # A finding stored before ranges were recorded.
    rec = recommend_fix("5.2.15", [
        _f("A", ["5.2.17", "6.0.8"]),
        _f("B", ["5.2.16", "6.0.7"]),
    ], "PyPI")
    assert rec is not None and rec.version == "5.2.17" and not rec.verified and not rec.unfixed


def test_semver_pre_releases_sort_before_the_release():
    rec = recommend_fix("1.2.3", [
        _f("A", ["1.2.4-beta.1", "1.2.4"], [[{"introduced": "0"}, {"fixed": "1.2.4"}]], eco="npm"),
    ], "npm")
    assert rec is not None and rec.version == "1.2.4"


def test_malformed_ranges_and_versions_degrade_instead_of_raising():
    rec = recommend_fix("1.0", [
        _f("A", ["1.1", None], "not ranges"),  # type: ignore[arg-type]
        _f("B", ["1.2"], [[{"introduced": "0"}, {"fixed": 5}], ["junk"]]),  # type: ignore[list-item]
    ], "PyPI")
    assert rec is not None and rec.version == "1.2" and not rec.verified
    assert recommend_fix("not-a-version!", [_f("A", ["1.1"])], "PyPI") is None


def test_findings_group_by_package_in_first_appearance_order():
    groups = group_findings([
        _f("A", ["5.2.17"]), _f("X", ["2.8.0"], package="urllib3", version="2.7.0"), _f("B", ["5.2.16"]),
    ])
    assert [(g.package, [f["advisory_id"] for f in g.findings]) for g in groups] == [
        ("Django", ["A", "B"]), ("urllib3", ["X"]),
    ]


def _render(findings, **kw) -> str:
    buf = io.StringIO()
    _print_findings_by_package(Console(file=buf, width=200, color_system=None), findings, show_details=False, **kw)
    return buf.getvalue()


def test_text_output_shows_one_recommendation_per_package():
    out = _render([_f("A", ["5.2.17", "6.0.8"], _Q238), _f("B", ["5.2.16", "6.0.7"], _TWO_LINES)])
    assert "[VULN] Django@5.2.15 — 2 advisories" in out
    assert out.count("→") == 1
    assert "upgrade to 5.2.17 (fixes all 2)" in out
    assert "6.0.8" not in out


def test_text_output_marks_a_recommendation_inside_the_cooldown_period():
    findings = [_f("A", ["5.2.17"], _Q238)]
    out = _render(findings, ages={("PyPI", "Django", "5.2.17"): 2.5}, cooldown_days=7)
    assert "in cooldown: published 2.5 days ago (cooldown 7d)" in out
    out = _render(findings, ages={("PyPI", "Django", "5.2.17"): 30.0}, cooldown_days=7)
    assert "cooldown" not in out


def test_text_output_names_advisories_the_recommendation_does_not_fix():
    out = _render([_f("A", ["1.1"], [[{"introduced": "0"}, {"fixed": "1.1"}]], version="1.0"),
                   _f("B", [], [[{"introduced": "0"}]], version="1.0")])
    assert "upgrade to 1.1 (fixes 1 of 2)" in out
    assert "B [HIGH] — summary B (no fix in the recommended version)" in out


def test_text_output_does_not_interpret_markup_in_advisory_text():
    out = _render([_f("A", ["1.1"], version="1.0", summary="[bold]x[/bold] [red]")])
    assert "[bold]x[/bold] [red]" in out


def test_json_remediations():
    [r] = _remediations_json([_f("A", ["5.2.17"], _Q238)], {("PyPI", "Django", "5.2.17"): 1.0}, 7)
    assert r["recommended_version"] == "5.2.17" and r["in_cooldown"] is True
    assert r["advisories"] == [{"id": "A", "aliases": []}]
    assert r["unfixed_advisory_ids"] == [] and r["verified"] is True


def test_osv_parser_keeps_the_ranges_for_the_queried_package_only():
    vuln = {"affected": [
        {"package": {"ecosystem": "PyPI", "name": "django"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.2.17"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "other"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "Django"},
         "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "6.0a1"}, {"fixed": "6.0.8"}]}]},
    ]}
    assert _extract_affected_ranges(vuln, "Django", "pypi") == [
        [{"introduced": "0"}, {"fixed": "5.2.17"}],
        [{"introduced": "6.0a1"}, {"fixed": "6.0.8"}],
    ]
    assert _extract_fixed_versions(vuln, "Django", "pypi") == ["5.2.17", "6.0.8"]


def test_aliases_merge_into_one_advisory():
    advs = merge_aliases([
        _f("GHSA-1", ["1.1"], aliases=["CVE-1", "PYSEC-1"]),
        _f("GHSA-2", ["1.1"], aliases=["CVE-2"]),
        _f("PYSEC-1", ["1.1"], aliases=["CVE-1", "GHSA-1"], summary=None, severity=None),
        # Shares only a CVE with GHSA-2: merged transitively.
        _f("PYSEC-2", ["1.1"], aliases=["CVE-2"]),
        _f("OTHER", ["1.1"]),
    ])
    assert [a.ids for a in advs] == [["GHSA-1", "PYSEC-1"], ["GHSA-2", "PYSEC-2"], ["OTHER"]]
    assert advs[0].id == "GHSA-1" and advs[0].other_ids == ["PYSEC-1"]


def test_merged_advisory_takes_the_member_with_a_summary_and_the_worst_severity():
    [adv] = merge_aliases([
        _f("PYSEC-1", ["1.1"], aliases=["GHSA-1"], summary=None, severity="CRITICAL"),
        _f("GHSA-1", ["1.1"], aliases=["PYSEC-1"], severity="MEDIUM"),
    ])
    assert adv.id == "GHSA-1" and adv.summary == "summary GHSA-1" and adv.severity == "CRITICAL"


def test_a_malicious_alias_makes_the_merged_advisory_malicious():
    [adv] = merge_aliases([
        _f("GHSA-1", [], aliases=["MAL-1"]),
        _f("MAL-1", [], aliases=["GHSA-1"], is_malicious=True),
    ])
    assert adv.is_malicious


def test_text_output_prints_aliases_once_and_counts_vulnerabilities():
    out = _render([
        _f("GHSA-1", ["5.2.17"], _Q238, aliases=["PYSEC-1"]),
        _f("PYSEC-1", ["5.2.17"], _Q238, aliases=["GHSA-1"], summary=None),
        _f("GHSA-2", ["5.2.16"], _TWO_LINES),
    ])
    assert "Django@5.2.15 — 2 advisories" in out
    assert "upgrade to 5.2.17 (fixes all 2)" in out
    assert "GHSA-1 [HIGH] — summary GHSA-1 (also PYSEC-1)" in out
    assert out.count("PYSEC-1") == 1


def test_unfixed_is_reported_per_merged_advisory():
    out = _render([
        _f("A", ["1.1"], [[{"introduced": "0"}, {"fixed": "1.1"}]], version="1.0"),
        _f("B", [], [[{"introduced": "0"}]], version="1.0", aliases=["C"]),
        _f("C", [], [[{"introduced": "0"}]], version="1.0", aliases=["B"]),
    ])
    assert "upgrade to 1.1 (fixes 1 of 2)" in out
    assert out.count("(no fix in the recommended version)") == 1


def test_advisory_lines_are_labelled_only_when_malicious():
    out = _render([
        _f("GHSA-1", ["1.1"], version="1.0", package="p"),
        _f("MAL-1", [], version="1.0", package="p", is_malicious=True),
    ])
    lines = out.splitlines()
    assert "    GHSA-1 [HIGH] — summary GHSA-1" in lines
    assert any(line.startswith("    MALICIOUS MAL-1") for line in lines)
    assert not any(line.lstrip().startswith("VULN") for line in lines)


def test_advisories_are_sorted_most_severe_first():
    [group] = group_findings([
        _f("LOW-1", ["1.1"], version="1.0", severity="LOW"),
        _f("NONE-1", ["1.1"], version="1.0", severity=None),
        _f("HIGH-1", ["1.1"], version="1.0", severity="HIGH"),
        _f("MED-1", ["1.1"], version="1.0", severity="MEDIUM"),
        _f("HIGH-2", ["1.1"], version="1.0", severity="HIGH"),
        _f("CRIT-1", ["1.1"], version="1.0", severity="CRITICAL"),
        _f("MAL-1", [], version="1.0", severity=None, is_malicious=True),
    ])
    assert [a.id for a in group.advisories] == [
        "MAL-1", "CRIT-1", "HIGH-1", "HIGH-2", "MED-1", "LOW-1", "NONE-1",
    ]


def test_limit_bounds_the_range():
    # OSV: a version at or above every limit is outside the range.
    findings = [
        _f("A", ["2.1"], [[{"introduced": "0"}, {"limit": "2.0"}]], version="1.5"),
        _f("B", ["2.1"], [[{"introduced": "0"}, {"fixed": "2.1"}]], version="1.5"),
    ]
    rec = recommend_fix("1.5", findings, "PyPI")
    assert rec is not None and rec.version == "2.1" and not rec.unfixed


def test_limit_star_and_multiple_limits():
    # "*" is no bound; with several limits, below any one of them is enough.
    star = [_f("A", ["2.1"], [[{"introduced": "0"}, {"limit": "*"}]], version="1.5")]
    rec = recommend_fix("1.5", star, "PyPI")
    assert rec is not None and rec.unfixed == ("A",)
    two = [
        _f("A", [], [[{"introduced": "0"}, {"limit": "2.0"}, {"limit": "3.0"}]], version="1.5"),
        _f("B", ["2.5", "3.1"], [[{"introduced": "0"}, {"fixed": "2.5"}]], version="1.5"),
    ]
    rec = recommend_fix("1.5", two, "PyPI")
    assert rec is not None and rec.version == "3.1" and not rec.unfixed


@pytest.mark.parametrize("ranges", [
    [[{}]],
    [[]],
    [[{"introduced": "0", "fixed": 5}]],  # non-string boundary, filtered to nothing usable
    [[{"introduced": "3.0"}, {"fixed": "3.1"}]],  # well formed, but not covering 1.0
])
def test_ranges_not_containing_the_installed_version_are_not_trusted(ranges):
    rec = recommend_fix("1.0", [
        _f("A", ["2.0"], ranges, version="1.0"),
        _f("B", ["1.1"], [[{"introduced": "0"}, {"fixed": "1.1"}]], version="1.0"),
    ], "PyPI")
    # A falls back to its own nearest fix, 2.0, and is reported as unverified.
    assert rec is not None and rec.version == "2.0" and not rec.unfixed and not rec.verified


def test_extra_non_string_event_fields_do_not_make_a_range_malformed():
    vuln = {"affected": [{
        "package": {"ecosystem": "PyPI", "name": "pkg"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.3", "note": 1}]}],
    }]}
    assert _extract_affected_ranges(vuln, "pkg", "pypi") == [[{"introduced": "2.0"}, {"fixed": "2.3"}]]


@pytest.mark.parametrize("bad_range", [
    [{"introduced": "1.5"}, {"fixed": 5}],  # non-string boundary
    [{"introduced": "1.5"}, None],  # non-dict event
    "not-a-list",
])
def test_one_malformed_range_makes_the_advisorys_ranges_unusable(bad_range):
    # The ranges are read as the COMPLETE affected set: keeping only the valid
    # [0, 1.1) would make 1.6 — inside the broken range — look fixed.
    vuln = {"affected": [{
        "package": {"ecosystem": "PyPI", "name": "pkg"},
        "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]},
            {"type": "ECOSYSTEM", "events": bad_range},
        ],
    }]}
    assert _extract_affected_ranges(vuln, "pkg", "pypi") == []
    # The usable fixed version is still offered as an upgrade target.
    assert _extract_fixed_versions(vuln, "pkg", "pypi") == ["1.1"]

    rec = recommend_fix("1.0", [
        _f("A", _extract_fixed_versions(vuln, "pkg", "pypi"),
           _extract_affected_ranges(vuln, "pkg", "pypi"), version="1.0"),
        _f("B", ["1.6"], [[{"introduced": "0"}, {"fixed": "1.6"}]], version="1.0"),
    ], "PyPI")
    assert rec is not None and not rec.verified


def test_aliases_count_once_when_scoring_partial_fixes():
    # 1.1 leaves the GHSA/PYSEC pair open; 2.0 leaves C open. One vulnerability
    # each, so the lower version wins rather than the cross-major one.
    pair = [[{"introduced": "0"}, {"fixed": "2.0"}]]
    rec = recommend_fix("1.0", [
        _f("GHSA-1", ["2.0"], pair, version="1.0", aliases=["PYSEC-1"]),
        _f("PYSEC-1", ["2.0"], pair, version="1.0", aliases=["GHSA-1"]),
        _f("C", ["1.1"], [[{"introduced": "0"}, {"fixed": "1.1"}, {"introduced": "1.5"}]], version="1.0"),
    ], "PyPI")
    assert rec is not None
    assert (rec.version, set(rec.unfixed), rec.major_upgrade) == ("1.1", {"GHSA-1", "PYSEC-1"}, False)


def test_semver_build_metadata_is_ignored_for_precedence():
    from packagealert.osv.remediation import _generic_key as key

    assert key("1.2.3-beta.1+build") == key("1.2.3-beta.1")
    assert key("1.2.3-beta.1+zzz") < key("1.2.3-beta.2")
    # A hyphen inside build metadata is not a pre-release.
    assert key("1.0.0+build-1") == key("1.0.0")
    assert key("1.0.0+build-1") > key("1.0.0-rc.1")


def test_scan_list_counts_vulnerabilities_like_the_detail_view():
    import types

    from packagealert.cli.app import _findings_cell

    findings = [
        _f("GHSA-1", ["1.1"], version="1.0", aliases=["PYSEC-1"]),
        _f("PYSEC-1", ["1.1"], version="1.0", aliases=["GHSA-1"]),
        _f("GHSA-2", ["1.1"], version="1.0"),
    ]
    record = types.SimpleNamespace(findings=findings, finding_count=3, osv_failures=0)
    assert _findings_cell(record) == "2"
    record.osv_failures = 4
    assert _findings_cell(record) == "2 [yellow](+4 unchecked)[/yellow]"
    # A record whose findings were not kept still shows the stored count.
    assert _findings_cell(types.SimpleNamespace(findings=[], finding_count=5, osv_failures=0)) == "5"


@pytest.mark.parametrize(("version", "affected"), [
    ("0.5", True), ("1.5", True), ("2.5", True), ("3.5", False),
])
def test_limit_follows_the_osv_evaluation_algorithm(version, affected):
    # OSV's IncludedInRanges(): BeforeLimits() gates the whole range (below ANY
    # limit), and the sorted-event loop handles only introduced/fixed/
    # last_affected. So `limit` is not a closing event: 1.5 is affected here,
    # because nothing in the event loop closes the range opened at 0.
    from packagealert.osv.remediation import _in_range, _pypi_key

    events = [{"introduced": "0"}, {"limit": "1.0"}, {"introduced": "2.0"}, {"limit": "3.0"}]
    assert _in_range(events, _pypi_key(version), _pypi_key) is affected


_STORED_FINDINGS = [
    _f("GHSA-1", ["5.2.17", "6.0.8"], _Q238, aliases=["PYSEC-1"]),
    _f("PYSEC-1", ["5.2.17", "6.0.8"], _Q238, aliases=["GHSA-1"]),
]


def _assert_read_back_remediations(out: dict) -> None:
    [r] = out["remediations"]
    assert r["recommended_version"] == "5.2.17"
    assert r["advisories"] == [{"id": "GHSA-1", "aliases": ["PYSEC-1"]}]
    # Age and cooldown need a registry lookup only the live scan makes.
    assert r["recommended_age_days"] is None and r["in_cooldown"] is None


async def test_stored_scan_json_includes_remediations(capsys):
    import json
    from unittest.mock import AsyncMock, patch

    from packagealert.cli import app as app_module
    from packagealert.config import AppConfig
    from packagealert.scheduler.db import ScanRecord

    record = ScanRecord(
        id=7, project_path="/proj", scanned_at=0.0, schedule="daily", scan_type="project",
        findings=_STORED_FINDINGS, sources=["pypi"], max_severity="HIGH", finding_count=2,
    )
    with (
        patch("packagealert.storage.db.open_db", AsyncMock(return_value=AsyncMock())),
        patch("packagealert.plugins.registry.plugin_registry.try_scans_show", AsyncMock(return_value=False)),
        patch("packagealert.scheduler.db.get_scan_result", AsyncMock(return_value=record)),
    ):
        await app_module._scans_show(AppConfig(), 7, "json", False)
    _assert_read_back_remediations(json.loads(capsys.readouterr().out))


def test_central_scan_json_includes_remediations(capsys):
    import json

    from packagealert.plugins.central.plugin import _render_scan_detail

    record = {
        "id": 9, "project_path": "/proj", "scan_type": "project", "status": "findings",
        "finding_count": 2, "findings": [*_STORED_FINDINGS, "not-a-finding"],
        "sources": ["pypi"], "scanned_at": "2026-01-01T00:00:00+00:00",
    }
    _render_scan_detail(record, "json", show_details=False)
    _assert_read_back_remediations(json.loads(capsys.readouterr().out))


def test_a_string_fixed_versions_is_not_read_character_by_character():
    # A finding read back from a server may not keep its list shape.
    rec = recommend_fix("1.0", [_f("A", "1.1, 2.0", version="1.0")], "PyPI")  # type: ignore[arg-type]
    assert rec is not None and rec.version is None
    out = _render([_f("A", "1.1, 2.0", version="1.0")])  # type: ignore[arg-type]
    assert "no fixed version known" in out


def _html(findings) -> str:
    from pathlib import Path

    from packagealert.cli.app import _render_html

    return _render_html(Path("/proj"), ["pypi"], [], findings)


def _html_row(html: str, adv_id: str) -> str:
    start = html.index(f">{adv_id}</a>")
    return html[start:html.index("</tr>", start)]


def test_html_marks_the_advisories_the_recommendation_leaves_open():
    html = _html([
        _f("A", ["1.1"], [[{"introduced": "0"}, {"fixed": "1.1"}]], version="1.0"),
        _f("B", [], [[{"introduced": "0"}]], version="1.0", aliases=["C"]),
        _f("C", [], [[{"introduced": "0"}]], version="1.0", aliases=["B"]),
    ])
    assert "upgrade to 1.1 (fixes 1 of 2)" in html
    assert "not fixed by the recommended version" in _html_row(html, "B")
    assert "not fixed by the recommended version" not in _html_row(html, "A")
    assert html.count("not fixed by the recommended version") == 1


def test_no_recommended_version_marks_no_row_as_left_open():
    findings = [_f("A", [], [[{"introduced": "0"}]], version="1.0")]
    out = _render(findings)
    assert "no fixed version known" in out and "recommended version" not in out
    html = _html(findings)
    assert "no fixed version known" in html and "not fixed by the recommended version" not in html


def _vuln(ranges, versions):
    affected = {"package": {"ecosystem": "PyPI", "name": "pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": r} for r in ranges]}
    if versions is not ...:
        affected["versions"] = versions
    return {"affected": [affected]}


def test_a_candidate_listed_explicitly_as_affected_is_not_recommended():
    # A's range [0, 1.1) covers 1.0, but A also lists 1.6 itself as affected;
    # B is fixed at 1.6. OSV's affected set is ranges OR versions, so 1.6
    # still has A and must not be reported as fixing everything.
    vuln = _vuln([[{"introduced": "0"}, {"fixed": "1.1"}]], ["1.0", "1.6"])
    a = _f("A", _extract_fixed_versions(vuln, "pkg", "pypi"), _extract_affected_ranges(vuln, "pkg", "pypi"),
           version="1.0", affected_versions=_extract_affected_versions(vuln, "pkg", "pypi"))
    b = _f("B", ["1.6", "1.7"], [[{"introduced": "0"}, {"fixed": "1.6"}]], version="1.0")
    rec = recommend_fix("1.0", [a, b], "PyPI")
    assert rec is not None and rec.version == "1.7" and not rec.unfixed and rec.verified


def test_only_listed_versions_outside_the_ranges_are_kept():
    # The usual shape: `versions` repeats what the ranges already cover.
    within = _vuln([[{"introduced": "0"}, {"fixed": "1.1"}]], ["0.9", "1.0", "1.0.1"])
    assert _extract_affected_versions(within, "pkg", "pypi") == []
    extra = _vuln([[{"introduced": "0"}, {"fixed": "1.1"}]], ["1.0", "1.6", "not!a!version", "1.6"])
    assert _extract_affected_versions(extra, "pkg", "pypi") == ["1.6", "not!a!version"]
    assert _extract_affected_versions(_vuln([[{"introduced": "0"}, {"fixed": "1.1"}]], ...), "pkg", "pypi") == []


@pytest.mark.parametrize("versions", ["1.6", [1.6], [None]])
def test_a_malformed_versions_list_makes_the_ranges_unusable(versions):
    vuln = _vuln([[{"introduced": "0"}, {"fixed": "1.1"}]], versions)
    assert _extract_affected_ranges(vuln, "pkg", "pypi") == []
    assert _extract_fixed_versions(vuln, "pkg", "pypi") == ["1.1"]


def test_installed_version_covered_only_by_the_explicit_list_is_trusted():
    rec = recommend_fix("2.0", [
        _f("A", ["2.1"], [[{"introduced": "0"}, {"fixed": "1.1"}]], version="2.0", affected_versions=["2.0"]),
    ], "PyPI")
    assert rec is not None and rec.version == "2.1" and rec.verified


def test_an_unorderable_listed_version_falls_back_unverified():
    rec = recommend_fix("1.0", [
        _f("A", ["1.1"], [[{"introduced": "0"}, {"fixed": "1.1"}]], version="1.0", affected_versions=["not!a!version"]),
    ], "PyPI")
    assert rec is not None and rec.version == "1.1" and not rec.verified


@pytest.mark.parametrize("old, new, crosses", [
    ("0.3.1", "0.4.0", True), ("0.0.3", "0.0.4", True), ("0.3.1", "0.3.9", False),
    ("1.2.0", "1.9.0", False), ("1.9.0", "2.0.0", True), ("0.9.0", "1.0.0", True),
])
def test_npm_major_line_follows_semver_caret(old, new, crosses):
    from packagealert.osv.remediation import _generic_key, _major_for
    a, b = _major_for("npm", _generic_key(old)), _major_for("npm", _generic_key(new))
    assert (a != b) is crosses


def test_pypi_major_is_the_first_release_number():
    from packagealert.osv.remediation import _major_for, _pypi_key
    assert _major_for("PyPI", _pypi_key("0.3.1")) == _major_for("PyPI", _pypi_key("0.4.0"))


# --- a same-line alternative when the full fix needs a new major ---

def _psp(adv_id, fixed):
    return _f(adv_id, [fixed], [[{"introduced": "0"}, {"fixed": fixed}]], package="postcss-selector-parser",
              version="6.1.2", eco="npm")


def test_a_major_fix_comes_with_the_best_same_line_alternative():
    rec = recommend_fix("6.1.2", [_psp("GHSA-rj75", "7.1.6"), _psp("GHSA-w9m9", "6.1.4")], "npm")
    assert rec is not None and (rec.version, rec.major_upgrade) == ("7.1.6", True)
    assert (rec.same_line_version, rec.same_line_unfixed) == ("6.1.4", ("GHSA-rj75",))


def test_no_same_line_alternative_when_nothing_on_the_line_fixes_anything():
    rec = recommend_fix("6.1.2", [_psp("GHSA-rj75", "7.1.6")], "npm")
    assert rec is not None and rec.major_upgrade and rec.same_line_version is None


def test_no_same_line_alternative_when_the_fix_is_on_the_line():
    rec = recommend_fix("6.1.2", [_psp("GHSA-w9m9", "6.1.4")], "npm")
    assert rec is not None and not rec.major_upgrade and rec.same_line_version is None
