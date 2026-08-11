import httpx
import pytest
import respx

from packagealert.config import OsvConfig
from packagealert.osv.client import (
    OsvClient,
    _cvss3_label,
    _extract_fixed_versions,
    _normalize_pypi_name,
    _numeric_score_label,
    _severity_from_response,
)

MALICIOUS_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "MAL-2025-1234",
                    "summary": "Malicious package steals credentials",
                    "database_specific": {"severity": "CRITICAL"},
                    "aliases": [],
                }
            ]
        },
        {"vulns": []},
    ]
}

CLEAN_RESPONSE = {"results": [{"vulns": []}, {"vulns": []}]}


@pytest.fixture
def osv_client():
    cfg = OsvConfig(base_url="https://api.osv.dev/v1")
    return OsvClient(cfg)


@respx.mock
@pytest.mark.asyncio
async def test_batch_query_malicious(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=MALICIOUS_RESPONSE)
    )
    queries = [("pypi", "evil-pkg", "1.0.0"), ("pypi", "safe-pkg", None)]
    results = await osv_client.batch_query(queries)
    assert len(results) == 2
    assert results[0].has_malicious is True
    assert results[1].has_malicious is False


@respx.mock
@pytest.mark.asyncio
async def test_batch_query_empty_returns_clean(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=CLEAN_RESPONSE)
    )
    results = await osv_client.batch_query([("npm", "lodash", "4.17.21"), ("npm", "express", None)])
    assert all(not r.has_malicious for r in results)


@respx.mock
@pytest.mark.asyncio
async def test_retries_on_503(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200, json=CLEAN_RESPONSE),
        ]
    )
    results = await osv_client.batch_query([("pypi", "pkg", "1.0"), ("pypi", "pkg2", None)])
    assert len(results) == 2


@respx.mock
@pytest.mark.asyncio
async def test_returns_empty_on_persistent_failure(osv_client):
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(500)
    )
    results = await osv_client.batch_query([("pypi", "pkg", "1.0")])
    assert len(results) == 1
    assert results[0].has_malicious is False


@respx.mock
@pytest.mark.asyncio
async def test_fixed_versions_populated_from_enrich(osv_client):
    # The /querybatch response only includes id+modified; fixed_versions must be
    # extracted from the full advisory fetched during _enrich.
    batch_response = {
        "results": [
            {"vulns": [{"id": "GHSA-test-1234-abcd", "modified": "2025-01-01T00:00:00Z"}]}
        ]
    }
    full_advisory = {
        "id": "GHSA-test-1234-abcd",
        "summary": "Test vuln",
        "database_specific": {"severity": "HIGH"},
        "aliases": [],
        "affected": [
            {
                "package": {"name": "twisted", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "26.4.0rc2"}],
                    }
                ],
            }
        ],
    }
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=batch_response)
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-test-1234-abcd").mock(
        return_value=httpx.Response(200, json=full_advisory)
    )

    results = await osv_client.batch_query([("pypi", "twisted", "25.5.0")])
    assert len(results) == 1
    adv = results[0].advisories[0]
    assert adv.fixed_versions == ["26.4.0rc2"]


def _make_vuln(pkg_name: str, fixed: str) -> dict:
    return {
        "id": "GHSA-test-0000-0000",
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
    }


def test_normalize_pypi_name():
    assert _normalize_pypi_name("Django_Debug_Toolbar") == "django-debug-toolbar"
    assert _normalize_pypi_name("my.package-name") == "my-package-name"
    assert _normalize_pypi_name("requests") == "requests"


def test_extract_fixed_versions_underscore_query_hyphen_advisory():
    # Query uses underscores; OSV advisory spells the name with hyphens.
    vuln = _make_vuln("django-debug-toolbar", "4.0.0")
    assert _extract_fixed_versions(vuln, "django_debug_toolbar", "pypi") == ["4.0.0"]


def test_extract_fixed_versions_hyphen_query_underscore_advisory():
    vuln = _make_vuln("my_package", "2.1.0")
    assert _extract_fixed_versions(vuln, "my-package", "pypi") == ["2.1.0"]


def test_extract_fixed_versions_dot_separator():
    vuln = _make_vuln("zope.interface", "6.0.0")
    assert _extract_fixed_versions(vuln, "zope-interface", "pypi") == ["6.0.0"]


# ---------------------------------------------------------------------------
# _cvss3_label
# ---------------------------------------------------------------------------

class TestCvss3Label:
    def test_high_availability_only(self):
        # PYSEC-2026-213: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 HIGH
        assert _cvss3_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == "HIGH"

    def test_critical_full_impact(self):
        # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 CRITICAL
        assert _cvss3_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == "CRITICAL"

    def test_medium(self):
        # AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L → 4.3 MEDIUM
        assert _cvss3_label("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L") == "MEDIUM"

    def test_low(self):
        # AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N → LOW
        assert _cvss3_label("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") == "LOW"

    def test_none_score(self):
        # All impact metrics N → base score 0.0 → NONE
        assert _cvss3_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == "NONE"

    def test_invalid_vector_returns_none(self):
        assert _cvss3_label("not-a-vector") is None
        assert _cvss3_label("CVSS:3.1/AV:N/AC:L") is None  # missing metrics

    def test_roundup_boundary_exactness(self):
        # Scores that land exactly on a severity boundary must not be inflated by
        # floating-point rounding.  AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L → 6.5 MEDIUM.
        assert _cvss3_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L") == "MEDIUM"
        # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L → 7.3 HIGH (above 7.0 boundary).
        assert _cvss3_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L") == "HIGH"


# ---------------------------------------------------------------------------
# _severity_from_response
# ---------------------------------------------------------------------------

class TestSeverityFromResponse:
    def test_database_specific_label_preferred(self):
        # GHSA style — label present, no CVSS needed
        data = {
            "database_specific": {"severity": "HIGH"},
            "severity": [],
        }
        assert _severity_from_response(data) == "HIGH"

    def test_database_specific_moderate_normalised_to_medium(self):
        data = {"database_specific": {"severity": "MODERATE"}}
        assert _severity_from_response(data) == "MEDIUM"

    def test_database_specific_lowercase_normalised(self):
        data = {"database_specific": {"severity": "high"}}
        assert _severity_from_response(data) == "HIGH"

    def test_database_specific_unknown_label_falls_through_to_cvss(self):
        # An unrecognised label in database_specific must not be returned verbatim;
        # the function should fall through and try the CVSS severity array.
        data = {
            "database_specific": {"severity": "INFORMATIONAL"},
            "severity": [{"type": "CVSS_V3", "score": 7.5}],
        }
        assert _severity_from_response(data) == "HIGH"

    def test_falls_back_to_cvss_vector(self):
        # PYSEC style — no database_specific, CVSS vector only
        data = {
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        }
        assert _severity_from_response(data) == "HIGH"

    def test_database_specific_wins_over_cvss(self):
        # Both present — database_specific label takes precedence
        data = {
            "database_specific": {"severity": "CRITICAL"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        }
        assert _severity_from_response(data) == "CRITICAL"

    def test_ignores_non_cvss_v3_type(self):
        data = {
            "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:N/I:N/A:C"}],
        }
        assert _severity_from_response(data) is None

    def test_no_severity_fields(self):
        assert _severity_from_response({}) is None
        assert _severity_from_response({"database_specific": {}}) is None

    def test_database_specific_non_dict_ignored(self):
        # API returns unexpected type for database_specific — must not raise.
        assert _severity_from_response({"database_specific": "HIGH"}) is None
        assert _severity_from_response({"database_specific": 42}) is None

    def test_severity_non_list_ignored(self):
        # API returns a dict instead of a list for severity — must not raise.
        assert _severity_from_response({"severity": {"type": "CVSS_V3", "score": 7.5}}) is None

    def test_severity_list_with_non_dict_entries_skipped(self):
        # Mix of valid and invalid entries — invalid skipped, valid processed.
        data = {"severity": [
            "not-a-dict",
            {"type": "CVSS_V3", "score": 7.5},
        ]}
        assert _severity_from_response(data) == "HIGH"

    def test_numeric_float_score(self):
        data = {"severity": [{"type": "CVSS_V3", "score": 7.5}]}
        assert _severity_from_response(data) == "HIGH"

    def test_numeric_string_score(self):
        data = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        assert _severity_from_response(data) == "HIGH"

    def test_vector_without_cvss_prefix(self):
        # Vector missing the "CVSS:3.1/" prefix — still parseable
        data = {"severity": [{"type": "CVSS_V3", "score": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}
        assert _severity_from_response(data) == "HIGH"

    def test_cvss_v4_numeric_score_accepted(self):
        # CVSS_V4 numeric score — accepted and mapped to label.
        data = {"severity": [{"type": "CVSS_V4", "score": 9.3}]}
        assert _severity_from_response(data) == "CRITICAL"

    def test_multiple_entries_returns_highest(self):
        # LOW vector first, CRITICAL numeric second — must return CRITICAL.
        data = {"severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
            {"type": "CVSS_V3", "score": 9.8},
        ]}
        assert _severity_from_response(data) == "CRITICAL"

    def test_multiple_entries_order_independent(self):
        # Same two entries in reversed order — result must be the same.
        data = {"severity": [
            {"type": "CVSS_V3", "score": 9.8},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
        ]}
        assert _severity_from_response(data) == "CRITICAL"

    def test_cvss_v4_vector_string_not_parsed(self, caplog):
        # CVSS_V4 vector strings are not parsed with the v3 formula — return None
        # rather than produce a potentially wrong label, and emit a warning so we
        # know when it's worth implementing a v4 parser.
        import logging
        data = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}
        with caplog.at_level(logging.WARNING, logger="packagealert.osv.client"):
            result = _severity_from_response(data)
        assert result is None
        assert any("CVSS_V4" in r.message for r in caplog.records)

    def test_unknown_type_skipped(self):
        data = {"severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]}
        assert _severity_from_response(data) is None

    def test_cvss_v3_malformed_vector_returns_none(self):
        # type is CVSS_V3 but the vector is garbage — _cvss3_label() returns None,
        # _severity_from_response() must propagate that as None, not raise or
        # return a misleading label.
        data = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/GARBAGE"}]}
        assert _severity_from_response(data) is None

    def test_cvss_v3_empty_score_returns_none(self):
        data = {"severity": [{"type": "CVSS_V3", "score": ""}]}
        assert _severity_from_response(data) is None


# ---------------------------------------------------------------------------
# _numeric_score_label
# ---------------------------------------------------------------------------

class TestNumericScoreLabel:
    @pytest.mark.parametrize("score,expected", [
        (0.0, "NONE"),
        (0.1, "LOW"),
        (3.9, "LOW"),
        (4.0, "MEDIUM"),
        (6.9, "MEDIUM"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
        (10.0, "CRITICAL"),
    ])
    def test_boundaries(self, score, expected):
        assert _numeric_score_label(score) == expected

    @pytest.mark.parametrize("score", [
        float("nan"),
        float("inf"),
        float("-inf"),
        -0.1,
        10.1,
    ])
    def test_invalid_scores_return_none(self, score):
        assert _numeric_score_label(score) is None


# ---------------------------------------------------------------------------
# Severity wired into _parse_batch_response (batch query path)
# ---------------------------------------------------------------------------

@respx.mock
@pytest.mark.asyncio
async def test_batch_query_pysec_severity_from_cvss(osv_client):
    # Simulate a PYSEC advisory in the batch response that carries only a CVSS
    # vector — no database_specific.  The enrichment path fetches the full record.
    batch_response = {
        "results": [
            {"vulns": [{"id": "PYSEC-2026-213", "modified": "2026-01-01T00:00:00Z"}]}
        ]
    }
    full_advisory = {
        "id": "PYSEC-2026-213",
        "summary": "ReDoS in minimatch",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    }
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=batch_response)
    )
    respx.get("https://api.osv.dev/v1/vulns/PYSEC-2026-213").mock(
        return_value=httpx.Response(200, json=full_advisory)
    )

    results = await osv_client.batch_query([("pypi", "somelib", "1.0.0")])
    adv = results[0].advisories[0]
    assert adv.severity == "HIGH"


@respx.mock
@pytest.mark.asyncio
async def test_batch_query_ghsa_severity_from_database_specific(osv_client):
    # GHSA advisory in the batch response — severity via database_specific.
    batch_response = {
        "results": [
            {"vulns": [{"id": "GHSA-test-1111-aaaa", "modified": "2026-01-01T00:00:00Z",
                        "database_specific": {"severity": "CRITICAL"}}]}
        ]
    }
    full_advisory = {
        "id": "GHSA-test-1111-aaaa",
        "summary": "Critical vuln",
        "database_specific": {"severity": "CRITICAL"},
    }
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=batch_response)
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-test-1111-aaaa").mock(
        return_value=httpx.Response(200, json=full_advisory)
    )

    results = await osv_client.batch_query([("npm", "somelib", "1.0.0")])
    adv = results[0].advisories[0]
    assert adv.severity == "CRITICAL"
