from datetime import UTC, datetime
from pathlib import Path

from packagealert.models.advisories import OsvAdvisory, OsvResult
from packagealert.models.events import PackageEvent
from packagealert.models.risk import RiskReport, RiskSignal


def test_package_event_defaults():
    ev = PackageEvent(
        ecosystem="pypi",
        package_name="requests",
        version="2.31.0",
        source="process",
        manager="pip",
        project_path=None,
        timestamp=datetime.now(UTC),
    )
    assert ev.package_name == "requests"
    assert ev.ecosystem == "pypi"


def test_package_event_normalizes_name():
    ev = PackageEvent(
        ecosystem="pypi",
        package_name="My_Package",
        version=None,
        source="cache",
        manager="uv",
        project_path=Path("/tmp"),
        timestamp=datetime.now(UTC),
    )
    assert ev.package_name == "my-package"


def test_osv_advisory_malicious_flag():
    adv = OsvAdvisory(
        id="MAL-2025-1234",
        summary="Credential stealer",
        severity="CRITICAL",
        aliases=[],
    )
    assert adv.is_malicious is True


def test_osv_advisory_alias_malicious():
    adv = OsvAdvisory(id="GHSA-xxxx", summary="Bad", aliases=["MAL-2025-9999"])
    assert adv.is_malicious is True


def test_osv_result_has_malicious():
    result = OsvResult(
        package_name="evil",
        ecosystem="pypi",
        version="1.0",
        advisories=[OsvAdvisory(id="MAL-2025-1", summary="bad", severity="CRITICAL", aliases=[])],
    )
    assert result.has_malicious is True


def test_osv_result_clean():
    result = OsvResult(package_name="safe", ecosystem="npm", version="1.0", advisories=[])
    assert result.has_malicious is False


def test_risk_report_critical():
    report = RiskReport(
        package_name="evil-pkg",
        ecosystem="npm",
        score=82,
        signals=[
            RiskSignal(name="postinstall", score=20, reason="postinstall script found"),
            RiskSignal(name="obfuscated_js", score=25, reason="eval() detected"),
        ],
    )
    assert report.level == "critical"


def test_risk_report_warning():
    report = RiskReport(package_name="x", ecosystem="npm", score=45, signals=[])
    assert report.level == "warning"


def test_risk_report_info():
    report = RiskReport(package_name="x", ecosystem="npm", score=20, signals=[])
    assert report.level == "info"
