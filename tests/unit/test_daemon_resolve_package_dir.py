"""Tests for daemon._resolve_package_dir's manifest-warning plumbing.

REGRESSION context: LanguageBase.resolve_package_dir_manifest_warning surfaces
when a distribution's RECORD exists but could not be parsed (e.g. a corrupt
manifest crafted to evade source-code heuristics via _record_paths_by_top_level
returning _RECORD_CORRUPT — see packagealert/languages/python.py). Without this
wiring, resolve_package_dir correctly refusing to guess a directory for such a
manifest is indistinguishable from an ordinary clean scan.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from packagealert.daemon import _resolve_package_dir
from packagealert.models.events import PackageEvent


def _event(ecosystem: str = "pypi", site_packages_dir: Path | None = None) -> PackageEvent:
    return PackageEvent(
        ecosystem=ecosystem,
        package_name="acme",
        version="1.0.0",
        source="process",
        manager="pip",
        project_path=None,
        timestamp=datetime.now(UTC),
        site_packages_dir=site_packages_dir,
    )


def test_resolve_package_dir_returns_both_dirs_and_warning(tmp_path: Path) -> None:
    sp = tmp_path / "site-packages"
    sp.mkdir()
    lang = MagicMock()
    lang.resolve_package_dir.return_value = [sp / "acme"]
    lang.resolve_package_dir_manifest_warning.return_value = "RECORD unreadable"

    with patch("packagealert.daemon.lang_registry.for_ecosystem", return_value=lang):
        dirs, warning = _resolve_package_dir(_event(site_packages_dir=sp))

    assert dirs == [sp / "acme"]
    assert warning == "RECORD unreadable"


def test_resolve_package_dir_warning_present_even_when_no_dirs_resolved(tmp_path: Path) -> None:
    """The exact corrupt-manifest scenario: resolve_package_dir correctly
    returns [] (nothing safe to report), but the warning must still surface."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    lang = MagicMock()
    lang.resolve_package_dir.return_value = []
    lang.resolve_package_dir_manifest_warning.return_value = "RECORD unreadable"

    with patch("packagealert.daemon.lang_registry.for_ecosystem", return_value=lang):
        dirs, warning = _resolve_package_dir(_event(site_packages_dir=sp))

    assert dirs == []
    assert warning == "RECORD unreadable"


def test_resolve_package_dir_no_warning_hook_defaults_to_none(tmp_path: Path) -> None:
    """A plugin without the hook (pre-v5, unshimmed in this direct-mock test)
    must not raise — getattr's callable guard degrades to no warning."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    lang = MagicMock(spec=["resolve_package_dir"])
    lang.resolve_package_dir.return_value = [sp / "acme"]

    with patch("packagealert.daemon.lang_registry.for_ecosystem", return_value=lang):
        dirs, warning = _resolve_package_dir(_event(site_packages_dir=sp))

    assert dirs == [sp / "acme"]
    assert warning is None


def test_resolve_package_dir_manifest_warning_raising_does_not_abort(tmp_path: Path) -> None:
    """A raising manifest-warning hook must not break the whole resolution —
    dirs already found by resolve_package_dir are still returned."""
    sp = tmp_path / "site-packages"
    sp.mkdir()
    lang = MagicMock()
    lang.resolve_package_dir.return_value = [sp / "acme"]
    lang.resolve_package_dir_manifest_warning.side_effect = RuntimeError("plugin exploded")

    with patch("packagealert.daemon.lang_registry.for_ecosystem", return_value=lang):
        dirs, warning = _resolve_package_dir(_event(site_packages_dir=sp))

    assert dirs == [sp / "acme"]
    assert warning is None


def test_resolve_package_dir_cache_source_skips_everything() -> None:
    """Only process-monitor events have an extracted directory to inspect."""
    event = PackageEvent(
        ecosystem="pypi",
        package_name="acme",
        version="1.0.0",
        source="cache",
        manager="pip",
        project_path=None,
        timestamp=datetime.now(UTC),
    )
    dirs, warning = _resolve_package_dir(event)
    assert dirs == []
    assert warning is None
