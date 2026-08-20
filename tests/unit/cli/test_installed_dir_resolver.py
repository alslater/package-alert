"""Tests for cli/app.py's _installed_dir_resolver — the --scan-installed path
resolver used by score_packages.

REGRESSION context: the path resolver and the manifest-warning resolver it now
also returns must correlate correctly, so a distribution with a corrupt
RECORD in one environment still surfaces its unverifiable_manifest signal even
when a healthy copy in another environment resolves real directories and wins
the score competition (see packagealert/scoring.py's manifest_warning_resolver
and packagealert/languages/python.py's _RECORD_CORRUPT).
"""
from __future__ import annotations

import csv
from pathlib import Path

from packagealert.cli.app import _installed_dir_resolver


def _make_venv_site_packages(root: Path, venv_name: str) -> Path:
    sp = root / venv_name / "lib" / "python3.12" / "site-packages"
    sp.mkdir(parents=True)
    return sp


def test_resolver_pair_returns_paths_and_none_warning_for_a_healthy_record(tmp_path: Path) -> None:
    sp = _make_venv_site_packages(tmp_path, "venv")
    dist_info = sp / "acme-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "RECORD").write_text("acme/__init__.py,sha256=abc,100\n")
    (sp / "acme").mkdir()

    resolve, resolve_warning = _installed_dir_resolver(tmp_path)
    groups = resolve("pypi", "acme", "1.0.0")
    warning = resolve_warning("pypi", "acme", "1.0.0")

    assert groups == [[sp / "acme"]]
    assert warning is None


def test_resolver_pair_surfaces_warning_for_a_corrupt_record(tmp_path: Path) -> None:
    """The exact reported scenario: a corrupt RECORD resolves to no directories,
    but the manifest warning must still be resolvable for the same key."""
    sp = _make_venv_site_packages(tmp_path, "venv")
    dist_info = sp / "acme-1.0.0.dist-info"
    dist_info.mkdir()
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (dist_info / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")
    (sp / "acme").mkdir()
    (sp / "acme" / "plugin.py").write_text("# plugin")

    resolve, resolve_warning = _installed_dir_resolver(tmp_path)
    groups = resolve("pypi", "acme", "1.0.0")
    warning = resolve_warning("pypi", "acme", "1.0.0")

    assert groups == []
    assert warning is not None
    assert "RECORD" in warning


def test_resolver_pair_warning_survives_a_healthy_copy_in_another_environment(tmp_path: Path) -> None:
    """The reviewer's exact scenario: one venv has a corrupt RECORD (resolves
    to no directories for that environment), another has a healthy copy of
    the same name/version. The path resolver still returns the healthy
    environment's group, and the warning resolver still reports the
    corrupt environment's problem for the same (ecosystem, name, version)."""
    sp_bad = _make_venv_site_packages(tmp_path, ".venv")
    dist_info_bad = sp_bad / "acme-1.0.0.dist-info"
    dist_info_bad.mkdir()
    huge_field = "a" * (csv.field_size_limit() + 1000)
    (dist_info_bad / "RECORD").write_text(f"{huge_field},sha256=abc,100\n")
    (sp_bad / "acme").mkdir()

    sp_good = _make_venv_site_packages(tmp_path, "env")
    dist_info_good = sp_good / "acme-1.0.0.dist-info"
    dist_info_good.mkdir()
    (dist_info_good / "RECORD").write_text("acme/__init__.py,sha256=abc,100\n")
    (sp_good / "acme").mkdir()

    resolve, resolve_warning = _installed_dir_resolver(tmp_path)
    groups = resolve("pypi", "acme", "1.0.0")
    warning = resolve_warning("pypi", "acme", "1.0.0")

    # Only the healthy environment contributes a real candidate group.
    assert groups == [[sp_good / "acme"]]
    # But the corrupt environment's warning is not lost.
    assert warning is not None
    assert "RECORD" in warning


def test_resolver_pair_no_warning_when_nothing_is_corrupt(tmp_path: Path) -> None:
    _resolve, resolve_warning = _installed_dir_resolver(tmp_path)
    assert resolve_warning("pypi", "nonexistent", "1.0.0") is None
