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

import pytest

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


@pytest.mark.asyncio
async def test_daemon_scores_independent_copies_one_at_a_time(tmp_path):
    """The daemon's risk pass keeps the highest copy's report rather than summing
    signals across independent copies (install script 20 + eval 25 = 45)."""
    import json
    from datetime import UTC, datetime

    from packagealert.analyzers.risk import RiskEngine
    from packagealert.config import HeuristicsConfig
    from packagealert.daemon import _analyze_copies
    from packagealert.models.events import PackageEvent

    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0",
                                                "scripts": {"postinstall": "node setup.js"}}))
    (a / "setup.js").write_text("console.log(1)\n")
    (b / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0"}))
    (b / "index.js").write_text("eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString())\n")
    event = PackageEvent(ecosystem="npm", package_name="evilpkg", version="1.0.0", source="process",
                         manager="pnpm", project_path=None, timestamp=datetime.now(UTC))
    report = await _analyze_copies(RiskEngine(HeuristicsConfig()), event, [a, b], None, local_only=True)
    assert report.score == 25


@pytest.mark.asyncio
async def test_public_event_scores_a_non_public_copy_on_its_source(tmp_path):
    """A public process event whose name and version also resolve to a file: copy and a
    copy of unknown source in pnpm's store: only the registry copy is scored with the
    public package's metadata."""
    import json
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from packagealert.daemon import _analyze_copies

    store = tmp_path / "node_modules" / ".pnpm"
    shortened = ("n" * 86 + "@1.0.0_react@18.2.0")[:87] + "_" + "0123456789abcdef" * 2
    dirs = []
    for store_id, name in (("evilpkg@1.0.0", "evilpkg"), ("evilpkg@file+..+evilpkg-1.0.0.tgz", "evilpkg"),
                           (shortened, "evilpkg")):
        d = store / store_id / "node_modules" / name
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
        dirs.append(d)
    calls: list = []

    class Engine:
        async def analyze(self, event, package_dirs, manifest_warning=None, *, local_only=False):
            calls.append((package_dirs[0].parent.parent.name, local_only))
            return SimpleNamespace(score=0)

    event = PackageEvent(ecosystem="npm", package_name="evilpkg", version="1.0.0", source="process",
                         manager="pnpm", project_path=tmp_path, timestamp=datetime.now(UTC))
    await _analyze_copies(Engine(), event, dirs, None)
    assert dict(calls) == {"evilpkg@1.0.0": False, "evilpkg@file+..+evilpkg-1.0.0.tgz": True, shortened: True}


@pytest.mark.asyncio
async def test_public_event_whose_only_copy_is_a_file_copy_is_scored_on_its_source(tmp_path):
    import json
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from packagealert.daemon import _analyze_copies

    d = tmp_path / "node_modules" / ".pnpm" / "evilpkg@file+..+evilpkg-1.0.0.tgz" / "node_modules" / "evilpkg"
    d.mkdir(parents=True)
    (d / "package.json").write_text(json.dumps({"name": "evilpkg", "version": "1.0.0"}))
    seen: list = []

    class Engine:
        async def analyze(self, event, package_dirs, manifest_warning=None, *, local_only=False):
            seen.append(local_only)
            return SimpleNamespace(score=0)

    event = PackageEvent(ecosystem="npm", package_name="evilpkg", version="1.0.0", source="process",
                         manager="pnpm", project_path=tmp_path, timestamp=datetime.now(UTC))
    await _analyze_copies(Engine(), event, [d], None)
    assert seen == [True]


@pytest.mark.asyncio
async def test_a_failing_copy_does_not_discard_a_siblings_finding(tmp_path):
    """One copy's scoring raising (a popularity-cache read, say) keeps the other copy's
    report; only when every copy fails does the error propagate."""
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from packagealert.daemon import _analyze_copies

    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()

    class Engine:
        def __init__(self, failing):
            self.failing = failing

        async def analyze(self, event, package_dirs, manifest_warning=None, *, local_only=False):
            if package_dirs[0] in self.failing:
                raise OSError("popularity cache unreadable")
            return SimpleNamespace(score=80)

    event = PackageEvent(ecosystem="npm", package_name="evilpkg", version="1.0.0", source="process",
                         manager="pnpm", project_path=tmp_path, timestamp=datetime.now(UTC))
    report = await _analyze_copies(Engine({a}), event, [a, b], None)
    assert report.score == 80
    with pytest.raises(OSError):
        await _analyze_copies(Engine({a, b}), event, [a, b], None)
