from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from packagealert.cli.app import _render_html, _run_scan_project
from packagealert.config import load_config
from packagealert.yanks import YankedVersion

from .test_recommendation_ages import _scan_with_a_vulnerable_django

DJANGO = YankedVersion("PyPI", "django", "5.2.15", "Setup blunder")


async def _scan(tmp_path, fmt, *, found=(DJANGO,), failures=0, **kw):
    a, b, c = _scan_with_a_vulnerable_django(tmp_path)
    check = AsyncMock(return_value=(list(found), failures))
    with a, b, c, patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})), \
            patch("packagealert.yanks.check_yanks", check):
        await _run_scan_project(load_config(None), tmp_path, scan_unpinned=False, installed=False,
                                show_details=False, fmt=fmt, no_risk=True, **kw)
    return check


async def test_scan_json_carries_yanks(tmp_path, capsys):
    await _scan(tmp_path, "json")
    out = json.loads(capsys.readouterr().out)
    assert out["yanked"] == [DJANGO.as_dict()] and out["yank_failures"] == 0
    assert out["findings"]  # the advisory is still reported as before


async def test_scan_text_lists_yanks(tmp_path, capsys):
    await _scan(tmp_path, "text")
    out = capsys.readouterr().out
    assert "Yanked versions (1):" in out and "django 5.2.15 — Setup blunder" in out


async def test_yank_failures_are_reported(tmp_path, capsys):
    await _scan(tmp_path, "text", found=(), failures=3)
    assert "Yank status unavailable for 3 package(s)" in capsys.readouterr().out


async def test_yank_reason_is_printed_literally(tmp_path, capsys):
    await _scan(tmp_path, "text", found=(YankedVersion("PyPI", "django", "5.2.15", "[red]x[/red] <b>"),))
    assert "[red]x[/red] <b>" in capsys.readouterr().out


async def test_no_yank_skips_the_check(tmp_path, capsys):
    check = await _scan(tmp_path, "json", no_yank=True)
    check.assert_not_awaited()
    out = json.loads(capsys.readouterr().out)
    assert out["yanked"] == [] and out["yank_failures"] == 0


async def test_scan_result_carries_yanks_to_plugins(tmp_path):
    fired = AsyncMock()
    with patch("packagealert.cli.app.plugin_registry.fire_on_scan_complete", fired):
        await _scan(tmp_path, "json")
    assert fired.await_args is not None
    [scan] = fired.await_args.args
    assert scan.yanked == [DJANGO.as_dict()] and scan.finding_count == 1


def test_html_escapes_yank_reason():
    html = _render_html(Path("/p"), ["pypi (requirements.txt)"], [], [],
                        yanked=[YankedVersion("PyPI", "x", "1.0", "<script>a</script>").as_dict()], yank_failures=2)
    assert "<script>a</script>" not in html and "&lt;script&gt;" in html
    assert "Yanked versions" in html and "2 yank-unchecked" in html


async def test_installed_scan_does_not_check_yanks(tmp_path, capsys):
    # Installed packages record no index, so a private one could be matched to an
    # unrelated public project; yanks are reported for locked versions only.
    from packagealert.parsers.lockfiles import LockedPackage, ProjectScan

    a, b, c = _scan_with_a_vulnerable_django(tmp_path)
    check = AsyncMock(return_value=([DJANGO], 0))
    installed = ProjectScan(sources=["pypi (.venv)"], pinned=[LockedPackage("django", "5.2.15", "pypi")], unpinned=[])
    with a, b, c, patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})), \
            patch("packagealert.yanks.check_yanks", check), \
            patch("packagealert.parsers.lockfiles.scan_installed", return_value=installed):
        await _run_scan_project(load_config(None), tmp_path, scan_unpinned=False, installed=True,
                                show_details=False, fmt="json", no_risk=True)
    check.assert_not_awaited()
    out = json.loads(capsys.readouterr().out)
    assert out["yanked"] == [] and out["yank_failures"] == 0 and out["findings"]
