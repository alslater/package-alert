"""Registry and advisory text must not reach the terminal as control sequences (#79)."""

from __future__ import annotations

import ast
import io
import logging
from datetime import UTC
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from rich.table import Table

from packagealert.config import AppConfig
from packagealert.models.advisories import OsvAdvisory, OsvResult
from packagealert.safe_output import harden, make_console, strip_control

# The issue's payload: an OSC title change, clear screen, an SGR colour, a C1 CSI and a DEL.
EVIL = "\x1b]0;pwned-title\x07 \x1b[2Jcleared \x1b[31mred \x9b31mc1 \x7fend"
INJECTED = ("\x1b", "\x07", "\x9b", "\x7f")


def _clean(text: str) -> bool:
    return not any(c in text for c in INJECTED)


def test_strip_control_removes_c0_c1_and_del_but_keeps_text_newlines_and_tabs():
    out = strip_control(EVIL + "\nline\ttab ünïcode ✓")
    assert _clean(out)
    assert "pwned-title" in out and "cleared" in out and "\nline\ttab ünïcode ✓" in out
    assert strip_control("plain") == "plain"
    assert strip_control("a\rb\x00c\x1fd\x85e") == "abcde"


def _terminal_console() -> tuple:
    buf = io.StringIO()
    return make_console(file=buf, force_terminal=True, color_system="truecolor", width=200), buf


def test_console_strips_injected_sequences_and_keeps_its_own_styling():
    console, buf = _terminal_console()
    console.print(f"[red]ours[/red] {EVIL}", markup=True)
    console.print(EVIL, markup=False, style="bold")
    out = buf.getvalue()
    assert "\x1b[31m" not in out.replace("\x1b[31mours", "")  # only Rich's own red, around "ours"
    assert "\x1b]0;" not in out and "\x1b[2J" not in out and "\x9b" not in out and "\x07" not in out
    assert "\x1b[1m" in out  # Rich's bold still rendered
    assert "pwned-title" in out and "cleared" in out


def test_console_strips_nested_renderables():
    console, buf = _terminal_console()
    table = Table("name", "summary")
    table.add_row("pkg", EVIL)
    console.print(table)
    out = buf.getvalue()
    assert "\x1b]0;" not in out and "\x1b[2J" not in out and "\x9b" not in out and "cleared" in out


@pytest.mark.parametrize("display", ["status", "live"])
def test_live_and_status_displays_are_filtered(display):
    # Live and Status push their own render hook after the console exists, so a filter applied
    # by a hook never saw the display they add (the pre-flight status, pa fix's spinner).
    import time

    from rich.live import Live
    from rich.text import Text

    console, buf = _terminal_console()
    if display == "status":
        with console.status(f"checking {EVIL}"):
            time.sleep(0.3)
    else:
        with Live(Text(f"fixing {EVIL}"), console=console, refresh_per_second=20):
            time.sleep(0.3)
    out = buf.getvalue()
    assert "cleared" in out
    assert "\x1b]0;" not in out and "\x1b[2J" not in out and "\x9b" not in out and "\x07" not in out


def test_harden_is_idempotent():
    console, buf = _terminal_console()
    assert harden(harden(console)) is console
    console.print("x")
    assert buf.getvalue().count("x") == 1


def test_every_console_in_the_package_is_hardened():
    """No bare rich Console(): each must come from make_console() or pass through harden()."""
    root = Path(__file__).resolve().parents[2] / "packagealert"
    offenders = []
    for path in root.rglob("*.py"):
        if path.name == "safe_output.py":
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                if name in {"Console", "_Console", "RichConsole"}:
                    offenders.append(f"{path.relative_to(root.parent)}:{node.lineno}")
    assert offenders == []


# --- the places external text is shown ---------------------------------------------------------


def _event():
    from datetime import datetime

    from packagealert.models.events import PackageEvent

    return PackageEvent(ecosystem="pypi", package_name="evilpkg", version="1.0.0", source="process",
                        manager="pip", project_path=None, timestamp=datetime.now(UTC))


async def test_pa_query_output_is_clean(capsys):
    from packagealert.cli.app import _run_query

    class _DB:
        async def close(self):
            pass

    async def _open_db(*_a, **_k):
        return _DB()

    class _NoCache:
        def __init__(self, *_a, **_k):
            pass

        async def get(self, *_a, **_k):
            return None

        async def set(self, *_a, **_k):
            return None

    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "MAL-2026-1"}]}]}))
        respx.get("https://api.osv.dev/v1/vulns/MAL-2026-1").mock(return_value=httpx.Response(
            200, json={"id": "MAL-2026-1", "summary": EVIL, "details": EVIL}))
        with (
            patch("packagealert.storage.db.open_db", _open_db),
            patch("packagealert.osv.cache.OsvCache", _NoCache),
        ):
            await _run_query(AppConfig(), "pypi", "evilpkg", "1.0.0")
    out = capsys.readouterr().out
    assert "cleared" in out  # the summary was shown
    assert _clean(out)


async def test_scan_project_text_output_is_clean(capsys, tmp_path):
    import sys

    from packagealert.cli.app import _run_scan_project

    sys.path.insert(0, "tests/unit")
    from test_config import _make_fake_osv

    (tmp_path / "requirements.txt").write_text("django==5.2.15\n")
    fake_open_db, FakeOsvClient, FakeOsvCache = _make_fake_osv()
    FakeOsvCache.return_value.get = AsyncMock(return_value=None)
    FakeOsvCache.return_value.set = AsyncMock()
    FakeOsvClient.return_value.batch_query = AsyncMock(return_value=[OsvResult(
        package_name="django", ecosystem="pypi", version="5.2.15",
        advisories=[OsvAdvisory(id="GHSA-1", summary=EVIL, details=EVIL, severity="HIGH",
                                fixed_versions=["5.2.17"])],
    )])
    with (
        patch("packagealert.storage.db.open_db", fake_open_db),
        patch("packagealert.osv.client.OsvClient", FakeOsvClient),
        patch("packagealert.osv.cache.OsvCache", FakeOsvCache),
        patch("packagealert.cli.app._recommendation_ages", AsyncMock(return_value={})),
    ):
        await _run_scan_project(AppConfig(), tmp_path, scan_unpinned=False, installed=False,
                                show_details=True, fmt="text", no_risk=True, no_yank=True)
    out = capsys.readouterr().out
    assert "cleared" in out
    assert _clean(out)


def test_terminal_alert_is_clean(capsys):
    from packagealert.alerts import terminal

    event = _event()
    result = OsvResult(package_name="evilpkg", ecosystem="pypi", version="1.0.0",
                       advisories=[OsvAdvisory(id="MAL-2026-1", summary=EVIL)])
    terminal.alert_malicious(event, result)
    err = capsys.readouterr().err
    assert "cleared" in err
    assert _clean(err)


def test_html_report_is_clean(tmp_path):
    from packagealert.cli.app import _render_html
    from packagealert.yanks import YankedVersion

    finding = {"advisory_id": "MAL-1", "package": "evilpkg", "ecosystem": "PyPI", "version": "1.0.0",
               "fixed_versions": [], "affected_ranges": [], "is_malicious": True, "severity": None,
               "summary": EVIL, "details": EVIL, "url": "https://osv.dev/vulnerability/MAL-1"}
    yank = YankedVersion("PyPI", "other", "2.0", EVIL).as_dict()
    html = _render_html(tmp_path, [], [], [finding], yanked=[yank])
    assert "cleared" in html
    assert _clean(html)


async def test_desktop_notification_is_clean():
    from packagealert.alerts import desktop

    event = _event()
    result = OsvResult(package_name="evilpkg", ecosystem="pypi", version="1.0.0",
                       advisories=[OsvAdvisory(id="MAL-2026-1", summary=EVIL)])
    proc = AsyncMock()
    proc.wait = AsyncMock(return_value=0)
    spawn = AsyncMock(return_value=proc)
    with patch("packagealert.alerts.desktop.shutil.which", return_value="/usr/bin/notify-send"), \
         patch("packagealert.alerts.desktop.asyncio.create_subprocess_exec", spawn):
        await desktop.notify_malicious(event, result)
    argv = " ".join(spawn.call_args.args)
    assert "notify-send" in argv and "cleared" in argv
    assert _clean(argv)


def test_log_handler_console_is_clean(tmp_path, capsys):
    from packagealert.config import LogConfig
    from packagealert.logging_setup import configure_logging

    configure_logging(LogConfig(file=None, level="WARNING"))
    try:
        logging.getLogger("packagealert.test").warning("yank reason: %s", EVIL)
        captured = capsys.readouterr()
        err = captured.out + captured.err
    finally:
        logging.basicConfig(handlers=[logging.NullHandler()], force=True)
    assert "cleared" in err
    assert _clean(err)


async def test_sandbox_runner_hardens_an_injected_console(tmp_path):
    from rich.console import Console

    from packagealert.sandbox.runner import SandboxRunner

    buf = io.StringIO()
    runner = SandboxRunner(AppConfig(), console=Console(file=buf, width=200))
    runner._console.print(f"  pkg==1.0: {EVIL}", markup=False)
    assert "cleared" in buf.getvalue()
    assert _clean(buf.getvalue())


@pytest.mark.parametrize("payload", [EVIL])
def test_payload_is_actually_dangerous_without_hardening(payload):
    """Control: a plain Rich console passes the sequences through (the bug in #79)."""
    from rich.console import Console

    buf = io.StringIO()
    Console(file=buf, force_terminal=True, width=200).print(payload, markup=False, highlight=False)
    assert "\x1b]0;" in buf.getvalue() and "\x1b[2J" in buf.getvalue()
