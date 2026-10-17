"""Keep text from registries, advisory databases and projects from steering the terminal.

Package names, yank reasons, deprecation messages and OSV summaries are written by whoever
publishes a package. Rich strips only BEL, BS, VT, FF and CR, so ESC- and CSI-introduced
sequences in that text would reach the terminal: rewriting its title, clearing the screen to
hide a warning, recolouring output, or (OSC 8, OSC 52) adding hyperlinks or writing the clipboard.

Every rich Console in the package comes from make_console() or passes through harden(), which
strips control characters from the text of each segment the console renders. The filter wraps
Console.render() rather than using a render hook: Console.print() sends every renderable through
it, including those a later hook adds (a Live or Status display), whereas a hook only sees what
earlier hooks passed it. Rich's own styling and cursor control are separate (style codes and
control segments), so they are unaffected.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from rich.console import Console, ConsoleOptions, RenderableType
from rich.segment import Segment

# C0 controls other than tab and newline, DEL, and C1 controls (0x9b is a one-byte CSI).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_HARDENED = "_package_alert_hardened"


def strip_control(text: str) -> str:
    """*text* without C0 (except tab and newline), DEL and C1 control characters."""
    return _CONTROL_RE.sub("", text)


def _strip_segments(segments: Iterable[Segment]) -> Iterable[Segment]:
    for segment in segments:
        if segment.control or not _CONTROL_RE.search(segment.text):
            yield segment
        else:
            yield Segment(strip_control(segment.text), segment.style)


def harden(console: Console) -> Console:
    """Install the control-character filter on *console* (idempotent) and return it."""
    if getattr(console, _HARDENED, False):
        return console
    render = console.render

    def safe_render(renderable: RenderableType, options: ConsoleOptions | None = None) -> Iterable[Segment]:
        return _strip_segments(render(renderable, options))

    setattr(console, "render", safe_render)  # noqa: B010 — shadows the method on this instance only
    setattr(console, _HARDENED, True)
    return console


def make_console(*args: Any, **kwargs: Any) -> Console:
    """A rich Console with harden() applied; takes Console's arguments."""
    return harden(Console(*args, **kwargs))
