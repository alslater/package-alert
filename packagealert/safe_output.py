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


# A URL runs to the next whitespace: ";" and "@" can be part of its credentials. Its userinfo
# runs to the last "@" before the authority ends, whitespace included, so no part of a
# password with a space in it is left after the redacted URL.
_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#]*@)?\S*")


def _redact_url(url: str) -> str:
    """*url* with credentials hidden: userinfo and a query replaced by ``REDACTED``, and a URL
    that cannot be parsed or whose path holds what looks like a token replaced whole. A local
    ``file:`` URL, or one with none of these, is left as it is."""
    from urllib.parse import urlsplit, urlunsplit

    from packagealert.languages.python_tools import safe_source_url

    prefix = "git+" if url.startswith("git+") else ""
    try:
        parts = urlsplit(url.removeprefix("git+"))
        has_userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        return "REDACTED-URL"
    if parts.scheme == "file":
        return url
    if safe_source_url(url) is None:
        return "REDACTED-URL"
    netloc = "REDACTED@" + parts.netloc.rsplit("@", 1)[1] if has_userinfo else parts.netloc
    return prefix + urlunsplit((parts.scheme, netloc, parts.path, "REDACTED" if parts.query else "", parts.fragment))


def redacted(argv: list[str]) -> list[str]:
    """*argv* for display (printed commands, banners, logs): each URL in it with credentials
    hidden (``_redact_url()``). The command itself is run with *argv* as it is."""
    return [redacted_text(a) for a in argv]


# What can close a URL quoted in a message (`…`, '…', "…", (from …), <…>, […], end of a
# sentence or clause, `'…': error`): left out of the URL, so a token ending its path is still
# recognised as one.
_URL_CLOSERS = "`'\")>],.:;"


def _redact_match(url: str) -> str:
    core = url.rstrip(_URL_CLOSERS)
    return _redact_url(core) + url[len(core):]


def redacted_text(text: str) -> str:
    """*text* for display with each URL in it redacted as ``redacted()`` does."""
    return _URL_RE.sub(lambda m: _redact_match(m.group(0)), text)
