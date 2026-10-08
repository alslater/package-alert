"""Run-and-read helpers for `uv lock --dry-run` trial resolves.

uv writes all of a dry run's output to stderr. On success (exit 0) it prints
`Resolved N packages …`, then one line per changed package: `Update <pkg>
<old versions> -> <new versions>`, `Add <pkg> <versions>`, `Remove <pkg>
<versions>`, or `No lockfile changes detected`. Each side is uv's sorted,
", "-joined set of `v<version>` tokens; several versions mean the package is
locked once per marker fork. When no resolution exists (exit 1) it prints `No solution found
when resolving dependencies` and an explanation naming each constraint. This
format is not a documented interface (audited against uv 0.12.23 — see the uv
audit in .claude/CLAUDE.md), so anything unrecognised makes the trial
inconclusive rather than being guessed at.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from packaging.version import InvalidVersion, Version

from packagealert.remediate.adapter import Blocker, Change, TrialResult, Yank

_UPDATE_RE = re.compile(r"^Update (\S+) (.+) -> (.+)\Z")
_ADD_RE = re.compile(r"^Add (\S+) (.+)\Z")
_REMOVE_RE = re.compile(r"^Remove (\S+) (.+)\Z")
_VERSION_RE = re.compile(r"v(\S+)")
_YANKED_RE = re.compile(r'^warning: `([^`=\s]+)==([^`\s]+)` is yanked(?: \(reason: "(.*)"\))?\Z')
_IGNORED_RE = re.compile(r"^(Using |warning: )")
_RESOLUTION_SUMMARY = re.compile(r"^(Resolved |No lockfile changes detected\Z)")
_NO_SOLUTION = "No solution found when resolving dependencies"
# `<parent><spec> depends on <dep><constraint>`; a parent written as
# `all of:` (a multi-line version list) has no name on this line and is skipped.
_DEPENDS_RE = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)([<>=!~][^\s,]*(?:,[<>=!~][^\s,]*)*)? depends on "
    r"([A-Za-z0-9][A-Za-z0-9._-]*)([<>=!~][^\s]*)"
)


def trial_argv(pins: list[tuple[str, str]], float_packages: Iterable[str] = ()) -> list[str]:
    """`uv lock --dry-run` with each pin exact and each float_packages entry free to move."""
    argv = ["uv", "lock", "--dry-run"]
    for name, version in pins:
        argv += ["--upgrade-package", f"{name}=={version}"]
    for name in float_packages:
        argv += ["--upgrade-package", name]
    return argv


def _versions(text: str) -> tuple[str, ...] | None:
    """uv's ascending ", "-joined version list; None if any token is not a plain vX."""
    out = []
    for token in text.split(", "):
        m = _VERSION_RE.fullmatch(token)
        if m is None:
            return None
        out.append(m.group(1))
    return tuple(out)


def _expand(action: str, name: str, old: tuple[str, ...], new: tuple[str, ...]) -> list[Change] | None:
    """Change records for one uv change line; None if its versions cannot be ordered.

    Each introduced version is paired with the old version just below it (a
    fork moving up), or with the lowest old version when it is below them all (a
    downgrade). Each dropped version is paired with the new version just above
    it, or the highest, so the fork it moved to is checked as well. A package
    locked at several versions afterwards carries them all in ``fork_versions``.
    """
    fork = new if len(new) > 1 else ()
    if action == "add":
        return [Change("add", name, None, v, fork) for v in new]
    if action == "remove":
        return [Change("remove", name, v, None) for v in old]
    try:
        key = {v: Version(v) for v in (*old, *new)}
    except InvalidVersion:
        return None
    pairs: list[tuple[str, str]] = []
    for v in new:
        if v not in old:
            below = [o for o in old if key[o] < key[v]]
            pairs.append((max(below, key=key.__getitem__) if below else min(old, key=key.__getitem__), v))
    for d in old:
        if d not in new:
            above = [n for n in new if key[n] > key[d]]
            pair = (d, min(above, key=key.__getitem__) if above else max(new, key=key.__getitem__))
            if pair not in pairs:
                pairs.append(pair)
    return [Change("update", name, o, n, fork) for o, n in pairs]


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _blocker(stderr: str, pinned: dict[str, str]) -> Blocker | None:
    """The last parent constraint on a pinned package that is not uv's echo of the pin."""
    found: Blocker | None = None
    targets = {_norm(k): v for k, v in pinned.items()}
    for m in _DEPENDS_RE.finditer(stderr):
        parent, dep, constraint = _norm(m.group(1)), _norm(m.group(3)), m.group(4).rstrip(",")
        if parent == "project" or dep not in targets:
            continue
        if constraint == f"=={targets[dep]}":
            continue  # uv restating the forced pin, not a real constraint
        found = Blocker(parent, f"{dep}{constraint}")
    return found


_MARKER_RE = re.compile(r"^(cause:|╰─▶)\s*")


def _explanation(stderr: str) -> str:
    """The first explanation line after uv's "No solution found" line, markers stripped."""
    lines = [ln.strip() for ln in stderr.splitlines()]
    for i, line in enumerate(lines):
        if _NO_SOLUTION not in line:
            continue
        for nxt in lines[i + 1 :]:
            if nxt:
                return _MARKER_RE.sub("", nxt) or line
        return line
    return ""


_ERROR_RE = re.compile(r"(?:error:|×)\s*(.+)")
_EXCEPTION_RE = re.compile(r"\s*([A-Za-z_][\w.]*(?:Error|Exception)): (.+)")


def _failure_detail(stderr: str) -> str:
    """uv's error line, with the last exception a failed build printed; "" if uv printed none.

    uv ends a failure with generic hints, so the last line rarely says what went
    wrong; its first `error:` line (`×` on a terminal) names the failing step,
    and a build backend's traceback ends with the actual cause.
    """
    lines = stderr.splitlines()
    head = next((m.group(1).strip() for ln in lines if (m := _ERROR_RE.fullmatch(ln.strip()))), "")
    if not head:
        return ""
    causes = [m for ln in lines if (m := _EXCEPTION_RE.fullmatch(ln))]
    return f"{head} ({causes[-1].group(1)}: {causes[-1].group(2).strip()})" if causes else head


def parse_trial(
    returncode: int,
    stderr: str,
    *,
    timed_out: bool = False,
    pinned: dict[str, str] | None = None,
) -> TrialResult:
    """Classify one captured trial; see the module docstring for the format."""
    if timed_out:
        return TrialResult("inconclusive", detail="the trial resolve timed out")
    if returncode != 0:
        if _NO_SOLUTION in stderr:
            return TrialResult(
                "blocked", blocker=_blocker(stderr, pinned or {}), detail=_explanation(stderr)
            )
        last = next((ln.strip() for ln in reversed(stderr.splitlines()) if ln.strip()), "")
        return TrialResult("inconclusive",
                           detail=_failure_detail(stderr) or last or f"uv exited with status {returncode}")
    changes: list[Change] = []
    yanked: list[Yank] = []
    saw_resolution_summary = False
    for raw in stderr.splitlines():
        line = raw.strip()
        if m := _YANKED_RE.match(line):
            yanked.append(Yank(_norm(m.group(1)), m.group(2), m.group(3)))
            continue
        if line.startswith("warning:") and "yank" in line.lower():
            # A yank warning in a format _YANKED_RE does not know: ignoring it
            # could approve a command that installs a yanked release.
            return TrialResult("inconclusive", detail=f"unrecognised uv yank warning: {line}")
        # Other warnings (deprecated settings, a VIRTUAL_ENV that is not the
        # project's) say nothing about what the resolution installs.
        if not line or _IGNORED_RE.match(line):
            continue
        if _RESOLUTION_SUMMARY.match(line):
            saw_resolution_summary = True
            continue
        if m := _UPDATE_RE.match(line):
            action, name, old, new = "update", m.group(1), _versions(m.group(2)), _versions(m.group(3))
        elif m := _ADD_RE.match(line):
            action, name, old, new = "add", m.group(1), (), _versions(m.group(2))
        elif m := _REMOVE_RE.match(line):
            action, name, old, new = "remove", m.group(1), _versions(m.group(2)), ()
        else:
            return TrialResult("inconclusive", detail=f"unrecognised uv output: {line}")
        if old is None or new is None:
            return TrialResult("inconclusive",
                               detail=f"uv changed {name}, a git-sourced or dynamic version pa fix cannot check")
        expanded = _expand(action, _norm(name), old, new)
        if expanded is None:
            return TrialResult("inconclusive", detail=f"cannot order the versions uv reported for {name}")
        changes.extend(expanded)
    if not saw_resolution_summary:
        return TrialResult("inconclusive", detail="no resolution summary in uv output")
    return TrialResult("resolved", changes=tuple(changes), yanked=tuple(yanked))
