"""`pa fix --tools --uv`: fix vulnerable packages in a uv tool environment.

A tool's ``uv-receipt.toml`` records what ``uv tool install`` was asked for:
the tool's requirement first, then each ``--with``, its ``python`` and its
``[tool.options]``. ``uv tool install --force`` resolves from scratch, so
every package it does not pin moves to its newest allowed version (measured
with uv 0.13.5: an installed pygments 2.15.0 became 2.21.0). It also ignores
the receipt's ``python`` and options, so the printed command carries them
over, and ``--python`` always: without it uv moved a 3.12 tool to 3.13. A pin
added with ``--with 'pkg==X'`` is recorded in the receipt, so a later
``uv tool upgrade`` keeps it.

The trial is ``uv pip install --dry-run --upgrade --python <tool venv>``
with the receipt's requirements and the pins: ``--upgrade`` drops the
preference for installed versions, so it resolves as the reinstall does,
and its changes are relative to what the tool has installed. Its output is
uv's dry-run report on stderr (``Resolved N packages``, then `` - name==old``
and `` + name==new`` lines, or ``Would make no changes``), not a documented
interface (audited against uv 0.13.5 — see the uv audit in .claude/CLAUDE.md),
so anything unrecognised makes the trial inconclusive. A receipt option this
module cannot carry over makes every fix held, since a command without it
would install from somewhere else.
"""

from __future__ import annotations

import dataclasses
import email.parser
import os
import re
import tomllib
import typing
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from packagealert import safe_read
from packagealert.languages.python_fix import uv_trial
from packagealert.languages.python_fix.tool_fix import (
    Baseline,
    Inventory,
    ToolState,
    first_write_dir,
    in_place,
    inventory,
    is_venv,
    measure_from_baseline,
    public_cadences,
    reread_env,
)
from packagealert.remediate.adapter import Change, LockfileError, TrialResult, Yank
from packagealert.remediate.graph import DependencyGraph
from packagealert.safe_output import redacted, redacted_text

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from packagealert.languages.base import PackageSpec
    from packagealert.languages.python_tools import ToolEnv
    from packagealert.remediate.adapter import TrialRunner
    from packagealert.remediate.planner import FixPlan, PlannedFix

RECEIPT = "uv-receipt.toml"

# Receipt options with the same meaning in `uv tool install` and `uv pip install`:
# (key, flag, kind). A "bool" is a bare flag when true; a "list" repeats the flag.
_OPTIONS: tuple[tuple[str, str, str], ...] = (
    ("index-url", "--index-url", "str"),
    ("extra-index-url", "--extra-index-url", "list"),
    ("no-index", "--no-index", "bool"),
    ("find-links", "--find-links", "list"),
    ("index-strategy", "--index-strategy", "str"),
    ("keyring-provider", "--keyring-provider", "str"),
    ("resolution", "--resolution", "str"),
    ("prerelease", "--prerelease", "str"),
    ("exclude-newer", "--exclude-newer", "str"),
    ("link-mode", "--link-mode", "str"),
    ("compile-bytecode", "--compile-bytecode", "bool"),
    ("no-build", "--no-build", "bool"),
)
# `uv tool install --no-binary` is a flag; `uv pip install` takes a value.
_NO_BINARY = "no-binary"
_VALUE_FLAGS = frozenset(flag for _, flag, kind in _OPTIONS if kind != "bool")
_BOOL_FLAGS = frozenset(flag for _, flag, kind in _OPTIONS if kind == "bool")


class ReceiptError(LockfileError):
    """A uv-receipt.toml that cannot be read as a tool's record."""


def _norm(name: str) -> str:
    return uv_trial._norm(name)


@dataclass(frozen=True)
class ToolRequirement:
    name: str
    """As the receipt spells it."""
    kind: str
    """``registry``, ``editable``, ``directory``, ``path``, ``url`` or ``git``."""
    specifier: str = ""
    extras: tuple[str, ...] = ()
    marker: str | None = None
    location: str | None = None
    """The path or URL of a non-registry requirement."""

    @property
    def canonical(self) -> str:
        return _norm(self.name)

    @property
    def local(self) -> bool:
        return self.kind in ("editable", "directory", "path")

    def _named(self) -> str:
        return f"{self.name}[{','.join(self.extras)}]" if self.extras else self.name

    def _marker(self) -> str:
        return f" ; {self.marker}" if self.marker else ""

    def _url(self) -> str:
        assert self.location is not None
        if self.kind in ("editable", "directory", "path"):
            return Path(self.location).as_uri()
        return self.location

    def pep508(self, specifier: str | None = None) -> str:
        """The requirement as one PEP 508 string, with *specifier* in place of its own."""
        if self.kind == "registry":
            return f"{self._named()}{self.specifier if specifier is None else specifier}{self._marker()}"
        return f"{self._named()} @ {self._url()}{self._marker()}"

    def editable(self) -> str:
        """An editable requirement as its absolute path with any extras (``/src/app[dev]``): the form
        ``-e``/``--editable`` take, which the sandbox's argv rewriting leaves as it is (it reads a
        ``name @ file://…`` value as a relative path)."""
        assert self.kind == "editable" and self.location is not None
        return f"{self.location}[{','.join(self.extras)}]" if self.extras else self.location


@dataclass(frozen=True)
class Receipt:
    requirements: tuple[ToolRequirement, ...]
    """The tool's own first, then each ``--with``."""
    python: str | None
    options: Mapping[str, object]
    unsupported: tuple[str, ...]
    """What the printed command cannot carry over: every fix is held while any is listed."""
    providers: frozenset[str] = frozenset()
    """Canonical names of the ``--with-executables-from`` requirements: those an entry point
    other than the tool's own comes ``from``."""

    @property
    def tool(self) -> ToolRequirement:
        return self.requirements[0]


def _git_location(git: str) -> str:
    """uv's recorded git source (``URL?rev=R&subdirectory=S#SHA``) as a pip-style ``git+URL@R#subdirectory=S``.

    The recorded revision is kept rather than the commit, as ``uv tool upgrade`` does. It is
    percent-encoded again (the receipt has ``rev=feature%40alice``): uv rejects a URL with a
    second ``@`` as ambiguous, and decodes the revision it splits off.
    """
    from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

    parts = urlsplit(git)
    query = parse_qs(parts.query)
    rev = (query.get("rev") or query.get("tag") or query.get("branch") or [parts.fragment or ""])[0]
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    out = f"git+{base}" + (f"@{quote(rev, safe='/')}" if rev else "")
    if sub := (query.get("subdirectory") or [""])[0]:
        out += f"#subdirectory={sub}"
    return out


def _requirement(entry: object) -> tuple[ToolRequirement | None, str | None]:
    """(the requirement, None), or (None, why it cannot be carried over)."""
    if not isinstance(entry, dict) or not isinstance(name := entry.get("name"), str) or not name:
        return None, "a malformed requirement"
    extras = entry.get("extras", [])
    marker = entry.get("marker")
    if not (isinstance(extras, list) and all(isinstance(e, str) for e in extras)) or not (
            marker is None or isinstance(marker, str)):
        return None, f"{name}'s extras or marker"
    if "index" in entry:
        return None, f"{name}'s index"
    common = {"extras": tuple(extras), "marker": marker}
    for key in ("editable", "directory", "path"):
        if key in entry:
            where = entry[key]
            if not isinstance(where, str) or not os.path.isabs(where):
                return None, f"{name}'s {key} path"
            return ToolRequirement(name, key, location=where, **common), None
    if "git" in entry:
        if not isinstance(entry["git"], str):
            return None, f"{name}'s git source"
        try:
            location = _git_location(entry["git"])
        except ValueError:
            return None, f"{name}'s git source"
        return ToolRequirement(name, "git", location=location, **common), None
    if "url" in entry:
        url, sub = entry["url"], entry.get("subdirectory")
        if not isinstance(url, str) or not (sub is None or isinstance(sub, str)):
            return None, f"{name}'s URL source"
        return ToolRequirement(name, "url", location=url + (f"#subdirectory={sub}" if sub else ""),
                               **common), None
    specifier = entry.get("specifier", "")
    if not isinstance(specifier, str):
        return None, f"{name}'s specifier"
    return ToolRequirement(name, "registry", specifier=specifier.replace(" ", ""), **common), None


def read_receipt(text: str) -> Receipt:
    """Parse a uv-receipt.toml; ReceiptError when it is not a tool's record. Nothing else is
    raised, whatever shape a value has: each tool is planned in one run, and ``--apply``
    re-reads the receipt a reinstall wrote before deciding whether to roll it back."""
    try:
        return _read_receipt(text)
    except ReceiptError:
        raise
    except RecursionError:
        raise ReceiptError("not a uv tool receipt (nested too deeply to read)") from None
    except (TypeError, AttributeError, ValueError) as exc:
        raise ReceiptError(f"not a uv tool receipt ({exc})") from None


def _read_receipt(text: str) -> Receipt:
    try:
        tool = tomllib.loads(text)["tool"]
        entries = tool["requirements"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ReceiptError(f"not a uv tool receipt ({exc})") from None
    if not isinstance(tool, dict) or not isinstance(entries, list) or not entries:
        raise ReceiptError("not a uv tool receipt (no requirements)")
    if _has_nul(tool):
        # No path, URL or name can hold one: os.path functions raise ValueError on it.
        raise ReceiptError("not a uv tool receipt (a value contains a NUL character)")
    unsupported: list[str] = []
    requirements: list[ToolRequirement] = []
    for entry in entries:
        req, why = _requirement(entry)
        if req is None:
            if not requirements:
                raise ReceiptError(f"cannot read the tool's own requirement ({why})")
            unsupported.append(str(why))
            continue
        requirements.append(req)
    for key in ("constraints", "overrides", "excludes", "build-constraint-dependencies"):
        if tool.get(key):
            unsupported.append(key)
    python = tool.get("python")
    if python is not None and not isinstance(python, str):
        unsupported.append("python")
        python = None
    options = tool.get("options") or {}
    if not isinstance(options, dict):
        raise ReceiptError("not a uv tool receipt (malformed [tool.options])")
    known = {key: kind for key, _, kind in _OPTIONS} | {_NO_BINARY: "bool"}
    for key, value in options.items():
        kind = known.get(key)
        ok = (kind == "str" and isinstance(value, str)
              or kind == "bool" and isinstance(value, bool)
              or kind == "list" and isinstance(value, list) and all(isinstance(v, str) for v in value))
        if not ok:
            unsupported.append(f"option {key}")
    if requirements[0].marker:
        unsupported.append(f"{requirements[0].name}'s marker")
    providers = _providers(tool.get("entrypoints"), requirements, unsupported)
    # An editable requirement is passed as a bare path, which cannot carry a marker.
    unsupported += [f"{r.name}'s marker" for r in requirements[1:] if r.kind == "editable" and r.marker]
    return Receipt(tuple(requirements), python, dict(options), tuple(dict.fromkeys(unsupported)), providers)


def _providers(entrypoints: object, requirements: list[ToolRequirement], unsupported: list[str]) -> frozenset[str]:
    """The requirements whose executables the tool also installs (``--with-executables-from``):
    ``uv tool install --force`` without that option removes them (measured with uv 0.13.5).
    One with no requirement to pass, or only an editable one (which that option does not take),
    is added to *unsupported*."""
    entries = entrypoints if isinstance(entrypoints, list) else None
    # Checked before anything is hashed: a malformed `from` (a list, a table) is held, not a crash.
    # Each entry also needs its name and absolute `install-path`: --apply restores executables
    # from them, and an entry without one would be left out of the rollback.
    froms = [e.get("from") for e in entries or () if isinstance(e, dict)]
    if entries is None or any(not _entrypoint_complete(e) for e in entries):
        unsupported.append("entrypoints")
    providers = {_norm(f) for f in froms if isinstance(f, str)} - {requirements[0].canonical}
    for name in sorted(providers):
        kinds = {r.kind for r in requirements[1:] if r.canonical == name}
        if not kinds or "editable" in kinds:
            unsupported.append(f"executables from {name}")
    return frozenset(providers)


def _has_nul(value: object) -> bool:
    if isinstance(value, str):
        return "\0" in value
    if isinstance(value, dict):
        return any(_has_nul(v) for v in value.values())
    return isinstance(value, list) and any(_has_nul(v) for v in value)


def _entrypoint_complete(entry: object) -> bool:
    """Whether *entry* is a whole ``ToolEntrypoint``: a name, an absolute install path, and a
    ``from`` that is absent (older receipts) or a requirement name."""
    return (isinstance(entry, dict) and isinstance(entry.get("name"), str) and bool(entry["name"])
            and isinstance(path := entry.get("install-path"), str) and os.path.isabs(path)
            and (entry.get("from") is None or isinstance(entry.get("from"), str)))


def option_args(receipt: Receipt, *, pip: bool) -> list[str]:
    """The receipt's options as arguments for ``uv tool install`` (or, with *pip*, ``uv pip install``)."""
    args: list[str] = []
    for key, flag, kind in _OPTIONS:
        value = receipt.options.get(key)
        if kind == "bool" and value is True:
            args.append(flag)
        elif kind == "str" and isinstance(value, str):
            args += [flag, value]
        elif kind == "list" and isinstance(value, list):
            for v in value:
                args += [flag, v]
    if receipt.options.get(_NO_BINARY) is True:
        args += ["--no-binary", ":all:"] if pip else ["--no-binary"]
    return args


def _pinned(receipt: Receipt, pins: Sequence[tuple[str, str]]) -> tuple[list[tuple[ToolRequirement, str | None]], list[str]]:
    """Each receipt requirement with the specifier a pin gives it (None: its own), and the pins
    no requirement without a marker covers, as ``name==version``. A name the receipt repeats
    (each with its own extras or marker) has the pin on every occurrence; one whose marker is
    false for the tool's interpreter is ignored by uv, so it alone does not carry the pin."""
    wanted = {_norm(n): v for n, v in pins}
    reqs = [(r, f"=={wanted[r.canonical]}" if r.kind == "registry" and r.canonical in wanted else None)
            for r in receipt.requirements]
    covered = {r.canonical for r, spec in reqs if spec is not None and not r.marker}
    return reqs, [f"{n}=={wanted[_norm(n)]}" for n, _ in pins if _norm(n) not in covered]


def interpreter(receipt: Receipt, env_python: str | None) -> str | None:
    """The ``--python`` request the reinstall needs: the receipt's, else the venv's X.Y."""
    return receipt.python or env_python


def install_argv(receipt: Receipt, pins: Sequence[tuple[str, str]], python: str | None) -> list[str]:
    """``uv tool install --force`` reinstalling the tool as its receipt records it, plus *pins*."""
    reqs, extra = _pinned(receipt, pins)
    (tool, tool_spec), *withs = reqs
    argv = ["uv", "tool", "install", "--force"]
    argv += ["--editable", tool.editable()] if tool.kind == "editable" else [tool.pep508(tool_spec)]
    for req, spec in withs:
        if req.kind == "editable":
            argv += ["--with-editable", req.editable()]
        else:
            flag = "--with-executables-from" if req.canonical in receipt.providers else "--with"
            argv += [flag, req.pep508(spec)]
    for pin in extra:
        argv += ["--with", pin]
    if python:
        argv += ["--python", python]
    return [*argv, *option_args(receipt, pip=False)]


def trial_argv(receipt: Receipt, venv_python: Path, pins: Sequence[tuple[str, str]] = ()) -> list[str]:
    """The dry run that resolves as ``install_argv`` would, against the tool's own interpreter."""
    reqs, extra = _pinned(receipt, pins)
    argv = ["uv", "pip", "install", "--dry-run", "--upgrade", "--python", str(venv_python),
            *option_args(receipt, pip=True)]
    for req, spec in reqs:
        argv += ["-e", req.editable()] if req.kind == "editable" else [req.pep508(spec)]
    return [*argv, *extra]


def _as_uv(argv: list[str]) -> list[str] | None:
    """*argv* with its program written ``uv``, when it is uv: by name or path, or the
    ``uv.__pa_real`` original a ``pa setup`` shim leaves, which the sandbox puts in
    ``argv[0]`` before its path hooks run."""
    if not argv or Path(argv[0]).name.removesuffix(".__pa_real") != "uv":
        return None
    return ["uv", *argv[1:]]


def is_read_only_command(argv: list[str]) -> bool:
    """Whether *argv* is exactly a ``trial_argv()``: ``uv pip install --dry-run --upgrade
    --python PATH``, then only carried-over options, requirements and ``-e REQ``."""
    argv = _as_uv(argv) or []
    if argv[:6] != ["uv", "pip", "install", "--dry-run", "--upgrade", "--python"] or len(argv) < 8:
        return False
    if not os.path.isabs(argv[6]):
        return False
    rest = argv[7:]
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in _BOOL_FLAGS:
            i += 1
        elif arg in _VALUE_FLAGS or arg in ("-e", "--no-binary"):
            if i + 1 >= len(rest) or not rest[i + 1] or rest[i + 1].startswith("-"):
                return False
            if arg == "--no-binary" and rest[i + 1] != ":all:":
                return False
            i += 2
        elif arg and not arg.startswith("-"):
            i += 1
        else:
            return False
    return True


_REINSTALL = ["uv", "tool", "install", "--force"]
_EDITABLE_FLAGS = frozenset({"-e", "--editable", "--with-editable"})


# Options whose value can name a local directory, as a path or a file:// URL.
_LOCATION_FLAGS = frozenset({"--find-links", "--index-url", "--extra-index-url"})


def _local_location(value: str) -> Path | None:
    """The local path *value* names: an absolute path, a ``file://`` URL, or a ``git+file://``
    repository (its ``@revision`` and ``#subdirectory`` dropped); None for anything else."""
    from urllib.parse import unquote, urlsplit

    if value.startswith("git+file:///"):
        # pip's form: the revision follows the path's last "@" (it can contain "/", as a branch
        # name can); split before decoding, so an encoded "@" stays part of the path.
        path = urlsplit(value.removeprefix("git+")).path
        head, at, _ = path.rpartition("@")
        return Path(unquote(head if at else path))
    if value.startswith("file:///"):
        return Path(unquote(urlsplit(value).path))
    return Path(value) if os.path.isabs(value) else None


def local_sources(argv: list[str]) -> list[Path]:
    """The local directories and files a ``trial_argv()`` or an ``install_argv()`` reinstall
    reads: each editable path (``-e``, ``--editable``, ``--with-editable``; extras dropped),
    each local ``name @ file://…`` or ``git+file://…`` requirement, and each local
    ``--find-links``, ``--index-url`` or ``--extra-index-url`` (a path or a ``file://`` URL)."""
    argv = _as_uv(argv) or []
    if is_read_only_command(argv):
        rest = argv[7:]
    elif argv[:4] == _REINSTALL:
        rest = argv[4:]
    else:
        return []
    out: list[Path] = []
    for i, arg in enumerate(rest):
        if i and rest[i - 1] in _EDITABLE_FLAGS:
            path = arg.split("[", 1)[0]
            if os.path.isabs(path):
                out.append(Path(path))
            continue
        if i and rest[i - 1] in _LOCATION_FLAGS:
            if (where := _local_location(arg)) is not None:
                out.append(where)
            continue
        _, sep, url = arg.partition(" @ ")
        url = url.split(" ; ", 1)[0]
        if sep and url.startswith(("file:///", "git+file:///")) and (where := _local_location(url)):
            out.append(where)
    return out


# ` - name==1.0`, ` + name==1.1`, optionally ` (from <url>)`; ` + name @ <url>` for a
# local requirement rebuilt from its source, whose version the dry run does not know.
_LINE_RE = re.compile(r"^([-+~]) ([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(\S+)(?: \(from (\S+)\))?\Z")
_UNVERSIONED_RE = re.compile(r"^([-+~]) ([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])? @ (\S+)\Z")
# uv fetching a git requirement's repository: `Updating <url> (<rev>)`, `Updated <url> (<commit>)`.
_GIT_FETCH_RE = re.compile(r"^Updat(ing|ed) \S+ \([^()\s]+\)\Z")
_SUMMARY_RE = re.compile(
    r"^(Resolved \d+ packages? in |Checked \d+ packages? in |Would make no changes\Z|"
    r"Would (download|uninstall|install) \d+ packages?\Z)")


def parse_trial(returncode: int, stderr: str, *, timed_out: bool = False,
                pinned: dict[str, str] | None = None,
                local: Iterable[str] = ()) -> TrialResult:
    """Classify one dry run's output. *local* are the canonical names of the receipt's
    requirements built from their source (a local path, or git): rebuilt from it, they are
    reinstalled but never moved."""
    if timed_out:
        return TrialResult("inconclusive", detail="the trial resolve timed out")
    if returncode != 0:
        if uv_trial._NO_SOLUTION in stderr:
            return TrialResult("blocked", blocker=uv_trial._blocker(stderr, pinned or {}),
                               detail=uv_trial._explanation(stderr))
        last = next((ln.strip() for ln in reversed(stderr.splitlines()) if ln.strip()), "")
        return TrialResult("inconclusive",
                           detail=uv_trial._failure_detail(stderr) or last or f"uv exited with status {returncode}")
    local = frozenset(local)
    removed: dict[str, str] = {}
    added: dict[str, str] = {}
    non_public: set[tuple[str, str]] = set()
    yanked: list[Yank] = []
    saw_summary = False
    for raw in stderr.splitlines():
        line = raw.strip()
        if m := uv_trial._YANKED_RE.match(line):
            yank = Yank(_norm(m.group(1)), m.group(2), m.group(3))
            if yank not in yanked:
                yanked.append(yank)
            continue
        if line.startswith("warning:") and "yank" in line.lower():
            return TrialResult("inconclusive", detail=f"unrecognised uv yank warning: {line}")
        if not line or uv_trial._IGNORED_RE.match(line) or _GIT_FETCH_RE.match(line):
            continue
        if _SUMMARY_RE.match(line):
            saw_summary = True
            continue
        if m := _UNVERSIONED_RE.match(line):
            if _norm(m.group(2)) not in local:
                return TrialResult("inconclusive", detail=f"uv installs {m.group(2)} from {m.group(3)}, "
                                                          "a version pa fix cannot check")
            continue
        m = _LINE_RE.match(line)
        if m is None:
            return TrialResult("inconclusive", detail=f"unrecognised uv output: {line}")
        sign, name, version, source = m.group(1), _norm(m.group(2)), m.group(3), m.group(4)
        if source is not None:
            # Recorded for a reinstall at the same version too: the trial's end state keeps it,
            # and a baseline upgrade it keeps back is reported from it.
            non_public.add((name, version))  # the version it replaces is private too
        if name in local or sign == "~":
            continue
        (removed if sign == "-" else added)[name] = version
    if not saw_summary:
        return TrialResult("inconclusive", detail="no resolution summary in uv output")
    changes = [Change("update", n, removed[n], added[n]) for n in sorted(removed.keys() & added.keys())
               if removed[n] != added[n]]
    changes += [Change("add", n, None, added[n]) for n in sorted(added.keys() - removed.keys())]
    changes += [Change("remove", n, removed[n], None) for n in sorted(removed.keys() - added.keys())]
    return TrialResult("resolved", changes=tuple(changes), yanked=tuple(yanked),
                       non_public=frozenset(non_public))


def _after(before: Mapping[str, frozenset[str]], changes: Iterable[Change]) -> dict[str, frozenset[str]]:
    state = {n: set(v) for n, v in before.items()}
    for c in changes:
        versions = state.setdefault(c.package, set())
        if c.old is not None:
            versions.discard(c.old)
        if c.new is not None:
            versions.add(c.new)
    return {n: frozenset(v) for n, v in state.items() if v}


def _one(versions: frozenset[str] | None, name: str) -> str | None:
    if not versions:
        return None
    if len(versions) > 1:
        raise ValueError(f"{name} is installed at several versions")
    return next(iter(versions))


def diff_from_baseline(installed: Mapping[str, frozenset[str]], baseline: Mapping[str, frozenset[str]],
                       trial: Mapping[str, frozenset[str]]) -> tuple[tuple[Change, ...], tuple[Change, ...]]:
    """(changes, declined): what the *trial* end state changes from the *baseline*'s.

    A version below the baseline's that is not below the *installed* one keeps the baseline's
    upgrade back rather than downgrading the tool: it is ``declined`` (from the baseline's
    version to the trial's), and, when it is still a version the tool does not have, also a
    change from the installed version (an ``add`` when the tool has none). ValueError for a
    version that cannot be ordered or a package at several versions.
    """
    from packaging.version import InvalidVersion, Version

    def below(a: str, b: str) -> bool:
        try:
            return Version(a) < Version(b)
        except InvalidVersion as exc:
            raise ValueError(str(exc)) from None

    changes: list[Change] = []
    declined: list[Change] = []
    for name in sorted(baseline.keys() | trial.keys()):
        b, t = _one(baseline.get(name), name), _one(trial.get(name), name)
        if b == t:
            continue
        i = _one(installed.get(name), name)
        if b is not None and t is not None and below(t, b) and (i is None or not below(t, i)):
            declined.append(Change("update", name, b, t))
            if i is None:
                changes.append(Change("add", name, None, t))
            elif t != i:
                changes.append(Change("update", name, i, t))
        elif b is None:
            changes.append(Change("add", name, None, t))
        elif t is None:
            changes.append(Change("remove", name, b, None))
        else:
            changes.append(Change("update", name, b, t))
    return tuple(changes), tuple(declined)


_PROJECT_CONFIG = ("uv.toml", "pyproject.toml")


def project_config(directory: Path) -> Path | None:
    """The uv configuration file uv run from *directory* would discover: the nearest
    ``uv.toml``, or ``pyproject.toml`` with a ``[tool.uv]`` table (one that cannot be read
    counts), in *directory* or an ancestor."""
    for d in (directory, *directory.parents):
        for name in _PROJECT_CONFIG:
            f = d / name
            try:
                if not f.is_file():
                    continue
                if name == "uv.toml":
                    return f
                tool = tomllib.loads(safe_read.read_text(f, errors="replace")).get("tool")
                if isinstance(tool, dict) and "uv" in tool:
                    return f
            except (OSError, ValueError, RecursionError):  # RecursionError: nesting too deep to parse
                return f
    return None


def _pip_table(path: Path) -> bool:
    """Whether a uv configuration file sets ``[pip]`` (``[tool.uv.pip]`` in a pyproject.toml);
    one that cannot be read counts."""
    try:
        data = tomllib.loads(safe_read.read_text(path, errors="replace"))
    except (OSError, ValueError, RecursionError):  # RecursionError: nesting too deep to parse
        return True
    if path.name == "pyproject.toml":
        tool = data.get("tool")
        data = tool.get("uv", {}) if isinstance(tool, dict) else {}
    return isinstance(data, dict) and bool(data.get("pip"))


def _command_env() -> Mapping[str, str]:
    """The environment uv runs with: the sandbox's settled one when a command is being judged
    (pa fix sets it for its trials and the reinstall), else this process's."""
    from packagealert.parsers.process_args import SANDBOX_ENV

    env = SANDBOX_ENV.get()
    return env if env is not None else os.environ


def pip_settings(venv: Path) -> Path | None:
    """A uv configuration file the trial would read whose ``[pip]`` settings apply to
    ``uv pip install`` (the trial) but not to ``uv tool install`` (the reinstall); None when
    there is none."""
    from packagealert.languages import python_tools as pt

    env = _command_env()
    if named := env.get("UV_CONFIG_FILE"):
        files = [Path(named)]
    elif pt._truthy(env.get("UV_NO_CONFIG")):
        files = []
    else:
        user, system = pt._config_dirs(env)
        files = [user / "uv" / "uv.toml"]
        if not pt._truthy(env.get("UV_NO_SYSTEM_CONFIG")):
            files += [next((f for f in [*(d / "uv" / "uv.toml" for d in system), pt._UV_SYSTEM_CONFIG]
                            if pt._is_file(f)), pt._UV_SYSTEM_CONFIG)]
        if (project := project_config(venv)) is not None:
            files.append(project)
    return next((f for f in files if pt._is_file(f) and _pip_table(f)), None)


def config_mismatch(venv: Path) -> str | None:
    """Why the trial, run from the tool's *venv*, and the reinstall could read different uv
    configuration, or None when they read the same file or none. ``uv tool`` reads no project
    configuration wherever it runs (only the user's, the system's, or a named file), while
    ``uv pip`` discovers it from its directory up, so a project file the trial would find
    is one the reinstall, or the printed command wherever it is pasted, never reads."""
    from packagealert.languages import python_tools as pt

    env = _command_env()
    if (pip := pip_settings(venv)) is not None:
        return (f"{pip} has [pip] settings, which apply to the trial (uv pip install) but not to the "
                "reinstall (uv tool install)")
    if (named := env.get("UV_CONFIG_FILE")) and not os.path.isabs(named):
        return (f"UV_CONFIG_FILE={named} is relative, so the trial (run from the tool's venv) and the "
                "reinstall (run from another directory) would read different files")
    if named or pt._truthy(env.get("UV_NO_CONFIG")):
        return None  # neither discovers a project file: both read the named file, or none
    if (trial := project_config(venv)) is None:
        return None
    return (f"the trial would read {trial}, which uv tool install ignores; move or remove the "
            "uv.toml or [tool.uv] table")


def full_python(venv: Path) -> str | None:
    """The interpreter's full version (``3.12.13``, ``3.14.0rc3``) from the venv's pyvenv.cfg, for
    ``python_full_version`` markers; None when it does not say."""
    try:
        text = safe_read.read_text(venv / "pyvenv.cfg", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip().lower() in ("version", "version_info") and re.fullmatch(
                r"\d+\.\d+(\.\d+)?((a|b|rc)\d+)?", v := value.strip()):  # a pre-release keeps its suffix
            return v
    return None


class Interpreter(typing.NamedTuple):
    """The tool's interpreter, as its pyvenv.cfg records it."""

    version: str | None
    """The full version (``3.12.13``)."""
    implementation: str | None = None
    """``CPython``, ``PyPy``; None when not recorded."""


def tool_interpreter(venv: Path, fallback: str | None = None) -> Interpreter:
    """The tool's interpreter from its pyvenv.cfg (uv records ``implementation``)."""
    implementation = None
    try:
        for line in safe_read.read_text(venv / "pyvenv.cfg", errors="replace").splitlines():
            key, _, value = line.partition("=")
            if key.strip().lower() == "implementation" and value.strip():
                implementation = value.strip()
    except OSError:
        pass
    return Interpreter(full_python(venv) or fallback, implementation)


_IDENTITY_VARS = ("implementation_name", "platform_python_implementation", "implementation_version")


def _as_interpreter(python: str | Interpreter | None) -> Interpreter:
    return python if isinstance(python, Interpreter) else Interpreter(python)


def _holds(marker, env: Mapping[str, str], unknown: frozenset[str], extra: str = "") -> bool:
    """Whether *marker* holds; True when it refers to a variable whose value for the tool's
    interpreter is not known (*unknown*), so what may be required is kept."""
    text = str(marker)
    if any(v in text for v in unknown):
        return True
    return bool(marker.evaluate({**env, "extra": extra}))


def applicable(receipt: Receipt, python: str | Interpreter | None) -> list[ToolRequirement]:
    """The receipt's requirements whose marker holds for the tool's interpreter on this
    machine; one whose marker cannot be read, or needs what is not known about the
    interpreter, is kept."""
    from packaging.markers import InvalidMarker, Marker

    env, unknown = _marker_environment(python)
    out = []
    for r in receipt.requirements:
        try:
            if r.marker and not _holds(Marker(r.marker), env, unknown):
                continue
        except (InvalidMarker, ValueError):
            pass
        out.append(r)
    return out


def required_packages(site_packages: Path | None, receipt: Receipt,
                      python: str | Interpreter | None) -> frozenset[str]:
    """Every name the receipt's requirements need, transitively, installed or not. ValueError
    when a distribution they reach has METADATA that cannot be read."""
    edges = dependency_edges(site_packages, receipt, python, installed_only=False)
    seen = {r.canonical for r in applicable(receipt, python)}
    stack = list(seen)
    while stack:
        for dep in edges.get(stack.pop(), ()):
            if dep not in seen:
                seen.add(dep)
                stack.append(dep)
    return frozenset(seen)


def _marker_environment(python: str | Interpreter | None) -> tuple[dict[str, str], frozenset[str]]:
    """(the marker environment of the tool's interpreter on this machine, the variables whose
    value for it is not known). The interpreter identity is the tool's own, not pa's."""
    from packaging.markers import default_environment

    interp = _as_interpreter(python)
    env = {k: str(v) for k, v in default_environment().items()}
    unknown: set[str] = set()
    # Never pa's own version: an X.Y version leaves the full one unknown, no version both.
    version = interp.version or ""
    full = version.count(".") >= 2
    if version:
        env["python_version"] = ".".join(version.split(".")[:2])
    else:
        unknown.add("python_version")
    if full:
        env["python_full_version"] = version
    else:
        unknown.add("python_full_version")
    if interp.implementation is None:
        unknown.update(_IDENTITY_VARS)
    else:
        env["platform_python_implementation"] = interp.implementation
        env["implementation_name"] = interp.implementation.lower()
        if interp.implementation.lower() == "cpython" and full:
            env["implementation_version"] = version
        else:
            unknown.add("implementation_version")
    return env, frozenset(unknown)


def _requires(dist_info: Path) -> list[str] | None:
    """The distribution's ``Requires-Dist`` lines; None when its METADATA cannot be read."""
    try:
        text = safe_read.read_text(dist_info / "METADATA", errors="replace")
    except OSError:
        return None
    return email.parser.Parser().parsestr(text, headersonly=True).get_all("Requires-Dist") or []


def dependency_edges(site_packages: Path | None, receipt: Receipt, python: str | Interpreter | None, *,
                     installed_only: bool = True) -> dict[str, frozenset[str]]:
    """name -> the installed names it requires (every name it requires, without
    *installed_only*), read from each dist-info's ``Requires-Dist``, following the extras the
    receipt (and each requirement) asks for, with markers judged for the tool's interpreter
    (*python*: an ``Interpreter``, or its full version). A requirement that cannot be parsed
    is left out; a reachable distribution whose METADATA cannot be read is too, unless every
    name is wanted (not *installed_only*), when it raises ValueError: what it needs is then
    not known."""
    from packaging.markers import InvalidMarker
    from packaging.requirements import InvalidRequirement, Requirement

    if site_packages is None:
        return {}
    metadata: dict[str, Path] = {}
    try:
        for d in site_packages.iterdir():
            if d.suffix == ".dist-info" and "-" in d.stem:
                metadata.setdefault(_norm(d.stem.split("-", 1)[0]), d)
    except OSError:
        return {}
    env, unknown = _marker_environment(python)
    edges: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    queue = [(r.canonical, extra) for r in applicable(receipt, python) for extra in ("", *r.extras)]
    while queue:
        name, extra = queue.pop()
        if (name, extra) in seen or name not in metadata:
            continue
        seen.add((name, extra))
        lines = _requires(metadata[name])
        if lines is None:
            if not installed_only:
                raise ValueError(f"cannot read {metadata[name].name}/METADATA")
            continue
        for line in lines:
            try:
                req = Requirement(line)
                if req.marker is not None and not _holds(req.marker, env, unknown, extra):
                    continue
            except (InvalidRequirement, InvalidMarker, ValueError):
                continue
            dep = _norm(req.name)
            if dep in metadata or not installed_only:
                edges.setdefault(name, set()).add(dep)
                queue += [(dep, e) for e in ("", *req.extras)]
    return {n: frozenset(d) for n, d in edges.items()}


# ---- what --apply checks after the reinstall (cli/fix_tools.py) ------------------------------

def readable_receipt(data: bytes | None) -> bool:
    """Whether *data* is a receipt uv (and pa fix) can use as the tool's record: one ``pa fix``
    could plan from again, with nothing it would hold as malformed or not carried over."""
    if data is None:
        return False
    try:
        receipt = read_receipt(data.decode("utf-8", errors="strict"))
    except (ReceiptError, UnicodeDecodeError):
        return False
    return not receipt.unsupported


def entrypoint_paths(receipt: bytes | None) -> set[Path]:
    """The executables a receipt records (each entry point's absolute ``install-path``)."""
    if receipt is None:
        return set()
    try:
        entries = tomllib.loads(receipt.decode("utf-8", errors="replace"))["tool"]["entrypoints"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError, RecursionError):  # nesting too deep to parse
        return set()
    # A NUL cannot name a file: os.path functions raise ValueError on it.
    return {Path(p) for e in (entries if isinstance(entries, list) else [])
            if isinstance(e, dict) and isinstance(p := e.get("install-path"), str) and os.path.isabs(p)
            and "\0" not in p}


def _physical(paths: set[Path]) -> set[Path]:
    """*paths* with each parent directory resolved, the name kept: two receipts can name one
    executables directory through different links (the name itself is the link uv writes)."""
    return {Path(os.path.realpath(p.parent)) / p.name for p in paths}


def unexpected(expected: Mapping[str, frozenset[str]], actual: Mapping[str, frozenset[str]],
               before: Mapping[str, frozenset[str]], required: frozenset[str],
               local: frozenset[str] = frozenset()) -> list[str]:
    """How *actual* differs from the verified end state. A package left out that the plan did not
    move is allowed only when it is not *required* (the receipt's requirements and what they
    need, read from the reinstalled environment): a reinstall drops what nothing needs. A
    *local* package (built from its source: a checkout, or git) need only be present: the dry
    run does not know the version its source now holds."""
    out = []
    for name in sorted(expected.keys() | actual.keys() | required):
        want, got = expected.get(name, frozenset()), actual.get(name, frozenset())
        if name in required and not got:
            pass  # a requirement the reinstalled tool needs is missing
        elif name in local and got:
            continue  # rebuilt from its source, at whatever version that now holds
        elif want == got or (not got and want == before.get(name) and name not in required):
            continue
        out.append(f"{name} {', '.join(sorted(got)) or 'absent'} (verified: {', '.join(sorted(want)) or 'absent'})")
    return out


class UvToolFixAdapter:
    """pa fix for one uv tool environment (``ToolEnv``).

    Its "lock file" is the tool's receipt; the trial runs in the tool's venv
    directory with the tool's interpreter. ``pa fix --apply`` reinstalls the
    tool with ``apply_argv()`` (see ``cli/fix_tools.py``), not by writing files.
    """

    ecosystem = "PyPI"
    lockfile_name = RECEIPT
    can_force = False
    pins_every_copy = False
    yanks_from_registry = True
    # How --apply names the tool and its command (``cli.fix_tools.ToolApplyTarget``).
    kind = "tool"
    action = "reinstall"
    doing = "reinstalling the tool"
    confirm_note = "reinstalls the tool"

    def __init__(self, env: ToolEnv, receipt: Receipt, receipt_bytes: bytes) -> None:
        self.env = env
        self.receipt = receipt
        self.name = f"uv tool {env.name}"
        self.label = env.label
        self.state = ToolState(receipt_bytes, self._installed())
        # The no-pin resolution's end state, once run (None when it did not resolve).
        self._baseline = Baseline()
        # Names installed, required or seen in a trial from outside public PyPI: never looked
        # up there.
        self._not_public: set[str] = ({_norm(p.name) for p in env.packages if not p.public}
                                      | {r.canonical for r in receipt.requirements if r.kind != "registry"})

    @classmethod
    def for_env(cls, env: ToolEnv) -> UvToolFixAdapter:
        """ReceiptError when the tool's receipt cannot be read."""
        try:
            data = safe_read.read_bytes(env.venv_root / RECEIPT)
        except OSError as exc:
            raise ReceiptError(f"cannot read {RECEIPT} ({exc.strerror or exc})") from None
        return cls(env, read_receipt(data.decode("utf-8", errors="replace")), data)

    def _installed(self) -> dict[str, frozenset[str]]:
        out: dict[str, set[str]] = {}
        for p in self.env.packages:
            out.setdefault(_norm(p.name), set()).add(p.version)
        return {n: frozenset(v) for n, v in out.items()}

    @property
    def venv_python(self) -> Path:
        return self.env.venv_root / "bin" / "python"

    @property
    def python(self) -> str | None:
        return interpreter(self.receipt, self.env.python)

    @property
    def local(self) -> frozenset[str]:
        """The receipt's requirements built from a local path."""
        return frozenset(r.canonical for r in self.receipt.requirements if r.local)

    @property
    def from_source(self) -> frozenset[str]:
        """The receipt's requirements built from their source (a local path, or git): their
        version is whatever the source holds, so a trial or a reinstall needs them present,
        not at a given version."""
        return self.local | frozenset(r.canonical for r in self.receipt.requirements if r.kind == "git")

    def find_lockfile(self, root: Path) -> Path | None:
        path = root / RECEIPT
        return path if path.is_file() else None

    def load_graph(self, lockfile: Path) -> DependencyGraph:
        member = self.label
        names = frozenset(r.canonical for r in self.receipt.requirements)
        deps = dict(dependency_edges(self.env.site_packages, self.receipt,
                                     tool_interpreter(self.env.venv_root, self.env.python)))
        deps[member] = names
        non_public = frozenset(_norm(p.name) for p in self.env.packages if not p.public)
        # A requirement from a local path, git or a URL has no registry version to pin.
        sourced = frozenset(r.canonical for r in self.receipt.requirements if r.kind != "registry")
        return DependencyGraph(members=frozenset({member}), direct=names, deps=deps,
                               versions=self.state.installed, non_registry=non_public | sourced,
                               local_source=self.local)

    def locked_packages(self, lockfile: Path) -> list[PackageSpec]:
        from packagealert.languages.base import PackageSpec

        return [PackageSpec(name=_norm(p.name), version=p.version, ecosystem=self.ecosystem,
                            from_public_registry=p.public) for p in self.env.packages]

    def _ordered(self, plan: FixPlan) -> list[PlannedFix]:
        ordered = sorted(plan.planned, key=lambda f: f.package)
        return ordered[:1] if plan.separate else ordered

    def pins(self, plan: FixPlan) -> list[tuple[str, str]]:
        """The exact pins the command adds: none when reinstalling alone reaches every fix, else
        the pins its verifying trial ran with (verification's own combined-pin rules)."""
        from packagealert.remediate.verify import _combined_pins

        ordered = self._ordered(plan)
        if all(f.by_relock for f in ordered):
            return []
        return _combined_pins(ordered, self.ecosystem)

    def apply_argv(self, plan: FixPlan) -> list[str] | None:
        """The one command that applies *plan*, or None when there is nothing to apply.

        ``uv tool upgrade`` when no pin is needed, unless the tool reads a local path (a
        checkout, a local ``--find-links``): that command names none, so the sandbox could not
        bind it. ``uv tool install --force`` with no pins resolves the same way and names them.
        None while ``held_reason()`` holds the tool."""
        if not plan.planned or self.held_reason() is not None:
            return None
        pins = self.pins(plan)
        if not pins and not local_sources(trial_argv(self.receipt, self.venv_python)):
            return ["uv", "tool", "upgrade", self.env.name]
        return install_argv(self.receipt, pins, self.python)

    def commands(self, plan: FixPlan, project_dir: Path | None = None,
                 sync_flags: tuple[str, ...] = ()) -> list[list[str]]:
        """The printed command: ``apply_argv()`` with credentials redacted, and, when uv's tool
        directories are chosen by the environment, those directories as absolute assignments,
        so it acts on the verified tool wherever it is pasted."""
        argv = self.apply_argv(plan)
        if argv is None:
            return []
        scope = [f"{var}={value}" for var, value in (
            ("UV_TOOL_DIR", str(self.env.venv_root.parent) if os.environ.get("UV_TOOL_DIR") else None),
            ("UV_TOOL_BIN_DIR", os.path.abspath(os.environ["UV_TOOL_BIN_DIR"])
             if os.environ.get("UV_TOOL_BIN_DIR") else None),
        ) if value]
        return [[*(["env", *scope] if scope else []), *redacted(argv)]]

    def probe_argv(self) -> list[str]:
        return trial_argv(self.receipt, self.venv_python)

    async def _run(self, pins: Sequence[tuple[str, str]], run: TrialRunner) -> TrialResult:
        if (problem := config_mismatch(self.env.venv_root)) is not None:
            return TrialResult("inconclusive", detail=problem)
        out = await run.read_only(trial_argv(self.receipt, self.venv_python, pins))
        result = parse_trial(out.returncode, out.stderr, timed_out=out.timed_out,
                             pinned=dict(pins), local=self.from_source)
        if result.detail:
            # Quoted from uv's output, which can name a source URL with its credentials; the
            # detail is shown in the report.
            result = dataclasses.replace(result, detail=redacted_text(result.detail))
        if result.status != "resolved":
            return result
        # The changes' old versions are installed ones: those not from the public registry are
        # not looked up there either.
        installed = frozenset((_norm(p.name), p.version) for p in self.env.packages if not p.public)
        self._not_public.update(n for n, _ in result.non_public)
        return dataclasses.replace(result, after=_after(self.state.installed, result.changes),
                                   non_public=result.non_public | installed)

    async def trial(self, pins, floats, run, *, force=(), lowest=None) -> TrialResult:
        """Everything floats in the reinstall, so *floats* say nothing a fresh resolve does not.

        The changes are measured from the baseline (what reinstalling with nothing pinned
        installs), as verification judges them, with the baseline's upgrades a pin keeps back
        in ``declined``; ``after`` is the trial's whole end state. Without a baseline they are
        measured from what the tool has installed."""
        if force:
            raise ValueError("the uv tool adapter cannot force a version")
        if (held := self.held_reason()) is not None:
            return TrialResult("inconclusive", detail=held)
        result = await self._run(pins, run)
        return measure_from_baseline(self.state.installed, result, await self.baseline(run))

    async def baseline(self, run: TrialRunner) -> TrialResult | None:
        """What reinstalling (or ``uv tool upgrade``) changes with nothing pinned, measured from
        what the tool has installed; run once, and None when it does not resolve."""
        if self.held_reason() is not None:
            return None
        return await self._baseline.get(lambda: self._run((), run))

    def held_reason(self) -> str | None:
        """Why no command can apply a fix to this tool, which holds every fix; None when one can."""
        home = self.env.venv_root.parent / _norm(self.receipt.tool.name)
        if home != self.env.venv_root:
            # uv reinstalls a tool in the directory named after its requirement: a copied or
            # renamed environment's command would replace another one.
            return (f"its receipt is for {self.receipt.tool.name}, so uv would reinstall {home}, "
                    f"not {self.env.venv_root}")
        if self.receipt.unsupported:
            return f"the command cannot carry over the tool's {', '.join(self.receipt.unsupported)}"
        if self.python is None:
            # uv tool install --force ignores the tool's interpreter: without --python it can
            # move the tool to another Python version, which the trial did not run with.
            return ("neither its receipt nor its pyvenv.cfg records its Python version, so a "
                    "reinstall could change it")
        return None

    # ---- --apply (``cli.fix_tools.ToolApplyTarget``) ----

    @property
    def venv_root(self) -> Path:
        return self.env.venv_root

    @property
    def metadata_path(self) -> Path:
        return self.env.venv_root / RECEIPT

    @property
    def backup_name(self) -> str:
        return f"uv-tool-{self.env.name}"

    def pin_problem(self, plan: FixPlan) -> str | None:
        """Every verified plan has a command (``apply_argv()``)."""
        return None

    def install_root(self, parsed: object) -> Path | None:
        """The tools directory ``pa run`` would reinstall in, resolved."""
        return first_write_dir(parsed)

    def bin_dir(self, parsed: object) -> Path:
        """The executables' directory ``pa run`` binds writable; ValueError when it does not say."""
        dirs = getattr(parsed, "extra_write_home_dirs", None) or []
        if len(dirs) < 2 or not isinstance(dirs[1], Path):
            raise ValueError("pa run did not say which directory the tool's executables go in")
        return dirs[1]

    def run_env(self, parsed: object) -> dict[str, str]:
        """UV_TOOL_DIR and UV_TOOL_BIN_DIR set to the absolute directories ``pa run`` resolved for
        *parsed*, so a run from another directory resolves the same ones."""
        dirs = getattr(parsed, "extra_write_home_dirs", None) or []
        return {k: str(d) for k, d in zip(("UV_TOOL_DIR", "UV_TOOL_BIN_DIR"), dirs, strict=False)
                if isinstance(d, Path) and d.is_absolute()}

    def read_only_paths(self, parsed: object) -> list[Path]:
        """Nothing outside the tool and its executables needs to stay read-only for uv."""
        return []

    def reread(self, root_identity: tuple[str, int, int] | None = None
               ) -> tuple[bytes | None, Inventory | None]:
        """The tool's receipt and installed versions now (None for what cannot be read)."""
        receipt, env = reread_env(self.env, RECEIPT, root_identity)
        return receipt, (None if env is None else inventory(env))

    def config_problem(self, extra_env: Sequence[str]) -> str | None:
        """Why the reinstall could read other uv configuration from its trial (see ``config_mismatch()``)."""
        return config_mismatch(self.env.venv_root)

    def executables(self, metadata: bytes | None) -> set[Path]:
        return entrypoint_paths(metadata)

    def end_state_problem(self, expected: Mapping[str, frozenset[str]], before: Mapping[str, frozenset[str]],
                          root_identity: tuple[str, int, int] | None) -> str | None:
        """Why the reinstalled tool is not the verified end state (*expected*, and *before* for
        what the plan did not move), or None when it is."""
        venv = self.env.venv_root
        new_receipt, new_env = reread_env(self.env, RECEIPT, root_identity)
        if new_env is not None and readable_receipt(new_receipt) and is_venv(venv):
            after = inventory(new_env)
            try:
                # The new receipt's requirements too: a --with pin is one, and what it needs is required.
                interp = tool_interpreter(venv, new_env.python)
                reinstalled = read_receipt((new_receipt or b"").decode())
                required = (required_packages(new_env.site_packages, self.receipt, interp)
                            | required_packages(new_env.site_packages, reinstalled, interp))
            except ValueError as exc:
                problems = [f"what the reinstalled packages need cannot be read ({exc})"]
            else:
                problems = unexpected(expected, after, before, required, self.from_source)
                # The tool must be one pa fix could plan for again: a receipt for another tool (whose
                # directory uv would reinstall) or with no recorded interpreter would be held.
                if held := type(self)(new_env, reinstalled, new_receipt or b"").held_reason():
                    problems.append(f"pa fix would hold the reinstalled tool: {held}")
            # An executable the tool had and the reinstall dropped (a `--with-executables-from` not
            # carried over removes its provider's): the versions alone would accept that.
            if lost := sorted(p.name for p in _physical(entrypoint_paths(self.state.receipt_bytes))
                              - _physical(entrypoint_paths(new_receipt))):
                problems.append(f"it no longer installs {', '.join(lost)}")
            return f"the reinstall did not install the verified versions: {'; '.join(problems)}" if problems else None
        if new_env is not None and not readable_receipt(new_receipt):
            return "the reinstalled tool has no usable uv-receipt.toml (unreadable, or one pa fix would hold)"
        if new_env is not None and not is_venv(venv):
            return "the reinstalled tool is not a working virtualenv (pyvenv.cfg or bin/python is missing)"
        if not in_place(venv, root_identity):
            return "the tool's directory was replaced during the run"
        return "the reinstalled tool could not be read"

    async def cadences(self, names: list[str]) -> dict[str, str | None]:
        # A private package's name is not sent to PyPI; it has no public release history.
        return await public_cadences(names, self._not_public, _norm)
