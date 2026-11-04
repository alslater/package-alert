"""`pa fix --tools --pipx`: fix vulnerable packages in a pipx app's environment.

pipx records an app in ``pipx_metadata.json`` inside its venv: the main package
(``package_or_url`` and the ``pip_args`` it was installed with) and each injected
package. The fix is ``pipx runpip <app> install <pkg>==<version> ...``: pip then
keeps everything else installed, and the command never names the main package, so
pipx does not rewrite its recorded spec. The trial is the same ``pip install
--dry-run --report`` with the app's own requirements in ``reqs.txt`` and
``cons.txt`` (the main package pinned to what is installed), so the main package
and its extras reach pip only through files. A pip option this module cannot carry
over is recorded in ``PipxMetadata.unsupported``, and the caller holds the app.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

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
    write_dirs,
)
from packagealert.languages.python_fix.uv_tool import _after
from packagealert.remediate.adapter import (
    Blocker,
    Change,
    LockfileError,
    TrialResult,
    Yank,
)
from packagealert.safe_output import redacted, redacted_text

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from packagealert.languages.base import PackageSpec
    from packagealert.languages.python_fix.uv_tool import ToolRequirement
    from packagealert.languages.python_tools import ToolEnv
    from packagealert.remediate.adapter import TrialRunner
    from packagealert.remediate.graph import DependencyGraph
    from packagealert.remediate.planner import FixPlan

# pip options whose value the command and the trial carry over.
_VALUE_FLAGS = frozenset({"--index-url", "--extra-index-url", "--find-links", "--trusted-host"})
_BOOL_FLAGS = frozenset({"--pre"})
_EDITABLE_FLAGS = frozenset({"--editable", "-e"})
# Changes how pip installs, not which versions it resolves.
_IGNORED_FLAGS = frozenset({"--force-reinstall"})
# pipx_metadata_version values pipx 1.18.4 reads (its current one and the legacy ones it converts).
_METADATA_VERSIONS = frozenset({f"0.{n}" for n in range(1, 13)})


class MetadataError(LockfileError):
    """A pipx_metadata.json that cannot be read as an app's record."""


def _norm(name: str) -> str:
    return uv_trial._norm(name)


@dataclass(frozen=True)
class PipxPackage:
    spec: str
    """``package_or_url`` as pipx recorded it."""
    name: str
    pip_args: tuple[str, ...]
    """The supported options, as ``--flag`` / ``value`` tokens (``=`` forms split)."""
    editable: bool
    local: bool
    main: bool


@dataclass(frozen=True)
class PipxMetadata:
    version: str
    backend: str
    main: PipxPackage
    injected: tuple[PipxPackage, ...]
    python: str | None
    unsupported: tuple[str, ...]
    """Recorded pip options this module cannot carry over."""
    suffix: str = ""
    """``pipx install --suffix``: the app's venv is named after the main package plus this."""


_PIN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9._!+-]*\Z")


def _has_nul(value: object) -> bool:
    if isinstance(value, str):
        return "\0" in value
    if isinstance(value, dict):
        return any(_has_nul(k) or _has_nul(v) for k, v in value.items())
    return isinstance(value, list) and any(_has_nul(v) for v in value)


def _unsafe(value: str) -> bool:
    """Whether *value* could be read as an option, or as more than one line, in a requirements file."""
    return value.startswith("-") or any(ord(c) < 32 or ord(c) == 127 for c in value)


def _is_local(spec: str) -> bool:
    return os.path.isabs(spec) or spec.startswith("file:")


def _split_args(args: list[str], *, main: bool) -> tuple[list[str], bool, list[str]]:
    """(supported tokens, editable, unsupported option names) of a package's ``pip_args``."""
    kept: list[str] = []
    unsupported: list[str] = []
    editable = False
    i = 0
    while i < len(args):
        arg = args[i]
        flag, eq, value = arg.partition("=")
        if flag in _VALUE_FLAGS and eq and value:
            kept += [flag, value]
        elif arg in _VALUE_FLAGS and i + 1 < len(args) and args[i + 1] and not args[i + 1].startswith("-"):
            kept += [arg, args[i + 1]]
            i += 1
        elif arg in _BOOL_FLAGS:
            kept.append(arg)
        elif arg in _EDITABLE_FLAGS and main:
            editable = True
        elif arg in _IGNORED_FLAGS:
            pass
        elif arg in _EDITABLE_FLAGS:
            unsupported.append("--editable (injected)")
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                i += 1
        else:
            unsupported.append(flag if arg.startswith("-") else arg)
            if arg.startswith("-") and not eq and i + 1 < len(args) and not args[i + 1].startswith("-"):
                i += 1
        i += 1
    return kept, editable, unsupported


def _package(entry: object, *, main: bool) -> tuple[PipxPackage, list[str]]:
    if not isinstance(entry, dict):
        raise MetadataError("not a pipx metadata file (a package entry is not an object)")
    spec, name, args = entry.get("package_or_url"), entry.get("package"), entry.get("pip_args")
    if not isinstance(spec, str) or not spec or not isinstance(name, str) or not name:
        raise MetadataError("not a pipx metadata file (a package has no name or spec)")
    if _unsafe(spec) or _unsafe(name):
        raise MetadataError("not a pipx metadata file (a package spec or name is not a plain one)")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise MetadataError("not a pipx metadata file (pip_args is not a list of strings)")
    kept, editable, unsupported = _split_args(args, main=main)
    return PipxPackage(spec, name, tuple(kept), editable, _is_local(spec), main), unsupported


def read_metadata(text: str) -> PipxMetadata:
    """Parse a pipx_metadata.json; MetadataError when it is not an app's record. Nothing else
    is raised, whatever shape a value has."""
    try:
        return _read_metadata(text)
    except MetadataError:
        raise
    except RecursionError:
        raise MetadataError("not a pipx metadata file (nested too deeply to read)") from None
    except (TypeError, AttributeError, ValueError) as exc:
        raise MetadataError(f"not a pipx metadata file ({exc})") from None


def _read_metadata(text: str) -> PipxMetadata:
    doc = json.loads(text)
    if not isinstance(doc, dict) or not isinstance(doc.get("main_package"), dict):
        raise MetadataError("not a pipx metadata file (no main_package)")
    if _has_nul(doc):
        raise MetadataError("not a pipx metadata file (contains a NUL character)")
    version = doc.get("pipx_metadata_version")
    if version not in _METADATA_VERSIONS:
        raise MetadataError(f"unsupported pipx metadata version {version}")
    injected_doc = doc.get("injected_packages", {})
    if not isinstance(injected_doc, dict):
        raise MetadataError("not a pipx metadata file (injected_packages is not an object)")
    main, unsupported = _package(doc["main_package"], main=True)
    injected: list[PipxPackage] = []
    for entry in injected_doc.values():
        package, bad = _package(entry, main=False)
        injected.append(package)
        unsupported += bad
    index_urls = {a[1] for p in (main, *injected) for a in zip(p.pip_args, p.pip_args[1:]) if a[0] == "--index-url"}
    if len(index_urls) > 1:
        unsupported.append("--index-url (differs between packages)")
    backend = doc.get("backend")
    python = doc.get("python_version")
    suffix = doc["main_package"].get("suffix") or ""
    if not isinstance(suffix, str) or _unsafe(f"x{suffix}") or "/" in suffix:
        raise MetadataError("not a pipx metadata file (the suffix is not a plain one)")
    return PipxMetadata(
        version=version,
        backend=backend if isinstance(backend, str) and backend else "pip",
        main=main,
        injected=tuple(injected),
        python=python.removeprefix("Python ").strip() or None if isinstance(python, str) else None,
        unsupported=tuple(dict.fromkeys(unsupported)),
        suffix=suffix,
    )


def option_args(meta: PipxMetadata) -> list[str]:
    """The index and resolution options of the main package and every injected one, each pair
    once, as the command and the trial pass them."""
    out: list[str] = []
    seen: set[tuple[str, ...]] = set()
    for package in (meta.main, *meta.injected):
        args = package.pip_args
        i = 0
        while i < len(args):
            unit = (args[i],) if args[i] in _BOOL_FLAGS else (args[i], args[i + 1])
            i += len(unit)
            if unit not in seen:
                seen.add(unit)
                out += unit
    return out


def _pin_args(meta: PipxMetadata, pins: Sequence[tuple[str, str]]) -> list[str]:
    for name, version in pins:
        if not _PIN_RE.match(f"{name}=={version}"):
            raise ValueError("not a plain name==version pin")
    main = _norm(meta.main.name)
    return [f"{n}=={v}" for n, v in pins if _norm(n) != main]


def apply_argv(app: str, meta: PipxMetadata, pins: Sequence[tuple[str, str]]) -> list[str]:
    """``pipx runpip`` installing *pins* into the app's venv; the main package is never named."""
    return ["pipx", "runpip", app, "install", *option_args(meta), *_pin_args(meta, pins)]


# Not --quiet: pip prints a conflict's cause ("X depends on Y") only at its default verbosity.
_TRIAL_HEAD = ["install", "--dry-run", "--no-input"]
_TRIAL_FILES = (("-r", "reqs.txt"), ("-c", "cons.txt"), ("--report", "report.json"))


def _trial_files_args(workdir: Path) -> list[str]:
    return [a for flag, name in _TRIAL_FILES for a in (flag, str(workdir / name))]


def trial_argv(app: str, meta: PipxMetadata, pins: Sequence[tuple[str, str]], *, workdir: Path) -> list[str]:
    """The dry run resolving as ``apply_argv`` would. The app's own requirements come from
    ``reqs.txt`` and ``cons.txt`` in *workdir* (the trial's scratch copy), and the report goes
    there: named by absolute path, since pipx runs pip in the app's venv directory.
    ``--no-input`` makes a 401 or a keyring prompt a plain failure instead of a wait."""
    return ["pipx", "runpip", app, *_TRIAL_HEAD, *option_args(meta), *_trial_files_args(workdir),
            *_pin_args(meta, pins)]


def trial_files(meta: PipxMetadata, installed_main: str | None) -> dict[str, str]:
    """``reqs.txt`` (the main spec, then each injected one) and ``cons.txt`` (the main package at
    its installed version; pip honours it for a local main too, so it is always written)."""
    lines = [f"-e {p.spec}" if p.editable else p.spec for p in (meta.main, *meta.injected)]
    cons = f"{meta.main.name}=={installed_main}\n" if installed_main else ""
    return {"reqs.txt": "".join(f"{line}\n" for line in lines), "cons.txt": cons}



def _scratch_workdir(path: str) -> Path | None:
    """The directory of *path* when it is a plain absolute path to a file directly inside a
    directory strictly under pa fix's scratch root (where the sandbox runs scratch commands)."""
    from packagealert.sandbox import runner

    p = Path(path)
    if not p.is_absolute() or os.path.normpath(path) != path or path.endswith("/"):
        return None
    try:
        root = runner.SCRATCH_ROOT.resolve(strict=False)
        parent = p.parent.resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    return p.parent if parent != root and parent.is_relative_to(root) else None


def is_trial_command(argv: list[str]) -> bool:
    """Whether *argv* is exactly a ``trial_argv()``: ``pipx runpip APP install --dry-run
    --no-input``, the carried-over options, ``reqs.txt``, ``cons.txt`` and ``report.json`` in one
    scratch directory, then only ``name==version`` pins."""
    if not argv or Path(argv[0]).name.removesuffix(".__pa_real") != "pipx":
        return False
    if argv[1:2] != ["runpip"] or len(argv) < 4 or not argv[2] or argv[2].startswith("-"):
        return False
    if "/" in argv[2] or argv[2] in (".", "..") or _unsafe(argv[2]):
        return False  # the app names one directory in pipx's venvs directory, and its lock beside it
    rest = argv[3:]
    head = len(_TRIAL_HEAD)
    if rest[:head] != _TRIAL_HEAD:
        return False
    i = head
    while i < len(rest):
        if rest[i] in _BOOL_FLAGS:
            i += 1
        elif rest[i] in _VALUE_FLAGS:
            if i + 1 >= len(rest) or not rest[i + 1] or rest[i + 1].startswith("-"):
                return False
            i += 2
        else:
            break
    files = rest[i:i + 2 * len(_TRIAL_FILES)]
    if len(files) != 2 * len(_TRIAL_FILES) or (workdir := _scratch_workdir(files[1])) is None:
        return False
    if files != _trial_files_args(workdir):
        return False
    return all(_PIN_RE.match(p) for p in rest[i + len(files):])


_PUBLIC_FILES_HOST = "https://files.pythonhosted.org/"
_NO_SUCH_OPTION_RE = re.compile(r"no such option: --(?:dry-run|report)\b")
_AUTH_RE = re.compile(
    r"(?<![\w.-])(?:401|403)(?:\s+(?:Client Error|Server Error|Error|Unauthorized|Forbidden)|(?=\W*Credentials))"
    r"|HTTP error (?:401|403)\b", re.IGNORECASE)


def _bare_name(spec: str) -> str:
    """The normalised distribution name of a requirement-like *spec*: no extras, specifier, marker or URL."""
    from packaging.requirements import InvalidRequirement, Requirement
    try:
        return _norm(Requirement(spec).name)
    except InvalidRequirement:
        return _norm(re.split(r"[\[ =<>!~;@]", spec.strip(), maxsplit=1)[0])
_CANNOT_INSTALL_RE = re.compile(r"^ERROR: (Cannot install .+? because .+)$", re.MULTILINE)
# pip's "The conflict is caused by:" lines (on stdout, at its default verbosity): "<parent> <version>
# depends on <requirement>", the requirement as pip formats it ("urllib3<1.27 and >=1.21.1").
_DEPENDS_RE = re.compile(r"^[ \t]+(\S+) (\S+) depends on (([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]\n]*\])?[^\n]*?)[ \t]*$",
                         re.MULTILINE)
# A requirements or constraints file pip names in its own message: the trial's scratch files.
_TRIAL_FILE_RE = re.compile(r"-[rc] \S+ \(line \d+\)")
_NO_MATCH_RE = re.compile(r"^ERROR: (Could not find a version that satisfies the requirement [^\n(]+?)\s*(?:\(from versions:.*\))?$", re.MULTILINE)
_YANK_REASON_RE = re.compile(
    r"yanked version: '([^']+)' candidate \(version (\S+) at [^\n]*\)\s*\n(?:WARNING: )?Reason for being yanked: ([^\n]*)")


def too_old(pip_version: str | None) -> TrialResult:
    """The result for a pip too old to verify with (no ``--dry-run`` or ``--report``)."""
    which = f" {pip_version}" if pip_version else ""
    return TrialResult("inconclusive", detail=f"pipx's shared pip{which} is too old to verify: run pipx upgrade-shared")


def _main_move_detail(main: str, app: str) -> str:
    return f"the fix needs a newer {main}: run pipx upgrade {app}, then plan again"


def _last_error(stderr: str, returncode: int) -> str:
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip() and not ln.rstrip().endswith("' failed")]
    errors = [ln for ln in lines if ln.startswith("ERROR:")]
    pick = (errors or lines or [f"pip exited with status {returncode}"])[-1]
    if pick == "ERROR: Exception:":
        # pip's internal-error banner: the traceback after it ends with the exception itself.
        pick = lines[-1]
    return redacted_text(pick.removeprefix("ERROR:").strip())


def _version_order(version: str) -> tuple[int, object]:
    """A sort key that orders versions as versions, any that cannot be read last."""
    from packaging.version import InvalidVersion, Version

    try:
        return 0, Version(version)
    except InvalidVersion:
        return 1, version


def _report_pip(report: bytes | None) -> str | None:
    """The ``pip_version`` pip's report records; None when it records none that can be read."""
    try:
        doc = json.loads(report or b"")
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    version = doc.get("pip_version") if isinstance(doc, dict) else None
    return version if isinstance(version, str) else None


def _read_report(report: bytes | None) -> list[dict[str, object]] | None:
    if not report or not report.strip():
        return None
    try:
        doc = json.loads(report)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    install = doc.get("install") if isinstance(doc, dict) else None
    if not isinstance(install, list) or not all(isinstance(e, dict) for e in install):
        return None
    return install


def _entry(item: dict[str, object]) -> tuple[str, str, bool, bool, str, bool] | None:
    """(name, version, direct, non_public, source, yanked) of a report's install entry."""
    meta = item.get("metadata")
    if not isinstance(meta, dict):
        return None
    name, version = meta.get("name"), meta.get("version")
    # The report is written inside the sandbox: a name or version that is not a plain one (an
    # option, a URL, a space) is unreadable rather than passed on to a pin.
    if not isinstance(name, str) or not isinstance(version, str) or not _PIN_RE.match(f"{name}=={version}"):
        return None
    info = item.get("download_info")
    info = info if isinstance(info, dict) else {}
    url = info.get("url") if isinstance(info.get("url"), str) else ""
    built = "dir_info" in info or "vcs_info" in info or item.get("is_direct") is True
    non_public = built or not str(url).startswith(_PUBLIC_FILES_HOST)
    return _norm(name), version, built, non_public, str(url), item.get("is_yanked") is True


def _excludes(requirement: str, name: str, version: str) -> bool:
    """Whether pip's *requirement* on *name* (``urllib3[x]<1.27 and >=1.21.1; marker``) rejects
    *version*. False when it cannot be read: only a requirement known to exclude the pin blocks it."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion, Version

    spec = requirement[len(name):].split(";", 1)[0].strip()
    spec = re.sub(r"^\[[^\]]*\]", "", spec).strip().replace(" and ", ",")
    try:
        return not SpecifierSet(spec).contains(Version(version), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return False


def _trial_files_named(text: str, app: str, workdir: Path | None) -> str:
    """*text* with the trial's own files (``-r <copy>/reqs.txt (line N)``) named as the app's
    requirements: matched by their exact path (which may hold a space), else by shape."""
    named = f"{app}'s requirements"
    if workdir is not None:
        for flag, name in (("-r", "reqs.txt"), ("-c", "cons.txt")):
            text = re.sub(rf"{flag} {re.escape(str(workdir / name))} \(line \d+\)", lambda _m: named, text)
    return _TRIAL_FILE_RE.sub(named, text)


def _conflict(cannot: str, output: str, *, app: str, pinned: Mapping[str, str],
              workdir: Path | None = None) -> TrialResult:
    """A resolution conflict: blocked by the requirement(s) pip names (*output*: what pip printed)
    that exclude a pinned version, else by pip's own "Cannot install" sentence (*cannot*), with
    the trial's files named as the app's requirements. pip lists every requirement on the
    conflicting package, including those the pin satisfies, so each is checked."""
    targets = {_norm(k): v for k, v in pinned.items()}
    causes: list[Blocker] = []
    for d in _DEPENDS_RE.finditer(output):
        parent, version, requirement, dep = d.group(1), d.group(2), d.group(3), _norm(d.group(4))
        if dep in targets and _excludes(requirement, d.group(4), targets[dep]):
            causes.append(Blocker(_bare_name(parent), redacted_text(requirement), redacted_text(version)))
    if causes:
        return TrialResult("blocked", blocker=causes[0], detail="; ".join(dict.fromkeys(c.describe() for c in causes)))
    return TrialResult("blocked", detail=redacted_text(_trial_files_named(cannot, app, workdir)))


def _classify_failure(returncode: int, stderr: str, *, main: str, app: str, pinned: Mapping[str, str],
                      private_index: bool, pip_version: str | None, stdout: str = "",
                      workdir: Path | None = None) -> TrialResult:
    if _NO_SUCH_OPTION_RE.search(stderr):
        return too_old(pip_version)
    if _AUTH_RE.search(re.sub(r"\(from versions:[^\n]*", "", stderr)):
        return TrialResult("inconclusive", detail="the index needs credentials the sandbox does not have")
    if m := _CANNOT_INSTALL_RE.search(stderr):
        # A requirement excluding a pinned version is the cause even where pip's sentence also
        # names the app (it does when the app's requirement on the capping package is a range).
        conflict = _conflict(m.group(1), f"{stdout}\n{stderr}", app=app, pinned=pinned, workdir=workdir)
        if conflict.blocker is not None:
            return conflict
        subject = m.group(1).split(" because ", 1)[0].removeprefix("Cannot install ")
        names = {_norm(re.split(r"[ =<>!~(]", part.strip(), maxsplit=1)[0]) for part in re.split(r", | and ", subject)}
        if _bare_name(main) in names:
            return TrialResult("blocked", detail=_main_move_detail(main, app))
        return conflict
    if "No matching distribution found" in stderr:
        # An index offering no version at all of a package being pinned to a known release did
        # not answer; one pip found through its config or environment needs no private_index.
        if private_index or "(from versions: none)" in stderr:
            return TrialResult("inconclusive", detail="the index returned no match; it may need "
                                                      "credentials the sandbox does not have")
        found = _NO_MATCH_RE.search(stderr)
        return TrialResult("blocked", detail=redacted_text(found.group(1)) if found else _last_error(stderr, returncode))
    return TrialResult("inconclusive", detail=_last_error(stderr, returncode))


def parse_pip_trial(returncode: int, report: bytes | None, stderr: str, *, main: str, app: str,
                    pinned: Mapping[str, str], local: frozenset[str],
                    installed: Mapping[str, frozenset[str]], private_index: bool = False,
                    pip_version: str | None = None, timed_out: bool = False, stdout: str = "",
                    workdir: Path | None = None) -> TrialResult:
    """Classify one ``pip install --dry-run --report`` trial of *app* (its main package is *main*).

    The report decides when it parses, whatever pip's exit status; without one the failure is read
    from *stderr*, and a conflict's cause from *stdout*; *workdir* (the trial's copy) is never
    named in a detail. pip lists a registry package only when it would change, but always lists a
    requirement given as a path, so a change is a version that differs from *installed*.
    The main package moving is checked first, then a path/URL-sourced package changing, and
    only then are unchanged local packages treated as present. Under ``--no-input`` pip does not
    mention a 401, so *private_index* (the app names an index other than PyPI) is what tells an
    unreadable index from a missing version. With *pip_version* (the pip checked before the
    trial), a report another pip wrote is inconclusive.
    """
    if timed_out:
        return TrialResult("inconclusive", detail="the trial resolve timed out")
    install = _read_report(report)
    if install is None:
        if returncode == 0:
            return TrialResult("inconclusive", detail="pip wrote no readable report")
        return _classify_failure(returncode, stderr, main=main, app=app, pinned=pinned,
                                 private_index=private_index, pip_version=pip_version, stdout=stdout,
                                 workdir=workdir)
    if pip_version is not None and (ran := _report_pip(report)) != pip_version:
        # The gate checked one pip; a report from another (one a build left in the venv, say)
        # is in a format nothing checked.
        return TrialResult("inconclusive", detail=f"the trial ran pip {ran or '(unknown)'}, not the pip "
                                                  f"{pip_version} checked before it")
    main_name = _bare_name(main)
    have = {_norm(k): v for k, v in installed.items()}
    reasons = {(_norm(n), v): r for n, v, r in _YANK_REASON_RE.findall(stderr)}
    local = frozenset(_norm(n) for n in local)
    changes: list[Change] = []
    non_public: set[tuple[str, str]] = set()
    yanked: list[Yank] = []
    sourced: list[str] = []
    for item in install:
        entry = _entry(item)
        if entry is None:
            return TrialResult("inconclusive", detail="pip's report has an entry this cannot read")
        name, version, built, private, url, is_yanked = entry
        old = have.get(name, frozenset())
        was = None if not old else (version if version in old else min(old, key=_version_order))
        if private or name in local:
            non_public.add((name, version))
            if was is not None:
                non_public.add((name, was))
        if is_yanked:
            yanked.append(Yank(name, version, redacted_text(reasons[(name, version)]) if (name, version) in reasons else None))
        if was == version:
            continue
        if name == main_name:
            return TrialResult("blocked", detail=_main_move_detail(main, app))
        if built or name in local:
            sourced.append(f"{name} is built from {redacted_text(url)} and would change from "
                           f"{was or 'nothing'} to {version}; the fix command cannot reproduce that")
        changes.append(Change("update" if was else "add", name, was, version))
    if sourced:
        return TrialResult("inconclusive", detail=sourced[0])
    return TrialResult("resolved", changes=tuple(sorted(changes, key=lambda c: c.package)),
                       yanked=tuple(yanked), non_public=frozenset(non_public))


# ---- the sandbox's view of a trial ----------------------------------------------------------

def _pipx_home() -> Path:
    """The pipx home the sandboxed pipx uses."""
    from packagealert.parsers.process_args import _pipx_home as home

    return home()


def _pipx_shared() -> Path:
    """The shared libraries the sandboxed pipx uses: $PIPX_SHARED_LIBS as pipx resolves it (the
    sandbox passes it in), else ``<home>/shared``."""
    if os.environ.get("PIPX_SHARED_LIBS"):
        from packagealert.parsers.process_args import _pipx_shared_libs

        return _pipx_shared_libs()
    return _pipx_home() / "shared"


def trial_workdir(argv: list[str]) -> Path | None:
    """The scratch copy (resolved) a ``trial_argv()`` names its files in; None for anything else."""
    if not is_trial_command(argv):
        return None
    report = argv[argv.index("--report") + 1]
    try:
        return Path(report).parent.resolve(strict=False)
    except (OSError, RuntimeError):
        return None


def _overlaps(a: Path, b: Path) -> bool:
    """Whether *a* and *b* (resolved) are the same, or one lies inside the other."""
    try:
        a, b = a.resolve(strict=False), b.resolve(strict=False)
    except (OSError, RuntimeError):
        return True
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


# What a directory pip builds from has at its root (pip refuses one with none of them).
_PROJECT_FILES = ("pyproject.toml", "setup.py", "setup.cfg")


def checkout_problem(checkout: Path, pipx_home: Path, *, why: str = "which the trial keeps read-only") -> str | None:
    """Why the sandbox must not make *checkout* writable: it is, holds or lies in pipx's home,
    whose venvs and shared libraries a trial keeps read-only (and a reinstall keeps its shared
    libraries read-only, and snapshots its venvs); or it is not a Python project. The path comes
    from an app's pipx_metadata.json, which an earlier sandboxed pipx command could write, so
    it must at least name what pip could build from. None when it may."""
    if _overlaps(checkout, pipx_home):
        return f"the app's checkout {checkout} is, holds or lies in pipx's home {pipx_home}, {why}"
    if not any((checkout / name).is_file() for name in _PROJECT_FILES):
        return (f"the app's checkout {checkout} has no pyproject.toml, setup.py or setup.cfg, so it is not a "
                "project pip could build; pa will not make it writable")
    return None


def _trial_app(argv: list[str]) -> str | None:
    return argv[2] if is_trial_command(argv) else None


def lock_file(app: str, venvs: Path) -> Path:
    """The lock pipx opens read-write around ``runpip`` (``VenvContainer.venv_lock()``)."""
    from packaging.utils import canonicalize_name

    return venvs / f".{canonicalize_name(app)}.lock"


def trial_lock_files(argv: list[str], venvs: Path) -> list[Path]:
    """The one file a trial writes outside its scratch copy: the app's lock (pipx crashes on a
    read-only one before pip starts)."""
    app = _trial_app(argv)
    return [lock_file(app, venvs)] if app else []


def trial_checkouts(argv: list[str], venvs: Path) -> list[Path]:
    """The local checkouts a trial builds in place: pip writes ``<name>.egg-info`` into a local
    or editable package's directory to read its metadata, and fails when it cannot. Read from
    the app's own pipx_metadata.json, since the command names none of them."""
    app = _trial_app(argv)
    if app is None:
        return []
    from packagealert import safe_read

    try:
        meta = read_metadata(safe_read.read_text(venvs / app / METADATA, errors="replace"))
    except (OSError, MetadataError):
        return []
    out = _checkouts(meta)
    for where in out:
        if (problem := checkout_problem(where, venvs.parent)) is not None:
            raise ValueError(problem)
    return out


def _checkouts(meta: PipxMetadata) -> list[Path]:
    """The local directories *meta*'s packages are built from (not a local wheel or sdist file,
    which is only read)."""
    from packagealert.languages.python_fix.uv_tool import _local_location

    return [where for package in (meta.main, *meta.injected)
            if package.local and (where := _local_location(re.sub(r"\[[^\]]*\]\Z", "", package.spec))) is not None
            and not (os.path.lexists(where) and not where.is_dir())]


# What pipx 1.18.4 keeps directly in its home (pipx.paths: venvs, shared, py, logs, .cache, .trash,
# and the legacy-default trash; shared_libs.py: .shared.lock beside shared).
HOME_ENTRIES = frozenset({"venvs", "shared", "py", "logs", ".cache", ".trash", "trash", ".shared.lock"})
# The ones the sandbox binds read-only over a writable home, so each must be a real directory.
READ_ONLY_HOME_DIRS = ("shared", "py", ".cache")
_HOME_FILES = frozenset({".shared.lock"})


def home_problem(home: Path) -> str | None:
    """Why *home* must not be bound writable whole as pipx's home: it holds something pipx
    does not keep there (PIPX_HOME=~/.local would make the user's site-packages and keyrings
    writable), or one of the directories kept read-only is a link. None when it may; a home
    that does not exist yet may (pipx creates it)."""
    try:
        entries = sorted(e.name for e in home.iterdir())
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"cannot list pipx's home {home}: {exc.strerror or exc}"
    unexpected = [e for e in entries if e not in HOME_ENTRIES]
    if unexpected:
        shown = ", ".join(unexpected[:10]) + (f", and {len(unexpected) - 10} more" if len(unexpected) > 10 else "")
        return (f"pipx's home {home} holds entries pipx does not keep there ({shown}); pa run binds the whole "
                "home writable for this command, so it refuses one that is not only pipx's")
    wrong = [e for e in entries if (home / e).is_symlink()
             or not ((home / e).is_file() if e in _HOME_FILES else (home / e).is_dir())]
    if wrong:
        return (f"pipx's home {home} has {', '.join(wrong)} as a link or the wrong kind of entry; pa run binds "
                "the whole home writable for this command, so a link there would make its target writable")
    return None


def app_venv_problem(names: Sequence[str] | None, venvs: Path) -> str | None:
    """Why the venv a pipx command writes must not be written: ``venvs/<name>`` (*names* as pipx
    names them, ``ParsedInstall.pipx_venvs``) is a link, whose site-packages, bin directory and
    backup would be derived from, and written through, it. With *names* None (a venv named only
    after a build), any venv that is a link."""
    if names is None:
        try:
            entries = sorted(venvs.iterdir())
        except FileNotFoundError:
            return None
        except OSError as exc:
            return f"pipx's venvs directory {venvs} cannot be read ({exc})"
        names = [e.name for e in entries]
    for name in names:
        if "/" not in name and name not in ("", ".", "..") and (venvs / name).is_symlink():
            return f"pipx's venv {venvs / name} is a link; pa run will not write through it"
    return None


def venvs_problem(venvs: Path, home: Path) -> str | None:
    """Why pipx's venvs directory (``<home>/venvs``) must not be bound writable: it is a link, or
    not a directory (binding a link would make whatever it names writable). None when it is a
    real directory, or does not exist yet."""
    if not os.path.lexists(venvs):
        return None
    if venvs.is_symlink() or not venvs.is_dir():
        return (f"pipx's venvs directory {venvs} is a link or not a directory of pipx's home {home}; pa run "
                "will not make it writable")
    return None


def recorded_checkouts(apps: Sequence[str], venvs: Path) -> list[Path]:
    """The local directories the pipx apps *apps* (every app in *venvs* when empty) are built
    from, read from each one's pipx_metadata.json (the command names only the app): what
    ``pipx reinstall``/``upgrade`` and their -all forms build from in place. An app whose
    metadata cannot be read contributes nothing, so its rebuild cannot see its source."""
    from packaging.utils import canonicalize_name

    from packagealert import safe_read

    if apps:
        names = [n for app in apps for n in dict.fromkeys((app, canonicalize_name(app)))]
    else:
        try:
            names = sorted(d.name for d in venvs.iterdir() if not d.name.startswith(".") and d.is_dir())
        except OSError:
            return []
    out: list[Path] = []
    for name in names:
        if "/" in name or name in (".", ".."):
            continue
        try:
            meta = read_metadata(safe_read.read_text(venvs / name / METADATA, errors="replace"))
        except (OSError, MetadataError):
            continue
        out += [c for c in _checkouts(meta) if c not in out]
    return out


def rebuild_checkouts(argv: list[str], cwd: Path, venvs: Path) -> list[Path]:
    """The local directories a pipx command other than a trial builds in place, so the sandbox
    must show them writable (pip writes ``<name>.egg-info`` into a plain local checkout too):
    for ``reinstall``, ``upgrade`` and their -all forms each rebuilt app's recorded local
    sources (recorded_checkouts()); for ``install`` each spec naming a local directory."""
    from packagealert.languages.python_fix.uv_tool import _local_location
    from packagealert.parsers.process_args import parse_pipx_args

    if not argv or Path(argv[0]).name.removesuffix(".__pa_real") != "pipx" or is_trial_command(argv):
        return []
    parsed = parse_pipx_args(["pipx", *argv[1:]])
    if parsed is None or argv[1:2] == ["runpip"]:
        return []
    if parsed.rebuilds_recorded_envs:
        return recorded_checkouts(parsed.packages, venvs)
    if parsed.writable_tool_home is None:
        return []
    out: list[Path] = []
    for spec in parsed.packages:
        spec = re.sub(r"\[[^\]]*\]\Z", "", spec)
        where = _local_location(spec) if _is_local(spec) else (
            cwd / spec if spec.startswith(".") or "/" in spec else None)
        if where is not None and where.is_dir():
            out.append(_resolved(where))
    return out


def _is_apply_command(argv: list[str]) -> bool:
    if not argv or Path(argv[0]).name.removesuffix(".__pa_real") != "pipx":
        return False
    return argv[1:2] == ["runpip"] and len(argv) > 4 and argv[3] == "install" and not argv[2].startswith("-")


def local_sources(argv: list[str]) -> list[Path]:
    """The local directories a trial or a fix command reads: each local ``--find-links``,
    ``--index-url`` or ``--extra-index-url`` (a path or a ``file://`` URL)."""
    from packagealert.languages.python_fix.uv_tool import (
        _LOCATION_FLAGS,
        _local_location,
    )

    if not (is_trial_command(argv) or _is_apply_command(argv)):
        return []
    rest = argv[4:]
    return [where for flag, value in itertools.pairwise(rest)
            if flag in _LOCATION_FLAGS and (where := _local_location(value)) is not None]


# ---- configuration the trial and the fix read -----------------------------------------------

# Environment variables pip's configuration depends on (beyond each PIP_* setting).
_PIP_CONFIG_VARS = ("HOME", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "VIRTUAL_ENV", "PYTHONPATH")


def _pip_environment(extra_env: Sequence[str]) -> dict[str, str]:
    from packagealert.sandbox.runner import _settled_sandbox_env

    env = _settled_sandbox_env(list(extra_env))
    return {k: v for k, v in env.items() if k.startswith("PIP_") or k in _PIP_CONFIG_VARS}


def config_problem(trial_env: Sequence[str], apply_env: Sequence[str]) -> str | None:
    """Why the trial and the fix could read different pip configuration, or None.

    Both run pip through ``pipx runpip`` in the sandbox, which shows them the same configuration
    files (the system's, the user's, the app venv's), and pipx runs pip in the app's venv
    directory for both, so a relative path in a setting names the same file. What can differ
    is the environment: each passes the sandbox's allowlist plus its own extra variables
    (*trial_env*, *apply_env*, as ``--env`` names them)."""
    trial, apply = _pip_environment(trial_env), _pip_environment(apply_env)
    differ = sorted(k for k in trial.keys() | apply.keys() if trial.get(k) != apply.get(k))
    if not differ:
        return None
    return (f"the fix would run with different pip settings from its trial ({', '.join(differ)}); "
            "plan again with the same --env")


# ---- the shared pip -------------------------------------------------------------------------

OLDEST_VERIFIED_PIP = "26.2.1"
"""The oldest pip the trial fixtures (tests/fixtures/pip_trial) were recorded with: an older one's
report and errors have not been checked. Never below 22.2, which added ``--dry-run`` and
``--report``."""


def shared_pip_version(env: ToolEnv) -> str | None:
    """The version of the pip in pipx's shared libraries, which ``pipx runpip`` runs for a pip-backend
    app (*env*): read from ``<PIPX_SHARED_LIBS>/lib/python*/site-packages/pip-*.dist-info`` (the
    shared libraries the sandboxed pipx is given, ``<PIPX_HOME>/shared`` by default). None when
    there is not exactly one interpreter directory holding exactly one pip."""
    shared = _pipx_shared() / "lib"
    try:
        sites = [d / "site-packages" for d in shared.iterdir() if d.name.startswith("python")]
        if len(sites) != 1:
            return None
        dists = [d.name for d in sites[0].iterdir() if d.name.startswith("pip-") and d.name.endswith(".dist-info")]
    except OSError:
        return None
    if len(dists) != 1:
        return None
    return dists[0].removeprefix("pip-").removesuffix(".dist-info") or None


def trial_pip_version(env: ToolEnv) -> tuple[str | None, bool]:
    """(the version of the pip ``pipx runpip`` runs for *env*, whether it is the app's own): the
    app's own when its site-packages has one (``<venv>/bin/python -m pip`` imports it before the
    shared libraries' ``.pth`` entry), else the shared one (``shared_pip_version()``). The version
    is None when that cannot be told (a ``pip`` package with no single ``pip-*.dist-info``)."""
    site = env.site_packages
    if site is None:
        return shared_pip_version(env), False
    try:
        names = [e.name for e in site.iterdir()]
    except OSError:
        return None, True
    dists = [n for n in names if n.startswith("pip-") and n.endswith(".dist-info")]
    if not dists and "pip" not in names:
        return shared_pip_version(env), False
    if len(dists) != 1:
        return None, True
    return dists[0].removeprefix("pip-").removesuffix(".dist-info") or None, True


def _pip_problem(version: str | None, own: bool = False) -> TrialResult | None:
    """Why the trial cannot run with pip *version* (the app's *own* pip, or the shared one)."""
    from packaging.version import InvalidVersion, Version

    if version is None:
        return TrialResult("inconclusive", detail="cannot tell which pip pipx uses")
    try:
        old = Version(version) < Version(OLDEST_VERIFIED_PIP)
    except InvalidVersion:
        return TrialResult("inconclusive", detail="cannot tell which pip pipx uses")
    if old and own:
        return TrialResult("inconclusive", detail=f"the app's own pip {version} is too old to verify (pipx runpip "
                                                  "runs it rather than the shared one)")
    return too_old(version) if old else None


# ---- the adapter -----------------------------------------------------------------------------

METADATA = "pipx_metadata.json"


def _sourced(package: PipxPackage) -> bool:
    """Whether *package* is built from its source (a path, git or a URL), not from an index."""
    from packaging.requirements import InvalidRequirement, Requirement

    if package.local or package.editable:
        return True
    try:
        return Requirement(package.spec).url is not None
    except InvalidRequirement:
        return True


def _requirement(package: PipxPackage) -> ToolRequirement:
    """*package* as a receipt requirement, for the dependency graph (name and extras)."""
    from packaging.requirements import InvalidRequirement, Requirement

    from packagealert.languages.python_fix.uv_tool import ToolRequirement

    if package.local:
        extras = re.search(r"\[([^\]]*)\]\Z", package.spec)
        names = tuple(e.strip() for e in extras.group(1).split(",") if e.strip()) if extras else ()
        return ToolRequirement(package.name, "editable" if package.editable else "directory", extras=names,
                               location=package.spec)
    try:
        req = Requirement(package.spec)
        return ToolRequirement(package.name, "url" if req.url else "registry", extras=tuple(sorted(req.extras)),
                               marker=str(req.marker) if req.marker else None)
    except InvalidRequirement:
        return ToolRequirement(package.name, "url")


def _private_index(args: Sequence[str]) -> bool:
    """Whether *args* (``option_args()``) send pip to an index other than public PyPI, or to find-links."""
    from packagealert.parsers.lockfiles import is_public_pypi_index

    for flag, value in itertools.pairwise(args):
        if flag == "--find-links" or (flag in ("--index-url", "--extra-index-url")
                                      and not is_public_pypi_index(value)):
            return True
    return False


class PipxAppFixAdapter:
    """pa fix for one pipx app (``ToolEnv``).

    Its "lock file" is the app's pipx_metadata.json. The trial runs ``pipx runpip`` in a
    scratch copy holding the app's requirement files, with the app's venv read-only; the fix
    is ``pipx runpip <app> install`` with every package the verified trial moves pinned.
    """

    ecosystem = "PyPI"
    lockfile_name = METADATA
    can_force = False
    pins_every_copy = False
    # pins() pins what the app's own requirements move (the baseline), so verification holds a
    # major or too-young version there as it would one a pin makes.
    drift_pinned_by = "the app's own requirements, which the command pins"
    yanks_from_registry = True
    # How --apply names the app and its command (``cli.fix_tools.ToolApplyTarget``).
    kind = "app"
    action = "fix"
    doing = "the fix"
    confirm_note = "pins its packages with pipx runpip"
    applied_label = "packages pinned with pipx runpip"

    @property
    def command_note(self) -> str:
        """Printed under the commands: the pins are not recorded where pipx would keep them."""
        return (f"A later pipx upgrade or pipx reinstall of {self.env.name} can undo these pins; "
                "pa scan-tools reports the packages again if it does.")

    def __init__(self, env: ToolEnv, meta: PipxMetadata | None, meta_bytes: bytes) -> None:
        """*meta* is None only for pipx's shared libraries, which have none (and are held)."""
        self.env = env
        self._meta = meta
        self.name = f"pipx {env.name}"
        self.label = env.label
        self.state = ToolState(meta_bytes, self._installed())
        self._baseline = Baseline()
        # The sandbox --env names the trials ran with (``config_problem()``); None until one runs.
        self.trial_env: tuple[str, ...] | None = None
        packages = (meta.main, *meta.injected) if meta is not None else ()
        # Names installed, recorded or seen in a trial from outside public PyPI: never looked up there.
        self._not_public: set[str] = ({_norm(p.name) for p in env.packages if not p.public}
                                      | {_norm(p.name) for p in packages if _sourced(p)})

    @classmethod
    def for_env(cls, env: ToolEnv) -> PipxAppFixAdapter:
        """MetadataError when the app's pipx_metadata.json cannot be read."""
        from packagealert import safe_read
        from packagealert.languages.python_tools import PIPX_SHARED

        if env.name == PIPX_SHARED:
            return cls(env, None, b"")
        try:
            data = safe_read.read_bytes(env.venv_root / METADATA)
        except OSError as exc:
            raise MetadataError(f"cannot read {METADATA} ({exc.strerror or exc})") from None
        return cls(env, read_metadata(data.decode("utf-8", errors="replace")), data)

    @property
    def meta(self) -> PipxMetadata:
        if self._meta is None:
            raise ValueError("pipx's shared libraries have no metadata")
        return self._meta

    def _installed(self) -> dict[str, frozenset[str]]:
        out: dict[str, set[str]] = {}
        for p in self.env.packages:
            out.setdefault(_norm(p.name), set()).add(p.version)
        return {n: frozenset(v) for n, v in out.items()}

    def _packages(self) -> tuple[PipxPackage, ...]:
        return () if self._meta is None else (self._meta.main, *self._meta.injected)

    @property
    def local(self) -> frozenset[str]:
        """The app's packages built from a local path."""
        return frozenset(_norm(p.name) for p in self._packages() if p.local)

    @property
    def from_source(self) -> frozenset[str]:
        """The app's packages built from their source (a path, git or a URL): no version can be pinned."""
        return frozenset(_norm(p.name) for p in self._packages() if _sourced(p))

    def find_lockfile(self, root: Path) -> Path | None:
        path = root / METADATA
        return path if path.is_file() else None

    def load_graph(self, lockfile: Path) -> DependencyGraph:
        from packagealert.languages.python_fix.uv_tool import (
            Receipt,
            dependency_edges,
            tool_interpreter,
        )
        from packagealert.remediate.graph import DependencyGraph

        member = self.label
        receipt = Receipt(tuple(_requirement(p) for p in self._packages()), None, {}, ())
        names = frozenset(r.canonical for r in receipt.requirements)
        deps = dict(dependency_edges(self.env.site_packages, receipt,
                                     tool_interpreter(self.env.venv_root, self.env.python)))
        deps[member] = names
        non_public = frozenset(_norm(p.name) for p in self.env.packages if not p.public)
        return DependencyGraph(members=frozenset({member}), direct=names, deps=deps,
                               versions=self.state.installed, non_registry=non_public | self.from_source,
                               local_source=self.local)

    def locked_packages(self, lockfile: Path) -> list[PackageSpec]:
        from packagealert.languages.base import PackageSpec

        return [PackageSpec(name=_norm(p.name), version=p.version, ecosystem=self.ecosystem,
                            from_public_registry=p.public) for p in self.env.packages]

    def pins(self, plan: FixPlan) -> list[tuple[str, str]]:
        """Every package the verified trial's end state (``plan.verified_after``) has at a version
        the app does not, at that version; never the main package, which the command must not
        name. The command installs only these, so a package the trial moved without the plan
        asking (a dependency of a fix) is pinned too, or pip would leave it where it is. []
        while the plan has no verified end state; ValueError for a package at several versions,
        or one built from its source, in it."""
        after = plan.verified_after
        if after is None:
            return []
        main = _norm(self.meta.main.name)
        sourced = self.from_source
        out: list[tuple[str, str]] = []
        for name, versions in sorted(after.items()):
            if len(versions) != 1:
                raise ValueError(f"{name} is at several versions in the verified end state")
            (version,) = versions
            canonical = _norm(name)
            if canonical == main or self.state.installed.get(canonical) == frozenset({version}):
                continue
            if canonical in sourced:
                raise ValueError(f"{name} is built from its source; the command cannot move it")
            out.append((name, version))
        return out

    def apply_argv(self, plan: FixPlan) -> list[str] | None:
        """The one command that applies *plan*, or None when there is nothing to apply, the plan
        has no verified end state, or ``held_reason()`` holds the app."""
        if not plan.planned or self.held_reason() is not None:
            return None
        try:
            pins = self.pins(plan)
            return apply_argv(self.env.name, self.meta, pins) if pins else None
        except ValueError:
            return None

    def commands(self, plan: FixPlan, project_dir: Path | None = None,
                 sync_flags: tuple[str, ...] = ()) -> list[list[str]]:
        """The printed command: ``apply_argv()`` with credentials redacted, and, when pipx's home is
        chosen by the environment, that home as an absolute assignment, so it acts on the
        verified app wherever it is pasted."""
        argv = self.apply_argv(plan)
        if argv is None:
            return []
        # The home as pipx resolves it, not the venv's resolved path: venvs may be a link.
        scope = ["env", f"PIPX_HOME={_pipx_home()}"] if os.environ.get("PIPX_HOME") else []
        return [[*scope, *redacted(argv)]]

    def probe_argv(self) -> list[str]:
        from packagealert.sandbox import runner

        return trial_argv(self.env.name, self.meta, [], workdir=runner.SCRATCH_ROOT / "trial")

    async def _run(self, pins: Sequence[tuple[str, str]], run: TrialRunner) -> TrialResult:
        meta = self.meta
        main = self.state.installed.get(_norm(meta.main.name), frozenset())
        files = trial_files(meta, next(iter(main)) if len(main) == 1 else None)

        def write(copy: Path) -> None:
            for name, text in files.items():
                (copy / name).write_text(text)

        copies: list[Path] = []

        def command(copy: Path) -> list[str]:
            copies.append(copy)
            return trial_argv(self.env.name, meta, pins, workdir=copy)

        env = getattr(run, "extra_env", None)
        self.trial_env = tuple(env) if isinstance(env, (list, tuple)) else None
        try:
            out = await run.in_copy([], [write, command], read_back=["report.json"])
        except Exception as exc:  # noqa: BLE001 - a sandbox that refuses the trial: could not verify, with why
            return TrialResult("inconclusive", detail=redacted_text(str(exc)) or "the trial could not run")
        if not out.results:
            return TrialResult("inconclusive", detail="the trial did not run")
        r = out.results[-1]
        result = parse_pip_trial(r.returncode, out.files.get("report.json"), r.stderr, main=meta.main.name,
                                 app=self.env.name, pinned=dict(pins), local=self.local,
                                 installed=self.state.installed, private_index=_private_index(option_args(meta)),
                                 pip_version=trial_pip_version(self.env)[0], timed_out=r.timed_out,
                                 stdout=r.stdout, workdir=copies[-1] if copies else None)
        if result.status != "resolved":
            return result
        # The changes' old versions are installed ones: those not from the public registry are
        # not looked up there either.
        installed = frozenset((_norm(p.name), p.version) for p in self.env.packages if not p.public)
        self._not_public.update(n for n, _ in result.non_public)
        return dataclasses.replace(result, after=_after(self.state.installed, result.changes),
                                   non_public=result.non_public | installed)

    def _blocked_before_trial(self) -> TrialResult | None:
        from packagealert.sandbox import isolation
        from packagealert.sandbox.runner import CONTAINER_IN_PLACE_REFUSAL

        if (held := self.held_reason()) is not None:
            return TrialResult("inconclusive", detail=held)
        try:
            container = isolation.selected() == isolation.CONTAINER
        except isolation.IsolationError as exc:
            return TrialResult("inconclusive", detail=str(exc))
        if container:
            return TrialResult("inconclusive", detail=CONTAINER_IN_PLACE_REFUSAL)
        for checkout in _checkouts(self.meta):
            if (problem := checkout_problem(checkout, _pipx_home())) is not None:
                return TrialResult("inconclusive", detail=problem)
        return _pip_problem(*trial_pip_version(self.env))

    async def trial(self, pins: list[tuple[str, str]], floats: list[str], run: TrialRunner, *,
                    force: Sequence[tuple[str, str]] = (),
                    lowest: Mapping[tuple[str, str], str] | None = None) -> TrialResult:
        """Resolve with *pins* through ``pipx runpip`` (pip keeps whatever it need not move, so
        *floats* say nothing more). The changes are measured from the baseline, as
        verification judges them; ``after`` is the trial's whole end state."""
        if force:
            raise ValueError("the pipx adapter cannot force a version")
        if (blocked := self._blocked_before_trial()) is not None:
            return blocked
        if any(_norm(n) == _bare_name(self.meta.main.name) for n, _ in pins):
            # The command never names the main package (runpip would rewrite pipx's record of
            # the app), so a fix of the app itself is a pipx upgrade.
            return TrialResult("blocked", detail=_main_move_detail(self.meta.main.name, self.env.name))
        result = await self._run(pins, run)
        return measure_from_baseline(self.state.installed, result, await self.baseline(run))

    async def baseline(self, run: TrialRunner) -> TrialResult | None:
        """What a ``runpip install`` of the app's own requirements changes with nothing pinned,
        measured from what the app has installed; run once, and None when it does not resolve."""
        if self._blocked_before_trial() is not None:
            return None
        return await self._baseline.get(lambda: self._run((), run))

    def held_reason(self) -> str | None:
        """Why no command can apply a fix to this app, which holds every fix; None when one can."""
        from packaging.utils import canonicalize_name

        from packagealert.languages.python_tools import PIPX_SHARED

        if self._meta is None or self.env.name == PIPX_SHARED:
            return "pipx owns its shared libraries: run pipx upgrade-shared"
        meta = self._meta
        recorded = f"{meta.main.name}{meta.suffix}"
        if canonicalize_name(recorded) != self.env.name:
            return f"its metadata is for {recorded}, so pipx would act on another app"
        if meta.unsupported:
            # An unknown pip argument is kept as written, and may be a URL with credentials.
            return redacted_text(f"the command cannot carry over the app's {', '.join(meta.unsupported)}")
        if meta.backend == "uv":
            return "uv backend not supported yet"
        if meta.backend != "pip":
            return f"the command cannot carry over the app's {meta.backend} backend"
        live = _pipx_home() / "venvs" / self.env.name
        if _resolved(live) != _resolved(self.env.venv_root):
            # pa run's pipx acts on its own home's app of that name.
            return f"pipx would act on {live}, not {self.env.venv_root}"
        return None

    async def cadences(self, names: list[str]) -> dict[str, str | None]:
        # A private package's name is not sent to PyPI; it has no public release history.
        return await public_cadences(names, self._not_public, _norm)

    # ---- --apply (``cli.fix_tools.ToolApplyTarget``) ----

    @property
    def venv_root(self) -> Path:
        return self.env.venv_root

    @property
    def metadata_path(self) -> Path:
        return self.env.venv_root / METADATA

    @property
    def backup_name(self) -> str:
        return f"pipx-app-{self.env.name}"

    def pin_problem(self, plan: FixPlan) -> str | None:
        """Why the verified plan has no command although the app is not held: ``pins()``'s reason."""
        if not plan.planned or self.held_reason() is not None:
            return None
        try:
            _pin_args(self.meta, self.pins(plan))
        except ValueError as exc:
            return str(exc)
        return None

    def install_root(self, parsed: object) -> Path | None:
        """The venvs directory ``pa run``'s pipx would act in, resolved."""
        return first_write_dir(parsed)

    def bin_dir(self, parsed: object) -> None:
        """None: runpip writes console scripts into the app's own ``bin``, inside the venv, and
        PIPX_BIN_DIR stays read-only."""

    def run_env(self, parsed: object) -> dict[str, str]:
        """PIPX_HOME set to the absolute home ``pa run`` resolved for *parsed*, so a run from
        another directory resolves the same one."""
        dirs = write_dirs(parsed)
        return {"PIPX_HOME": str(dirs[0].parent)} if dirs and dirs[0].is_absolute() else {}

    def read_only_paths(self, parsed: object) -> list[Path]:
        """pipx's shared libraries (``$PIPX_SHARED_LIBS``, else ``<PIPX_HOME>/shared``), which
        every app's pip runs from."""
        dirs = write_dirs(parsed)
        if not dirs:
            return []
        return [_pipx_shared() if os.environ.get("PIPX_SHARED_LIBS") else dirs[0].parent / "shared"]

    def reread(self, root_identity: tuple[str, int, int] | None = None
               ) -> tuple[bytes | None, Inventory | None]:
        """The app's pipx_metadata.json and installed versions now (None for what cannot be read)."""
        meta, env = reread_env(self.env, METADATA, root_identity)
        return meta, (None if env is None else inventory(env))

    def config_problem(self, extra_env: Sequence[str]) -> str | None:
        """Why the fix, run with the sandbox --env names *extra_env*, could read other pip
        settings from its trial; also when no trial recorded its own."""
        if self.trial_env is None:
            return "no trial recorded the pip settings the fix was verified with; plan again"
        return config_problem(self.trial_env, extra_env)

    def executables(self, metadata: bytes | None) -> set[Path]:
        """None outside the venv: runpip's console scripts are in the app's ``bin``."""
        return set()

    def end_state_problem(self, expected: Mapping[str, frozenset[str]], before: Mapping[str, frozenset[str]],
                          root_identity: tuple[str, int, int] | None) -> str | None:
        """Why the app after the fix is not the verified end state, or None when it is: its
        pipx_metadata.json must be byte for byte what it was, the venv must still start, and every
        package must be at its verified version (*expected*), or, one the plan does not name, at
        the version installed just before the run (*before*)."""
        venv = self.env.venv_root
        meta, env = reread_env(self.env, METADATA, root_identity)
        if not in_place(venv, root_identity):
            return "the app's directory was replaced during the run"
        if meta != self.state.receipt_bytes:
            return f"{METADATA} changed during the fix"
        if not is_venv(venv):
            return "the app is not a working virtualenv after the fix (pyvenv.cfg or bin/python is missing)"
        if env is None:
            return "the app's packages could not be read after the fix"
        after = inventory(env)
        problems = []
        for name in sorted(expected.keys() | before.keys() | after.keys()):
            want = expected.get(name, before.get(name, frozenset()))
            got = after.get(name, frozenset())
            if got != want:
                problems.append(f"{name} {', '.join(sorted(got)) or 'absent'} "
                                f"(expected: {', '.join(sorted(want)) or 'absent'})")
        return f"pip did not install the verified versions: {'; '.join(problems)}" if problems else None


def _resolved(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return path
