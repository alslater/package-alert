"""pa fix's npm trial: run npm against a scratch copy and compare lock files.

npm has no dry-run resolve and its summary says "up to date" even after
rewriting the lock, so a trial reads only the resulting package-lock.json.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from packagealert.languages.node_fix import npm_lock
from packagealert.osv.remediation import _generic_key
from packagealert.remediate.adapter import Blocker, Change, TrialResult, TrialRunner

FLAGS = ("--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund")
FILES = ["package.json", "package-lock.json", ".npmrc"]
_NAME = r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"
_VERSION = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
_SPEC_RE = re.compile(rf"{_NAME}@{_VERSION}", re.IGNORECASE)
# npm-package-arg reads a spec ending in one of these as a local tarball, version-shaped or not.
_FILE_SUFFIXES = (".tgz", ".tar", ".tar.gz")
_CODE_RE = re.compile(r"^npm error code (\S+)", re.MULTILINE)
_ERROR_LINE_RE = re.compile(r"^npm error (\S.*)$", re.MULTILINE)
_NAME_RE = re.compile(_NAME, re.IGNORECASE)
# npm 11: "npm error notarget No matching version found for express@99.0.0."
_ETARGET_RE = re.compile(r"No matching version found for (\S+?)\.?(?:\s|$)")
# npm 11: "npm error peer react@"^18.2.0" from react-dom@18.2.0"
_PEER_RE = re.compile(r"peer (\S+) from (\S+)@(\S+)")
_RELEASE_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")

Release = tuple[int, int, int]
# A pin's scope: (package, target, lowest copy it moves, major_floor(lowest)).
_Window = tuple[str, str, str, Release]


class ExistingOverride(Exception):
    """package.json already overrides this package; pa fix does not rewrite it."""


class _EditFailed(Exception):
    """The copied package.json could not be read or written."""


# The sections of a release that declare what it depends on.
_DEP_SECTIONS = ("dependencies", "peerDependencies", "optionalDependencies")
_REGISTRY = "https://registry.npmjs.org"


def install_argv(specs: list[str]) -> list[str]:
    return ["npm", "install", *specs, *FLAGS]


def update_argv(names: list[str]) -> list[str]:
    return ["npm", "update", *names, *FLAGS]


def is_scratch_command(argv: list[str]) -> bool:
    """Whether *argv* is a command an npm trial runs in its scratch copy.

    Exactly `npm install [name@version …]` or `npm update <name …>`, with each
    of FLAGS once (in any order) and no other option; versions are exact and
    names are registry package names. An install spec's version is an exact
    semver version (no range) and the spec does not end in .tgz, .tar or
    .tar.gz, so no path, tarball, URL, git, range or alias spec passes.
    """
    if len(argv) < 2 or Path(argv[0]).name != "npm" or argv[1] not in ("install", "update"):
        return False
    rest = argv[2:]
    flags = [a for a in rest if a.startswith("-")]
    args = [a for a in rest if not a.startswith("-")]
    if sorted(flags) != sorted(FLAGS):
        return False
    if argv[1] == "install" and any(a.lower().endswith(_FILE_SUFFIXES) for a in args):
        return False
    pattern = _SPEC_RE if argv[1] == "install" else _NAME_RE
    return all(pattern.fullmatch(a) for a in args) and (argv[1] == "install" or bool(args))


def _key(version: str) -> Any:
    k = _generic_key(version)
    if k is None:
        raise ValueError(f"unreadable version {version!r}")
    return k


def _release(version: str) -> Release:
    """*version*'s major, minor and patch numbers (any prerelease or build part is ignored)."""
    m = _RELEASE_RE.match(version)
    if m is None:
        raise ValueError(f"unreadable version {version!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def major_floor(version: str) -> Release:
    """The first release on *version*'s npm major line: its first non-zero component, the rest zero.

    npm's caret rule: 6.3.1 -> 6.0.0, 0.3.4 -> 0.3.0, 0.0.3 -> 0.0.3.
    """
    major, minor, patch = _release(version)
    if major:
        return major, 0, 0
    return (0, minor, 0) if minor else (0, 0, patch)


def lowest_locked_below(lock: dict, name: str, target: str) -> str | None:
    """The lowest locked version of *name* below *target* on the highest major line that has one, or None.

    Only that line: a copy on an older line is not the one an upgrade to
    *target* replaces, and reaching back to it would move it across lines too.
    """
    try:
        below = [v for n, v in npm_lock.copies(lock).values()
                 if n == name and v is not None and _RELEASE_RE.match(v) and _key(v) < _key(target)]
        return lowest_on_top_line(below)
    except (ValueError, npm_lock.NpmLockError):
        return None


def lowest_on_top_line(versions: Iterable[str]) -> str | None:
    """The lowest of *versions* on the highest major line among them, or None when there are none."""
    versions = list(versions)
    if not versions:
        return None
    top = max(major_floor(v) for v in versions)
    return min((v for v in versions if major_floor(v) == top), key=_key)


def override_key(name: str, lowest: str, target: str) -> str:
    """The overrides key moving copies of *name* from *lowest*'s major line up to *target*.

    The range starts at the major line of *lowest* (the lowest copy the fix
    moves), so copies on older lines are never matched, and ends below
    *target*, so copies already at or above it are not. ``npm pkg set`` splits
    its argument at the first ``=``, so the key cannot spell ``>=``; it uses
    node-semver's X-range instead: ``>6`` is ``>=7.0.0``, ``>0.2`` is
    ``>=0.3.0`` and ``>0.0.2`` is ``>0.0.2``.
    """
    major, minor, patch = major_floor(lowest)
    if major:
        lower = f">{major - 1}"
    elif minor:
        lower = f">0.{minor - 1}"
    elif patch:
        lower = f">0.0.{patch - 1}"
    else:
        return f"{name}@<{target}"
    return f"{name}@{lower} <{target}"


def _checked_copies(lock: dict) -> dict[str, tuple[str, str]]:
    """Each installed copy's lock path -> (name, version); ValueError for a copy without a version."""
    out: dict[str, tuple[str, str]] = {}
    for path, (name, version) in npm_lock.copies(lock).items():
        if version is None:
            raise ValueError(f"lock entry for {name} has no version")
        out[path] = (name, version)
    return out


_Dependent = tuple[str, str | None, dict[str, tuple[str, str]]]
"""One dependent copy: (lock path, version, {declared dependency: (package, version) it resolves}).

Keyed by the name the dependent declares, not the package's own name: two
aliases of one package (``first`` and ``second`` both ``npm:qs@…``) are
separate dependencies that can resolve different versions.
"""


def _dependents_by_name(lock: dict, copies: Mapping[str, tuple[str, str]]) -> dict[str, list[_Dependent]]:
    out: dict[str, list[_Dependent]] = {}
    for path, name, version, deps in npm_lock.dependents(lock):
        resolved = {dep: copies[p] for dep, p in deps.items() if p in copies}
        out.setdefault(name, []).append((path, version, resolved))
    return out


def _line(d: _Dependent) -> object:
    try:
        return major_floor(d[1]) if d[1] else None
    except ValueError:
        return None


def _counterpart(x: _Dependent, others: list[_Dependent]) -> _Dependent | None:
    """*x*'s closest counterpart among *others* (see ``_match``), or None."""
    lx = _line(x)
    for same in (lambda y: y[0] == x[0] and y[1] == x[1],
                 lambda y: y[1] == x[1],
                 lambda y: lx is not None and _line(y) == lx and y[0] == x[0],
                 lambda y: lx is not None and _line(y) == lx,
                 lambda y: y[0] == x[0]):
        found = next((y for y in others if same(y)), None)
        if found is not None:
            return found
    return None


def _match(before: list[_Dependent], after: list[_Dependent]) -> tuple[list[tuple[_Dependent, _Dependent]],
                                                                     list[_Dependent], list[_Dependent]]:
    """Pair one package's copies across the two locks: (pairs, copies only before, copies only after).

    Each copy, on either side, is compared with its closest counterpart on
    the other: the same path and version, else the same version (npm moved
    the copy), else a copy on the same major line, preferring the same path
    (npm patched it; the line is what its dependents ask for), else the same
    path (updated in place across lines). Counterparts can be shared, since
    npm often merges several copies into one or splits one into several, so
    a copy only counts as appearing or disappearing when it has none.
    """
    b, a = sorted(before, key=lambda d: d[0]), sorted(after, key=lambda d: d[0])
    pairs: list[tuple[_Dependent, _Dependent]] = []
    gone: list[_Dependent] = []
    added: list[_Dependent] = []
    for x in b:
        y = _counterpart(x, a)
        if y is None:
            gone.append(x)
        else:
            pairs.append((x, y))
    for y in a:
        x = _counterpart(y, b)
        if x is None:
            added.append(y)
        elif (x, y) not in pairs:
            pairs.append((x, y))
    return pairs, gone, added


def diff(before: dict, after: dict, floor: dict | None = None) -> tuple[Change, ...]:
    """What changed for the packages that depend on each copy; see ``diff_with_declined``."""
    return diff_with_declined(before, after, floor)[0]


def diff_with_declined(
    before: dict, after: dict, floor: dict | None = None,
) -> tuple[tuple[Change, ...], tuple[Change, ...]]:
    """What changed for the packages that depend on each copy, dependent copy by dependent copy.

    npm moves copies between lock paths as it hoists, so a path's version is
    not what matters; what each dependent resolves is. Every copy of a
    dependent (and the root) is matched with its counterpart in the other lock
    (see ``_match``), and each dependency it resolves to a different version
    is an ``update``. A dependent that newly resolves a dependency is an
    ``add``, and one that stops is a ``remove``, but only for a version
    installed or removed outright: depending on a copy that was already there
    installs nothing. So a swap of hoisted copies that leaves every dependent
    its version is no change, while one copy of a parent moved onto (or off)
    a version another copy has is. Raises ValueError for a copy without a
    version or a changed version it cannot order.

    *floor* is the project's own lock when *before* is the baseline (a plain
    re-lock, which can move dependents up): a dependent moving below its
    *before* version is then a downgrade only when it also ends below what it
    resolves in *floor*. Otherwise it declines the baseline's upgrade, which
    is returned separately, as (changes, declined); and when it ends above
    the *floor* version it still installs a new version, so that is also an
    ``update`` from the *floor* version in changes, or an ``add`` when
    *floor* does not resolve it at all (the baseline added it).
    """
    old_copies, new_copies = _checked_copies(before), _checked_copies(after)
    old_versions = set(old_copies.values())
    new_versions = set(new_copies.values())
    old, new = _dependents_by_name(before, old_copies), _dependents_by_name(after, new_copies)
    held = _dependents_by_name(floor, _checked_copies(floor)) if floor is not None else {}
    events: list[tuple[str, str, str | None, str | None]] = []
    declined: list[tuple[str, str, str | None, str | None]] = []

    def floor_version(name: str, dependent: _Dependent, dep: str, now: tuple[str, str]) -> str | None | bool:
        """What *dependent* resolves *dep* to in the project's own lock (*floor*), when that is *now* or lower.

        True when the project's lock does not resolve it at all (the re-lock
        adds it), False when it resolves it higher than *now* (a downgrade).
        """
        match = _counterpart(dependent, held.get(name, []))
        was = match[2].get(dep) if match is not None else None
        if was is None or was[0] != now[0]:
            return True
        if _key(was[1]) > _key(now[1]):
            return False
        return was[1]

    def compare(was: Mapping[str, tuple[str, str]], now: Mapping[str, tuple[str, str]],
                name: str = "", dependent: _Dependent | None = None) -> None:
        for dep in sorted(was.keys() | now.keys()):
            r_was, r_now = was.get(dep), now.get(dep)
            if r_was == r_now:
                continue
            if (floor is not None and dependent is not None and r_was is not None and r_now is not None
                    and r_was[0] == r_now[0] and _key(r_now[1]) < _key(r_was[1])
                    and (kept := floor_version(name, dependent, dep, r_now)) is not False):
                # Declines the baseline's upgrade without going below the project's own version.
                declined.append(("update", r_now[0], r_was[1], r_now[1]))
                if kept is True:
                    # The project's lock has none: this version is newly installed.
                    events.append(("add", r_now[0], None, r_now[1]))
                elif kept != r_now[1]:
                    # Still above what the project has: a version it newly installs.
                    events.append(("update", r_now[0], kept, r_now[1]))
                continue
            if r_was is None:
                if r_now is not None and r_now not in old_versions:
                    events.append(("add", r_now[0], None, r_now[1]))
            elif r_now is None:
                if r_was not in new_versions:
                    events.append(("remove", r_was[0], r_was[1], None))
            elif r_was[0] == r_now[0]:
                events.append(("update", r_now[0], r_was[1], r_now[1]))
            else:
                # The alias now points at a different package: one removed, one installed.
                if r_was not in new_versions:
                    events.append(("remove", r_was[0], r_was[1], None))
                if r_now not in old_versions:
                    events.append(("add", r_now[0], None, r_now[1]))

    for name in sorted(old.keys() | new.keys()):
        pairs, gone, added = _match(old.get(name, []), new.get(name, []))
        for x, y in pairs:
            compare(x[2], y[2], name, y)
        for x in gone:
            compare(x[2], {})
        for y in added:
            compare({}, y[2])
    after_versions: dict[str, set[str]] = {}
    for name, version in new_copies.values():
        after_versions.setdefault(name, set()).add(version)
    def build(found: list[tuple[str, str, str | None, str | None]]) -> tuple[Change, ...]:
        out = []
        for action, name, was, now in dict.fromkeys(found):
            for v in (was, now):
                if v is not None:
                    _key(v)
            versions = after_versions.get(name, set())
            forks = tuple(sorted(versions, key=_key)) if len(versions) > 1 else ()
            out.append(Change(action, name, was, now, forks))
        return tuple(out)

    return build(events), build(declined)


def _overrides(value: object, name: str) -> bool:
    """Whether an overrides object (at any nesting) has a key for *name*."""
    if not isinstance(value, dict):
        return False
    for key, inner in value.items():
        k = str(key).lower()
        if k == name or k.startswith(f"{name}@") or _overrides(inner, name):
            return True
    return False


def override_edit(name: str, target: str, lowest: str | None = None) -> Callable[[Path], None]:
    """An edit adding ``override_key(name, lowest, target): target`` to the copy's package.json overrides.

    *lowest* defaults to *target*. Copies on a major line below *lowest*'s and
    copies already at or above *target* are untouched by the range-scoped key.
    Raises ExistingOverride when package.json already overrides *name*.
    """
    return override_edits([(name, lowest or target, target)])


def override_edits(entries: Sequence[tuple[str, str, str]]) -> Callable[[Path], None]:
    """One edit adding an ``override_key(name, lowest, target): target`` entry per (name, lowest, target).

    Raises ExistingOverride when the copied package.json already overrides one
    of the names (several entries for one name, on different major lines, are
    pa fix's own); _EditFailed when it cannot be read or written.
    """
    def edit(copy: Path) -> None:
        path = copy / "package.json"
        try:
            manifest = json.loads(path.read_text())
            if not isinstance(manifest, dict):
                raise TypeError("package.json is not an object")
            overrides = manifest.setdefault("overrides", {})
            if not isinstance(overrides, dict):
                raise TypeError("package.json overrides is not an object")
        except (OSError, ValueError, TypeError) as exc:
            raise _EditFailed(str(exc)) from exc
        for name, _lowest, _target in entries:
            if _overrides(overrides, name.lower()):
                raise ExistingOverride(name)
        for name, low, target in entries:
            overrides[override_key(name, low, target)] = target
        try:
            path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        except OSError as exc:
            raise _EditFailed(str(exc)) from exc
    return edit


def override_removal(entries: Sequence[tuple[str, str, str]]) -> Callable[[Path], None]:
    """An edit removing the keys ``override_edits(entries)`` added (and ``overrides`` itself once empty).

    The project's own overrides stay. Raises _EditFailed when package.json
    cannot be read or written.
    """
    def edit(copy: Path) -> None:
        path = copy / "package.json"
        try:
            manifest = json.loads(path.read_text())
            overrides = manifest.get("overrides") if isinstance(manifest, dict) else None
            if not isinstance(overrides, dict):
                raise TypeError("package.json overrides is not an object")
            for name, low, target in entries:
                overrides.pop(override_key(name, low, target), None)
            if not overrides:
                del manifest["overrides"]
            path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        except (OSError, ValueError, TypeError) as exc:
            raise _EditFailed(str(exc)) from exc
    return edit


def _declared_spec(lock: dict, path: str, name: str, holder: str) -> str | None:
    """The range declared for the copy at *path* by a package that resolves *name* to it.

    The holder's own declaration is preferred; otherwise the copy's direct
    parent's: the package whose node_modules holds a nested copy, or for a
    hoisted copy the package before it on the shortest dependency chain.
    Then any other declaring package, then the root.
    """
    packages = lock["packages"]
    found: dict[str, str] = {}
    for parent, info in packages.items():
        if parent and not npm_lock._installed(parent, info):
            continue
        spec = npm_lock.declared_range(lock, parent, name)
        if spec is not None and npm_lock.resolve(lock, parent, name) == path:
            found[parent] = spec
    others = sorted(p for p in found if p)
    if f"node_modules/{holder}" in found:
        return found[f"node_modules/{holder}"]
    container = path.rsplit("/node_modules/", 1)[0] if "/node_modules/" in path else ""
    if container in others:
        return found[container]
    chain = npm_lock.load_graph_from(lock).path_to(name)
    if len(chain) > 1:
        parent_name = chain[-2]
        for p in others:
            if npm_lock._name_of(p, packages[p]) == parent_name:
                return found[p]
    if others:
        return found[others[0]]
    return found.get("")


def _pinner(lock: dict, path: str, target: str, holder: str,
            exempt: frozenset[str] = frozenset()) -> tuple[str, str] | None:
    """(name, declared range) of a package whose range for the copy at *path* does not admit *target*.

    That package, not necessarily a direct dependency, is what keeps the copy
    back, so it is the one to upgrade. Preferred: the direct *holder*, then the
    package whose node_modules holds the copy, then the one nearest the root.
    None when every dependent admits *target* (npm has simply not moved it).
    Dependents named in *exempt* are not considered.
    """
    graph = npm_lock.load_graph_from(lock)
    container = path.rsplit("/node_modules/", 1)[0] if "/node_modules/" in path else None
    found: list[tuple[tuple[int, int, str], str, str]] = []
    for dpath, dname, _version, deps in npm_lock.dependents(lock):
        if not dpath or dname is None or dname in exempt:
            continue
        for declared, copy in deps.items():
            if copy != path:
                continue
            spec = npm_lock.declared_range(lock, dpath, declared)
            if spec is not None and _admits(target, spec):
                continue
            spec = spec if spec is not None else "an unreadable range"
            depth = len(graph.path_to(dname)) or len(lock["packages"])
            rank = 0 if dname == holder else 1 if dpath == container else 2
            found.append(((rank, depth, dpath), dname, spec))
    if not found:
        return None
    _rank, dname, spec = min(found)
    return dname, spec


def _left_below(after: dict, windows: Sequence[_Window], force: Collection[tuple[str, str]]) -> TrialResult | None:
    """The first copy of a pinned package still below its target in its window, as a trial result.

    A copy remains when it is on or above its window's floor (see
    ``major_floor``) and below the target; a copy on an older major line is
    not one that pin moves. For an unforced pin it is ``blocked`` by the
    package keeping it there (``_pinner``, else the direct dependency holding
    it); for a forced pin the override did not reach it (a bundled copy, say),
    so the trial is ``inconclusive``.
    """
    for name, target, _low, floor in windows:
        for path, (n, version) in sorted(npm_lock.copies(after).items()):
            if (n == name and version is not None and _release(version) >= floor
                    and _key(version) < _key(target)):
                if (name, target) in force:
                    return TrialResult("inconclusive",
                                       detail=f"the override did not reach {name} {version} at {path}")
                holder = npm_lock.holder_of(after, path)
                pinner = _pinner(after, path, target, holder)
                parent, spec = pinner if pinner else (holder, _declared_spec(after, path, name, holder))
                return TrialResult("blocked", blocker=Blocker(parent, f"{name}@{spec or version}"),
                                   detail=f"{name} {version} stays under {parent}")
    return None


def _crossed(changes: Iterable[Change], forced: Sequence[_Window]) -> TrialResult | None:
    """An ``inconclusive`` result when an override moved a copy from a major line no override covers.

    Only lines below the highest forced line count: an override never matches
    a copy above its target. The lowest such copy is named, so the detail does
    not depend on lock order.
    """
    lines: dict[str, set[Release]] = {}
    for name, _target, _low, floor in forced:
        lines.setdefault(name, set()).add(floor)
    crossed = [c for c in changes
               if c.package in lines and c.action in ("update", "remove") and c.old is not None
               and major_floor(c.old) not in lines[c.package] and major_floor(c.old) < max(lines[c.package])]
    if not crossed:
        return None
    c = min(crossed, key=lambda c: (c.package, _release(c.old or "")))
    return TrialResult("inconclusive", detail=f"the override moved {c.package} {c.old} across a major line")


def _failure(stderr: str, returncode: int) -> TrialResult:
    """Map a failed npm command fail-closed: ETARGET and ERESOLVE block, anything else is unknown."""
    if "code ETARGET" in stderr:
        m = _ETARGET_RE.search(stderr)
        return TrialResult("blocked", detail=f"no such version: {m.group(1) if m else 'see npm error'}")
    if "code ERESOLVE" in stderr:
        m = _PEER_RE.search(stderr)
        blocker = Blocker(m.group(2), f"peer {m.group(1)}") if m else None
        return TrialResult("blocked", blocker=blocker, detail="npm found a peer dependency conflict")
    if m := _CODE_RE.search(stderr):
        what = f"code {m.group(1)}"
    elif m := _ERROR_LINE_RE.search(stderr):
        what = m.group(1)
    else:
        what = f"exit status {returncode}"
    return TrialResult("inconclusive", detail=f"npm failed: {what}")


def _declares(info: dict, package: str) -> str | None:
    """The range a lock entry declares for *package* (in any dependency section), or None."""
    for section in npm_lock._DEP_KEYS:
        deps = info.get(section)
        if isinstance(deps, dict) and isinstance(deps.get(package), str):
            return deps[package]
    return None


def _admits(version: str, spec: str) -> bool:
    """Whether npm's range *spec* admits *version* (a tag, alias, URL or unreadable spec does not)."""
    import nodesemver

    try:
        return bool(nodesemver.satisfies(version, spec))
    except Exception:  # noqa: BLE001 - node-semver raises assorted errors for specs that are not ranges
        return False


def parent_release_admitting(document: object, above: str, package: str, target: str) -> tuple[str, str] | None:
    """The lowest release above *above* in a registry package document whose declared range admits *target*.

    Returns (release, range) for *package*, read from the release's
    dependencies, peerDependencies or optionalDependencies; prereleases are
    skipped. None when no release qualifies or the document is not the
    expected shape.
    """
    versions = document.get("versions") if isinstance(document, dict) else None
    if not isinstance(versions, dict):
        return None
    try:
        floor = _key(above)
    except ValueError:
        return None
    found = []
    for version, info in versions.items():
        if (not isinstance(version, str) or not re.fullmatch(_VERSION, version) or "-" in version
                or not isinstance(info, dict) or _key(version) <= floor):
            continue
        for section in _DEP_SECTIONS:
            declared = info.get(section)
            spec = declared.get(package) if isinstance(declared, dict) else None
            if isinstance(spec, str) and _admits(target, spec):
                found.append((_key(version), version, spec))
                break
    if not found:
        return None
    _k, version, spec = min(found)
    return version, spec


async def fetch_package_document(name: str) -> object | None:
    """The public npm registry's (abbreviated) document for *name*, or None when it cannot be fetched."""
    import httpx

    from packagealert.languages.node import quote_npm_name

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{_REGISTRY}/{quote_npm_name(name)}",
                                    headers={"Accept": "application/vnd.npm.install-v1+json"})
        if resp.status_code != 200:
            return None
        return resp.json()
    except (httpx.HTTPError, ValueError):
        return None


async def find_parent_upgrade(
    lock: dict, parent: str, package: str, target: str, project_dir: Path,
    fetch: Callable[[str], Awaitable[object | None]] | None = None,
) -> tuple[str, str] | None:
    """The lowest release of *parent* above its locked copies that admits *package* at *target*.

    Read from the public registry, so only when every locked copy of *parent*
    came from it (a private package of the same name is a different one),
    each classified as the lock parser does (``package_lock_provenance()``):
    a copy declared from a URL is not, and one without a resolved URL takes
    the registry npm is configured with for *project_dir*.
    The release is looked for above the highest of the copies holding
    *package* back (those whose declared range does not admit *target*), so it
    replaces each of them, and a copy on another major line that already
    admits it does not decide the line. None when the
    parent is not locked, is not public, the copies holding it back are on
    more than one major line (no one release moves them all), or no release
    qualifies.
    """
    from packagealert.languages.node import npm_registries, package_lock_provenance

    packages = npm_lock._validate(lock)
    entries = [(path, info) for path, info in packages.items()
               if path and isinstance(info, dict) and npm_lock._installed(path, info)
               and npm_lock._name_of(path, info) == parent and isinstance(info.get("version"), str)]
    provenance = package_lock_provenance(packages, npm_registries(project_dir))
    if not entries or not all(provenance.get(path, False) for path, _info in entries):
        return None
    holding = [info["version"] for _path, info in entries if not _admits(target, _declares(info, package) or "")]
    try:
        versions = holding or [info["version"] for _path, info in entries]
        if len({major_floor(v) for v in versions}) > 1:
            return None
        # Above the highest of them, so the release replaces every one: one between
        # the copies would leave the higher copies, still pinning *package*, behind.
        highest = max(versions, key=_key)
    except ValueError:
        return None
    document = await (fetch or fetch_package_document)(parent)
    return parent_release_admitting(document, highest, package, target)


def _outside_declared(lock: dict, name: str, target: str, floor: Release,
                      exempt: frozenset[str] = frozenset()) -> TrialResult | None:
    """``blocked`` when a package depending on a copy the override would move does not admit *target*.

    An override past a version a parent declares (``@remix-run/router@1.9.0``
    under react-router 6.16) resolves cleanly but can break that parent at
    run time, which no lock comparison can see; upgrading the parent is the
    fix. Only copies in the override's window (*floor* to *target*) count, and
    the package named is ``_pinner()``'s choice. Dependents in *exempt* (ones
    the same trial pins) are judged after it, by ``_pinned_after``.
    """
    for path, (n, version) in sorted(npm_lock.copies(lock).items()):
        if n != name:
            continue
        try:
            in_window = version is not None and floor <= _release(version) < _release(target)
        except ValueError:
            in_window = True
        if not in_window:
            continue
        if pin := _pinner(lock, path, target, npm_lock.holder_of(lock, path), exempt):
            return _pinned_result(name, pin)
    return None


def _pinned_result(name: str, pin: tuple[str, str]) -> TrialResult:
    parent, spec = pin
    return TrialResult("blocked", blocker=Blocker(parent, f"{name}@{spec}"),
                       detail=f"{parent} pins {name}@{spec}; upgrade {parent} rather than override it")


def _pinned_after(after: dict, name: str, target: str) -> TrialResult | None:
    """``blocked`` when a dependent in the resulting lock declares a range for an overridden copy that excludes *target*."""
    for path, (n, version) in sorted(npm_lock.copies(after).items()):
        if n == name and version == target and (pin := _pinner(after, path, target, npm_lock.holder_of(after, path))):
            return _pinned_result(name, pin)
    return None


_Step = list[str] | Callable[[Path], None]
"""A command run in the scratch copy, or an edit made on it between commands."""


async def _resulting_lock(
    run: TrialRunner, argvs: list[_Step], edit: Callable[[Path], None] | None,
) -> dict | TrialResult:
    """Run *argvs* in a scratch copy and return the lock they leave, or the ``TrialResult`` saying why not."""
    try:
        out = await run.in_copy(FILES, argvs, edit)
    except ExistingOverride as exc:
        return TrialResult("inconclusive", detail=f"package.json already overrides {exc}")
    except _EditFailed as exc:
        return TrialResult("inconclusive", detail=f"could not add the override to package.json: {exc}")
    last = out.results[-1] if out.results else None
    if last is None or last.timed_out:
        return TrialResult("inconclusive", detail="the trial did not finish")
    if last.returncode != 0:
        return _failure(last.stderr, last.returncode)
    raw = out.files.get("package-lock.json")
    if raw is None:
        return TrialResult("inconclusive", detail="the trial left no lock file")
    try:
        return npm_lock.check_lock(json.loads(raw), "the trial's lock file")
    except (ValueError, npm_lock.NpmLockError) as exc:
        return TrialResult("inconclusive", detail=f"could not read the trial's lock file: {exc}")


async def run_baseline(run: TrialRunner) -> dict | TrialResult:
    """The lock a plain ``npm install`` (nothing pinned) leaves: what npm re-resolves regardless of any fix."""
    return await _resulting_lock(run, [install_argv([])], None)


async def run_trial(
    direct: frozenset[str], before: dict, pins: Sequence[tuple[str, str]], floats: Sequence[str],
    run: TrialRunner, *, force: Sequence[tuple[str, str]] = (), lowest: Mapping[tuple[str, str], str] | None = None,
    plain_after: dict | None = None, floor: dict | None = None,
) -> TrialResult:
    """Run npm with *pins* (direct ones installed, *force*d ones overridden) and *floats* updated.

    *force* holds pins, (package, target), not names: one package can be
    pinned on several major lines, and only the windows forced are overridden.

    *direct* is the project's direct dependencies and *before* the lock the
    changes are measured from: the baseline (``run_baseline()``) when there is
    one, so what npm re-resolves anyway is not blamed on the pins.
    *plain_after* is that baseline's own lock: a trial running exactly the
    baseline's command (nothing installed, updated or overridden) reuses it,
    and *floor* is the project's own lock, which a downgrade is judged
    against (see ``diff``).
    *lowest* maps a pin (package, target) to the lowest vulnerable copy it is
    meant to move (default: its target); only copies from that copy's major
    line up to the target count, and a forced override is scoped to them, so
    one package can be pinned on several major lines at once. A transitive
    pin that is not forced is only checked: a copy left below its target is
    ``blocked`` by the package keeping it there. A transitive pin with no
    *lowest* entry is a parent upgrade and is overridden within its own
    major line, since installing it would make it a direct dependency; its
    window starts from the project's own lock (*floor*, else *before*), as the
    printed commands scope it. A forced override that moves a copy from a
    major line it does not cover is ``inconclusive``.
    """
    forced_pins = set(force)
    parents: set[tuple[str, str]] = set()
    if lowest is not None:
        parents = {(n, v) for n, v in pins if n not in direct and (n, v) not in lowest and (n, v) not in forced_pins}
        forced_pins |= parents
    windows: list[_Window] = []
    # The project's own lock: what the scratch copy (and the user's real install)
    # starts from, and what the printed commands scope a parent's override by.
    project_lock = floor if floor is not None else before
    try:
        for n, v in pins:
            # A parent upgrade's window starts at its lowest locked copy below the
            # target, so one across a major line (p 3.8.4 -> 5.0.7) still reaches it.
            low = ((lowest or {}).get((n, v))
                   or (lowest_locked_below(project_lock, n, v) if (n, v) in parents else None) or v)
            windows.append((n, v, low, major_floor(low)))
    except ValueError as exc:
        return TrialResult("inconclusive", detail=f"cannot scope the fix: {exc}")
    specs = [f"{n}@{v}" for n, v in pins if n in direct and (n, v) not in forced_pins]
    argvs: list[_Step] = [install_argv(specs)]
    if floats:
        argvs.append(update_argv(list(floats)))
    forced = [w for w in windows if (w[0], w[1]) in forced_pins]
    entries = [(n, low, v) for n, v, low, _floor in forced]
    edit = override_edits(entries) if forced else None
    if forced:
        # The overrides are temporary: once the first install has locked the
        # targets, they are removed and the project re-locked. Every dependent's
        # range admits the target (checked here and after the run), so npm keeps
        # it; the second lock is the one judged, and package.json is left as it was.
        argvs += [override_removal(entries), install_argv([])]
    # Packages this trial pins change with it, so their ranges are judged in
    # the resulting lock instead (``_pinned_after``).
    pinned = frozenset(n for n, _v in pins)
    for n, v, _low, line in forced:
        if blocked := _outside_declared(before, n, v, line, pinned):
            return blocked
    if plain_after is not None and argvs == [install_argv([])] and edit is None:
        after: dict | TrialResult = plain_after
    else:
        after = await _resulting_lock(run, argvs, edit)
    if isinstance(after, TrialResult):
        return after
    try:
        changes, declined = diff_with_declined(before, after, floor)
        if crossed := _crossed(changes, forced):
            return crossed
        if below := _left_below(after, windows, forced_pins):
            return below
        for n, v, _low, _line in forced:
            if blocked := _pinned_after(after, n, v):
                return blocked
    except (ValueError, npm_lock.NpmLockError) as exc:
        return TrialResult("inconclusive", detail=f"could not read the trial's lock file: {exc}")
    return TrialResult("resolved", changes, declined=declined, non_public=non_public_versions(after, changes, run.project_dir))


def non_public_versions(after: dict, changes: Iterable[Change], project_dir: Path) -> frozenset[tuple[str, str]]:
    """The versions *changes* install of which no copy in *after* comes from the public registry.

    As in ``check_yanks``, one public copy is enough for the registry's answer
    to be about the package, so only a version every copy of which resolves
    elsewhere (a private registry, git, a file, a URL dependency) is left
    unlooked-up. Each copy is classified as the lock parser does
    (``package_lock_provenance()``), so an entry without a resolved URL takes
    the registry npm is configured with for *project_dir*.
    """
    from packagealert.languages.node import npm_registries, package_lock_provenance

    new = {(c.package, c.new) for c in changes if c.action in ("update", "add") and c.new}
    packages = npm_lock._validate(after)
    provenance = package_lock_provenance(packages, npm_registries(project_dir))
    private, public = set(), set()
    for path, info in packages.items():
        if not path or not isinstance(info, dict):
            continue
        key = (npm_lock._name_of(path, info), info.get("version"))
        if key in new:
            (public if provenance.get(path, False) else private).add(key)
    return frozenset(private - public)
