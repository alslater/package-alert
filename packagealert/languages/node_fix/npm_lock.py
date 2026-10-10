"""Read package-lock.json (lockfileVersion 2 or 3) for pa fix."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from packagealert.remediate.adapter import LockfileError
from packagealert.remediate.graph import DependencyGraph

_DEP_KEYS = ("dependencies", "optionalDependencies", "peerDependencies")
_ROOT_DEP_KEYS = (*_DEP_KEYS, "devDependencies")


class NpmLockError(LockfileError):
    """package-lock.json cannot be used by pa fix; the message says why."""


def _norm(name: object) -> str:
    """*name* as written: npm package names are case-sensitive (in the registry and in OSV)."""
    if not isinstance(name, str):
        raise NpmLockError(f"package-lock.json has a non-string package name: {name!r}")
    return name


def _section(info: dict, key: str, where: str) -> dict:
    """*info*'s dependency section *key*; {} when absent, NpmLockError when not an object."""
    value = info.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise NpmLockError(f"package-lock.json: {key!r} of {where} is not an object")
    return value


def _validate(lock: dict) -> dict[str, dict]:
    """Check the shape every reader relies on; return the packages map."""
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise NpmLockError("package-lock.json has no packages map")
    for path, info in packages.items():
        if not isinstance(path, str) or not isinstance(info, dict):
            raise NpmLockError(f"package-lock.json: entry {path!r} is not an object")
        name = info.get("name")
        if name is not None and not isinstance(name, str):
            raise NpmLockError(f"package-lock.json: entry {path!r} has a non-string name")
        for key in _ROOT_DEP_KEYS if path == "" else _DEP_KEYS:
            _section(info, key, path or "the root")
    top_name = lock.get("name")
    if top_name is not None and not isinstance(top_name, str):
        raise NpmLockError("package-lock.json has a non-string name")
    return packages


def read_lock(path: Path) -> dict:
    """Read and validate *path*; NpmLockError if pa fix cannot use it.

    A project with npm-shrinkwrap.json is refused: npm resolves from that file
    instead of package-lock.json, so a trial of package-lock.json would verify
    a different lock from the one the printed commands use.
    """
    shrinkwrap = path.parent / "npm-shrinkwrap.json"
    if shrinkwrap.exists():
        raise NpmLockError(f"{shrinkwrap} takes precedence over {path.name} for npm, and pa fix does not "
                           f"support npm-shrinkwrap.json yet")
    try:
        data = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise NpmLockError(f"cannot read {path}: {exc}") from exc
    return check_lock(data, str(path))


def check_lock(data: object, where: str) -> dict:
    """Check that *data* is a lock pa fix can read (named *where* in errors); return it.

    Used for the project's lock and for every lock a trial leaves, so a trial
    whose npm writes another format is inconclusive rather than read with
    these versions' assumptions.
    """
    if not isinstance(data, dict):
        raise NpmLockError(f"{where} is not a JSON object")
    version = data.get("lockfileVersion")
    # Exactly the integer 2 or 3 (type, not isinstance: a bool is an int, and
    # 3.0 == 3): a later format may change what the packages map means, so it
    # is refused rather than read with these versions' assumptions.
    if type(version) is not int or version not in (2, 3):
        hint = ("this version of pa fix supports 2 and 3 only" if type(version) is int and version > 3
                else "run npm install with npm 7 or later")
        raise NpmLockError(f"{where} is lockfileVersion {version!r}; pa fix needs 2 or 3 ({hint})")
    packages = _validate(data)
    if packages[""].get("workspaces"):
        raise NpmLockError(f"{where} belongs to an npm workspace, which pa fix does not support yet")
    return data


def _name_of(path: str, info: dict) -> str:
    return _norm(info.get("name") or path.rsplit("node_modules/", 1)[-1])


def _installed(path: str, info: dict) -> bool:
    """Whether *path* is a package installed under node_modules rather than a local one.

    A ``link`` entry (a ``file:`` dependency) and a key outside node_modules/
    (the linked directory itself, such as ``../local``) are the project's own
    packages: they have no registry version.
    """
    return path.startswith("node_modules/") and not info.get("link")


def copies(lock: dict) -> dict[str, tuple[str, str | None]]:
    """Every installed copy: lock path -> (name, version or None); local packages are left out."""
    _validate(lock)
    out = {}
    for path, info in lock["packages"].items():
        if _installed(path, info):
            version = info.get("version")
            out[path] = (_name_of(path, info), version if isinstance(version, str) else None)
    return out


def dependents(lock: dict) -> list[tuple[str, str, str | None, dict[str, str]]]:
    """The root and every installed copy, with npm's resolution of each dependency it declares.

    Returns (lock path, name, version, {dependency: resolved lock path}); the
    root is ("", "", None, …) and a dependency that does not resolve is left out.
    """
    packages = _validate(lock)
    out = []
    for path, info in packages.items():
        if path and not _installed(path, info):
            continue
        resolved: dict[str, str] = {}
        for key in _ROOT_DEP_KEYS if path == "" else _DEP_KEYS:
            for dep in _section(info, key, path or "the root"):
                target = resolve(lock, path, dep)
                if target is not None:
                    resolved[dep] = target
        version = info.get("version")
        out.append((path, _name_of(path, info) if path else "", version if isinstance(version, str) else None,
                    resolved))
    return out


def resolve(lock: dict, from_path: str, name: str) -> str | None:
    """npm's lookup: the nearest node_modules/<name> from *from_path* up to the root."""
    packages = lock["packages"]
    base = from_path
    while True:
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        cut = base.rfind("/node_modules/")
        base = base[:cut] if cut >= 0 else ""


_REGISTRY_TARBALL = re.compile(r"^/(?P<name>.+)/-/[^/]+\.tgz$")


def _registry_shaped(resolved: str, name: str) -> bool:
    """True for an http(s) URL whose path ends in npm's /<name>/-/<file>.tgz."""
    parts = urlsplit(resolved)
    if parts.scheme not in ("http", "https"):
        return False
    match = _REGISTRY_TARBALL.match(unquote(parts.path))
    if match is None:
        return False
    # A private registry may sit under a path prefix (/api/npm/repo/<name>/-/...).
    found = "/" + match.group("name").lower()
    return found.endswith("/" + name.lower())


def _non_registry(info: dict, name: str) -> bool:
    if info.get("link") or not isinstance(info.get("version"), str):
        return True
    resolved = info.get("resolved")
    if resolved is None:
        return False
    return not isinstance(resolved, str) or not _registry_shaped(resolved, name)


def load_graph(path: Path) -> DependencyGraph:
    return load_graph_from(read_lock(path))


def load_graph_from(lock: dict) -> DependencyGraph:
    from packagealert.languages.node import npm_spec_non_registry

    packages = _validate(lock)
    root = packages[""]
    member = _norm(root.get("name") or lock.get("name") or "(root)")

    def installs(from_path: str, dep: str) -> str | None:
        """The package a declaration of *dep* at *from_path* installs, by its own name.

        An alias ("alias": "npm:bar@^1") is locked at node_modules/alias with
        name bar: it is bar that has versions and findings, never "alias".
        """
        found = resolve(lock, from_path, dep)
        return _name_of(found, packages[found]) if found is not None else None

    direct: set[str] = set()
    deps: dict[str, set[str]] = {member: set()}
    versions: dict[str, set[str]] = {}
    non_registry: set[str] = set()
    aliased: set[str] = set()
    for p, info in packages.items():
        installed = p == "" or (p.startswith("node_modules/") and _installed(p, info))
        name = member if p == "" else _name_of(p, info)
        for k in _ROOT_DEP_KEYS if p == "" else _DEP_KEYS:
            for dep, spec in _section(info, k, p or "the root").items():
                target = installs(p, dep)
                if p == "":
                    direct.add(target or _norm(dep))
                # A dependency declared from a file, git or URL is not a registry package even when
                # its resolved URL looks like a registry tarball, so every declaration is checked too.
                if npm_spec_non_registry(spec):
                    non_registry.add(target or _norm(dep))
                if isinstance(spec, str) and spec.startswith("npm:") and target is not None:
                    aliased.add(target)
                if installed and target is not None:
                    deps.setdefault(name, set()).add(target)
        if not p.startswith("node_modules/"):
            continue
        if _non_registry(info, name):
            non_registry.add(name)
        if installed and isinstance(info.get("version"), str):
            versions.setdefault(name, set()).add(info["version"])
    deps[member] |= direct
    return DependencyGraph(
        members=frozenset({member}), direct=frozenset(direct),
        deps={k: frozenset(v) for k, v in deps.items()},
        versions={k: frozenset(v) for k, v in versions.items()},
        non_registry=frozenset(non_registry), aliased=frozenset(aliased),
    )


def _top(path: str) -> str:
    """The top-level package directory a lock path sits in: node_modules/a/node_modules/b -> a."""
    rest = path[len("node_modules/"):]
    first = rest.split("/node_modules/", 1)[0]
    return first


def holder_of(lock: dict, path: str) -> str:
    graph = load_graph_from(lock)
    top = _norm(_top(path))
    chain = graph.path_to(top)
    return chain[1] if len(chain) > 1 else top


def declared_range(lock: dict, holder_path: str, name: str) -> str | None:
    info = _validate(lock).get(holder_path) or {}
    for k in _ROOT_DEP_KEYS:
        spec = _section(info, k, holder_path or "the root").get(name)
        if isinstance(spec, str):
            return spec
    return None
