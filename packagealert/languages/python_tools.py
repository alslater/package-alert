"""pipx apps and uv tool environments: where they are, what is installed in them, and where it came from.

`pa scan-tools` (#117) scans each tools directory as one unit. This module only reads: a tool's
packages come from its dist-info, its source from pipx's or uv's own record of the install and
each distribution's direct_url.json. Nothing in a tool environment is ever run.
"""
from __future__ import annotations

import errno
import json
import logging
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from packagealert import safe_read

log = logging.getLogger(__name__)

# What a token looks like in a URL's path: a long run of letters and digits, both present.
_TOKEN_SEGMENT_RE = re.compile(r"^(?=.*[0-9])(?=.*[A-Za-z])[A-Za-z0-9_\-]{20,}$")
# A credential by its issuer's prefix (GitLab, GitHub, PyPI, npm, Slack), digits or not.
_TOKEN_PREFIX_RE = re.compile(
    r"^(?:glpat|gldt|glptt|glrt|ghp|gho|ghu|ghs|ghr|github_pat|pypi|npm|xox[abposr])[-_][A-Za-z0-9_\-]{20,}$")
# A JWT: three base64url parts joined by dots (a distribution's file name has more, shorter parts).
_JWT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}$")
# Hosts that serve public PyPI's own distribution files.
_PUBLIC_FILE_HOSTS = frozenset({"files.pythonhosted.org", "pypi.org", "pypi.python.org"})
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)")


@dataclass
class ToolRoot:
    """A tools directory: pipx's venvs directory or uv's tool directory."""

    manager: str        # "pipx" | "uv"
    root: Path
    active: bool        # the manager's live directory; False only for a leftover pipx layout
    exists: bool
    # pipx's home as configured, before resolving (venvs may be a link elsewhere): where its
    # shared libraries are. None for uv.
    home: Path | None = None


@dataclass
class ToolPackage:
    name: str
    version: str
    public: bool        # from public PyPI, so its name may be looked up there


@dataclass
class ToolEnv:
    manager: str
    name: str
    venv_root: Path
    python: str | None                  # "3.13", from pyvenv.cfg
    site_packages: Path | None
    orphaned: list[str]                 # lib/pythonX.Y directories of an interpreter no longer used
    provenance: dict
    packages: list[ToolPackage] = field(default_factory=list)
    # The app's distribution as its manager records it; pipx's --suffix makes the directory
    # name differ from it (`app-dev` installs `app`).
    distribution: str | None = None
    # Directories whose packages were not checked: unreadable, or (lib) holding several
    # interpreters' directories with nothing to say which one is in use.
    unchecked: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.manager}:{self.name}"

    @property
    def version(self) -> str | None:
        own = _canonical(self.distribution or self.name)
        return next((p.version for p in self.packages if _canonical(p.name) == own), None)


def tool_roots(managers: tuple[str, ...] = ("pipx", "uv")) -> list[ToolRoot]:
    """Every tools directory to scan for *managers*: each manager's live directory, existing or
    not (#116's exact resolvers), and a leftover pipx layout pipx no longer uses (inactive)."""
    from packagealert.parsers.process_args import _pipx_home_exact, _uv_tool_dir_exact

    roots: list[ToolRoot] = []
    # Every root is reported resolved, so the same directory reached through a symlink keeps
    # one identity from run to run, and an alias of another root is not reported twice.
    if "pipx" in managers:
        pipx_home = _pipx_home_exact()
        live = _resolved(pipx_home / "venvs")
        roots.append(ToolRoot("pipx", live, active=True, exists=_dir_state(live) is not False, home=pipx_home))
        home = Path.home()
        xdg = os.environ.get("XDG_DATA_HOME", "")
        homes = [home / ".local" / "pipx", home / ".local" / "share" / "pipx",
                 *([Path(xdg) / "pipx"] if os.path.isabs(xdg) else [])]
        layouts: dict[Path, Path] = {}
        for layout_home in homes:
            layouts.setdefault(_resolved(layout_home / "venvs"), layout_home)
        for layout, layout_home in layouts.items():
            if _dir_state(layout) is not False and layout != live:
                roots.append(ToolRoot("pipx", layout, active=False, exists=True, home=layout_home))
    if "uv" in managers:
        live = _resolved(_uv_tool_dir_exact())
        roots.append(ToolRoot("uv", live, active=True, exists=_dir_state(live) is not False))
    return roots


def _dir_state(path: Path) -> bool | None:
    """Whether *path* is a directory, or None when that cannot be told (a parent that cannot
    be searched): Path.is_dir() raises then. A root or tool that cannot be told is scanned,
    so it is reported unchecked rather than taken as absent."""
    import stat

    try:
        return stat.S_ISDIR(path.stat().st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return None


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


def tool_envs(root: ToolRoot) -> tuple[list[ToolEnv], list[str]]:
    """(the tool environments directly inside *root*, with their packages and provenance, the
    directories whose packages were not checked). Such a directory is reported, never
    skipped: an empty inventory would read as a clean scan.

    An entry is a tool environment only if its name is a single safe path component, it
    resolves inside the root (no symlink out of the tree), and it is a real virtualenv
    (pyvenv.cfg with a home key, and bin/python or bin/activate)."""
    from packagealert.languages.python import _contained_in, _safe_tool_name

    if not root.exists:
        return [], []
    try:
        entries = sorted(root.root.iterdir())
    except OSError:
        return [], [str(root.root)]
    envs: list[ToolEnv] = []
    unchecked: list[str] = []
    for entry in entries:
        if not _safe_tool_name(entry.name):
            continue
        if (state := _dir_state(entry)) is None:
            unchecked.append(str(entry))
            continue
        if not state or not _contained_in(entry, root.root):
            continue
        venv = entry.resolve()
        if not os.access(venv, os.R_OK | os.X_OK):
            unchecked.append(str(entry))
            continue
        is_venv, cannot_check = _venv_check(venv)
        if not is_venv:
            unchecked += [cannot_check] if cannot_check else []
            continue
        env = _tool_env(root, entry.name, venv)
        envs.append(env)
        unchecked += env.unchecked
    if root.manager == "pipx":
        shared, shared_unchecked = _pipx_shared_env(root)
        envs += shared
        unchecked += shared_unchecked
    return envs, unchecked


def _venv_check(venv: Path) -> tuple[bool, str | None]:
    """(whether *venv* is a real virtualenv, the path that could not be checked when that
    cannot be told). An unreadable pyvenv.cfg, or a bin/ that cannot be searched for the
    interpreter, is a venv that could not be checked, not a non-venv."""
    from packagealert.languages.python import _looks_like_venv

    try:
        if _looks_like_venv(venv):
            return True, None
    except OSError:                     # bin/ cannot be searched (Python 3.12 and 3.13 raise)
        pass
    if os.path.lexists(cfg := venv / "pyvenv.cfg") and not os.access(cfg, os.R_OK):
        return False, str(cfg)
    if (bin_state := _dir_state(bin_dir := venv / "bin")) is None or (
            bin_state and not os.access(bin_dir, os.X_OK)):
        return False, str(bin_dir)
    return False, None


# pipx's shared libraries (pip), which every app imports through its pipx_shared.pth.
PIPX_SHARED = "(shared)"


def _pipx_shared_env(root: ToolRoot) -> tuple[list[ToolEnv], list[str]]:
    """pipx's shared-libraries venv in *root*'s pipx home (<pipx home>/shared, found from the
    home as configured, not from where venvs resolves), scanned like a tool named PIPX_SHARED:
    it must be a real venv inside that home, and one that cannot be checked is unchecked.
    pipx keeps no record for it, so its provenance is unknown."""
    from packagealert.languages.python import _contained_in

    home = root.home or root.root.parent
    shared = home / "shared"
    if (state := _dir_state(shared)) is None:
        return [], [str(shared)]
    if not state or not _contained_in(shared, home):
        return [], []
    venv = shared.resolve()
    if not os.access(venv, os.R_OK | os.X_OK):
        return [], [str(shared)]
    is_venv, cannot_check = _venv_check(venv)
    if not is_venv:
        return [], [cannot_check] if cannot_check else []
    env = _tool_env(root, PIPX_SHARED, venv)
    return [env], list(env.unchecked)


def _tool_env(root: ToolRoot, name: str, venv: Path) -> ToolEnv:
    from packagealert.languages.python import _contained_in, _distinfo_to_metadata

    python = _pyvenv_python(venv)
    record = _pipx_provenance(venv) if root.manager == "pipx" else _uv_provenance(venv)
    provenance, index_private = record.provenance, record.private
    env = ToolEnv(root.manager, name, venv, python, None, [], provenance, distribution=record.distribution)
    # A tool made with --system-site-packages also imports its base interpreter's packages,
    # which cannot be listed without running that interpreter: its pyvenv.cfg says so.
    if _pyvenv_setting(venv, "include-system-site-packages", "").lower() == "true":
        env.unchecked.append(str(venv / "pyvenv.cfg"))
    # Everything read, or called safe to delete, must really lie inside this tool's own
    # (resolved) venv: a symlink to another tool's lib, or out of the tools directory, is not
    # this tool's to scan or remove.
    lib = venv / "lib"
    try:
        if _dir_state(lib) is not False and not _contained_in(lib, venv):
            env.unchecked.append(str(lib))
            return env
        site, orphaned = _site_packages(venv, python)
        env.orphaned = [o for o in orphaned if _contained_in(venv / o, venv)]
        if site is None:
            return env
        if not _contained_in(site, venv):
            env.unchecked.append(str(site))
            return env
        env.site_packages = site
        dist_infos = sorted(d for d in env.site_packages.iterdir() if d.suffix == ".dist-info")
    except _AmbiguousInterpreter:
        env.unchecked.append(str(venv / "lib"))
        return env
    except OSError as exc:
        env.unchecked.append(str(exc.filename or venv / "lib"))
        return env
    # The manager's record names where the app and anything installed beside it came from;
    # a missing direct_url.json does not make a local, git or URL distribution public.
    app = _canonical(record.distribution or name)
    for dist_info in dist_infos:
        if (state := _dir_state(dist_info)) is None:
            env.unchecked.append(str(dist_info))
            continue
        if not state:
            continue
        # Metadata from outside the tool is not this tool's; metadata that cannot be read says
        # nothing about where the distribution came from.
        if not _contained_in(dist_info, venv) or not os.access(dist_info, os.R_OK | os.X_OK):
            env.unchecked.append(str(dist_info))
            continue
        meta = _distinfo_to_metadata(dist_info)
        if meta is None or not meta.version:
            continue
        recorded = _direct_url_provenance(dist_info)
        direct = recorded["kind"] if recorded and recorded["kind"] != "pypi" else None
        if recorded is not None and recorded["kind"] != "unknown" and _canonical(meta.name) == app:
            _reconcile_provenance(env, recorded)
        # The manager's record speaks for a distribution only without a direct_url.json of
        # its own: one naming a public PyPI file says it was reinstalled from PyPI since.
        own = recorded is None and _canonical(meta.name) in record.not_public
        env.packages.append(ToolPackage(meta.name, meta.version,
                                        public=direct is None and not index_private and not own))
    return env


def _reconcile_provenance(env: ToolEnv, direct: dict) -> None:
    """Take the app's provenance from its own direct_url.json: what is installed now
    (`pipx runpip app install -e /src/app` changes it without pipx's record), keeping the
    environment-level index flags."""
    flags = {k: v for k, v in env.provenance.items() if k in ("index_source", "extra_index")}
    env.provenance = {**direct, **flags}


def _str_list(value: object) -> list[str]:
    """The strings in a recorded list; nothing when the record holds something else."""
    return [a for a in value if isinstance(a, str)] if isinstance(value, list) else []


def _pyvenv_setting(venv: Path, key: str, default: str) -> str:
    """A pyvenv.cfg setting's value, or *default* when it is absent or cannot be read."""
    try:
        text = safe_read.read_text(venv / "pyvenv.cfg", errors="replace")
    except OSError:
        return default
    for line in text.splitlines():
        name, eq, value = line.partition("=")
        if eq and name.strip().lower() == key:
            return value.strip()
    return default


def _pyvenv_python(venv: Path) -> str | None:
    """The interpreter's major.minor from pyvenv.cfg (venv writes `version`, uv `version_info`)."""
    try:
        text = safe_read.read_text(venv / "pyvenv.cfg", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip().lower() in ("version", "version_info") and (m := _VERSION_RE.match(value.strip())):
            return f"{m.group(1)}.{m.group(2)}"
    return None


# An interpreter's lib directory: pythonX.Y, pythonX.Yt when free-threaded, pypyX.Y for PyPy.
_INTERPRETER_DIR_RE = re.compile(r"(?:python\d+\.\d+t?|pypy\d+\.\d+)\Z")


def _site_packages(venv: Path, python: str | None) -> tuple[Path | None, list[str]]:
    """(the site-packages of the interpreter in use, the other lib/pythonX.Y directories).

    A free-threaded interpreter uses lib/pythonX.Yt, PyPy lib/pypyX.Y (its pyvenv.cfg gives
    the language version). Raises _AmbiguousInterpreter when the one in use cannot be told
    among several (no version in pyvenv.cfg, or more than one of those for its version): neither scanning one nor calling the others orphaned would be safe. Raises
    OSError when lib exists but cannot be read."""
    lib = venv / "lib"
    try:
        entries = [d for d in lib.iterdir() if _INTERPRETER_DIR_RE.match(d.name)]
    except FileNotFoundError:
        return None, []
    versions = sorted(d.name for d in entries if _searchable_dir(d))
    if python:
        candidates = [v for v in (f"python{python}", f"python{python}t", f"pypy{python}") if v in versions]
        # Names for one directory (python3.13t a link to python3.13) are one interpreter.
        candidates = list({_resolved(lib / v): v for v in reversed(candidates)}.values())[::-1]
    else:
        candidates = versions
    if len(candidates) > 1:
        raise _AmbiguousInterpreter
    if not candidates:          # the interpreter in use has no lib directory: any other is stale
        return None, [f"lib/{v}" for v in versions]
    site = lib / candidates[0] / "site-packages"
    # A directory that is the one in use under another name (a link either way), or that holds
    # the site-packages in use (site-packages itself a link into it), is not stale.
    in_use = _resolved(lib / candidates[0])
    in_use_site = _resolved(lib / candidates[0] / "site-packages")
    orphaned = [f"lib/{v}" for v in versions if v != candidates[0] and _resolved(lib / v) != in_use
                and not in_use_site.is_relative_to(_resolved(lib / v))]
    return (site if _searchable_dir(site) else None), orphaned


def _searchable_dir(path: Path) -> bool:
    """Whether *path* is a directory; raises PermissionError when that cannot be told, which
    Path.is_dir() reports as False from Python 3.14 (and raises before it)."""
    if (state := _dir_state(path)) is None:
        raise PermissionError(errno.EACCES, "cannot be searched", str(path))
    return state


class _AmbiguousInterpreter(Exception):
    """A tool's lib holds several interpreters' directories and nothing says which is in use."""


_UNKNOWN_DIRECT = {"kind": "unknown", "editable": False}


def _direct_url_provenance(dist_info: Path) -> dict | None:
    """The provenance a distribution's direct_url.json (PEP 610) records, or None without
    one: {kind: local, path, editable}, {kind: git|url, url?}, or {kind: pypi} for a public
    PyPI file. pip writes one only for an install from a URL, a path or VCS, so one that
    cannot be read or parsed still says the distribution did not come from an index:
    {kind: unknown}."""
    try:
        data = json.loads(safe_read.read_text(dist_info / "direct_url.json", errors="replace"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return dict(_UNKNOWN_DIRECT)
    if not isinstance(data, dict):
        return dict(_UNKNOWN_DIRECT)
    url = data.get("url") if isinstance(data.get("url"), str) else None
    if "dir_info" in data:
        dir_info = data["dir_info"] if isinstance(data["dir_info"], dict) else {}
        provenance: dict = {"kind": "local", "editable": dir_info.get("editable") is True}
        if url and url.startswith("file://"):
            try:
                provenance["path"] = unquote(urlsplit(url).path)
            except ValueError:
                pass
        return provenance
    if "vcs_info" in data:
        return _with_url({"kind": "git", "editable": False}, f"git+{url}" if url and not url.startswith("git+") else url)
    host = _hostname(url) if url else None
    if host in _PUBLIC_FILE_HOSTS:
        return {"kind": "pypi", "editable": False}
    return _with_url({"kind": "url", "editable": False}, url)


@dataclass
class _ManagerRecord:
    """What a tool's manager recorded: the app's provenance, whether the environment's packages
    may have come from somewhere other than public PyPI, the app's distribution name, and the
    distributions (canonical names) it says were installed from a path, git or a URL."""

    provenance: dict
    private: bool = False
    distribution: str | None = None
    not_public: frozenset[str] = frozenset()


_UNKNOWN_RECORD = _ManagerRecord({"kind": "unknown"})
_NOT_INDEX_KINDS = ("local", "git", "url")


def _pipx_provenance(venv: Path) -> _ManagerRecord:
    """The app's record from pipx_metadata.json: its main package and every injected one.

    Without a readable record the provenance is "unknown" and the packages count as public:
    pipx and uv always write one, and judging them private would leave them unchecked, where
    looking them up at worst adds a lookup (as npm provenance treats an unknown source)."""
    try:
        meta = json.loads(safe_read.read_text(venv / "pipx_metadata.json", errors="replace"))
        main = meta["main_package"]
        spec = main.get("package_or_url") or main.get("package") or ""
        pip_args = _str_list(main.get("pip_args"))
        injected = meta.get("injected_packages") or {}
        injected = list(injected.values()) if isinstance(injected, dict) else []
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return _UNKNOWN_RECORD
    editable = "--editable" in pip_args or "-e" in pip_args
    index_url: str | None = None
    distribution = main.get("package") if isinstance(main.get("package"), str) else None
    not_public: set[str] = set()
    sources = _Sources()
    from_config = False
    # The main package and every injected one are separate installations into the same
    # environment, each with its own --pip-args: a replacement index in any of them may have
    # supplied any of the environment's packages. pipx records only those arguments, so an
    # index set in pip's or uv's own configuration (pipx installs with either) counts for
    # each installation that did not replace it on the command line, and only the
    # configuration that installation read (--isolated skips the user's).
    for record in [main, *injected]:
        if not isinstance(record, dict):
            continue
        record_args = _str_list(record.get("pip_args"))
        record_sources, record_from_config, record_index_url = _installation_sources(record_args, venv)
        sources |= record_sources
        from_config = from_config or record_from_config
        # The index recorded is the main installation's, unless only an injection's is the
        # private one that makes the environment's packages private.
        if record is main or (record_index_url is not None and _sources([record_index_url]).index
                              and not _sources([index_url]).index):
            index_url = record_index_url
        name = record.get("package")
        record_spec = str(record.get("package_or_url") or name or "")
        if record is not main and isinstance(name, str) \
                and _provenance_of_spec(record_spec, False, None, False)["kind"] in _NOT_INDEX_KINDS:
            not_public.add(_canonical(name))
    private = sources.private
    from_config = from_config and private
    # The app's own source (a path, git or a URL) still names where the app itself came from.
    provenance = _provenance_of_spec(str(spec), editable, None if from_config else index_url, private)
    if from_config:
        provenance["index_source"] = "config"
    if not private and sources.extra:
        provenance["extra_index"] = True
    if distribution and provenance["kind"] in _NOT_INDEX_KINDS:
        not_public.add(_canonical(distribution))
    return _ManagerRecord(provenance, private, distribution, frozenset(not_public))


@dataclass(frozen=True)
class _Sources:
    """Where an install's settings send it besides public PyPI.

    `index`: a replacement index that is not PyPI's, and `other`: find-links or no index at
    all; either means a package may not be on PyPI, so it is not looked up there. `extra`: an
    extra index that is not PyPI's, beside PyPI; packages are still looked up, since PyPI
    remains a source and a public package of the same name is exactly what to check."""

    index: bool = False
    other: bool = False
    extra: bool = False

    @property
    def private(self) -> bool:
        return self.index or self.other

    def __or__(self, other: _Sources) -> _Sources:
        return _Sources(self.index or other.index, self.other or other.other, self.extra or other.extra)


def _sources(index: Iterable[object] = (), extra: Iterable[object] = (), find_links: object = None,
             no_index: object = None) -> _Sources:
    """_Sources from settings: index URLs (a list, or a whitespace-separated string, may hold
    several; PyPI's own count for nothing), find-links and no-index."""
    return _Sources(_any_private_url(index), bool(find_links) or no_index is True or _truthy(no_index),
                    _any_private_url(extra))


def _any_private_url(values: Iterable[object]) -> bool:
    from packagealert.parsers.lockfiles import is_public_pypi_index

    return any(not is_public_pypi_index(u) for value in values
               for u in (value if isinstance(value, list) else str(value or "").split()))


@dataclass(frozen=True)
class _InstallArgs:
    """What an installation's recorded --pip-args say about where its packages came from."""

    index_url: str | None       # the replacement index given (uv: its legacy --index-url), if any
    sources: _Sources           # what the arguments alone name (index: the effective one)
    isolated: bool = False      # pip's --isolated: no user configuration or PIP_* variables
    config_file: str | None = None      # uv's --config-file, replacing its discovery
    no_config: bool = False             # uv's --no-config: no configuration file discovered
    default_index: str | None = None    # uv's --default-index, ahead of --index-url
    file_index: str | None = None       # the last --index-url in the requirement files named
    constraint_files: tuple[str, ...] = ()
    requirement_files: tuple[str, ...] = ()
    rejected: bool = False              # this backend would refuse the arguments


def _installation_sources(pip_args: list[str], venv: Path) -> tuple[_Sources, bool, str | None]:
    """(the sources one pipx installation used, whether its configuration rather than its
    arguments made them private, the replacement index its arguments name).

    pipx installs with pip or uv and records neither which, so each backend's reading is
    resolved on its own (its view of the arguments, then its own configuration and
    precedence) and the two combined: pip reads `--index` as a prefix of --index-url, uv as
    an extra index beside its --default-index."""
    pip_args_read = _read_install_args(pip_args, uv=False)
    uv_args_read = _read_install_args(pip_args, uv=True)
    pip_index = pip_args_read.file_index if pip_args_read.file_index is not None else pip_args_read.index_url
    uv_index = uv_args_read.default_index if uv_args_read.default_index is not None else (
        uv_args_read.file_index if uv_args_read.file_index is not None else uv_args_read.index_url)
    readings = [(pip_args_read, lambda: _pip_effective_sources(pip_args_read, venv), pip_index),
                (uv_args_read, lambda: _uv_effective_sources(uv_args_read), uv_index)]
    # Only a backend that accepts the arguments could have run them; when neither does,
    # both readings are kept.
    readings = [r for r in readings if not r[0].rejected] or readings
    sources = _Sources()
    for _, effective, _ in readings:
        sources |= effective()
    from_args = any(read.sources.private for read, _, _ in readings)
    candidates = [index for _, _, index in readings if index is not None]
    # The index to record is the one that made the packages private, when either reading has one.
    index_url = next((u for u in candidates if _sources([u]).index), candidates[0] if candidates else None)
    return sources, sources.private and not from_args, index_url


def _read_install_args(pip_args: list[str], *, uv: bool) -> _InstallArgs:
    """*pip_args* as pip (optparse) or `uv pip install` reads them. pip takes a unique
    long-option prefix as that option (`--index-u`, `--extra-index`); uv takes no prefixes.
    Both take an option's value from the next argument unless attached, and grouped short
    options, a value-taking one ending the group with the rest of it as its value
    (`-ihttps://…`, `-vf/wheels`)."""
    from packagealert.parsers.process_args import (
        _PIP_GENERAL_LONG_OPTIONS_BY_VERSION,
        _PIP_INSTALL_LONG_OPTIONS_BY_VERSION,
        _PIP_INSTALL_SHORT_OPTIONS,
        _PIP_VALUE_FLAGS,
        _UV_PIP_INSTALL_LONG_OPTIONS,
        _UV_PIP_INSTALL_SHORT_OPTIONS,
        _UV_PIP_INSTALL_VALUE_FLAGS,
        _expand_long_prefix_across,
    )

    index_url: str | None = None
    extra: list[str] = []
    other = isolated = no_config = False
    config_file: str | None = None
    from_files = _Sources()
    # pipx records --editable/-e alone in pip_args and passes the app's path separately.
    value_flags = (_UV_PIP_INSTALL_VALUE_FLAGS if uv else _PIP_VALUE_FLAGS) - {"-e", "--editable"}
    if uv:
        args = list(pip_args)
    else:
        longs = tuple(g | i for g, i in zip(_PIP_GENERAL_LONG_OPTIONS_BY_VERSION,
                                            _PIP_INSTALL_LONG_OPTIONS_BY_VERSION, strict=True))
        args = [_expand_long_prefix_across(a, longs, _PIP_VALUE_FLAGS, frozenset()) for a in pip_args]
    options: list[tuple[str, str | None]] = []
    # Each backend refuses an option it does not have: pip a long one none of its versions has
    # (uv's --default-index, --no-config, --requirements …) or uv's -b/-p/-P/-n, uv one not its
    # own (pip's prefixes, `--index-u`, -I, -V). Such an install cannot have run with that backend.
    known_longs = _UV_PIP_INSTALL_LONG_OPTIONS if uv else frozenset().union(
        *_PIP_GENERAL_LONG_OPTIONS_BY_VERSION, *_PIP_INSTALL_LONG_OPTIONS_BY_VERSION)
    known_shorts = _UV_PIP_INSTALL_SHORT_OPTIONS if uv else _PIP_INSTALL_SHORT_OPTIONS
    rejected = False
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            break
        if arg.startswith("--"):
            name, eq, attached = arg.partition("=")
            rejected = rejected or name not in known_longs
            if eq or name not in value_flags:
                options.append((name, attached if eq else None))
            else:
                options.append((name, args[i] if i < len(args) else ""))
                i += 1
        elif arg.startswith("-") and len(arg) > 1:
            for j, letter in enumerate(arg[1:], start=2):
                short = "-" + letter
                rejected = rejected or short not in known_shorts
                # pipx records -e alone; with its value attached (`-e/src/plugin`) it takes it.
                if short not in value_flags and not (short == "-e" and arg[j:]):
                    options.append((short, None))
                    continue
                if arg[j:]:
                    options.append((short, arg[j:]))
                else:
                    options.append((short, args[i] if i < len(args) else ""))
                    i += 1
                break
    default_index: str | None = None
    constraints: list[str] = []
    requirements: list[str] = []
    for name, value in options:
        if name in ("--index-url", "-i", "--pypi-url"):
            index_url = value or ""
        elif name == "--default-index" and uv:      # pip has no such option
            default_index = value or ""
        elif name == "--extra-index-url" or (name == "--index" and uv):    # uv's --index is beside PyPI
            extra.append(value or "")
        elif name in ("--find-links", "-f", "--no-index"):
            other = True
        elif name == "--isolated":
            isolated = True
            # uv pip still honours its deprecated --isolated: no configuration file discovered.
            no_config = no_config or uv
        elif name == "--config-file" and uv:
            config_file = value or None
            # A relative path depended on where pipx ran: what it configured is unknown.
            other = other or not Path(config_file or "").is_absolute()
        elif name == "--no-config" and uv:
            no_config = True
        elif name in ("-c", "--constraint", "--constraints"):
            constraints.append(value or "")
        elif name in ("-r", "--requirement", "--requirements"):
            requirements.append(value or "")
    file_index, from_files = _requirement_files_sources([*constraints, *requirements], pip=not uv)
    # A requirements file's --index-url is applied after the command line's, and uv chains
    # --default-index ahead of the legacy --index-url, whatever their order.
    legacy = file_index if file_index is not None else index_url
    sources = _sources([default_index if default_index is not None else legacy], extra)
    return _InstallArgs(index_url, _Sources(sources.index, other, sources.extra) | from_files, isolated, config_file,
                        no_config, default_index, file_index, tuple(constraints), tuple(requirements),
                        rejected=rejected)


_COMMENT_RE = re.compile(r"(^|\s+)#.*$")


def _logical_lines(lines: list[str]) -> list[str]:
    """A requirements file's lines as pip reads them (req_file.preprocess()): a line ending
    in a backslash continues on the next (a comment line never does), then comments, which
    start at a `#` beginning the line or following whitespace, are removed."""
    joined: list[str] = []
    pending: list[str] = []
    for line in lines:
        if not line.endswith("\\") or _COMMENT_RE.match(line):
            if _COMMENT_RE.match(line):
                line = " " + line           # a comment line ends a continuation
            joined.append("".join(pending) + line)
            pending = []
        else:
            pending.append(line[:-1])
    if pending:
        joined.append("".join(pending))
    return [_ENV_VAR_RE.sub(_expand_env_var, stripped)
            for line in joined if (stripped := _COMMENT_RE.sub("", line).strip())]


# pip's expand_env_variables(): ${NAME}, upper case, digits and underscores only.
_ENV_VAR_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env_var(match: re.Match[str]) -> str:
    """A variable's value; an unset or empty one is left as written, as pip leaves it."""
    return os.environ.get(match.group(1)) or match.group(0)


# How many requirement files one installation's arguments may read, includes included: files
# that each include the next twice double the reads at every level.
_MAX_REQUIREMENT_FILE_READS = 256


# pip's requirement-file decoding (req_file.BOMS, then a PEP 263 coding comment, then UTF-8).
_REQUIREMENTS_BOMS = (
    (b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16-be"),
)
_PEP263_ENCODING_RE = re.compile(rb"coding[:=]\s*([-\w.]+)")


def _decode_requirements(data: bytes) -> str | None:
    """A requirements file's text as pip decodes it: a byte-order mark names the encoding (and
    is dropped), else a `# coding:` comment in the first two lines, else UTF-8. None where pip
    would fall back to the locale's encoding, which cannot be known here."""
    try:
        for bom, encoding in _REQUIREMENTS_BOMS:
            if data.startswith(bom):
                return data[len(bom):].decode(encoding)
        for line in data.split(b"\n")[:2]:
            if line[:1] == b"#" and (m := _PEP263_ENCODING_RE.search(line)):
                return data.decode(m.group(1).decode("ascii"))
        return data.decode("utf-8")
    except (UnicodeDecodeError, LookupError):
        return None


def _requirement_files_sources(paths: list[str], *, pip: bool = True) -> tuple[str | None, _Sources]:
    """(the last --index-url, every other source) of *paths* read in order, as pip reads its
    requirement files: constraints first, then requirements (get_requirements()). *pip*: a
    line including another file follows pip's rules (see _requirements_file_sources())."""
    index_url: str | None = None
    found = _Sources()
    budget = [_MAX_REQUIREMENT_FILE_READS]
    for path in paths:
        last, sources = _requirements_file_sources(path, budget=budget, pip=pip)
        index_url = last if last is not None else index_url
        found |= sources
    return index_url, found


def _requirements_file_sources(path: str, _seen: set[Path] | None = None, *,
                               budget: list[int], pip: bool = True) -> tuple[str | None, _Sources]:
    """(the last --index-url, the other sources) a requirements or constraints file named in
    --pip-args gives the install (pip applies its options to the whole install), with
    everything it includes, in pip's order: a later --index-url replaces an earlier one.
    Options are read as pip reads them (lockfiles.requirements_line_options(): unique
    prefixes, attached values), and an extra index stays an extra index, as on the command
    line. A file that cannot be read or parsed counts as private: a relative path depended
    on where pipx ran, and the file may have changed since; so does one past *budget* (the
    reads left for the whole installation).

    pip (*pip*) follows only one include on a line, its first -r, else its first -c, and
    ignores the line's other options (RequirementsFileParser._parse_and_recurse()); an empty
    --index-url leaves the index as it was (handle_option_line()). uv's own parser cannot be
    run here, so its reading follows every include on the line, which errs toward private."""
    from packagealert.parsers.lockfiles import requirements_line_options

    unresolved = (None, _Sources(other=True))
    ancestors = set() if _seen is None else _seen
    file = Path(path)
    if not file.is_absolute():
        return unresolved
    try:
        # Includes resolve against the name as given, as pip joins them to it; the resolved
        # file only tells a cycle.
        real = file.resolve()
        if real in ancestors:           # a cycle; pip reads a file included twice twice
            return None, _Sources()
        ancestors = ancestors | {real}
        if budget[0] <= 0:
            return unresolved
        budget[0] -= 1
        text = _decode_requirements(safe_read.read_bytes(file))
    except (OSError, RuntimeError):
        return unresolved
    if text is None:
        return unresolved
    lines = text.splitlines()
    index_url: str | None = None
    found = _Sources()
    for line in _logical_lines(lines):
        if not line.startswith("-"):
            continue
        options = requirements_line_options(line)
        if options is None:
            return unresolved
        includes = [(o, v) for o, v in options if o in ("--requirement", "--constraint")]
        if pip and includes:
            options = [next((i for i in includes if i[0] == "--requirement"), includes[0])]
        for option, value in options:
            if option in ("--requirement", "--constraint"):
                included_index, included = _requirements_file_sources(str(file.parent / (value or "")), ancestors,
                                                                     budget=budget, pip=pip)
                index_url = included_index if included_index is not None else index_url
                found |= included
            elif option in ("--index-url", "--pypi-url"):
                index_url = value or index_url
            elif option == "--extra-index-url":
                found |= _sources(extra=[value or ""])
            elif option in ("--find-links", "--no-index"):
                found |= _Sources(other=True)
    return index_url, found


def _pip_effective_sources(args: _InstallArgs, venv: Path) -> _Sources:
    """The sources pip used: its arguments with its configuration as it stands now (see
    _pip_config_sources()). pip uses one replacement index, the last one set, in this order:
    the configured index, the command line's --index-url, configured requirement files, then
    the requirement files the command line names. Every other source adds up."""
    config = _pip_config_sources(venv, isolated=args.isolated)
    # A configured list is the option's default, which the command line's values extend.
    file_index, from_files = _requirement_files_sources(
        [*config.constraint_files, *args.constraint_files, *config.requirement_files, *args.requirement_files])
    final = next((u for u in (file_index, args.index_url, config.index_url) if u is not None), None)
    others = _Sources(other=args.sources.other or config.sources.other or from_files.other,
                      extra=args.sources.extra or config.sources.extra or from_files.extra)
    return _sources([final]) | others


# System-wide configuration files outside the XDG directories (module-level so tests can move them).
_PIP_SITE_CONFIG = Path("/etc/pip.conf")
_UV_SYSTEM_CONFIG = Path("/etc/uv/uv.toml")


def _config_dirs(env: Mapping[str, str]) -> tuple[Path, list[Path]]:
    """(the user's XDG config directory, the system XDG config directories)."""
    return (Path(env.get("XDG_CONFIG_HOME") or Path.home() / ".config"),
            [Path(d) for d in (env.get("XDG_CONFIG_DIRS") or "/etc/xdg").split(":") if d])


# The pip settings that name a source, as pip.conf and PIP_* spell them, and the aliases pip
# also accepts for them (any of an option's long names works as a configuration key).
_PIP_SOURCE_KEYS = ("index-url", "extra-index-url", "find-links", "no-index", "requirement", "constraint")
_PIP_KEY_ALIASES = {"pypi-url": "index-url"}


@dataclass(frozen=True)
class _PipConfig:
    """What pip's configuration names: its replacement index, every other source, and the
    constraint and requirement files it lists."""

    index_url: str | None
    sources: _Sources
    constraint_files: tuple[str, ...] = ()
    requirement_files: tuple[str, ...] = ()


def _pip_config_sources(venv: Path, *, isolated: bool = False) -> _PipConfig:
    """The sources pip's effective configuration names, resolved as pip resolves it: files in
    pip's load order (system, user, the venv's own, then PIP_CONFIG_FILE), a later file's
    value replacing an earlier one; [install] over [global]; PIP_* variables over every file.
    An empty value is ignored, as pip ignores it. In isolated mode (--isolated) pip reads
    neither the user's files nor PIP_* variables; the system, venv and PIP_CONFIG_FILE files
    still count.
    PIP_CONFIG_FILE=os.devnull loads no file, and an existing PIP_CONFIG_FILE skips the user's."""
    import configparser

    env = os.environ
    named = env.get("PIP_CONFIG_FILE")
    sections: dict[str, dict[str, str]] = {"global": {}, "install": {}}
    if named != os.devnull:
        user, system = _config_dirs(env)
        files = [*(d / "pip" / "pip.conf" for d in system), _PIP_SITE_CONFIG]
        if not isolated and not (named and os.path.exists(named)):
            files += [Path.home() / ".pip" / "pip.conf", user / "pip" / "pip.conf"]
        files += [venv / "pip.conf", *([Path(named)] if named else [])]
        for conf in files:
            parser = configparser.ConfigParser(interpolation=None)
            try:
                parser.read_string(safe_read.read_text(conf, errors="replace"))
            except (OSError, configparser.Error):
                continue
            for section, values in sections.items():
                if parser.has_section(section):
                    for key, value in parser.items(section):
                        if (key := _PIP_KEY_ALIASES.get(k := key.replace("_", "-"), k)) in _PIP_SOURCE_KEYS \
                                and value:
                            # An empty value is skipped. pip 24.0 and 26.x let it clear an earlier
                            # file's value, pip 25.3 does not (measured): pipx records no pip
                            # version, so the earlier value, the one keeping packages private, stays.
                            values[key] = value
    effective = {**sections["global"], **sections["install"]}
    variables = {} if isolated else env
    for key in _PIP_SOURCE_KEYS:
        if variables.get(var := "PIP_" + key.upper().replace("-", "_")):
            effective[key] = variables[var]
    # pip applies PIP_PYPI_URL and PIP_INDEX_URL in os.environ's order, so with both set
    # either may win: a private one is taken.
    candidates = [u for u in (effective.get("index-url"), variables.get("PIP_PYPI_URL")) if u]
    index_url = next((u for u in candidates if _sources([u]).index), candidates[0] if candidates else None)
    sources = _sources(extra=[effective.get("extra-index-url")], find_links=effective.get("find-links"),
                       no_index=effective.get("no-index"))
    # Requirement and constraint files configured this way are read like -r/-c ones (see
    # _pip_effective_sources() for their order).
    return _PipConfig(index_url, sources, tuple((effective.get("constraint") or "").split()),
                      tuple((effective.get("requirement") or "").split()))


def _uv_index_env_urls(value: str | None) -> list[str]:
    """UV_INDEX's URLs: whitespace-separated, each optionally named (`name=url`)."""
    return [entry.partition("=")[2] if "=" in entry.split("://")[0] else entry for entry in (value or "").split()]


def _uv_config_tables(config_file: str | None = None, *, no_config: bool = False) -> tuple[list[dict], bool]:
    """(uv's configuration tables for `uv pip` (which pipx runs), highest precedence first:
    each file's [pip] table, then each file's top level, the user's file before the system's;
    whether an explicitly chosen file could not be read). UV_CONFIG_FILE or --config-file
    replaces discovery, even beside UV_NO_CONFIG, as uv does; what such a file said is
    unknown when it is now missing or invalid."""
    import tomllib

    env = os.environ
    explicit = bool(named := config_file or env.get("UV_CONFIG_FILE"))
    if named:
        files = [Path(named)]
    elif no_config or _truthy(env.get("UV_NO_CONFIG")):
        files = []
    else:
        user, system = _config_dirs(env)
        files = [user / "uv" / "uv.toml"]
        if not _truthy(env.get("UV_NO_SYSTEM_CONFIG")):
            # uv reads the first system file that exists, and /etc/uv/uv.toml only without one.
            files += [next((f for f in [*(d / "uv" / "uv.toml" for d in system), _UV_SYSTEM_CONFIG]
                            if _is_file(f)), _UV_SYSTEM_CONFIG)]
    loaded: list[dict] = []
    unresolved = False
    for conf in files:
        try:
            loaded.append(tomllib.loads(safe_read.read_text(conf, errors="replace")))
        except (OSError, ValueError):
            unresolved = explicit
    return [t["pip"] for t in loaded if isinstance(t.get("pip"), dict)] + loaded, unresolved


def _is_file(path: Path) -> bool:
    """Path.is_file(), False where it would raise; uv likewise skips a file it cannot query."""
    try:
        return path.is_file()
    except OSError:
        return False


def _uv_effective_sources(args: _InstallArgs) -> _Sources:
    """The sources uv used, resolved as uv resolves its arguments with its settings: indexes
    chain in order (--default-index or UV_DEFAULT_INDEX, --index-url or UV_INDEX_URL, then
    each table's `index` entries, then the first table's `index-url`) and the first default
    one replaces PyPI; other indexes and find-links add up; `no-index` comes from the
    highest-precedence setting."""
    env = os.environ
    tables, unresolved = _uv_config_tables(args.config_file, no_config=args.no_config)
    indexes = [table.get("index") for table in tables]
    entries = [i for value in indexes if isinstance(value, list) for i in value if isinstance(i, dict)]
    legacy = args.file_index if args.file_index is not None else args.index_url
    defaults = [args.default_index or env.get("UV_DEFAULT_INDEX"), legacy or env.get("UV_INDEX_URL"),
                *(i.get("url") for i in entries if i.get("default") is True),
                next((t["index-url"] for t in tables if t.get("index-url")), None)]
    default = next((d for d in defaults if d), None)
    extra = [env.get("UV_EXTRA_INDEX_URL"), _uv_index_env_urls(env.get("UV_INDEX")),
             *(i.get("url") for i in entries if i.get("default") is not True),
             *(t.get("extra-index-url") for t in tables)]
    find_links = env.get("UV_FIND_LINKS") or any(t.get("find-links") for t in tables)
    no_index = env.get("UV_NO_INDEX") if "UV_NO_INDEX" in env else next(
        (t["no-index"] for t in tables if "no-index" in t), None)
    configured = _sources([default], extra, find_links or unresolved, no_index)
    # The arguments' own extra indexes, find-links and no-index add to the configured ones.
    return configured | _Sources(other=args.sources.other, extra=args.sources.extra)


def _uv_table_sources(table: dict) -> tuple[str | None, _Sources]:
    """(the default index, the sources) a uv receipt's [tool.options] records. uv chains the
    `index` entries ahead of the legacy `index-url`, so a default entry is the default index
    even beside one; any other entry, and `extra-index-url`, sit beside it."""
    entries = [i for i in table.get("index") or [] if isinstance(i, dict)] if isinstance(table.get("index"), list) else []
    legacy = table.get("index-url")
    default = next((i.get("url") for i in entries if i.get("default") is True),
                   legacy if isinstance(legacy, str) else None)
    extra = [table.get("extra-index-url"), *(i.get("url") for i in entries if i.get("default") is not True)]
    return (default if isinstance(default, str) else None,
            _sources([default], extra, table.get("find-links"), table.get("no-index")))


def _truthy(value: object) -> bool:
    """A boolean setting as pip (strtobool) and uv read it."""
    from packagealert.parsers.process_args import _UV_SYSTEM_PYTHON_TRUTHY

    return str(value).strip().lower() in _UV_SYSTEM_PYTHON_TRUTHY if value is not None else False


def _uv_provenance(venv: Path) -> _ManagerRecord:
    """The tool's record from uv-receipt.toml: its requirement, and each one added with
    --with; without a readable receipt, as for pipx (_pipx_provenance())."""
    import tomllib

    try:
        receipt = tomllib.loads(safe_read.read_text(venv / "uv-receipt.toml", errors="replace"))
        tool = receipt["tool"]
        requirement, *with_requirements = tool["requirements"]
        options = tool.get("options") or {}
    except (OSError, ValueError, KeyError, TypeError):
        return _UNKNOWN_RECORD
    if not isinstance(requirement, dict) or not isinstance(options, dict):
        return _UNKNOWN_RECORD
    index_url, sources = _uv_table_sources(options)
    provenance, index_private = _uv_requirement_provenance(requirement, index_url, sources.private)
    if not index_private and sources.extra:
        provenance["extra_index"] = True
    not_public = {
        _canonical(r["name"]) for r in [requirement, *with_requirements]
        if isinstance(r, dict) and isinstance(r.get("name"), str)
        and _uv_requirement_provenance(r, None, False)[0]["kind"] in _NOT_INDEX_KINDS
    }
    name = requirement.get("name")
    return _ManagerRecord(provenance, index_private, name if isinstance(name, str) else None, frozenset(not_public))


def _uv_requirement_provenance(requirement: dict, index_url: object, index_private: bool) -> tuple[dict, bool]:
    if isinstance(editable := requirement.get("editable"), str):
        return {"kind": "local", "path": editable, "editable": True}, index_private
    for key in ("directory", "path"):
        if isinstance(where := requirement.get(key), str):
            return {"kind": "local", "path": where, "editable": False}, index_private
    if isinstance(git := requirement.get("git"), str):
        return _with_url({"kind": "git", "editable": False}, git), index_private
    if isinstance(url := requirement.get("url"), str):
        kind = "pypi" if _hostname(url) in _PUBLIC_FILE_HOSTS else "url"
        return _with_url({"kind": kind, "editable": False}, url), index_private
    if index_private:
        return _with_url({"kind": "index", "editable": False}, index_url if isinstance(index_url, str) else None), True
    return {"kind": "pypi", "editable": False}, False


# A PEP 508 direct reference's "name[extras] @ " before its URL.
_NAMED_URL_RE = re.compile(r"^[A-Za-z0-9][\w.-]*(\[[^\]]*\])?\s*@\s*(?=[A-Za-z][\w+.-]*://)")


def _provenance_of_spec(spec: str, editable: bool, index_url: str | None, index_private: bool) -> dict:
    """A pipx package_or_url: a path, a VCS or archive URL (bare, or `name @ url`), or a
    requirement from an index."""
    url = _NAMED_URL_RE.sub("", spec.strip(), count=1)
    if url.startswith("git+"):
        return _with_url({"kind": "git", "editable": editable}, url)
    if "://" in url:
        kind = "pypi" if _hostname(url) in _PUBLIC_FILE_HOSTS else "url"
        return _with_url({"kind": kind, "editable": editable}, url)
    if spec.startswith(("/", "./", "../", "~")) or os.sep in spec:
        return {"kind": "local", "path": spec, "editable": editable}
    if index_private:
        return _with_url({"kind": "index", "editable": editable}, index_url)
    return {"kind": "pypi", "editable": editable}


def _hostname(url: str) -> str | None:
    """*url*'s host, or None when it cannot be parsed (`https://[broken`): never one of
    PyPI's, so a malformed URL counts as a private source."""
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _with_url(provenance: dict, url: str | None) -> dict:
    if (safe := safe_source_url(url)) is not None:
        provenance["url"] = safe
    return provenance


def safe_source_url(url: str | None) -> str | None:
    """*url* fit to record or upload: userinfo, query and fragment removed; None when it cannot
    be parsed, or a path segment looks like a token (a credential embedded in the path, as some
    private indexes use)."""
    if not isinstance(url, str) or not url.strip():
        return None
    scheme_prefix = ""
    raw = url.strip()
    if raw.startswith("git+"):
        scheme_prefix, raw = "git+", raw[4:]
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not parts.scheme or not host:
        return None
    # Decoded first, so neither an encoded character nor an encoded "/" hides a token.
    if any(_TOKEN_SEGMENT_RE.match(segment) or _JWT_SEGMENT_RE.match(segment) or _TOKEN_PREFIX_RE.match(segment)
           for segment in unquote(parts.path).split("/")):
        return None
    if ":" in host:                     # an IPv6 literal keeps its brackets
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    return scheme_prefix + urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()
