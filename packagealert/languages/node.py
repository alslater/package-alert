"""Node.js/npm language module implementing the LanguageBase contract."""
from __future__ import annotations

import functools
import json
import logging
import os
import re
import shutil
import time
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

import httpx

from packagealert import safe_read
from packagealert.heuristics.base import AbstractHeuristic
from packagealert.languages.base import (
    CURRENT_CONTRACT_VERSION,
    MAX_TOP_PACKAGES,
    PackageMetadata,
    PackageSpec,
    PreRunResult,
    ProcessInstall,
    SandboxPaths,
    SandboxTargets,
    ShellEnvironment,
    Snapshot,
    parse_registry_timestamp,
)
from packagealert.models.risk import RiskSignal

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal regex constants (mirrored from heuristics/npm.py)
# ---------------------------------------------------------------------------
_EVAL_RE = re.compile(r"\beval\s*\(", re.MULTILINE)
_CHILD_PROCESS_RE = re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)", re.MULTILINE)
_NETWORK_RE = re.compile(
    r"\b(fetch|axios|http\.request|https\.request|require\s*\(\s*['\"]https?['\"]\s*\))\b"
)
_CURL_RE = re.compile(r"\b(curl|wget)\b")
_POWERSHELL_RE = re.compile(r"\bpowershell\b", re.IGNORECASE)
_CREDENTIAL_RE = re.compile(
    r"\b(HOME|USERPROFILE|\.ssh|\.aws|credential|token|password|passwd)\b", re.IGNORECASE
)

_JS_EXTENSIONS = {".js", ".cjs", ".mjs"}
_MAX_FILE_SIZE = 512 * 1024  # 512 KB
_MAX_JS_FILES = 20


# ---------------------------------------------------------------------------
# Inline heuristic
# ---------------------------------------------------------------------------

class _NpmHeuristic(AbstractHeuristic):
    """Inline reimplementation of NpmHeuristics for the NodeLanguage module."""

    async def analyze(self, package_dir: Path) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        pkg_json_path = package_dir / "package.json"
        if not pkg_json_path.exists():
            return signals

        try:
            pkg = json.loads(safe_read.read_bytes(pkg_json_path))
        except Exception:  # noqa: BLE001 — malformed/unreadable package.json, no signals to extract
            return signals

        scripts: dict[str, str] = pkg.get("scripts", {})
        install_keys = {"preinstall", "install", "postinstall"}
        found_install = install_keys & scripts.keys()
        if found_install:
            signals.append(RiskSignal(
                name="install_script",
                score=20,
                reason=f"Install lifecycle script found: {', '.join(sorted(found_install))}",
            ))

        all_script_code = " ".join(scripts.values())
        if _CURL_RE.search(all_script_code):
            signals.append(RiskSignal(
                name="curl_in_script",
                score=15,
                reason="curl/wget in install scripts",
            ))
        if _POWERSHELL_RE.search(all_script_code):
            signals.append(RiskSignal(
                name="powershell_in_script",
                score=20,
                reason="PowerShell in install scripts",
            ))

        js_files = []
        for p in package_dir.rglob("*"):
            if p.suffix not in _JS_EXTENSIONS:
                continue
            if "node_modules" in p.parts[len(package_dir.parts):]:
                continue
            try:
                if p.stat().st_size < _MAX_FILE_SIZE:
                    js_files.append(p)
            except OSError:
                pass
            if len(js_files) >= _MAX_JS_FILES:
                break

        combined_js = ""
        for js_file in js_files:
            try:
                combined_js += safe_read.read_text(js_file, errors="replace") + "\n"
            except OSError:
                pass

        if _EVAL_RE.search(combined_js):
            signals.append(RiskSignal(
                name="eval_usage",
                score=25,
                reason="eval() detected in JS source",
            ))
        if _CHILD_PROCESS_RE.search(combined_js):
            signals.append(RiskSignal(
                name="child_process",
                score=20,
                reason="child_process require detected",
            ))
        if _NETWORK_RE.search(combined_js):
            signals.append(RiskSignal(
                name="network_access",
                score=10,
                reason="Network API usage detected in JS",
            ))
        if _CREDENTIAL_RE.search(combined_js):
            signals.append(RiskSignal(
                name="credential_access",
                score=25,
                reason="Credential/secret path patterns in JS",
            ))

        return signals


# ---------------------------------------------------------------------------
# NodeLanguage
# ---------------------------------------------------------------------------

# Hosts serving the public npm registry (registry.yarnpkg.com is yarn's proxy of it).
_PUBLIC_NPM_HOSTS = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
_YARN_RESOLVED_RE = re.compile(r'^\s+resolved\s+"([^"]+)"', re.MULTILINE)


def quote_npm_name(name: str) -> str:
    """*name* as a registry URL path segment: a scoped name keeps its @ and encodes its /."""
    return quote(name, safe="@")


def from_public_npm_registry(resolved: object) -> bool:
    """Whether a lock entry's ``resolved`` URL is a tarball on the public npm registry.

    Anything else (a private registry, git, a file or link, or no URL at all)
    is not: a lookup on registry.npmjs.org would describe a different package
    of the same name, or none.
    """
    if not isinstance(resolved, str):
        return False
    try:
        url = urlsplit(resolved)
    except ValueError:
        return False
    return url.scheme in ("https", "http") and url.hostname in _PUBLIC_NPM_HOSTS


def _npm_config_env() -> dict[str, str]:
    """npm configuration set in the environment: ``npm_config_<key>``, matched case-insensitively.

    Inside a sandboxed command (``SANDBOX_ENV``) the environment npm there gets,
    which leaves out a registry variable carrying credentials; elsewhere this
    process's.
    """
    import os

    from packagealert.parsers.process_args import SANDBOX_ENV

    source = SANDBOX_ENV.get()
    environ = os.environ if source is None else source
    prefix = "npm_config_"
    return {k[len(prefix):].lower(): v for k, v in environ.items() if k.lower().startswith(prefix) and v}


def _npm_registry_env_names() -> list[str]:
    """The environment variables (as spelled) that npm's registry settings come from.

    That is ``npm_config_registry``, ``npm_config_@scope:registry`` and the
    ones locating config files (``npm_config_userconfig``,
    ``npm_config_globalconfig``, ``npm_config_prefix``) in any letter case, and a
    variable that is the whole value of a registry line in the user's, the
    global or npm's builtin npmrc and holds a credential-free URL
    (``_npmrc_registry_refs``). These are what
    ``_npm_registries()`` reads, so the sandbox passes them on
    and npm there fetches from the registry the provenance check assumed.
    Credentials (``npm_config_//host/:_authToken``) are not among them.
    """
    import os

    prefix = "npm_config_"
    names = []
    for name, value in os.environ.items():
        key = name[len(prefix):].lower() if name.lower().startswith(prefix) else None
        if not value or key is None:
            continue
        # A registry address only when it carries no credentials (https://user:pass@host/
        # would hand them to install code); the others are file paths.
        if key in ("userconfig", "globalconfig", "prefix") or (
                (key == "registry" or (key.startswith("@") and key.endswith(":registry")))
                and _credential_free_url(value)):
            names.append(name)
    # Registry-address variables of the user's own and the machine's config files (never
    # one that may carry a credential). A project's .npmrc is the repository's, so its
    # references are not passed at all; --env or sandbox.extra_env passes one deliberately.
    trusted = [rc for rc, ok in _npm_system_npmrc_entries() if ok]
    for rc in (_user_npmrc(), *trusted):
        names.extend(name for name in _npmrc_registry_refs(rc) if name not in names)
    return names


_NPMRC_ENV_RE = re.compile(r"\$\{([^}?]+)(\?)?\}")


def _expand_npmrc_env(value: str, env: Mapping[str, str] | None = None) -> str:
    """*value* with npm's ``${VAR}`` references expanded from *env* (default: this process's environment).

    ``${VAR?}`` becomes empty when VAR is unset; a plain ``${VAR}`` that is
    unset stays as written (npm itself refuses such a config), so it is not
    mistaken for any real registry.
    """
    import os

    source = os.environ if env is None else env

    def sub(m: re.Match[str]) -> str:
        found = source.get(m.group(1))
        if found is not None:
            return found
        return "" if m.group(2) else m.group(0)
    return _NPMRC_ENV_RE.sub(sub, value)


def _user_npmrc() -> Path:
    """The user's npm configuration file (``npm_config_userconfig`` moves it), as an absolute path.

    npm resolves a relative userconfig against its working directory, which
    for the host's command is this process's.
    """
    return _npm_env_path("userconfig") or Path.home() / ".npmrc"


def _user_npmrc_visible() -> bool:
    """Whether npm in a sandboxed command (``SANDBOX_ENV``) sees the user's config file: it
    is bound wherever it is, after any tmpfs, but not into a plugin's hidden path
    (``SANDBOX_HIDDEN``), which is laid over every bind, as written or along its links.
    Outside a sandbox, always."""
    from packagealert.parsers.process_args import SANDBOX_ENV, SANDBOX_HIDDEN

    if SANDBOX_ENV.get() is None:
        return True
    return not _passes_through(_user_npmrc(), SANDBOX_HIDDEN.get())


# The settings that locate npm's user and global config files.
_NPM_CONFIG_LOCATORS = ("userconfig", "globalconfig", "prefix")


def _npm_env_path(key: str, env: Mapping[str, str] | None = None, *, relative: bool = True) -> Path | None:
    """The path-typed npm setting *key* from the environment (``npm_config_<key>``, in
    *env*, default _npm_environ()) as npm reads it: ``${VAR}`` expanded, then as
    _npm_path(). Without *relative*, None for a relative one.

    The ``${VAR}``s come from this process's environment, where the user set them:
    the sandbox is given the setting as this absolute path (prepare_sandbox_env()),
    not the variables.
    """
    env = _npm_environ() if env is None else env
    values = [_expand_npmrc_env(v) for k, v in env.items() if k.lower() == f"npm_config_{key}" and v]
    if not values or not (relative or values[-1].startswith(("/", "~/"))):
        return None
    return _npm_path(values[-1], env)


def _npm_registries(root: Path, *, project: bool = True, command_line: Mapping[str, str] | None = None,
                    npm: bool = True) -> tuple[str | None, dict[str, str]]:
    """(default registry, {"@scope": registry}) as npm resolves them.

    npm's precedence: the command line (the running command's, from
    ``COMMAND_LINE_REGISTRIES``), the environment (``npm_config_registry``,
    ``npm_config_@scope:registry``), then the project's .npmrc, then the
    user's, then the global npmrc and npm's builtin one (_npm_global_npmrc(),
    _npm_builtin_npmrc()), which only npm reads: with *npm* false (for pnpm, whose
    version 11 on reads neither, and yarn) they are skipped. Without *project* the project's file is skipped, as
    npm does in global mode. Unreadable files are skipped. *command_line*
    (default ``COMMAND_LINE_REGISTRIES``) is the running command's settings.

    npm also lets the command line and the project's .npmrc move the user and
    global config files (``userconfig``, ``globalconfig``, ``prefix``). Where
    they lead is not followed: a file moved that way is left out (see
    _npm_global_npmrc()), so its registries are never assumed for a command
    whose npm does not read them. This reads the environment of the
    process parsing the lock file, which is the user's for ``package-alert``
    commands.
    """
    default: str | None = None
    scopes: dict[str, str] = {}
    from packagealert.parsers.process_args import COMMAND_LINE_REGISTRIES, SANDBOX_ENV

    # The environment, then the running command's own --registry/--@scope:registry over it.
    command_line = COMMAND_LINE_REGISTRIES.get() if command_line is None else command_line
    # npm's own shebang can change the environment it runs with (env -i, -u, VAR=…), so
    # where its configuration comes from is not known: only its command line is assumed.
    environment_known = not npm or _npm_runtime(_npm_environ()) != _UNKNOWN_RUNTIME
    for key, value in (*(_npm_config_env().items() if environment_known else ()), *command_line.items()):
        if key == "registry":
            default = value
        elif key.startswith("@") and key.endswith(":registry"):
            scopes[key[: -len(":registry")]] = value
    # Both files expand their ${VAR}s as npm in the sandbox will, from the environment
    # the sandbox gets (SANDBOX_ENV, inside pa run and pa fix trials); elsewhere from
    # this process's. The sandbox is given only some of them (_npmrc_registry_refs).
    sandbox_env = SANDBOX_ENV.get()
    moved = {key for key in _NPM_CONFIG_LOCATORS if key in command_line}
    if project:  # the environment's setting of a locator overrides the project's
        moved.update(key for key, _ in _npmrc_lines(root / ".npmrc")
                     if key in _NPM_CONFIG_LOCATORS and key not in _npm_config_env())
    if npm:
        builtin = _npm_builtin_npmrc(_npm_environ())
        if builtin is not None and _npm_sandbox_can_read(builtin, None) and \
                _npm_builtin_moves_userconfig(builtin, _npm_config_env()):
            moved.add("userconfig")
    files = [*([root / ".npmrc"] if project else []),
             *([] if "userconfig" in moved or not _user_npmrc_visible() else [_user_npmrc()]),
             *(_npm_system_npmrcs(moved) if npm else [])] if environment_known else []
    for rc in files:
        # Within one file the last assignment of a key wins, as in npm's INI parser;
        # between sources the earlier (higher-precedence) one does.
        file_default, file_scopes = _npmrc_registries(rc, sandbox_env)
        if default is None:
            default = file_default
        for scope, value in file_scopes.items():
            scopes.setdefault(scope, value)
    return default, scopes


def _npmrc_lines(rc: Path) -> list[tuple[str, str]]:
    """(key, value) for each top-level setting line of *rc*, in order, decoded as npm's INI
    parser decodes them (_ini_unsafe()): quotes removed, an inline ``;``/``#`` comment
    cut. A ``[section]``'s settings are not top-level, so none after one is read.

    An unreadable file has none, and so does anything but a regular file (a FIFO would
    block the read forever); a symlinked config is read.
    """
    raw = _read_regular(rc, follow_symlinks=True)
    try:
        lines = raw.decode().splitlines() if raw is not None else []
    except UnicodeDecodeError:
        return []
    found = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if _INI_SECTION_RE.match(stripped):
            break
        key, sep, value = line.partition("=")
        if sep:
            found.append((_ini_unsafe(key), _ini_unsafe(value)))
    return found


_INI_SECTION_RE = re.compile(r"^\[([^\]]*)\]\s*$")


def _ini_unsafe(value: str) -> str:
    """A key or value as npm's ``ini`` package decodes it (its ``unsafe()``): a quoted one
    ('…' or "…") is unquoted, and JSON-decoded when it parses; otherwise it ends at the
    first unescaped ``;`` or ``#``, ``\\;``, ``\\#`` and ``\\\\`` standing for the character."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        if value[0] == "'":
            value = value[1:-1]
        try:
            decoded = json.loads(value)
        except ValueError:
            return value
        return decoded if isinstance(decoded, str) else value
    out = []
    escaped = False
    for char in value:
        if escaped:
            out.append(char if char in "\\;#" else "\\" + char)
            escaped = False
        elif char in ";#":
            break
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    if escaped:
        out.append("\\")
    return "".join(out).strip()


def _npmrc_registry_lines(rc: Path) -> list[tuple[str, str]]:
    """(key, value as written) for each ``registry`` / ``@scope:registry`` line of *rc*, in order."""
    return [(key, value) for key, value in _npmrc_lines(rc)
            if key == "registry" or (key.startswith("@") and key.endswith(":registry"))]


def _npm_environ() -> Mapping[str, str]:
    """The environment npm runs with: the sandbox's inside a sandboxed command, else this process's."""
    from packagealert.parsers.process_args import SANDBOX_ENV

    source = SANDBOX_ENV.get()
    return os.environ if source is None else source


def _npm_path(value: str, env: Mapping[str, str]) -> Path | None:
    """A path-typed npm setting as npm reads it: ``~/`` from $HOME, relative to the working
    directory."""
    if not value:
        return None
    if value.startswith("~/"):
        value = os.path.join(env.get("HOME") or str(Path.home()), value[2:])
    return Path(os.path.abspath(value))


def _real_executable(found: str) -> Path:
    """The executable *found* on PATH runs, resolved: the original a package-alert
    shim replaced (its ``.__pa_real`` sibling) when there is one. Raises OSError or
    RuntimeError when it cannot be resolved."""
    resolved = Path(found).resolve()
    original = resolved.with_name(f"{resolved.name}.__pa_real")
    return original.resolve() if original.exists() else resolved


def _command_npm() -> tuple[str | None, str | None]:
    """(the npm script, the node named to run it) of the running command (COMMAND_ARGV):
    ``npm …`` or ``/opt/x/bin/npm …`` gives (that npm, None), ``node /…/npm-cli.js …``
    (as the process monitor sees every npm) gives both, and (UNKNOWN_SCRIPT, that node)
    when node runs a script the command line no longer shows (npm rewrites its process
    title). (None, None) when it is not npm."""
    from packagealert.parsers.process_args import COMMAND_ARGV, UNKNOWN_SCRIPT

    argv = list(COMMAND_ARGV.get() or ())
    if not argv:
        return None, None
    node: str | None = None
    if argv[0] == UNKNOWN_SCRIPT and (len(argv) < 2 or argv[1] == UNKNOWN_SCRIPT):
        return UNKNOWN_SCRIPT, UNKNOWN_SCRIPT  # neither the runtime nor the script is known
    if (argv[0] == UNKNOWN_SCRIPT or _runtime_name(argv[0]) in ("node", "nodejs")) and len(argv) > 1:
        node = argv.pop(0)  # UNKNOWN_SCRIPT: a node the monitor could not see
        if argv[0] == UNKNOWN_SCRIPT:
            return UNKNOWN_SCRIPT, node
        argv[0] = os.path.abspath(argv[0])  # node resolves its script against the working directory
    script = argv[0]
    if _runtime_name(script) != "npm":
        return None, None
    return script, node


def _runtime_name(path: str) -> str:
    """*path*'s command name as the npm parser normalises it (``/opt/x/bin/npm-11`` and
    ``npm-cli.js`` are npm, ``node20`` is node), a package-alert shim's renamed original
    (``node.__pa_real``) included, and without a script extension (``pnpm.cjs``), as
    the pnpm parser reads it."""
    from packagealert.parsers.process_args import _cmd

    name = _cmd(Path(path).name.removesuffix(".__pa_real"))
    for suffix in (".cjs", ".mjs", ".js"):
        name = name.removesuffix(suffix)
    return name


def _which(name: str, env: Mapping[str, str]) -> str | None:
    """*name* as a shell finds it: a path as written, else looked up on the environment's PATH."""
    return _kernel_absolute(name) if os.sep in name else shutil.which(name, path=env.get("PATH"))


def _kernel_absolute(path: str | Path) -> str:
    """*path* made absolute against the working directory as the kernel reads it when it
    runs or opens it: ``..`` is left in place, to apply after any symlink before it
    (``/opt/selector/../bin/node`` with ``selector -> /srv/node/lib`` is /srv/node/bin/node),
    unlike os.path.abspath(), which drops it lexically."""
    path = os.fspath(path)
    return path if os.path.isabs(path) else os.path.join(os.getcwd(), path)


def _npm_builtin_npmrc(env: Mapping[str, str]) -> Path | None:
    """npm's builtin config file (``<npm's package>/npmrc``) for the npm the running
    command invokes (_command_npm()), else the one on PATH, and None when the npm node
    runs is not known: distribution packages set ``globalconfig``/``prefix`` there
    (Debian: /etc/npmrc)."""
    from packagealert.parsers.process_args import UNKNOWN_SCRIPT

    script = _command_npm()[0]
    found = None if script == UNKNOWN_SCRIPT else _which(script or "npm", env)
    if found is None:
        return None
    try:
        real = _real_executable(found)
    except (OSError, RuntimeError):
        return None
    for directory in list(real.parents)[:3]:
        manifest = _read_json_object(directory / "package.json")
        if manifest is not None and manifest.get("name") == "npm":
            return directory / "npmrc"
    return None


def _npm_default_prefix(env: Mapping[str, str]) -> Path | None:
    """npm's default global prefix: $PREFIX, else the installation of the node running npm
    (the one the running command names, else the one on PATH: /usr/local/bin/node ->
    /usr/local), under $DESTDIR when set."""
    if env.get("PREFIX"):
        # A relative one is npm's working directory's, which is not known here (an observed
        # process, a scratch trial) and is not made absolute for the command.
        return Path(env["PREFIX"]) if os.path.isabs(env["PREFIX"]) else None
    runtime = _npm_runtime(env)
    if runtime in (_UNKNOWN_RUNTIME, _UNSEEN_RUNTIME):
        return None
    found = _which(runtime or "node", env)
    if found is None:
        return None
    try:
        prefix = _real_executable(found).parent.parent  # process.execPath is the real binary
    except (OSError, RuntimeError):
        return None
    if env.get("DESTDIR"):
        if not os.path.isabs(env["DESTDIR"]):
            return None  # npm's working directory's, as $PREFIX
        prefix = Path(env["DESTDIR"]) / prefix.relative_to(prefix.anchor)
    return prefix


def _npm_global_npmrc(moved: Collection[str] = ()) -> Path | None:
    """npm's global config file (see _npm_global_npmrc_located())."""
    return _npm_global_npmrc_located(moved)[0]


def _npm_global_npmrc_located(moved: Collection[str] = ()) -> tuple[Path | None, bool]:
    """(npm's global config file, whether the repository cannot have chosen it).

    npm locates it as the ``globalconfig`` setting from the environment, the user's
    .npmrc or the builtin one, in that order; else ``<prefix>/etc/npmrc``, with
    ``prefix`` looked up the same way and defaulting to _npm_default_prefix().

    npm also takes either setting from the command line and the project's .npmrc,
    and *moved* names the locators (_NPM_CONFIG_LOCATORS) set there. Where they
    point is not followed: the sandbox could not be made to read a file the
    repository names. So None is returned wherever such a setting decides the
    location (a moved ``userconfig`` hides the user's file, which could), and the
    global file's registries are then not assumed, which only adds lookups. The file
    is not trusted when an npm or node the repository may have chosen located it: an
    untrusted builtin npmrc (_npm_builtin_trusted()) or, for the default prefix, an
    untrusted node (_npm_node_trusted()).
    """
    from packagealert.parsers.process_args import COMMAND_CWD_KNOWN, UNKNOWN_SCRIPT

    env = _npm_environ()
    environment = _npm_config_env()
    builtin = _npm_builtin_npmrc(env)
    if builtin is not None and not _npm_sandbox_can_read(builtin, None):
        builtin = None  # npm in the sandbox does not see what it would choose either
    files = [*([_user_npmrc()] if _user_npmrc_visible() else []), *([builtin] if builtin else [])]

    def setting(key: str) -> tuple[bool, Path | None, bool]:
        """(whether *key* is set, the path it names, whether the builtin npmrc set it)."""
        if key in environment:
            # A relative one is npm's working directory's: this process's for a command
            # package-alert runs (prepare_sandbox_env() gives a sandboxed npm that absolute
            # path), unknown to the daemon for an observed process, where it is not followed.
            return True, _npm_env_path(key, env, relative=COMMAND_CWD_KNOWN.get()), False
        for rc in files:
            values = [value for name, value in _npmrc_lines(rc) if name == key]
            if values:  # the last assignment in a file wins; an unset ${VAR} stays as written
                value = _expand_npmrc_env(values[-1], env)
                # npm resolves a relative one against its working directory, which for a
                # trial is the scratch copy, so where it leads is not followed.
                return True, _npm_path(value, env) if value.startswith(("/", "~/")) else None, rc == builtin
        return False, None, False

    def trusted(by_builtin: bool) -> bool:
        return not by_builtin or builtin is None or _npm_builtin_trusted(builtin)

    if "globalconfig" in moved:
        return None, True
    if "globalconfig" in environment:
        return setting("globalconfig")[1], True
    if "userconfig" in moved or _npm_builtin_moves_userconfig(builtin, environment):
        return None, True
    found, globalconfig, by_builtin = setting("globalconfig")
    if found:
        # One the builtin npmrc chose is trusted only if no hop of its own chain is the repository's.
        chain_ok = not by_builtin or globalconfig is None or _outside_project(globalconfig)
        return globalconfig, trusted(by_builtin) and chain_ok
    if _command_npm()[0] == UNKNOWN_SCRIPT:
        return None, True  # the unknown npm's builtin npmrc may choose it (globalconfig, prefix)
    if "prefix" in moved:
        return None, True
    found, prefix, by_builtin = setting("prefix")
    if found:
        located_trusted = trusted(by_builtin)
    else:
        prefix = _npm_default_prefix(env)
        located_trusted = bool(env.get("PREFIX")) or _npm_node_trusted()
    rc = prefix / "etc" / "npmrc" if prefix is not None else None
    if rc is not None and (by_builtin or not found):
        # Found by npm rather than named by the user: trusted only if no hop of its own
        # chain is the repository's (<prefix>/etc/npmrc -> <repo>/selector -> …).
        located_trusted = located_trusted and _outside_project(rc)
    return rc, located_trusted


def _npm_builtin_moves_userconfig(builtin: Path | None, environment: Mapping[str, str]) -> bool:
    """Whether npm's builtin npmrc *builtin* sets ``userconfig``, which then replaces the
    user's file unless the environment sets it. Where it leads is not followed, as for a
    moved locator (_npm_global_npmrc_located())."""
    if builtin is None or "userconfig" in environment:
        return False
    return any(key == "userconfig" for key, _ in _npmrc_lines(builtin))


# The directory the sandbox replaces with an empty tmpfs.
_SANDBOX_TMP = Path("/tmp")


def _passes_through(rc: Path, directories: Collection[Path]) -> bool:
    """Whether resolving *rc* visits any of *directories* (_resolution_paths()); True when
    it cannot be resolved."""
    try:
        traversed = _resolution_paths(rc)
    except (OSError, RuntimeError):
        return True
    return any(path.is_relative_to(d) for path in traversed for d in directories)


def _resolution_paths(path: Path) -> list[Path]:
    """Every path resolving *path* visits, component by component: each symlink and what it
    names, through to the end. A missing component ends the walk; more than 40 links
    (the kernel's limit) raise OSError."""
    pending = list(Path(_kernel_absolute(path)).parts[1:])
    current = Path("/")
    visited = [Path(_kernel_absolute(path))]
    links = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            continue
        candidate = current / part
        visited.append(candidate)
        if not candidate.is_symlink():
            current = candidate
            continue
        links += 1
        if links > 40:
            raise OSError(f"too many levels of symbolic links: {path}")
        target = Path(os.readlink(candidate))
        if target.is_absolute():
            current = Path("/")
            pending[:0] = list(target.parts[1:])
        else:
            pending[:0] = list(target.parts)
    visited.append(current)
    return visited


def _npm_builtin_trusted(builtin: Path) -> bool:
    """Whether *builtin* belongs to an npm the repository cannot have chosen: the one on
    PATH (not one the command names by path), installed outside the project (_project_boundaries())
    and reached without passing through it: the PATH entry, the original behind a
    package-alert shim, and every link on the way (``<repo>/node_modules/.bin/npm ->
    /opt/npm/bin/npm-cli.js`` is the repository's choice of npm).

    The builtin npmrc of any other npm (``node tools/npm/bin/npm-cli.js``) is read like
    any config npm reads, but it could name or link to any file and refer to any
    variable, so it and a global npmrc it chose are never bound into the sandbox and
    their variables are not passed (_npm_system_npmrc_entries()).
    """
    script = _command_npm()[0]
    if not _on_path(script, "npm") or not _outside_project(builtin):
        return False
    found = _which(script or "npm", _npm_environ())
    return found is not None and _executable_outside_project(found)


def _npm_node_trusted() -> bool:
    """Whether the node whose installation gives npm's default prefix is one the
    repository cannot have chosen: the one on PATH (not one the command names by path,
    ``./runtime/bin/node npm-cli.js``), installed outside the project (_project_boundaries()). A
    global npmrc it locates is otherwise treated like an untrusted builtin npmrc."""
    node = _npm_runtime(_npm_environ())
    if node in (_UNKNOWN_RUNTIME, _UNSEEN_RUNTIME):
        return False
    found = _which(node or "node", _npm_environ())
    # The original behind a package-alert shim counts too, as the default prefix follows it.
    return found is not None and _on_path(node, "node") and _executable_outside_project(found)


def _npm_runtime(env: Mapping[str, str]) -> str | None:
    """The node that runs npm when the running command names one (``node npm-cli.js``),
    else the interpreter npm's own shebang names (``#!/opt/x/bin/node``, or
    ``#!/usr/bin/env node-20`` on PATH; _UNKNOWN_RUNTIME when ``env``'s arguments cannot
    be read or the interpreter is not node, such as a shell launcher), else None: the
    node on PATH (``#!/usr/bin/env node``)."""
    from packagealert.parsers.process_args import UNKNOWN_SCRIPT

    script, node = _command_npm()
    if node == UNKNOWN_SCRIPT:
        return _UNSEEN_RUNTIME
    if node is not None:
        return node
    found = None if script == UNKNOWN_SCRIPT else _which(script or "npm", env)
    if found is None:
        return None
    try:
        with safe_read.open_regular(_real_executable(found)) as fh:
            first = fh.readline(4096)
    except (OSError, RuntimeError):
        return None
    if not first.startswith(b"#!"):
        return None
    words = first[2:].decode(errors="replace").split()
    if not words:
        return None
    if Path(words[0]).name == "env":
        return _env_command(words[1:])  # looked up on PATH
    if os.path.isabs(words[0]) and _runtime_name(words[0]) in ("node", "nodejs"):
        return words[0]
    return _UNKNOWN_RUNTIME  # a launcher (#!/bin/sh) runs some node it chooses


# A runtime that cannot be established, such as a launcher or an ``env`` that changes
# npm's environment: the config it would locate is not assumed, nor the environment's.
_UNKNOWN_RUNTIME = "\0unknown"
# A runtime the daemon did not see (an observed process's executable was unreadable):
# the config it would locate is not assumed, but npm's environment is the usual one.
_UNSEEN_RUNTIME = "\0unseen"


def _env_command(args: list[str]) -> str | None:
    """The command ``env`` runs from a shebang's arguments (``-S node --flag``): None for
    ``node``, the one on PATH, else that node (``node-20``). _UNKNOWN_RUNTIME when ``env``
    changes the environment or directory npm runs with (``-i``, ``-u``, ``-C``, ``VAR=…``:
    its PATH, $PREFIX and npm_config_* settings are then not the caller's), uses an option
    not known here or a quoted, escaped or ``$``-expanded word, or runs something but node."""
    for word in args:
        if word in ("-S", "--split-string", "--"):
            continue
        if word.startswith("-") or "=" in word:
            return _UNKNOWN_RUNTIME  # an option or an assignment
        if _runtime_name(word) not in ("node", "nodejs"):
            return _UNKNOWN_RUNTIME  # not node (a launcher, which may set any environment), or a word env -S unquotes or expands
        return None if word == "node" else word
    return _UNKNOWN_RUNTIME


def _on_path(named: str | None, name: str) -> bool:
    """Whether *named*, the executable a command names (None: none), is the *name* on PATH."""
    if named is None or os.sep not in named:
        return True
    on_path = _which(name, _npm_environ())
    try:
        return on_path is not None and _real_executable(named) == _real_executable(on_path)
    except (OSError, RuntimeError):
        return False


def _outside_project(path: Path) -> bool:
    """Whether resolving *path* stays outside the project (_project_boundaries()): as written,
    at every symlink on the way (``npmrc -> <repo>/selector -> ~/.ssh/id_rsa``) and where it
    ends. False when it cannot be resolved."""
    boundaries = _project_boundaries()
    try:
        traversed = _resolution_paths(path)
    except (OSError, RuntimeError):
        return False
    return not any(p.is_relative_to(b) for p in traversed for b in boundaries)


def _executable_outside_project(found: str) -> bool:
    """Whether the executable *found* on PATH is reached without passing through the
    project: its own chain, and that of the original behind a package-alert shim (its
    ``.__pa_real`` sibling, followed hop by hop rather than resolved first, so a link
    through the repository on the way counts). False when it cannot be resolved."""
    try:
        resolved = Path(found).resolve()
    except (OSError, RuntimeError):
        return False
    original = resolved.with_name(f"{resolved.name}.__pa_real")
    chains = [Path(found), *([original] if os.path.lexists(original) else [])]
    return all(_outside_project(path) for path in chains)


# Directories that mark a repository's root.
_VCS_MARKERS = (".git", ".hg")


def _project_boundaries() -> list[Path]:
    """The directories whose contents a repository may have chosen: the project of the
    working directory and, when package-alert acts on another one (``pa fix /srv/repo``,
    ``COMMAND_PROJECT``), that one's too (_project_boundary())."""
    from packagealert.parsers.process_args import COMMAND_PROJECT

    starts = [Path.cwd(), *([target] if (target := COMMAND_PROJECT.get()) is not None else [])]
    return list(dict.fromkeys(_project_boundary(start) for start in starts))


def _project_boundary(start: Path) -> Path:
    """The project *start* lies in: the outermost directory at or above it that is a
    repository root (``.git``, ``.hg``) or has a package.json (a workspace root, whose
    ``node_modules/.bin`` may be on PATH), else *start* itself.

    The outermost, since a repository can check in a marker of its own lower down
    (``packages/app/.hg``). Only below $HOME when *start* is (a home directory kept in
    git is not the project), and never the filesystem root."""
    start = Path(os.path.abspath(start))
    home = Path.home()
    chain = [d for d in (start, *start.parents) if d != d.parent]
    if start.is_relative_to(home):
        chain = [d for d in chain if d != home and d.is_relative_to(home)]
    marked = [d for d in chain
              if (d / "package.json").is_file() or any((d / marker).exists() for marker in _VCS_MARKERS)]
    return marked[-1] if marked else start


def _npm_system_npmrc_entries(moved: Collection[str] = ()) -> list[tuple[Path, bool]]:
    """(file, trusted) for the global npmrc (_npm_global_npmrc_located(*moved*)) then npm's
    builtin one: trusted unless an npm or node the repository may have chosen is the
    file or located it (_npm_global_npmrc_located())."""
    builtin = _npm_builtin_npmrc(_npm_environ())
    trusted = builtin is None or _npm_builtin_trusted(builtin)
    global_rc, global_trusted = _npm_global_npmrc_located(moved)
    return [(rc, ok) for rc, ok in ((global_rc, global_trusted), (builtin, trusted)) if rc is not None]


def _npm_home_bind(rc: Path) -> Path | None:
    """Where NodeLanguage.home_ro_paths() binds the global or builtin npmrc *rc* (when it is
    trusted): at its own name when that is under $HOME, else at its real one when that
    is, else nowhere (it is visible already, or not at all)."""
    home = Path.home()
    if Path(os.path.abspath(rc)).is_relative_to(home):
        return Path(os.path.abspath(rc))
    try:
        real = rc.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return real if real.is_relative_to(home) else None


def _sandbox_breaks(rc: Path, bound: Path | None) -> bool:
    """Whether npm in the sandbox cannot follow *rc* to its file, given *bound* (where the
    file is bound in: NodeLanguage.home_ro_paths(), None: nowhere). True when it cannot
    be resolved.

    Every path resolving it visits (_resolution_paths()) must be shown, as the sandbox
    mounts them in order (packagealert.sandbox.bwrap.build_cmd()): the host read-only,
    then empty tmpfs over /tmp, $HOME and ``sandbox.extra_tmpfs`` (``SANDBOX_TMPFS``),
    then the read-only binds that show parts of these again (the runtime installations,
    ``SANDBOX_HOME_VISIBLE``, and the file's own bind), then empty tmpfs over their log
    directories (``SANDBOX_POST_RO_TMPFS``), then the writable binds (the working
    directory, ``SANDBOX_WRITABLE``; outside a sandboxed command, this process's working
    directory as well), each bind with the directories leading to it, and last the
    plugins' hidden paths (``SANDBOX_HIDDEN``), which nothing shows. A bind at *rc*'s
    own name replaces the chain behind it.
    """
    from packagealert.parsers.process_args import (
        SANDBOX_ENV,
        SANDBOX_HIDDEN,
        SANDBOX_HOME_VISIBLE,
        SANDBOX_POST_RO_TMPFS,
        SANDBOX_TMPFS,
        SANDBOX_WRITABLE,
    )

    hidden = SANDBOX_HIDDEN.get()
    writable = SANDBOX_WRITABLE.get() if SANDBOX_ENV.get() is not None else (Path.cwd(), *SANDBOX_WRITABLE.get())
    read_only = (*SANDBOX_HOME_VISIBLE.get(), *([bound] if bound is not None else []))
    covered = (_SANDBOX_TMP, Path.home(), *SANDBOX_TMPFS.get())
    written = Path(os.path.abspath(rc))
    if bound is not None and bound == written:
        # Its bind replaces the chain behind it, but what is mounted after the bind still
        # applies: a log-directory tmpfs over it, unless a writable bind shows it again.
        if _passes_through(rc, hidden):
            return True
        return not any(written.is_relative_to(d) for d in writable) and \
            any(written.is_relative_to(d) and written != d for d in SANDBOX_POST_RO_TMPFS.get())
    try:
        traversed = _resolution_paths(rc)
    except (OSError, RuntimeError):
        return True

    def shown_by(binds: Collection[Path], path: Path) -> bool:  # bound in, or a directory leading to one
        return any(path.is_relative_to(d) or d.is_relative_to(path) for d in binds)

    def inside(dirs: Collection[Path], path: Path) -> bool:
        return any(path.is_relative_to(d) and path != d for d in dirs)

    # Last mount first: the hidden paths, the writable binds, the tmpfs over the read-only
    # binds' log directories, the read-only binds, then the tmpfs they are laid over.
    for path in traversed:
        if any(path.is_relative_to(d) for d in hidden):
            return True
        if shown_by(writable, path):
            continue
        if inside(SANDBOX_POST_RO_TMPFS.get(), path):
            return True
        if shown_by(read_only, path):
            continue
        if inside(covered, path):
            return True
    return False


def _npm_system_npmrcs(moved: Collection[str] = ()) -> list[Path]:
    """The global npmrc then npm's builtin one (_npm_system_npmrc_entries()), the
    lowest-precedence config files.

    Inside a sandboxed command (``SANDBOX_ENV``) one npm there cannot read is left
    out: under /tmp or linking there (the sandbox mounts a fresh /tmp), one that
    cannot be resolved, and an untrusted one that only a bind would make visible
    (it is not bound, see NodeLanguage.home_ro_paths()).
    """

    return [rc for rc, ok in _npm_system_npmrc_entries(moved) if _npm_sandbox_can_read(rc, ok)]


def _npm_sandbox_can_read(rc: Path, trusted: bool | None) -> bool:
    """Whether npm can read the global or builtin npmrc *rc* where the running command
    runs: anywhere outside a sandboxed command (``SANDBOX_ENV``); inside one, when the
    sandbox shows every path its resolution visits (_sandbox_breaks()), counting the bind
    a *trusted* one gets (None: the builtin npmrc, whose trust is looked up)."""
    from packagealert.parsers.process_args import SANDBOX_ENV

    if SANDBOX_ENV.get() is None:
        return True
    if trusted is None:
        trusted = _npm_builtin_trusted(rc)
    # Only a trusted file is bound in (NodeLanguage.home_ro_paths()).
    return not _sandbox_breaks(rc, _npm_home_bind(rc) if trusted else None)


def _npmrc_registries(rc: Path, env: Mapping[str, str] | None = None) -> tuple[str | None, dict[str, str]]:
    """The registry settings one .npmrc file makes, its ``${VAR}``s from *env*; an unreadable file makes none."""
    default: str | None = None
    scopes: dict[str, str] = {}
    for key, raw in _npmrc_registry_lines(rc):
        value = _expand_npmrc_env(raw, env)
        if not value:
            continue
        if key == "registry":
            default = value
        else:
            scopes[key[: -len(":registry")]] = value
    return default, scopes


def _npmrc_registry_refs(rc: Path) -> list[str]:
    """The environment variables *rc*'s registry lines name that may be passed into the sandbox.

    Only a line whose whole value is one variable (``registry=${CORP_REGISTRY}``)
    holding an http(s) URL with no credentials in it: such a variable is a
    registry address, like ``npm_config_registry``. A variable substituted into
    part of a URL (``https://${NPM_TOKEN}@host/``, a token in the path) may be a
    credential, and is never passed; nor are credential lines' variables.
    """
    import os

    found = []
    for _key, raw in _npmrc_registry_lines(rc):
        whole = _NPMRC_ENV_RE.fullmatch(raw)
        if whole is None:
            continue
        value = os.environ.get(whole.group(1))
        if value is not None and _credential_free_url(value):
            found.append(whole.group(1))
    return list(dict.fromkeys(found))


def _credential_free_url(value: str) -> bool:
    """Whether *value* is an http(s) URL with a host and no username or password in it."""
    try:
        url = urlsplit(value)
    except ValueError:
        return False
    return url.scheme in ("http", "https") and bool(url.hostname) and url.username is None and url.password is None


def _from_configured_registry(name: str, registries: tuple[str | None, dict[str, str]]) -> bool:
    """Whether *name* is fetched from the public registry by this configuration (the default when unset)."""
    default, scopes = registries
    scope = name.split("/", 1)[0] if name.startswith("@") else None
    url = scopes.get(scope) if scope in scopes else default
    return url is None or from_public_npm_registry(url)


def _pnpm_store_id(rel: Path) -> str | None:
    """The virtual-store entry of a manifest at .pnpm/<id>/node_modules/<name>/package.json
    (or @scope/<name>) relative to node_modules, or None for any other path."""
    parts = rel.parts
    if len(parts) not in (5, 6) or parts[0] != ".pnpm" or parts[2] != "node_modules" or parts[-1] != "package.json":
        return None
    if (len(parts) == 6) != parts[3].startswith("@") or any(x.startswith(".") for x in parts[1:-1]):
        return None
    return parts[1]


def _nested_manifest(rel: Path) -> bool:
    """Whether *rel* (relative to node_modules) is the manifest of a nested copy:
    <pkg>/node_modules/<pkg>/.../package.json, each <pkg> a name or @scope/name, as
    npm and yarn 1 nest a second version of a package beneath its dependent."""
    return _manifest_depth(rel) >= 2


def _manifest_depth(rel: Path) -> int:
    """How many packages deep the manifest at *rel* (relative to node_modules) is: 1 for
    <pkg>/package.json, 2 for <pkg>/node_modules/<pkg>/package.json, and so on, each
    <pkg> a name or @scope/name; 0 for any other path, such as a manifest a package
    ships in a subdirectory of its own (dom-helpers/activeElement/package.json)."""
    parts = rel.parts
    if not parts or parts[-1] != "package.json":
        return 0
    i, packages, segments = 0, 0, parts[:-1]
    while i < len(segments):
        width = 2 if segments[i].startswith("@") else 1
        name = segments[i:i + width]
        if len(name) != width or any(not x or x.startswith(".") or x == "node_modules" for x in name):
            return 0
        packages += 1
        i += width
        if i < len(segments):
            if segments[i] != "node_modules":
                return 0
            i += 1
            if i == len(segments):
                return 0
    return packages


def _nested_copy_dirs(node_modules: Path) -> dict[str, tuple[Path, ...]]:
    """The package directories under *node_modules* beyond node_modules/<name> and
    pnpm's store entries themselves, by the name their manifest declares: every nested
    one (a store package's bundled dependencies included), and any installed under an alias (`"x": "npm:ms@2.1.2"` installs ms as x). One whose
    manifest declares no name is indexed by the name it is installed under. Each is a
    real directory inside node_modules. The index is cached per install (see
    _nested_index_key())."""
    return _nested_index(str(node_modules), _nested_index_key(node_modules))


def _nested_index_key(node_modules: Path) -> tuple:
    """What identifies one state of a node_modules tree for the index: its own mtime
    and that of the hidden lock npm (`.package-lock.json`) or yarn 1 (`.yarn-integrity`)
    rewrites on every install that changes the tree (pnpm: its `.modules.yaml` and its
    store, which gains an entry per new package), plus a minute, so a change no
    install recorded is picked up within one."""
    stamps = []
    for path in (node_modules, node_modules / ".package-lock.json", node_modules / ".yarn-integrity",
                 node_modules / ".modules.yaml", node_modules / ".pnpm"):
        try:
            stamps.append(path.stat().st_mtime_ns)
        except OSError:
            stamps.append(None)
    return (*stamps, int(time.monotonic() // 60))


def _package_entries(directory: str) -> list[tuple[str, str]]:
    """(installed name, path) of each package directory directly in a node_modules,
    scoped ones included. Symlinks (workspace and link: dependencies, pnpm's links
    into its store) and dot entries are not packages installed there."""
    out: list[tuple[str, str]] = []
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return out
    for entry in entries:
        if entry.name.startswith(".") or not entry.is_dir(follow_symlinks=False):
            continue
        if not entry.name.startswith("@"):
            out.append((entry.name, entry.path))
            continue
        try:
            scoped = list(os.scandir(entry.path))
        except OSError:
            continue
        out += [(f"{entry.name}/{s.name}", s.path) for s in scoped
                if not s.name.startswith(".") and s.is_dir(follow_symlinks=False)]
    return out


@functools.lru_cache(maxsize=8)
def _nested_index(node_modules: str, _key: tuple) -> dict[str, tuple[Path, ...]]:
    found: dict[str, list[Path]] = {}

    def add(name: str, path: str, nested: bool) -> None:
        declared = _manifest_field(Path(path), "name") or name
        if nested or declared != name:
            found.setdefault(declared, []).append(Path(path))

    pending = []
    for name, path in _package_entries(node_modules):
        add(name, path, nested=False)
        pending.append(path)
    # A pnpm store package itself is resolved by _pnpm_store_dirs(); what it bundles is
    # nested inside it.
    store = os.path.join(node_modules, ".pnpm")
    if os.path.isdir(store) and not os.path.islink(store):
        try:
            entries = [e.path for e in os.scandir(store) if not e.name.startswith(".")
                       and e.name != "node_modules" and e.is_dir(follow_symlinks=False)]
        except OSError:
            entries = []
        for entry in entries:
            sub = os.path.join(entry, "node_modules")
            if not os.path.islink(sub) and os.path.isdir(sub):
                pending += [path for _name, path in _package_entries(sub)]
    while pending:
        sub = os.path.join(pending.pop(), "node_modules")
        if os.path.islink(sub) or not os.path.isdir(sub):
            continue
        for name, path in _package_entries(sub):
            add(name, path, nested=True)
            pending.append(path)
    return {name: tuple(dirs) for name, dirs in found.items()}


def _pnpm_store_id_source(store_id: str, name: str) -> bool | None:
    """Whether a virtual-store entry holds a registry version (True), another source
    (False), or cannot say (None). pnpm names an entry `<name>@<version>[_<peers>]`
    with `/` in a scoped name escaped as `+`, while a file:, link:, git or tarball
    source puts that source there (`localpkg@file+..`). A shortened entry is read
    without its hash; if pnpm cut it before any of the source survived (before the
    `@` after the name, or right after it), the source is unknown."""
    hashed = _PNPM_HASHED_ID.fullmatch(store_id)
    kept = hashed.group(1) if hashed else store_id
    prefix = name.replace("/", "+") + "@"
    if not kept.startswith(prefix) or len(kept) == len(prefix):
        return None
    return kept[len(prefix):][:1].isdigit()


def _read_manifest(path: Path) -> dict | None:
    """The JSON object in the manifest at *path*, or None. Only a regular file is read,
    never through a symlink: an install can leave anything at that path, and a FIFO
    there would block the read forever."""
    return _read_json_regular(path, follow_symlinks=False)


def _read_json_regular(path: Path, *, follow_symlinks: bool) -> dict | None:
    """The JSON object in the regular file at *path*, or None (see _read_regular())."""
    raw = _read_regular(path, follow_symlinks=follow_symlinks)
    try:
        data = json.loads(raw) if raw is not None else None
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _read_regular(path: Path, *, follow_symlinks: bool) -> bytes | None:
    """The contents of the regular file at *path*, or None (see packagealert.safe_read)."""
    try:
        return safe_read.read_bytes(path, follow_symlinks=follow_symlinks)
    except OSError:
        return None


def _manifest_field(package_dir: Path, key: str) -> str | None:
    """A non-empty string field of the manifest in *package_dir*, or None."""
    value = (_read_manifest(package_dir / "package.json") or {}).get(key)
    return value if isinstance(value, str) and value else None  # "" is no value


def _manifest_version(package_dir: Path) -> str | None:
    return _manifest_field(package_dir, "version")


# A virtual-store id pnpm shortened: what it kept, then `_` and a 32-hex hash.
_PNPM_HASHED_ID = re.compile(r"(.*)_[0-9a-f]{32}\Z")


@functools.lru_cache(maxsize=8)
def _pnpm_store_entries(store: str, mtime_ns: int) -> tuple[str, ...]:
    """The virtual store's entry names, listed once per scan (keyed on the store's
    mtime, which changes whenever an entry is added or removed)."""
    try:
        return tuple(sorted(os.listdir(store)))
    except OSError:
        return ()


def _pnpm_store_dirs(store: Path, node_modules: Path, name: str, version: str | None) -> list[Path]:
    """The package directories of *name* at *version* in pnpm's virtual store, each
    resolved and inside node_modules.

    pnpm names an entry after the package (`<name>@<version>`, `/` escaped as `+`).
    A long one it cuts and suffixes with a hash (depPathToFilename():
    `<filename cut short>_<32 hex>`), and the cut can fall inside the name. So an
    entry is resolved only when it starts with the escaped name, or is hashed and its
    cut prefix starts the escaped name."""
    found: list[Path] = []
    try:
        mtime_ns = store.stat().st_mtime_ns
    except OSError:
        return []
    escaped = name.replace("/", "+")
    for entry_name in _pnpm_store_entries(str(store), mtime_ns):
        if not entry_name.startswith(escaped):
            hashed = _PNPM_HASHED_ID.fullmatch(entry_name)
            if hashed is None or not hashed.group(1) or not escaped.startswith(hashed.group(1)):
                continue
        entry = store / entry_name
        try:
            package_dir = (entry / "node_modules" / name).resolve()
            if not package_dir.is_relative_to(node_modules) or not package_dir.is_dir():
                continue
        except (OSError, RuntimeError):  # RuntimeError: a symlink loop on Python 3.12
            continue
        if _manifest_version(package_dir) == version and package_dir not in found:
            found.append(package_dir)
    return found


def _non_registry_version(version: object) -> bool:
    """Whether a locked version names a non-registry source (a file, link, git repository or URL)."""
    return isinstance(version, str) and (
        version.startswith(("file:", "link:", "git", "github:", "http:", "https:")) or "://" in version)


def _yarn_block_non_registry(block: str) -> bool:
    """Whether a yarn.lock block's selectors name a non-registry source (``x@file:../x``, ``x@github:o/r``).

    A local or git dependency records its source only in the selector line,
    not in a ``resolved`` field.
    """
    header = block.lstrip().split("\n", 1)[0].rstrip().rstrip(":")
    for selector in header.split(","):
        selector = selector.strip().strip('"')
        at = selector.find("@", 1)          # past a scope's leading @
        if npm_spec_non_registry(selector[at + 1:] if at > 0 else ""):
            return True
    return False


def _npm_alias_target(raw: str) -> str:
    """The package an ``x@npm:y@1`` argument installs (``y@1``); any other argument unchanged."""
    at = raw.find("@", 1)
    return raw[at + len("@npm:"):] if at > 0 and raw[at + 1:].startswith("npm:") else raw


def _npm_explicit_spec_non_registry(raw: str) -> bool:
    """Whether a package argument (``name@spec``, a bare spec or a path) names a non-registry source."""
    if raw.startswith((".", "/", "~")) or raw.endswith((".tgz", ".tar.gz", ".tar")):
        return True
    at = raw.find("@", 1)                # past a scope's leading @
    spec = raw[at + 1:] if at > 0 else ""
    return npm_spec_non_registry(spec) or (at <= 0 and npm_spec_non_registry(raw))


def npm_spec_non_registry(spec: object) -> bool:
    """Whether a declared dependency spec names a non-registry source.

    A file, link, git repository, URL or ``user/repo`` shorthand is; a range,
    version, tag or ``npm:`` alias of a registry package is not, whichever
    registry serves it.
    """
    if not isinstance(spec, str) or spec.startswith("npm:"):
        return False
    return _non_registry_version(spec) or spec.startswith(("github:", "gitlab:", "bitbucket:", "gist:")) or (
        "/" in spec and not spec.startswith("@"))


def _lock_entry_public(name: str, resolved: object, registries: tuple[str | None, dict[str, str]]) -> bool:
    """Provenance of a lock entry: its own resolved URL when it records one, else the configured registry."""
    if isinstance(resolved, str) and resolved:
        return from_public_npm_registry(resolved)
    return _from_configured_registry(name, registries)


def npm_registries(root: Path, *, project: bool = True, command_line: Mapping[str, str] | None = None,
                   npm: bool = True) -> tuple[str | None, dict[str, str]]:
    """The registries npm (or with *npm* false, pnpm or yarn) uses for a project at *root*
    (see ``_npm_registries``)."""
    return _npm_registries(root, project=project, command_line=command_line, npm=npm)


def package_lock_entry_public(key: str, info: dict, registries: tuple[str | None, dict[str, str]]) -> bool:
    """Whether a package-lock.json ``packages`` entry comes from the public registry.

    A link, a local directory (a workspace member or file: target, whose key
    is not under node_modules/) or a non-registry version is local; otherwise
    the entry's resolved URL decides, else the configured registry
    (*registries*, from ``npm_registries()``).
    """
    if info.get("link") or "node_modules/" not in key or _non_registry_version(info.get("version")):
        return False
    name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
    return _lock_entry_public(name, info.get("resolved"), registries)


def package_lock_provenance(packages: dict, registries: tuple[str | None, dict[str, str]]) -> dict[str, bool]:
    """Whether each entry of a package-lock.json ``packages`` map comes from the public registry, by path.

    Each entry is judged by ``package_lock_entry_public()``, and the copy a
    dependent declares from a file, git or URL (``npm_spec_non_registry()``)
    is never public: its resolved URL can look exactly like a registry
    tarball. That copy is found by npm's nested lookup, so a registry copy of
    the same name elsewhere in the tree is unaffected. A bundled entry
    (``inBundle``) shipped in its containing package's tarball: with no resolved
    URL of its own, the configured registry says nothing about it, so it takes that
    package's verdict (a link, a non-registry version or declaration still makes it
    local); with one, it is public only if both are.
    """
    from packagealert.languages.node_fix.npm_lock import resolve

    lock = {"packages": packages}
    declared: set[str] = set()
    for path, info in packages.items():
        if not isinstance(path, str) or not isinstance(info, dict):
            continue
        for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            deps = info.get(section)
            if not isinstance(deps, dict):
                continue
            for dep, spec in deps.items():
                if isinstance(dep, str) and npm_spec_non_registry(spec) and (found := resolve(lock, path, dep)):
                    declared.add(found)
    public = {path: path not in declared and package_lock_entry_public(path, info, registries)
              for path, info in packages.items() if path and isinstance(path, str) and isinstance(info, dict)}
    # Shallowest first, so each bundled entry's container already has its final verdict
    # and a non-public bundle carries over to what it bundles in turn.
    bundled = sorted((path for path, info in packages.items() if path in public and info.get("inBundle") is True),
                     key=lambda path: path.count("/node_modules/"))
    for path in bundled:
        container = path.rsplit("/node_modules/", 1)[0]
        if container not in public:
            continue
        info = packages[path]
        resolved = info.get("resolved")
        if isinstance(resolved, str) and resolved:
            public[path] = public[path] and public[container]
        else:
            local = path in declared or bool(info.get("link")) or _non_registry_version(info.get("version"))
            public[path] = not local and public[container]
    return public


def _installed_provenance(node_modules: Path) -> tuple[dict[str, bool], tuple[str | None, dict[str, str]]]:
    """(lock path -> from the public registry, the configured registries) for packages just installed.

    Read from the lock npm wrote for *node_modules*: its hidden
    ``node_modules/.package-lock.json`` (npm 7+), else the project's
    package-lock.json, judged as ``package_lock_provenance()`` judges any lock.
    The hidden lock has no root entry, so the root's declarations are taken
    from the project lock or package.json. A package with no entry follows the
    configured registries, npm's own config files included only when an npm lock
    shows npm wrote the tree (_npm_wrote()).
    """
    project = node_modules.parent
    registries = npm_registries(project, npm=_npm_wrote(node_modules))
    hidden, full = (_lock_packages(node_modules / ".package-lock.json"),
                    _lock_packages(project / "package-lock.json"))
    packages = hidden if hidden is not None else full
    if packages is None:
        return {}, registries
    if "" not in packages:
        # npm's hidden lock has no root entry, and the root's declarations are what mark a
        # direct URL, git or file dependency: they come from the project lock the same
        # install wrote, else package.json.
        root = full.get("") if full is not None else None
        if not isinstance(root, dict):
            root = _read_json_object(project / "package.json")
        packages = {"": root, **packages} if isinstance(root, dict) else packages
    return package_lock_provenance(packages, registries), registries


# What pnpm and yarn leave in a node_modules they wrote.
_OTHER_MANAGER_MARKERS = (".modules.yaml", ".yarn-integrity", ".yarn-state.yml")


def _npm_wrote(node_modules: Path) -> bool:
    """Whether npm wrote *node_modules*, so npm's global and builtin npmrc apply (pnpm and
    yarn read neither): the running command's manager when it is known; else not when
    pnpm's or yarn's state file is there (a project lock npm left behind proves nothing
    then), else when it has npm's hidden lock or its project an npm lock."""
    from packagealert.parsers.process_args import COMMAND_ARGV

    argv = COMMAND_ARGV.get()
    if argv:
        first, *rest = argv
        tool = _runtime_name(rest[0]) if rest and _runtime_name(first) in ("node", "nodejs") else _runtime_name(first)
        if tool in ("yarn", "pnpm", "pn"):
            return False
        if tool == "npm":
            return True
    if any((node_modules / marker).exists() for marker in _OTHER_MANAGER_MARKERS):
        return False
    return (node_modules / ".package-lock.json").is_file() or (node_modules.parent / "package-lock.json").is_file()


def _copy_provenance(node_modules: Path) -> dict[str, bool]:
    """_installed_provenance()'s lock path -> from the public registry, cached while the
    locks, package.json and the configured registries are unchanged: it is consulted
    once per copy scored, and a large tree's lock is slow to parse."""
    project = node_modules.parent
    default, scopes = npm_registries(project, npm=_npm_wrote(node_modules))
    stamps = []
    for path in (node_modules / ".package-lock.json", project / "package-lock.json", project / "package.json"):
        try:
            stamps.append(path.stat().st_mtime_ns)
        except OSError:
            stamps.append(None)
    return _cached_copy_provenance(str(node_modules), (*stamps, default, tuple(sorted(scopes.items()))))


@functools.lru_cache(maxsize=8)
def _cached_copy_provenance(node_modules: str, _key: tuple) -> dict[str, bool]:
    return _installed_provenance(Path(node_modules))[0]


def _lock_packages(lock: Path) -> dict | None:
    """A lock file's ``packages`` map, or None when it cannot be read."""
    data = _read_json_object(lock)
    packages = data.get("packages") if data is not None else None
    return packages if isinstance(packages, dict) else None


def _read_json_object(path: Path) -> dict | None:
    # A lock file may be a symlink (a monorepo's shared lock); it must still be a
    # regular file, since a FIFO in its place would block the read forever.
    return _read_json_regular(path, follow_symlinks=True)


class NodeLanguage:
    """Language module for Node.js / npm / yarn / pnpm."""

    name: str = "node"
    # Not annotated ClassVar: LanguageBase declares these as read-only
    # properties (to admit both class-level and per-instance implementers -
    # see base.py), and pyright only accepts a plain class attribute against
    # a property, not one explicitly typed ClassVar. Safe to share across
    # calls regardless — there is exactly one NodeLanguage instance per
    # process and nothing ever mutates the list in place.
    ecosystems = ["npm"]  # noqa: RUF012
    process_names = ["npm", "yarn", "pnpm", "pn", "node", "nodejs"]  # noqa: RUF012
    contract_version: int = CURRENT_CONTRACT_VERSION
    # resolve_package_dir() can return several copies of one name and version (pnpm's
    # store: peer contexts, a file: tarball beside a registry copy; npm and yarn 1:
    # the same version nested beneath several dependents). Each is its own
    # package, so each is risk-scored on its own rather than their signals summed.
    resolve_package_dir_returns_copies: bool = True
    author: str = "builtin"
    repository: str = "builtin"

    # ------------------------------------------------------------------
    # parse_process_install
    # ------------------------------------------------------------------

    def parse_package_spec(self, raw: str) -> tuple[str, str | None]:
        from packagealert.parsers.process_args import _parse_npm_spec
        return _parse_npm_spec(raw)

    def serialise_package_spec(self, name: str, version: str | None) -> str:
        return f"{name}@{version}" if version else name

    def parse_process_install(self, args: list[str]) -> ProcessInstall | None:
        from packagealert.parsers.process_args import (
            parse_npm_args,
            parse_pnpm_args,
            parse_yarn_args,
        )

        result = parse_npm_args(args) or parse_yarn_args(args) or parse_pnpm_args(args)
        if result is None:
            return None
        specs: list[PackageSpec] = []
        for raw in result.packages or []:
            # An alias (x@npm:y@1) installs the package it names; git, URL, file and
            # local-path specs are not the registry package of that name.
            raw = _npm_alias_target(raw)
            name, version = self.parse_package_spec(raw)
            if name:
                specs.append(PackageSpec(name=name.lower(), version=version, ecosystem="npm",
                                         from_public_registry=not _npm_explicit_spec_non_registry(raw)))

        _LOCKFILE_HINTS: dict[str, str] = {
            "npm": "package-lock.json",
            "yarn": "yarn.lock",
            "pnpm": "pnpm-lock.yaml",
        }
        return ProcessInstall(
            manager=result.manager,
            packages=specs,
            defer_to_lockfile=not result.global_install,
            lockfile_hint=_LOCKFILE_HINTS.get(result.manager),
            global_install=result.global_install,
            # Only True for the subcommand shapes parse_npm_args/
            # parse_yarn_args/parse_pnpm_args already classify as installing
            # the existing lock file in full (bare `npm install`/`ci`,
            # `npm update`/`audit fix`, bare `yarn`/`yarn install`/`dedupe`,
            # `pnpm install`/`dedupe`/`fetch`/`import`) — not for a removal,
            # even though a removal shares the same manager and empty
            # `packages`.
            is_lockfile_install=result.is_lockfile_install,
            should_gate=result.should_gate,
            # `npm --prefix`, `yarn --cwd`, `pnpm -C`: the directory whose
            # package.json and lock file the command actually uses.
            working_dir=result.working_dir,
            project_dir=result.project_dir,
            # pnpm's `--lockfile-dir`: the lock file lives apart from the project.
            lockfile_dir=result.lockfile_dir,
            # pnpm `deploy <dir>`: installs into that directory too.
            install_dirs=list(result.install_dirs),
            # npm's `--registry`/`--@scope:registry`: where the named packages come from.
            registries=result.registries,
            ambiguous_dirs=result.ambiguous_dirs,
        )

    # ------------------------------------------------------------------
    # parse_lockfile
    # ------------------------------------------------------------------

    def parse_lockfile(self, path: Path) -> list[PackageSpec]:
        if path.name == "package-lock.json":
            return self._parse_package_lock(path)
        if path.name == "yarn.lock":
            return self._parse_yarn_lock(path)
        if path.name == "pnpm-lock.yaml":
            return self._parse_pnpm_lock(path)
        return []

    def _parse_package_lock(self, path: Path) -> list[PackageSpec]:
        registries = _npm_registries(path.parent)
        try:
            data = json.loads(safe_read.read_text(path))
            result = []
            # v2/v3 format uses "packages"
            if "packages" in data:
                provenance = package_lock_provenance(data["packages"], registries)
                for key, info in data["packages"].items():
                    if not key:  # root entry
                        continue
                    name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
                    public = provenance.get(key, False)
                    result.append(PackageSpec(name=name, version=info.get("version"), ecosystem="npm",
                                              is_dev=bool(info.get("dev")), from_public_registry=public))
            elif "dependencies" in data:
                # v1 format — prefer per-entry "dev" flag; fall back to root devDependencies list.
                # A package present in both prod and dev contexts is conservative: prod (False).
                dev_names = set(data.get("devDependencies", {}).keys())
                for name, info in data["dependencies"].items():
                    if "dev" in info:
                        is_dev = bool(info["dev"])
                    else:
                        is_dev = name in dev_names
                    result.append(PackageSpec(name=name, version=info.get("version"), ecosystem="npm", is_dev=is_dev,
                                              from_public_registry=not _non_registry_version(info.get("version"))
                                              and _lock_entry_public(name, info.get("resolved"), registries)))
            return result
        except Exception:  # noqa: BLE001 — malformed lockfile, best-effort parse
            log.debug("Failed to parse package-lock.json at %s", path)
            return []

    def _parse_yarn_lock(self, path: Path) -> list[PackageSpec]:
        registries = _npm_registries(path.parent, npm=False)
        # yarn.lock custom format: header line(s) of comma-separated selectors
        # like `name@range:` or `"@scope/name@range":`, followed by indented fields.
        # Each block resolves to one version; we extract the name from the first selector.
        # Matches both plain names (lodash) and scoped names (@babel/core).
        _HEADER_RE = re.compile(r'^"?(@?[^@"\s][^@"]*?)@', re.MULTILINE)
        _VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)
        # Matches dependency entries within a block's `dependencies:` section:
        #   lodash "^4.17.0"  or  "@babel/core" "^7.0.0"
        _DEP_ENTRY_RE = re.compile(r'^\s+"?(@?[^@"\s][^@"]*?)"?\s+"([^"]+)"')
        try:
            text = safe_read.read_text(path)
        except Exception:  # noqa: BLE001 — unreadable lockfile, best-effort parse
            log.debug("Failed to read yarn.lock at %s", path)
            return []

        # Load package.json for seed classification (name → version range).
        prod_direct: dict[str, str] = {}
        dev_direct: dict[str, str] = {}
        pkg_json_available = False
        pkg_json = path.parent / "package.json"
        try:
            pkg_data = json.loads(safe_read.read_text(pkg_json))
            prod_direct = dict(pkg_data.get("dependencies", {}))
            dev_direct = dict(pkg_data.get("devDependencies", {}))
            pkg_json_available = True
        except Exception:
            log.debug("Failed to read package.json at %s for seed classification", pkg_json, exc_info=True)

        # First pass: parse all blocks to collect resolved versions and adjacency.
        # Block header selectors (name@range) are the keys by which parent blocks
        # reference children in their dependencies: section.
        # adjacency: maps (name, range) → (resolved_name, resolved_version)
        # block_deps: maps resolved (name, version) → list of (dep_name, dep_range)
        resolved_map: dict[tuple[str, str], tuple[str, str]] = {}  # (name, range) → (name, version)
        block_deps: dict[tuple[str, str], list[tuple[str, str]]] = {}  # (name, version) → [(dep_name, dep_range)]

        blocks = re.split(r"\n\n+", text)
        for block in blocks:
            stripped = block.lstrip()
            header = _HEADER_RE.match(stripped)
            version_match = _VERSION_RE.search(block)
            if not header or not version_match:
                continue
            resolved_version = version_match.group(1)

            # Extract all selectors from the header line (before the colon).
            header_line = stripped.split("\n", 1)[0].rstrip(":")
            selectors = [s.strip().strip('"') for s in header_line.split(",")]
            resolved_name = _HEADER_RE.match(selectors[0].lstrip('"') if selectors else "")
            if not resolved_name:
                continue
            name = resolved_name.group(1)

            for sel in selectors:
                sel = sel.strip().strip('"')
                sel_match = _HEADER_RE.match(sel)
                if sel_match:
                    sel_name = sel_match.group(1)
                    # range is everything after "name@"
                    sel_range = sel[len(sel_match.group(0)):]
                    resolved_map[(sel_name, sel_range)] = (name, resolved_version)

            # Parse dependencies: section within this block.
            deps: list[tuple[str, str]] = []
            in_deps = False
            for line in block.split("\n"):
                if line.strip() == "dependencies:":
                    in_deps = True
                    continue
                if in_deps:
                    if line and not line[0].isspace():
                        break  # back to block header level
                    m = _DEP_ENTRY_RE.match(line)
                    if m:
                        deps.append((m.group(1), m.group(2)))
            block_deps[(name, resolved_version)] = deps

        if not pkg_json_available:
            # Without package.json seeds we can't classify anything
            result: list[PackageSpec] = []
            for block in blocks:
                stripped = block.lstrip()
                header = _HEADER_RE.match(stripped)
                version_match = _VERSION_RE.search(block)
                if header and version_match:
                    name = header.group(1).lstrip('"')
                    resolved = _YARN_RESOLVED_RE.search(block)
                    result.append(PackageSpec(name=name, version=version_match.group(1), ecosystem="npm", is_dev=None,
                                              from_public_registry=not _yarn_block_non_registry(block)
                                              and _lock_entry_public(
                                                  name, resolved.group(1) if resolved else None, registries)))
            return result

        # BFS reachability from prod and dev seeds.
        def _reachable(seed_deps: dict[str, str]) -> set[tuple[str, str]]:
            visited: set[tuple[str, str]] = set()
            # Use (name, range) → resolved to pin each seed to the exact lockfile entry.
            queue: list[tuple[str, str]] = []
            for seed_name, seed_range in seed_deps.items():
                node = resolved_map.get((seed_name, seed_range))
                if node:
                    queue.append(node)
            while queue:
                node = queue.pop()
                if node in visited:
                    continue
                visited.add(node)
                for dep_name, dep_range in block_deps.get(node, []):
                    child = resolved_map.get((dep_name, dep_range))
                    if child and child not in visited:
                        queue.append(child)
            return visited

        prod_reachable = _reachable(prod_direct)
        dev_reachable = _reachable(dev_direct)

        result = []
        seen: set[tuple[str, str]] = set()
        for block in blocks:
            stripped = block.lstrip()
            header = _HEADER_RE.match(stripped)
            version_match = _VERSION_RE.search(block)
            if not header or not version_match:
                continue
            name = header.group(1).lstrip('"')
            version = version_match.group(1)
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            in_prod = key in prod_reachable
            in_dev = key in dev_reachable
            if in_prod:
                is_dev: bool | None = False
            elif in_dev:
                is_dev = True
            else:
                is_dev = None  # unreachable from either seed (workspace members, etc.)
            resolved = _YARN_RESOLVED_RE.search(block)
            result.append(PackageSpec(name=name, version=version, ecosystem="npm", is_dev=is_dev,
                                      from_public_registry=not _yarn_block_non_registry(block)
                                      and _lock_entry_public(
                                          name, resolved.group(1) if resolved else None, registries)))
        return result

    def _parse_pnpm_lock(self, path: Path) -> list[PackageSpec]:
        registries = _npm_registries(path.parent, npm=False)

        def public(name: str, version: str) -> bool:
            # pnpm-lock.yaml records no registry URL; a non-registry source shows in the version.
            if _non_registry_version(version):
                return False
            return _from_configured_registry(name, registries)

        # Parse pnpm-lock.yaml without PyYAML using line scanning.
        # pnpm v9+ lockfile keys:   `  name@version:` or `  '@scope/name@version':`
        # pnpm v6 lockfile keys:    `  /name@version:` or `  /@scope/name@1.2.3:`
        # We capture an optional leading '/' and strip it from the name.
        _PKG_LINE_RE = re.compile(
            r"^  '?/?(@?[^@'/\s][^@']*?)@([^':(]+)[^':]*'?\s*:$"
        )
        # Matches dependency entries in snapshots: section at 6-space indent:
        #   "      accepts: 1.3.8"  or  "      '@scope/pkg': 2.0.0"
        _SNAP_DEP_RE = re.compile(r"^      '?(@?[^@'/\s][^@']*?)'?\s*:\s+(\S+)")
        # Matches snapshot entry keys — like _PKG_LINE_RE but allows trailing content
        # after the colon (e.g. "accepts@1.3.8: {}" for entries with no sub-keys).
        _SNAP_KEY_RE = re.compile(
            r"^  '?/?(@?[^@'/\s][^@']*?)@([^':(]+)[^':]*'?\s*:"
        )
        try:
            text = safe_read.read_text(path)
        except Exception:  # noqa: BLE001 — unreadable lockfile, best-effort parse
            log.debug("Failed to read pnpm-lock.yaml at %s", path)
            return []
        lines = text.splitlines()

        # ------------------------------------------------------------------
        # Pass 1: parse importers['.'] to collect prod/dev seed (name, version)
        # pairs and whether dev detection is possible at all.
        # ------------------------------------------------------------------
        prod_seeds: dict[str, str] | None = None  # None = no importers: section found
        dev_seeds: dict[str, str] | None = None
        in_root_importer = False
        in_prod_deps = False
        in_dev_deps = False
        _current_dep_name: str | None = None
        _IMPORTER_RE = re.compile(r"^  '\.':\s*$|^  \.\:\s*$")
        for line in lines:
            if line == "importers:":
                prod_seeds = {}
                dev_seeds = {}
                in_root_importer = False
                continue
            if prod_seeds is None or dev_seeds is None:
                continue
            if _IMPORTER_RE.match(line):
                in_root_importer = True
                in_prod_deps = False
                in_dev_deps = False
                _current_dep_name = None
                continue
            if in_root_importer:
                if line and not line.startswith(" "):
                    in_root_importer = False
                    in_prod_deps = False
                    in_dev_deps = False
                    _current_dep_name = None
                elif line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
                    # Another importer key at 2-space indent — exit root importer scope.
                    in_root_importer = False
                    in_prod_deps = False
                    in_dev_deps = False
                    _current_dep_name = None
                elif line.strip() == "dependencies:":
                    in_prod_deps = True
                    in_dev_deps = False
                    _current_dep_name = None
                elif line.strip() == "devDependencies:":
                    in_dev_deps = True
                    in_prod_deps = False
                    _current_dep_name = None
                elif line.startswith("    ") and not line.startswith("      ") and line.rstrip().endswith(":"):
                    # Sibling section under importer (specifiers:, etc.)
                    in_prod_deps = False
                    in_dev_deps = False
                    _current_dep_name = None
                elif in_dev_deps or in_prod_deps:
                    if line.startswith("      ") and not line.startswith("        "):
                        # Dep name key, e.g. "      express:" or "      '@scope/pkg':"
                        _current_dep_name = line.strip().rstrip(":").strip("'\"")
                        if not _current_dep_name or _current_dep_name.startswith("-"):
                            _current_dep_name = None
                    elif line.startswith("        ") and _current_dep_name:
                        # 8-space indent: specifier/version sub-keys for this dep
                        stripped = line.strip()
                        if stripped.startswith("version:"):
                            resolved = stripped[len("version:"):].strip().split("(", 1)[0]
                            target = dev_seeds if in_dev_deps else prod_seeds
                            target[_current_dep_name] = resolved

        # ------------------------------------------------------------------
        # Pass 2: parse packages: section to collect the canonical package list.
        # ------------------------------------------------------------------
        packages: list[tuple[str, str]] = []  # (name, version) in declaration order
        in_packages = False
        for line in lines:
            if line == "packages:":
                in_packages = True
                continue
            if in_packages:
                if line and not line.startswith(" "):
                    in_packages = False
                    continue
                m = _PKG_LINE_RE.match(line)
                if m:
                    packages.append((m.group(1), m.group(2)))

        if dev_seeds is None or prod_seeds is None:
            # No importers: section — cannot classify anything.
            return [PackageSpec(name=n, version=v, ecosystem="npm", is_dev=None, from_public_registry=public(n, v))
                    for n, v in packages]

        # ------------------------------------------------------------------
        # Pass 3: parse snapshots: section to build adjacency map.
        # snapshots: contains per-package resolved dependency lists.
        # Format:
        #   express@4.18.2:
        #     dependencies:
        #       accepts: 1.3.8
        # Key is "name@version" (same as in packages:).
        # ------------------------------------------------------------------
        snap_deps: dict[tuple[str, str], list[tuple[str, str]]] = {}
        in_snapshots = False
        current_snap: tuple[str, str] | None = None
        in_snap_deps = False
        for line in lines:
            if line == "snapshots:":
                in_snapshots = True
                continue
            if not in_snapshots:
                continue
            if line and not line.startswith(" "):
                in_snapshots = False
                continue
            m = _SNAP_KEY_RE.match(line)
            if m:
                current_snap = (m.group(1), m.group(2))
                snap_deps[current_snap] = []
                in_snap_deps = False
                continue
            if current_snap is None:
                continue
            if line.strip() == "dependencies:":
                in_snap_deps = True
                continue
            if in_snap_deps:
                if line.startswith("    ") and not line.startswith("      "):
                    # Back to 4-space indent = sibling section (optionalDependencies:, etc.)
                    in_snap_deps = False
                dm = _SNAP_DEP_RE.match(line)
                if dm:
                    dep_ver = dm.group(2).split("(", 1)[0]  # strip peer suffix e.g. 1.0.0(react@18.2.0)
                    snap_deps[current_snap].append((dm.group(1), dep_ver))

        # ------------------------------------------------------------------
        # BFS reachability from prod and dev seeds.
        # Seeds are (name, resolved_version) pairs from importers['.'].
        # ------------------------------------------------------------------
        def _reachable(seed_deps: dict[str, str]) -> set[tuple[str, str]]:
            visited: set[tuple[str, str]] = set()
            queue: list[tuple[str, str]] = []
            for seed_name, seed_ver in seed_deps.items():
                node = (seed_name, seed_ver)
                if node in snap_deps:
                    queue.append(node)
            while queue:
                node = queue.pop()
                if node in visited:
                    continue
                visited.add(node)
                for dep_name, dep_version in snap_deps.get(node, []):
                    child = (dep_name, dep_version)
                    if child not in visited and child in snap_deps:
                        queue.append(child)
            return visited

        prod_reachable = _reachable(prod_seeds)
        dev_reachable = _reachable(dev_seeds)
        has_snapshots = bool(snap_deps)

        result: list[PackageSpec] = []
        for name, version in packages:
            key = (name, version)
            in_prod = key in prod_reachable
            in_dev = key in dev_reachable
            if not has_snapshots:
                # No snapshots: section — only direct root importer deps are classifiable.
                # Match by (name, version) so that when a name appears in both prod and dev
                # seeds at different versions, each version is classified correctly.
                # Packages not matching any seed are transitives or other-importer deps;
                # use None so --prod-only warns rather than silently treating them as prod.
                prod_ver = prod_seeds.get(name)
                dev_ver = dev_seeds.get(name)
                if prod_ver == version:
                    is_dev: bool | None = False
                elif dev_ver == version:
                    is_dev = True
                else:
                    is_dev = None
            elif in_prod:
                is_dev = False
            elif in_dev:
                is_dev = True
            else:
                is_dev = None  # unreachable from either seed (peer-only, etc.)
            result.append(PackageSpec(name=name, version=version, ecosystem="npm", is_dev=is_dev,
                                      from_public_registry=public(name, version)))
        return result

    # ------------------------------------------------------------------
    # inspect_package
    # ------------------------------------------------------------------

    def inspect_package(self, path: Path) -> PackageMetadata | None:
        """Inspect an npm tarball artifact. Returns None if unsupported."""
        from packagealert.parsers.npm import inspect_npm_tarball

        info = inspect_npm_tarball(path)
        if info is None:
            return None
        return PackageMetadata(name=info.name, version=info.version, ecosystem="npm")

    # ------------------------------------------------------------------
    # cache_paths
    # ------------------------------------------------------------------

    def cache_paths(self) -> list[Path]:
        # Watch only index-v5, not content-v2 (opaque hash blobs) or tmp.
        # index-v5 contains parseable metadata; content-v2 adds thousands of
        # dirs of zero classification value and exhausts inotify watch limits.
        return [Path.home() / ".npm" / "_cacache" / "index-v5"]

    # ------------------------------------------------------------------
    # classify_cache_file / cache_file_globs
    # ------------------------------------------------------------------

    def cache_file_globs(self) -> list[str]:
        # index-v5 entries sit at exactly two levels of two-hex-char bucket dirs.
        return ["[0-9a-f][0-9a-f]/[0-9a-f][0-9a-f]/*"]

    # key format: "make-fetch-happen:request-cache:https://registry/…/name/-/name-version.tgz"
    _INDEX_KEY_RE = re.compile(r"/(@[^/]+/[^/]+|[^/]+)/-/[^/]+-(\d[^/]*)\.tgz$")
    _HEX_BUCKET_RE = re.compile(r"^[0-9a-f]{2}$")

    # Tail buffer large enough for any realistic index-v5 last line (~200 B typical).
    _TAIL_BYTES = 4096

    def classify_cache_file(self, path: Path) -> PackageMetadata | None:
        # Cheap structural guard: index-v5 entries are plain files (not dirs)
        # nested exactly two hex-bucket levels deep.  Skip anything that doesn't
        # match before doing any I/O — this avoids reading pip/uv cache files,
        # site-packages files, or any other non-npm path the monitor may surface.
        if (path.is_dir()
                or path.suffix                # index-v5 entries have no extension
                or not self._HEX_BUCKET_RE.match(path.parent.name)
                or not self._HEX_BUCKET_RE.match(path.parent.parent.name)
                or self._HEX_BUCKET_RE.match(path.parent.parent.parent.name)):
            return None
        # index-v5 files contain newline-delimited records; the last line is the
        # current cache entry. Each record is "<sha>\t<json>" where the JSON has
        # a "key" field with the package URL. Only the last line is needed, so
        # tail-read to avoid loading the full file.
        try:
            with safe_read.open_regular(path) as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - self._TAIL_BYTES))
                tail = fh.read().decode("utf-8", errors="replace")
        except OSError:
            return None
        last_line = tail.rstrip("\n").rsplit("\n", 1)[-1]
        try:
            _, _, json_part = last_line.partition("\t")
            data = json.loads(json_part)
            key = data.get("key", "")
        except (ValueError, AttributeError):
            return None
        m = self._INDEX_KEY_RE.search(key)
        if not m:
            return None
        name, version = m.group(1), m.group(2)
        name = unquote(name)
        # After decoding, validate: scoped names must be @scope/pkg (exactly one
        # '/'), unscoped names must contain no '/'. A percent-encoded '/' in the
        # unscoped branch would otherwise produce an inconsistent name.
        if name.startswith("@"):
            if name.count("/") != 1:
                return None
        else:
            if "/" in name:
                return None
        return PackageMetadata(name=name, version=version, ecosystem="npm")

    # ------------------------------------------------------------------
    # heuristics
    # ------------------------------------------------------------------

    def heuristics(self) -> list[AbstractHeuristic]:
        return [_NpmHeuristic()]

    # ------------------------------------------------------------------
    # lockfile_patterns
    # ------------------------------------------------------------------

    def lockfile_patterns(self) -> list[str]:
        return ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]

    # ------------------------------------------------------------------
    # detect_installed_packages
    # ------------------------------------------------------------------

    def detect_installed_packages(self, root: Path) -> list[PackageMetadata]:
        """Every package installed under root/node_modules, once per name and version.

        The tree is walked rather than asked of `npm ls`, whose answer depends on
        whether it succeeds (`--depth=0` lists only direct dependencies): hoisted
        copies, those nested beneath their dependents (a/node_modules/<name>) and those
        in pnpm's store. Each is named as its manifest declares, so an alias is the
        package it installs. A name and version counts as from the public registry
        unless every copy is not, judged as the post-install collector judges a copy:
        by its lock entry, or a store entry's id, else the configured registries."""
        node_modules = root / "node_modules"
        if not node_modules.is_dir():
            return []
        by_path, registries = _installed_provenance(node_modules)
        # pnpm installed a store entry, and pnpm does not read npm's global or builtin npmrc.
        store_registries = npm_registries(root, npm=False)
        public: dict[tuple[str, str | None], bool] = {}

        def add(package_dir: str, lock_key: str | None, store_id: str | None, inherited: bool | None) -> bool | None:
            """Record one copy; its verdict (None when it is not a package)."""
            manifest = _read_manifest(Path(package_dir, "package.json")) or {}
            name, version = manifest.get("name"), manifest.get("version") or None
            if not isinstance(name, str) or not name or not (version is None or isinstance(version, str)):
                return None
            source = _pnpm_store_id_source(store_id, name) if store_id is not None else True
            if inherited is not None:
                copy_public = inherited  # bundled inside a store package: its source is the parent's
            elif source is False:
                copy_public = False  # file:, link:, git or a tarball URL, not the registry
            elif lock_key is not None and lock_key in by_path:
                copy_public = by_path[lock_key]
            else:
                copy_public = _from_configured_registry(name, registries if store_id is None else store_registries)
            public[(name, version)] = public.get((name, version), False) or copy_public
            return copy_public

        def children(package_dir: str) -> list[tuple[str, str]]:
            sub = os.path.join(package_dir, "node_modules")
            return [] if os.path.islink(sub) or not os.path.isdir(sub) else _package_entries(sub)

        # The tree: hoisted copies and those nested beneath their dependents, each with
        # its own lock entry.
        pending = [(path, "node_modules/" + name) for name, path in _package_entries(str(node_modules))]
        while pending:
            package_dir, lock_key = pending.pop()
            add(package_dir, lock_key, None, None)
            pending += [(path, f"{lock_key}/node_modules/{name}") for name, path in children(package_dir)]
        # pnpm's store: an entry's own package is the real directory beside its
        # dependencies' links, and any dependency it bundles is nested inside it.
        store = node_modules / ".pnpm"
        try:
            entries = [e for e in os.scandir(store) if not e.name.startswith(".") and e.name != "node_modules"
                       and e.is_dir(follow_symlinks=False)] if store.is_dir() and not store.is_symlink() else []
        except OSError:
            entries = []
        for entry in entries:
            bundled: list[tuple[str, bool | None]] = []
            for name, path in children(entry.path):
                verdict = add(path, None, entry.name, None)
                if verdict is None:
                    # No readable manifest: judge the owner by its store id and the name
                    # it is installed under, for what it bundles.
                    verdict = (False if _pnpm_store_id_source(entry.name, name) is False
                               else _from_configured_registry(name, store_registries))
                bundled += [(child, verdict) for _n, child in children(path)]
            while bundled:
                package_dir, inherited = bundled.pop()
                verdict = add(package_dir, None, None, inherited)
                bundled += [(child, inherited if verdict is None else verdict) for _n, child in children(package_dir)]
        return [PackageMetadata(name=name, version=version, ecosystem="npm", from_public_registry=is_public)
                for (name, version), is_public in public.items()]

    # ------------------------------------------------------------------
    # sandbox_paths
    # ------------------------------------------------------------------

    def sandbox_paths(self) -> SandboxPaths:
        home = Path.home()
        return SandboxPaths(
            read_only=[
                home / ".nvm",
                home / ".npmrc",
                home / ".config" / "npm",
            ],
            writable=[
                home / ".npm",
            ],
            hidden=[
                home / ".ssh",
                home / ".aws",
                home / ".gnupg",
            ],
        )

    # ------------------------------------------------------------------
    # resolve_sandbox_targets
    # ------------------------------------------------------------------

    def resolve_sandbox_targets(
        self,
        parsed: Any,
        cwd: Path,
    ) -> SandboxTargets:
        targets = SandboxTargets()
        # node_modules lives under cwd, already covered by the cwd bind
        targets.scan_targets.append(cwd / "node_modules")
        # pnpm `deploy <dir>` installs into <dir>/node_modules as well; as a scan
        # target it is also snapshotted, so --no-change and a failed post-install
        # check restore it.
        # The destination itself is snapshotted too: deploy copies project files
        # there, and `deploy --force` deletes what was there first.
        for d in getattr(parsed, "install_dirs", None) or []:
            if isinstance(d, str) and d:
                # Lexically, as pnpm's path.join() does: `missing/../out` is `out`.
                dest = Path(os.path.normpath(cwd / d))
                targets.scan_targets.append(dest / "node_modules")
                targets.snapshot_only_dirs.append(dest)
        npm_cache = Path.home() / ".npm"
        if npm_cache.exists():
            targets.write_dirs.append(npm_cache)
        return targets

    def sandbox_env(self) -> list[str]:
        return [
            "NPM_CONFIG_CACHE",
            "NODE_PATH", "NODE_ENV",
            "NVM_DIR", "NVM_BIN",
            # In any spelling npm accepts, as the provenance check reads them.
            *_npm_registry_env_names(),
        ]

    # ------------------------------------------------------------------
    # Optional sandbox/flag extension points (no npm-specific behaviour yet)
    # ------------------------------------------------------------------

    def available_flags(self) -> list[tuple[str, str]]:
        return []

    def prepare_sandbox_argv(self, argv: list[str], cwd: Path) -> list[str]:
        return argv

    def sandbox_extra_ro_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    def sandbox_extra_write_paths(self, argv: list[str], cwd: Path) -> list[Path]:
        return []

    def post_run_scan_targets(self, parsed: Any, cwd: Path) -> list[Path]:
        return []

    def pre_run_check(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str] = frozenset(),
    ) -> PreRunResult:
        return PreRunResult(ok=True)

    def configure_sandbox(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
        home_ro: list[Path],
        sandbox_env: dict[str, str],
    ) -> None:
        pass

    def configure_sandbox_writable(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
    ) -> list[tuple[Path, Path]]:
        return []

    def configure_sandbox_writable_warning(
        self,
        parsed: Any | None,
        cwd: Path,
        flags: frozenset[str],
        targets: SandboxTargets,
    ) -> str | None:
        return None

    def prepare_sandbox_env(
        self,
        parsed: Any,
        cwd: Path,
        env: dict[str, str],
    ) -> list[Path]:
        """Give npm absolute config-file locations.

        npm in the sandbox may run elsewhere than this process (a trial's
        scratch copy), so ``npm_config_userconfig``, ``npm_config_globalconfig``
        and ``npm_config_prefix`` are replaced by the paths they name here, as
        the provenance check read them. Variables a project's .npmrc refers to
        are not passed: that file is the repository's.
        """
        for key in _NPM_CONFIG_LOCATORS:
            resolved = _npm_env_path(key, env)
            for name in [n for n, v in env.items() if n.lower() == f"npm_config_{key}" and v]:
                env[name] = str(resolved)
        return []

    def explicit_package_public(self, raw: str, parsed: Any, project_dir: Path) -> bool:
        """Whether a package named on the command line (``@scope/x@^1``) comes from the public registry.

        A git, URL, file or local-path spec does not. Otherwise the registry
        npm would use decides: the command line's ``--registry`` and
        ``--@scope:registry`` (``parsed.registries``), then the environment,
        the project's .npmrc (*project_dir*; not for a global install, as
        npm itself ignores it then) and the user's.
        """
        raw = _npm_alias_target(raw)
        if _npm_explicit_spec_non_registry(raw):
            return False
        at = raw.find("@", 1)            # past a scope's leading @
        name = raw[:at] if at > 0 else raw
        # npm ignores the project's .npmrc in global mode.
        given = getattr(parsed, "registries", None) or {}
        given = {k: v for k, v in given.items() if isinstance(v, str)}
        return _from_configured_registry(name, npm_registries(
            project_dir, project=not getattr(parsed, "global_install", False), command_line=given,
            npm=getattr(parsed, "manager", "npm") == "npm"))

    def interpreter_shim_script(self, real: Path, pa: Path) -> str | None:
        return None

    # ------------------------------------------------------------------
    # shell_environment
    # ------------------------------------------------------------------

    def shell_environment(self, cwd: Path) -> ShellEnvironment:
        result = ShellEnvironment()
        nm_bin = cwd / "node_modules" / ".bin"
        if nm_bin.is_dir():
            result.path_prepends.append(str(nm_bin))
            result.notes.append("node_modules/.bin in PATH")
        if (cwd / "package.json").exists():
            result.scan_targets.append(cwd / "node_modules")
        npm_cache = Path.home() / ".npm"
        if npm_cache.exists():
            result.write_dirs.append(npm_cache)
        return result

    def detect_new_packages(
        self,
        new_paths: set[Path],
        walk_root: Path,
    ) -> list[PackageSpec]:
        results = []
        provenance: tuple[dict[str, bool], tuple[str | None, dict[str, str]]] | None = None
        store_registries: tuple[str | None, dict[str, str]] | None = None
        for p in new_paths:
            if p.name != "package.json":
                continue
            try:
                rel = p.relative_to(walk_root)
            except ValueError:
                continue
            # A package's own manifest: <pkg>/package.json or @scope/<pkg>/package.json,
            # and nested beneath its dependent as npm and yarn 1 nest a second version
            # (a/node_modules/b/package.json, scoped names included) — never one a package
            # ships in a subdirectory of its own (dom-helpers/activeElement/package.json).
            # pnpm's isolated layout keeps the package itself in its virtual store,
            # linked from node_modules: .pnpm/<id>/node_modules/<name>/package.json.
            store_id = _pnpm_store_id(rel)
            if store_id is None and not _manifest_depth(rel):
                continue
            if p.is_symlink():
                continue  # skip symlinks — could point outside the install target
            try:
                if not p.resolve(strict=True).is_relative_to(walk_root.resolve(strict=True)):
                    continue
            except (OSError, RuntimeError):
                continue
            try:
                data = _read_manifest(p)
                if data is None:
                    continue
                name = data.get("name")
                version = data.get("version") or None
                if name:
                    if provenance is None:
                        provenance = _installed_provenance(walk_root)
                    by_path, registries = provenance
                    key = "node_modules/" + "/".join(rel.parts[:-1])
                    source = _pnpm_store_id_source(store_id, name) if store_id is not None else True
                    if source is False:
                        public = False  # file:, link:, git or a tarball URL, not the registry
                    elif store_id is not None:  # pnpm's, which does not read npm's own config files
                        if store_registries is None:
                            store_registries = npm_registries(walk_root.parent, npm=False)
                        public = _from_configured_registry(name, store_registries)
                    else:
                        public = by_path[key] if key in by_path else _from_configured_registry(name, registries)
                    results.append(PackageSpec(name=name, version=version, ecosystem="npm",
                                               from_public_registry=public, source_unknown=source is None))
            except Exception:
                log.debug("Failed to read/parse %s", p, exc_info=True)
        return results

    def home_ro_paths(self) -> list[Path]:
        # The user's config wherever npm_config_userconfig moves it, and the global and
        # builtin npmrc when they live under $HOME (a prefix such as ~/.npm-global), all
        # of which npm in the sandbox reads; elsewhere they are visible already.
        # A file only (a setting naming a directory such as $HOME must not expose it). The
        # user's is bound wherever it is (/tmp is replaced too); the others at their own
        # name when that is under $HOME, else at their real one when that is (a /etc/npmrc
        # linking into $HOME).
        home = Path.home()
        user = [home / ".npmrc", _user_npmrc()]
        # Only trusted ones: a repository's own npm could name or link to any file.
        system = [rc for rc, ok in _npm_system_npmrc_entries() if ok]
        found: list[Path] = []
        for rc in dict.fromkeys([*user, *system]):
            try:
                real = rc.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if not real.is_file():
                continue
            bind = rc if rc in user else _npm_home_bind(rc)
            if rc not in user and _sandbox_breaks(rc, bind):
                continue  # npm in the sandbox cannot follow it, so it is not exposed either
            if bind is not None and bind not in found:
                found.append(bind)
        return found

    def top_packages_url(self) -> str | None:
        # ecosyste.ms ranks by actual download count with no keyword/text
        # filter. The npm registry's own search API (`-/v1/search`) was tried
        # first, but every query there is a text-relevance search with a
        # popularity *boost* — there is no way to ask it for "everything,
        # sorted by popularity" independent of a text match. Filtering on
        # `keywords:javascript` excluded any popular package that doesn't
        # self-tag that exact keyword: jsdom (29k+ dependents, actual download
        # rank ~442) tags itself dom/html/whatwg/w3c and never appeared in that
        # corpus at any page depth, so it could never be recognised as a
        # legitimate exact match nor serve as a typosquat target.
        return (
            "https://packages.ecosyste.ms/api/v1/registries/npmjs.org/package_names"
            f"?per_page={MAX_TOP_PACKAGES}&sort=downloads&page=1"
        )

    async def fetch_top_packages(self, client: httpx.AsyncClient, url: str) -> list[str] | None:
        resp = await client.get(url)
        resp.raise_for_status()
        names = resp.json()
        if not isinstance(names, list):
            return None
        # normalise_name, not the PEP-503-folding normalise_package_name: npm
        # does not collapse separators, so folding here would store
        # "socket-io" for the registry's "socket.io" and TyposquatDetector's
        # later per-ecosystem normalisation could never recover the dot.
        #
        # Sliced locally rather than trusting per_page in the URL: the contract
        # (LanguageBase.fetch_top_packages) requires every implementation to
        # cap the result itself, so an oversized or nonconforming response from
        # ecosyste.ms is never stored in full regardless of what the query asked for.
        packages = [self.normalise_name(n) for n in names if isinstance(n, str)][:MAX_TOP_PACKAGES]
        return packages if packages else None

    def top_packages_fallback(self) -> list[str]:
        return [
            "lodash", "express", "react", "react-dom", "axios", "moment", "chalk",
            "commander", "yargs", "webpack", "babel-core", "eslint", "typescript",
            "jest", "mocha", "nodemon", "dotenv", "cors", "body-parser", "mongoose",
            "sequelize", "socket.io", "passport", "jsonwebtoken", "bcrypt", "multer",
            "uuid", "debug", "async", "underscore", "bluebird", "request", "node-fetch",
            "cross-env", "concurrently", "prettier", "husky", "lint-staged", "pm2",
            "next", "nuxt", "vue", "angular", "svelte", "gatsby", "webpack-cli",
            "babel-loader", "css-loader", "style-loader", "mini-css-extract-plugin",
        ]

    def package_manager_names(self) -> list[str]:
        # pn is pnpm's short name, shipped from pnpm 11.
        return ["npm", "yarn", "pnpm", "pn"]

    def project_shim_names(self) -> list[str]:
        return self.package_manager_names()

    def interpreter_names(self) -> list[str]:
        return ["node", "nodejs"]

    def project_bin_dirs(self, root: Path) -> list[Path]:
        p = root / "node_modules" / ".bin"
        return [p] if p.is_dir() else []

    def publication_date_url(self, name: str, version: str) -> str | None:
        # The per-version endpoint (/name/version) does not include a publish
        # timestamp. The abbreviated metadata (install-v1 Accept header) also
        # omits it. The full package document is the only source for the `time`
        # dict, which maps version strings to ISO timestamps. Results are cached
        # in SQLite for 30 days so this large fetch is a one-time cost per version.
        # Scoped packages (@scope/pkg) must have the slash percent-encoded.
        encoded = quote(name, safe="@")
        return f"https://registry.npmjs.org/{encoded}"

    def publication_date_parse(self, data: object, version: str | None) -> float | None:
        """Look up the version in the package document's `time` dict."""
        if not isinstance(data, dict):
            return None
        version_time = data.get("time", {})
        if version and version in version_time:
            t = version_time[version]
            try:
                # npm emits Zulu ("...Z"), which is offset-aware: converting rather
                # than replacing keeps this correct if that ever changes.
                return parse_registry_timestamp(t).timestamp()
            except ValueError:
                pass
        return None

    def yank_status_url(self, name: str, version: str) -> str | None:
        """The package document: npm has no yank, but a maintainer can deprecate a single release."""
        return f"https://registry.npmjs.org/{quote(name, safe='@')}"

    def yank_status_parse(self, data: object, version: str | None) -> tuple[bool, str | None] | None:
        """(withdrawn, message) for *version*; None when the document does not list it.

        npm has no yank, and ``deprecated`` is used far more loosely: whole
        major lines are deprecated when they reach end of life ("eslint 8 is no
        longer supported"), and whole packages when they are abandoned. A
        deprecated release counts as withdrawn only when the newest release on
        its own major line (npm's caret rule; prereleases aside) is not
        deprecated, as with lodash 4.18.0 ("Bad release") beside 4.18.1.
        """
        from packagealert.languages.node_fix.npm_trial import _key, major_floor

        if not isinstance(data, dict) or not isinstance(data.get("versions"), dict) or version is None:
            return None
        versions = data["versions"]
        info = versions.get(version)
        if not isinstance(info, dict):
            return None
        message = info.get("deprecated")
        if not (isinstance(message, str) and message):
            return False, None
        def on_line(v: object, line: object) -> bool:
            try:
                return isinstance(v, str) and "-" not in v and isinstance(versions[v], dict) and major_floor(v) == line
            except ValueError:  # an unreadable version elsewhere in the document is skipped
                return False

        try:
            line = major_floor(version)
            newest = max((v for v in versions if on_line(v, line)), key=_key, default=version)
        except ValueError:
            return None
        if versions[newest].get("deprecated"):
            return False, None  # the whole line (or package) is end of life, not one withdrawn release
        return True, message

    def osv_ecosystem(self) -> str | None:
        return "npm"

    def normalise_name(self, name: str) -> str:
        """Lowercase only — this registry does not collapse separators."""
        return name.lower()

    def is_scratch_command(self, argv: list[str]) -> bool:
        """Whether *argv* is pa fix's npm trial, which the sandbox runs only in a scratch copy.

        Optional hook: see the comment beside fix_adapters() in base.py.
        """
        from packagealert.languages.node_fix.npm_trial import is_scratch_command

        return is_scratch_command(argv)

    def fix_adapters(self) -> list:
        """`pa fix` adapters for Node package managers (npm only so far).

        Optional hook: see the fix_adapters() comment in base.py. Imported here
        so loading the plugin does not load pa fix.
        """
        from packagealert.languages.node_fix.npm import NpmFixAdapter

        return [NpmFixAdapter()]

    def popularity_ecosystem(self) -> str | None:
        return "NPM"

    def resolve_package_dir(
        self,
        package_name: str,
        project_path: Path | None,
        site_packages_dir: Path | None,
        version: str | None = None,
    ) -> list[Path]:
        if project_path is None:
            return []
        # Validate: scoped packages have exactly one '/' (e.g. @scope/name);
        # unscoped packages have none. Reject anything else to prevent traversal.
        # Reject path separators and leading dots to prevent traversal.
        if package_name.startswith("@"):
            parts = package_name.split("/")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                return []
            if any(p.startswith(".") for p in parts):
                return []
            if any(c in parts[1] for c in "/:+\\"):
                return []
        else:
            if not package_name or package_name[0] == ".":
                return []
            if any(c in package_name for c in "/:+\\"):
                return []
        node_modules = (project_path / "node_modules").resolve()
        try:
            candidate: Path | None = (project_path / "node_modules" / package_name).resolve()
        except (OSError, RuntimeError):  # RuntimeError: a symlink loop on Python 3.12
            candidate = None
        if candidate is not None and not candidate.is_relative_to(node_modules):
            candidate = None  # e.g. a workspace link: not this install's copy
        top = candidate if candidate is not None and candidate.is_dir() else None
        if top is not None and _manifest_field(top, "name") not in (None, package_name):
            top = None  # an alias: another package installed under this name
        # pnpm's isolated layout links only a direct dependency from node_modules/<name>,
        # and its store can hold several copies of one version (peer contexts, a file:
        # tarball). npm and yarn 1 hoist one version to node_modules/<name> and nest any
        # other beneath its dependent (a/node_modules/<name>). Every contained copy at
        # *version* is scanned (with no version: each copy whose manifest has none), from
        # whichever layouts are present.
        store = node_modules / ".pnpm"
        copies = _pnpm_store_dirs(store, node_modules, package_name, version) if store.is_dir() else []
        for nested in _nested_copy_dirs(node_modules).get(package_name, ()):
            try:
                package_dir = nested.resolve()
            except (OSError, RuntimeError):  # RuntimeError: a symlink loop on Python 3.12
                continue
            if package_dir.is_relative_to(node_modules) and _manifest_version(package_dir) == version \
                    and package_dir not in copies:
                copies.append(package_dir)
        # The top-level copy: always for an unversioned package, else at *version*.
        if top is not None and (version is None or _manifest_version(top) == version) and top not in copies:
            copies.insert(0, top)
        if copies or store.is_dir():
            return copies
        # No copy at *version* (one that is a range rather than what was installed):
        # the top-level copy, as before.
        return [top] if top is not None else []

    def copy_from_public_registry(self, package_name: str, package_dir: Path) -> bool | None:
        """Whether a directory resolve_package_dir() returned is a registry copy: False
        for a pnpm store entry from a file:, link:, git or tarball source, None when its
        store id was shortened past the source, and True for a registry entry. Outside
        the store, a copy the lock npm wrote records (node_modules/a/node_modules/<name>)
        is judged by its lock entry, and one it does not by the configured registries;
        a directory outside any node_modules has the event's provenance."""
        parts = package_dir.parts
        if ".pnpm" not in parts:
            if "node_modules" not in parts:
                return True
            root = parts.index("node_modules")
            key = "/".join(parts[root:])
            recorded = _copy_provenance(Path(*parts[:root + 1])).get(key)
            if recorded is not None:
                return recorded
            # Not in the lock: the configured registries decide, as discovery judges it, with
            # npm's own config files only for a tree npm wrote.
            return _from_configured_registry(package_name, npm_registries(
                Path(*parts[:root]), npm=_npm_wrote(Path(*parts[:root + 1]))))
        i = len(parts) - 1 - parts[::-1].index(".pnpm")
        if i + 3 >= len(parts) or parts[i + 2] != "node_modules":
            return True
        # A dependency bundled inside a store package shipped in that package's tarball,
        # so it is judged by the entry's own package (.pnpm/<id>/node_modules/<pkg>/...).
        width = 2 if parts[i + 3].startswith("@") else 1
        owner = "/".join(parts[i + 3:i + 3 + width]) if len(parts) > i + 3 + width else package_name
        source = _pnpm_store_id_source(parts[i + 1], owner)
        if source is not True or i < 1 or parts[i - 1] != "node_modules":
            return source
        # A registry entry: public only if the project's configuration fetches that
        # package from the public registry (a scope can name a private one).
        return _from_configured_registry(owner, npm_registries(Path(*parts[:i - 1]), npm=False))

    def resolve_package_dir_manifest_warning(
        self,
        package_name: str,
        project_path: Path | None,
        site_packages_dir: Path | None,
        version: str | None = None,
    ) -> str | None:
        """node_modules/<name> is a direct, unambiguous path — resolve_package_dir
        above parses no manifest file to distrust, unlike PyPI's RECORD. Nothing
        here can be corrupted to force a shared-namespace-style misattribution."""
        return None

    def latest_version_url(self, name: str) -> str | None:
        encoded = quote(name, safe="@")
        return f"https://registry.npmjs.org/{encoded}/latest"

    def latest_version_parse(self, data: object, name: str) -> str | None:
        if not isinstance(data, dict):
            return None
        return data.get("version") or None

    # ------------------------------------------------------------------
    # snapshot
    # ------------------------------------------------------------------

    def snapshot(self, install_root: Path) -> Snapshot:
        """Snapshot all node_modules packages under install_root."""
        node_modules = install_root / "node_modules"
        data: dict[str, str] = {}
        if not node_modules.exists():
            return Snapshot(data=data)

        # Non-scoped packages
        for pkg_json in node_modules.glob("*/package.json"):
            pkg_dir = pkg_json.parent
            try:
                pkg_data = json.loads(safe_read.read_bytes(pkg_json))
                version = pkg_data.get("version") or ""
                data[str(pkg_dir)] = version
            except Exception:
                log.debug("Failed to read/parse %s", pkg_json, exc_info=True)
        # Scoped packages (@scope/package)
        for pkg_json in node_modules.glob("@*/*/package.json"):
            pkg_dir = pkg_json.parent
            try:
                pkg_data = json.loads(safe_read.read_bytes(pkg_json))
                version = pkg_data.get("version") or ""
                data[str(pkg_dir)] = version
            except Exception:
                log.debug("Failed to read/parse %s", pkg_json, exc_info=True)

        return Snapshot(data=data)

    # ------------------------------------------------------------------
    # detect_post_install
    # ------------------------------------------------------------------

    def detect_post_install(self, before: Snapshot, after: Snapshot) -> list[PackageSpec]:
        """Return PackageSpec objects for packages that appeared after before."""
        new_paths = after.data.keys() - before.data.keys()
        results: list[PackageSpec] = []
        for path_str in new_paths:
            pkg_json = Path(path_str) / "package.json"
            try:
                data = json.loads(safe_read.read_bytes(pkg_json))
                name = data.get("name", "")
                version = data.get("version") or None
                if name:
                    results.append(PackageSpec(name=name, version=version, ecosystem="npm"))
            except Exception:
                log.debug("Failed to read/parse %s", pkg_json, exc_info=True)
        return results
