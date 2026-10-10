from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from packagealert.managers import manager_registry_name

# Matches the leading PEP 508 distribution name (letters, digits, hyphens, underscores, dots).
_PIP_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")
# pip's options, GENERATED from pip's own parser objects (`takes_value()` on
# every option of `create_main_parser()` and `create_command("install")`) for
# each supported pip version, merged — no option takes a value in one version
# and not another. Hand-maintained sets missed global options (`--log-file`,
# `--keyring-provider`, `--use-feature`) and hidden aliases (`--source`,
# `--pypi-url`), which a differential test against pip's parser found; see
# CLAUDE.md for regenerating. Generated against: pip 24.0, 25.3, 26.1.2.
_PIP_VALUE_FLAGS = frozenset({
    "--abi", "--all-releases", "--build-constraint", "--cache-dir",
    "--cert", "--client-cert", "--config-settings", "--constraint",
    "--default-timeout", "--editable", "--exists-action",
    "--extra-index-url", "--find-links", "--global-option", "--group",
    "--implementation", "--index-url", "--keyring-provider", "--local-log",
    "--log", "--log-file", "--no-binary", "--only-binary", "--only-final",
    "--platform", "--prefix", "--progress-bar", "--proxy", "--pypi-url",
    "--python", "--python-version", "--report", "--requirement",
    "--requirements-from-script", "--resume-retries", "--retries", "--root",
    "--root-user-action", "--source", "--source-dir", "--source-directory",
    "--src", "--target", "--timeout", "--trusted-host",
    "--upgrade-strategy", "--uploaded-prior-to", "--use-deprecated",
    "--use-feature", "-C", "-c", "-e", "-f", "-i", "-r", "-t",
})
_PIP_GLOBAL_VALUE_FLAGS = frozenset({
    "--cache-dir", "--cert", "--client-cert", "--default-timeout",
    "--exists-action", "--keyring-provider", "--local-log", "--log",
    "--log-file", "--proxy", "--python", "--resume-retries", "--retries",
    "--timeout", "--trusted-host", "--use-deprecated", "--use-feature",
})
# Every long option per supported version, for abbreviation expansion
# (uniqueness depends on the version: `--requirem` is unique in pip 25.3 and
# ambiguous in 26.1). Same versions as above.
_PIP_GENERAL_LONG_OPTIONS_BY_VERSION: tuple[frozenset[str], ...] = (
    frozenset({
        "--cache-dir", "--cert", "--client-cert", "--debug",
        "--default-timeout", "--disable-pip-version-check",
        "--exists-action", "--help", "--isolated", "--keyring-provider",
        "--local-log", "--log", "--log-file", "--no-cache-dir",
        "--no-color", "--no-input", "--no-python-version-warning",
        "--proxy", "--python", "--quiet", "--require-venv",
        "--require-virtualenv", "--retries", "--timeout", "--trusted-host",
        "--use-deprecated", "--use-feature", "--verbose", "--version",
    }),
    frozenset({
        "--cache-dir", "--cert", "--client-cert", "--debug",
        "--default-timeout", "--disable-pip-version-check",
        "--exists-action", "--help", "--isolated", "--keyring-provider",
        "--local-log", "--log", "--log-file", "--no-cache-dir",
        "--no-color", "--no-input", "--no-python-version-warning",
        "--proxy", "--python", "--quiet", "--require-venv",
        "--require-virtualenv", "--resume-retries", "--retries",
        "--timeout", "--trusted-host", "--use-deprecated", "--use-feature",
        "--verbose", "--version",
    }),
    frozenset({
        "--cache-dir", "--cert", "--client-cert", "--debug",
        "--default-timeout", "--disable-pip-version-check",
        "--exists-action", "--help", "--isolated", "--keyring-provider",
        "--local-log", "--log", "--log-file", "--no-cache-dir",
        "--no-color", "--no-input", "--no-python-version-warning",
        "--proxy", "--python", "--quiet", "--require-venv",
        "--require-virtualenv", "--resume-retries", "--retries",
        "--timeout", "--trusted-host", "--use-deprecated", "--use-feature",
        "--verbose", "--version",
    }),
)
_PIP_INSTALL_LONG_OPTIONS_BY_VERSION: tuple[frozenset[str], ...] = (
    frozenset({
        "--abi", "--break-system-packages", "--cache-dir", "--cert",
        "--check-build-dependencies", "--client-cert", "--compile",
        "--config-settings", "--constraint", "--debug", "--default-timeout",
        "--disable-pip-version-check", "--dry-run", "--editable",
        "--exists-action", "--extra-index-url", "--find-links",
        "--force-reinstall", "--global-option", "--help",
        "--ignore-installed", "--ignore-requires-python",
        "--implementation", "--index-url", "--isolated",
        "--keyring-provider", "--local-log", "--log", "--log-file",
        "--no-binary", "--no-build-isolation", "--no-cache-dir",
        "--no-clean", "--no-color", "--no-compile", "--no-dependencies",
        "--no-deps", "--no-index", "--no-input",
        "--no-python-version-warning", "--no-use-pep517", "--no-user",
        "--no-warn-conflicts", "--no-warn-script-location", "--only-binary",
        "--platform", "--pre", "--prefer-binary", "--prefix",
        "--progress-bar", "--proxy", "--pypi-url", "--python",
        "--python-version", "--quiet", "--report", "--require-hashes",
        "--require-venv", "--require-virtualenv", "--requirement",
        "--retries", "--root", "--root-user-action", "--source",
        "--source-dir", "--source-directory", "--src", "--target",
        "--timeout", "--trusted-host", "--upgrade", "--upgrade-strategy",
        "--use-deprecated", "--use-feature", "--use-pep517", "--user",
        "--verbose", "--version",
    }),
    frozenset({
        "--abi", "--break-system-packages", "--build-constraint",
        "--cache-dir", "--cert", "--check-build-dependencies",
        "--client-cert", "--compile", "--config-settings", "--constraint",
        "--debug", "--default-timeout", "--disable-pip-version-check",
        "--dry-run", "--editable", "--exists-action", "--extra-index-url",
        "--find-links", "--force-reinstall", "--group", "--help",
        "--ignore-installed", "--ignore-requires-python",
        "--implementation", "--index-url", "--isolated",
        "--keyring-provider", "--local-log", "--log", "--log-file",
        "--no-binary", "--no-build-isolation", "--no-cache-dir",
        "--no-clean", "--no-color", "--no-compile", "--no-dependencies",
        "--no-deps", "--no-index", "--no-input",
        "--no-python-version-warning", "--no-user", "--no-warn-conflicts",
        "--no-warn-script-location", "--only-binary", "--platform", "--pre",
        "--prefer-binary", "--prefix", "--progress-bar", "--proxy",
        "--pypi-url", "--python", "--python-version", "--quiet", "--report",
        "--require-hashes", "--require-venv", "--require-virtualenv",
        "--requirement", "--resume-retries", "--retries", "--root",
        "--root-user-action", "--source", "--source-dir",
        "--source-directory", "--src", "--target", "--timeout",
        "--trusted-host", "--upgrade", "--upgrade-strategy",
        "--use-deprecated", "--use-feature", "--use-pep517", "--user",
        "--verbose", "--version",
    }),
    frozenset({
        "--abi", "--all-releases", "--break-system-packages",
        "--build-constraint", "--cache-dir", "--cert",
        "--check-build-dependencies", "--client-cert", "--compile",
        "--config-settings", "--constraint", "--debug", "--default-timeout",
        "--disable-pip-version-check", "--dry-run", "--editable",
        "--exists-action", "--extra-index-url", "--find-links",
        "--force-reinstall", "--group", "--help", "--ignore-installed",
        "--ignore-requires-python", "--implementation", "--index-url",
        "--isolated", "--keyring-provider", "--local-log", "--log",
        "--log-file", "--no-binary", "--no-build-isolation",
        "--no-cache-dir", "--no-clean", "--no-color", "--no-compile",
        "--no-dependencies", "--no-deps", "--no-index", "--no-input",
        "--no-python-version-warning", "--no-user", "--no-warn-conflicts",
        "--no-warn-script-location", "--only-binary", "--only-final",
        "--platform", "--pre", "--prefer-binary", "--prefix",
        "--progress-bar", "--proxy", "--pypi-url", "--python",
        "--python-version", "--quiet", "--report", "--require-hashes",
        "--require-venv", "--require-virtualenv", "--requirement",
        "--requirements-from-script", "--resume-retries", "--retries",
        "--root", "--root-user-action", "--source", "--source-dir",
        "--source-directory", "--src", "--target", "--timeout",
        "--trusted-host", "--upgrade", "--upgrade-strategy",
        "--uploaded-prior-to", "--use-deprecated", "--use-feature",
        "--use-pep517", "--user", "--verbose", "--version",
    }),
)
# Flags that consume the next argument as their value for `uv add` / `uv remove`.
# Audited against: uv 0.12.23 `uv add --help` / `uv remove --help`, plus the
# hidden names probed from uv's CLI source.
_UV_PROJECT_VALUE_FLAGS = frozenset({
    # Python selector
    "-p", "--python",
    # Dependency targeting (add/remove)
    "-r", "--requirements",
    "-m", "--marker",
    "--optional", "--group", "--extra",
    "--script", "--package",
    "--bounds",
    # VCS pinning (add only)
    "--tag", "--rev", "--branch",
    # Index / source resolution
    "--index", "--default-index", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links",
    "--index-strategy", "--keyring-provider",
    # Solver strategy
    "-c", "--constraints",
    "--resolution", "--prerelease", "--prerelease-package", "--fork-strategy",
    "--exclude-newer", "--exclude-newer-package",
    # Upgrade control
    "-P", "--upgrade-package", "--upgrade-group",
    # Install control
    "--no-install-package",
    "--reinstall-package",
    "--link-mode",
    # Build config
    "-C", "--config-setting", "--config-settings-package",
    "--no-build-isolation-package",
    "--no-build-package",
    "--no-binary-package",
    "--no-sources-package",
    # Cache
    "--cache-dir",
    "--refresh-package",
    # Global flags that take values
    "--allow-insecure-host",
    "--directory",
    "--project",
    "--config-file",
    "--color",
    # Hidden from --help (clap `hide`/`alias`), found by probing every long
    # name in uv's CLI source (crates/uv-cli/src/lib.rs) — see CLAUDE.md.
    "--config-settings", "--constraint", "--no-editable-package", "--only-install-package", "--preview-feature", "--preview-features", "--python-fetch", "--python-preference", "--requirement", "--trusted-host",
})

# Flags that consume the next argument as their value for `uv tool install/upgrade`.
# Audited against: uv 0.12.23 `uv tool install --help` / `uv tool upgrade --help`,
# plus the hidden names probed from uv's CLI source.
_UV_TOOL_VALUE_FLAGS = frozenset({
    # Python selector
    "-p", "--python",
    # Extra dependencies (install only)
    "-w", "--with", "--with-requirements", "--with-editable", "--with-executables-from",
    # Constraints / overrides
    "-c", "--constraints", "--overrides", "--excludes",
    "-b", "--build-constraints",
    # Index / source
    "--index", "--default-index", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links",
    "--index-strategy", "--keyring-provider",
    # Upgrade control
    "-P", "--upgrade-package", "--upgrade-group",
    # Solver strategy
    "--resolution", "--prerelease", "--prerelease-package", "--fork-strategy",
    "--exclude-newer", "--exclude-newer-package",
    # Platform (install only)
    "--python-platform", "--torch-backend",
    # Install control
    "--reinstall-package",
    "--link-mode",
    # Build config
    "-C", "--config-setting",
    "--config-settings-package",   # install
    "--config-setting-package",    # upgrade (different spelling)
    "--no-build-isolation-package",
    "--no-build-package",
    "--no-binary-package",
    "--no-sources-package",
    # Cache
    "--cache-dir",
    "--refresh-package",
    # Global flags that take values
    "--allow-insecure-host",
    "--directory",
    "--project",
    "--config-file",
    "--color",
    # Hidden from --help (clap `hide`/`alias`), found by probing every long
    # name in uv's CLI source (crates/uv-cli/src/lib.rs) — see CLAUDE.md.
    "--build-constraint", "--config-settings", "--constraint", "--exclude", "--from", "--override", "--preview-feature", "--preview-features", "--python-fetch", "--python-preference", "--trusted-host",
})

# Flags that consume the next argument as their value for `pipx install/inject/etc`.
# Audited against: pipx 1.14.1 `pipx install --help` / `pipx inject --help`.
_PIPX_VALUE_FLAGS = frozenset({
    "--python",
    "--suffix",
    "--preinstall",
    "--index-url", "-i",
    "--pip-args",
    "--backend",
    "--fetch-python",  # install only
    # Gone from pipx 1.14's help but still accepted by older pipx; keeping it
    # cannot swallow a real argument on 1.14, which rejects the command.
    "--spec",
    "-r", "--requirement",  # inject only
})

def _positionals(args: list[str], value_flags: frozenset[str]) -> list[str]:
    """Return all positional arguments, skipping flags and their values.

    Recognises ``--`` as the end-of-options marker; all tokens after it are
    treated as positionals regardless of whether they start with ``-``.
    """
    result: list[str] = []
    skip_next = False
    for i, arg in enumerate(args):
        if arg == "--":
            result.extend(args[i + 1:])
            break
        if skip_next:
            skip_next = False
            continue
        if arg in value_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        result.append(arg)
    return result


def _value_flag_args(args: list[str], collect_flags: frozenset[str]) -> list[str]:
    """Return the values consumed by flags in *collect_flags*.

    Handles three spelling forms:
    - Space-separated:  ``-r file.txt`` / ``--requirements file.txt``
    - Equals-form:      ``--requirements=file.txt``
    - Concatenated short: ``-rfile.txt``

    For equals-form and concatenated matching, only flags that appear literally
    in *collect_flags* are matched (e.g. ``-r`` matches ``-rfile`` but ``--req``
    does not match ``--requirements=…``).

    Tokens after ``--`` are not inspected (they are positionals, not flag values).
    """
    result: list[str] = []
    collect_next = False
    long_flags = frozenset(f for f in collect_flags if f.startswith("--"))
    short_flags = frozenset(f for f in collect_flags if f.startswith("-") and not f.startswith("--"))
    for arg in args:
        if arg == "--":
            break
        if collect_next:
            result.append(arg)
            collect_next = False
            continue
        if arg in collect_flags:
            collect_next = True
            continue
        # Equals-form: --requirements=file.txt
        for lf in long_flags:
            prefix = lf + "="
            if arg.startswith(prefix):
                result.append(arg[len(prefix):])
                break
        else:
            # Concatenated short: -rfile.txt
            for sf in short_flags:
                if len(sf) == 2 and arg.startswith(sf) and len(arg) > len(sf):
                    result.append(arg[len(sf):])
                    break
    return result


def _first_positional(args: list[str], value_flags: frozenset[str]) -> str | None:
    """Return the first positional argument, skipping flags and their values."""
    positionals = _positionals(args, value_flags)
    return positionals[0] if positionals else None


# Decides whether an option consumes the argument after it: (option, next) ->
# bool, where next is None at the end of the command line. A frozenset of
# value-taking names covers most tools; npm and yarn need `next` too.
_Consumes = Callable[[str, "str | None"], bool]


def _in_set(value_flags: frozenset[str]) -> _Consumes:
    def consumes(flag: str, _next: str | None) -> bool:
        return flag in value_flags
    return consumes


def _skip_options(args: list[str], i: int, consumes: _Consumes) -> int:
    """Index of the first argument at or after `i` that is not an option or an
    option's value. `--` is never skipped."""
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        nxt = args[i + 1] if i + 1 < len(args) else None
        i += 2 if consumes(args[i], nxt) else 1
    return i


def _positionals_by(args: list[str], consumes: _Consumes) -> list[str]:
    """Like _positionals(), with a consumption rule instead of a fixed set."""
    result: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            result.extend(args[i + 1:])
            break
        if arg.startswith("-"):
            nxt = args[i + 1] if i + 1 < len(args) else None
            i += 2 if consumes(arg, nxt) else 1
            continue
        result.append(arg)
        i += 1
    return result


def _dispatch_subcommand(
    args: list[str],
    consumes: _Consumes,
    parse_sub: Callable[[list[str]], ParsedInstall | None],
) -> tuple[ParsedInstall | None, int]:
    """Find the subcommand behind any leading options and parse from it.

    Returns (result, index of the subcommand). Every package manager accepts
    options BEFORE its subcommand (`npm --silent install x`, `uv -q add x`),
    and an argv that parses to None is exec'd by the sandbox runner with no
    sandbox and no pre-flight at all — so a leading option must never make a
    command unrecognisable.

    `consumes` is exact for the options audited from each tool's help. For
    anything it does not know — a flag a newer release added — it assumes
    boolean, which would read that option's VALUE as the subcommand. So when
    the subcommand is unrecognised and follows an option directly, it is
    retried as that option's value. This errs toward gating: at worst an odd
    command such as `npm --foo run install` is treated as an install.
    """
    i = _skip_options(args, 0, consumes)
    while True:
        result = parse_sub(args[i:])
        if result is not None:
            return result, i
        prev = args[i - 1] if 0 < i <= len(args) else ""
        if not (
            i < len(args)
            and prev.startswith("-")
            and prev != "--"
            and "=" not in prev
        ):
            return None, i
        i = _skip_options(args, i + 1, consumes)


def _last_flag_value(args: list[str], flags: frozenset[str]) -> str | None:
    """The value of the last of `flags` in `args` (any spelling
    _value_flag_args() accepts), or None."""
    values = _value_flag_args(args, flags)
    return values[-1] if values else None

# Matches scp-style VCS refs: git@host:path (colon, not slash, after hostname).
_SCP_VCS_RE = re.compile(r"^git@[^/:]+:[^/]")


def _is_vcs_editable(s: str) -> bool:
    """Return True if an -e/--editable value is a VCS URL, not a local path.

    Only VCS editables are relevant for SSH detection and OSV pre-flight.
    Local paths (., .., /abs, relative/) keep packages[] empty so the
    lock-file fallback in _preflight still runs.
    """
    return (
        "://" in s
        or s.startswith(("git+", "hg+", "svn+", "bzr+"))
        or bool(_SCP_VCS_RE.match(s))
    )



@dataclass
class ParsedInstall:
    manager: str
    packages: list[str] = field(default_factory=list)
    ecosystem: str = "pypi"
    venv_exe: str | None = None  # path used to derive site-packages
    req_files: list[str] = field(default_factory=list)  # -r / --requirement file paths
    lockfile_hint: str | None = None  # preferred lockfile to scan (relative path)
    global_install: bool = False
    suggested_env: dict[str, str] = field(default_factory=dict)
    extra_write_home_dirs: list[Path] = field(default_factory=list)
    # Name of the target environment receiving the packages when it differs from
    # packages[0] (e.g. pipx inject httpie httpx → target_env_name="httpie").
    # None means the environment name is derived from packages[0] as normal.
    target_env_name: str | None = None
    # True only for a command that installs/syncs the *existing* lock file's
    # full contents with no explicit package names of its own (bare `npm
    # install`, `yarn install`, `pnpm dedupe`, `pipenv sync`, `uv sync`/`lock`,
    # `npm audit fix`) — the one case where scanning the current lock file
    # for OSV advisories / typosquat / risk signals is actually checking what
    # is *about to be installed*.
    #
    # `packages == [] and req_files == []` looks identical for that case and
    # for a *removal* (`npm uninstall`, `yarn/pnpm remove`, `uv remove`) or an
    # unrelated non-install subcommand (`pipenv shell`/`check`/`clean`, `uv
    # run`/`cache`/`venv`, `pnpm fetch` is the one exception — see its own
    # comment) — both also produce an empty packages/req_files ParsedInstall,
    # but scanning the lock file there checks packages the command is not
    # installing at all, and could block a legitimate uninstall or read-only
    # command over a risk signal on a dependency the user is trying to remove
    # or never asked to gate in the first place. Must be set explicitly by
    # each parser rather than inferred from packages/req_files being empty.
    is_lockfile_install: bool = False
    # False for a command that is guaranteed to install/change nothing no
    # matter what packages/req_files/is_lockfile_install say — a report-only
    # or check-only invocation (`npm install <pkg> --dry-run`, `npm update
    # --dry-run`, `npm audit fix --dry-run`, `uv sync --check`, `pnpm dedupe
    # --check`, `pipenv update --dry-run`/`--outdated`). These flags don't
    # change the command's *shape* (explicit packages stay in `packages`,
    # `is_lockfile_install` reflects what the equivalent real command would
    # do) — they only mean the pre-flight gates have nothing real to gate,
    # since nothing will actually be installed. Consulting `packages`/
    # `is_lockfile_install` alone is not enough: `npm install lodash
    # --dry-run` still has a non-empty `packages`, which the gates would
    # otherwise query and potentially block, even though the command installs
    # nothing regardless of the answer. Checked before any other field by
    # `_resolve_query_packages`/`_preflight`. Defaults to True (gate
    # normally) so every existing/third-party parser that doesn't know about
    # this field keeps its current behaviour.
    should_gate: bool = True
    # True when the command targets the system Python rather than an active
    # venv/conda environment — `uv pip sync`/`uv pip install --system`, or
    # the equivalent UV_SYSTEM_PYTHON env var (uv's own docs: `--system`
    # "Install packages into the system Python environment", with
    # `env: UV_SYSTEM_PYTHON`). Verified empirically (`uv pip sync -v`)
    # that `--system` switches uv's interpreter discovery entirely — from
    # "searching in virtual environments" (VIRTUAL_ENV/CONDA_PREFIX/.venv,
    # what `_discover_target_python_version` models) to "searching in
    # search path or managed installations", which explicitly *ignores* an
    # active VIRTUAL_ENV even if one is set. Consumers must not apply
    # VIRTUAL_ENV/CONDA_PREFIX-based version discovery when this is True —
    # see `_collect_pylock_packages`'s use of `_TARGET_VERSION_UNKNOWN`.
    is_system_python_target: bool = False
    # The directory the command effectively runs in, and the one it discovers
    # its project (lock file) from, when the invocation moves either — uv's
    # `--directory` and `--project`. Each unresolved, exactly as given, None
    # when not moved, and each with its OWN base: `working_dir` is relative to
    # the process's cwd, `project_dir` to the effective working directory (as
    # uv resolves `--project`). See resolve_invocation_dirs().
    working_dir: str | None = None
    project_dir: str | None = None
    # Where the lock file lives, when the invocation moves it independently of
    # the project (pnpm's `--lockfile-dir`). Relative to the process cwd — NOT
    # to working_dir: measured, `pnpm -C sub install --lockfile-dir locks`
    # writes ./locks/pnpm-lock.yaml. None means the project directory.
    lockfile_dir: str | None = None
    # Registry settings given on the command line, keyed as the manager names
    # them (npm: "registry", "@scope:registry"). They take precedence over the
    # environment and config files when deciding which registry a named
    # package comes from.
    registries: dict[str, str] = field(default_factory=dict)

    @property
    def registry_name(self) -> str:
        """Registry lookup key for this manager; see :func:`manager_registry_name`."""
        return manager_registry_name(self.manager)


def derive_site_packages(exe_path: str) -> Path | None:
    """
    Given any executable inside a venv's bin/ (pip, python, uv…),
    return its site-packages directory.

    Works for:  /path/to/venv/bin/pip
                /path/to/venv/bin/python3
    Returns None for system executables or paths that don't resolve to a venv.
    """
    p = Path(exe_path)
    if not p.is_absolute():
        return None
    # venv/bin/<exe>  →  venv/lib/pythonX.Y/site-packages
    venv_root = p.parent.parent
    candidates = sorted(venv_root.glob("lib/python*/site-packages"))
    return candidates[0] if candidates else None


# The running command's own registry settings (``ParsedInstall.registries``),
# set by the sandbox runner for the command it runs. Lock-file parsers that
# resolve an entry without a resolved URL from the configured registry give it
# precedence over the environment and config files, as the tool itself does.
# Empty everywhere else (scans, the daemon).
COMMAND_LINE_REGISTRIES: ContextVar[Mapping[str, str]] = ContextVar(
    "COMMAND_LINE_REGISTRIES", default=MappingProxyType({}))


def parse_package_spec(spec: str, ecosystem: str) -> tuple[str, str | None]:
    """
    Extract (normalized_name, version_or_None) from a raw package spec token.

    Non-pinned version constraints (>=, ~=, ^, ranges) are dropped and None is
    returned for version so that OSV queries are broadened rather than skipped.

    For built-in ecosystems the appropriate parser is called directly.  For
    unknown ecosystems the language registry is consulted so that external
    plugins can provide their own spec parsing via parse_package_spec().
    """
    if ecosystem == "pypi":
        return _parse_pip_spec(spec)
    if ecosystem == "npm":
        return _parse_npm_spec(spec)
    if ecosystem == "packagist":
        return _parse_composer_spec(spec)
    # Fall back to the language module's own parser for plugin ecosystems.
    from packagealert.languages import registry as lang_registry
    lang_registry.load()
    lang = lang_registry.for_ecosystem(ecosystem)
    if lang is not None:
        return lang.parse_package_spec(spec)
    return spec, None


def _parse_pip_spec(spec: str) -> tuple[str, str | None]:
    # Strip PEP 508 environment markers (everything after the first ';')
    spec = spec.partition(";")[0].strip()
    # Reject local paths, VCS URLs (scheme-based and scp-style), and direct URLs
    if (
        spec.startswith((".", "/", "git+", "hg+", "svn+", "bzr+", "file:"))
        or "://" in spec
        or _SCP_VCS_RE.match(spec)
    ):
        return "", None
    m = _PIP_NAME_RE.match(spec)
    if not m:
        return "", None
    name = m.group(1)
    rest = spec[m.end():].lstrip()
    # Skip extras e.g. flask[async]
    if rest.startswith("["):
        close = rest.find("]")
        rest = rest[close + 1:].lstrip() if close != -1 else ""
    # Only extract the version for an exact pin (==), not >=, ~=, !=, etc.
    version: str | None = None
    if rest.startswith("==") and not rest.startswith("==="):
        ver = rest[2:].split(",")[0].strip()
        if ver:
            version = ver
    return name, version


def _is_valid_npm_bare_name(name: str) -> bool:
    """Return True for a registry package name; False for paths, URLs, or protocols."""
    return bool(name) and name[0] not in "./" and all(c not in name for c in "/:+\\")


def _parse_npm_spec(spec: str) -> tuple[str, str | None]:
    # Scoped packages: @org/pkg or @org/pkg@version
    if spec.startswith("@"):
        slash = spec.find("/")
        if slash == -1:
            return "", None  # malformed scoped name with no slash
        at_idx = spec.find("@", slash)
        name = spec[:at_idx] if at_idx != -1 else spec
        ver = spec[at_idx + 1:] if at_idx != -1 else ""
        # Reject extra path segments: valid form is exactly @scope/package
        if name.count("/") != 1:
            return "", None
    else:
        name, _, ver = spec.partition("@")
        if not _is_valid_npm_bare_name(name.strip()):
            return "", None
    ver = ver.strip()
    # Keep only concrete versions (at least X.Y); bare major tags like "18" are ranges.
    version = ver if ver and re.match(r"^\d+\.\d[\d.]*(-[\w.]+)?(\+[\w.]+)?$", ver) else None
    return name.strip(), version


# Packagist names must be vendor/package — exactly one slash, both parts non-empty.
_COMPOSER_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _parse_composer_spec(spec: str) -> tuple[str, str | None]:
    # vendor/package or vendor/package:constraint or "vendor/package ^1.0"
    name, sep, ver = spec.partition(":")
    if not sep:
        name, _, ver = spec.partition(" ")
    name = name.strip()
    if not _COMPOSER_NAME_RE.match(name):
        return "", None
    ver = ver.strip().lstrip("v")
    # Only exact numeric versions; drop ^ ~ >= * etc.
    version = ver if ver and re.match(r"^\d[\d.]*$", ver) else None
    return name, version


_CMD_VERSION_SUFFIX_RE = re.compile(r"[-.](\d[\d.]*)$")


def _basename(path: str) -> str:
    return re.split(r"[/\\]", path)[-1]


def _cmd(path: str) -> str:
    """Return the normalised command basename: strip path, version suffixes,
    Windows .exe extension, and Node *-cli.js wrappers.

    e.g. /usr/bin/python3.11 -> python3
         C:\\Python\\pip.exe  -> pip
         /usr/lib/node/npm-cli.js -> npm
    """
    name = _basename(path).lower()
    name = name.removesuffix(".exe")
    name = name.removesuffix("-cli.js")
    return _CMD_VERSION_SUFFIX_RE.sub("", name)


_PY_FLAGS_WITH_VALUE = frozenset({"-W", "-X", "-w"})
_PY_FLAGS_NO_VALUE = frozenset({
    "-B", "-b", "-d", "-E", "-h", "-i", "-I",
    "-O", "-OO", "-q", "-s", "-S", "-u", "-v", "-V", "-x",
})


def _find_m_pip_args(argv: list[str]) -> list[str] | None:
    """Scan the interpreter flag prefix of argv for -m pip.

    Returns the args after '-m pip' if found, or None if the argv is not a
    'python -m pip ...' invocation. Stops at the first non-flag token (script
    name), -c, or -- to avoid false-positives from script arguments.
    """
    idx = 1
    while idx < len(argv):
        tok = argv[idx]
        if tok == "-m":
            if idx + 1 < len(argv) and argv[idx + 1] == "pip":
                return argv[idx + 2:]
            return None
        if tok in ("-c", "--"):
            return None
        if tok in _PY_FLAGS_WITH_VALUE:
            idx += 2  # e.g. -W default
            continue
        if tok in _PY_FLAGS_NO_VALUE:
            idx += 1
            continue
        # Combined short option with inline value: -Wd, -Xfoo, etc.
        if len(tok) > 2 and tok[0] == "-" and tok[1] in "WXw":
            idx += 1
            continue
        # Any other single-char short flag not in our tables
        if tok.startswith("-") and len(tok) == 2:
            idx += 1
            continue
        # Long option: --foo or --foo=bar (consume next token as value if no =)
        if tok.startswith("--"):
            if "=" not in tok and idx + 1 < len(argv) and not argv[idx + 1].startswith("-"):
                idx += 2  # --opt value
            else:
                idx += 1  # --opt=value or boolean --opt
            continue
        return None  # non-flag token — script name
    return None  # exhausted argv without finding -m pip


def parse_pip_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    # Handle: pip install, /path/to/pip install, python -m pip install
    cmd = _cmd(argv[0])
    if cmd in ("pip", "pip3"):
        args = argv[1:]
        venv_exe = argv[0]
    elif cmd in ("python", "python3"):
        if len(argv) >= 2 and _cmd(argv[1]) in ("pip", "pip3"):
            # python /path/to/pip install ...
            args = argv[2:]
        else:
            # python [-flags…] -m pip install …
            m_pip_args = _find_m_pip_args(argv)
            if m_pip_args is None:
                return None
            args = m_pip_args
        venv_exe = argv[0]
    else:
        return None
    args = list(args)
    if not args:
        return None

    # pip accepts global options before the subcommand (e.g. `pip -q install ...`).
    # Skip leading flags to find the subcommand — it is always a bare word.
    # Flags that consume the next token as a separate value must be skipped as a pair
    # so the value is not mistaken for the subcommand (e.g. `--cache-dir /tmp install`).
    # Flags using `--flag=value` form are safe to skip as a single token.
    # Expand abbreviated long options first (`pip install --constr c.txt`).
    args = _canonicalise_long_options(
        args, _pip_expand_general, _PIP_GLOBAL_VALUE_FLAGS, {"install": _pip_expand_install}
    )
    subcmd_idx = None
    i = 0
    while i < len(args):
        tok = args[i]
        if not tok.startswith("-"):
            subcmd_idx = i
            break
        if tok in _PIP_GLOBAL_VALUE_FLAGS and "=" not in tok:
            i += 2  # skip flag and its value token
        else:
            i += 1
    if subcmd_idx is None:
        return None  # only flags, no subcommand

    subcmd = args[subcmd_idx]
    # Only sandbox subcommands that introduce new code into the environment.
    # `uninstall` is intentionally excluded — removing a package cannot introduce
    # malicious code, so sandboxing it provides no security benefit.
    # Anything else (list, show, freeze, uninstall, unknown future subcommands)
    # passes through directly.
    if subcmd != "install":
        return None
    packages: list[str] = []
    req_files: list[str] = []
    skip_value_for: str | None = None
    install_args = args[subcmd_idx + 1:]
    for pos, arg in enumerate(install_args):
        if arg == "--" and skip_value_for is None:
            # End of options: everything after is a positional (a package).
            packages.extend(install_args[pos + 1:])
            break
        if skip_value_for is not None:
            if skip_value_for in ("-r", "--requirement"):
                req_files.append(arg)
            elif skip_value_for in ("-e", "--editable") and _is_vcs_editable(arg):
                packages.append(arg)
            skip_value_for = None
            continue
        if arg in ("-r", "--requirement"):
            skip_value_for = arg
            continue
        if arg.startswith("--requirement="):
            req_files.append(arg[len("--requirement="):])
            continue
        if arg.startswith("-r") and len(arg) > 2:
            req_files.append(arg[2:])
            continue
        if arg in ("-e", "--editable"):
            skip_value_for = arg
            continue
        if arg.startswith("--editable="):
            val = arg[len("--editable="):]
            if _is_vcs_editable(val):
                packages.append(val)
            continue
        if arg in _PIP_VALUE_FLAGS:
            skip_value_for = arg
            continue
        if arg.startswith("-"):
            continue
        packages.append(arg)
    # `--dry-run` resolves dependencies and reports what would happen without
    # actually installing anything (pip's own docs) — nothing to gate,
    # regardless of explicit packages or -r/--requirement files.
    should_gate = "--dry-run" not in args[subcmd_idx + 1:]
    return ParsedInstall(
        manager="pip", packages=packages, ecosystem="pypi", venv_exe=venv_exe,
        req_files=req_files, should_gate=should_gate,
    )


# Truthy string forms UV_SYSTEM_PYTHON accepts — verified empirically
# against uv 0.12.2 (`uv pip sync -v` DEBUG output) across uv's complete
# boolean vocabulary: "1"/"true"/"yes"/"on"/"y"/"t" (case-insensitive, e.g.
# "TRUE"/"On"/"Y" all switch uv's interpreter discovery to system mode);
# "0"/"false"/"no"/"off"/"n"/"f" don't. Any other value (e.g. "2", "") is a
# hard error from uv itself, so it never reaches a successful invocation
# for us to observe.
_UV_SYSTEM_PYTHON_TRUTHY = frozenset({"1", "true", "yes", "on", "y", "t"})


def _uv_targets_system_python(rest: list[str]) -> bool:
    """True if this `uv pip sync`/`uv pip install` invocation targets the
    system Python rather than an active venv/conda environment.

    `--system` (uv's own docs: "Install packages into the system Python
    environment") or its env-var equivalent UV_SYSTEM_PYTHON switches uv's
    interpreter discovery entirely — verified empirically (`uv pip sync
    -v`) to go from "searching in virtual environments" to "searching in
    search path or managed installations", explicitly ignoring an active
    VIRTUAL_ENV. See ParsedInstall.is_system_python_target's docstring for
    why this matters to marker evaluation.
    """
    import os

    if "--system" in rest:
        return True
    return os.environ.get("UV_SYSTEM_PYTHON", "").lower() in _UV_SYSTEM_PYTHON_TRUTHY


# Options that consume the next argument for `uv pip install` — uv's own set,
# not pip's: `_PIP_VALUE_FLAGS` lacked 35 of these (`--resolution`,
# `--torch-backend`, the global `--directory`/`--color`, …), so their values
# were read as package names. Audited against: uv 0.12.23
# `uv pip install --help`.
_UV_PIP_INSTALL_VALUE_FLAGS = frozenset({
    "--allow-insecure-host", "--build-constraints", "--cache-dir", "--cert",
    "--color", "--config-file", "--config-setting",
    "--config-settings-package", "--constraints", "--default-index",
    "--directory", "--editable", "--exclude-newer",
    "--exclude-newer-package", "--excludes", "--extra", "--extra-index-url",
    "--find-links", "--fork-strategy", "--group", "--index",
    "--index-strategy", "--index-url", "--keyring-provider", "--link-mode",
    "--no-binary", "--no-build-isolation-package", "--no-editable-package",
    "--no-sources-package", "--only-binary", "--output-format",
    "--overrides", "--prefix", "--prerelease", "--prerelease-package",
    "--project", "--python", "--python-platform", "--python-version",
    "--refresh-package", "--reinstall-package", "--requirements",
    "--resolution", "--target", "--torch-backend", "--upgrade-group",
    "--upgrade-package", "-C", "-P", "-b", "-c", "-e", "-f", "-i", "-p",
    "-r", "-t",
    # Hidden from --help (clap `hide`/`alias`), found by probing every long
    # name in uv's CLI source (crates/uv-cli/src/lib.rs) — see CLAUDE.md.
    "--build-constraint", "--config-settings", "--constraint", "--exclude", "--override", "--preview-feature", "--preview-features", "--python-fetch", "--python-preference", "--requirement", "--trusted-host",
})
# Every spelling uv accepts for a requirements file (`uv pip install`, `uv add`):
# `--requirements`, and the hidden `--requirement` alias.
_UV_PIP_REQUIREMENT_FLAGS = frozenset({"-r", "--requirement", "--requirements"})

# uv's global options that consume the next argument. uv accepts global options
# BEFORE the subcommand (`uv -q add requests`, `uv --directory backend sync`),
# so the subcommand is the first argument that is neither one of these, nor its
# value, nor a boolean flag. Audited against: uv 0.12.23 `uv --help`.
_UV_GLOBAL_VALUE_FLAGS = frozenset({
    "--cache-dir",
    "--color",
    "--allow-insecure-host",
    "--directory",
    "--project",
    "--config-file",
    # Hidden from --help (clap `hide`/`alias`), found by probing every long
    # name in uv's CLI source (crates/uv-cli/src/lib.rs) — see CLAUDE.md.
    "--preview-feature", "--preview-features", "--python-fetch", "--python-preference", "--trusted-host",
})


class InvalidInvocationDirectory(ValueError):
    """A directory option (`--directory`, `-C`, `--lockfile-dir`, …) that
    cannot be resolved — a symlink loop, or an unreadable path component.
    Callers must treat the invocation as unusable (fail closed), never fall
    back to the process cwd: that would scan a different project from the one
    the command names."""


def _canonical(path: Path) -> Path:
    """Resolve `path`, rejecting a symlink loop on every supported Python.

    A non-strict resolve() cannot be relied on to notice a loop: Python 3.12
    raises RuntimeError, but 3.13+ returns the loop UNRESOLVED, so the loop
    would be accepted there. strict=True reports it on every version (3.12:
    RuntimeError; 3.13+: OSError ELOOP) and reports a merely MISSING path as
    FileNotFoundError on every version — which is legitimate (pnpm creates its
    `--lockfile-dir`), so only that falls back to a non-strict resolve.
    """
    try:
        return path.resolve(strict=True)
    except FileNotFoundError:
        pass
    except (OSError, RuntimeError) as exc:
        raise InvalidInvocationDirectory(f"cannot resolve {path}: {exc}") from exc
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:
        raise InvalidInvocationDirectory(f"cannot resolve {path}: {exc}") from exc


def resolve_invocation_dirs(
    cwd: Path, working_dir: str | None, project_dir: str | None
) -> tuple[Path, Path]:
    """Return (work_dir, project_dir) for a command run from `cwd`.

    Mirrors uv's own rules: `--directory` changes the working directory, and
    relative paths (requirement files included) resolve against it;
    `--project` only moves project discovery and resolves relative to that
    working directory. Either defaults to the directory before it, so a
    command that moves neither gets (cwd, cwd).

    A moved directory is CANONICALISED (`..` and symlinks resolved): the
    sandbox decides what may become writable by comparing these against cwd,
    and a lexical `cwd / "../elsewhere"` would pass `is_relative_to(cwd)`.
    Raises InvalidInvocationDirectory if a moved directory cannot be resolved.
    """
    work = _canonical(cwd / working_dir) if working_dir else cwd
    project = _canonical(work / project_dir) if project_dir else work
    return work, project


def resolve_lockfile_dir(cwd: Path, lockfile_dir: str | None, project_dir: Path) -> Path:
    """The directory a command's lock file lives in: `lockfile_dir` resolved
    against the process `cwd` (see ParsedInstall.lockfile_dir), else the
    project directory."""
    return _canonical(cwd / lockfile_dir) if lockfile_dir else project_dir


def parse_uv_args(argv: list[str]) -> ParsedInstall | None:
    if not argv or _cmd(argv[0]) != "uv":
        return None
    args = argv[1:]
    result, i = _dispatch_subcommand(
        args,
        _in_set(_UV_GLOBAL_VALUE_FLAGS),
        lambda rest: _parse_uv_subcommand(argv[0], rest),
    )
    if result is not None:
        # Global options may also follow the subcommand, so read them from the
        # whole command line. `--project` has no effect under `uv pip`.
        #
        # Their env-var forms (UV_WORKING_DIR, UV_PROJECT) are deliberately
        # NOT read here: this parser also runs in the daemon, whose
        # os.environ is the daemon's own rather than the observed process's,
        # so a stray value there would redirect every uv process's lock-file
        # scan to the wrong directory.
        result.working_dir = _last_flag_value(args, frozenset({"--directory"}))
        if args[i:i + 1] != ["pip"]:
            result.project_dir = _last_flag_value(args, frozenset({"--project"}))
    return result


def _parse_uv_subcommand(venv_exe: str, args: list[str]) -> ParsedInstall | None:
    """Parse `args`, which start at uv's subcommand."""
    if not args:
        return None
    subcmd = args[0]
    if subcmd in ("pip", "tool"):
        # uv accepts its GLOBAL options between command levels too (`uv pip
        # --color never sync r.txt`, `uv tool -q install ruff`), and only
        # those — a level-specific option there (`uv pip --system sync`) is
        # rejected. Without skipping them the nested command was unrecognised:
        # `uv tool -q install x` parsed to None and ran unsandboxed, and
        # `uv pip -q install x` resolved to no packages at all.
        j = _skip_options(args, 1, _in_set(_UV_GLOBAL_VALUE_FLAGS))
        args = [subcmd, *args[j:]]
    if subcmd == "add":
        packages = _positionals(args[1:], _UV_PROJECT_VALUE_FLAGS)
        # Every spelling uv accepts, the hidden `--requirement` alias included:
        # an alias that is only SKIPPED as a value drops the file entirely.
        req_files = _value_flag_args(args[1:], _UV_PIP_REQUIREMENT_FLAGS)
        return ParsedInstall(manager="uv-project", packages=packages, ecosystem="pypi", venv_exe=venv_exe, req_files=req_files)
    if subcmd == "remove":
        # Removal mutates uv.lock, but removes a package rather than
        # installing one — putting the removed names into `packages` would
        # make the risk/cooldown gates and OSV pre-flight query them as if
        # they were about to be installed, and could block the removal of
        # the very (suspicious) dependency the user is trying to get rid of.
        # Not a lockfile-install case either. Matches the npm/yarn/pnpm
        # `remove` branches below, which likewise return empty `packages`.
        return ParsedInstall(manager="uv-project", packages=[], ecosystem="pypi", venv_exe=venv_exe)
    if subcmd == "sync":
        # Materialises the project's existing lock file with no package names
        # of its own — the one uv subcommand this scan should cover.
        # Exception: `--check` only reports whether the environment is
        # synchronized with the project, and `--dry-run` performs a dry run
        # "without writing the lockfile or modifying the project environment"
        # (both uv's own docs) — nothing to gate regardless of
        # is_lockfile_install.
        is_report_only = "--check" in args[1:] or "--dry-run" in args[1:]
        return ParsedInstall(
            manager="uv-project", packages=[], ecosystem="pypi", venv_exe=venv_exe,
            is_lockfile_install=True,
            should_gate=not is_report_only,
        )
    if subcmd == "lock":
        # Regenerates uv.lock from pyproject.toml's declared dependencies —
        # does not install anything into the environment, and does not even
        # read the *existing* lock file as its surface (it resolves fresh).
        # Scanning the current (about-to-be-replaced) uv.lock here would gate
        # a lock-generation operation against stale contents. Not a
        # lockfile-install case.
        return ParsedInstall(manager="uv-project", packages=[], ecosystem="pypi", venv_exe=venv_exe)
    if subcmd == "pip" and len(args) > 1 and args[1] == "sync":
        # `uv pip sync <SRC_FILE>...` installs exactly the packages listed in
        # the given requirements/pylock files (uv's own docs) — a real
        # install, unlike `uv pip install`'s src files are positional
        # arguments here, not values of a -r/--requirement flag.
        rest = args[2:]
        req_files: list[str] = []
        skip_value_for: str | None = None
        # Audited against: uv 0.12.23 `uv pip sync --help`.
        _UV_PIP_SYNC_VALUE_FLAGS = frozenset({
            "-c", "--constraints", "-b", "--build-constraints",
            "--extra", "--group", "--cert", "--target", "-t",
            "--python", "-p", "--python-version", "--python-platform",
            "--index", "--default-index", "-i", "--index-url", "--extra-index-url",
            "--index-strategy", "--keyring-provider", "--config-setting", "-C",
            "--find-links", "-f", "--cache-dir", "--exclude-newer",
            "--exclude-newer-package",
            "--link-mode", "--prefix",
            "--config-settings-package", "--no-sources-package",
            "--no-binary", "--only-binary",
            "--reinstall-package", "--refresh-package",
            "--torch-backend", "--output-format",
            # Global flags that take values
            "--allow-insecure-host", "--directory", "--project",
            "--config-file", "--color",
            # Hidden from --help (clap `hide`/`alias`), found by probing every
            # long name in uv's CLI source — see CLAUDE.md.
            "--build-constraint", "--config-settings", "--constraint",
            "--preview-feature", "--preview-features", "--python-fetch",
            "--python-preference", "--trusted-host",
            # --no-index is intentionally excluded: it is a boolean flag
            # (uv's own docs) with no value of its own — including it here
            # would consume the very next token (often the requirements
            # filename itself, e.g. `uv pip sync --no-index requirements.txt`)
            # as if it were --no-index's argument, silently dropping the
            # requirements file from req_files.
        })
        for arg in rest:
            if skip_value_for is not None:
                skip_value_for = None
                continue
            if arg in _UV_PIP_SYNC_VALUE_FLAGS:
                skip_value_for = arg
                continue
            if not arg.startswith("-"):
                req_files.append(arg)
        # `--dry-run` resolves dependencies and prints the plan without
        # actually installing anything (uv's own docs) — nothing to gate.
        should_gate = "--dry-run" not in rest
        return ParsedInstall(
            manager="uv", packages=[], ecosystem="pypi", venv_exe=venv_exe,
            req_files=req_files, should_gate=should_gate,
            is_system_python_target=_uv_targets_system_python(rest),
        )
    if subcmd == "pip" and len(args) > 1 and args[1] == "install":
        rest = args[2:]
        packages: list[str] = []
        req_files: list[str] = []
        skip_value_for: str | None = None
        for arg in rest:
            if skip_value_for is not None:
                if skip_value_for in _UV_PIP_REQUIREMENT_FLAGS:
                    req_files.append(arg)
                elif skip_value_for in ("-e", "--editable") and _is_vcs_editable(arg):
                    packages.append(arg)
                skip_value_for = None
                continue
            if arg in _UV_PIP_REQUIREMENT_FLAGS:
                skip_value_for = arg
                continue
            if arg.startswith(("--requirement=", "--requirements=")):
                req_files.append(arg.split("=", 1)[1])
                continue
            if arg.startswith("-r") and len(arg) > 2:
                req_files.append(arg[2:])
                continue
            if arg in ("-e", "--editable"):
                skip_value_for = arg
                continue
            if arg.startswith("--editable="):
                val = arg[len("--editable="):]
                if _is_vcs_editable(val):
                    packages.append(val)
                continue
            if arg in _UV_PIP_INSTALL_VALUE_FLAGS:
                skip_value_for = arg
                continue
            if not arg.startswith("-"):
                packages.append(arg)
        # `--dry-run` resolves dependencies and prints the resulting plan
        # without actually installing anything (uv's own docs) — nothing to
        # gate, regardless of explicit packages or -r/--requirement files.
        should_gate = "--dry-run" not in rest
        return ParsedInstall(
            manager="uv", packages=packages, ecosystem="pypi", venv_exe=venv_exe,
            req_files=req_files, should_gate=should_gate,
            is_system_python_target=_uv_targets_system_python(rest),
        )
    if subcmd == "tool":
        tool_subcmd = args[1] if len(args) > 1 else None
        # `update` is uv's alias for `upgrade` (clap `alias`, not shown in help).
        if tool_subcmd in ("install", "upgrade", "update"):
            tool_name = _first_positional(args[2:], _UV_TOOL_VALUE_FLAGS)
            # The hidden `--from <REQ>` is the requirement actually installed
            # (`uv tool install ruff --from 'ruff==0.1.0'`); uv rejects one
            # whose package name differs from the positional, but it can carry
            # the real version, so it is the spec to check.
            from_spec = _last_flag_value(args[2:], frozenset({"--from"}))
            spec = from_spec or tool_name
            packages = [spec] if spec else []
            home = Path.home()
            return ParsedInstall(
                manager="uv", packages=packages, ecosystem="pypi", venv_exe=venv_exe,
                extra_write_home_dirs=[
                    home / ".local" / "share" / "uv" / "tools",
                    home / ".local" / "bin",
                ],
            )
        if tool_subcmd == "run":
            # Executes an already-installed tool — not installing anything.
            return ParsedInstall(manager="uv", packages=[], ecosystem="pypi", venv_exe=venv_exe)
        return None
    if subcmd in ("run", "python", "init", "build", "publish", "export",
                  "cache", "version", "generate-shell-completion", "self",
                  "pip", "venv"):
        # None of these install from the lock file — `run`/`python` execute,
        # `cache`/`version`/`venv`/`self` manage local state, `build`/`publish`
        # produce or upload artifacts, `export`/`generate-shell-completion`
        # only read. is_lockfile_install stays False (the default): scanning
        # the lock file here would gate a command that installs nothing.
        return ParsedInstall(manager="uv", packages=[], ecosystem="pypi", venv_exe=venv_exe)
    return None


# pip (optparse), pipenv and pipx (argparse) accept any UNIQUE PREFIX of a
# long option — measured: `pip install --constr c.txt`, `pipenv install --pyth
# 3.12`, `pipx install --suff x` all resolve — so an abbreviation must be
# expanded before any value-flag set is consulted, or its value is read as a
# package (which for pipenv also switched off the Pipfile.lock scan). These are
# EVERY long option at each parser level, Boolean ones included: uniqueness is
# judged against all of them. An ambiguous prefix is left alone — both parsers
# reject it (`pip install --requirem`: "ambiguous option"). uv, composer, pnpm
# and yarn reject unknown prefixes outright. Audited against: pip 25.3,
# pipenv 2026.6.2, pipx 1.14.1 (option columns of each `--help`).
_PIPENV_GLOBAL_LONG_OPTIONS = frozenset({
    "--bare", "--clear", "--envs", "--help", "--man", "--no-site-packages",
    "--py", "--pypi-mirror", "--python", "--quiet", "--rm",
    "--site-packages", "--support", "--venv", "--verbose", "--version",
    "--where",
})
_PIPENV_LONG_OPTIONS: dict[str, frozenset[str]] = {
    "install": frozenset({
        "--all", "--categories", "--clear", "--deploy", "--dev",
        "--editable", "--extra-pip-args", "--extras", "--help",
        "--ignore-pipfile", "--index", "--no-site-packages", "--pre",
        "--pypi-mirror", "--python", "--quiet", "--requirements",
        "--site-packages", "--skip-lock", "--system", "--verbose",
    }),
    "sync": frozenset({
        "--all", "--bare", "--categories", "--clear", "--dev",
        "--extra-pip-args", "--extras", "--help", "--no-site-packages",
        "--pre", "--pypi-mirror", "--python", "--quiet", "--site-packages",
        "--system", "--verbose",
    }),
    "update": frozenset({
        "--all", "--bare", "--categories", "--clear", "--dev", "--dry-run",
        "--editable", "--extra-pip-args", "--extras", "--help",
        "--ignore-pipfile", "--index", "--lock-only", "--outdated", "--pre",
        "--pypi-mirror", "--python", "--quiet", "--requirements",
        "--skip-lock", "--system", "--verbose",
    }),
}
_PIPX_LONG_OPTIONS: dict[str, frozenset[str]] = {
    "install": frozenset({
        "--backend", "--editable", "--fetch-missing-python",
        "--fetch-python", "--force", "--global", "--help", "--include-deps",
        "--index-url", "--pip-args", "--preinstall", "--python", "--quiet",
        "--suffix", "--system-site-packages", "--verbose",
    }),
    "inject": frozenset({
        "--backend", "--editable", "--force", "--global", "--help",
        "--include-apps", "--include-deps", "--index-url", "--pip-args",
        "--quiet", "--requirement", "--system-site-packages", "--verbose",
        "--with-suffix",
    }),
    "upgrade": frozenset({
        "--backend", "--editable", "--fetch-missing-python",
        "--fetch-python", "--force", "--global", "--help",
        "--include-injected", "--index-url", "--install", "--pip-args",
        "--python", "--quiet", "--system-site-packages", "--verbose",
    }),
    "reinstall": frozenset({
        "--backend", "--fetch-missing-python", "--fetch-python", "--global",
        "--help", "--python", "--quiet", "--verbose",
    }),
    "upgrade-all": frozenset({
        "--backend", "--editable", "--force", "--global", "--help",
        "--include-injected", "--index-url", "--pip-args", "--quiet",
        "--skip", "--system-site-packages", "--verbose",
    }),
    "reinstall-all": frozenset({
        "--backend", "--fetch-missing-python", "--fetch-python", "--global",
        "--help", "--python", "--quiet", "--skip", "--verbose",
    }),
    "install-all": frozenset({
        "--backend", "--editable", "--fetch-missing-python",
        "--fetch-python", "--force", "--global", "--help", "--index-url",
        "--pip-args", "--python", "--quiet", "--system-site-packages",
        "--verbose",
    }),
}


def _expand_long_prefix(token: str, long_options: frozenset[str]) -> str:
    """Rewrite a unique-prefix abbreviation of one of `long_options` to the
    full option (`--pyth` -> `--python`, `--constr=c` -> `--constraint=c`);
    anything else — an exact option, an ambiguous or unknown prefix, a short
    option, a positional — is returned unchanged."""
    if not token.startswith("--") or token == "--":
        return token
    name, eq, value = token.partition("=")
    if name in long_options:
        return token
    matches = [o for o in long_options if o.startswith(name)]
    return matches[0] + eq + value if len(matches) == 1 else token


def _expand_long_prefix_across(
    token: str,
    by_version: tuple[frozenset[str], ...],
    value_flags: frozenset[str],
    collected: frozenset[str],
) -> str:
    """_expand_long_prefix() for a tool whose option set differs by version
    (pip), when the version in use is unknown.

    A prefix is expanded when every version that resolves it resolves it to the
    SAME option — a version where it is ambiguous or unknown rejects the command
    outright, so nothing installs there. If versions disagree, the choice
    matters only when a candidate is not value-taking or its value is collected
    (a requirements file, an editable): then it is left alone. Otherwise every
    candidate just consumes one value, and any of them gives the same parse
    (pip's `--g`: `--global-option` in 24.0, `--group` from 25).
    """
    if not token.startswith("--") or token == "--":
        return token
    name = token.partition("=")[0]
    if any(name in longs for longs in by_version):
        return token
    targets = {
        expanded.partition("=")[0]
        for longs in by_version
        if (expanded := _expand_long_prefix(token, longs)) != token
    }
    if len(targets) == 1 or (
        targets and all(t in value_flags and t not in collected for t in targets)
    ):
        return _expand_long_prefix(token, frozenset({min(targets)}))
    return token


def _canonicalise_long_options(
    args: list[str],
    expand_top: Callable[[str], str],
    top_level_value_flags: frozenset[str],
    expand_by_subcommand: dict[str, Callable[[str], str]],
) -> list[str]:
    """Expand abbreviated long options level by level, as argparse/optparse
    do: before the subcommand with the top-level expander, after it with that
    subcommand's own. Nothing after `--` is touched."""
    out: list[str] = []
    i = 0
    subcommand: str | None = None
    while i < len(args):
        arg = args[i]
        if arg == "--":
            out.extend(args[i:])
            break
        if subcommand is None:
            if arg.startswith("-"):
                expanded = expand_top(arg)
                out.append(expanded)
                if expanded in top_level_value_flags and i + 1 < len(args):
                    out.append(args[i + 1])
                    i += 2
                    continue
            else:
                subcommand = arg
                out.append(arg)
        else:
            expand = expand_by_subcommand.get(subcommand)
            out.append(expand(arg) if expand is not None else arg)
        i += 1
    return out


def _single_version(options: frozenset[str]) -> Callable[[str], str]:
    return lambda token: _expand_long_prefix(token, options)


_PIP_COLLECTED_FLAGS = frozenset({"-r", "--requirement", "-e", "--editable"})


def _pip_expand_general(token: str) -> str:
    return _expand_long_prefix_across(
        token, _PIP_GENERAL_LONG_OPTIONS_BY_VERSION, _PIP_GLOBAL_VALUE_FLAGS, _PIP_COLLECTED_FLAGS
    )


def _pip_expand_install(token: str) -> str:
    return _expand_long_prefix_across(
        token, _PIP_INSTALL_LONG_OPTIONS_BY_VERSION, _PIP_VALUE_FLAGS, _PIP_COLLECTED_FLAGS
    )


def _pipx_home() -> Path:
    """Return the pipx home directory, mirroring pipx's own resolution order.

    Resolution (matches pipx ≥ 1.4 on each platform):
      1. $PIPX_HOME if set
      2. Legacy ~/.local/pipx if it exists (migration fallback on Linux/macOS)
      3. Platform default: ~/.local/share/pipx on Linux (XDG user_data_dir),
         ~/pipx on Windows, ~/.local/pipx on macOS/other

    The result is validated against credential dirs and unsafe system paths.
    If PIPX_HOME points at something dangerous, fall back to the platform
    default so we fail safe rather than exposing sensitive directories.
    """
    import os
    import sys

    home = Path.home()

    # Use the same credential-dir list as the sandbox runner so both enforce a
    # consistent boundary.  Imported lazily to avoid a circular dependency.
    from packagealert.sandbox.runner import credential_dirs

    def is_credential_dir(p: Path) -> bool:
        return any(p == c or p.is_relative_to(c) for c in credential_dirs())

    override = os.environ.get("PIPX_HOME")
    if override:
        candidate = Path(override).expanduser()
        # resolve(strict=False) normalises ".." without requiring the path to exist,
        # preventing traversal bypasses like ~/.local/../.ssh/pipx passing a prefix check.
        resolved = candidate.resolve(strict=False)
        # Reject paths that land inside system dirs or credential dirs.
        _SAFE_PREFIXES = (home / ".local", home / "pipx", home / ".local" / "pipx")
        safe = any(
            resolved == p or resolved.is_relative_to(p)
            for p in _SAFE_PREFIXES
        )
        if safe and not is_credential_dir(resolved):
            return resolved
        # Fall through to platform default — log at debug level to avoid noise.
        import logging
        logging.getLogger(__name__).debug(
            "PIPX_HOME=%r is outside expected locations; using platform default", override
        )

    # Legacy path (created by older pipx or explicit prior install).
    legacy = home / ".local" / "pipx"
    if legacy.exists():
        return legacy

    # Platform default matching pipx's own logic (platformdirs user_data_dir).
    if sys.platform.startswith("linux"):
        _xdg_raw = os.environ.get("XDG_DATA_HOME", "")
        _xdg_default = home / ".local" / "share"
        if _xdg_raw:
            _xdg_candidate = Path(_xdg_raw)
            # Check is_absolute() on the raw value before resolve() — resolve(strict=False)
            # makes relative paths absolute (relative to cwd), which would bypass this check
            # when cwd happens to be under $HOME.
            # resolve(strict=False) then normalises ".." so "/home/user/../etc" is rejected.
            if _xdg_candidate.is_absolute():
                _xdg_resolved = _xdg_candidate.resolve(strict=False)
            else:
                _xdg_resolved = None
            # Require absolute path under $HOME, not inside a credential directory.
            if (
                _xdg_resolved is not None
                and _xdg_resolved.is_relative_to(home)
                and not is_credential_dir(_xdg_resolved)
            ):
                xdg_data = _xdg_resolved
            else:
                import logging
                logging.getLogger(__name__).debug(
                    "XDG_DATA_HOME=%r is not a safe absolute path under $HOME; using default", _xdg_raw
                )
                xdg_data = _xdg_default
        else:
            xdg_data = _xdg_default
        return xdg_data / "pipx"
    if sys.platform == "win32":
        return home / "pipx"
    # macOS and other Unix
    return home / ".local" / "pipx"


def parse_pipx_args(argv: list[str]) -> ParsedInstall | None:
    if not argv or _cmd(argv[0]) != "pipx":
        return None
    # pipx's top level accepts only -h/--version, so abbreviations matter only
    # after the subcommand (`pipx install --suff x tool`).
    args = _canonicalise_long_options(
        argv[1:], _single_version(frozenset({"--help", "--version"})), frozenset(),
        {sub: _single_version(opts) for sub, opts in _PIPX_LONG_OPTIONS.items()},
    )
    if not args:
        return None
    subcmd = args[0]
    if subcmd in ("install", "upgrade", "reinstall"):
        # `install`/`upgrade` take ONE OR MORE packages (pipx's own parser:
        # nargs="+"); checking only the first let `pipx install black evil`
        # install `evil` unchecked.
        packages = _positionals(args[1:], _PIPX_VALUE_FLAGS)
        home = Path.home()
        return ParsedInstall(
            manager="pipx", packages=packages, ecosystem="pypi", venv_exe=argv[0],
            extra_write_home_dirs=[
                _pipx_home() / "venvs",
                home / ".local" / "bin",
            ],
        )
    if subcmd in ("inject",):
        positionals = _positionals(args[1:], _PIPX_VALUE_FLAGS)
        venv_name = positionals[0] if positionals else None
        packages = positionals[1:]
        # `-r FILE` names packages to inject; its value is skipped as a
        # package above and scanned as a requirements file here.
        req_files = _value_flag_args(args[1:], frozenset({"-r", "--requirement"}))
        home = Path.home()
        return ParsedInstall(
            manager="pipx", packages=packages, ecosystem="pypi", venv_exe=argv[0],
            extra_write_home_dirs=[
                _pipx_home() / "venvs",
                home / ".local" / "bin",
            ],
            target_env_name=venv_name,
            req_files=req_files,
        )
    if subcmd in ("upgrade-all", "reinstall-all", "install-all"):
        # Packages are unknown but the command installs/upgrades tool venvs —
        # sandbox it with the full venvs dir writable so no install escapes.
        home = Path.home()
        return ParsedInstall(
            manager="pipx", packages=[], ecosystem="pypi", venv_exe=argv[0],
            extra_write_home_dirs=[
                _pipx_home() / "venvs",
                home / ".local" / "bin",
            ],
        )
    if subcmd in ("run", "uninstall", "uninstall-all", "list", "environment",
                  "ensurepath", "completions"):
        return None
    return None


# Composer options that consume the next argument when given as `--opt VALUE`
# (they are shown as `--opt=VALUE`; Symfony Console accepts both, and also an
# attached short value such as `-dsub`). `-d`/`--working-dir` is the only one
# composer accepts before the subcommand. Audited against: Composer 2.10.1
# `composer --help` / `composer require --help` / `install --help` /
# `update --help`.
_COMPOSER_VALUE_FLAGS = frozenset({
    "-d", "--working-dir",
    "--prefer-install", "--audit-format", "--ignore-platform-req",
    "--apcu-autoloader-prefix", "--with",
})


# Options with an OPTIONAL value (`--opt[=VALUE]` in composer's help): Symfony
# Console consumes the next argument for these when it does not start with `-`
# (the composer oracle confirms it). Audited against: Composer 2.10.1.
_COMPOSER_OPTIONAL_VALUE_FLAGS = frozenset({"--bump-after-update"})


def _composer_consumes(flag: str, nxt: str | None) -> bool:
    if flag in _COMPOSER_VALUE_FLAGS:
        return True
    return flag in _COMPOSER_OPTIONAL_VALUE_FLAGS and nxt is not None and not nxt.startswith("-")


def parse_composer_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _cmd(argv[0])
    if cmd == "composer":
        args = argv[1:]
    elif cmd in ("php", "php8", "php7") and len(argv) > 1 and "composer" in _basename(argv[1]):
        args = argv[2:]
    else:
        return None
    result, _i = _dispatch_subcommand(args, _composer_consumes, _parse_composer_subcommand)
    if result is not None:
        # `-d`/`--working-dir` changes the directory composer runs in,
        # composer.json and composer.lock included.
        result.working_dir = _last_flag_value(args, frozenset({"-d", "--working-dir"}))
    return result


# Every spelling composer resolves to an install-family command (names, aliases,
# unique abbreviations), from Symfony's Application::find(). GENERATED against
# Composer 2.10.1 by tests/fixtures/argv_oracles/generate_composer_commands.php.
_COMPOSER_COMMANDS: dict[str, str] = {
    "g": "global",
    "gl": "global",
    "glo": "global",
    "glob": "global",
    "globa": "global",
    "global": "global",
    "i": "install",
    "ins": "install",
    "inst": "install",
    "insta": "install",
    "instal": "install",
    "install": "install",
    "r": "require",
    "req": "require",
    "requ": "require",
    "requi": "require",
    "requir": "require",
    "require": "require",
    "u": "update",
    "up": "update",
    "upd": "update",
    "upda": "update",
    "updat": "update",
    "update": "update",
    "upg": "update",
    "upgr": "update",
    "upgra": "update",
    "upgrad": "update",
    "upgrade": "update",
}


def _parse_composer_subcommand(args: list[str]) -> ParsedInstall | None:
    """Parse `args`, which start at composer's subcommand. The command is
    resolved as composer itself resolves it (`i`, `req`, `upg`, …); an
    unrecognised spelling used to parse to None and run ungated."""
    if not args:
        return None
    subcmd = _COMPOSER_COMMANDS.get(args[0], args[0])
    if subcmd == "global":
        # `composer global <cmd>` runs <cmd> in COMPOSER_HOME: a global
        # install, handled like `npm install -g` (pre-flight on the named
        # packages, not sandboxed). It used to parse to None and run with no
        # pre-flight at all. The lock file it acts on is COMPOSER_HOME's, not
        # the cwd's, so it must not be read as a project lock-file install.
        nested = _parse_composer_subcommand(
            args[_skip_options(args, 1, _composer_consumes):]
        )
        if nested is not None:
            nested.global_install = True
            nested.is_lockfile_install = False
        return nested
    # `--dry-run` outputs the operations but executes nothing (Composer's own
    # docs) — nothing to gate, regardless of explicit packages or
    # is_lockfile_install.
    should_gate = "--dry-run" not in args[1:]
    if subcmd == "require":
        packages = _positionals_by(args[1:], _composer_consumes)
        return ParsedInstall(
            manager="composer", packages=packages, ecosystem="packagist",
            should_gate=should_gate,
        )
    if subcmd in ("update", "upgrade"):
        # `composer update <pkg>` installs NEWER versions of exactly the named
        # packages (UpdateCommand's setUpdateAllowList), so those must be
        # checked — the current composer.lock still holds the old ones. A bare
        # `update` re-resolves everything.
        packages = _positionals_by(args[1:], _composer_consumes)
        return ParsedInstall(
            manager="composer", packages=packages, ecosystem="packagist",
            is_lockfile_install=not packages, should_gate=should_gate,
        )
    if subcmd == "install":
        # Materialises composer.lock. Package arguments are rejected by
        # composer ("Invalid argument ... Use composer require"), so none are
        # ever installed this way.
        return ParsedInstall(
            manager="composer", packages=[], ecosystem="packagist", is_lockfile_install=True,
            should_gate=should_gate,
        )
    return None


# pipenv options that consume the next argument, before the subcommand
# (`--pypi-mirror`, `--python`) or after it. `-e`/`--editable` and
# `-r`/`--requirements` are listed too, so their values are never mistaken for
# package names — parse_pipenv_args() then reads both back explicitly, since
# each names something that IS installed. Audited against: pipenv 2026.6.2
# `pipenv --help` / `pipenv install --help` / `sync --help` / `update --help`.
_PIPENV_VALUE_FLAGS = frozenset({
    "--pypi-mirror", "--python",
    "--categories", "--extra-pip-args", "--extras", "-i", "--index",
    "-e", "--editable", "-r", "--requirements",
})


def parse_pipenv_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _cmd(argv[0])
    if cmd == "pipenv":
        args = argv[1:]
    elif cmd in ("python", "python3") and len(argv) > 1 and "pipenv" in _basename(argv[1]):
        args = argv[2:]
    else:
        return None
    # Expand abbreviated long options first: `pipenv install --pyth 3.12` read
    # "3.12" as a package, which also switched off the Pipfile.lock scan.
    args = _canonicalise_long_options(
        args, _single_version(_PIPENV_GLOBAL_LONG_OPTIONS), _PIPENV_VALUE_FLAGS,
        {sub: _single_version(opts) for sub, opts in _PIPENV_LONG_OPTIONS.items()},
    )
    result, _i = _dispatch_subcommand(
        args, _in_set(_PIPENV_VALUE_FLAGS), _parse_pipenv_subcommand
    )
    return result


def _parse_pipenv_subcommand(args: list[str]) -> ParsedInstall | None:
    """Parse `args`, which start at pipenv's subcommand."""
    if not args:
        return None
    subcmd = args[0]
    # venv_exe is intentionally None for pipenv: argv[0] is the Python that runs
    # the pipenv tool itself (e.g. pipx's venv), not the project venv that pipenv
    # manages. The project venv path isn't known until pipenv resolves it at runtime.
    if subcmd in ("install", "sync"):
        # An option's VALUE is not a package: `pipenv install --python 3.12`
        # used to yield packages ["3.12"], which also switched off the
        # Pipfile.lock scan below. Editable paths ARE installed, so they stay
        # packages; requirement files are scanned as such.
        rest = args[1:]
        packages = (
            _positionals(rest, _PIPENV_VALUE_FLAGS)
            + _value_flag_args(rest, frozenset({"-e", "--editable"}))
        )
        req_files = _value_flag_args(rest, frozenset({"-r", "--requirements"}))
        # A bare `pipenv install`/`sync` (no explicit packages or requirement
        # files) installs the existing Pipfile.lock in full — that case should
        # scan it. An explicit `pipenv install requests` already carries its
        # own package name and does not need the lock-file branch at all.
        return ParsedInstall(
            manager="pipenv", packages=packages, ecosystem="pypi", venv_exe=None,
            req_files=req_files,
            is_lockfile_install=not packages and not req_files,
        )
    if subcmd == "update":
        # `pipenv update` resolves/re-locks and then always syncs
        # (installs) the result into the environment — a real install of
        # the resulting lock file's contents. Exception: `--dry-run` and
        # `--outdated` both route entirely to do_outdated() in pipenv's own
        # do_update() (dry-run sets outdated=True), which only lists
        # updatable packages and never locks or syncs anything — nothing to
        # gate regardless of is_lockfile_install.
        is_report_only = "--dry-run" in args[1:] or "--outdated" in args[1:]
        # `pipenv update <pkg>` installs a NEW version of the named packages,
        # so those are what must be checked — the lock file still holds the
        # old one. A bare `update` re-locks and syncs everything.
        rest = args[1:]
        packages = (
            _positionals(rest, _PIPENV_VALUE_FLAGS)
            + _value_flag_args(rest, frozenset({"-e", "--editable"}))
        )
        req_files = _value_flag_args(rest, frozenset({"-r", "--requirements"}))
        return ParsedInstall(
            manager="pipenv", packages=packages, ecosystem="pypi", venv_exe=None,
            req_files=req_files,
            is_lockfile_install=not packages and not req_files,
            should_gate=not is_report_only,
        )
    if subcmd == "upgrade":
        # Unlike `update`, `upgrade` only re-resolves the named (or
        # Pipfile-modified) packages and rewrites Pipfile.lock — it never
        # calls pipenv's sync/install routine. Scanning the current lock
        # file here would gate a command that installs nothing. Not a
        # lockfile-install case.
        return ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi", venv_exe=None)
    if subcmd == "lock":
        # Regenerates Pipfile.lock from Pipfile's declared requirements —
        # does not install anything into the environment. Scanning the
        # current (about-to-be-replaced) Pipfile.lock here would gate a
        # lock-generation operation against stale contents. Not a
        # lockfile-install case.
        return ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi", venv_exe=None)
    if subcmd in ("create", "graph", "check", "requirements",
                  "verify", "run", "shell", "scripts", "open", "uninstall",
                  "clean", "envs"):
        # None of these install anything: create/envs manage the venv itself,
        # graph/check/requirements/verify only read, run/shell execute,
        # scripts/open are utilities, and uninstall removes — scanning the
        # lock file here would gate a command that installs nothing, or
        # block a legitimate removal over a signal on the package being
        # removed.
        return ParsedInstall(manager="pipenv", packages=[], ecosystem="pypi", venv_exe=None)
    return None


# yarn 1 global options (they apply to every subcommand; `add`/`install` add
# no value-taking options of their own). Audited against: yarn 1.22.22
# `yarn --help` / `yarn add --help` / `yarn install --help`.
_YARN_VALUE_FLAGS = frozenset({
    "--cache-folder", "--cwd", "--global-folder", "--https-proxy",
    "--link-folder", "--modules-folder", "--mutex", "--network-concurrency",
    "--network-timeout", "--otp", "--preferred-cache-folder", "--proxy",
    "--registry", "--use-yarnrc",
})
# Options with an OPTIONAL value (`--prod [prod]`). yarn's commander consumes
# the next argument for these whenever it does not start with `-` — measured:
# `yarn --prod versions` consumed "versions" and ran a bare `yarn` install.
_YARN_OPTIONAL_VALUE_FLAGS = frozenset({
    "--emoji", "--prod", "--production", "--scripts-prepend-node-path",
})


# Options that make yarn print and exit instead of running a command.
_YARN_TERMINAL_FLAGS = frozenset({"-v", "--version", "-h", "--help"})


def _yarn_consumes(flag: str, nxt: str | None) -> bool:
    if flag in _YARN_VALUE_FLAGS:
        return True
    return flag in _YARN_OPTIONAL_VALUE_FLAGS and nxt is not None and not nxt.startswith("-")


def parse_yarn_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _cmd(argv[0])
    if cmd != "yarn":
        return None
    args = argv[1:]
    # A bare `yarn` (options only) is an install, but `yarn --version`/`-v`/
    # `--help` only print. Only an UNCONSUMED option counts: measured, yarn
    # reads `yarn --cwd --help …` as a directory named "--help", so treating
    # that token as help would let a real install run ungated.
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        if args[i] in _YARN_TERMINAL_FLAGS:
            return None
        nxt = args[i + 1] if i + 1 < len(args) else None
        i += 2 if _yarn_consumes(args[i], nxt) else 1
    result, _i = _dispatch_subcommand(args, _yarn_consumes, _parse_yarn_subcommand)
    if result is not None:
        # `--cwd` is the directory yarn runs in, package.json and yarn.lock
        # included.
        result.working_dir = _last_flag_value(args, frozenset({"--cwd"}))
    return result


def _parse_yarn_subcommand(args: list[str]) -> ParsedInstall | None:
    """Parse `args`, which start at yarn's subcommand (or are empty)."""
    if not args:
        # bare `yarn` (options only, or nothing at all) installs all deps from
        # the lockfile
        return ParsedInstall(manager="yarn", packages=[], ecosystem="npm", is_lockfile_install=True)
    subcmd = args[0]
    if subcmd == "global":
        # `yarn global add <pkg>` installs into yarn's global directory — a
        # global install, handled like `npm install -g` (pre-flight on the
        # named packages, not sandboxed). It used to parse to None and run
        # with no pre-flight at all.
        rest = args[_skip_options(args, 1, _yarn_consumes):]
        if rest[:1] in (["add"], ["upgrade"]):
            return ParsedInstall(
                manager="yarn", packages=_positionals_by(rest[1:], _yarn_consumes),
                ecosystem="npm", global_install=True,
            )
        return None
    if subcmd == "add":
        packages = _positionals_by(args[1:], _yarn_consumes)
        return ParsedInstall(manager="yarn", packages=packages, ecosystem="npm")
    if subcmd == "upgrade":
        # `yarn upgrade [pkg...]` installs NEWER versions: of the named
        # packages, or of everything.
        packages = _positionals_by(args[1:], _yarn_consumes)
        return ParsedInstall(manager="yarn", packages=packages, ecosystem="npm",
                             is_lockfile_install=not packages)
    if subcmd in ("upgrade-interactive", "upgradeInteractive"):
        # Installs whichever upgrades the user picks — unknown in advance.
        return ParsedInstall(manager="yarn", packages=[], ecosystem="npm", is_lockfile_install=True)
    if subcmd == "workspace":
        # `yarn workspace <name> <command> ...` re-runs yarn with <command> in
        # that workspace (yarn's cli: PROXY_COMMANDS workspace=2), so the
        # nested command decides. The workspace's directory comes from
        # package.json, which argv alone cannot resolve.
        return _parse_yarn_subcommand(args[2:]) if len(args) > 2 else None
    if subcmd in ("install", "dedupe"):
        return ParsedInstall(manager="yarn", packages=[], ecosystem="npm", is_lockfile_install=True)
    if subcmd == "remove":
        # Removal mutates yarn.lock, but removes a package rather than
        # installing one — scanning the lock file here would gate the very
        # dependency being removed. Not a lockfile-install case.
        return ParsedInstall(manager="yarn", packages=[], ecosystem="npm")
    return None


# pnpm options that consume the next argument, across `add`/`install`/
# `dedupe`/`fetch` (pnpm accepts them before the subcommand too). Audited
# against: pnpm 7.26.3 `pnpm add --help` / `pnpm install --help` /
# `pnpm dedupe --help` / `pnpm fetch --help`.
_PNPM_VALUE_FLAGS = frozenset({
    "-C", "--dir",
    "--changed-files-ignore-pattern", "--child-concurrency", "--filter",
    "--filter-prod", "--hoist-pattern", "--lockfile-dir", "--loglevel",
    "--modules-dir", "--network-concurrency", "--package-import-method",
    "--public-hoist-pattern", "--reporter", "--store-dir", "--test-pattern",
    "--virtual-store-dir",
})


def parse_pnpm_args(argv: list[str]) -> ParsedInstall | None:
    if not argv:
        return None
    cmd = _cmd(argv[0])
    if cmd != "pnpm":
        return None
    args = argv[1:]
    result, _i = _dispatch_subcommand(
        args, _in_set(_PNPM_VALUE_FLAGS), lambda rest: _parse_pnpm_subcommand(args, rest)
    )
    if result is not None:
        # `-C`/`--dir` changes the directory pnpm runs in; `--lockfile-dir`
        # moves pnpm-lock.yaml alone.
        result.working_dir = _last_flag_value(args, frozenset({"-C", "--dir"}))
        result.lockfile_dir = _last_flag_value(args, frozenset({"--lockfile-dir"}))
    return result


def _parse_pnpm_subcommand(all_args: list[str], args: list[str]) -> ParsedInstall | None:
    """Parse `args`, which start at pnpm's subcommand. `all_args` is the whole
    command line: pnpm accepts its options before the subcommand too
    (`pnpm -g add x`), so flags are read from it rather than from `args`."""
    if not args:
        return None
    subcmd = args[0]
    if subcmd in ("add", "install", "i"):
        packages = []
        if subcmd == "add":
            packages = _positionals(args[1:], _PNPM_VALUE_FLAGS)
        # `-g`/`--global` installs into pnpm's global store, not the project:
        # a global install, handled like `npm install -g`.
        is_global = "-g" in all_args or "--global" in all_args
        # `install`/`i` with no explicit packages materialises the existing
        # pnpm-lock.yaml in full; `add` always names its own packages.
        return ParsedInstall(
            manager="pnpm", packages=packages, ecosystem="npm",
            global_install=is_global,
            is_lockfile_install=not packages and not is_global,
        )
    if subcmd in ("update", "up", "upgrade"):
        # pnpm's own commandNames for `update`. It installs NEWER versions: of
        # the named packages, or of everything.
        packages = _positionals(args[1:], _PNPM_VALUE_FLAGS)
        return ParsedInstall(
            manager="pnpm", packages=packages, ecosystem="npm",
            global_install="-g" in all_args or "--global" in all_args,
            is_lockfile_install=not packages and not ("-g" in all_args or "--global" in all_args),
        )
    if subcmd in ("dedupe", "fetch"):
        # Both install from the existing lock file with no package names of
        # their own (dedupe re-installs with newer-compatible versions;
        # fetch populates the virtual store from it). Exception: `dedupe
        # --check` only reports whether changes are possible "without
        # installing packages or editing the lockfile" (pnpm's own docs) —
        # nothing to gate regardless of is_lockfile_install.
        is_check_only = subcmd == "dedupe" and "--check" in all_args
        return ParsedInstall(
            manager="pnpm", packages=[], ecosystem="npm",
            is_lockfile_install=True,
            should_gate=not is_check_only,
        )
    if subcmd == "import":
        # Generates pnpm-lock.yaml from a *different* manager's lockfile
        # (package-lock.json/yarn.lock) — writes only the lockfile, never
        # touches node_modules. Scanning pnpm's own (unrelated, possibly
        # nonexistent) lock file here would gate a command that installs
        # nothing. Not a lockfile-install case.
        return ParsedInstall(manager="pnpm", packages=[], ecosystem="npm")
    if subcmd in ("remove", "rm", "uninstall", "un"):
        # Removal mutates pnpm-lock.yaml, but removes a package rather than
        # installing one — scanning the lock file here would gate the very
        # dependency being removed. Not a lockfile-install case.
        return ParsedInstall(manager="pnpm", packages=[], ecosystem="npm")
    return None


def parse_npm_args(argv: list[str]) -> ParsedInstall | None:
    """Parse an npm invocation the way npm itself does.

    Options go through a port of npm's own parser (nopt over npm's config
    definitions — see packagealert.parsers.npm_argv), and the command through
    a port of npm's `deref()`, so every spelling npm accepts is handled: option
    abbreviations and shorthands (`--prefi`, `-s`, `--local`), runs of
    single-letter shorthands, and command aliases and abbreviations (`inst`,
    `isntall`, `ic`, `upd`). Approximating those rules by hand left real
    installs unrecognised, which the sandbox runner then executes unchecked.
    """
    from packagealert.parsers import npm_argv

    if not argv:
        return None
    # Node.js sets process.title, so psutil may report the full invocation as
    # a single packed argv[0] e.g. "npm install react" with empty trailing slots.
    if " " in argv[0] and argv[0].lstrip().startswith("npm"):
        argv = argv[0].split() + [a for a in argv[1:] if a]
    cmd = _cmd(argv[0])
    if cmd == "npm":
        args = argv[1:]
    elif cmd in ("node", "nodejs") and len(argv) > 1 and "npm" in _basename(argv[1]):
        # node /path/to/npm-cli.js install ...
        args = argv[2:]
    else:
        return None
    config, positionals = npm_argv.parse(args)
    if not positionals:
        return None
    command = npm_argv.deref(positionals[0])
    rest = positionals[1:]
    # npm's own flatten step: global mode is `global`, or `location=global`
    # (which wins even over --no-global).
    is_global = config.get("global") is True or config.get("location") == "global"
    # `--dry-run` reports what a command would do without doing it;
    # `--package-lock-only` only rewrites package-lock.json. Neither installs,
    # whatever the command would otherwise carry — nothing to gate.
    should_gate = not (config.get("dry-run") is True or config.get("package-lock-only") is True)
    prefix = config.get("prefix")
    # `--prefix`/`-C` sets the directory npm installs into and reads
    # package.json / package-lock.json from.
    working_dir = prefix if isinstance(prefix, str) and prefix else None
    # `--registry` and `--@scope:registry` choose where the named packages come from.
    registries = {k: v for k, v in config.items() if isinstance(v, str) and v
                  and (k == "registry" or (k.startswith("@") and k.endswith(":registry")))}

    def result(packages: list[str], lockfile: bool) -> ParsedInstall:
        return ParsedInstall(
            manager="npm", packages=packages, ecosystem="npm",
            global_install=is_global,
            # A global install's lock file is not the project's.
            is_lockfile_install=lockfile and not is_global,
            should_gate=should_gate, working_dir=working_dir, registries=registries,
        )

    if command == "install":
        # A package-less `install` materialises package-lock.json in full.
        return result(rest, lockfile=not rest)
    if command == "ci":
        # `ci` ignores any arguments and installs the lock file exactly —
        # reading them as packages also switched the lock-file scan off.
        return result([], lockfile=True)
    if command == "update":
        # `npm update <pkg>` installs a NEW version of the named packages,
        # so those are what must be checked; a bare `update` re-resolves the
        # whole tree.
        return result(rest, lockfile=not rest)
    if command == "dedupe":
        return result([], lockfile=True)
    if command == "uninstall":
        # Removal mutates package-lock.json, but removes a package rather than
        # installing one — scanning the lock file here would gate the very
        # dependency being removed. Not a lockfile-install case.
        return ParsedInstall(manager="npm", packages=[], ecosystem="npm", working_dir=working_dir)
    if command == "audit" and rest[:1] == ["fix"]:
        # Rewrites package-lock.json to non-vulnerable versions — an install
        # of (updated) dependencies, not a removal.
        return result([], lockfile=True)
    return None
