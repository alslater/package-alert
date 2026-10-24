"""pnpm 8-11's own command-line parsing, ported from @pnpm/parse-cli-args.

pnpm 8-11 parse with @pnpm/parse-cli-args over @pnpm/nopt, a fork of nopt that
adds `escapeArgs` (an argument naming one of those commands passes the rest
through unparsed). Its two passes are translated here: an exploratory pass with
the universal options plus `add`/`install`'s finds the command, and a second
pass with the universal options plus that command's own types and shorthands
parses the line. Renamed options, `recursive`, `--filter` and `install <pkg>`
are then applied as pnpm does, and pnpm 11's wrapper strips a leading `pm` and
reparses `with current`.

The tables are GENERATED from each pnpm version (_pnpm_tables.py) and nopt itself
is the shared port in npm_argv; tests/unit/test_argv_oracles.py checks every
version against what that version's own parseCliArgs() recorded.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import cache

from packagealert.parsers._pnpm_tables import PNPM_TABLES
from packagealert.parsers.npm_argv import Shorthands, Types, parse_with

_RECURSIVE_CMDS = frozenset({"recursive", "multi", "m"})
# Options pnpm 8-10 only warn about (main()'s DEPRECATED_OPTIONS); pnpm 11 has none.
_DEPRECATED_OPTIONS = frozenset({"independent-leaves", "lock", "resolution-strategy"})
_SCOPE_REGISTRY = re.compile(r"^@[a-z0-9][\w.-]*:registry$")
_BOOL: tuple[str, tuple[str, ...]] = ("single", ("Boolean",))


@dataclass
class PnpmParse:
    """What pnpm's parseCliArgs() returns, as far as package-alert uses it."""

    cmd: str | None
    params: list[str]
    options: dict[str, object] = field(default_factory=dict)
    fallback: bool = False
    # Options pnpm does not know for this command. pnpm 8-11 refuse to run a
    # command with any (outside _DEPRECATED_OPTIONS, which only warn).
    unknown: list[str] = field(default_factory=list)
    # Options given whose every value nopt's validators rejected, so pnpm's own
    # reading lacks them (a registry URL our validator cannot canonicalise as
    # pnpm's URL parser would, for one).
    dropped: list[str] = field(default_factory=list)
    # pnpm 12: the settings taken out before clap besides the registries, as
    # `--config.<key>` or a bare flag, whose effect (precedence, the directory a
    # relative path is anchored to) package-alert does not model.
    overrides: list[str] = field(default_factory=list)

    @property
    def rejected(self) -> bool:
        """pnpm exits with "Unknown option" before running anything."""
        return bool(self.unknown) and not self.fallback


@dataclass(frozen=True)
class _Tables:
    major: int
    # pnpm 11.28.7+ types `--config.<key>` as the command declares <key>, in both
    # nopt passes (configDotTypes).
    typed_config_dot: bool
    universal: Types
    universal_shorthands: Shorthands
    renamed: dict[str, str]
    fallback: str | None
    escape_args: tuple[str, ...]
    commands: dict[str, str]
    command_types: dict[str, Types]
    command_shorthands: dict[str, Shorthands]

    def long_name(self, name: str | None) -> str | None:
        return self.commands.get(name) if name else None

    def types_for(self, name: str | None) -> Types:
        return self.command_types.get(self.long_name(name) or "", {})

    def shorthands_for(self, name: str | None) -> Shorthands:
        return self.command_shorthands.get(self.long_name(name) or "", {})


def versions() -> list[str]:
    """The pnpm versions the tables were generated from, oldest first."""
    return sorted(PNPM_TABLES, key=lambda v: [int(x) for x in v.split(".")])


def _shorthands(raw: dict) -> Shorthands:
    return {k: tuple(v) for k, v in raw.items()}


@cache
def _tables(version: str) -> _Tables:
    t = PNPM_TABLES[version]
    return _Tables(
        major=int(version.split(".")[0]),
        typed_config_dot=tuple(int(x) for x in version.split(".")) >= (11, 28, 7),
        universal=t["universal"],
        universal_shorthands=_shorthands(t["universal_shorthands"]),
        renamed=t["renamed"],
        fallback=t["fallback"],
        escape_args=tuple(t["escape_args"]),
        commands=t["commands"],
        command_types=t["command_types"],
        command_shorthands={k: _shorthands(v) for k, v in t["command_shorthands"].items()},
    )


def _special_cmds(major: int) -> frozenset[str]:
    """Commands whose own arguments are passed through: SPECIALLY_ESCAPED_CMDS."""
    if major >= 11:
        return frozenset({"run", "dlx", "with"})
    if major == 10:
        return frozenset({"run", "dlx"})
    return frozenset({"run"})


def parse_cli_args(version: str, argv: list[str]) -> PnpmParse | None:
    """pnpm *version*'s parse of *argv* (the arguments after `pnpm`).

    None where pnpm exits before running a command (help, version, or a
    `with current` with nothing after it).
    """
    t = _tables(version)
    argv = list(argv)
    if t.major < 11:
        return _parse(t, argv)
    # pnpm 11's wrapper: a leading `pm` forces the built-in command, and
    # `with current <cmd>` is reparsed without those two words.
    if argv[:1] == ["pm"]:
        argv = argv[1:]
    result = _parse(t, argv)
    if result is not None and result.cmd == "with" and result.params[:1] == ["current"]:
        idx = _find_with_current_index(argv, t.universal)
        if idx < 0 or len(argv) - idx - 2 == 0:
            return None
        result = _parse(t, [*argv[:idx], *argv[idx + 2:]])
    return result


def _find_with_current_index(argv: list[str], types: Types) -> int:
    for i in range(len(argv) - 1):
        if argv[i] != "with" or argv[i + 1] != "current":
            continue
        prev = argv[i - 1] if i > 0 else None
        if prev is not None and _long_option_consumes_value(prev, types):
            continue
        return i
    return -1


def _long_option_consumes_value(token: str, types: Types) -> bool:
    if not token.startswith("--") or "=" in token:
        return False
    name = token[2:]
    if name.startswith("no-"):
        return False
    kind, names = types.get(name, (None, ()))
    return not (kind is not None and "Boolean" in names)


def _parse(t: _Tables, input_argv: list[str]) -> PnpmParse | None:
    exploratory_types: Types = {
        "filter": ("single", ("String",)), "help": _BOOL, "recursive": _BOOL,
        **t.universal, **t.types_for("add"), **t.types_for("install"),
    }
    exploratory_shorthands: Shorthands = {"r": ("--recursive",), **t.universal_shorthands}
    explored, e_remain = parse_with(input_argv, exploratory_types, exploratory_shorthands, frozenset(t.escape_args))

    recursive_used = bool(e_remain) and e_remain[0] in _RECURSIVE_CMDS
    effective = e_remain[1:] if recursive_used else e_remain
    command_name: str | None
    if t.long_name(effective[0] if effective else None) != "install" or len(effective) == 1:
        command_name = effective[0] if effective else None
    else:
        command_name = "add"
    cmd = t.long_name(command_name)
    fallback = bool(command_name and not cmd and t.fallback)
    special = _special_cmds(t.major)
    if fallback:
        cmd = command_name = t.fallback
        input_argv = [t.fallback or "", *input_argv]
    elif cmd not in special:
        if explored.get("help"):
            return None
        if t.major >= 9 and (explored.get("version") or explored.get("v")):
            return None

    types: Types = {**t.universal, **t.types_for(command_name)}
    argv = input_argv
    config_dot: list[str] = []
    if t.major >= 11 and "config" in types:
        # pnpm 11 sets `--config.*` aside and merges it back after the parse
        # (separateConfigDotArgs/mergeExtractedConfigArgs), so it overrides.
        config_dot = [a for a in argv if a.startswith("--config.")]
        argv = [a for a in argv if not a.startswith("--config.")]
    if cmd in special:
        idx = 1 + (1 if recursive_used else 0) + (-1 if fallback and t.fallback == "run" else 0)
        escape: tuple[str, ...] = (e_remain[idx],) if 0 <= idx < len(e_remain) else ()
    elif t.major >= 11:
        escape = t.escape_args if command_name in t.escape_args else ()
    else:
        escape = t.escape_args
    shorthands: Shorthands = {**t.universal_shorthands, **t.shorthands_for(command_name)}
    # pnpm 11.28.7+ also declares each `config.<key>`, so `--con` no longer abbreviates
    # `--config`, and a `--config.<key>` value is cleaned as <key>'s type.
    config_types: Types = {f"config.{k}": v for k, v in types.items()} if t.typed_config_dot else {}
    main_types: Types = {"recursive": _BOOL, **types, **config_types}
    parsed, remain = parse_with(argv, main_types, shorthands, frozenset(escape))
    options: dict[str, object] = dict(parsed)
    dropped = _clean(options, main_types)  # inside nopt, before pnpm's renames
    if config_dot:
        merged: dict[str, object] = dict(parse_with(config_dot, config_types, {})[0])
        dropped += _clean(merged, config_types)  # untyped keys get nopt's default types
        options.update(merged)
    dropped = [k.removeprefix("config.") for k in dropped]
    for key in list(options):
        target = t.renamed.get(key)
        if target:
            # pnpm 8-9 let the renamed spelling override; 10+ keep the canonical one.
            if t.major < 10 or target not in options:
                options[target] = options[key]
            del options[key]
    if cmd in special and options.get("help"):
        return None

    params = remain[1:]
    if options.get("recursive") is not True and (options.get("filter") or options.get("filter-prod") or recursive_used):
        options["recursive"] = True
        sub = t.long_name(remain[1]) if len(remain) > 1 else None
        if sub and recursive_used:
            params = params[1:]
            cmd = sub
    if cmd == "install" and params:
        cmd = "add"
    elif not cmd and options.get("recursive"):
        cmd = "recursive"
    deprecated = _DEPRECATED_OPTIONS if t.major < 11 else frozenset()
    # A scoped registry option (`--@scope:registry`) is known from pnpm 9.
    unknown = [k for k in options if k not in types and not k.startswith(("//", "config."))
               and not (t.major >= 9 and _SCOPE_REGISTRY.match(k)) and k not in deprecated]
    # normalizeOptions(): `config.<key>` is the setting <key>, the later spelling winning.
    normalized: dict[str, object] = {}
    for key, value in options.items():
        normalized[key.removeprefix("config.")] = value
    return PnpmParse(cmd=cmd, params=params, options=normalized, fallback=fallback, unknown=unknown,
                     dropped=dropped)


_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/\s]")


def _valid(value: object, name: str) -> tuple[bool, object]:
    """nopt's validator for one type name: (accepted, value as stored)."""
    if name == "Boolean":
        return (True, value) if isinstance(value, bool) else (False, value)
    if name == "null":
        return (True, None) if value is None else (False, value)
    if name.startswith("="):
        return (True, value) if value == name[1:] else (False, value)
    if name == "String":
        return (True, value) if isinstance(value, str) else (True, str(value).lower()) if isinstance(value, bool) else (False, value)
    if name == "url":
        return (True, value) if isinstance(value, str) and _URL_RE.match(value) else (False, value)
    if name == "path":
        # nopt's validatePath rejects `true`, keeps `null`, and stringifies the rest
        # as JavaScript does, so `--no-prefix` (false) is the path "false".
        if value is True:
            return False, value
        if value is None:
            return True, None
        if not isinstance(value, str):
            value = "false" if value is False else str(value)
        # nopt's validatePath expands a leading `~/` with os.homedir() ($HOME).
        home = os.environ.get("HOME")
        if home and value.startswith("~/"):
            value = os.path.join(home, value[2:])
        return True, os.path.normpath(value or ".")
    if name == "Number":
        try:
            return True, float(value) if isinstance(value, str) else value
        except ValueError:
            return False, value
    return True, value  # a type package-alert never reads (Date, Stream, ...)


_JSONABLE = {"true": True, "false": False, "null": None}


def _clean(options: dict[str, object], types: Types) -> list[str]:
    """nopt's clean() for the values package-alert reads: every string is trimmed; a
    value no type accepts is dropped; a path is resolved against the cwd; and a key
    with no type takes nopt's default types, so "true"/"false"/"null" become JSON.
    Returns the keys it dropped."""
    dropped: list[str] = []
    for key, value in list(options.items()):
        kind, names = types.get(key, (None, ()))
        if kind is None:
            if isinstance(value, str):
                options[key] = _JSONABLE.get(value.strip(), value.strip())
            continue
        candidates = [n for n in names if n != "Array"] or ["String"]
        values = value if isinstance(value, list) else [value]
        kept = []
        for v in values:
            if isinstance(v, str):
                v = v.strip()
            for name in candidates:
                ok, stored = _valid(v, name)
                if ok:
                    kept.append(stored)
                    break
        if not kept:
            del options[key]
            dropped.append(key)
        else:
            options[key] = kept if isinstance(value, list) else kept[0]
    return dropped


def native_versions() -> list[str]:
    """The pnpm 12+ versions with a table, oldest first."""
    from packagealert.parsers._pnpm_native_tables import PNPM_NATIVE_TABLES

    return sorted(PNPM_NATIVE_TABLES, key=lambda v: [int(x) for x in v.split(".")])


def _native_table(version: str) -> dict:
    from packagealert.parsers._pnpm_native_tables import PNPM_NATIVE_TABLES

    return PNPM_NATIVE_TABLES[version]


def _native_tables(version: str) -> tuple[dict, dict, dict, dict, dict, dict]:
    t = _native_table(version)
    return t["commands"], t["options"], t["shorts"], t["aliases"], t["renamed"], t["settings"]


def _parse_bool(value: str) -> bool | None:
    """pnpm 12's parse_bool(): `true`/`1` and `false`/`0`, in any case."""
    return {"true": True, "1": True, "false": False, "0": False}.get(value.lower())


def _to_kebab_case(name: str) -> str:
    """pnpm 12's to_kebab_case() (pnpm/crates/config/src/naming_cases.rs): words
    split at non-alphanumerics, lower-to-upper, letter-digit and acronym-word
    boundaries, joined with `-` and lowercased (`Registry`, `saveWorkspaceProtocol`)."""
    words: list[str] = []
    current = ""
    prev = ""
    for index, char in enumerate(name):
        if not (char.isascii() and char.isalnum()):
            if current:
                words.append(current)
            current, prev = "", ""
            continue
        following = name[index + 1] if index + 1 < len(name) else ""
        if prev and ((prev.isalpha() and char.isdigit()) or (prev.isdigit() and char.isalpha())
                     or (prev.islower() and char.isupper())
                     or (prev.isupper() and char.isupper() and following.islower())):
            words.append(current)
            current = ""
        current += char
        prev = char
    if current:
        words.append(current)
    return "-".join(words).lower()


def _setting_takes(setting: list, value: str, *, dotted: bool = False) -> bool:
    """Whether a pnpm 12 setting takes *value*: its `--<name>=<value>` form, or
    with *dotted* its `--config.<name>=<value>` form, which can take more."""
    kind, values, dotted_values = setting
    if dotted and value in dotted_values:
        return True
    if kind == "bool":
        return _parse_bool(value) is not None or value in values
    if kind == "int":
        return re.fullmatch(r"[+-]?\d+", value) is not None and -(2**31) <= int(value) < 2**31
    if kind == "uint":
        return re.fullmatch(r"\+?\d+", value) is not None and int(value) < 2**64
    return kind == "text" or value in values


def _setting_claims(setting: list, token: str | None) -> bool:
    """Whether a bare pnpm 12 setting flag takes *token*, the argument after it."""
    if token is None:
        return False
    if setting[0] == "bool":
        return _parse_bool(token) is not None
    if setting[0] == "text":
        return not token.startswith("-")
    return _setting_takes(setting, token)


class _NativeArity:
    """Every pnpm 12 command's option arities merged, for the scans that run
    before the command is known: an option that takes a value for one command
    and not another counts as a flag, so a command name is never taken as a
    value (flag_relocation.rs)."""

    def __init__(self, version: str) -> None:
        self.commands, options, shorts_by_scope, aliases_by_scope, _renamed, self.settings = _native_tables(version)
        self.kinds: dict[str, str] = {}
        for table in options.values():
            for name, kind in table.items():
                self.kinds[name] = kind if self.kinds.get(name, kind) == kind else "flag"
        self.shorts = {k: v for table in shorts_by_scope.values() for k, v in table.items()}
        self.aliases = {k: v for table in aliases_by_scope.values() for k, v in table.items()}

    def width(self, arg: str, following: str | None, *, setting_first: bool = False) -> int:
        """How many arguments the option *arg* occupies. With *setting_first* (the
        scans before extraction, parse_boundary.rs), a Boolean setting claims a
        following `true`/`false` even where a command also declares the name."""
        if "=" in arg and arg.startswith("--") or arg.startswith("--config."):
            return 1
        if setting_first and arg.startswith("--") and following is not None \
                and self.settings.get(arg[2:], [""])[0] == "bool" and _parse_bool(following) is not None:
            return 2
        if arg.startswith("--"):
            name = self.aliases.get(arg, arg)
            kind = self.kinds.get(name)
            if kind not in (None, "flag", "optional"):
                return 2
            setting = self.settings.get(arg[2:]) if kind is None else None
            return 2 if setting is not None and _setting_claims(setting, following) else 1
        # A short cluster takes the next argument when its first value-taking
        # short is its last character.
        for j in range(1, len(arg)):
            kind = self.kinds.get(self.shorts.get("-" + arg[j], ""))
            if kind not in (None, "flag", "optional"):
                return 2 if j == len(arg) - 1 else 1
        return 1


def _native_command(argv: list[str], arity: _NativeArity, *, setting_first: bool = False) -> tuple[str | None, int]:
    """(the command pnpm 12 finds in *argv*, its index), or (None, -1).

    `install` naming a package is `add` (install_as_add.rs): that is the
    grammar its options are checked against.
    """
    commands = arity.commands
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            return None, -1
        if arg.startswith("-") and len(arg) > 1:
            i += arity.width(arg, argv[i + 1] if i + 1 < len(argv) else None, setting_first=setting_first)
            continue
        if arg in ("pm", *_RECURSIVE_CMDS):
            i += 1
            continue
        cmd = commands.get(arg)
        if cmd == "install" and _native_names_a_package(argv, i + 1, arity):
            cmd = "add"
        return cmd, i
    return None, -1


def _native_next_positional(argv: list[str], start: int, arity: _NativeArity) -> int | None:
    """The index of the first non-option argument from *start*, stepping over
    options and the values they take (next_positional() in parse_boundary.rs)."""
    i = start
    while i < len(argv):
        arg = argv[i]
        if arg == "--" or not (arg.startswith("-") and len(arg) > 1):
            return i
        i += arity.width(arg, argv[i + 1] if i + 1 < len(argv) else None, setting_first=True)
    return None


def _native_names_a_package(argv: list[str], start: int, arity: _NativeArity) -> bool:
    i = start
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            return i + 1 < len(argv)
        if arg.startswith("-") and len(arg) > 1:
            i += arity.width(arg, argv[i + 1] if i + 1 < len(argv) else None)
            continue
        return True
    return False


def _native_extract(argv: list[str], end: int, claimed: set[str], settings: dict,
                    options: dict[str, object], overrides: list[str]) -> list[str]:
    """*argv* with what pnpm 12 takes out before clap (ConfigOverrides::extract):
    each `--config.<key>=<value>`, and each setting spelled as a bare flag that
    the command does not declare, with the value it claims. Every token before
    *end* is looked at on its own, so one between an option and its value goes
    too. A registry setting is recorded in *options*, every other one taken out
    in *overrides*."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        following = argv[i + 1] if i + 1 < min(end, len(argv)) else None
        if i >= end or not arg.startswith("--"):
            out.append(arg)
            i += 1
            continue
        if arg.startswith("--config."):
            key, eq, value = arg[len("--config."):].partition("=")
            if not eq or not key:
                i += 1  # malformed: dropped
                continue
            setting = settings.get(key)
            if setting is not None and not _setting_takes(setting, value, dotted=True):
                out.append(arg)  # left for clap, which rejects it
            elif key in ("state-dir", "store-dir"):
                out.append(f"--{key}={value}")
            elif _to_kebab_case(key) == "registry":
                options["registry"] = value  # set() matches settings in kebab case
            elif key.startswith("@") and key.endswith(":registry") and "/" not in key and len(key) > len("@:registry"):
                options[key] = value
            else:
                overrides.append(key)
            i += 1
            continue
        name, eq, value = arg[2:].partition("=")
        negated = name.removeprefix("no-") if name.startswith("no-") and not eq else None
        if negated is not None and negated not in claimed and settings.get(negated, [""])[0] == "bool":
            i += 1
            continue
        setting = settings.get(name) if name not in claimed else None
        if setting is None:
            out.append(arg)
            i += 1
        elif eq:
            if _setting_takes(setting, value):
                overrides.append(name)
            else:
                out.append(arg)
            i += 1
        elif setting[0] == "bool":
            overrides.append(name)
            i += 2 if following is not None and _parse_bool(following) is not None else 1
        elif _setting_claims(setting, following):
            overrides.append(name)
            i += 2
        else:
            out.append(arg)  # its value is missing: left for clap
            i += 1
    return out


def _native_relocate(argv: list[str], arity: _NativeArity, options_by_scope: dict, aliases_by_scope: dict) -> list[str]:
    """*argv* with each option before the command that the command owns, and the
    top level does not, moved to just after the command, order kept
    (flag_relocation.rs). Values are stepped over with the merged arities."""
    target, at = _native_command(argv, arity)
    if target is None or at <= 0:
        return argv
    own = options_by_scope.get(target, {})
    top = options_by_scope[""]
    kept: list[str] = []
    moved: list[str] = []
    i = 0
    while i < at:
        arg = argv[i]
        if not (arg.startswith("-") and len(arg) > 1):
            kept.append(arg)
            i += 1
            continue
        width = arity.width(arg, argv[i + 1] if i + 1 < len(argv) else None)
        if arg.startswith("--"):
            name = arg.partition("=")[0]
            name = aliases_by_scope.get(target, {}).get(name) or aliases_by_scope[""].get(name, name)
            negated = "--" + name[5:] if name.startswith("--no-") else None
            owned = (name in own or (negated is not None and own.get(negated) == "flag")) and name not in top
        else:
            # A cluster moves as a whole when every short in it, up to its first
            # value-taking one, is known and at least one belongs to the command.
            names = []
            for c in arg[1:]:
                short = arity.shorts.get("-" + c)
                if short is None:
                    names = []
                    break
                names.append(short)
                if arity.kinds.get(short) not in (None, "flag", "optional"):
                    break
            owned = bool(names) and any(n in own and n not in top for n in names)
        (moved if owned else kept).extend(argv[i:i + width])
        i += width
    return [*kept, argv[at], *moved, *argv[at + 1:]]


def _native_shadowed(argv: list[str], renamed: dict[str, str], arity: _NativeArity) -> set[str]:
    """The renamed options pnpm 12 drops because their canonical one is also
    given (renamed_options.rs): `--prefix` beside `--dir` or `-C`. Values are
    stepped over, and a short cluster ends at its first value-taking short."""
    given: set[str] = set()
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            break
        if arg.startswith("--"):
            given.add(arg.partition("=")[0])
        elif arg.startswith("-") and len(arg) > 1:
            for c in arg[1:]:
                name = arity.shorts.get("-" + c, "")
                given.add(name)
                if arity.kinds.get(name) not in (None, "flag", "optional"):
                    break
        if arg.startswith("-") and len(arg) > 1:
            i += arity.width(arg, argv[i + 1] if i + 1 < len(argv) else None)
        else:
            i += 1
    return {alias for alias, canonical in renamed.items() if alias in given and canonical in given}


def parse_native(argv: list[str], *, lenient: bool = False, pnpm_version: str | None = None) -> PnpmParse | None:
    """pnpm 12+'s parse of *argv*: its pre-clap rewrites, then clap's rules
    over the generated table for *pnpm_version* (default: the newest).

    The rewrites (pnpm/crates/cli/src/lib.rs), in pnpm's order: `pm` is
    stripped; `--config.<key>=<value>` and the settings given as bare flags
    (`--ignore-scripts`, `--global-dir <dir>`) are taken out, each with the
    value it claims; a flag gets a hidden `--no-<flag>`; `--silent` and a lone
    `-s` are `--reporter=silent`; `--<flag>=<bool>` is accepted; a renamed
    option (`--prefix`) is dropped when its canonical one is also given; an
    option before the command that the command owns is moved after it; and
    `install <pkg>` is `add`.

    Then clap: no abbreviations; a value option takes the next token (one
    starting with `-` is an error), a multi-value option every value that
    follows; an unknown option or command is an error (None: nothing runs).
    `true`/`false` after a flag is a positional.

    With *lenient*, an option the table does not know is skipped instead of
    refused, and an unknown command directly after it is read as its value:
    a best guess at a command no reading accepts, used only to gate one that
    pnpm 12 might run (see parse_pnpm_args()).
    """
    pnpm_version = pnpm_version or native_versions()[-1]
    optional_values: dict[str, list[str]] = _native_table(pnpm_version)["optional_values"]
    commands, options_by_scope, shorts_by_scope, aliases_by_scope, renamed, settings = _native_tables(pnpm_version)
    arity = _NativeArity(pnpm_version)
    options: dict[str, object] = {}
    target, at = _native_command(argv, arity, setting_first=True)
    end = argv.index("--") if "--" in argv else len(argv)
    # The spawned pnpm's arguments, after `with <version>`, are its own; `with
    # current` is followed to the command inside it (parse_boundary.rs).
    # Where pnpm stops owning argv (parse_boundary.rs): after a positional naming no
    # command (the `pnpm <script>` fallback), even one extraction will later make an
    # option's value; after the next positional of run/exec/dlx; after a script
    # shortcut (test/start/stop); and after a versioned `with`.
    def forwarded_from(cmd: str | None, index: int) -> int | None:
        if index < 0:
            return None
        if cmd is None or cmd in ("test", "start", "stop"):
            return index + 1
        if cmd in ("run", "exec", "dlx"):
            following = _native_next_positional(argv, index + 1, arity)
            return following + 1 if following is not None else None
        return None

    boundary = forwarded_from(target, at)
    if boundary is not None:
        end = min(end, boundary)
    inner, inner_at = target, at
    while inner == "with":
        version = _native_next_positional(argv, inner_at + 1, arity)
        if version is None:
            break
        if argv[version] != "current":
            end = min(end, version + 1)
            break
        nested, nested_at = _native_command(argv[version + 1:], arity, setting_first=True)
        inner, inner_at = nested, version + 1 + nested_at if nested_at >= 0 else -1
        boundary = forwarded_from(inner, inner_at)
        if boundary is not None:
            end = min(end, boundary)
    # `with current` is rewritten in the same process after extraction, so its
    # inner command's settings are taken out too, against with's own options.
    claimed = set() if target == "with" else {
        n[2:] for n in (*options_by_scope.get(target or "", {}), *aliases_by_scope.get(target or "", {}))}
    overrides: list[str] = []
    argv = _native_extract(argv, end, claimed, settings, options, overrides)
    argv = _native_relocate(argv, arity, options_by_scope, aliases_by_scope)
    target, _at = _native_command(argv, arity)
    shadowed = _native_shadowed(argv, renamed, arity)
    cmd: str | None = None
    params: list[str] = []
    after_unknown = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            params.extend(argv[i + 1:])
            break
        scope = cmd or target or ""
        table = {**options_by_scope[""], **options_by_scope.get(scope, {})}
        follows_unknown, after_unknown = after_unknown, False
        if arg == "--silent" or (arg == "-s" and scope != "run"):
            options["reporter"] = "silent"
            i += 1
            continue
        if arg.startswith("-") and len(arg) > 1:
            if arg.startswith("--"):
                name, eq, value = arg.partition("=")
            else:
                # A cluster of shorts (`-rC sub`, `-rCsub`): each Boolean one is
                # set, and the first that takes a value takes the rest of the
                # cluster (less a leading `=`), or the next argument.
                eq, value = "", ""
                for j in range(1, len(arg)):
                    short = "-" + arg[j]
                    name = shorts_by_scope.get(scope, {}).get(short) or shorts_by_scope[""].get(short, "")
                    if table.get(name) != "flag" or j == len(arg) - 1:
                        rest = arg[j + 1:]
                        if rest:
                            eq, value = "=", rest.removeprefix("=")
                            if not value and table.get(name) not in (None, "flag"):
                                return None  # `-C=`: clap requires a value
                        break
                    options[name[2:]] = True
            drop = name in shadowed
            name = aliases_by_scope.get(scope, {}).get(name) or aliases_by_scope[""].get(name, name)
            kind = table.get(name)
            if drop:
                # drop_shadowed_aliases() removes the alias and the value it would take
                # before clap validates anything, so a missing value is no error.
                i += 1 if eq or kind in ("flag", "optional", None) else 2
                continue
            if kind is None and name.startswith("--no-") \
                    and table.get("--" + name[5:]) == "flag" and name[5:] not in ("help", "version"):
                # A hidden negation; `--no-<flag>=<bool>` is `--<flag>` when false.
                negated = _parse_bool(value) if eq else True
                if negated is None:
                    return None  # clap: a flag takes no value
                options[name[5:]] = not negated
                i += 1
                continue
            if kind is None:
                if not lenient:
                    return None  # clap: unexpected argument
                after_unknown = not eq
                i += 1
                continue
            store = {} if drop else options
            if kind == "optional":
                allowed = optional_values.get(name)
                if eq and allowed and value not in allowed:
                    return None  # clap: invalid value
                store[name[2:]] = value if eq else True
            elif kind == "flag":
                if eq and _parse_bool(value) is None:
                    return None  # clap: a flag takes no value
                store[name[2:]] = _parse_bool(value) if eq else True
            elif eq:
                store[name[2:]] = value
            elif kind == "multi":
                taken = []
                while i + 1 < len(argv) and (argv[i + 1] == "-" or not argv[i + 1].startswith("-")):
                    i += 1
                    taken.append(argv[i])  # a lone `-` is a value to clap
                if not taken:
                    return None
                store[name[2:]] = taken
            else:
                if i + 1 >= len(argv) or (argv[i + 1].startswith("-") and argv[i + 1] != "-"):
                    return None  # clap: a value is required
                i += 1
                store[name[2:]] = argv[i]
            i += 1
            continue
        if cmd is None and lenient and follows_unknown and arg not in commands:
            i += 1  # the value of the unknown option before it
            continue
        if cmd is None:
            if arg in ("pm", *_RECURSIVE_CMDS):
                if arg != "pm":
                    options["recursive"] = True
                i += 1
                continue
            cmd = commands.get(arg)
            if cmd is None:
                return None  # clap: unrecognized subcommand
            if cmd == "install" and target == "add":
                cmd = "add"  # `install <pkg>` is checked against add's options
            if cmd == "with":
                # The version is the next positional; with's own options may precede it.
                version = _native_next_positional(argv, i + 1, arity)
                if version is None or argv[version] == "--":
                    return None
                if argv[version] == "current":  # reparsed here, outer options kept
                    inner = parse_native([*argv[:i], *argv[i + 1:version], *argv[version + 1:]], lenient=lenient,
                                         pnpm_version=pnpm_version)
                    if inner is not None:
                        for key, value in options.items():  # what extraction took out
                            inner.options.setdefault(key, value)
                        inner.overrides = [*overrides, *inner.overrides]
                    return inner
                params.extend(argv[version:])  # the version, then the spawned pnpm's own arguments
                break
        else:
            params.append(arg)
        i += 1
    if cmd is None:
        return None
    return PnpmParse(cmd=cmd, params=params, options=options, overrides=overrides)
