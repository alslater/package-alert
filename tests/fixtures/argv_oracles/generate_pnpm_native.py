"""Regenerate the parsing table for pnpm 12+, the native Rust (clap) rewrite (#93).

clap has no parse-only entry point, but it validates options before running
anything: `pnpm <cmd> <option> --help` reports "a value is required" for an
option that takes a value and prints help for one that does not, so no command
runs. The command list, aliases, option spellings, short forms and multi-value
options (`<CPU>...`, which take every following value) come from pnpm's own
`--help`; whether each option takes a value comes from that probe.

Help omits what pnpm 12 accepts without declaring it to clap: hidden aliases
(`--prefix` for `--dir`) and the settings pnpm takes out of argv before clap
(`--ignore-scripts`, `--global-dir <dir>`; pnpm/crates/cli/src/config_overrides).
Every option name pnpm 8-11 know (_pnpm_tables.py) is probed for those, each
probe ending in an invalid `--zzbogus` so clap always errors and nothing runs:
"a value is required for '--X'" is a value option X; an accepted name that
clap reports as "unexpected value ... for '--X'" when given `=maybe` is a
flag X; another accepted name is a Boolean setting (which also claims a
following `true`/`false`); and a rejected one is a value setting if it claims
the token after it — free text, a number, or one of pnpm 8-11's enum values.

    python tests/fixtures/argv_oracles/generate_pnpm_native.py <dir>/node_modules/pnpm ...

Give every pnpm 12+ release whose table differs (the latest, and the last release
before each parse change); parse_pnpm_args() reads them all.

writes packagealert/parsers/_pnpm_native_tables.py.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = ROOT / "packagealert" / "parsers" / "_pnpm_native_tables.py"
INSTALLING = {"add", "install", "update", "dedupe", "fetch", "deploy", "ci", "install-test",
              "unlink", "remove", "import", "self-update", "recursive", "with", "pipeline"}

_COMMAND = re.compile(r"^  ([a-z][a-z0-9-]*)\s{2,}.*?(?:\[alias(?:es)?: ([^\]]+)\])?\s*$")
_OPTION = re.compile(r"^\s+(?:(-[A-Za-z]), )?(--[a-z][a-z0-9-]*)(?:\s+<[^>]+>(\.\.\.)?|\[=<[^>]+>\])?\s*$")
_ALIAS = re.compile(r"^\s+\[alias(?:es)?: (--[^\]]+)\]")


def _help(pnpm: Path, args: list[str], env: dict[str, str], cwd: Path) -> str:
    r = subprocess.run([str(pnpm), *args], env=env, cwd=cwd, capture_output=True, text=True, timeout=30, check=False)
    return r.stdout + r.stderr


def _commands(text: str) -> dict[str, str]:
    commands: dict[str, str] = {}
    section = False
    for line in text.splitlines():
        if line.startswith("Commands:"):
            section = True
            continue
        if section and line and not line.startswith(" "):
            break
        m = _COMMAND.match(line) if section else None
        if m:
            commands[m.group(1)] = m.group(1)
            for alias in (m.group(2) or "").split(","):
                if alias.strip():
                    commands[alias.strip()] = m.group(1)
    return commands


def _options(text: str) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """(--name -> "multi"/"maybe-value"/"flag", -x -> --name, --alias -> --name) from help."""
    options: dict[str, str] = {}
    shorts: dict[str, str] = {}
    aliases: dict[str, str] = {}
    last: str | None = None
    for line in text.splitlines():
        m = _OPTION.match(line)
        if m:
            short, name, multi = m.groups()
            options[name] = "multi" if multi else ("maybe-value" if "<" in line or "[=" in line else "flag")
            if short:
                shorts[short] = name
            last = name
            continue
        a = _ALIAS.match(line)
        if a and last:
            for alias in a.group(1).split(","):
                aliases[alias.strip()] = last
    return options, shorts, aliases


def _takes_value(pnpm: Path, cmd: list[str], option: str, env: dict[str, str], cwd: Path) -> bool:
    return "a value is required for" in _help(pnpm, [*cmd, option, "--help"], env, cwd)


def _kind_of(pnpm: Path, scope: list[str], name: str, help_kind: str, env: dict[str, str], cwd: Path,
             optional_values: dict[str, list[str]]) -> str:
    """'value', 'multi', 'optional' (`--color[=<COLOR>]`: a value only when
    attached, its accepted values recorded in *optional_values*) or 'flag'."""
    if _takes_value(pnpm, scope, name, env, cwd):
        return "multi" if help_kind == "multi" else "value"
    if help_kind != "maybe-value":
        return "flag"
    out = _help(pnpm, [*scope, f"{name}=zzbad", "--zzbogus"], env, cwd)
    m = re.search(r"expected one of: ([^\n]+)", out)
    if m:
        # The list clap prints is not exhaustive (--color also takes true/false):
        # Boolean spellings are probed too.
        listed = {v.strip() for v in m.group(1).split(",")}
        listed.update(v for v in ("true", "false", "1", "0", "yes", "no")
                      if "unexpected argument '--zzbogus'" in _help(pnpm, [*scope, f"{name}={v}", "--zzbogus"], env, cwd))
        optional_values[name] = sorted(listed)
    else:
        optional_values[name] = []
    return "optional"


_VALUE_REQUIRED = re.compile(r"a value is required for '(--[a-z0-9-]+) <[^>]+>(\.\.\.)?'")
_SOURCE = "https://raw.githubusercontent.com/pnpm/pnpm/v{version}/pnpm/crates/{path}"


def _source(version: str, path: str) -> str:
    import urllib.request

    with urllib.request.urlopen(_SOURCE.format(version=version, path=path), timeout=30) as resp:
        return resp.read().decode()


def _source_settings(version: str) -> dict[str, list[str]]:
    """Setting names pnpm 12 takes out of argv (config_overrides/tokens.rs), each
    with its enum's values (config/src/setting_types.rs): candidates for probing."""
    tokens = _source(version, "cli/src/config_overrides/tokens.rs")
    types = _source(version, "config/src/setting_types.rs") + _source(version, "config/src/setting_types/workspace.rs")
    # An enum deserialised by hand names its spellings only as string literals
    # (`"deep"`, `"rolling"`); each is a candidate, and the probes decide.
    literals = sorted(set(re.findall(r'"([a-z][a-z0-9-]*)"', types)))
    enums: dict[str, list[str]] = {}
    for rename, name, body in re.findall(
            r'rename_all = "([a-z-]+)"\)\]\s*pub enum (\w+) \{([^}]*)\}', types):
        variants = re.findall(r"^\s*([A-Z]\w*)", body, re.MULTILINE)
        kebab = [re.sub(r"(?<!^)([A-Z])", r"-\1", v).lower() for v in variants]
        enums[name] = kebab if rename == "kebab-case" else [v.lower() for v in variants]
    block = tokens[tokens.index("BARE_SETTING_FLAGS"):]
    block = block[:block.index("];")]
    found: dict[str, list[str]] = {}
    for name, arity in re.findall(r'\(\s*"([a-z-]+)",\s*(SettingArity::[^)]*\)?)', block):
        enum = re.search(r"is_enum::<(\w+)>", arity)
        found[name] = (enums.get(enum.group(1)) or literals) if enum else []
    return found


def _source_renamed(version: str) -> dict[str, str]:
    """pnpm 12's renamed options (cli/src/renamed_options.rs): an alias dropped when
    its canonical option is also given, wherever each appears."""
    src = _source(version, "cli/src/renamed_options.rs")
    return {f"--{a}": f"--{c}" for a, c in
            re.findall(r'RenamedOption \{ alias: "([a-z-]+)", canonical_long: "([a-z-]+)"', src)}
_UNEXPECTED_VALUE = re.compile(r"unexpected value '[^']*' for '(--[a-z0-9-]+)")


def _candidates() -> dict[str, list[str]]:
    """Every long option pnpm 8-11 know -> its enum values (empty unless an enum)."""
    sys.path.insert(0, str(ROOT))
    from packagealert.parsers._pnpm_tables import PNPM_TABLES

    found: dict[str, list[str]] = {}
    for t in PNPM_TABLES.values():
        for types in (t["universal"], *t["command_types"].values()):
            for name, (_kind, names) in types.items():
                values = found.setdefault(name, [])
                values.extend(n[1:] for n in names if n.startswith("=") and n[1:] not in values)
    found.pop("help", None)
    found.pop("version", None)
    return found


def _hidden(pnpm: Path, scope: list[str], name: str, env: dict[str, str], cwd: Path) -> tuple[str, str, str] | None:
    """("option", canonical, 'value'|'multi'|'flag') for a clap option *name* spells
    at *scope*, ("accepted", "", "") for a name pnpm takes but clap does not
    declare (a Boolean setting), or None.

    `--<name> --help` prints help, so nothing runs, unless *name* takes a value
    ("a value is required for '--X'") or nothing accepts it ("unexpected
    argument"). A single trailing invalid option cannot tell these apart: clap
    reports an unknown argument before a missing value.
    """
    out = _help(pnpm, [*scope, f"--{name}", "--help"], env, cwd)
    if m := _VALUE_REQUIRED.search(out):
        return "option", m.group(1), "multi" if m.group(2) else "value"
    if out.lstrip().lower().startswith("error"):
        return None
    # Accepted without a value: clap names a flag it was given a value for;
    # a setting given a non-Boolean value is left for clap as a whole token.
    if m := _UNEXPECTED_VALUE.search(_help(pnpm, [*scope, f"--{name}=maybe", "--zzbogus"], env, cwd)):
        return "option", m.group(1), "flag"
    return "accepted", "", ""


def _claims(pnpm: Path, name: str, token: str, env: dict[str, str], cwd: Path) -> bool:
    """Whether the setting *name* takes *token* after it: with no command, a token
    it does not take would be read as one."""
    return "unexpected argument '--zzbogus'" in _help(pnpm, [f"--{name}", token, "--zzbogus"], env, cwd)


def _setting(pnpm: Path, name: str, values: list[str], env: dict[str, str], cwd: Path) -> list | None:
    """How pnpm 12 takes the setting *name* out of argv, or None if it does not."""
    def accepted(token: str) -> bool:
        return "unexpected argument '--zzbogus'" in _help(pnpm, [token, "--zzbogus"], env, cwd)

    if _hidden(pnpm, [], name, env, cwd) == ("accepted", "", ""):
        # A keyword can be taken only by `--config.<name>=` (saveWorkspaceProtocol's
        # `rolling`), so the two spellings are probed apart.
        return ["bool", [v for v in values if accepted(f"--{name}={v}")],
                [v for v in values if accepted(f"--config.{name}={v}")]]
    if _claims(pnpm, name, "zzval", env, cwd):
        return ["text", [], []]
    if _claims(pnpm, name, "1", env, cwd):
        kind = "int" if _claims(pnpm, name, "-1", env, cwd) else "uint"
        return [kind, [], []]
    taken = [v for v in values if _claims(pnpm, name, v, env, cwd)]
    return ["enum", taken, [v for v in values if accepted(f"--config.{name}={v}")]] if taken else None


def probe(pkg: Path) -> tuple[str, dict]:
    """(pnpm's version, its table) for the pnpm in *pkg*."""
    pnpm = pkg / "pnpm"
    version = json.loads((pkg / "package.json").read_text())["version"]
    with tempfile.TemporaryDirectory(prefix="pa-pnpm-native-") as tmp_s:
        tmp = Path(tmp_s)
        cwd = tmp / "cwd"
        cwd.mkdir()
        env = {**os.environ, "HOME": str(tmp / "home"), "XDG_CONFIG_HOME": str(tmp / "home" / ".config"),
               "XDG_DATA_HOME": str(tmp / "home" / ".local" / "share"), "PNPM_HOME": str(tmp / "pnpm-home")}
        root = _help(pnpm, ["--help"], env, cwd)
        commands = _commands(root)
        global_opts, root_shorts, root_aliases = _options(root.split("Options:", 1)[1] if "Options:" in root else "")
        per_command: dict[str, dict[str, str]] = {"": {}}
        shorts: dict[str, dict[str, str]] = {"": root_shorts}
        aliases: dict[str, dict[str, str]] = {"": root_aliases}
        optional_values: dict[str, list[str]] = {}
        for name, kind in global_opts.items():
            per_command[""][name] = _kind_of(pnpm, [], name, kind, env, cwd, optional_values)
        # Never `with`: `pnpm with <version>` downloads that pnpm, even with
        # --help. parse_native() reads no options after it anyway.
        for full in sorted(set(commands.values()) & INSTALLING - {"with"}):
            opts, cmd_shorts, cmd_aliases = _options(_help(pnpm, [full, "--help"], env, cwd))
            shorts[full] = cmd_shorts
            aliases[full] = cmd_aliases
            per_command[full] = {}
            for name, kind in opts.items():
                if name in per_command[""]:
                    continue
                per_command[full][name] = _kind_of(pnpm, [full], name, kind, env, cwd, optional_values)
            print(f"pnpm {version} {full}: {sum(v != 'flag' for v in per_command[full].values())} value options")
        # What help omits: hidden aliases at each level, then pnpm's own settings.
        candidates = _candidates()
        for name, values in _source_settings(version).items():
            known = candidates.setdefault(name, [])
            known.extend(v for v in values if v not in known)
        # A renamed option is an alias of its canonical one (renamed_options.rs).
        renamed = {a: c for a, c in _source_renamed(version).items() if c in per_command[""]}
        aliases[""].update(renamed)
        # An optional-value option (`--color[=<COLOR>]`) gets no hidden negation;
        # pnpm declares its `--no-<name>` as a separate hidden option.
        for table in per_command.values():
            for name, kind in list(table.items()):
                if kind == "optional":
                    candidates.setdefault(f"no-{name[2:]}", [])
        for scope_name, table in sorted(per_command.items()):
            scope = [scope_name] if scope_name else []
            for name in sorted(candidates):
                spelled = f"--{name}"
                if spelled in table or spelled in per_command[""] or spelled in aliases[scope_name]:
                    continue
                found = _hidden(pnpm, scope, name, env, cwd)
                if found is not None and found[0] == "option":
                    _kind, canonical, kind = found
                    if canonical != spelled:
                        aliases[scope_name][spelled] = canonical
                    (per_command[""] if canonical in per_command[""] else table).setdefault(canonical, kind)
            print(f"pnpm {version} {scope_name or '(global)'}: hidden spellings probed")
        settings: dict[str, list] = {}
        for name, values in sorted(candidates.items()):
            if f"--{name}" not in per_command[""] and f"--{name}" not in aliases[""]:
                found_setting = _setting(pnpm, name, values, env, cwd)
                if found_setting is not None:
                    settings[name] = found_setting
        print(f"pnpm {version}: {len(settings)} settings taken out before clap")
    return version, {
        "commands": dict(sorted(commands.items())),
        "options": {k: dict(sorted(v.items())) for k, v in sorted(per_command.items())},
        "shorts": {k: dict(sorted(v.items())) for k, v in sorted(shorts.items())},
        "aliases": {k: dict(sorted(v.items())) for k, v in sorted(aliases.items())},
        "optional_values": dict(sorted(optional_values.items())),
        "renamed": dict(sorted(renamed.items())),
        "settings": dict(sorted(settings.items())),
    }


def generate(pkgs: list[Path]) -> None:
    tables = dict(probe(pkg) for pkg in pkgs)
    versions = sorted(tables, key=lambda v: [int(x) for x in v.split(".")])
    lines = [
        '"""pnpm 12+ (native, clap) argv-parsing data, GENERATED — do not edit by hand.',
        "",
        f"Generated from pnpm {', '.join(versions)} by tests/fixtures/argv_oracles/generate_pnpm_native.py;",
        "see packagealert/parsers/pnpm_argv.py.",
        "",
        "Per pnpm version: 'commands', every command name (aliases included) -> its full",
        "name. 'options', per installing command ('' = global, accepted anywhere): 'value'",
        "takes one value, 'multi' every value that follows, 'optional' one only when",
        "attached (`--color=auto`), 'flag' none. 'shorts' and 'aliases', short forms and",
        "long aliases per command ('' = before the command). 'optional_values', an",
        "'optional' option's accepted attached values (empty: any). 'renamed', an alias",
        "pnpm drops when its canonical option is also given. 'settings', those pnpm takes",
        "out of argv before clap unless the command declares the name itself: [kind,",
        "values, dotted values]. 'bool' (also `--no-<name>`, `--<name>=<bool>`, and a",
        "following true/false/1/0; values: keywords `--<name>=` also takes), 'text' (a",
        "following token not starting with `-`), 'int'/'uint', or 'enum' (one of values).",
        "Dotted values: what `--config.<name>=` takes besides.",
        '"""',
        "",
        "PNPM_NATIVE_TABLES: dict[str, dict] = {",
    ]
    for version in versions:
        lines.append(f"    {version!r}: {{")
        for key, value in tables[version].items():
            if isinstance(value, dict) and value and all(isinstance(v, dict) for v in value.values()):
                lines.append(f"        {key!r}: {{")
                lines.extend(f"            {k!r}: {v!r}," for k, v in value.items())
                lines.append("        },")
            else:
                lines.append(f"        {key!r}: {value!r},")
        lines.append("    },")
    lines.append("}")
    OUT.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    generate([Path(p).resolve() for p in sys.argv[1:]])
