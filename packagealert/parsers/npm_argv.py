"""npm's own command-line parsing, ported from nopt and npm's cmd-list.

npm decides what an argument means with nopt (`parse()` / `resolveShort()` in
nopt/lib/nopt-lib.js) driven by its config definitions, and resolves the
command with cmd-list's `deref()`. Approximating those rules produced a long
series of misparses — an unrecognised install is run by the sandbox shim with
no sandbox and no pre-flight — so this module translates them line for line
instead, over tables generated from npm itself (_npm_tables.py). Keep each
function in step with its JavaScript counterpart; the differential test in
tests/unit/test_argv_oracles.py checks the result against real npm.
"""

from __future__ import annotations

import re
from functools import cache

from packagealert.parsers._npm_tables import (
    NPM_COMMAND_ALIASES,
    NPM_COMMANDS,
    NPM_SHORTHANDS,
    NPM_TYPES,
)

_Scalar = bool | str | float | None
_Value = _Scalar | list[_Scalar]


def abbrev(words: list[str] | tuple[str, ...]) -> dict[str, str]:
    """Port of the `abbrev` package: every unambiguous prefix -> its word."""
    word_list = sorted({str(w) for w in words})
    out: dict[str, str] = {}
    prev = ""
    for idx, current in enumerate(word_list):
        nxt = word_list[idx + 1] if idx + 1 < len(word_list) else ""
        next_matches = prev_matches = True
        j = 0
        cl = len(current)
        while j < cl:
            ch = current[j]
            next_matches = next_matches and ch == (nxt[j] if j < len(nxt) else "")
            prev_matches = prev_matches and ch == (prev[j] if j < len(prev) else "")
            if not next_matches and not prev_matches:
                j += 1
                break
            j += 1
        prev = current
        if j == cl:
            out[current] = current
            continue
        a = current[:j]
        while j <= cl:
            out[a] = current
            if j < cl:
                a += current[j]
            j += 1
    return out


@cache
def _key_abbrevs() -> dict[str, str]:
    return abbrev(tuple(NPM_TYPES))


@cache
def _shorthand_abbrevs() -> dict[str, str]:
    return abbrev(tuple(NPM_SHORTHANDS))


def _resolve_short(arg: str) -> list[str] | None:
    """Port of nopt's resolveShort()."""
    abbrevs = _key_abbrevs()
    arg = re.sub(r"^-+", "", arg)
    if abbrevs.get(arg) == arg:  # an exact known option
        return None
    if arg in NPM_SHORTHANDS:  # an exact shorthand
        return list(NPM_SHORTHANDS[arg])
    singles = [c for c in arg if len(c) == 1 and c in NPM_SHORTHANDS]
    if "".join(singles) == arg:  # single-char shorthands glommed together
        return [part for c in singles for part in NPM_SHORTHANDS[c]]
    if arg in abbrevs and arg not in NPM_SHORTHANDS:  # prefer an option abbrev
        return None
    arg = _shorthand_abbrevs().get(arg, arg)
    parts = NPM_SHORTHANDS.get(arg)
    return list(parts) if parts is not None else None


def _js_is_number(s: str) -> bool:
    """JavaScript's `!isNaN(s)` for a string."""
    s = s.strip()
    if s == "":
        return True
    try:
        float(s)
    except ValueError:
        return bool(re.fullmatch(r"0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+", s))
    return s.lower() not in ("nan", "inf", "-inf", "+inf", "infinity", "-infinity", "+infinity")


def parse(argv: list[str]) -> tuple[dict[str, _Value], list[str]]:
    """Port of nopt's parse(): (config values, remaining positionals)."""
    args = list(argv)
    data: dict[str, _Value] = {}
    remain: list[str] = []
    abbrevs = _key_abbrevs()
    i = 0
    while i < len(args):
        arg = args[i]
        if re.fullmatch(r"-{2,}", arg):
            remain.extend(args[i + 1:])
            break
        if arg.startswith("-") and len(arg) > 1:
            had_eq = False
            at = arg.find("=")
            if at > -1:
                had_eq = True
                value = arg[at + 1:]
                arg = arg[:at]
                args[i:i + 1] = [arg, value]
            sh_res = _resolve_short(arg)
            if sh_res is not None:
                args[i:i + 1] = sh_res
                if arg != sh_res[0]:
                    continue  # re-parse the expansion in place
            arg = re.sub(r"^-+", "", arg)
            no: bool | None = None
            while arg.lower().startswith("no-"):
                no = not no
                arg = arg[3:]
            if abbrevs.get(arg) and abbrevs[arg] != arg:
                arg = abbrevs[arg]
            kind: str | None
            names: tuple[str, ...]
            kind, names = NPM_TYPES.get(arg, (None, ()))
            has_type = kind is not None
            is_type_array = kind == "list" and len(names) != 1
            single = names[0] if names and (kind == "single" or len(names) == 1) else None
            is_array = single == "Array" or (is_type_array and "Array" in names)
            if not has_type and arg in data:
                is_array = True
            la = args[i + 1] if i + 1 < len(args) else None
            is_bool = (
                no is not None
                or single == "Boolean"
                or (is_type_array and "Boolean" in names)
                or (not has_type and not had_eq)
                or (la == "false" and (single == "null" or (is_type_array and "null" in names)))
            )
            val: _Scalar
            if is_bool:
                val = not no
                if la in ("true", "false"):
                    val = la == "true"
                    la = None
                    if no:
                        val = not val
                    i += 1
                if is_type_array and la:
                    if f"={la}" in names:
                        val = la
                        i += 1
                    elif la == "null" and "null" in names:
                        val = None
                        i += 1
                    elif not re.match(r"^-{2,}[^-]", la) and _js_is_number(la) and "Number" in names:
                        val = float(la) if la.strip() else 0.0
                        i += 1
                    elif not re.match(r"^-[^-]", la) and "String" in names:
                        val = la
                        i += 1
                _store(data, arg, val, is_array)
                i += 1
                continue
            if single == "String":
                if la is None:
                    la = ""
                elif re.match(r"^-{1,2}[^-]+", la):
                    la = ""
                    i -= 1
            if la and re.fullmatch(r"-{2,}", la):
                la = None
                i -= 1
            val = True if la is None else la
            _store(data, arg, val, is_array)
            i += 2
            continue
        remain.append(arg)
        i += 1
    return data, remain


def _store(data: dict[str, _Value], key: str, val: _Scalar, is_array: bool) -> None:
    if is_array:
        existing = data.get(key)
        items: list[_Scalar]
        if isinstance(existing, list):
            items = existing
        else:
            items = [] if key not in data else [existing]
        items.append(val)
        data[key] = items
    else:
        data[key] = val


@cache
def _command_abbrevs() -> dict[str, str]:
    return abbrev((*NPM_COMMANDS, *NPM_COMMAND_ALIASES))


def deref(command: str | None) -> str | None:
    """Port of npm's cmd-list deref(): the canonical command, or None."""
    if not command:
        return None
    if re.search(r"[A-Z]", command):
        command = re.sub(r"([A-Z])", lambda m: "-" + m.group(1).lower(), command)
    if command in NPM_COMMANDS:
        return command
    if command in NPM_COMMAND_ALIASES:
        return NPM_COMMAND_ALIASES[command]
    resolved = _command_abbrevs().get(command)
    while resolved in NPM_COMMAND_ALIASES:
        resolved = NPM_COMMAND_ALIASES[resolved]
    return resolved
