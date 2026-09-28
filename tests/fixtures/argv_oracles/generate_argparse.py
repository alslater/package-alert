# pyright: reportMissingImports=false
# (Run with the tool's own interpreter, not this project's venv.)
"""Regenerate pipenv.json / pipx.json: package-alert's pipenv and pipx parsers
are checked against each tool's OWN argparse parser, on a corpus generated from
that parser's own actions. Nothing is executed — this only parses.

    /path/to/pipenv/venv/bin/python tests/fixtures/argv_oracles/generate_argparse.py pipenv
    /path/to/pipx/venv/bin/python   tests/fixtures/argv_oracles/generate_argparse.py pipx

(`head -1 "$(readlink -f "$(which pipenv)")"` shows pipenv's interpreter.)
Only command lines the tool ACCEPTS are recorded.
"""
import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

_VALUES = ("VAL", "3.12", "1", "x")


def _subparsers(parser):
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            return a.choices
    return {}


def _options(parser):
    return [a for a in parser._actions if a.option_strings and not isinstance(a, argparse._HelpAction)
            and not isinstance(a, argparse._VersionAction)]


def _takes_value(action):
    return action.nargs != 0 and not isinstance(
        action, (argparse._StoreTrueAction, argparse._StoreFalseAction, argparse._CountAction,
                 argparse._StoreConstAction, argparse._AppendConstAction))


def _spellings(action, all_longs):
    out = list(action.option_strings)
    for lo in (s for s in action.option_strings if s.startswith("--")):
        for n in range(3, len(lo)):
            if [x for x in all_longs if x.startswith(lo[:n])] == [lo]:
                out.append(lo[:n])
    return out


def _parse(tool, argv):
    """argparse's verdict, or None if it rejects the command line."""
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            if tool == "pipenv":
                from pipenv.cli.command import build_parser
                ns, remaining = build_parser().parse_known_args(list(argv))
                if remaining and ns.command != "run":
                    return None
            else:
                from pipx.main import get_command_parser
                ns = get_command_parser()[0].parse_args(list(argv))
    except (SystemExit, Exception):  # noqa: BLE001 — rejected
        return None
    return ns


def _value_for(tool, action, context):
    if action.choices:
        return str(next(iter(action.choices)))
    for v in _VALUES:
        if _parse(tool, [*context[:-1], action.option_strings[0], v, context[-1]] if context else [action.option_strings[0], v]) is not None:
            return v
    return "VAL"


def _truth(tool, ns):
    """What the tool then DOES, which is not always what the subcommand says:
    pipx's setup() exits after printing `--version` before any subcommand runs,
    and pipenv's `-h`/`--help` prints help even alongside a subcommand. Other
    root-level pipenv flags (`--where`, `--venv`, ...) are honoured only with
    no subcommand, so with one the subcommand still runs."""
    cmd = getattr(ns, "command", None)
    if tool == "pipx" and getattr(ns, "version", False):
        cmd = None
    if tool == "pipenv" and getattr(ns, "help", False):
        cmd = None
    if tool == "pipenv":
        return {"cmd": cmd,
                "packages": sorted([*(getattr(ns, "packages", None) or []), *(getattr(ns, "editables", None) or [])]),
                "req_files": sorted(r for r in [getattr(ns, "requirementstxt", None)] if r)}
    packages = {"install": getattr(ns, "package_spec", None), "upgrade": getattr(ns, "packages", None),
                "inject": getattr(ns, "dependencies", None),
                "reinstall": [ns.package] if getattr(ns, "package", None) and cmd == "reinstall" else None}.get(str(cmd)) or []
    reqs = getattr(ns, "requirements", None) if cmd == "inject" else None
    return {"cmd": cmd, "packages": sorted(packages),
            "req_files": sorted(reqs if isinstance(reqs, list) else [reqs] if reqs else []),
            "target": getattr(ns, "package", None) if cmd == "inject" else None}


def _corpus(tool):
    if tool == "pipenv":
        from pipenv.cli.command import build_parser
        root = build_parser()
        subs = {k: v for k, v in _subparsers(root).items() if k in ("install", "sync", "update")}
        tails = {"install": ["evilpkg"], "sync": [], "update": ["evilpkg"]}
    else:
        from pipx.main import get_command_parser
        root = get_command_parser()[0]
        subs = {k: v for k, v in _subparsers(root).items()
                if k in ("install", "inject", "upgrade", "reinstall", "install-all", "upgrade-all", "reinstall-all")}
        tails = {"install": ["evilpkg"], "inject": ["target", "evilpkg"], "upgrade": ["evilpkg"],
                 "reinstall": ["evilpkg"], "install-all": ["spec.json"], "upgrade-all": [], "reinstall-all": []}
    out = []
    root_longs = [s for a in _options(root) for s in a.option_strings if s.startswith("--")]
    for action in _options(root):
        for sp in _spellings(action, root_longs):
            for sub in subs:
                v = [_value_for(tool, action, [sub])] if _takes_value(action) else []
                out.append([sp, *v, sub, *tails[sub]])
    for sub, sp_parser in subs.items():
        longs = [s for a in _options(sp_parser) for s in a.option_strings if s.startswith("--")]
        out.append([sub, *tails[sub]])
        out.append([sub, *tails[sub], "second"])  # several positionals
        for action in _options(sp_parser):
            for spelling in _spellings(action, longs):
                v = [_value_for(tool, action, [sub, *tails[sub]])] if _takes_value(action) else []
                out.append([sub, spelling, *v, *tails[sub]])
                out.append([sub, *tails[sub], spelling, *v])
                if v and spelling.startswith("--"):
                    out.append([sub, *tails[sub], f"{spelling}={v[0]}"])
    return out


if __name__ == "__main__":
    tool = sys.argv[1]
    cases = [[argv, _truth(tool, ns)] for argv in _corpus(tool) if (ns := _parse(tool, argv)) is not None]
    path = Path(__file__).with_name(f"{tool}.json")
    path.write_text(json.dumps(cases, indent=0) + "\n")
    print(f"{tool}: {len(cases)} accepted cases recorded in {path}")
