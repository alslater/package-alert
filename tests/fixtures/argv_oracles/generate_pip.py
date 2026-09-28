# pyright: reportMissingImports=false
# (Run with the interpreter of each pip being recorded, not this project's venv.)
"""Regenerate pip.json: package-alert's pip parser is checked against pip's OWN
parser on a corpus generated from pip's own option inventory.

Run with each supported pip's interpreter (pip must be importable there; no
command is executed — this only parses), e.g.:

    for py in ~/.pyenv/versions/3.11.*/bin/python ~/.pyenv/versions/3.12.*/bin/python; do
        "$py" tests/fixtures/argv_oracles/generate_pip.py
    done

Each run adds/replaces its pip version's entry in pip.json. Only command lines
pip ACCEPTS are recorded; one it rejects installs nothing, so there is no
ground truth to match. See "Auditing value-consuming flag lists" in CLAUDE.md.
"""
import contextlib
import io
import json
from pathlib import Path

import pip
from pip._internal.cli.main_parser import create_main_parser, parse_command
from pip._internal.commands import create_command

_VCS = ("git+", "hg+", "svn+", "bzr+")


def _options(parser):
    for group in [parser, *parser.option_groups]:
        yield from group.option_list


def _spellings(opt, all_longs):
    out = [*opt._short_opts, *opt._long_opts]
    for lo in opt._long_opts:  # every UNIQUE abbreviation
        for n in range(3, len(lo)):
            if [l for l in all_longs if l.startswith(lo[:n])] == [lo]:
                out.append(lo[:n])
    return out


def _corpus():
    main = create_main_parser()
    inst = create_command("install", isolated=False).parser
    g_longs = [l for o in _options(main) for l in o._long_opts]
    i_longs = [l for o in _options(inst) for l in o._long_opts]
    value = lambda o: o.choices[0] if o.choices else "VAL"
    skip = ("help", "version")
    out = []
    for opt in (o for o in _options(main) if o.dest not in skip):
        for sp in _spellings(opt, g_longs):
            if opt.takes_value():
                out.append([sp, value(opt), "install", "evilpkg"])
                if sp.startswith("--"):
                    out.append([f"{sp}={value(opt)}", "install", "evilpkg"])
            else:
                out.append([sp, "install", "evilpkg"])
    for opt in (o for o in _options(inst) if o.dest not in skip):
        for sp in _spellings(opt, i_longs):
            v = [value(opt)] if opt.takes_value() else []
            out.append(["install", sp, *v, "evilpkg"])
            out.append(["install", "evilpkg", sp, *v])
    out += [["install", "-r", "req.txt"], ["install", "-rreq.txt"],
            ["install", "--requirement=req.txt", "x"],
            ["install", "-e", "git+https://h/r#egg=a"], ["install", "--", "--weird"]]
    return out


def _truth(argv):
    """What pip itself parses `pip <argv>` as, or None if pip rejects it."""
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            name, cmd_args = parse_command(list(argv))
            if name != "install":
                return {"cmd": name}
            opts, args = create_command("install", isolated=False).parse_args(cmd_args)
    except (SystemExit, Exception):  # noqa: BLE001 — pip rejected it
        return None
    vcs_editables = [e for e in (opts.editables or []) if e.startswith(_VCS) or "://" in e]
    return {"cmd": "install", "packages": sorted(args + vcs_editables),
            "req_files": sorted(opts.requirements or [])}


if __name__ == "__main__":
    path = Path(__file__).with_name("pip.json")
    data = json.loads(path.read_text()) if path.exists() else {}
    cases = [[argv, t] for argv in _corpus() if (t := _truth(argv)) is not None]
    data[pip.__version__] = cases
    path.write_text(json.dumps(data, indent=0, sort_keys=True) + "\n")
    print(f"pip {pip.__version__}: {len(cases)} accepted cases recorded in {path}")
