"""Regenerate pnpm's parsing tables and oracle fixture from pnpm itself (#93).

pnpm 8-11 are JavaScript: they parse with @pnpm/parse-cli-args over @pnpm/nopt,
driven by option-type and shorthand tables that live inside the bundle. Neither
is importable, so a scratch COPY of each bundle is patched:

* the library's parseCliArgs() dumps the tables it is given, then exits
  (PA_DUMP_TABLES) -> packagealert/parsers/_pnpm_tables.py;
* main() runs pnpm's own CLI parse over a batch of command lines and records
  each result before anything executes (PA_PARSE_BATCH) -> pnpm.json.

Nothing is installed or run. Usage, with each pnpm installed somewhere
disposable (`npm install --prefix <dir> pnpm@X`):

    python tests/fixtures/argv_oracles/generate_pnpm.py <dir>/node_modules/pnpm ...

pnpm 12 (a native Rust/clap rewrite) is handled by generate_pnpm_native.py.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TABLES = ROOT / "packagealert" / "parsers" / "_pnpm_tables.py"
FIXTURE = HERE / "pnpm.json"

# Serialise one nopt type the way _npm_tables.py does: a type name, "null", or "=literal".
_DUMP_JS = r"""
const __paName = (x) => {
  if (x === null) return "null";
  if (x === String) return "String";
  if (x === Boolean) return "Boolean";
  if (x === Number) return "Number";
  if (x === Array) return "Array";
  if (x === Date) return "Date";
  if (typeof x === "string" || typeof x === "number" || typeof x === "boolean") return "=" + String(x);
  if (typeof x === "function") return x.name || "Function";
  if (x && typeof x === "object") {
    if ("join" in x && "resolve" in x) return "path";
    if ("URL" in x || ("parse" in x && "format" in x)) return "url";
    if ("pipe" in x || "Readable" in x) return "Stream";
  }
  return "Unknown";
};
const __paType = (t) => Array.isArray(t)
  ? (t.length === 1 ? ["single", [__paName(t[0])]] : ["list", t.map(__paName)])
  : ["single", [__paName(t)]];
const __paTypes = (o) => Object.fromEntries(Object.entries(o || {}).map(([k, v]) => [k, __paType(v)]));
const __paShort = (o) => Object.fromEntries(Object.entries(o || {}).filter(([k]) => k !== "___singles")
  .map(([k, v]) => [k, Array.isArray(v) ? v : String(v).split(/\s+/)]));
"""


def _bundle(pkg: Path) -> Path:
    for name in ("pnpm.cjs", "pnpm.mjs"):
        if (pkg / "dist" / name).exists():
            return pkg / "dist" / name
    raise SystemExit(f"{pkg}: not a JavaScript pnpm (no dist/pnpm.cjs or dist/pnpm.mjs)")


def _patch(bundle: Path) -> None:
    src = bundle.read_text()
    esm = bundle.suffix == ".mjs"
    fs = 'const __paFs = await import("node:fs");' if esm else 'const __paFs = require("fs");'
    # 1. the library parseCliArgs(opts, inputArgv): dump its tables.
    lib = re.compile(r"(async function parseCliArgs\((opts\d*), inputArgv\) \{)")
    m = lib.search(src)
    if not m:
        raise SystemExit(f"{bundle}: library parseCliArgs(opts, inputArgv) not found")
    opts = m.group(2)
    dump = (
        "if (process.env.PA_DUMP_TABLES) {" + fs + _DUMP_JS
        + "const __paCmds = {};"
        + 'for (const n of JSON.parse(__paFs.readFileSync(process.env.PA_DUMP_NAMES, "utf8"))) {'
        + f"  const full = {opts}.getCommandLongName(n); if (full == null) continue;"
        + f"  __paCmds[n] = {{full, types: __paTypes({opts}.getTypesByCommandName(n)),"
        + f"                  shorthands: __paShort(({opts}.shorthandsByCommandName || {{}})[n])}}; }}"
        + "__paFs.writeFileSync(process.env.PA_DUMP_TABLES, JSON.stringify({"
        + f"  universal: __paTypes({opts}.universalOptionsTypes), universalShorthands: __paShort({opts}.universalShorthands),"
        + f"  renamed: {opts}.renamedOptions || {{}}, fallback: {opts}.fallbackCommand || null,"
        + f"  escapeArgs: {opts}.escapeArgs || [], commands: __paCmds}}));"
        + "process.exit(0); }"
    )
    src = src[: m.end()] + dump + src[m.end():]
    # 2. main(): batch-run pnpm's CLI parse (the wrapper, so pnpm 11's pm/with handling is included).
    main = re.compile(r"(async function main\w*\(inputArgv\) \{\n\s*let parsedCliArgs;)")
    call = re.search(r"parsedCliArgs = await ([^;]*parseCliArgs\w*\)?)\(inputArgv\);", src)
    if not main.search(src) or not call:
        raise SystemExit(f"{bundle}: main() parse call not found")
    batch = (
        "if (process.env.PA_PARSE_BATCH) {" + fs + "const __paOut = [];"
        + 'for (const __a of JSON.parse(__paFs.readFileSync(process.env.PA_PARSE_BATCH, "utf8"))) {'
        + f"  try {{ const __p = await {call.group(1)}([...__a]);"
        + "    __paOut.push({cmd: __p.cmd, params: __p.params, options: __p.options,"
        + "                  unknown: Array.from(__p.unknownOptions ? __p.unknownOptions.keys() : []),"
        + "                  fallback: !!__p.fallbackCommandUsed}); }"
        + "  catch (__e) { __paOut.push({error: String(__e && __e.message)}); } }"
        + "__paFs.writeFileSync(process.env.PA_PARSE_OUT, JSON.stringify(__paOut)); process.exit(0); }"
    )
    src = main.sub(lambda mm: mm.group(1) + " " + batch, src, count=1)
    bundle.write_text(src)


def _run(pkg: Path, env: dict[str, str], cwd: Path) -> None:
    binary = next(p for p in (pkg / "bin" / "pnpm.cjs", pkg / "bin" / "pnpm.mjs") if p.exists())
    subprocess.run(["node", str(binary), "x"], env={**os.environ, **env}, cwd=cwd, check=True,
                   capture_output=True, timeout=600)


def _command_names(bundle: Path) -> list[str]:
    """Every name a command registers (aliases included), from the bundle's commandNames."""
    names: set[str] = set()
    for group in re.findall(r"commandNames\w*\s*[=:]\s*\[([^\]]*)\]", bundle.read_text()):
        names.update(re.findall(r'"([a-z][a-z0-9-]*)"', group))
    return sorted(names)


# Commands whose parse decides whether package-alert gates the run.
INSTALLING = {"add", "install", "update", "dedupe", "fetch", "deploy", "ci", "install-test",
              "unlink", "remove", "import", "self-update", "recursive", "with"}


def _value_for(t: list) -> str:
    names = t[1]
    lits = [n[1:] for n in names if n.startswith("=")]
    if lits:
        return lits[0]
    if "Number" in names:
        return "1"
    if "url" in names:
        return "https://r.example/"
    return "VAL"


def _boolean_only(t: list) -> bool:
    return all(n in ("Boolean", "null") for n in t[1])


def _unique_prefixes(key: str, keys: list[str]) -> list[str]:
    return [key[:n] for n in range(3, len(key)) if [k for k in keys if k.startswith(key[:n])] == [key]]


def _corpus(tables: dict) -> list[list[str]]:
    cmds = tables["commands"]
    spellings = sorted(n for n, c in cmds.items() if c["full"] in INSTALLING)
    corpus: list[list[str]] = []
    for c in spellings:
        corpus += [[c], [c, "evilpkg"], [c, "evilpkg", "other"]]
    contexts = ["add", "install", "update"]
    for ctx in contexts:
        types = {**tables["universal"], **(cmds.get(ctx) or {}).get("types", {})}
        keys = sorted(types)
        for key in keys:
            t = types[key]
            for f in [f"--{key}", *(f"--{p}" for p in _unique_prefixes(key, keys))]:
                if _boolean_only(t):
                    corpus += [[f, ctx, "evilpkg"], [ctx, f, "evilpkg"], [ctx, f], [ctx, f, "false"],
                               [f, "true", ctx], [f"--no-{f[2:]}", ctx, "evilpkg"]]
                else:
                    v = _value_for(t)
                    corpus += [[f, v, ctx, "evilpkg"], [ctx, f, v, "evilpkg"], [ctx, f, v], [f"{f}={v}", ctx],
                               [ctx, f, "--global", "evilpkg"], [ctx, f]]
        shorts = {**tables["universalShorthands"], **(cmds.get(ctx) or {}).get("shorthands", {})}
        for s in shorts:
            flag = f"-{s}" if len(s) == 1 else f"--{s}"
            corpus += [[ctx, flag, "evilpkg"], [flag, "VAL", ctx], [ctx, flag, "VAL", "evilpkg"]]
        singles = "".join(s for s in shorts if len(s) == 1)
        for i in range(len(singles) - 1):
            corpus.append([ctx, f"-{singles[i:i + 2]}", "evilpkg"])
    corpus += [
        ["pm", "add", "evilpkg"], ["pm", "install"], ["with", "current", "add", "evilpkg"],
        ["with", "10", "install"], ["--prod", "false", "with", "current", "install"],
        ["recursive", "add", "evilpkg"], ["m", "install"], ["-r", "add", "evilpkg"],
        ["--filter", "web", "add", "evilpkg"], ["--", "install", "evilpkg"], ["install", "--", "--weird"],
        ["add", "--global=evilpkg"], ["install", "--global", "false", "evilpkg"], ["exec", "install", "x"],
        ["dlx", "install"], ["run", "install"], ["create", "install"], ["deploy", "--prod", "false", "out"],
        ["add", "@corp/pkg", "--@corp:registry", "https://npm.corp.example/"],
        ["add", "x", "--registry=https://r.example/", "--hoist-pattern", "--registry=https://s.example/"],
        ["-C", "a", "--prefix", "b", "install"], ["--lockfile-dir", "l", "install"],
        # `--config.<key>` registry overrides, alone and against --registry, in both orders.
        ["add", "x", "--config.registry=https://r.example/"], ["--config.registry=https://r.example/", "install"],
        ["add", "@corp/x", "--config.@corp:registry=https://r.example/"],
        ["add", "x", "--registry=https://a.example/", "--config.registry=https://b.example/"],
        ["add", "x", "--config.registry=https://b.example/", "--registry=https://a.example/"],
        ["add", "lodash", "--stor", "cache", "--config.registry=https://registry.npmjs.org/"],
        # nopt trims every string and turns an untyped "true"/"false" into JSON.
        ["add", "lodash", "--stor", "cache", "--registry= https://registry.npmjs.org/ "],
        ["add", "-g", "x", "--stor", "cache", "--config.global=true"],
        ["add", "x", "--stor", "cache", "--config.global=false"],
        ["add", "x", "--stor", "cache", "--config.Registry=https://registry.npmjs.org/"],
        # validatePath stringifies false: --no-prefix is the directory "false".
        ["--no-prefix", "install", "--stor", "cache"], ["--no-dir", "install"],
    ]
    # An escaped command's name after the command: from there on everything is a positional
    # (pnpm 8-10 always; pnpm 11 only when the command itself is one of them).
    for esc in ("exec", "create", "dlx", "test"):
        corpus += [["add", "evilpkg", esc, "--global"], ["install", esc, "--frozen-lockfile"],
                   ["add", esc, "-g", "x"], ["update", esc, "--latest"], [esc, "add", "evilpkg"]]
    seen: set[tuple[str, ...]] = set()
    return [a for a in corpus if not (tuple(a) in seen or seen.add(tuple(a)))]


# What a case records: enough to decide gating, nothing machine-specific.
_KEEP = ("global", "dir", "lockfile-dir", "registry", "check", "recursive", "workspace-root")


# Options pnpm 8-10's main() only warns about; any other unknown option makes it exit.
_DEPRECATED = {"independent-leaves", "lock", "resolution-strategy"}


def _truth(r: dict, cwd: Path) -> list | None:
    """[cmd, params, options] for a parse whose command installs, else None (pnpm
    errors, falls back to a script, or exits on an unknown option)."""
    if "error" in r or r.get("fallback") or r.get("cmd") not in INSTALLING:
        return None
    if any(u not in _DEPRECATED for u in r.get("unknown") or []):
        return None
    opts = {}
    for k, v in (r.get("options") or {}).items():
        if k in _KEEP or (k.startswith("@") and k.endswith(":registry")):
            if isinstance(v, str) and k in ("dir", "lockfile-dir") and os.path.isabs(v):
                v = os.path.relpath(v, cwd)
            opts[k] = v
    if opts.get("workspace-root"):
        # pnpm sets dir to the workspace root it finds, which depends on the machine.
        opts.pop("dir", None)
    return [r["cmd"], r.get("params") or [], opts]


def generate(pkg_dirs: list[Path]) -> None:
    with tempfile.TemporaryDirectory(prefix="pa-pnpm-gen-") as tmp_s:
        tmp = Path(tmp_s)
        prepared: dict[str, Path] = {}
        all_tables: dict[str, dict] = {}
        for n, pkg in enumerate(pkg_dirs):
            version = json.loads((pkg / "package.json").read_text())["version"]
            copy = tmp / f"pnpm-{n}"
            shutil.copytree(pkg, copy, symlinks=True)
            bundle = _bundle(copy)
            _patch(bundle)
            (tmp / "names.json").write_text(json.dumps(_command_names(bundle)))
            _run(copy, {**_env(tmp), "PA_DUMP_TABLES": str(tmp / "tables.json"),
                        "PA_DUMP_NAMES": str(tmp / "names.json")}, _cwd(tmp))
            all_tables[version] = json.loads((tmp / "tables.json").read_text())
            prepared[version] = copy
        # Every version parses the SAME corpus, the union of what each version's tables
        # suggest, so a version absent from a case really parses it as no install.
        corpus: list[list[str]] = []
        seen: set[tuple[str, ...]] = set()
        for tables in all_tables.values():
            for argv in _corpus(tables):
                if tuple(argv) not in seen:
                    seen.add(tuple(argv))
                    corpus.append(argv)
        (tmp / "batch.json").write_text(json.dumps(corpus))
        # Every corpus line is recorded, including those no version installs, so a
        # parser that starts gating one of them fails the exact per-version test.
        truths: dict[tuple[str, ...], dict[str, list]] = {tuple(argv): {} for argv in corpus}
        for version, copy in prepared.items():
            _run(copy, {**_env(tmp), "PA_PARSE_BATCH": str(tmp / "batch.json"),
                        "PA_PARSE_OUT": str(tmp / "out.json")}, _cwd(tmp))
            results = json.loads((tmp / "out.json").read_text())
            for argv, r in zip(corpus, results, strict=True):
                t = _truth(r, _cwd(tmp))
                if t is not None:
                    truths.setdefault(tuple(argv), {})[version] = t
            print(f"pnpm {version}: {len(all_tables[version]['commands'])} command names")
    print(f"{len(corpus)} command lines in the corpus")
    _write_tables(all_tables)
    # Each argv once, with the versions sharing a truth grouped ("8.15.9,9.15.9": truth).
    # A version absent from a case parses it as a command that installs nothing.
    cases = []
    for argv, by_version in truths.items():
        grouped: dict[str, list] = {}
        for version, t in by_version.items():
            key = json.dumps(t, sort_keys=True)
            grouped.setdefault(key, [t, []])[1].append(version)
        cases.append([list(argv), {",".join(vs): t for t, vs in grouped.values()}])
    FIXTURE.write_text(json.dumps({"pnpm": sorted(all_tables), "cases": cases}, separators=(",", ":")) + "\n")
    print(f"wrote {TABLES.relative_to(ROOT)} and {FIXTURE.relative_to(ROOT)}")


def _env(tmp: Path) -> dict[str, str]:
    home = tmp / "home"
    home.mkdir(exist_ok=True)
    return {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"), "npm_config_registry": "http://127.0.0.1:9/"}


def _cwd(tmp: Path) -> Path:
    """A workspace root: outside one, pnpm refuses `--workspace-root`, which users run inside one."""
    cwd = tmp / "cwd"
    cwd.mkdir(exist_ok=True)
    (cwd / "pnpm-workspace.yaml").write_text("packages: []\n")
    return cwd


def _py(obj: object) -> str:
    """A Python literal for *obj* (JSON data), leaving string contents untouched."""
    return repr(obj)


def _write_tables(all_tables: dict[str, dict]) -> None:
    lines = [
        '"""pnpm argv-parsing data, GENERATED — do not edit by hand.',
        "",
        f"Generated from pnpm {', '.join(sorted(all_tables, key=lambda v: [int(x) for x in v.split('.')]))} by",
        "tests/fixtures/argv_oracles/generate_pnpm.py; see packagealert/parsers/pnpm_argv.py.",
        '"""',
        "",
        "# Per pnpm version: option types in _npm_tables.py's form (('single'|'list', names)),",
        "# shorthands, renamed options, the fallback command, escaped commands, every command",
        "# name (aliases included) -> its full name, and each installing command's own types",
        "# and shorthands, keyed by full name.",
        "PNPM_TABLES: dict = {",
    ]
    for version in sorted(all_tables, key=lambda v: [int(x) for x in v.split(".")]):
        t = all_tables[version]
        lines.append(f"    {version!r}: {{")
        lines.append(f"        'universal': {_types_py(t['universal'])},")
        lines.append(f"        'universal_shorthands': {_py(t['universalShorthands'])},")
        lines.append(f"        'renamed': {_py(t['renamed'])},")
        lines.append(f"        'fallback': {_py(t['fallback'])},")
        lines.append(f"        'escape_args': {_py(t['escapeArgs'])},")
        lines.append("        'commands': {")
        for name in sorted(t["commands"]):
            lines.append(f"            {name!r}: {t['commands'][name]['full']!r},")
        lines.append("        },")
        # An alias registers the same types and shorthands as its full name.
        lines.append("        'command_types': {")
        for full in sorted({c["full"] for c in t["commands"].values()} & INSTALLING):
            c = t["commands"].get(full) or next(c for c in t["commands"].values() if c["full"] == full)
            lines.append(f"            {full!r}: {_types_py(c['types'])},")
        lines.append("        },")
        lines.append("        'command_shorthands': {")
        for full in sorted({c["full"] for c in t["commands"].values()} & INSTALLING):
            c = t["commands"].get(full) or next(c for c in t["commands"].values() if c["full"] == full)
            lines.append(f"            {full!r}: {_py(c['shorthands'])},")
        lines.append("        },")
        lines.append("    },")
    lines.append("}")
    TABLES.write_text("\n".join(lines) + "\n")


def _types_py(types: dict) -> str:
    return "{" + ", ".join(f"{k!r}: ({v[0]!r}, {tuple(v[1])!r})" for k, v in sorted(types.items())) + "}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    generate([Path(p).resolve() for p in sys.argv[1:]])
