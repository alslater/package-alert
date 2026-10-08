# pyright: reportMissingImports=false
# (Run with a pip's interpreter, not this project's venv.)
"""Regenerate pip_req_file.json: how pip itself parses requirements-file option lines.

package-alert decides whether a requirements file sends pip somewhere other than
public PyPI (see _requirements_option_is_private() in packagealert/parsers/
lockfiles.py), which decides whether its packages' yank status is looked up.
This records pip's requirements-file option inventory and, for a corpus built
from it (every long option and unique prefix, short options attached and
separate, "=" values, public and private URLs, several options on one line),
whether pip's own parser points at another source. Only lines pip ACCEPTS are
recorded: one it rejects installs nothing. Nothing is executed. E.g.:

    uv run --isolated --with pip==26.1.2 python tests/fixtures/argv_oracles/generate_pip_req_file.py
"""
import json
import shlex
from pathlib import Path

import pip
from pip._internal.req import req_file

_PUBLIC = {"https://pypi.org/simple", "https://pypi.python.org/simple"}
_VALUES = ["https://pypi.org/simple", "https://PYPI.org/simple/", "https://corp.example/simple", "./wheels"]
_EXTRA = [
    "--pre --extra-index-url https://corp.example/simple", "--trusted-host x -ihttps://corp.example/simple",
    "-i https://pypi.org/simple --no-index", "-i https://pypi.org/simple -f https://corp.example/links",
    "--hash=sha256:abc", "--require-hashes", "--prefer-binary --only-binary :all:", "-c constraints.txt",
    "-r other.txt -i https://corp.example/simple", "--index-url https://corp.example/simple -i https://pypi.org/simple",
]


def _private(line):
    """True/False for where pip would look, or None when pip rejects the line."""
    parser = req_file.build_parser()  # fresh: optparse's append options mutate their defaults
    _, opts = req_file.break_args_options(line)
    try:
        options, _ = parser.parse_args(shlex.split(opts), parser.get_default_values())
    except Exception:  # noqa: BLE001 - pip rejects the line
        return None
    index = options.index_url
    return bool(options.extra_index_urls or options.find_links or options.no_index
                or (index is not None and index.strip().rstrip("/").lower() not in _PUBLIC))


def main():
    parser = req_file.build_parser()
    longs = {lo: o.takes_value() for o in parser.option_list for lo in o._long_opts}
    shorts = {s: o._long_opts[0] for o in parser.option_list for s in o._short_opts}
    lines = []
    for o in parser.option_list:
        spellings = [*o._short_opts]
        for lo in o._long_opts:
            spellings += [lo[:n] for n in range(3, len(lo) + 1)]
        for sp in spellings:
            if not o.takes_value():
                lines.append(sp)
                continue
            for v in _VALUES:
                lines += [f"{sp}={v}", f"{sp} {v}"] if sp.startswith("--") else [f"{sp}{v}", f"{sp} {v}"]
    cases = [[line, p] for line in [*lines, *_EXTRA] if (p := _private(line)) is not None]
    out = Path(__file__).with_name("pip_req_file.json")
    out.write_text(json.dumps({"pip": pip.__version__, "long_options": longs, "short_options": shorts,
                               "cases": cases}, indent=1) + "\n")
    print(f"pip {pip.__version__}: {len(cases)} accepted lines, {sum(p for _, p in cases)} private")


if __name__ == "__main__":
    main()
