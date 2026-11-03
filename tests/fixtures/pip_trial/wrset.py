"""Summarise the paths a `strace -f -e trace=%file -o LOG ...` log wrote, by location.

usage: PA_PIPX_SCRATCH=<dir> python wrset.py LOG
Only reads LOG; runs nothing. Successful write-mode opens, mkdir, rename, unlink, symlink, link, chmod, utimes ...
Paths relative to a directory fd (unlinkat etc.) cannot be placed and are reported as RELATIVE.
"""
import collections
import os
import re
import sys

_scratch = os.environ.get("PA_PIPX_SCRATCH")
if not _scratch or len(sys.argv) != 2:
    sys.exit(__doc__)
S = os.path.realpath(_scratch)
WRITE_SYS = {"mkdir", "mkdirat", "rename", "renameat", "renameat2", "unlink", "unlinkat", "rmdir", "symlink",
             "symlinkat", "link", "linkat", "truncate", "chmod", "fchmodat", "fchmodat2", "utimensat", "utimes",
             "chown", "lchown", "fchownat", "setxattr"}
pat = re.compile(r'^(?:\d+\s+)?(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(.*)$')
strpat = re.compile(r'"((?:[^"\\]|\\.)*)"')
unfinished = re.compile(r'^(\d+)\s+(.*?)\s*<unfinished \.\.\.>$')
resumed = re.compile(r'^(\d+)\s+<\.\.\. \w+ resumed>\s?(.*)$')
out: dict[str, set[str]] = {}
with open(sys.argv[1], errors="replace") as _log:
    _raw = _log.readlines()
# strace -f splits a call another process interrupts into "PID call(args <unfinished ...>" and
# "PID <... call resumed>rest) = ret": rejoin them by PID before matching.
_lines: list[str] = []
_pending: dict[str, str] = {}
for raw in _raw:
    raw = raw.strip()
    if m := unfinished.match(raw):
        _pending[m.group(1)] = f"{m.group(1)} {m.group(2)}"
    elif (m := resumed.match(raw)) and m.group(1) in _pending:
        _lines.append(_pending.pop(m.group(1)) + m.group(2))
    else:
        _lines.append(raw)
for line in _lines:
    m = pat.match(line)
    if not m:
        continue
    sc, args, ret, _ = m.groups()
    if ret.startswith("-"):
        continue
    paths = strpat.findall(args)
    if not paths:
        continue
    if sc == "creat":
        w = True  # creat() takes a mode, not flags, and always creates or truncates
    elif sc in ("open", "openat", "openat2"):
        w = bool(re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC", args)) and "O_DIRECTORY" not in args
    else:
        w = sc in WRITE_SYS
    if w:
        for p in paths:
            out.setdefault(p, set()).add(sc)
PREFIXES = [("venv", S + "/pipx_home/venvs/"), ("shared", S + "/pipx_home/shared"), ("trash", S + "/pipx_home/.trash"),
            ("logs", S + "/pipx_home/logs"), ("py", S + "/pipx_home/py"), ("man", S + "/man"), ("bin", S + "/bin/"),
            ("SOURCE CHECKOUT", S + "/src/"), ("scratch-work", S + "/work"), ("~/.cache", os.path.expanduser("~/.cache")),
            ("tmp", "/tmp"), ("dev", "/dev/"), ("proc", "/proc")]


def cat(p: str) -> str:
    if not p.startswith("/"):
        return "RELATIVE(cwd-dependent)"
    for name, pre in PREFIXES:
        if p.startswith(pre):
            return name
    return "pipx_home-other" if p.startswith(S + "/pipx_home") else "OTHER"


cats: dict[str, list[tuple[str, list[str]]]] = collections.OrderedDict()
for p, s in out.items():
    cats.setdefault(cat(p), []).append((p, sorted(s)))
for c, lst in cats.items():
    print(f"[{c}] {len(lst)} paths")
    if c in ("venv", "tmp", "dev", "proc", "RELATIVE(cwd-dependent)"):
        continue
    for p, s in lst[:25]:
        print("    ", p.replace(S, "$S"), s)
