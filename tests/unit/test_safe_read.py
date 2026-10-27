"""A FIFO left where package-alert reads a file an install controls must never block it (#109)."""
from __future__ import annotations

import ast
import asyncio
import io
import json
import os
import tarfile
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from rich.console import Console

from packagealert import safe_read

_ROOT = Path(__file__).resolve().parents[2] / "packagealert"


def _bounded(fn: Callable[[], object], timeout: float = 5.0) -> object:
    """fn()'s result, failing rather than hanging if it blocks on a FIFO."""
    box: list = []
    worker = threading.Thread(target=lambda: box.append(fn()), daemon=True)
    worker.start()
    worker.join(timeout)
    assert box, "blocked reading a FIFO"
    return box[0]


# ── the helpers themselves ───────────────────────────────────────────────


def test_reads_a_regular_file_through_a_symlink(tmp_path):
    (tmp_path / "f").write_text("héllo")
    (tmp_path / "link").symlink_to(tmp_path / "f")
    assert safe_read.read_text(tmp_path / "link") == "héllo"
    assert safe_read.read_bytes(tmp_path / "f") == "héllo".encode()
    with pytest.raises(OSError):
        safe_read.read_bytes(tmp_path / "link", follow_symlinks=False)


@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_anything_but_a_regular_file_is_refused_without_blocking(tmp_path, kind):
    target = tmp_path / "x"
    os.mkfifo(target) if kind == "fifo" else target.mkdir()
    (tmp_path / "link").symlink_to(target)

    def attempt(path: Path) -> type[BaseException] | None:
        try:
            safe_read.read_bytes(path)
        except safe_read.NotARegularFile as e:
            return type(e)
        return None

    assert _bounded(lambda: attempt(target)) is safe_read.NotARegularFile
    assert _bounded(lambda: attempt(tmp_path / "link")) is safe_read.NotARegularFile
    assert issubclass(safe_read.NotARegularFile, OSError)


def test_invalid_utf8_follows_the_errors_argument(tmp_path):
    (tmp_path / "f").write_bytes(b"a\xffb")
    assert safe_read.read_text(tmp_path / "f", errors="replace") == "a�b"
    with pytest.raises(UnicodeDecodeError):
        safe_read.read_text(tmp_path / "f")


# ── the readers an install can reach ─────────────────────────────────────


@pytest.mark.parametrize(("ecosystem", "lock"), [
    ("npm", "package-lock.json"), ("npm", "yarn.lock"), ("npm", "pnpm-lock.yaml"),
    ("pypi", "uv.lock"), ("pypi", "Pipfile.lock"), ("pypi", "requirements.txt"), ("packagist", "composer.lock"),
])
def test_a_fifo_lock_file_parses_as_empty(tmp_path, ecosystem, lock):
    """A lock file an install replaced with a FIFO is scanned after the run: it must read
    as unreadable rather than hang pa run, the daemon or scan-project."""
    from packagealert.languages import registry

    registry.load()
    lang = registry.for_ecosystem(ecosystem)
    assert lang is not None
    os.mkfifo(tmp_path / lock)
    assert _bounded(lambda: lang.parse_lockfile(tmp_path / lock)) == []


def test_a_fifo_in_a_package_does_not_block_its_source_heuristics(tmp_path):
    from packagealert.languages.node import _NpmHeuristic
    from packagealert.languages.python import PythonLanguage

    os.mkfifo(tmp_path / "package.json")
    assert _bounded(lambda: asyncio.run(_NpmHeuristic().analyze(tmp_path))) == []
    (tmp_path / "package.json").unlink()
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "version": "1.0.0"}))
    os.mkfifo(tmp_path / "index.js")
    _bounded(lambda: asyncio.run(_NpmHeuristic().analyze(tmp_path)))
    os.mkfifo(tmp_path / "setup.py")
    os.mkfifo(tmp_path / "payload")                         # no suffix: probed for an embedded binary
    for heuristic in PythonLanguage().heuristics():
        _bounded(lambda h=heuristic: asyncio.run(h.analyze(tmp_path)))


def test_a_fifo_cache_artifact_is_not_read(tmp_path):
    from packagealert.languages.node import NodeLanguage
    from packagealert.parsers.npm import inspect_npm_tarball
    from packagealert.parsers.wheel import read_wheel_metadata

    os.mkfifo(tmp_path / "pkg.tgz")
    assert _bounded(lambda: inspect_npm_tarball(tmp_path / "pkg.tgz")) is None
    os.mkfifo(tmp_path / "pkg-1.0-py3-none-any.whl")
    assert _bounded(lambda: read_wheel_metadata(tmp_path / "pkg-1.0-py3-none-any.whl")) == {}
    index = tmp_path / ".npm" / "_cacache" / "index-v5" / "ab" / "cd"
    index.mkdir(parents=True)
    os.mkfifo(index / "0123456789abcdef")
    _bounded(lambda: NodeLanguage().classify_cache_file(index / "0123456789abcdef"))


def test_a_regular_tarball_is_still_inspected(tmp_path):
    from packagealert.parsers.npm import inspect_npm_tarball

    data = json.dumps({"name": "evilpkg", "version": "1.0.0"}).encode()
    member = tarfile.TarInfo("package/package.json")
    member.size = len(data)
    with tarfile.open(tmp_path / "pkg.tgz", "w:gz") as tf:
        tf.addfile(member, io.BytesIO(data))
    info = inspect_npm_tarball(tmp_path / "pkg.tgz")
    assert info is not None and (info.name, info.version) == ("evilpkg", "1.0.0")


def test_a_lock_file_replaced_with_a_fifo_during_the_run_counts_as_changed(tmp_path):
    from packagealert.sandbox.runner import _changed_lock_files, _snapshot_lock_files

    (tmp_path / "package-lock.json").write_text("{}")
    before = _snapshot_lock_files(tmp_path)
    (tmp_path / "package-lock.json").unlink()
    os.mkfifo(tmp_path / "package-lock.json")
    changed = _bounded(lambda: _changed_lock_files(tmp_path, before))
    assert tmp_path / "package-lock.json" in changed  # type: ignore[operator]
    _bounded(lambda: _snapshot_lock_files(tmp_path))


def test_restore_replaces_a_file_swapped_for_a_fifo(tmp_path):
    from packagealert.sandbox.backends.filesystem import FileSystemBackend

    target = tmp_path / "site"
    target.mkdir()
    (target / "mod.py").write_text("original")
    backend = FileSystemBackend()
    snap = backend.snapshot_install_target(target, Console(quiet=True))
    (target / "mod.py").unlink()
    os.mkfifo(target / "mod.py")
    _bounded(lambda: backend.restore_install_target(target, snap, Console(quiet=True)))
    # Through safe_read: a FIFO left behind fails here rather than blocking the suite.
    assert safe_read.read_text(target / "mod.py") == "original"


# ── no raw read creeps back in ───────────────────────────────────────────

# Modules that read files an install (or a sandboxed run) can control. Every file read
# in them goes through packagealert.safe_read.
_GUARDED = [
    *sorted((_ROOT / "languages").glob("*.py")),
    _ROOT / "parsers" / "lockfiles.py", _ROOT / "parsers" / "npm.py", _ROOT / "parsers" / "wheel.py",
    _ROOT / "monitors" / "cache.py",
    _ROOT / "sandbox" / "runner.py", *sorted((_ROOT / "sandbox" / "backends").glob("*.py")),
]
# (module, enclosing function, call) that are not file reads an install controls.
_ALLOWED = {
    ("monitors/cache.py", "_schedule_watch", "backfill_dedup.open"),  # the scan-dedup window, not a file
    # Given a handle safe_read.open_regular() opened; zf.open reads a member of that archive.
    ("parsers/wheel.py", "read_wheel_metadata", "zipfile.ZipFile"),
    ("parsers/wheel.py", "read_wheel_metadata", "zf.open"),
}


def _raw_reads(path: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node: ast.Call) -> None:
            func, call = node.func, None
            if isinstance(func, ast.Attribute):
                base = func.value.id if isinstance(func.value, ast.Name) else "?"
                if base != "safe_read" and func.attr in ("read_text", "read_bytes"):
                    call = func.attr
                elif base in ("zipfile", "tarfile") and func.attr in ("ZipFile", "is_zipfile", "open"):
                    if not any(k.arg == "fileobj" for k in node.keywords):
                        call = f"{base}.{func.attr}"
                elif base not in ("os", "safe_read") and func.attr == "open":
                    call = f"{base}.open"
            elif isinstance(func, ast.Name) and func.id == "open":
                call = "open"
            if call is not None:
                found.append((stack[-1] if stack else "<module>", call))
            self.generic_visit(node)

    Visitor().visit(ast.parse(path.read_text()))
    return found


@pytest.mark.parametrize("module", _GUARDED, ids=lambda p: str(p.relative_to(_ROOT)))
def test_guarded_modules_read_files_only_through_safe_read(module):
    rel = str(module.relative_to(_ROOT))
    raw = [(fn, call) for fn, call in _raw_reads(module) if (rel, fn, call) not in _ALLOWED]
    assert raw == [], f"{rel}: read through packagealert.safe_read instead: {raw}"


def test_read_text_translates_newlines_like_path_read_text(tmp_path):
    (tmp_path / "f").write_bytes(b"a\r\nb\rc\n")
    assert safe_read.read_text(tmp_path / "f") == (tmp_path / "f").read_text() == "a\nb\nc\n"


def test_a_crlf_yarn_lock_still_lists_every_package(tmp_path):
    """yarn.lock is parsed by blank-line blocks: a CRLF one must not collapse into one."""
    from packagealert.languages import registry

    registry.load()
    lang = registry.for_ecosystem("npm")
    assert lang is not None
    (tmp_path / "yarn.lock").write_bytes(
        b'# yarn lockfile v1\r\n\r\n\r\nlodash@^4.17.0:\r\n  version "4.17.21"\r\n'
        b'  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"\r\n\r\n'
        b'ms@^2.0.0:\r\n  version "2.1.3"\r\n  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.3.tgz"\r\n')
    assert sorted((p.name, p.version) for p in lang.parse_lockfile(tmp_path / "yarn.lock")) == [
        ("lodash", "4.17.21"), ("ms", "2.1.3")]
