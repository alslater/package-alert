from __future__ import annotations

import logging
from pathlib import Path

import pytest

from packagealert.remediate.adapter import Discovery, discover


class _Adapter:
    def __init__(self, name: str, lockfile_name: str):
        self.name = name
        self.ecosystem = "PyPI"
        self.lockfile_name = lockfile_name

    def find_lockfile(self, root: Path) -> Path | None:
        lock = root / self.lockfile_name
        return lock if lock.is_file() else None

    def load_graph(self, lockfile): raise NotImplementedError
    def locked_packages(self, lockfile): raise NotImplementedError
    def commands(self, plan): raise NotImplementedError
    def probe_argv(self): raise NotImplementedError
    async def trial(self, pins, floats, run, *, force=()): raise NotImplementedError


class _Lang:
    def __init__(self, name: str, adapters):
        self.name = name
        self._adapters = adapters

    def fix_adapters(self):
        if isinstance(self._adapters, Exception):
            raise self._adapters
        return self._adapters


class _NoHook:
    name = "nohook"


def test_discover_finds_the_adapter_whose_lock_file_exists(tmp_path):
    (tmp_path / "uv.lock").write_text("")
    uv = _Adapter("uv", "uv.lock")
    found = discover(tmp_path, [_Lang("python", [uv, _Adapter("pipenv", "Pipfile.lock")]), _NoHook()])
    assert found.matches == [(uv, tmp_path / "uv.lock")]
    assert found.supported == ["uv.lock", "Pipfile.lock"]


def test_discover_with_no_lock_file_lists_what_is_supported(tmp_path):
    found = discover(tmp_path, [_Lang("python", [_Adapter("uv", "uv.lock")])])
    assert found == Discovery(matches=[], supported=["uv.lock"])


def test_discover_reports_every_match(tmp_path):
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "Pipfile.lock").write_text("")
    found = discover(tmp_path, [_Lang("python", [_Adapter("uv", "uv.lock"), _Adapter("pipenv", "Pipfile.lock")])])
    assert [a.name for a, _ in found.matches] == ["uv", "pipenv"]


def test_discover_isolates_misbehaving_plugins(tmp_path, caplog):
    (tmp_path / "uv.lock").write_text("")
    good = _Adapter("uv", "uv.lock")

    class Incomplete:
        name, ecosystem, lockfile_name = "incomplete-adapter", "PyPI", "x.lock"

    def raise_oserror(root):
        raise OSError("boom")

    raising_find = _Adapter("raising-find", "rf.lock")
    raising_find.find_lockfile = raise_oserror  # type: ignore[method-assign]
    bad_return = _Adapter("str-return", "br.lock")
    bad_return.find_lockfile = lambda root: "br.lock"  # type: ignore[method-assign]
    bad_label = _Adapter("int-label", "bl.lock")
    bad_label.lockfile_name = 3  # type: ignore[assignment]

    languages = [
        _Lang("raises", RuntimeError("boom")),
        _Lang("not-a-list", _Adapter("t", "t.lock")),
        _Lang("mixed", [Incomplete(), raising_find, bad_return, bad_label]),
        _Lang("python", [good]),
    ]
    with caplog.at_level(logging.WARNING):
        found = discover(tmp_path, languages)
    assert found.matches == [(good, tmp_path / "uv.lock")]
    assert found.supported == ["uv.lock"]
    for name in ("lang=raises", "lang=not-a-list", "incomplete-adapter", "raising-find", "str-return", "int-label"):
        assert name in caplog.text


def test_discover_uses_the_registry_by_default(tmp_path):
    found = discover(tmp_path)
    assert isinstance(found, Discovery)
    assert "uv.lock" in found.supported


def test_discover_survives_raising_names_and_iteration(tmp_path):
    (tmp_path / "uv.lock").write_text("")
    good = _Adapter("uv", "uv.lock")

    class RaisingName(_Adapter):
        @property  # type: ignore[override]
        def name(self):
            raise RuntimeError("name prop")

        @name.setter
        def name(self, value):
            pass

    class RaisingList(list):
        def __iter__(self):
            raise RuntimeError("iter")

    class RaisingLangName:
        @property
        def name(self):
            raise RuntimeError("lang name")

        def fix_adapters(self):
            return [RaisingName("x", "x.lock")]

    languages = [
        _Lang("raising-name", [RaisingName("x", "x.lock")]),
        _Lang("raising-iter", RaisingList([good])),
        RaisingLangName(),
        _Lang("python", [good]),
    ]
    found = discover(tmp_path, languages)
    assert found.matches == [(good, tmp_path / "uv.lock")]


@pytest.mark.parametrize("method", ["find_lockfile", "load_graph", "locked_packages", "commands",
                                    "probe_argv", "trial"])
def test_adapter_with_a_non_callable_operation_is_skipped(tmp_path, caplog, method):
    (tmp_path / "uv.lock").write_text("")
    good = _Adapter("uv", "uv.lock")
    broken = _Adapter("broken", "uv.lock")
    setattr(broken, method, None)
    with caplog.at_level(logging.WARNING):
        found = discover(tmp_path, [_Lang("third-party", [broken]), _Lang("python", [good])])
    assert found.matches == [(good, tmp_path / "uv.lock")]
    assert "broken" in caplog.text


@pytest.mark.parametrize("attr, value", [("name", 3), ("name", ""), ("ecosystem", None), ("ecosystem", ""),
                                         ("lockfile_name", "")])
def test_adapter_with_a_malformed_string_attribute_is_skipped(tmp_path, caplog, attr, value):
    (tmp_path / "uv.lock").write_text("")
    good = _Adapter("uv", "uv.lock")
    broken = _Adapter("broken", "uv.lock")
    setattr(broken, attr, value)
    with caplog.at_level(logging.WARNING):
        found = discover(tmp_path, [_Lang("third-party", [broken]), _Lang("python", [good])])
    assert found.matches == [(good, tmp_path / "uv.lock")]
    assert "Unusable fix adapter" in caplog.text


def test_adapter_without_trial_is_skipped(tmp_path):
    class Old:
        name, ecosystem, lockfile_name = "old", "PyPI", "x.lock"
        def find_lockfile(self, root): return root / "x.lock"
        def load_graph(self, lockfile): ...
        def locked_packages(self, lockfile): ...
        def commands(self, plan, project_dir=None, sync_flags=()): ...
        def trial_argv(self, pins, floats=()): ...
        def parse_trial(self, *a, **k): ...

    class Lang:
        name = "x"
        def fix_adapters(self): return [Old()]

    assert discover(tmp_path, [Lang()]).matches == []
