"""The unit-test home isolation itself (#69)."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import urllib.parse
from pathlib import Path

import pytest

from tests.unit import _home_isolation
from tests.unit._home_isolation import (
    REAL_DATA_DIR,
    REAL_HOME,
    home_globals,
    unredirectable_defaults,
)


def test_no_home_path_is_bound_where_a_fixture_cannot_redirect_it():
    # A function or pydantic default computed from Path.home() at import keeps pointing at the
    # real home whatever a test does; the package must look the path up when it is used.
    assert unredirectable_defaults() == []


def test_every_home_derived_global_is_redirected():
    # Into this test's home. Not "none under the real home": pytest's base temp directory may
    # itself lie under it (--basetemp=$HOME/...).
    home = Path.home()
    assert [f"{m.__name__}.{a}" for m, a, v in home_globals() if not v.is_relative_to(home)] == []


def test_default_paths_follow_the_test_home():
    from packagealert.config import AppConfig, load_config
    from packagealert.sandbox import runner
    from packagealert.storage import db

    home = Path.home()
    assert home != REAL_HOME
    assert db.DEFAULT_DB_PATH.is_relative_to(home)
    assert runner.SCRATCH_ROOT.is_relative_to(home)
    log_file = AppConfig().log.file
    assert log_file is not None and log_file.is_relative_to(home)
    # The real user config is not read: load_config(None) sees only the test home.
    assert load_config(None).model_dump() == AppConfig().model_dump()


async def test_open_db_with_no_path_uses_the_test_home():
    from packagealert.storage.db import open_db

    db = await open_db(enabled_plugins=set())
    await db.close()
    assert (Path.home() / ".local" / "share" / "package-alert" / "package-alert.db").exists()


def test_the_real_data_directory_is_protected():
    assert REAL_DATA_DIR in _home_isolation.PROTECTED_ROOTS


@pytest.fixture
def probe(monkeypatch):
    """A protected database path inside this test's own home: the guard tests never go near the
    real data directory, so a broken guard cannot touch it either."""
    root = Path.home() / "protected-data"
    monkeypatch.setattr(_home_isolation, "PROTECTED_ROOTS", [root])
    return root / "package-alert.db"


def test_guard_refuses_a_protected_database(_isolated_home, probe):
    with pytest.raises(pytest.fail.Exception, match="real package-alert database"):
        sqlite3.connect(probe)
    assert _isolated_home == [probe]
    _isolated_home.clear()  # deliberate: otherwise the fixture fails this test at teardown


def test_guard_refuses_a_protected_database_through_aiosqlite(_isolated_home, probe):
    import aiosqlite

    async def open_protected():
        async with aiosqlite.connect(probe):
            pass

    with pytest.raises(pytest.fail.Exception, match="real package-alert database"):
        asyncio.run(open_protected())
    _isolated_home.clear()


async def test_guard_escapes_a_caller_that_catches_exception(_isolated_home, probe, monkeypatch):
    # _open_gate_resources() turns any Exception into "gate resources unavailable" and skips the
    # gates, which would hide an AssertionError; pytest.fail is a BaseException.
    from packagealert.config import AppConfig
    from packagealert.sandbox.runner import SandboxRunner
    from packagealert.storage import db

    monkeypatch.setattr(db, "DEFAULT_DB_PATH", probe)
    with pytest.raises(pytest.fail.Exception, match="real package-alert database"):
        await SandboxRunner(AppConfig())._open_gate_resources()
    _isolated_home.clear()


def test_guard_records_what_a_baseexception_handler_swallows(_isolated_home, probe):
    # The fixture fails the test at teardown from this record, so even a handler that catches
    # BaseException cannot hide the access.
    try:
        sqlite3.connect(probe)
    except BaseException:  # noqa: BLE001, S110 — the swallowing caller under test
        pass
    assert _isolated_home == [probe]
    _isolated_home.clear()


class _BytesPath:
    """A valid os.PathLike whose __fspath__() returns bytes, which sqlite3.connect() accepts."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def __fspath__(self) -> bytes:
        return os.fsencode(self._path)


@pytest.mark.parametrize("form", ["relative", "bytes", "bytes-pathlike", "uri", "percent-encoded-uri", "symlink"])
def test_guard_sees_through_other_spellings_of_a_protected_path(_isolated_home, probe, form, monkeypatch, tmp_path):
    probe.parent.mkdir(parents=True)
    kwargs: dict[str, bool] = {}
    if form == "relative":
        monkeypatch.chdir(probe.parent)
        arg: object = probe.name
    elif form == "bytes":
        arg = os.fsencode(probe)
    elif form == "bytes-pathlike":
        arg = _BytesPath(probe)
    elif form == "uri":
        arg, kwargs = f"file:{probe}?mode=rwc", {"uri": True}
    elif form == "percent-encoded-uri":
        arg, kwargs = "file:" + urllib.parse.quote(str(probe), safe="/"), {"uri": True}
    else:
        link = tmp_path / "link"
        link.symlink_to(probe.parent, target_is_directory=True)
        arg = link / probe.name
    with pytest.raises(pytest.fail.Exception, match="real package-alert database"):
        sqlite3.connect(arg, **kwargs)  # type: ignore[call-overload]  # bytes and object forms are the point
    assert not probe.exists()
    _isolated_home.clear()


@pytest.mark.parametrize(("database", "uri"), [(":memory:", False), ("", False),
                                                ("file:x?mode=memory", True)])
def test_guard_allows_memory_and_temporary_databases(probe, database, uri):
    sqlite3.connect(database, uri=uri).close()


def test_a_tests_own_monkeypatch_undo_leaves_isolation_active(monkeypatch, _isolated_home, probe):
    # Two tests call monkeypatch.undo(); that must not restore the real home or unguard SQLite.
    home = Path.home()
    monkeypatch.undo()
    assert Path.home() == home != REAL_HOME
    from packagealert.storage import db
    assert db.DEFAULT_DB_PATH.is_relative_to(home)
    # undo() also lifted the probe fixture's own patch; protect the probe again.
    monkeypatch.setattr(_home_isolation, "PROTECTED_ROOTS", [probe.parent])
    probe.parent.mkdir(parents=True)
    with pytest.raises(pytest.fail.Exception, match="real package-alert database"):
        sqlite3.connect(probe)
    _isolated_home.clear()


def test_real_home_is_the_one_the_session_started_with():
    # Guards the guard: REAL_HOME is captured before any fixture changes HOME.
    assert REAL_HOME != Path.home()


def test_no_global_is_left_pointing_at_another_tests_home(tmp_path_factory):
    # A module first imported after HOME moved would bind its constants to that test's home and
    # keep them there for the rest of the session.
    from tests.unit._home_isolation import _modules

    base, home = tmp_path_factory.getbasetemp(), Path.home()

    def other_home(v: object) -> bool:
        if not isinstance(v, Path) or not v.is_relative_to(base):
            return False
        top = base / v.relative_to(base).parts[0]
        return top.name.startswith("home") and top != home

    stale = [f"{m.__name__}.{a}" for m in _modules() for a, v in list(vars(m).items()) if other_home(v)]
    assert stale == []
