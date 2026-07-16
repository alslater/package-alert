from __future__ import annotations

import asyncio
import json

import pytest

from packagealert.storage.db import open_db
from packagealert.plugins.central import outbox
from packagealert.plugins.central.outbox import (
    OutboxEntry,
    enqueue,
    dequeue_all,
    delete,
    mark_failed,
    count,
    count_by_kind,
)


@pytest.fixture
async def db(tmp_path):
    conn = await open_db(tmp_path / "test.db", enabled_plugins={"pa-central"})
    yield conn
    await conn.close()


async def test_enqueue_and_dequeue_all(db):
    await enqueue(db, kind="scan", payload_json=json.dumps({"a": 1}))
    await enqueue(db, kind="alert", payload_json=json.dumps({"b": 2}))
    entries = await dequeue_all(db)
    assert len(entries) == 2
    assert all(isinstance(e, OutboxEntry) for e in entries)
    kinds = {e.kind for e in entries}
    assert kinds == {"scan", "alert"}


async def test_dequeue_all_filters_by_kind(db):
    await enqueue(db, kind="scan", payload_json=json.dumps({"a": 1}))
    await enqueue(db, kind="alert", payload_json=json.dumps({"b": 2}))
    entries = await dequeue_all(db, kind="scan")
    assert len(entries) == 1
    assert entries[0].kind == "scan"


async def test_enqueue_rejects_invalid_kind(db):
    with pytest.raises(ValueError, match="kind must be one of"):
        await enqueue(db, kind="bogus", payload_json=json.dumps({"a": 1}))


async def test_dequeue_all_rejects_invalid_kind(db):
    # enqueue() already validates kind; dequeue_all() must too — otherwise a
    # typo'd kind silently returns an empty list instead of surfacing the
    # bug, since central_outbox's CHECK constraint only ever sees valid
    # kinds (enqueue() is the only writer), so a bad filter value here just
    # never matches any row rather than erroring.
    await enqueue(db, kind="scan", payload_json=json.dumps({"a": 1}))
    with pytest.raises(ValueError, match="kind must be one of"):
        await dequeue_all(db, kind="bogus")


async def test_dequeue_all_orders_oldest_first(db):
    await enqueue(db, kind="scan", payload_json=json.dumps({"n": 1}))
    await enqueue(db, kind="scan", payload_json=json.dumps({"n": 2}))
    entries = await dequeue_all(db)
    assert [json.loads(e.payload_json)["n"] for e in entries] == [1, 2]


async def test_delete_removes_row(db):
    await enqueue(db, kind="scan", payload_json=json.dumps({"a": 1}))
    entries = await dequeue_all(db)
    await delete(db, entries[0].id)
    assert await dequeue_all(db) == []


async def test_delete_with_commit_false_defers_commit(tmp_path):
    # commit=False lets a caller batch several delete()/mark_failed() calls
    # inside its own explicit transaction to cut fsyncs — verified via a
    # second connection to the same file, which can only see the delete
    # once it's actually committed.
    db_path = tmp_path / "defer.db"
    conn_a = await open_db(db_path, enabled_plugins={"pa-central"})
    conn_b = await open_db(db_path, enabled_plugins={"pa-central"})
    try:
        await enqueue(conn_a, kind="scan", payload_json=json.dumps({"a": 1}))
        entries = await dequeue_all(conn_a)
        await delete(conn_a, entries[0].id, commit=False)

        # Not yet committed — a second connection still sees the row.
        assert len(await dequeue_all(conn_b)) == 1

        await conn_a.commit()
        assert await dequeue_all(conn_b) == []
    finally:
        await conn_a.close()
        await conn_b.close()


async def test_mark_failed_with_commit_false_defers_commit(tmp_path):
    db_path = tmp_path / "defer2.db"
    conn_a = await open_db(db_path, enabled_plugins={"pa-central"})
    conn_b = await open_db(db_path, enabled_plugins={"pa-central"})
    try:
        await enqueue(conn_a, kind="scan", payload_json=json.dumps({"a": 1}))
        entries = await dequeue_all(conn_a)
        await mark_failed(conn_a, entries[0].id, "boom", commit=False)

        # Not yet committed — a second connection still sees the old state.
        assert (await dequeue_all(conn_b))[0].attempts == 0

        await conn_a.commit()
        assert (await dequeue_all(conn_b))[0].attempts == 1
    finally:
        await conn_a.close()
        await conn_b.close()


async def test_mark_failed_increments_attempts_and_sets_error(db):
    await enqueue(db, kind="scan", payload_json=json.dumps({"a": 1}))
    entries = await dequeue_all(db)
    entry_id = entries[0].id
    await mark_failed(db, entry_id, "connection refused")
    updated = await dequeue_all(db)
    assert updated[0].attempts == 1
    assert updated[0].last_error == "connection refused"

    await mark_failed(db, entry_id, "timeout")
    updated = await dequeue_all(db)
    assert updated[0].attempts == 2
    assert updated[0].last_error == "timeout"


async def test_count_reflects_row_count(db):
    assert await count(db) == 0
    await enqueue(db, kind="scan", payload_json=json.dumps({"a": 1}))
    assert await count(db) == 1


async def test_count_by_kind_returns_zero_for_empty_outbox(db):
    assert await count_by_kind(db) == {"scan": 0, "alert": 0}


async def test_count_by_kind_splits_scan_and_alert(db):
    await enqueue(db, kind="scan", payload_json=json.dumps({"a": 1}))
    await enqueue(db, kind="scan", payload_json=json.dumps({"a": 2}))
    await enqueue(db, kind="alert", payload_json=json.dumps({"b": 1}))

    assert await count_by_kind(db) == {"scan": 2, "alert": 1}


async def test_enqueue_evicts_oldest_when_at_cap(db, monkeypatch):
    # The cap-eviction logic doesn't care about the cap's actual size — only
    # that eviction triggers once count() reaches it. Patching it down to a
    # small value validates the same behavior with far fewer DB round trips
    # than looping to the real production cap (500).
    cap = 5
    monkeypatch.setattr(outbox, "_OUTBOX_CAP", cap)

    for i in range(cap):
        await enqueue(db, kind="scan", payload_json=json.dumps({"n": i}))
    assert await count(db) == cap

    await enqueue(db, kind="scan", payload_json=json.dumps({"n": "overflow"}))

    assert await count(db) == cap
    entries = await dequeue_all(db)
    payload_ns = [json.loads(e.payload_json)["n"] for e in entries]
    assert 0 not in payload_ns  # oldest (n=0) was evicted
    assert "overflow" in payload_ns


async def test_enqueue_cap_holds_under_concurrent_callers(tmp_path, monkeypatch):
    # Two independent connections to the same on-disk DB, driving enqueue()
    # concurrently — this is the shape that would race without BEGIN IMMEDIATE:
    # both connections could read the same count() before either commits its
    # insert, and both skip eviction, pushing the table past the cap.
    # A small patched cap exercises the same race with far fewer inserts
    # than looping to the real production cap (500).
    cap = 5
    monkeypatch.setattr(outbox, "_OUTBOX_CAP", cap)

    db_path = tmp_path / "concurrent.db"
    conn_a = await open_db(db_path, enabled_plugins={"pa-central"})
    conn_b = await open_db(db_path, enabled_plugins={"pa-central"})
    try:
        for i in range(cap - 1):
            await enqueue(conn_a, kind="scan", payload_json=json.dumps({"n": i}))
        assert await count(conn_a) == cap - 1

        # These two enqueue() calls race for the same slot at the cap boundary.
        await asyncio.gather(
            enqueue(conn_a, kind="scan", payload_json=json.dumps({"n": "a"})),
            enqueue(conn_b, kind="scan", payload_json=json.dumps({"n": "b"})),
        )

        assert await count(conn_a) == cap
    finally:
        await conn_a.close()
        await conn_b.close()
