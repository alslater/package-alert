from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Literal

import aiosqlite

log = logging.getLogger(__name__)

_OUTBOX_CAP = 500

OutboxKind = Literal["scan", "alert"]
_VALID_KINDS: tuple[OutboxKind, ...] = ("scan", "alert")


@dataclass
class OutboxEntry:
    id: int
    kind: OutboxKind
    payload_json: str
    created_at: float
    attempts: int
    last_error: str | None


async def count(db: aiosqlite.Connection) -> int:
    async with db.execute("SELECT COUNT(*) AS n FROM central_outbox") as cur:
        row = await cur.fetchone()
    assert row is not None, "COUNT(*) always returns exactly one row"
    return int(row["n"])


async def count_by_kind(db: aiosqlite.Connection) -> dict[OutboxKind, int]:
    """Return {"scan": n, "alert": n} — kinds with zero queued entries are
    included with a count of 0, so callers never need `.get(kind, 0)`."""
    counts: dict[OutboxKind, int] = {kind: 0 for kind in _VALID_KINDS}
    async with db.execute(
        "SELECT kind, COUNT(*) AS n FROM central_outbox GROUP BY kind"
    ) as cur:
        rows = await cur.fetchall()
    for row in rows:
        counts[row["kind"]] = int(row["n"])
    return counts


async def _evict_oldest(db: aiosqlite.Connection) -> None:
    async with db.execute(
        "SELECT id, kind, created_at FROM central_outbox ORDER BY created_at ASC LIMIT 1"
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        return
    log.warning(
        "central_outbox at cap (%d); dropping oldest queued %s from %s",
        _OUTBOX_CAP,
        row["kind"],
        row["created_at"],
    )
    await db.execute("DELETE FROM central_outbox WHERE id=?", (row["id"],))


async def enqueue(db: aiosqlite.Connection, *, kind: OutboxKind, payload_json: str) -> None:
    if kind not in _VALID_KINDS:
        raise ValueError(f"kind must be one of {_VALID_KINDS}, got {kind!r}")
    # BEGIN IMMEDIATE takes the write lock up front, so the count-check,
    # eviction, and insert are atomic against concurrent enqueue() calls —
    # without it, two callers could both read the same count(), both decide
    # not to evict, and both insert, silently exceeding the cap.
    await db.execute("BEGIN IMMEDIATE")
    try:
        if await count(db) >= _OUTBOX_CAP:
            await _evict_oldest(db)
        await db.execute(
            """INSERT INTO central_outbox(kind, payload_json, created_at, attempts, last_error)
               VALUES(?, ?, ?, 0, NULL)""",
            (kind, payload_json, time.time()),
        )
        await db.commit()
    except BaseException:
        await db.rollback()
        raise


async def dequeue_all(
    db: aiosqlite.Connection, *, kind: OutboxKind | None = None
) -> list[OutboxEntry]:
    if kind is not None and kind not in _VALID_KINDS:
        raise ValueError(f"kind must be one of {_VALID_KINDS}, got {kind!r}")
    if kind is not None:
        sql = """SELECT id, kind, payload_json, created_at, attempts, last_error
                 FROM central_outbox WHERE kind=? ORDER BY created_at ASC"""
        params: tuple = (kind,)
    else:
        sql = """SELECT id, kind, payload_json, created_at, attempts, last_error
                 FROM central_outbox ORDER BY created_at ASC"""
        params = ()
    async with db.execute(sql, params) as cur:
        rows = await cur.fetchall()
    return [
        OutboxEntry(
            id=r["id"],
            kind=r["kind"],
            payload_json=r["payload_json"],
            created_at=r["created_at"],
            attempts=r["attempts"],
            last_error=r["last_error"],
        )
        for r in rows
    ]


async def delete(db: aiosqlite.Connection, entry_id: int, *, commit: bool = True) -> None:
    """Delete outbox entry *entry_id*.

    *commit* defaults to True (commit immediately, the historical
    behavior, and what every current caller uses). Pass commit=False if a
    future caller needs to batch several delete()/mark_failed() calls
    inside its own explicit transaction to cut down on fsyncs — one commit
    per row is real, avoidable cost for a caller processing many rows back
    to back with no I/O in between. NOTE: _drain_outbox() deliberately does
    NOT use this — it interleaves a network call to the fleet server
    between each row's DB mutation, and holding one open transaction across
    that network I/O would block a concurrent _enqueue_outbox()'s own
    BEGIN IMMEDIATE on the same shared connection for the whole drain tick
    (confirmed directly), trading the "many fsyncs" cost for a "stall
    concurrent alert reports" cost that's worse. commit=False is here for a
    caller that doesn't have that interleaved-I/O shape.
    """
    await db.execute("DELETE FROM central_outbox WHERE id=?", (entry_id,))
    if commit:
        await db.commit()


async def mark_failed(
    db: aiosqlite.Connection, entry_id: int, error: str, *, commit: bool = True
) -> None:
    """Record a failed send attempt for outbox entry *entry_id*.

    See delete()'s *commit* parameter — same rationale and the same
    "not used by _drain_outbox()" caveat.
    """
    await db.execute(
        "UPDATE central_outbox SET attempts = attempts + 1, last_error = ? WHERE id = ?",
        (error, entry_id),
    )
    if commit:
        await db.commit()
