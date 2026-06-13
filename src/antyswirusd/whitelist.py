"""SQLite-backed :class:`Whitelist` implementation.

A single aiosqlite connection is held for the lifetime of the
instance and shared between scanner and worker coroutines.

Schema
------

::

    CREATE TABLE entries (
        kind     TEXT NOT NULL,
        value    TEXT NOT NULL,
        added_at REAL NOT NULL,
        note     TEXT,
        PRIMARY KEY (kind, value)
    );
    CREATE INDEX idx_entries_kind ON entries(kind);

Semantics
---------

- ``matches_directory(path)`` matches the ``path`` entry if it
  equals the path *or* the path is a strict descendant
  (``path LIKE value || '/%'``). The trailing-slash join is what
  prevents the look-alike-prefix bug: a whitelist of ``/foo`` does
  not match ``/foobar``.
- ``is_hash_whitelisted(hash)`` is a direct equality check on the
  SHA-256 entry; the 64-hex-char format is enforced upstream by the
  IPC server before the row is inserted.
- ``remove`` is idempotent: it returns ``True`` only when a row was
  actually deleted, so the engine can decide whether a rescan is
  needed.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import aiosqlite

from antyswirus_lib.types import WhitelistEntry, WhitelistKind

log = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    kind     TEXT NOT NULL,
    value    TEXT NOT NULL,
    added_at REAL NOT NULL,
    note     TEXT,
    PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_entries_kind ON entries(kind);
"""


class Whitelist:
    """aiosqlite-backed :class:`Whitelist` implementation."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None
        self._closed = False

    async def open(self) -> None:
        if self._db is not None:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(self._db_path))
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.executescript(_SCHEMA)
        await db.commit()
        self._db = db

    async def close(self) -> None:
        if self._db is None:
            return
        db, self._db = self._db, None
        await db.close()
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    async def matches_directory(self, path: Path) -> bool:
        assert self._db is not None
        text = str(path)
        # We test two predicates: an exact match and a strict descendant
        # (path LIKE value || '/%'). The slash prefix prevents the
        # `/foo` vs `/foobar` lookalike-prefix bug.
        sql = (
            "SELECT 1 FROM entries "
            "WHERE kind = ? AND (? = value OR ? LIKE value || '/%') "
            "LIMIT 1"
        )
        async with self._db.execute(sql, (WhitelistKind.PATH.value, text, text)) as cur:
            row = await cur.fetchone()
        return row is not None

    async def is_hash_whitelisted(self, content_hash: str) -> bool:
        assert self._db is not None
        sql = "SELECT 1 FROM entries WHERE kind = ? AND value = ? LIMIT 1"
        async with self._db.execute(
            sql, (WhitelistKind.SHA256.value, content_hash)
        ) as cur:
            row = await cur.fetchone()
        return row is not None

    async def add(self, entry: WhitelistEntry) -> None:
        assert self._db is not None
        added_at = entry.added_at if entry.added_at > 0 else time.time()
        # INSERT OR IGNORE: keep the original added_at/note on duplicates.
        await self._db.execute(
            "INSERT OR IGNORE INTO entries(kind, value, added_at, note) "
            "VALUES (?, ?, ?, ?)",
            (entry.kind.value, entry.value, added_at, entry.note),
        )
        await self._db.commit()
        log.info("whitelist add: %s", entry)

    async def remove(self, entry: WhitelistEntry) -> bool:
        assert self._db is not None
        cur = await self._db.execute(
            "DELETE FROM entries WHERE kind = ? AND value = ?",
            (entry.kind.value, entry.value),
        )
        await self._db.commit()
        deleted = cur.rowcount > 0
        if deleted:
            log.info("whitelist remove: %s", entry)
        return deleted

    async def list(self) -> list[WhitelistEntry]:
        assert self._db is not None
        async with self._db.execute(
            "SELECT kind, value, added_at, note FROM entries "
            "ORDER BY added_at, kind, value"
        ) as cur:
            rows = await cur.fetchall()
        result: list[WhitelistEntry] = []
        for kind_raw, value, added_at, note in rows:
            try:
                kind = WhitelistKind(kind_raw)
            except ValueError:
                log.warning("whitelist row has unknown kind %r", kind_raw)
                continue
            result.append(
                WhitelistEntry(
                    kind=kind,
                    value=value,
                    added_at=added_at,
                    note=note,
                )
            )
        return result
