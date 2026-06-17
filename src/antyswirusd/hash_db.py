"""Local SQLite-backed malware hash database.

Stores SHA-256 hashes from MalwareBazaar in a single table. The
update/sync logic lives in separate modules; this class only owns
the schema and query methods.

Schema
-----

::

    CREATE TABLE malware_hashes (
        sha256          TEXT PRIMARY KEY,
        source          TEXT NOT NULL,    -- 'malwarebazaar'
        first_seen_utc  TEXT,             -- ISO-8601 datetime from source
        imported_at     REAL NOT NULL     -- unix timestamp of import
    );
    CREATE INDEX idx_hashes_source ON malware_hashes(source);
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import aiosqlite

from antyswirus_lib.types import HashLookup, Verdict

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS malware_hashes (
    sha256          TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    first_seen_utc  TEXT,
    imported_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hashes_source ON malware_hashes(source);
CREATE TABLE IF NOT EXISTS sync_meta (
    source      TEXT PRIMARY KEY,
    last_seq    TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
"""


class HashDatabase:
    """Local hash database queried by SHA-256."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

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
        if self._db is not None:
            db, self._db = self._db, None
            await db.close()

    async def lookup_by_hash(self, content_hash: str) -> HashLookup:
        """Return a verdict for the given SHA-256.

        Returns MALICIOUS if found in the database, UNKNOWN otherwise.
        """
        assert self._db is not None
        async with self._db.execute(
            "SELECT 1 FROM malware_hashes WHERE sha256 = ? LIMIT 1",
            (content_hash,),
        ) as cur:
            row = await cur.fetchone()
        if row is not None:
            return HashLookup(verdict=Verdict.MALICIOUS)
        return HashLookup(verdict=Verdict.UNKNOWN)

    # ------------------------------------------------------------------
    # Bulk import helpers (called by sync modules)
    # ------------------------------------------------------------------

    async def import_malwarebazaar_rows(self, rows: list[list[str | None]]) -> int:
        """Insert/update rows from a MalwareBazaar CSV dump.

        Each row is a positional list where ``row[0]`` is the
        ``first_seen_utc`` timestamp and ``row[1]`` is the SHA-256 hash.
        MalwareBazaar rows replace any existing entry for the same SHA-256.

        Uses ``executemany`` for performance. Returns the number of rows
        added (new minus replaced).
        """
        assert self._db is not None
        before = await self._row_count()
        now = time.time()
        params: list[tuple[str, str | None, float]] = []
        for r in rows:
            if len(r) < 2:
                continue
            sha256 = r[1]
            if not sha256:
                continue
            params.append(
                (
                    sha256,
                    r[0],
                    now,
                )
            )
        if not params:
            return 0
        try:
            await self._db.executemany(
                """
                INSERT INTO malware_hashes(
                    sha256, source, first_seen_utc, imported_at
                ) VALUES (?, 'malwarebazaar', ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    source          = 'malwarebazaar',
                    first_seen_utc  = COALESCE(excluded.first_seen_utc, malware_hashes.first_seen_utc),
                    imported_at     = excluded.imported_at
                """,
                params,
            )
        except Exception:
            log.warning("malwarebazaar batch import failed", exc_info=True)
            raise
        await self._db.commit()
        return (await self._row_count()) - before

    async def _row_count(self) -> int:
        assert self._db is not None
        async with self._db.execute("SELECT COUNT(*) FROM malware_hashes") as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async def get_sync_meta(self, source: str) -> str | None:
        """Return the last sync token for *source*, or None."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT last_seq FROM sync_meta WHERE source = ?", (source,)
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else None

    async def set_sync_meta(self, source: str, last_seq: str) -> None:
        assert self._db is not None
        await self._db.execute(
            "INSERT INTO sync_meta(source, last_seq, updated_at) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(source) DO UPDATE SET last_seq = excluded.last_seq, "
            "updated_at = excluded.updated_at",
            (source, last_seq, time.time()),
        )
        await self._db.commit()

    async def count(self) -> int:
        """Return the total number of stored hashes."""
        assert self._db is not None
        async with self._db.execute("SELECT COUNT(*) FROM malware_hashes") as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async def count_by_source(self) -> dict[str, int]:
        """Return a mapping of source -> row count."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT source, COUNT(*) FROM malware_hashes GROUP BY source"
        ) as cur:
            rows = await cur.fetchall()
        return dict(rows)
