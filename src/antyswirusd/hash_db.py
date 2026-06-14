"""Local SQLite-backed malware hash database.

Stores SHA-256, SHA-1, and MD5 hashes from multiple sources
(MalwareBazaar, VirusShare) in a single table. The update/sync
logic for each source lives in separate modules; this class only
owns the schema and query methods.

Schema
------

::

    CREATE TABLE malware_hashes (
        sha256      TEXT PRIMARY KEY,
        sha1        TEXT,
        md5         TEXT,
        source      TEXT NOT NULL,    -- 'malwarebazaar' | 'virusshare'
        first_seen  TEXT,             -- ISO-8601 datetime from source
        file_name   TEXT,
        file_type   TEXT,
        tags        TEXT,             -- JSON list
        signature   TEXT,             -- malware family / label
        imported_at REAL NOT NULL     -- unix timestamp of import
    );
    CREATE INDEX idx_hashes_md5   ON malware_hashes(md5);
    CREATE INDEX idx_hashes_sha1  ON malware_hashes(sha1);
    CREATE INDEX idx_hashes_source ON malware_hashes(source);
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import aiosqlite

from antyswirus_lib.types import HashLookup, Verdict

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS malware_hashes (
    sha256      TEXT PRIMARY KEY,
    sha1        TEXT,
    md5         TEXT,
    source      TEXT NOT NULL,
    first_seen  TEXT,
    file_name   TEXT,
    file_type   TEXT,
    tags        TEXT,
    signature   TEXT,
    imported_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hashes_md5 ON malware_hashes(md5);
CREATE INDEX IF NOT EXISTS idx_hashes_sha1 ON malware_hashes(sha1);
CREATE INDEX IF NOT EXISTS idx_hashes_source ON malware_hashes(source);
CREATE TABLE IF NOT EXISTS sync_meta (
    source      TEXT PRIMARY KEY,
    last_seq    TEXT NOT NULL,
    updated_at  REAL NOT NULL
);
"""


class HashDatabase:
    """Local hash database that can be queried by any of the three hash forms.

    Lookups try SHA-256 first (primary key), then SHA-1, then MD5,
    and return the first match found.
    """

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

    async def lookup_by_hash(
        self, content_hash: str, *, source: str | None = None
    ) -> HashLookup:
        """Return a verdict for the given hash.

        Tries SHA-256, SHA-1, then MD5. If *source* is given, only
        rows from that source are considered. MalwareBazaar rows are
        preferred when no source filter is given (queried first).
        Returns UNKNOWN if not found.
        """
        assert self._db is not None
        sources = [source] if source else ["malwarebazaar", "virusshare"]
        for src in sources:
            for column in ("sha256", "sha1", "md5"):
                async with self._db.execute(
                    f"SELECT source, signature, file_name FROM malware_hashes "
                    f"WHERE {column} = ? AND source = ? LIMIT 1",
                    (content_hash, src),
                ) as cur:
                    row = await cur.fetchone()
                if row is not None:
                    src_name, signature, file_name = row
                    parts = [f"source={src_name}"]
                    if signature:
                        parts.append(f"family={signature}")
                    if file_name:
                        parts.append(f"name={file_name}")
                    return HashLookup(
                        verdict=Verdict.MALICIOUS, detail="; ".join(parts)
                    )
        return HashLookup(verdict=Verdict.UNKNOWN)

    # ------------------------------------------------------------------
    # Bulk import helpers (called by sync modules)
    # ------------------------------------------------------------------

    async def import_malwarebazaar_rows(
        self, rows: list[dict[str, str | None]]
    ) -> int:
        """Insert/update rows from a MalwareBazaar CSV dump.

        Each dict must have keys: sha256_hash, sha1_hash, md5_hash,
        first_seen, file_name, file_type, tags, signature.
        MalwareBazaar rows take priority over VirusShare entries for
        the same SHA-256 (the source is set to 'malwarebazaar').

        Returns the number of rows processed (new + updated).
        """
        assert self._db is not None
        before = await self._row_count()
        now = time.time()
        for r in rows:
            sha256 = r.get("sha256_hash")
            if not sha256:
                continue
            tags_raw = r.get("tags") or ""
            tags_json = json.dumps([t.strip() for t in tags_raw.split(",") if t.strip()])
            try:
                await self._db.execute(
                    """
                    INSERT INTO malware_hashes(
                        sha256, sha1, md5, source, first_seen,
                        file_name, file_type, tags, signature, imported_at
                    ) VALUES (?, ?, ?, 'malwarebazaar', ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(sha256) DO UPDATE SET
                        source      = 'malwarebazaar',
                        sha1        = COALESCE(excluded.sha1, malware_hashes.sha1),
                        md5         = COALESCE(excluded.md5, malware_hashes.md5),
                        first_seen  = COALESCE(excluded.first_seen, malware_hashes.first_seen),
                        file_name   = COALESCE(excluded.file_name, malware_hashes.file_name),
                        file_type   = COALESCE(excluded.file_type, malware_hashes.file_type),
                        tags        = COALESCE(excluded.tags, malware_hashes.tags),
                        signature   = COALESCE(excluded.signature, malware_hashes.signature),
                        imported_at = excluded.imported_at
                    """,
                    (
                        sha256,
                        r.get("sha1_hash"),
                        r.get("md5_hash"),
                        r.get("first_seen"),
                        r.get("file_name"),
                        r.get("file_type"),
                        tags_json,
                        r.get("signature"),
                        now,
                    ),
                )
            except Exception:
                log.debug("import failed for sha256=%s", sha256)
        await self._db.commit()
        return (await self._row_count()) - before

    async def import_virusshare_hashes(
        self, hashes: list[str]
    ) -> int:
        """Insert SHA-256 hashes from VirusShare hash lists.

        Only SHA-256 is provided by VirusShare; SHA-1 and MD5 are
        left NULL. Returns the number of new rows inserted.
        """
        assert self._db is not None
        before = await self._row_count()
        now = time.time()
        for h in hashes:
            h = h.strip()
            if len(h) != 64 or not all(c in "0123456789abcdef" for c in h.lower()):
                continue
            try:
                await self._db.execute(
                    """
                    INSERT OR IGNORE INTO malware_hashes(
                        sha256, source, imported_at
                    ) VALUES (?, 'virusshare', ?)
                    """,
                    (h, now),
                )
            except Exception:
                pass
        await self._db.commit()
        return (await self._row_count()) - before

    async def _row_count(self) -> int:
        assert self._db is not None
        async with self._db.execute(
            "SELECT COUNT(*) FROM malware_hashes"
        ) as cur:
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
        async with self._db.execute(
            "SELECT COUNT(*) FROM malware_hashes"
        ) as cur:
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
