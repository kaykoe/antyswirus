"""SQLite-backed cache of scan results.

A file is considered "known" iff a row exists with matching
``(dev, inode, mtime_ns, size, generation)``. ``dev + inode`` together
identify a file on the filesystem, ``mtime_ns + size`` together
discriminate against inode reuse, and ``generation`` invalidates the
entire cache when the malware hash database is updated.

Writes go through ``INSERT … ON CONFLICT(path) DO UPDATE`` so a path
can be re-scanned with a fresh fingerprint without needing to
``DELETE`` first.

The cache also records the file's content hash when known, so the
whitelist-removal path can quickly find every file ever scanned that
had a particular hash.

The cache is backed by ``aiosqlite``. A single ``Connection`` is held
open for the lifetime of the cache; ``aiosqlite`` serialises
concurrent use from multiple coroutines, so the scanner and worker
coroutines can share the cache without explicit locking. The
connection is bound to the event loop that called :meth:`open`;
``close`` releases it cleanly.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import aiosqlite

from antyswirus_lib.types import FileFingerprint, Verdict

log = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_cache (
    path         TEXT PRIMARY KEY,
    dev          INTEGER NOT NULL,
    inode        INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    mtime_ns     INTEGER NOT NULL,
    generation   INTEGER NOT NULL,
    verdict      TEXT    NOT NULL,
    scanned_at   REAL    NOT NULL,
    content_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_cache_fp
    ON scan_cache(dev, inode, mtime_ns, size, generation);
CREATE INDEX IF NOT EXISTS idx_cache_hash
    ON scan_cache(content_hash);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_META_GENERATION = "hash_db_generation"
_META_VERSION = "hash_db_version"

_DEFAULT_GENERATION = 0


class ScanCache:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None
        self._generation: int = _DEFAULT_GENERATION
        self._version: str = ""

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
        self._generation = await self._read_meta_int(
            _META_GENERATION, _DEFAULT_GENERATION
        )
        self._version = await self._read_meta_str(_META_VERSION, "")

    async def _read_meta_int(self, key: str, default: int) -> int:
        assert self._db is not None
        async with self._db.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return default
        try:
            return int(row[0])
        except (TypeError, ValueError):
            return default

    async def _read_meta_str(self, key: str, default: str) -> str:
        assert self._db is not None
        async with self._db.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ) as cur:
            row = await cur.fetchone()
        return default if row is None else str(row[0])

    async def close(self) -> None:
        if self._db is not None:
            db, self._db = self._db, None
            await db.close()

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def version(self) -> str:
        return self._version

    async def last_scan_at(self) -> float | None:
        """Return the largest ``scanned_at`` across all cached rows, or None.

        Used by the IPC ``status`` response to populate the
        ``last_scan_at`` field for the TUI. A single ``MAX`` query
        against the (tiny) ``scan_cache`` table is cheap enough to
        run on every status call.
        """
        assert self._db is not None
        async with self._db.execute("SELECT MAX(scanned_at) FROM scan_cache") as cur:
            row = await cur.fetchone()
        if row is None or row[0] is None:
            return None
        try:
            return float(row[0])
        except (TypeError, ValueError):
            return None

    async def is_known(self, path: Path, fp: FileFingerprint) -> Verdict | None:
        """Return the cached verdict for ``path`` if it is still valid, else None."""
        assert self._db is not None
        async with self._db.execute(
            """
            SELECT verdict FROM scan_cache
            WHERE path = ? AND dev = ? AND inode = ?
              AND mtime_ns = ? AND size = ? AND generation = ?
            """,
            (
                str(path),
                fp.dev,
                fp.inode,
                fp.mtime_ns,
                fp.size,
                self._generation,
            ),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        try:
            return Verdict(row[0])
        except ValueError:
            log.warning("cache row for %s has unknown verdict %r", path, row[0])
            return None

    async def record(
        self,
        path: Path,
        fp: FileFingerprint,
        verdict: Verdict,
        content_hash: str | None = None,
    ) -> None:
        """Record (or update) the verdict for ``path``.

        ``content_hash`` is stored alongside the verdict so that a
        later ``whitelist_remove`` for a SHA-256 entry can locate
        every file that was ever scanned with that hash.
        """
        assert self._db is not None
        await self._db.execute(
            """
            INSERT INTO scan_cache(
                path, dev, inode, size, mtime_ns, generation,
                verdict, scanned_at, content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                dev          = excluded.dev,
                inode        = excluded.inode,
                size         = excluded.size,
                mtime_ns     = excluded.mtime_ns,
                generation   = excluded.generation,
                verdict      = excluded.verdict,
                scanned_at   = excluded.scanned_at,
                content_hash = excluded.content_hash
            """,
            (
                str(path),
                fp.dev,
                fp.inode,
                fp.size,
                fp.mtime_ns,
                self._generation,
                verdict.value,
                time.time(),
                content_hash,
            ),
        )
        await self._db.commit()

    async def paths_with_hash(
        self, content_hash: str
    ) -> list[tuple[Path, FileFingerprint]]:
        """Return every (path, fingerprint) pair that was scanned with ``content_hash``.

        Used by the engine's hash-rescan path: removing a SHA-256
        entry from the whitelist must trigger a re-scan of every
        file that was previously recorded as ``WHITELISTED`` for
        that hash, and the cache is the only place that records
        which file matched which hash.
        """
        assert self._db is not None
        async with self._db.execute(
            "SELECT path, dev, inode, size, mtime_ns FROM scan_cache "
            "WHERE content_hash = ?",
            (content_hash,),
        ) as cur:
            rows = await cur.fetchall()
        return [
            (
                Path(p),
                FileFingerprint(dev=dev, inode=inode, size=size, mtime_ns=mtime_ns),
            )
            for p, dev, inode, size, mtime_ns in rows
        ]

    async def set_generation(self, generation: int, version: str | None = None) -> None:
        """Bump the cache generation (and optionally the version string).

        Existing rows with a different generation naturally stop
        matching the WHERE clause on the next ``is_known`` call and
        are re-scanned. Old rows are not deleted; ``prune_missing``
        can clean them up.
        """
        assert self._db is not None
        await self._db.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (_META_GENERATION, str(generation)),
        )
        if version is not None:
            await self._db.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_META_VERSION, version),
            )
            self._version = version
        await self._db.commit()
        self._generation = generation

    async def prune_missing(self) -> int:
        """Delete cache rows whose path no longer exists. Returns count removed."""
        assert self._db is not None
        async with self._db.execute("SELECT path FROM scan_cache") as cur:
            rows = await cur.fetchall()
        removed = 0
        for (p,) in rows:
            if not Path(p).exists():
                await self._db.execute("DELETE FROM scan_cache WHERE path = ?", (p,))
                removed += 1
        if removed:
            await self._db.commit()
        return removed
