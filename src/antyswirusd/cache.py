"""SQLite-backed cache of previously-scanned files.

A file is considered "known" iff a row exists with matching
``(dev, inode, mtime_ns, size, generation)``. ``dev + inode`` together
identify a file on the filesystem, ``mtime_ns + size`` together
discriminate against inode reuse, and ``generation`` invalidates the
entire cache when the malware hash database is updated.

Writes go through ``INSERT … ON CONFLICT(path) DO UPDATE`` so a path
can be re-scanned with a fresh fingerprint without needing to
``DELETE`` first.

Threading model: the underlying ``sqlite3`` connection is opened with
``check_same_thread=False`` and used in autocommit mode. Each
public method runs a single statement, which is atomic from SQLite's
point of view, so the connection is safe to share between the
asyncio loop and the scanner's worker thread. ``prune_missing`` and
``set_generation`` hold a ``threading.Lock`` because they perform
multiple statements.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
import time
from pathlib import Path

from antyswirus_lib.types import FileFingerprint, Verdict

log = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_cache (
    path        TEXT PRIMARY KEY,
    dev         INTEGER NOT NULL,
    inode       INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    mtime_ns    INTEGER NOT NULL,
    generation  INTEGER NOT NULL,
    verdict     TEXT    NOT NULL,
    scanned_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_fp
    ON scan_cache(dev, inode, mtime_ns, size, generation);
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
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._generation: int = _DEFAULT_GENERATION
        self._version: str = ""

    async def open(self) -> None:
        await asyncio.to_thread(self._open_sync)

    def _open_sync(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(self._db_path),
            isolation_level=None,
            check_same_thread=False,
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(_SCHEMA)
        self._conn = conn
        self._generation = self._read_meta_int(_META_GENERATION, _DEFAULT_GENERATION)
        self._version = self._read_meta_str(_META_VERSION, "")

    def _read_meta_int(self, key: str, default: int) -> int:
        assert self._conn is not None
        cur = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cur.fetchone()
        if row is None:
            return default
        try:
            return int(row[0])
        except (TypeError, ValueError):
            return default

    def _read_meta_str(self, key: str, default: str) -> str:
        assert self._conn is not None
        cur = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cur.fetchone()
        return default if row is None else str(row[0])

    async def close(self) -> None:
        if self._conn is not None:
            conn, self._conn = self._conn, None
            await asyncio.to_thread(conn.close)

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def version(self) -> str:
        return self._version

    async def is_known(self, path: Path, fp: FileFingerprint) -> Verdict | None:
        """Return the cached verdict for ``path`` if it is still valid, else None."""
        return await asyncio.to_thread(self._is_known_sync, path, fp)

    def _is_known_sync(self, path: Path, fp: FileFingerprint) -> Verdict | None:
        assert self._conn is not None
        cur = self._conn.execute(
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
        )
        row = cur.fetchone()
        if row is None:
            return None
        try:
            return Verdict(row[0])
        except ValueError:
            log.warning("cache row for %s has unknown verdict %r", path, row[0])
            return None

    async def record(self, path: Path, fp: FileFingerprint, verdict: Verdict) -> None:
        await asyncio.to_thread(self._record_sync, path, fp, verdict)

    def _record_sync(self, path: Path, fp: FileFingerprint, verdict: Verdict) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            INSERT INTO scan_cache(
                path, dev, inode, size, mtime_ns, generation, verdict, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                dev        = excluded.dev,
                inode      = excluded.inode,
                size       = excluded.size,
                mtime_ns   = excluded.mtime_ns,
                generation = excluded.generation,
                verdict    = excluded.verdict,
                scanned_at = excluded.scanned_at
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
            ),
        )

    async def set_generation(self, generation: int, version: str | None = None) -> None:
        """Bump the cache generation (and optionally the version string).

        Existing rows with a different generation naturally stop
        matching the WHERE clause on the next ``is_known`` call and
        are re-scanned. Old rows are not deleted; ``prune_missing`` and
        a future size-based GC can clean them up.
        """
        await asyncio.to_thread(self._set_generation_sync, generation, version)

    def _set_generation_sync(self, generation: int, version: str | None) -> None:
        with self._lock:
            assert self._conn is not None
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_META_GENERATION, str(generation)),
            )
            if version is not None:
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (_META_VERSION, version),
                )
                self._version = version
            self._generation = generation

    async def prune_missing(self) -> int:
        """Delete cache rows whose path no longer exists. Returns count removed."""
        return await asyncio.to_thread(self._prune_missing_sync)

    def _prune_missing_sync(self) -> int:
        assert self._conn is not None
        with self._lock:
            cur = self._conn.execute("SELECT path FROM scan_cache")
            removed = 0
            for (p,) in cur:
                if not Path(p).exists():
                    self._conn.execute("DELETE FROM scan_cache WHERE path = ?", (p,))
                    removed += 1
            return removed
