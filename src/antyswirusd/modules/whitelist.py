"""Whitelist implementation for marking files as known-safe.

Maintains a SQLite database of path/hash pairs. When a file is whitelisted,
it is marked as safe and won't be flagged as malicious during scans.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import sqlite3
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS whitelist (
    path        TEXT PRIMARY KEY,
    hash        TEXT NOT NULL,
    added_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_whitelist_hash
    ON whitelist(hash);
"""


class Whitelist:
    """Maintains a whitelist of safe files indexed by path and hash.
    
    Files can be whitelisted by their path and file hash. The whitelist
    supports queries by both path and hash to enable efficient scanning.
    Removing a file from the whitelist removes all identical hashes.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    async def open(self) -> None:
        """Initialize the whitelist database."""
        await asyncio.to_thread(self._open_sync)

    def _open_sync(self) -> None:
        """Create database and open connection."""
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
        log.debug("Whitelist database opened at %s", self._db_path)

    async def contains(self, path: Path) -> bool:
        """Check if a path is whitelisted."""
        return await asyncio.to_thread(self._contains_sync, path)

    def _contains_sync(self, path: Path) -> bool:
        """Check if path exists in whitelist."""
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT 1 FROM whitelist WHERE path = ?", (str(path),)
        )
        return cur.fetchone() is not None

    async def contains_path(self, path: Path) -> bool:
        """Check if a path is whitelisted (alias for contains)."""
        return await self.contains(path)

    async def contains_hash(self, file_hash: str) -> bool:
        """Check if a hash exists in the whitelist."""
        return await asyncio.to_thread(self._contains_hash_sync, file_hash)

    def _contains_hash_sync(self, file_hash: str) -> bool:
        """Check if hash exists in whitelist."""
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT 1 FROM whitelist WHERE hash = ?", (file_hash,)
        )
        return cur.fetchone() is not None

    async def add(self, pattern: str, file_hash: str | None = None) -> None:
        """Add a file to the whitelist.
        
        Args:
            pattern: Path to the file as a string
            file_hash: The hash of the file (optional for compatibility)
        """
        path = Path(pattern)
        
        if file_hash is None:
            file_hash = await self._compute_file_hash(path)
        
        await asyncio.to_thread(self._add_sync, path, file_hash)

    def _add_sync(self, path: Path, file_hash: str) -> None:
        """Add path/hash to whitelist."""
        with self._lock:
            assert self._conn is not None
            self._conn.execute(
                """
                INSERT INTO whitelist(path, hash, added_at)
                VALUES (?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    hash = excluded.hash,
                    added_at = excluded.added_at
                """,
                (str(path), file_hash, time.time()),
            )
        log.info("Added to whitelist: %s (hash: %s)", path, file_hash[:16])

    async def remove(self, pattern: str) -> None:
        """Remove a file from the whitelist.
        
        Args:
            pattern: Path to the file as a string
        
        After removal, all identical hashes are also removed, and a scan
        is triggered for the path.
        """
        path = Path(pattern)
        await asyncio.to_thread(self._remove_sync, path)

    def _remove_sync(self, path: Path) -> None:
        """Remove path and all matching hashes from whitelist."""
        with self._lock:
            assert self._conn is not None
            
            cur = self._conn.execute(
                "SELECT hash FROM whitelist WHERE path = ?", (str(path),)
            )
            row = cur.fetchone()
            if not row:
                log.warning("Path not in whitelist: %s", path)
                return
            
            file_hash = row[0]
            
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM whitelist WHERE hash = ?", (file_hash,)
            )
            count = cur.fetchone()[0]
            
            self._conn.execute(
                "DELETE FROM whitelist WHERE hash = ?", (file_hash,)
            )
            
            log.info(
                "Removed %d entries with hash %s from whitelist (path: %s)",
                count,
                file_hash[:16],
                path,
            )

    async def list(self) -> list[str]:
        """Return all whitelisted paths as a list of strings."""
        return await asyncio.to_thread(self._list_sync)

    def _list_sync(self) -> list[str]:
        """Retrieve all whitelisted paths from database."""
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT path FROM whitelist ORDER BY added_at DESC"
        )
        return [row[0] for row in cur]

    async def list_with_hashes(self) -> dict[str, str]:
        """Return all whitelisted files as a dict of path -> hash."""
        return await asyncio.to_thread(self._list_with_hashes_sync)

    def _list_with_hashes_sync(self) -> dict[str, str]:
        """Retrieve all whitelisted path/hash pairs from database."""
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT path, hash FROM whitelist ORDER BY added_at DESC"
        )
        return {row[0]: row[1] for row in cur}

    async def _compute_file_hash(self, path: Path) -> str:
        """Compute SHA256 hash of a file."""
        return await asyncio.to_thread(self._compute_file_hash_sync, path)

    @staticmethod
    def _compute_file_hash_sync(path: Path) -> str:
        """Compute SHA256 hash of a file synchronously."""
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            log.error("Failed to compute hash for %s: %s", path, e)
            raise

    async def close(self) -> None:
        """Release any resources held by the whitelist."""
        if self._conn is not None:
            conn, self._conn = self._conn, None
            await asyncio.to_thread(conn.close)
        log.debug("Whitelist closed")

