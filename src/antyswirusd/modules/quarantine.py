"""SQLite-backed :class:`Quarantine` that stores quarantined file bytes on disk.

The on-disk layout is a single SQLite database for metadata and a
flat directory of payload files. The metadata schema::

    CREATE TABLE items (
        id              TEXT PRIMARY KEY,
        original_path   TEXT NOT NULL,
        quarantined_at  REAL NOT NULL,
        verdict         TEXT NOT NULL,
        detail          TEXT
    );

Each row corresponds to one payload stored at
``quarantine_dir/<id>``. The id is a UUID4 hex string generated on
ingest. ``quarantine`` copies the source bytes into the payload
directory; ``restore`` copies them back to ``dest`` and removes the
row; ``delete`` removes both the row and the payload file. ``list``
returns the current rows as :class:`QuarantinedFile` objects, sorted
by ``quarantined_at`` so the most recent appears last.

This implementation satisfies the :class:`Quarantine` Protocol from
``antyswirus_lib`` and is the default engine module wired up in
``antyswirusd.engine.Engine``. It is intentionally simple: the
malware-DB sync, real on-access integration, and so on will replace
it later, but the IPC contract works end-to-end today.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
import uuid
from pathlib import Path

import aiosqlite

from antyswirus_lib.protocols import QuarantinedFile
from antyswirus_lib.types import ScanResult, Verdict

log = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id             TEXT PRIMARY KEY,
    original_path  TEXT NOT NULL,
    quarantined_at REAL NOT NULL,
    verdict        TEXT NOT NULL,
    detail         TEXT
);
"""


class PersistentQuarantine:
    """A :class:`Quarantine` that persists to a SQLite DB and a payload directory."""

    def __init__(self, db_path: Path, payload_dir: Path) -> None:
        self._db_path = db_path
        self._payload_dir = payload_dir
        self._db: aiosqlite.Connection | None = None
        self._closed = False

    async def open(self) -> None:
        if self._db is not None:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._payload_dir.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(str(self._db_path))
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.executescript(_SCHEMA)
        await db.commit()
        self._db = db

    async def close(self) -> None:
        if self._db is None:
            self._closed = True
            return
        db, self._db = self._db, None
        await db.close()
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def _payload_path(self, qid: str) -> Path:
        return self._payload_dir / qid

    async def quarantine(self, path: Path, result: ScanResult) -> str:
        qid = uuid.uuid4().hex
        # Copy the file off the original path so a subsequent move /
        # delete of the source by the caller (or by a remount) cannot
        # truncate the bytes we hold for the user. ``copy2`` keeps the
        # original mtime / mode in case the user wants to inspect them.
        dest = self._payload_path(qid)
        try:
            await asyncio.to_thread(shutil.copy2, path, dest)
        except FileNotFoundError:
            raise
        except OSError as exc:
            log.error("quarantine: copy %s -> %s failed: %s", path, dest, exc)
            raise
        assert self._db is not None
        await self._db.execute(
            "INSERT INTO items(id, original_path, quarantined_at, verdict, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                qid,
                str(path),
                time.time(),
                result.verdict.value,
                result.detail,
            ),
        )
        await self._db.commit()
        log.warning("quarantined %s as %s", path, qid)
        return qid

    async def restore(self, quarantine_id: str, dest: Path) -> None:
        payload = self._payload_path(quarantine_id)
        if not payload.exists():
            raise KeyError(quarantine_id)
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            await asyncio.to_thread(shutil.copy2, payload, dest)
        except OSError as exc:
            log.error("restore: copy %s -> %s failed: %s", payload, dest, exc)
            raise
        assert self._db is not None
        await self._db.execute("DELETE FROM items WHERE id = ?", (quarantine_id,))
        await self._db.commit()
        try:
            payload.unlink()
        except OSError:
            pass
        log.info("restored %s -> %s", quarantine_id, dest)

    async def list(self) -> list[QuarantinedFile]:
        assert self._db is not None
        async with self._db.execute(
            "SELECT id, original_path, quarantined_at, verdict, detail "
            "FROM items ORDER BY quarantined_at, id"
        ) as cur:
            rows = await cur.fetchall()
        result: list[QuarantinedFile] = []
        for qid, original_path, quarantined_at, verdict_raw, detail in rows:
            try:
                verdict = Verdict(verdict_raw)
            except ValueError:
                log.warning(
                    "quarantine row %s has unknown verdict %r", qid, verdict_raw
                )
                continue
            result.append(
                QuarantinedFile(
                    id=qid,
                    original_path=Path(original_path),
                    quarantined_at=quarantined_at,
                    verdict=verdict,
                    detail=detail,
                )
            )
        return result

    async def delete(self, quarantine_id: str) -> None:
        assert self._db is not None
        cur = await self._db.execute("DELETE FROM items WHERE id = ?", (quarantine_id,))
        await self._db.commit()
        if cur.rowcount == 0:
            raise KeyError(quarantine_id)
        payload = self._payload_path(quarantine_id)
        try:
            payload.unlink(missing_ok=True)
        except OSError as exc:
            log.warning(
                "quarantine delete: could not remove payload %s: %s", payload, exc
            )
        log.info("deleted quarantine %s", quarantine_id)


# Backwards-compatible alias for code that imported the stub.
StubQuarantine = PersistentQuarantine
__all__ = ["PersistentQuarantine", "StubQuarantine"]
