"""aiosqlite-backed :class:`Quarantine` implementation.

Layout on disk
--------------

The on-disk store has two pieces:

- A SQLite database (``quarantine.db``) keyed on a per-file
  ``qid`` (uuid4 hex), holding the original path, the verdict that
  sent the file here, the timestamp, and the human-readable
  ``detail`` string.
- A directory (``quarantine/``) holding the moved files. The
  directory is mode ``0o700`` owned by the daemon, which is the
  isolation: non-root users cannot reach anything inside, so the
  files themselves keep their original mode / owner / group and no
  chmod bookkeeping is required.

Schema
------

::

    CREATE TABLE entries (
        qid            TEXT PRIMARY KEY,
        original_path  TEXT    NOT NULL,
        quarantined_at REAL    NOT NULL,
        verdict        TEXT    NOT NULL,
        detail         TEXT
    );
    CREATE INDEX idx_entries_quarantined_at ON entries(quarantined_at);

Semantics
---------

- ``quarantine(result)`` generates a fresh ``qid``, moves the
  file into the quarantine dir as ``<qid>__<basename>`` (the
  basename suffix is purely for human inspection; the ``qid`` is the
  unique handle), inserts the row, and returns the ``qid``.
- ``restore(qid)`` moves the file back to its original path. The
  original mode/owner/group come along on the rename unchanged.
  ``FileExistsError`` is raised if the destination is now occupied.
- ``delete(qid)`` unlinks the file and drops the row; it is
  idempotent for the file side (a vanished file is fine, the row
  still gets dropped).
- ``list(offset, limit)`` paginates the rows ordered by
  ``quarantined_at``; ``limit`` is clamped to :data:`MAX_LIST_LIMIT`.
- ``prune()`` removes rows whose quarantined file has vanished
  from disk, plus rows older than ``max_age_days`` (passed to the
  constructor). It returns the total count.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import uuid
from pathlib import Path

import aiosqlite

from antyswirus_lib.types import QuarantinedFile, ScanResult, Verdict

log = logging.getLogger(__name__)


MAX_LIST_LIMIT = 1000

_DIR_MODE = 0o700


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    qid            TEXT PRIMARY KEY,
    original_path  TEXT    NOT NULL,
    quarantined_at REAL    NOT NULL,
    verdict        TEXT    NOT NULL,
    detail         TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_quarantined_at
    ON entries(quarantined_at);
"""


def _safe_basename(path: Path) -> str:
    """Return a filesystem-safe basename for ``path``.

    Strips directory components and any NUL bytes, falling back to
    ``"file"`` if nothing usable remains. The ``qid`` prefix on the
    on-disk name guarantees uniqueness, so this is purely cosmetic.
    """
    name = path.name
    cleaned = name.replace("\x00", "").strip()
    return cleaned or "file"


class Quarantine:
    """aiosqlite-backed :class:`Quarantine` implementation."""

    def __init__(
        self,
        quarantine_dir: Path,
        db_path: Path,
        *,
        max_age_days: int = 14,
    ) -> None:
        self._dir = quarantine_dir
        self._db_path = db_path
        self._max_age_days = max_age_days
        self._db: aiosqlite.Connection | None = None
        self._closed = False

    @property
    def quarantine_dir(self) -> Path:
        return self._dir

    @property
    def max_age_days(self) -> int:
        return self._max_age_days

    async def open(self) -> None:
        if self._db is not None:
            return
        # The dir must exist with restrictive perms before any file
        # moves in. ``mkdir(..., exist_ok=True)`` honours the mode
        # only on first creation; if the dir already exists with
        # looser perms (e.g. from a manual pre-create) we re-apply
        # the mode explicitly.
        self._dir.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(self._chmod_dir, self._dir, _DIR_MODE)

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

    @staticmethod
    def _chmod_dir(path: Path, mode: int) -> None:
        os.chmod(path, mode)

    def _stored_path(self, qid: str, basename: str) -> Path:
        return self._dir / f"{qid}__{basename}"

    async def quarantine(self, result: ScanResult) -> str:
        assert self._db is not None
        qid = uuid.uuid4().hex
        stored = self._stored_path(qid, _safe_basename(result.path))
        self._dir.mkdir(parents=True, exist_ok=True)

        try:
            await asyncio.to_thread(shutil.move, str(result.path), str(stored))
        except FileNotFoundError:
            raise FileNotFoundError(result.path) from None
        except OSError as exc:
            raise OSError(
                f"Failed to quarantine {result.path} -> {stored}: {exc}"
            ) from exc

        await self._db.execute(
            """
            INSERT INTO entries(
                qid, original_path, quarantined_at, verdict, detail
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                qid,
                str(result.path),
                time.time(),
                result.verdict.value,
                result.detail,
            ),
        )
        await self._db.commit()
        log.warning("quarantined %s as %s (%s)", result.path, qid, result.detail or "")
        return qid

    async def restore(self, qid: str) -> None:
        assert self._db is not None
        async with self._db.execute(
            "SELECT original_path FROM entries WHERE qid = ?", (qid,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            raise KeyError(qid)
        original = Path(row[0])
        # Find the on-disk file by qid. We don't store the filename
        # in the db (only the qid), so we look up by listing the
        # dir for ``<qid>__*``. The qid prefix is unique.
        stored = await asyncio.to_thread(self._find_stored, qid)
        if stored is None:
            # DB row says we have it but the file is gone; prune
            # the row and surface the inconsistency.
            await self._db.execute("DELETE FROM entries WHERE qid = ?", (qid,))
            await self._db.commit()
            raise FileNotFoundError(f"quarantined file for {qid} is missing on disk")
        original.parent.mkdir(parents=True, exist_ok=True)
        if await asyncio.to_thread(original.exists):
            raise FileExistsError(original)

        try:
            await asyncio.to_thread(shutil.move, str(stored), str(original))
        except OSError as exc:
            raise OSError(
                f"Failed to restore {stored} -> {original}: {exc}"
            ) from exc

        await self._db.execute("DELETE FROM entries WHERE qid = ?", (qid,))
        await self._db.commit()
        log.info("restored %s from quarantine %s", original, qid)

    def _find_stored(self, qid: str) -> Path | None:
        prefix = f"{qid}__"
        try:
            for entry in os.listdir(self._dir):
                if entry.startswith(prefix):
                    return self._dir / entry
        except FileNotFoundError:
            return None

    async def stored_path(self, qid: str) -> Path | None:
        """Return the on-disk path of a quarantined file, or None if missing."""
        return await asyncio.to_thread(self._find_stored, qid)
        return None

    async def delete(self, qid: str) -> None:
        assert self._db is not None
        async with self._db.execute(
            "SELECT 1 FROM entries WHERE qid = ?", (qid,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            raise KeyError(qid)
        stored = await asyncio.to_thread(self._find_stored, qid)
        if stored is not None:
            try:
                await asyncio.to_thread(os.unlink, stored)
            except (FileNotFoundError, OSError):
                pass
        await self._db.execute("DELETE FROM entries WHERE qid = ?", (qid,))
        await self._db.commit()
        log.info("deleted quarantine entry %s", qid)

    async def list(self, *, offset: int = 0, limit: int = 100) -> list[QuarantinedFile]:
        assert self._db is not None
        if offset < 0:
            offset = 0
        limit = max(1, min(limit, MAX_LIST_LIMIT))
        async with self._db.execute(
            """
            SELECT qid, original_path, quarantined_at, verdict, detail
            FROM entries
            ORDER BY quarantined_at, qid
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
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

    async def count(self) -> int:
        """Return the total number of quarantine rows.

        Not on the Protocol — used by the IPC layer to populate the
        ``total`` field in the ``quarantine_list`` response.
        """
        assert self._db is not None
        async with self._db.execute("SELECT COUNT(*) FROM entries") as cur:
            (n,) = await cur.fetchone()
        return int(n)

    async def prune(self) -> int:
        """Drop rows whose file is gone, then age out old rows."""
        assert self._db is not None
        async with self._db.execute("SELECT qid, original_path FROM entries") as cur:
            rows = await cur.fetchall()
        removed = 0
        for qid, _ in rows:
            stored = await asyncio.to_thread(self._find_stored, qid)
            if stored is None:
                await self._db.execute("DELETE FROM entries WHERE qid = ?", (qid,))
                removed += 1
        if removed:
            await self._db.commit()
        # Age-based prune.
        cutoff = time.time() - self._max_age_days * 86400

        # Collect qids before deleting so we can clean up the on-disk files.
        async with self._db.execute(
            "SELECT qid FROM entries WHERE quarantined_at < ?", (cutoff,)
        ) as cur:
            aged_qids = [row[0] for row in await cur.fetchall()]

        aged = 0
        if aged_qids:
            cur = await self._db.execute(
                "DELETE FROM entries WHERE quarantined_at < ?", (cutoff,)
            )
            aged = cur.rowcount
            await self._db.commit()
            for qid in aged_qids:
                stored = await asyncio.to_thread(self._find_stored, qid)
                if stored is not None:
                    try:
                        await asyncio.to_thread(os.unlink, stored)
                    except OSError:
                        pass
        total = removed + aged
        if total:
            log.info(
                "prune: removed %d row(s) (missing=%d, aged=%d)",
                total,
                removed,
                aged,
            )
        return total
