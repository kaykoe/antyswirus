"""Bridge between sync producers and the async worker pool, plus the worker itself.

Producers (the in-thread filesystem walker in the scanner) push
``ScanRequest`` objects via :meth:`put_threadsafe`, which is safe to
call from any thread.

Consumers (``LookupWorker``) pop requests via ``await get()``. The
queue is closed with ``close()``; once closed, all pending and
future ``get`` calls return ``None`` and the workers can exit.

Worker flow per request:

    1. Hash the file (off the event loop via ``asyncio.to_thread``).
    2. Ask the whitelist whether this content hash is trusted.
       If yes, record ``WHITELISTED`` and skip the malware-DB call.
    3. Otherwise, ask the ``HashRepository`` for a verdict by hash.
    4. Record the verdict in the cache; quarantine on ``MALICIOUS``.
    5. Send a desktop notification when a file is quarantined.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from antyswirus_lib.hashing import compute_sha256
from antyswirusd.quarantine import Quarantine
from antyswirusd.whitelist import Whitelist
from antyswirus_lib.types import HashRepository
from antyswirus_lib.types import FileFingerprint, ScanResult, Verdict

if TYPE_CHECKING:
    from antyswirusd.cache import ScanCache

log = logging.getLogger(__name__)


def _notify_quarantined(file_path: str) -> None:
    try:
        subprocess.run(
            [
                "notify-send",
                "--urgency=critical",
                "File Quarantined",
                f"A file has been quarantined:\n{file_path}",
            ],
            timeout=5,
            capture_output=True,
        )
    except FileNotFoundError:
        log.warning("notify-send not found, skipping notification")
    except OSError as exc:
        log.warning("notification failed for %s: %s", file_path, exc)
    except subprocess.TimeoutExpired:
        log.warning("notify-send timed out for %s", file_path)


@dataclass(slots=True)
class ScanRequest:
    """A single file that needs to be hashed and looked up."""

    path: Path
    fingerprint: FileFingerprint


class LookupQueue:
    """A queue that accepts ``put`` from any thread and ``get`` from asyncio."""

    def __init__(self, *, maxsize: int = 4096) -> None:
        self._queue: asyncio.Queue[ScanRequest | None] = asyncio.Queue(maxsize=maxsize)
        self._closed = False
        self._dropped: int = 0

    @property
    def dropped(self) -> int:
        """Number of items dropped because the queue was full."""
        return self._dropped

    async def put(self, req: ScanRequest) -> None:
        if self._closed:
            return
        await self._queue.put(req)

    def put_threadsafe(self, req: ScanRequest) -> None:
        """Non-blocking put, safe to call from a worker thread."""
        if self._closed:
            return
        try:
            self._queue.put_nowait(req)
        except asyncio.QueueFull:
            self._dropped += 1
            log.warning("lookup queue full, dropping %s", req.path)

    def task_done(self) -> None:
        self._queue.task_done()

    async def join(self) -> None:
        await self._queue.join()

    def qsize(self) -> int:
        return self._queue.qsize()

    async def get(self) -> ScanRequest | None:
        item = await self._queue.get()
        if item is None:
            self._queue.task_done()
            return None
        return item

    def close(self) -> None:
        """Close the queue. Pending and future ``get`` calls return None."""
        if self._closed:
            return
        self._closed = True
        self._queue.put_nowait(None)


class LookupWorker:
    """Consumes ``ScanRequest``s and routes them through the engine modules."""

    def __init__(
        self,
        queue: LookupQueue,
        cache: "ScanCache",
        hash_repo: HashRepository,
        quarantine: Quarantine,
        whitelist: Whitelist,
    ) -> None:
        self._queue = queue
        self._cache = cache
        self._hash_repo = hash_repo
        self._quarantine = quarantine
        self._whitelist = whitelist

    async def run(self) -> None:
        log.debug("worker started")
        try:
            while True:
                req = await self._queue.get()
                if req is None:
                    break
                try:
                    await self._process(req)
                except Exception:
                    log.exception("worker failed processing %s", req.path)
                finally:
                    self._queue.task_done()
        finally:
            log.debug("worker stopped")

    async def _process(self, req: ScanRequest) -> None:
        try:
            content_hash = await asyncio.to_thread(compute_sha256, req.path)
        except FileNotFoundError:
            log.debug("file vanished before hash: %s", req.path)
            return
        except OSError as exc:
            log.warning("hash failed for %s: %s", req.path, exc)
            return

        if await self._whitelist.is_hash_whitelisted(content_hash):
            result = ScanResult(
                path=req.path,
                verdict=Verdict.WHITELISTED,
                detail="hash whitelisted",
            )
        else:
            hit = await self._hash_repo.lookup_by_hash(content_hash)
            result = ScanResult(path=req.path, verdict=hit.verdict, detail=hit.detail)

        if result.verdict is Verdict.MALICIOUS:
            qid = await self._quarantine.quarantine(result)
            await asyncio.to_thread(_notify_quarantined, str(req.path))
            log.warning(
                "quarantined %s as %s (%s)",
                req.path,
                qid,
                result.detail or "",
            )

        await self._cache.record(
            req.path, req.fingerprint, result.verdict, content_hash
        )
