"""Bridge between sync producers and the async worker pool.

Producers (the in-thread ``os.walk`` in the scanner, and in the
future the in-thread fanotify loop) push ``ScanRequest`` objects via
``put_threadsafe``, which is safe to call from any thread.

Consumers (``LookupWorker``) pop requests via ``await get()``. The
queue is closed with ``close()``; once closed, all pending and
future ``get`` calls return ``None`` and the workers can exit.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path

from antyswirus_lib.protocols import HashRepository, Quarantine
from antyswirus_lib.types import FileFingerprint, Verdict

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ScanRequest:
    """A single file that needs to be looked up by the hash repository."""

    path: Path
    fingerprint: FileFingerprint


class LookupQueue:
    """A queue that accepts ``put`` from any thread and ``get`` from asyncio."""

    def __init__(self, *, maxsize: int = 4096) -> None:
        self._queue: asyncio.Queue[ScanRequest | None] = asyncio.Queue(maxsize=maxsize)
        self._closed = False

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
        cache,  # ScanCache; imported lazily to avoid cycles in tests
        hash_repo: HashRepository,
        quarantine: Quarantine,
    ) -> None:
        self._queue = queue
        self._cache = cache
        self._hash_repo = hash_repo
        self._quarantine = quarantine

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
        result = await self._hash_repo.lookup(req.path)
        await self._cache.record(req.path, req.fingerprint, result.verdict)
        if result.verdict is Verdict.MALICIOUS:
            qid = await self._quarantine.quarantine(req.path, result)
            log.warning(
                "quarantined %s as %s (%s)",
                req.path,
                qid,
                result.detail or "",
            )
