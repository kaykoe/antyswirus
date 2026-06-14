"""In-memory stub for the :class:`Quarantine` protocol.

Logs every call at DEBUG and returns a fake quarantine id so the
engine pipeline can run end-to-end without a real quarantine.
"""

from __future__ import annotations

import logging
from pathlib import Path

from antyswirus_lib.protocols import QuarantinedFile
from antyswirus_lib.types import ScanResult, Verdict

log = logging.getLogger(__name__)


class StubQuarantine:
    async def open(self) -> None:
        log.debug("stub quarantine opened")

    async def close(self) -> None:
        log.debug("stub quarantine closed")

    async def quarantine(self, path: Path, result: ScanResult) -> str:
        log.debug("stub quarantine: %s (verdict=%s)", path, result.verdict.value)
        return "stub-qid"

    async def restore(self, quarantine_id: str) -> None:
        log.debug("stub restore: %s", quarantine_id)
        raise FileNotFoundError(f"stub quarantine: {quarantine_id} not found")

    async def list(
        self, *, offset: int = 0, limit: int = 100
    ) -> list[QuarantinedFile]:
        log.debug("stub quarantine list")
        return []

    async def delete(self, quarantine_id: str) -> None:
        log.debug("stub delete: %s", quarantine_id)

    async def prune(self) -> int:
        log.debug("stub prune")
        return 0
