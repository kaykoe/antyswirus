"""``Quarantine`` that logs calls and returns a fake id."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from antyswirus_lib.protocols import QuarantinedFile
from antyswirus_lib.types import ScanResult

log = logging.getLogger(__name__)


class StubQuarantine:
    async def quarantine(self, path: Path, result: ScanResult) -> str:
        qid = uuid.uuid4().hex
        log.warning("STUB quarantine %s as %s", path, qid)
        return qid

    async def restore(self, quarantine_id: str, dest: Path) -> None:
        log.debug("STUB restore %s -> %s", quarantine_id, dest)

    async def list(self) -> list[QuarantinedFile]:
        log.debug("STUB list quarantine")
        return []

    async def delete(self, quarantine_id: str) -> None:
        log.debug("STUB delete %s", quarantine_id)

    async def close(self) -> None:
        log.debug("stub quarantine closed")
