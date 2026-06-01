"""Stub ``HashRepository`` that always returns ``Verdict.UNKNOWN``.

Lets the engine run end-to-end without a malware database. Drop in
a real implementation by importing it in ``antyswirusd.engine``
instead of this stub.
"""

from __future__ import annotations

import logging
from pathlib import Path

from antyswirus_lib.types import ScanResult, Verdict

log = logging.getLogger(__name__)


class StubHashRepository:
    async def lookup(self, path: Path) -> ScanResult:
        log.debug("stub hash lookup: %s", path)
        return ScanResult(path=path, verdict=Verdict.UNKNOWN, detail="stub")

    async def close(self) -> None:
        log.debug("stub hash repository closed")
