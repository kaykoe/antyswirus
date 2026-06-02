"""``HashRepository`` that always returns ``Verdict.UNKNOWN``.

The repository is path-agnostic — it only sees content hashes. The
worker is responsible for hashing the file before calling
``lookup_by_hash``.
"""

from __future__ import annotations

import logging

from antyswirus_lib.types import HashLookup, Verdict

log = logging.getLogger(__name__)


class StubHashRepository:
    async def lookup_by_hash(self, content_hash: str) -> HashLookup:
        log.debug("stub hash lookup: sha256=%s", content_hash)
        return HashLookup(verdict=Verdict.UNKNOWN, detail="stub")

    async def close(self) -> None:
        log.debug("stub hash repository closed")
