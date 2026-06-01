"""Stub ``Whitelist`` that always returns False (nothing is whitelisted)."""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)


class StubWhitelist:
    async def contains(self, path: Path) -> bool:
        log.debug("STUB whitelist check: %s", path)
        return False

    async def add(self, pattern: str) -> None:
        log.debug("STUB whitelist add: %s", pattern)

    async def remove(self, pattern: str) -> None:
        log.debug("STUB whitelist remove: %s", pattern)

    async def list(self) -> list[str]:
        log.debug("STUB whitelist list")
        return []

    async def close(self) -> None:
        log.debug("stub whitelist closed")
