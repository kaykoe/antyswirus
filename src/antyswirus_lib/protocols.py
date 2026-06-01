"""Protocols for the engine's pluggable modules.

The engine never instantiates these directly. It receives concrete
implementations in its constructor and calls them through the
attributes declared here. Swapping a stub for a real implementation
is a one-line change in ``antyswirusd.engine.Engine``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from antyswirus_lib.types import ScanResult, Verdict


class HashRepository(Protocol):
    """Decides whether a given file is malicious.

    Implementations may consult a local cache, a remote service, a
    signature database, or any combination thereof. The engine calls
    this once per file that needs scanning, so implementations should
    be safe to call from multiple worker coroutines concurrently.
    """

    async def lookup(self, path: Path) -> ScanResult:
        """Return a ``ScanResult`` describing ``path``."""
        ...

    async def close(self) -> None:
        """Release any resources held by the repository."""
        ...


@dataclass(slots=True)
class QuarantinedFile:
    """Metadata about a file currently held in quarantine."""

    id: str
    original_path: Path
    quarantined_at: float
    verdict: Verdict
    detail: str | None = None


class Quarantine(Protocol):
    """Stores files deemed malicious in isolation.

    The engine calls ``quarantine`` whenever a worker produces a
    ``MALICIOUS`` verdict. The other methods are exposed to clients
    over the IPC channel.
    """

    async def quarantine(self, path: Path, result: ScanResult) -> str:
        """Move ``path`` into the quarantine and return a quarantine id."""
        ...

    async def restore(self, quarantine_id: str, dest: Path) -> None:
        """Restore a quarantined file to ``dest``."""
        ...

    async def list(self) -> list[QuarantinedFile]:
        """Return all files currently held in quarantine."""
        ...

    async def delete(self, quarantine_id: str) -> None:
        """Permanently remove a quarantined file."""
        ...

    async def close(self) -> None:
        """Release any resources held by the quarantine."""
        ...


class Whitelist(Protocol):
    """Marks files or path patterns as known-safe so they are skipped.

    Patterns are implementation-defined; a typical implementation
    would support exact paths plus glob patterns. The engine queries
    ``contains`` during the scan; clients call ``add``/``remove``/``list``
    over IPC.
    """

    async def contains(self, path: Path) -> bool:
        """Return True if ``path`` matches any whitelisted pattern."""
        ...

    async def add(self, pattern: str) -> None:
        """Add a new whitelisted pattern."""
        ...

    async def remove(self, pattern: str) -> None:
        """Remove a whitelisted pattern."""
        ...

    async def list(self) -> list[str]:
        """Return all currently whitelisted patterns."""
        ...

    async def close(self) -> None:
        """Release any resources held by the whitelist."""
        ...
