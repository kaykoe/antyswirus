"""Protocols for the engine's pluggable modules.

The engine never instantiates these directly. It receives concrete
implementations in its constructor and calls them through the
attributes declared here. Swapping an implementation is a one-line
change in ``antyswirusd.engine.Engine``.

All methods are async because the ``Whitelist`` and ``HashRepository``
back-ends may issue I/O (local SQLite, remote malware-DB service)
and the engine already runs everything through asyncio. Sync
implementations can simply return an awaitable that resolves
immediately.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

from antyswirus_lib.types import HashLookup, ScanResult, Verdict


class HashRepository(Protocol):
    """Decides whether a given content hash is malicious.

    The repository is path-agnostic: its only key is the content
    hash. The worker is responsible for hashing the file before
    calling ``lookup_by_hash``.

    Implementations may consult a local signature database, a
    remote service, or any combination. They should be safe to call
    from multiple worker coroutines concurrently.
    """

    async def lookup_by_hash(self, content_hash: str) -> HashLookup:
        """Return a verdict for ``content_hash``."""
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


class WhitelistKind(str, Enum):
    """The kind of a whitelist entry.

    - ``PATH``: an absolute directory path; everything in or below it is excluded
      from scanning. No globbing.
    - ``SHA256``: a content hash; a file whose content hashes to this value is
      trusted regardless of where it lives.
    """

    PATH = "path"
    SHA256 = "sha256"


@dataclass(slots=True, frozen=True)
class WhitelistEntry:
    """A single whitelist rule."""

    kind: WhitelistKind
    value: str
    added_at: float = 0.0
    note: str | None = None


class Whitelist(Protocol):
    """Marks directories and content hashes as known-safe.

    Two narrow query methods back two distinct pipeline hooks:

    - ``matches_directory`` is called by the scanner to decide
      whether to descend into a directory. Skipping is a real
      optimisation: no ``stat``, no cache check, no queue submission
      for anything inside.
    - ``is_hash_whitelisted`` is called by the lookup worker
      just before consulting the hash repository. If the file's
      content hash is whitelisted, the malware-DB is never queried
      and the verdict is ``WHITELISTED``.

    All methods are async. The on-disk implementation is aiosqlite;
    the connection is held by the engine on its event loop and is
    safe to share between scanner and worker coroutines.
    """

    async def open(self) -> None:
        """Open the underlying storage. Idempotent."""
        ...

    async def close(self) -> None:
        """Release any resources held by the whitelist."""
        ...

    async def matches_directory(self, path: Path) -> bool:
        """Return True iff ``path`` equals or is a descendant of any PATH entry."""
        ...

    async def is_hash_whitelisted(self, content_hash: str) -> bool:
        """Return True iff ``content_hash`` matches any SHA256 entry."""
        ...

    async def add(self, entry: WhitelistEntry) -> None:
        """Add a new entry. Duplicate (kind, value) pairs are ignored."""
        ...

    async def remove(self, entry: WhitelistEntry) -> bool:
        """Remove an entry. Return True iff the entry was present."""
        ...

    async def list(self) -> list[WhitelistEntry]:
        """Return all currently held entries, oldest first."""
        ...
