"""Shared data types for the antyswirus engine and client.

These types travel across the daemon/client boundary and are used by
every module in the project. Keep them serialisable and small.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NamedTuple, Protocol, runtime_checkable


class Verdict(str, Enum):
    """The outcome of looking up a single file.

    The string values are stable wire format; do not change them.
    """

    UNKNOWN = "unknown"
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    WHITELISTED = "whitelisted"
    ERROR = "error"


class FileFingerprint(NamedTuple):
    """A snapshot of a file's identifying attributes.

    Two files are considered "the same for caching purposes" iff
    every field matches. ``dev + inode`` discriminate across the
    filesystem, ``mtime_ns + size`` discriminate against inode reuse.
    """

    dev: int
    inode: int
    size: int
    mtime_ns: int

    @classmethod
    def from_stat(cls, st: os.stat_result) -> "FileFingerprint":
        return cls(
            dev=st.st_dev,
            inode=st.st_ino,
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
        )


@dataclass(slots=True)
class ScanResult:
    """The final verdict the engine records for a file, with its path attached."""

    path: Path
    verdict: Verdict
    detail: str | None = None


@dataclass(slots=True)
class HashLookup:
    """The verdict returned by ``HashRepository.lookup_by_hash``.

    Carries no path: the hash repository is path-agnostic — its only
    key is the content hash. The worker attaches the originating
    path when it wraps this in a ``ScanResult``.
    """

    verdict: Verdict
    detail: str | None = None


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


@dataclass(slots=True)
class QuarantinedFile:
    """Metadata about a file currently held in quarantine."""

    id: str
    original_path: Path
    quarantined_at: float
    verdict: Verdict
    detail: str | None = None


@runtime_checkable
class HashRepository(Protocol):
    """A source of hash-based verdicts, agnostic of file paths."""

    async def lookup_by_hash(self, content_hash: str) -> HashLookup: ...

    async def close(self) -> None: ...
