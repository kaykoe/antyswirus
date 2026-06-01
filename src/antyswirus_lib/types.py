"""Shared data types for the antyswirus engine and client.

These types travel across the daemon/client boundary and are used by
every module in the project. Keep them serialisable and small.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NamedTuple


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
    """The result of consulting the hash repository about a single file."""

    path: Path
    verdict: Verdict
    detail: str | None = None
