"""antyswirus_lib: types shared by the daemon and the client."""

from antyswirus_lib.hashing import compute_sha256
from antyswirus_lib.types import (
    FileFingerprint,
    HashLookup,
    QuarantinedFile,
    ScanResult,
    Verdict,
    WhitelistEntry,
    WhitelistKind,
)

__all__ = [
    "FileFingerprint",
    "HashLookup",
    "QuarantinedFile",
    "ScanResult",
    "Verdict",
    "WhitelistEntry",
    "WhitelistKind",
    "compute_sha256",
]
