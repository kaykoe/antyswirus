"""antyswirus_lib: types and protocol definitions shared by the daemon and the client."""

from antyswirus_lib.hashing import compute_sha256
from antyswirus_lib.protocols import (
    HashRepository,
    Quarantine,
    QuarantinedFile,
    Whitelist,
    WhitelistEntry,
    WhitelistKind,
)
from antyswirus_lib.types import (
    FileFingerprint,
    HashLookup,
    ScanResult,
    Verdict,
)

__all__ = [
    "FileFingerprint",
    "HashLookup",
    "HashRepository",
    "Quarantine",
    "QuarantinedFile",
    "ScanResult",
    "Verdict",
    "Whitelist",
    "WhitelistEntry",
    "WhitelistKind",
    "compute_sha256",
]
