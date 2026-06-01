"""antyswirus_lib: types and protocol definitions shared by the daemon and the client."""

from antyswirus_lib.protocols import (
    HashRepository,
    Quarantine,
    QuarantinedFile,
    Whitelist,
)
from antyswirus_lib.types import (
    FileFingerprint,
    ScanResult,
    Verdict,
)

__all__ = [
    "FileFingerprint",
    "HashRepository",
    "Quarantine",
    "QuarantinedFile",
    "ScanResult",
    "Verdict",
    "Whitelist",
]
