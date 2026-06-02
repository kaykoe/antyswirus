"""File-content hashing utilities.

Pure-Python, sync, no I/O framing concerns beyond reading the file
in fixed-size chunks so memory stays bounded regardless of file size.

The worker calls these via ``asyncio.to_thread`` to keep the event
loop responsive while hashing large files.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK_SIZE = 1 << 20  # 1 MiB


def compute_sha256(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of ``path``'s contents.

    Raises ``OSError`` if the file cannot be read.
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
