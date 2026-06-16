"""Sync module for VirusShare hash lists.

Downloads SHA-256 hash list archives from VirusShare and imports
them into the local :class:`HashDatabase <antyswirusd.hash_db.HashDatabase>`.

VirusShare publishes SHA-256 hashes across multiple zip archives
named ``VirusShare_XXXXX.zip`` (5-digit zero-padded index). Each
archive contains a plain-text file with one hex SHA-256 per line.

Sources
-------
- ``https://virusshare.com/hashes/VirusShare_XXXXX.zip``

The module tracks the last successfully imported file index in
``sync_meta`` so subsequent syncs resume where they left off.
The maximum index is discovered dynamically: the download loop
stops after three consecutive failures.
"""

from __future__ import annotations

import io
import logging
import zipfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from antyswirusd.hash_db import HashDatabase

log = logging.getLogger(__name__)

_BASE_URL = "https://virusshare.com/hashes/VirusShare_{:05d}.zip"
_SOURCE_NAME = "virusshare"
_MAX_CONSECUTIVE_FAILURES = 3


def _download_zip(index: int) -> bytes | None:
    """Download a VirusShare hash zip by index. Returns None on failure."""
    import urllib.request

    url = _BASE_URL.format(index)
    log.debug("downloading %s", url)
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:
            if resp.status != 200:
                log.warning("%s returned HTTP %d", url, resp.status)
                return None
            return resp.read()
    except Exception as exc:
        log.debug("failed to download %s: %s", url, exc)
        return None


def _extract_hashes(raw: bytes) -> list[str]:
    """Extract SHA-256 hashes from a VirusShare zip archive.

    The zip contains one or more text files with one hex hash per line.
    """
    hashes: list[str] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for name in zf.namelist():
            text = zf.read(name).decode("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line:
                    hashes.append(line)
    return hashes


async def sync_from_index(
    db: HashDatabase, start: int = 0, end: int | None = None
) -> dict[int, int]:
    """Download and import VirusShare hash lists from *start*.

    Stops when *end* is reached (if given) or after
    ``_MAX_CONSECUTIVE_FAILURES`` consecutive download failures.

    Returns a dict mapping each successfully imported index to the
    number of new hashes it contributed.
    """
    import asyncio

    results: dict[int, int] = {}
    consecutive_failures = 0
    i = start
    while True:
        if end is not None and i > end:
            break
        raw = await asyncio.to_thread(_download_zip, i)
        if raw is None:
            consecutive_failures += 1
            if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                log.info(
                    "stopping at index %d after %d consecutive failures",
                    i,
                    consecutive_failures,
                )
                break
            i += 1
            continue
        consecutive_failures = 0
        hashes = await asyncio.to_thread(_extract_hashes, raw)
        count = await db.import_virusshare_hashes(hashes)
        results[i] = count
        log.info(
            "VirusShare_%05d.zip: %d hashes, %d new",
            i,
            len(hashes),
            count,
        )
        await db.set_sync_meta(_SOURCE_NAME, str(i + 1))
        i += 1
    return results


async def sync(db: HashDatabase, *, full: bool = False) -> int:
    """Sync the local database with VirusShare hash lists.

    If *full* is True or no prior sync exists, all known hash files
    are downloaded. Otherwise the sync resumes from the last
    successfully imported index.

    Returns the total number of new hashes imported.
    """
    meta = await db.get_sync_meta(_SOURCE_NAME)
    start = 0 if (full or meta is None) else int(meta)
    results = await sync_from_index(db, start=start)
    return sum(results.values())
