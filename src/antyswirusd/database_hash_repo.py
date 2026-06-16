"""``HashRepository`` implementation backed by the local :class:`HashDatabase`.

Lookup strategy
---------------
1. Query the local database for a MalwareBazaar match (smaller DB,
   richer metadata — checked first).
2. If no match, query for a VirusShare match (50M+ hashes).
3. If neither matches, return ``Verdict.UNKNOWN``.

The database is periodically synced from both sources by the
:func:`sync_all <antyswirusd.database_hash_repo.sync_all>` helper.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from antyswirus_lib.types import HashLookup, Verdict

if TYPE_CHECKING:
    from antyswirusd.hash_db import HashDatabase

log = logging.getLogger(__name__)


class DatabaseHashRepository:
    """``HashRepository`` that queries the local malware hash database.

    MalwareBazaar rows are checked first (richer metadata, smaller
    set); VirusShare rows are the fallback.
    """

    def __init__(self, db: HashDatabase) -> None:
        self._db = db
        self._closed = False

    async def lookup_by_hash(self, content_hash: str) -> HashLookup:
        if self._closed:
            return HashLookup(verdict=Verdict.UNKNOWN, detail="repo closed")
        return await self._db.lookup_by_hash(content_hash)

    async def close(self) -> None:
        self._closed = True
        await self._db.close()


async def sync_all(
    hash_db: HashDatabase,
    *,
    malwarebazaar_full: bool = False,
    virusshare_full: bool = False,
) -> dict[str, int]:
    """Sync the local database from both online sources.

    Parameters
    ----------
    hash_db
        The database to populate.
    malwarebazaar_full
        If True, download the full MalwareBazaar dump (otherwise only
        recent entries).
    virusshare_full
        If True, download all VirusShare hash files (otherwise resume
        from last position).

    Returns
    -------
    dict[str, int]
        A mapping of source name to number of new hashes imported.
    """
    from antyswirusd import malwarebazaar, virusshare

    results: dict[str, int] = {}

    mb_count = await malwarebazaar.sync(hash_db, full=malwarebazaar_full)
    results["malwarebazaar"] = mb_count

    vs_count = await virusshare.sync(hash_db, full=virusshare_full)
    results["virusshare"] = vs_count

    return results
