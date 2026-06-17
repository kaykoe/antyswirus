"""``HashRepository`` implementation backed by the local :class:`HashDatabase`.

Lookup strategy
---------------
1. Query the local database for a MalwareBazaar match.
2. If no match, return ``Verdict.UNKNOWN``.

The database is synced from MalwareBazaar by the
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
    """``HashRepository`` that queries the local malware hash database."""

    def __init__(self, db: HashDatabase) -> None:
        self._db = db

    async def open(self) -> None:
        assert self._db is not None
        await self._db.open()

    async def lookup_by_hash(self, content_hash: str) -> HashLookup:
        db = self._db
        if db is None:
            return HashLookup(verdict=Verdict.UNKNOWN, detail="repo closed")
        log.debug("hash lookup: sha256=%s", content_hash)

        result = await db.lookup_by_hash(content_hash)
        if result.verdict is Verdict.MALICIOUS:
            return result
        return HashLookup(verdict=Verdict.UNKNOWN)

    async def close(self) -> None:
        db, self._db = self._db, None
        if db is not None:
            await db.close()


async def sync_all(
    hash_db: HashDatabase,
    *,
    api_key: str = "",
    malwarebazaar_full: bool = False,
) -> dict[str, int]:
    """Sync the local database from MalwareBazaar.

    Parameters
    ----------
    hash_db
        The database to populate.
    api_key
        MalwareBazaar API key for authenticated downloads.
    malwarebazaar_full
        If True, download the full MalwareBazaar dump (otherwise only
        recent entries).

    Returns
    -------
    dict[str, int]
        A mapping of source name to number of new hashes imported.
    """
    from antyswirusd import malwarebazaar

    results: dict[str, int] = {}

    mb_count = await malwarebazaar.sync(
        hash_db, api_key=api_key, full=malwarebazaar_full
    )
    results["malwarebazaar"] = mb_count

    return results
