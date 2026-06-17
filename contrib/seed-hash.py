#!/usr/bin/env python3
"""Seed the antyswirus hash DB with the EICAR test file hash.

Run as root (needs write access to /var/lib/antyswirus/hash.db)::

    sudo python3 contrib/seed-hash.py
"""

from __future__ import annotations

import asyncio
import hashlib

from antyswirusd.hash_db import HashDatabase
from antyswirus_lib.paths import RuntimePaths

EICAR_CONTENT = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


async def main() -> None:
    sha = hashlib.sha256(EICAR_CONTENT).hexdigest()
    print(f"EICAR SHA-256: {sha}")

    paths = RuntimePaths.default()
    db = HashDatabase(paths.hash_db_path)
    await db.open()
    count = await db.import_malwarebazaar_rows([
        ["2026-06-15 12:00:00", sha],
    ])
    await db.close()
    print(f"Inserted {count} hash(es) into {paths.hash_db_path}")
    print("Done — the daemon will detect any file matching this hash.")


if __name__ == "__main__":
    asyncio.run(main())
