"""Tests for the HashDatabase (local malware hash storage)."""

from __future__ import annotations

import asyncio


from antyswirus_lib.types import Verdict


class TestHashDatabase:
    def test_empty_db_returns_unknown(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                result = await db.lookup_by_hash("0" * 64)
                assert result.verdict is Verdict.UNKNOWN
            finally:
                await db.close()

        asyncio.run(go())

    def test_lookup_by_sha256(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                await db.import_malwarebazaar_rows(
                    [
                        ["2024-01-01", "a" * 64],
                    ]
                )
                result = await db.lookup_by_hash("a" * 64)
                assert result.verdict is Verdict.MALICIOUS
            finally:
                await db.close()

        asyncio.run(go())

    def test_import_malwarebazaar_dedup(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                row = ["2024-01-01", "a" * 64]
                first = await db.import_malwarebazaar_rows([row])
                second = await db.import_malwarebazaar_rows([row])
                assert first == 1
                assert second == 0
            finally:
                await db.close()

        asyncio.run(go())

    def test_sync_meta(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                assert await db.get_sync_meta("test_source") is None
                await db.set_sync_meta("test_source", "42")
                assert await db.get_sync_meta("test_source") == "42"
                await db.set_sync_meta("test_source", "99")
                assert await db.get_sync_meta("test_source") == "99"
            finally:
                await db.close()

        asyncio.run(go())

    def test_count_and_count_by_source(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                assert await db.count() == 0
                assert await db.count_by_source() == {}

                await db.import_malwarebazaar_rows(
                    [
                        [None, "a" * 64],
                        [None, "b" * 64],
                    ]
                )

                assert await db.count() == 2
                by_source = await db.count_by_source()
                assert by_source.get("malwarebazaar") == 2
            finally:
                await db.close()

        asyncio.run(go())

    def test_close_idempotent(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            await db.close()
            await db.close()

        asyncio.run(go())

    def test_open_idempotent(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            await db.open()
            await db.close()

        asyncio.run(go())

    def test_lookup_sha256_only(self, tmp_path):
        """SHA-1 and MD5 are not stored; only SHA-256 lookups match."""

        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                await db.import_malwarebazaar_rows(
                    [
                        ["2024-01-01", "a" * 64],
                    ]
                )
                # SHA-1 lookup should not match (no sha1 column)
                result = await db.lookup_by_hash("b" * 40)
                assert result.verdict is Verdict.UNKNOWN
                # MD5 lookup should not match (no md5 column)
                result = await db.lookup_by_hash("c" * 32)
                assert result.verdict is Verdict.UNKNOWN
            finally:
                await db.close()

        asyncio.run(go())
