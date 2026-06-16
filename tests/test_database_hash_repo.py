"""Tests for DatabaseHashRepository."""

from __future__ import annotations

import asyncio

from antyswirus_lib.types import Verdict


class TestDatabaseHashRepository:
    def test_lookup_unknown_returns_unknown(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase
            from antyswirusd.database_hash_repo import DatabaseHashRepository

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            repo = DatabaseHashRepository(db)
            await repo.open()
            try:
                result = await repo.lookup_by_hash("0" * 64)
                assert result.verdict is Verdict.UNKNOWN
            finally:
                await repo.close()

        asyncio.run(go())

    def test_lookup_malwarebazaar_returns_malicious(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase
            from antyswirusd.database_hash_repo import DatabaseHashRepository

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            repo = DatabaseHashRepository(db)
            await repo.open()
            try:
                await db.import_malwarebazaar_rows(
                    [
                        {
                            "sha256_hash": "a" * 64,
                            "first_seen_utc": "2024-01-01",
                            "tags": "",
                        }
                    ]
                )
                result = await repo.lookup_by_hash("a" * 64)
                assert result.verdict is Verdict.MALICIOUS
            finally:
                await repo.close()

        asyncio.run(go())

    def test_close_makes_lookup_return_unknown(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase
            from antyswirusd.database_hash_repo import DatabaseHashRepository

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            repo = DatabaseHashRepository(db)
            await repo.open()
            await repo.close()
            result = await repo.lookup_by_hash("d" * 64)
            assert result.verdict is Verdict.UNKNOWN
            assert "closed" in (result.detail or "")

        asyncio.run(go())

    def test_sync_all_structure(self):
        """sync_all has expected parameters (no network test)."""
        from antyswirusd.database_hash_repo import sync_all
        import inspect

        sig = inspect.signature(sync_all)
        assert "hash_db" in sig.parameters
        assert "api_key" in sig.parameters
