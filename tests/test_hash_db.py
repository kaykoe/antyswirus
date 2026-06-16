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
                await db.import_malwarebazaar_rows([
                    {
                        "sha256_hash": "a" * 64,
                        "first_seen": "2024-01-01",
                        "file_name": "evil.exe",
                        "file_type": "exe",
                        "tags": "trojan,downloader",
                        "signature": "AgentTesla",
                    }
                ])
                result = await db.lookup_by_hash("a" * 64)
                assert result.verdict is Verdict.MALICIOUS
                assert "AgentTesla" in result.detail
                assert "evil.exe" in result.detail
            finally:
                await db.close()

        asyncio.run(go())

    def test_malwarebazaar_preferred_over_virusshare(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                await db.import_malwarebazaar_rows([
                    {
                        "sha256_hash": "a" * 64,
                        "first_seen": "2024-01-01",
                        "file_name": "from_mb.exe",
                        "file_type": "exe",
                        "tags": "",
                        "signature": "MB_sig",
                    }
                ])
                await db.import_virusshare_hashes(["a" * 64])
                result = await db.lookup_by_hash("a" * 64)
                assert result.verdict is Verdict.MALICIOUS
                assert "MB_sig" in result.detail
                assert "malwarebazaar" in result.detail
            finally:
                await db.close()

        asyncio.run(go())

    def test_virusshare_fallback(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                await db.import_virusshare_hashes(["a" * 64])
                result = await db.lookup_by_hash("a" * 64)
                assert result.verdict is Verdict.MALICIOUS
                assert "virusshare" in result.detail
            finally:
                await db.close()

        asyncio.run(go())

    def test_import_virusshare_skips_invalid_hashes(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                before = await db.count()
                await db.import_virusshare_hashes([
                    "a" * 64,
                    "not-a-hex",
                    "short",
                    "b" * 64,
                ])
                after = await db.count()
                assert after - before == 2
            finally:
                await db.close()

        asyncio.run(go())

    def test_import_malwarebazaar_dedup(self, tmp_path):
        async def go():
            from antyswirusd.hash_db import HashDatabase

            db = HashDatabase(tmp_path / "hash.db")
            await db.open()
            try:
                row = {
                    "sha256_hash": "a" * 64,
                    "first_seen": "2024-01-01",
                    "file_name": None,
                    "file_type": None,
                    "tags": "",
                    "signature": None,
                }
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

                await db.import_malwarebazaar_rows([
                    {
                        "sha256_hash": "a" * 64,
                        "first_seen": None,
                        "file_name": None,
                        "file_type": None,
                        "tags": "",
                        "signature": None,
                    }
                ])
                await db.import_virusshare_hashes(["b" * 64, "c" * 64])

                assert await db.count() == 3
                by_source = await db.count_by_source()
                assert by_source.get("malwarebazaar") == 1
                assert by_source.get("virusshare") == 2
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
                await db.import_malwarebazaar_rows([
                    {
                        "sha256_hash": "a" * 64,
                        "first_seen": "2024-01-01",
                        "file_name": "evil.exe",
                        "file_type": "exe",
                        "tags": "",
                        "signature": "foo",
                    }
                ])
                # SHA-1 lookup should not match (no sha1 column)
                result = await db.lookup_by_hash("b" * 40)
                assert result.verdict is Verdict.UNKNOWN
                # MD5 lookup should not match (no md5 column)
                result = await db.lookup_by_hash("c" * 32)
                assert result.verdict is Verdict.UNKNOWN
            finally:
                await db.close()

        asyncio.run(go())
