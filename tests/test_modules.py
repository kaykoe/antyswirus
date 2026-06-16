"""Tests for the antyswirusd.modules package (in-memory module doubles)."""

from __future__ import annotations

import asyncio

from antyswirusd.modules import StubHashRepository
from antyswirus_lib import Verdict
from antyswirus_lib.types import HashLookup


class TestStubHashRepository:
    def test_lookup_by_hash_returns_unknown(self):
        async def go():
            repo = StubHashRepository()
            try:
                r = await repo.lookup_by_hash(
                    "0" * 64
                )  # hash is irrelevant for the stub
                assert isinstance(r, HashLookup)
                assert r.verdict is Verdict.UNKNOWN
                assert r.detail == "stub"
            finally:
                await repo.close()

        asyncio.run(go())

    def test_close_is_idempotent(self):
        async def go():
            repo = StubHashRepository()
            await repo.close()
            await repo.close()

        asyncio.run(go())
