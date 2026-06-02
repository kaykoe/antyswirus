"""Tests for the antyswirusd.stub modules.

The whitelist has no stub — the engine uses the real
``WhitelistDb`` directly. Stub tests for the hash repository and
quarantine remain here.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from antyswirusd.modules import StubHashRepository, StubQuarantine
from antyswirus_lib import Verdict
from antyswirus_lib.types import HashLookup, ScanResult


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


class TestStubQuarantine:
    def test_quarantine_returns_unique_id(self, tmp_path: Path):
        async def go():
            q = StubQuarantine()
            try:
                p = tmp_path / "evil.bin"
                p.write_bytes(b"x")
                r = ScanResult(path=p, verdict=Verdict.MALICIOUS)
                id1 = await q.quarantine(p, r)
                id2 = await q.quarantine(p, r)
                assert id1 != id2
                # Both ids are 32-char hex (uuid4().hex).
                uuid.UUID(hex=id1)
                uuid.UUID(hex=id2)
            finally:
                await q.close()

        asyncio.run(go())

    def test_list_is_empty(self):
        async def go():
            q = StubQuarantine()
            try:
                assert await q.list() == []
            finally:
                await q.close()

        asyncio.run(go())
