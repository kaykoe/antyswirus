"""Tests for the antyswirusd.modules package."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest

from antyswirusd.modules import PersistentQuarantine, StubHashRepository
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


class TestPersistentQuarantine:
    def _make(self, tmp_path: Path) -> PersistentQuarantine:
        q = PersistentQuarantine(
            db_path=tmp_path / "q.db",
            payload_dir=tmp_path / "payloads",
        )
        return q

    def test_quarantine_returns_unique_id(self, tmp_path: Path):
        async def go():
            q = self._make(tmp_path)
            await q.open()
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

    def test_list_is_empty(self, tmp_path: Path):
        async def go():
            q = self._make(tmp_path)
            await q.open()
            try:
                assert await q.list() == []
            finally:
                await q.close()

        asyncio.run(go())

    def test_quarantine_round_trip(self, tmp_path: Path):
        async def go():
            q = self._make(tmp_path)
            await q.open()
            try:
                p = tmp_path / "evil.bin"
                p.write_bytes(b"hello")
                qid = await q.quarantine(
                    p, ScanResult(path=p, verdict=Verdict.MALICIOUS, detail="t")
                )
                items = await q.list()
                assert len(items) == 1
                assert items[0].id == qid
                assert items[0].original_path == p
                assert items[0].verdict is Verdict.MALICIOUS
                assert items[0].detail == "t"
                # Payload exists on disk.
                assert (tmp_path / "payloads" / qid).read_bytes() == b"hello"
            finally:
                await q.close()

        asyncio.run(go())

    def test_restore_copies_back_and_removes_row(self, tmp_path: Path):
        async def go():
            q = self._make(tmp_path)
            await q.open()
            try:
                p = tmp_path / "evil.bin"
                p.write_bytes(b"payload-bytes")
                qid = await q.quarantine(
                    p, ScanResult(path=p, verdict=Verdict.MALICIOUS)
                )
                dest = tmp_path / "restored.bin"
                await q.restore(qid, dest)
                assert dest.read_bytes() == b"payload-bytes"
                assert await q.list() == []
                assert not (tmp_path / "payloads" / qid).exists()
            finally:
                await q.close()

        asyncio.run(go())

    def test_restore_unknown_id_raises(self, tmp_path: Path):
        async def go():
            q = self._make(tmp_path)
            await q.open()
            try:
                with pytest.raises(KeyError):
                    await q.restore("nope", tmp_path / "x")
            finally:
                await q.close()

        asyncio.run(go())

    def test_delete_removes_row_and_payload(self, tmp_path: Path):
        async def go():
            q = self._make(tmp_path)
            await q.open()
            try:
                p = tmp_path / "evil.bin"
                p.write_bytes(b"x")
                qid = await q.quarantine(
                    p, ScanResult(path=p, verdict=Verdict.MALICIOUS)
                )
                await q.delete(qid)
                assert await q.list() == []
                assert not (tmp_path / "payloads" / qid).exists()
            finally:
                await q.close()

        asyncio.run(go())

    def test_delete_unknown_id_raises(self, tmp_path: Path):
        async def go():
            q = self._make(tmp_path)
            await q.open()
            try:
                with pytest.raises(KeyError):
                    await q.delete("nope")
            finally:
                await q.close()

        asyncio.run(go())
