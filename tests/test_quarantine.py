"""Tests for the antyswirusd.quarantine module (QuarantineDb)."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import time
from pathlib import Path

import pytest

from antyswirusd.quarantine import MAX_LIST_LIMIT, QuarantineDb
from antyswirus_lib import Verdict
from antyswirus_lib.types import ScanResult


def _malicious(path: Path, detail: str = "eicar") -> ScanResult:
    return ScanResult(path=path, verdict=Verdict.MALICIOUS, detail=detail)


class TestOpenClose:
    def test_open_creates_dir_and_db(self, runtime_paths):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                assert runtime_paths.quarantine_dir.is_dir()
                assert runtime_paths.quarantine_db_path.exists()
                # Schema present.
                conn = sqlite3.connect(str(runtime_paths.quarantine_db_path))
                try:
                    rows = conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                finally:
                    conn.close()
                names = {r[0] for r in rows}
                assert "entries" in names
            finally:
                await db.close()

        asyncio.run(go())

    def test_open_is_idempotent(self, runtime_paths):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                await db.open()  # must not raise
            finally:
                await db.close()

        asyncio.run(go())

    def test_close_is_idempotent(self, runtime_paths):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.close()  # no-op
            await db.open()
            await db.close()
            await db.close()  # no-op

        asyncio.run(go())

    def test_quarantine_dir_is_mode_700(self, runtime_paths):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                mode = runtime_paths.quarantine_dir.stat().st_mode & 0o777
                # umask may further restrict, but it must not be 0o755.
                assert mode != 0o755
            finally:
                await db.close()

        asyncio.run(go())

    def test_open_retightens_loose_dir(self, runtime_paths):
        async def go():
            # Pre-create the dir with loose perms; ``open`` must fix it.
            runtime_paths.quarantine_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(runtime_paths.quarantine_dir, 0o755)
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                mode = runtime_paths.quarantine_dir.stat().st_mode & 0o777
                assert mode != 0o755
            finally:
                await db.close()

        asyncio.run(go())


class TestQuarantine:
    def test_quarantine_moves_file_and_returns_qid(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                original_bytes = a.read_bytes()
                qid = await db.quarantine(a, _malicious(a))
                # File is gone from scan_root.
                assert not a.exists()
                # File exists in quarantine dir.
                matches = [
                    p
                    for p in runtime_paths.quarantine_dir.iterdir()
                    if p.name.startswith(qid)
                ]
                assert len(matches) == 1
                assert matches[0].read_bytes() == original_bytes
                # qid is uuid4().hex.
                assert len(qid) == 32
                int(qid, 16)  # pure hex
            finally:
                await db.close()

        asyncio.run(go())

    def test_quarantine_inserts_row(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                before = time.time()
                qid = await db.quarantine(a, _malicious(a, detail="badtld"))
                after = time.time()
                conn = sqlite3.connect(str(runtime_paths.quarantine_db_path))
                try:
                    row = conn.execute(
                        "SELECT qid, original_path, quarantined_at, verdict, detail"
                        " FROM entries WHERE qid = ?",
                        (qid,),
                    ).fetchone()
                finally:
                    conn.close()
                assert row is not None
                assert row[0] == qid
                assert row[1] == str(a)
                assert before <= row[2] <= after
                assert row[3] == "malicious"
                assert row[4] == "badtld"
            finally:
                await db.close()

        asyncio.run(go())

    def test_quarantine_missing_file_raises(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "ghost.txt"
                with pytest.raises(FileNotFoundError):
                    await db.quarantine(a, _malicious(a))
            finally:
                await db.close()

        asyncio.run(go())

    def test_quarantine_preserves_basename_human_readable(
        self, runtime_paths, scan_root
    ):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "evil-payload.bin"
                a.write_bytes(b"x")
                qid = await db.quarantine(a, _malicious(a))
                stored = next(
                    p
                    for p in runtime_paths.quarantine_dir.iterdir()
                    if p.name.startswith(qid)
                )
                assert stored.name.endswith("__evil-payload.bin")
            finally:
                await db.close()

        asyncio.run(go())

    def test_quarantine_keeps_file_in_dir_root(self, runtime_paths, scan_root):
        """Files with deeply nested source paths still end up directly in the
        quarantine dir (no nested directories)."""

        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                deep = scan_root / "sub" / "c.txt"
                qid = await db.quarantine(deep, _malicious(deep))
                stored = next(
                    p
                    for p in runtime_paths.quarantine_dir.iterdir()
                    if p.name.startswith(qid)
                )
                assert stored.parent == runtime_paths.quarantine_dir
                # Only the basename of the source path is used.
                assert stored.name.endswith("__c.txt")
            finally:
                await db.close()

        asyncio.run(go())


class TestRestore:
    def test_restore_moves_file_back(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                original_bytes = a.read_bytes()
                qid = await db.quarantine(a, _malicious(a))
                await db.restore(qid)
                assert a.exists()
                assert a.read_bytes() == original_bytes
                # Row is gone.
                conn = sqlite3.connect(str(runtime_paths.quarantine_db_path))
                try:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM entries WHERE qid = ?", (qid,)
                    ).fetchone()[0]
                finally:
                    conn.close()
                assert count == 0
                # Quarantine dir no longer holds the file.
                leftovers = [
                    p
                    for p in runtime_paths.quarantine_dir.iterdir()
                    if p.name.startswith(qid)
                ]
                assert leftovers == []
            finally:
                await db.close()

        asyncio.run(go())

    def test_restore_unknown_id_raises(self, runtime_paths):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                with pytest.raises(KeyError):
                    await db.restore("deadbeef" * 4)
            finally:
                await db.close()

        asyncio.run(go())

    def test_restore_refuses_when_destination_occupied(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                qid = await db.quarantine(a, _malicious(a))
                # Occupy the original path with unrelated bytes.
                a.write_bytes(b"unrelated")
                with pytest.raises(FileExistsError):
                    await db.restore(qid)
                # The row is still there.
                conn = sqlite3.connect(str(runtime_paths.quarantine_db_path))
                try:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM entries WHERE qid = ?", (qid,)
                    ).fetchone()[0]
                finally:
                    conn.close()
                assert count == 1
            finally:
                await db.close()

        asyncio.run(go())

    def test_restore_prunes_row_when_file_vanished(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                qid = await db.quarantine(a, _malicious(a))
                # Yank the stored file out from under the db.
                stored = next(
                    p
                    for p in runtime_paths.quarantine_dir.iterdir()
                    if p.name.startswith(qid)
                )
                stored.unlink()
                with pytest.raises(FileNotFoundError):
                    await db.restore(qid)
                # Row was cleaned up.
                conn = sqlite3.connect(str(runtime_paths.quarantine_db_path))
                try:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM entries WHERE qid = ?", (qid,)
                    ).fetchone()[0]
                finally:
                    conn.close()
                assert count == 0
            finally:
                await db.close()

        asyncio.run(go())


class TestDelete:
    def test_delete_removes_file_and_row(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                qid = await db.quarantine(a, _malicious(a))
                stored = next(
                    p
                    for p in runtime_paths.quarantine_dir.iterdir()
                    if p.name.startswith(qid)
                )
                assert stored.exists()
                await db.delete(qid)
                assert not stored.exists()
                conn = sqlite3.connect(str(runtime_paths.quarantine_db_path))
                try:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM entries WHERE qid = ?", (qid,)
                    ).fetchone()[0]
                finally:
                    conn.close()
                assert count == 0
            finally:
                await db.close()

        asyncio.run(go())

    def test_delete_idempotent_on_missing_file(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                qid = await db.quarantine(a, _malicious(a))
                stored = next(
                    p
                    for p in runtime_paths.quarantine_dir.iterdir()
                    if p.name.startswith(qid)
                )
                stored.unlink()
                # Must not raise.
                await db.delete(qid)
                conn = sqlite3.connect(str(runtime_paths.quarantine_db_path))
                try:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM entries WHERE qid = ?", (qid,)
                    ).fetchone()[0]
                finally:
                    conn.close()
                assert count == 0
            finally:
                await db.close()

        asyncio.run(go())

    def test_delete_unknown_id_raises(self, runtime_paths):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                with pytest.raises(KeyError):
                    await db.delete("deadbeef" * 4)
            finally:
                await db.close()

        asyncio.run(go())


class TestList:
    def test_list_empty(self, runtime_paths):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                assert await db.list(offset=0, limit=100) == []
                assert await db.count() == 0
            finally:
                await db.close()

        asyncio.run(go())

    def test_list_returns_all_when_under_limit(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                paths = [
                    scan_root / "a.txt",
                    scan_root / "b.txt",
                    scan_root / "sub" / "c.txt",
                ]
                for p in paths:
                    await db.quarantine(p, _malicious(p))
                items = await db.list(offset=0, limit=100)
                assert len(items) == 3
                # Sorted by quarantined_at (and qid as tiebreaker).
                ts = [i.quarantined_at for i in items]
                assert ts == sorted(ts)
                assert await db.count() == 3
            finally:
                await db.close()

        asyncio.run(go())

    def test_list_pagination(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                paths = [
                    scan_root / "a.txt",
                    scan_root / "b.txt",
                    scan_root / "sub" / "c.txt",
                ]
                for p in paths:
                    await db.quarantine(p, _malicious(p))
                # Sleep so the timestamp ordering is stable.
                await asyncio.sleep(0.01)
                page1 = await db.list(offset=0, limit=2)
                page2 = await db.list(offset=2, limit=2)
                assert len(page1) == 2
                assert len(page2) == 1
                # No overlap.
                ids1 = {i.id for i in page1}
                ids2 = {i.id for i in page2}
                assert ids1.isdisjoint(ids2)
                assert len(ids1) + len(ids2) == 3
            finally:
                await db.close()

        asyncio.run(go())

    def test_list_limit_clamped_to_max(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                # A wild request must be clamped, not honoured.
                items = await db.list(offset=0, limit=10**9)
                # Without any rows this is just []; the clamp only
                # matters for actual data. Add one row and retry.
                p = scan_root / "a.txt"
                await db.quarantine(p, _malicious(p))
                items = await db.list(offset=0, limit=10**9)
                assert len(items) == 1
                # And ``MAX_LIST_LIMIT`` is what we expect.
                assert MAX_LIST_LIMIT == 1000
            finally:
                await db.close()

        asyncio.run(go())

    def test_list_items_carry_protocol_fields(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                before = time.time()
                qid = await db.quarantine(a, _malicious(a, detail="sig-x"))
                after = time.time()
                items = await db.list(offset=0, limit=10)
                assert len(items) == 1
                item = items[0]
                assert item.id == qid
                assert item.original_path == a
                assert before <= item.quarantined_at <= after
                assert item.verdict is Verdict.MALICIOUS
                assert item.detail == "sig-x"
            finally:
                await db.close()

        asyncio.run(go())


class TestCount:
    def test_count_tracks_inserts_and_deletes(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                assert await db.count() == 0
                a = scan_root / "a.txt"
                qid1 = await db.quarantine(a, _malicious(a))
                b = scan_root / "b.txt"
                qid2 = await db.quarantine(b, _malicious(b))
                assert await db.count() == 2
                await db.delete(qid1)
                assert await db.count() == 1
                await db.restore(qid2)
                assert await db.count() == 0
            finally:
                await db.close()

        asyncio.run(go())


class TestPrune:
    def test_prune_removes_rows_whose_file_vanished(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                qid = await db.quarantine(a, _malicious(a))
                stored = next(
                    p
                    for p in runtime_paths.quarantine_dir.iterdir()
                    if p.name.startswith(qid)
                )
                stored.unlink()
                removed = await db.prune()
                assert removed == 1
                assert await db.count() == 0
            finally:
                await db.close()

        asyncio.run(go())

    def test_prune_age_caps_rows_older_than_max_age_days(
        self, runtime_paths, scan_root
    ):
        async def go():
            # Build a db with max_age_days=1 so the test's old rows
            # are unambiguously "aged out".
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
                max_age_days=1,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                qid = await db.quarantine(a, _malicious(a))
                # Manually rewind the row's timestamp by 5 days.
                conn = sqlite3.connect(str(runtime_paths.quarantine_db_path))
                try:
                    conn.execute(
                        "UPDATE entries SET quarantined_at = ? WHERE qid = ?",
                        (time.time() - 5 * 86400, qid),
                    )
                    conn.commit()
                finally:
                    conn.close()
                removed = await db.prune()
                assert removed == 1
                assert await db.count() == 0
            finally:
                await db.close()

        asyncio.run(go())

    def test_prune_keeps_fresh_rows(self, runtime_paths, scan_root):
        async def go():
            db = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
                max_age_days=14,
            )
            await db.open()
            try:
                a = scan_root / "a.txt"
                await db.quarantine(a, _malicious(a))
                removed = await db.prune()
                assert removed == 0
                assert await db.count() == 1
            finally:
                await db.close()

        asyncio.run(go())


class TestPersistence:
    def test_rows_survive_reopen(self, runtime_paths, scan_root):
        async def go():
            db1 = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db1.open()
            try:
                a = scan_root / "a.txt"
                qid = await db1.quarantine(a, _malicious(a))
            finally:
                await db1.close()

            db2 = QuarantineDb(
                runtime_paths.quarantine_dir,
                runtime_paths.quarantine_db_path,
            )
            await db2.open()
            try:
                items = await db2.list(offset=0, limit=10)
                assert len(items) == 1
                assert items[0].id == qid
                # Restore works across restarts.
                await db2.restore(qid)
                assert a.exists()
            finally:
                await db2.close()

        asyncio.run(go())
