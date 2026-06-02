"""Tests for the antyswirusd.server module (IPC server)."""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path

import pytest

from antyswirusd.config import Config
from antyswirusd.engine import Engine
from antyswirus_lib.client import AntyswirusClient
from antyswirus_lib.ipc import ProtocolError, read_message


def _config() -> Config:
    return Config(
        worker_count=1,
        queue_size=16,
        log_level="WARNING",
        socket_mode=0o600,
    )


def _start_engine(runtime_paths, config) -> Engine:
    return Engine(runtime_paths, config)


class TestStatus:
    def test_status_returns_engine_info(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("status")
                assert resp.status == "ok"
                assert resp.result["pid"] > 0
                assert resp.result["workers"] == 1
                assert resp.result["cache_generation"] == 0
                assert resp.result["active_scans"] == 0
                # New fields: last_scan_at is None on a fresh daemon,
                # quarantine_count is 0 because nothing is quarantined.
                assert resp.result["last_scan_at"] is None
                assert resp.result["quarantine_count"] == 0
            finally:
                await engine.stop()

        asyncio.run(go())


class TestScan:
    def test_scan_queues_path_and_records(self, runtime_paths, scan_root):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("scan", path=str(scan_root))
                assert resp.status == "ok"
                assert resp.result["path"] == str(scan_root)
                # All 3 files should be recorded in the cache.
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("status")
                assert resp.result["active_scans"] == 0
                for p in [
                    scan_root / "a.txt",
                    scan_root / "b.txt",
                    scan_root / "sub" / "c.txt",
                ]:
                    assert await engine.cache.is_known(p, _fp(p)) is not None
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_scan_missing_path_returns_error(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call(
                        "scan", path=str(runtime_paths.runtime_dir / "nope")
                    )
                assert resp.status == "error"
                assert "not found" in (resp.error or "").lower()
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_scan_without_path_argument(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("scan")
                assert resp.status == "error"
                assert "path" in (resp.error or "").lower()
            finally:
                await engine.stop()

        asyncio.run(go())


class TestUnknownCommand:
    def test_unknown_command_returns_error(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("frobnicate")
                assert resp.status == "error"
                assert "frobnicate" in (resp.error or "")
            finally:
                await engine.stop()

        asyncio.run(go())


class TestQuarantineCommands:
    def test_quarantine_round_trip(self, runtime_paths, tmp_path):
        """End-to-end: quarantine, list, restore, delete."""

        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                payload = tmp_path / "evil.bin"
                payload.write_bytes(b"definitely-not-malicious")
                from antyswirus_lib import ScanResult, Verdict

                qid = await engine.quarantine.quarantine(
                    payload,
                    ScanResult(
                        path=payload,
                        verdict=Verdict.MALICIOUS,
                        detail="test",
                    ),
                )
                # Quarantine count via status IPC.
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("status")
                assert resp.result["quarantine_count"] == 1

                # List via IPC.
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("quarantine_list")
                assert resp.status == "ok"
                items = resp.result["items"]
                assert len(items) == 1
                assert items[0]["id"] == qid
                assert items[0]["original_path"] == str(payload)
                assert items[0]["verdict"] == "malicious"

                # Restore via IPC.
                restored = tmp_path / "restored.bin"
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call(
                        "quarantine_restore",
                        quarantine_id=qid,
                        dest=str(restored),
                    )
                assert resp.status == "ok"
                assert resp.result["restored"] == qid
                assert restored.read_bytes() == b"definitely-not-malicious"
                assert not (runtime_paths.quarantine_dir / qid).exists()

                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("status")
                assert resp.result["quarantine_count"] == 0
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_quarantine_delete_removes_payload(self, runtime_paths, tmp_path):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                payload = tmp_path / "evil.bin"
                payload.write_bytes(b"x")
                from antyswirus_lib import ScanResult, Verdict

                qid = await engine.quarantine.quarantine(
                    payload,
                    ScanResult(path=payload, verdict=Verdict.MALICIOUS),
                )
                assert (runtime_paths.quarantine_dir / qid).exists()
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("quarantine_delete", quarantine_id=qid)
                assert resp.status == "ok"
                assert not (runtime_paths.quarantine_dir / qid).exists()
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_restore_unknown_id_returns_error(self, runtime_paths, tmp_path):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call(
                        "quarantine_restore",
                        quarantine_id="nonexistent",
                        dest=str(tmp_path / "x"),
                    )
                assert resp.status == "error"
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_delete_unknown_id_returns_error(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call(
                        "quarantine_delete", quarantine_id="nonexistent"
                    )
                assert resp.status == "error"
            finally:
                await engine.stop()

        asyncio.run(go())


class TestWhitelistCommands:
    def test_add_list_remove_round_trip(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    add_resp = await c.call(
                        "whitelist_add",
                        kind="path",
                        value="/opt/trusted",
                        note="vendor dir",
                    )
                    assert add_resp.status == "ok"
                    assert add_resp.result == {
                        "added": {"kind": "path", "value": "/opt/trusted"}
                    }

                    list_resp = await c.call("whitelist_list")
                    assert list_resp.status == "ok"
                    entries = list_resp.result["entries"]
                    assert len(entries) == 1
                    assert entries[0]["kind"] == "path"
                    assert entries[0]["value"] == "/opt/trusted"
                    assert entries[0]["note"] == "vendor dir"
                    assert entries[0]["added_at"] > 0

                    rm_resp = await c.call(
                        "whitelist_remove", kind="path", value="/opt/trusted"
                    )
                    assert rm_resp.status == "ok"
                    # The rescan is fire-and-forget; the response carries
                    # the removed entry plus a flag indicating whether a
                    # rescan was scheduled.
                    assert rm_resp.result["removed"] == {
                        "kind": "path",
                        "value": "/opt/trusted",
                    }
                    assert rm_resp.result["rescan_scheduled"] is True

                    list_resp2 = await c.call("whitelist_list")
                    assert list_resp2.result["entries"] == []
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_add_rejects_relative_path(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call(
                        "whitelist_add", kind="path", value="relative/path"
                    )
                assert resp.status == "error"
                assert "absolute" in (resp.error or "").lower()
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_add_rejects_short_hash(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call(
                        "whitelist_add", kind="sha256", value="deadbeef"
                    )
                assert resp.status == "error"
                assert "64" in (resp.error or "")
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_add_rejects_unknown_kind(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call("whitelist_add", kind="banana", value="x")
                assert resp.status == "error"
                assert "kind" in (resp.error or "").lower()
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_remove_unknown_entry_is_ok(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                async with await AntyswirusClient.connect(
                    runtime_paths.socket_path
                ) as c:
                    resp = await c.call(
                        "whitelist_remove",
                        kind="sha256",
                        value="0" * 64,
                    )
                # Removing a non-existent entry is a no-op but must succeed.
                assert resp.status == "ok"
            finally:
                await engine.stop()

        asyncio.run(go())


class TestBadFraming:
    def test_garbage_length_returns_error_then_closes(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                reader, writer = await asyncio.open_unix_connection(
                    str(runtime_paths.socket_path)
                )
                try:
                    # Claim an absurdly long message, but send only the header.
                    writer.write(struct.pack(">I", 0xC0FFEE00))
                    await writer.drain()
                    # Server reads 4 bytes, sees length > 16 MiB, raises
                    # ProtocolError, writes an error frame, and closes.
                    # Client should be able to read the error frame.
                    err = await asyncio.wait_for(read_message(reader), timeout=2.0)
                    assert err["status"] == "error"
                    assert "unreasonable message length" in err["error"]
                    # Subsequent read should see EOF.
                    with pytest.raises(asyncio.IncompleteReadError):
                        await asyncio.wait_for(reader.readexactly(1), timeout=2.0)
                finally:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                    except (ConnectionResetError, BrokenPipeError):
                        pass
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_short_header_disconnects(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                # Client writes 2 bytes (less than the 4-byte length header),
                # then closes. Server's readexactly(4) should raise
                # IncompleteReadError, which the handler treats as a normal
                # disconnect (closes the writer, no error frame).
                reader, writer = await asyncio.open_unix_connection(
                    str(runtime_paths.socket_path)
                )
                try:
                    writer.write(b"\x00\x00")
                    await writer.drain()
                    writer.close()
                    with pytest.raises((ProtocolError, asyncio.IncompleteReadError)):
                        await asyncio.wait_for(read_message(reader), timeout=2.0)
                finally:
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                    except (ConnectionResetError, BrokenPipeError):
                        pass
            finally:
                await engine.stop()

        asyncio.run(go())

    def test_garbage_json_returns_error_then_disconnects(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                reader, writer = await asyncio.open_unix_connection(
                    str(runtime_paths.socket_path)
                )
                try:
                    payload = b"not json"
                    writer.write(struct.pack(">I", len(payload)) + payload)
                    await writer.drain()
                    # Server replies with an error frame, then closes.
                    header = await reader.readexactly(4)
                    (n,) = struct.unpack(">I", header)
                    raw = await reader.readexactly(n)
                    import json as _json

                    err = _json.loads(raw)
                    assert err["status"] == "error"
                    # The server disconnects the client after a protocol error.
                    with pytest.raises(asyncio.IncompleteReadError):
                        await asyncio.wait_for(reader.readexactly(1), timeout=2.0)
                finally:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                    except (ConnectionResetError, BrokenPipeError):
                        pass
            finally:
                await engine.stop()

        asyncio.run(go())


class TestBadArgs:
    def test_non_object_args_returns_error(self, runtime_paths):
        async def go():
            engine = _start_engine(runtime_paths, _config())
            await engine.start()
            try:
                reader, writer = await asyncio.open_unix_connection(
                    str(runtime_paths.socket_path)
                )
                try:
                    payload = b'{"id":"r","command":"status","args":"not-an-object"}'
                    writer.write(struct.pack(">I", len(payload)) + payload)
                    await writer.drain()
                    header = await reader.readexactly(4)
                    (n,) = struct.unpack(">I", header)
                    raw = await reader.readexactly(n)
                    import json as _json

                    err = _json.loads(raw)
                    assert err["status"] == "error"
                    assert "object" in err["error"].lower()
                finally:
                    writer.close()
                    await writer.wait_closed()
            finally:
                await engine.stop()

        asyncio.run(go())


def _fp(p: Path):
    from antyswirus_lib.types import FileFingerprint

    return FileFingerprint.from_stat(p.stat())
