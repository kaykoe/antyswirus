"""Tests for the antyswirus_lib shared library."""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import uuid
from pathlib import Path

import pytest

from antyswirus_lib import FileFingerprint, ScanResult, Verdict
from antyswirus_lib.ipc import (
    ProtocolError,
    Request,
    Response,
    read_message,
    write_message,
)


def _socketpair() -> tuple[socket.socket, socket.socket]:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    a.setblocking(False)
    b.setblocking(False)
    return a, b


def _async(coro):
    return asyncio.run(coro)


class TestVerdict:
    def test_values_are_stable_strings(self):
        # Wire format must not change silently.
        assert Verdict.UNKNOWN.value == "unknown"
        assert Verdict.SAFE.value == "safe"
        assert Verdict.SUSPICIOUS.value == "suspicious"
        assert Verdict.MALICIOUS.value == "malicious"
        assert Verdict.WHITELISTED.value == "whitelisted"
        assert Verdict.ERROR.value == "error"

    def test_inherits_from_str(self):
        assert Verdict.MALICIOUS == "malicious"


class TestFileFingerprint:
    def test_from_stat_round_trip(self, tmp_path: Path):
        p = tmp_path / "f"
        p.write_text("hello", encoding="utf-8")
        st = p.stat()
        fp = FileFingerprint.from_stat(st)
        assert fp.dev == st.st_dev
        assert fp.inode == st.st_ino
        assert fp.size == st.st_size
        assert fp.mtime_ns == st.st_mtime_ns

    def test_distinguishes_modified_file(self, tmp_path: Path):
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.write_text("one", encoding="utf-8")
        b.write_text("two", encoding="utf-8")
        assert FileFingerprint.from_stat(a.stat()) != FileFingerprint.from_stat(
            b.stat()
        )

    def test_inode_reuse_changes_fingerprint(self, tmp_path: Path):
        p = tmp_path / "x"
        p.write_text("a", encoding="utf-8")
        first = FileFingerprint.from_stat(p.stat())
        st = p.stat()
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5))
        p.write_text("ab", encoding="utf-8")
        second = FileFingerprint.from_stat(p.stat())
        assert first != second


class TestScanResult:
    def test_slots(self, tmp_path: Path):
        p = tmp_path / "evil.bin"
        r = ScanResult(path=p, verdict=Verdict.MALICIOUS, detail="trojan")
        assert r.path == p
        assert r.verdict is Verdict.MALICIOUS
        assert r.detail == "trojan"


class TestIpcFraming:
    def test_request_response_round_trip(self):
        async def go():
            a, b = _socketpair()
            try:
                srv_reader, srv_writer = await asyncio.open_connection(sock=a)
                cli_reader, cli_writer = await asyncio.open_connection(sock=b)
                try:
                    await write_message(cli_writer, Request(command="status", id="r1"))
                    msg = await read_message(srv_reader)
                    assert msg["command"] == "status"
                    assert msg["id"] == "r1"
                    await write_message(
                        srv_writer,
                        Response(id="r1", status="ok", result={"echo": "status"}),
                    )
                    raw = await read_message(cli_reader)
                    assert raw == {
                        "id": "r1",
                        "status": "ok",
                        "result": {"echo": "status"},
                        "error": None,
                    }
                finally:
                    srv_writer.close()
                    cli_writer.close()
                    await srv_writer.wait_closed()
                    await cli_writer.wait_closed()
            finally:
                a.close()
                b.close()

        _async(go())

    def test_oversize_message_rejected(self):
        async def go():
            a, b = _socketpair()
            try:
                srv_reader, srv_writer = await asyncio.open_connection(sock=a)
                cli_writer = (await asyncio.open_connection(sock=b))[1]
                try:
                    # Claim a 100 MiB payload, but send nothing afterwards.
                    cli_writer.write(struct.pack(">I", 100 * 1024 * 1024))
                    await cli_writer.drain()
                    cli_writer.close()
                    await cli_writer.wait_closed()
                    with pytest.raises(ProtocolError):
                        await read_message(srv_reader)
                finally:
                    srv_writer.close()
                    await srv_writer.wait_closed()
            finally:
                a.close()
                b.close()

        _async(go())

    def test_short_header_rejected(self):
        async def go():
            a, b = _socketpair()
            try:
                srv_reader, srv_writer = await asyncio.open_connection(sock=a)
                cli_writer = (await asyncio.open_connection(sock=b))[1]
                try:
                    cli_writer.write(b"\x00\x00")
                    await cli_writer.drain()
                    cli_writer.close()
                    await cli_writer.wait_closed()
                    with pytest.raises((ProtocolError, asyncio.IncompleteReadError)):
                        await read_message(srv_reader)
                finally:
                    srv_writer.close()
                    await srv_writer.wait_closed()
            finally:
                a.close()
                b.close()

        _async(go())


class TestRequestEncoding:
    def test_request_encode_is_length_prefixed(self):
        req = Request(command="scan", args={"path": "/x"})
        data = req.encode()
        (length,) = struct.unpack(">I", data[:4])
        assert length == len(data) - 4

    def test_request_id_is_uuid4_by_default(self):
        req = Request(command="status")
        uuid.UUID(req.id, version=4)  # raises if not a v4 UUID

    def test_request_can_override_id(self):
        req = Request(command="status", id="abc")
        assert req.id == "abc"

    def test_request_args_default_to_empty_dict(self):
        req = Request(command="status")
        assert req.args == {}
