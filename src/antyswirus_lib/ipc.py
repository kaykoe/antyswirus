"""Wire protocol for the antyswirus client <-> antyswirusd IPC channel.

Transport: Unix stream socket. Each message is a single JSON object
prefixed with a 4-byte big-endian length, which keeps the framing
binary-safe (paths may contain arbitrary bytes) and trivial to parse
on either end.

    [u32 BE length][utf-8 JSON payload]
    [u32 BE length][utf-8 JSON payload]
    ...

Request::

    {"id": "<uuid4>", "command": "scan", "args": {"path": "/home/x"}}

Response::

    {"id": "<uuid4>", "status": "ok"|"error",
     "result": <object>, "error": <string|null>}

Server-pushed events (not currently used; reserved for future
streaming of scan progress) follow the same framing and look like::

    {"event": "scan_progress", "data": {...}}
"""

from __future__ import annotations

import json
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any

_LENGTH_STRUCT = struct.Struct(">I")
_MAX_MESSAGE = 16 * 1024 * 1024  # 16 MiB; refuse anything larger


class ProtocolError(Exception):
    """Raised when the wire protocol is violated (bad framing, oversized, bad JSON)."""


@dataclass(slots=True)
class Request:
    """A client -> daemon request."""

    command: str
    args: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def encode(self) -> bytes:
        payload = json.dumps(
            {"id": self.id, "command": self.command, "args": self.args},
            separators=(",", ":"),
        ).encode("utf-8")
        return _LENGTH_STRUCT.pack(len(payload)) + payload


@dataclass(slots=True)
class Response:
    """A daemon -> client response."""

    id: str
    status: str
    result: Any = None
    error: str | None = None

    def encode(self) -> bytes:
        payload = json.dumps(
            {
                "id": self.id,
                "status": self.status,
                "result": self.result,
                "error": self.error,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        return _LENGTH_STRUCT.pack(len(payload)) + payload


async def read_message(reader) -> dict[str, Any]:
    """Read one framed JSON message from an ``asyncio.StreamReader``."""
    header = await reader.readexactly(_LENGTH_STRUCT.size)
    (length,) = _LENGTH_STRUCT.unpack(header)
    if length == 0 or length > _MAX_MESSAGE:
        raise ProtocolError(f"unreasonable message length: {length}")
    payload = await reader.readexactly(length)
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"bad JSON payload: {exc}") from exc


async def write_message(writer, message: dict[str, Any] | Request | Response) -> None:
    """Encode and write one framed message to an ``asyncio.StreamWriter``."""
    if isinstance(message, (Request, Response)):
        data = message.encode()
    else:
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        data = _LENGTH_STRUCT.pack(len(payload)) + payload
    writer.write(data)
    await writer.drain()
