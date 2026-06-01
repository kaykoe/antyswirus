"""Async client for talking to a running ``antyswirusd`` over its Unix socket."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from antyswirus_lib.ipc import (
    ProtocolError,
    Request,
    Response,
    read_message,
    write_message,
)


class AntyswirusClient:
    """A single connection to the daemon.

    Usage::

        async with AntyswirusClient.connect(socket_path) as client:
            response = await client.call("status")
    """

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._reader = reader
        self._writer = writer

    @classmethod
    async def connect(cls, socket_path: Path | str) -> "AntyswirusClient":
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        return cls(reader, writer)

    async def __aenter__(self) -> "AntyswirusClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass

    async def call(self, command: str, **args: Any) -> Response:
        """Send a request and return the response."""
        request = Request(command=command, args=args)
        await write_message(self._writer, request)
        raw = await read_message(self._reader)
        return _coerce_response(raw)


def _coerce_response(raw: dict[str, Any]) -> Response:
    try:
        return Response(
            id=str(raw["id"]),
            status=str(raw["status"]),
            result=raw.get("result"),
            error=raw.get("error"),
        )
    except KeyError as exc:
        raise ProtocolError(f"malformed response: missing {exc.args[0]!r}") from exc
