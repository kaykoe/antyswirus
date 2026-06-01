"""Unix-socket IPC server for client requests.

Implements only the commands that are meaningful with the current
stub modules. Whitelist and quarantine commands are recognised but
return ``not_implemented`` until those modules have real
implementations; adding them is a single ``elif`` branch.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from antyswirus_lib.ipc import (
    ProtocolError,
    Response,
    read_message,
    write_message,
)

if TYPE_CHECKING:
    from antyswirusd.engine import Engine

log = logging.getLogger(__name__)


class IpcServer:
    def __init__(self, socket_path: Path, engine: "Engine") -> None:
        self._socket_path = socket_path
        self._engine = engine
        self._server: asyncio.base_events.Server | None = None

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    async def start(self) -> None:
        self._socket_path.parent.mkdir(parents=True, exist_ok=True)
        self._socket_path.unlink(missing_ok=True)
        self._server = await asyncio.start_unix_server(
            self._handle, path=str(self._socket_path)
        )
        try:
            self._socket_path.chmod(self._engine.config.socket_mode)
        except OSError as exc:
            log.warning("could not chmod socket: %s", exc)
        log.info("IPC server listening on %s", self._socket_path)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        try:
            self._socket_path.unlink(missing_ok=True)
        except OSError:
            pass

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or "?"
        log.debug("client connected: %s", peer)
        try:
            while True:
                try:
                    msg = await read_message(reader)
                except asyncio.IncompleteReadError:
                    break
                except ProtocolError as exc:
                    log.warning("protocol error from %s: %s", peer, exc)
                    await self._write(
                        writer,
                        Response(id="", status="error", error=str(exc)),
                    )
                    break

                request_id = str(msg.get("id", ""))
                command = str(msg.get("command", ""))
                args = msg.get("args") or {}
                if not isinstance(args, dict):
                    await self._write(
                        writer,
                        Response(
                            id=request_id,
                            status="error",
                            error="args must be an object",
                        ),
                    )
                    continue

                response = await self._dispatch(command, args, request_id)
                await self._write(writer, response)
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            log.exception("unhandled error in IPC handler")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
            log.debug("client disconnected: %s", peer)

    async def _dispatch(
        self, command: str, args: dict[str, Any], request_id: str
    ) -> Response:
        try:
            if command == "status":
                st = self._engine.status()
                return Response(
                    id=request_id,
                    status="ok",
                    result={
                        "pid": st.pid,
                        "cache_generation": st.cache_generation,
                        "cache_version": st.cache_version,
                        "queue_size": st.queue_size,
                        "workers": st.workers,
                        "active_scans": st.active_scans,
                    },
                )
            if command == "scan":
                raw = args.get("path")
                if not isinstance(raw, str) or not raw:
                    return Response(
                        id=request_id,
                        status="error",
                        error="missing or invalid 'path' argument",
                    )
                result = await self._engine.scan(Path(raw))
                return Response(id=request_id, status="ok", result=result)
            if command == "stop":
                self._engine.request_shutdown()
                return Response(
                    id=request_id,
                    status="ok",
                    result={"stopping": True},
                )
            if command in (
                "whitelist_add",
                "whitelist_remove",
                "whitelist_list",
                "quarantine_list",
                "quarantine_restore",
                "quarantine_delete",
            ):
                return Response(
                    id=request_id,
                    status="error",
                    error=f"{command} is not implemented yet",
                )
            return Response(
                id=request_id,
                status="error",
                error=f"unknown command: {command!r}",
            )
        except FileNotFoundError as exc:
            return Response(
                id=request_id, status="error", error=f"not found: {exc.args[0]}"
            )
        except Exception as exc:
            log.exception("dispatch failed for command %r", command)
            return Response(id=request_id, status="error", error=str(exc))

    @staticmethod
    async def _write(writer: asyncio.StreamWriter, response: Response) -> None:
        try:
            await write_message(writer, response)
        except (ConnectionResetError, BrokenPipeError):
            pass
