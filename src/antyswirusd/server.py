"""Unix-socket IPC server for client requests.

The server tracks every in-flight handler task so that
:meth:`stop` can wait for them to complete before returning. A
``whitelist_remove`` handler is fire-and-forget from the caller's
point of view (it returns once the rescan is scheduled), so the
tracked task completes quickly. The actual rescan work is owned by
:attr:`Engine.rescan_tasks` and drained by :meth:`Engine.stop`.
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
from antyswirus_lib.types import WhitelistEntry, WhitelistKind

if TYPE_CHECKING:
    from antyswirusd.engine import Engine

log = logging.getLogger(__name__)


class IpcServer:
    def __init__(self, socket_path: Path, engine: "Engine") -> None:
        self._socket_path = socket_path
        self._engine = engine
        self._server: asyncio.base_events.Server | None = None
        self._active_handlers: set[asyncio.Task[None]] = set()

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
        # 1. Stop accepting new connections.
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # 2. Wait for in-flight handlers to complete.
        if self._active_handlers:
            await asyncio.gather(*self._active_handlers, return_exceptions=True)
        self._active_handlers.clear()
        # 3. Remove the socket file.
        try:
            self._socket_path.unlink(missing_ok=True)
        except OSError:
            pass

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._active_handlers.add(task)
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
            if task is not None:
                self._active_handlers.discard(task)
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
                        "pending_rescans": st.pending_rescans,
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
            if command == "whitelist_add":
                return await self._whitelist_add(request_id, args)
            if command == "whitelist_remove":
                return await self._whitelist_remove(request_id, args)
            if command == "whitelist_list":
                return await self._whitelist_list(request_id)
            if command == "quarantine_list":
                return await self._quarantine_list(request_id, args)
            if command == "quarantine_restore":
                return await self._quarantine_restore(request_id, args)
            if command == "quarantine_delete":
                return await self._quarantine_delete(request_id, args)
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

    def _parse_entry(self, args: dict[str, Any]) -> Response | WhitelistEntry:
        kind_raw = args.get("kind")
        value = args.get("value")
        if not isinstance(kind_raw, str) or not isinstance(value, str) or not value:
            return Response(
                id="",
                status="error",
                error="both 'kind' and 'value' are required and must be non-empty strings",
            )
        try:
            kind = WhitelistKind(kind_raw)
        except ValueError:
            return Response(
                id="",
                status="error",
                error=f"unknown kind {kind_raw!r}; expected one of: path, sha256",
            )
        if kind is WhitelistKind.PATH and not value.startswith("/"):
            return Response(
                id="",
                status="error",
                error="path entries must be absolute (start with '/')",
            )
        if kind is WhitelistKind.SHA256 and len(value) != 64:
            return Response(
                id="",
                status="error",
                error="sha256 entries must be 64 hex characters",
            )
        note = args.get("note")
        if note is not None and not isinstance(note, str):
            return Response(
                id="",
                status="error",
                error="'note' must be a string if provided",
            )
        return WhitelistEntry(kind=kind, value=value, note=note)

    async def _whitelist_add(self, request_id: str, args: dict[str, Any]) -> Response:
        parsed = self._parse_entry(args)
        if isinstance(parsed, Response):
            return Response(id=request_id, status=parsed.status, error=parsed.error)
        await self._engine.whitelist.add(parsed)
        return Response(
            id=request_id,
            status="ok",
            result={"added": {"kind": parsed.kind.value, "value": parsed.value}},
        )

    async def _whitelist_remove(
        self, request_id: str, args: dict[str, Any]
    ) -> Response:
        parsed = self._parse_entry(args)
        if isinstance(parsed, Response):
            return Response(id=request_id, status=parsed.status, error=parsed.error)
        # Fire-and-forget: the engine schedules a rescan task that runs
        # in the background. Engine.stop() waits for the rescan set to
        # drain so we never exit the daemon with a pending rescan.
        removed = await self._engine.whitelist.remove(parsed)
        if removed:
            self._engine.schedule_rescan(parsed)
        return Response(
            id=request_id,
            status="ok",
            result={
                "removed": {"kind": parsed.kind.value, "value": parsed.value},
                "rescan_scheduled": removed,
            },
        )

    async def _whitelist_list(self, request_id: str) -> Response:
        entries = await self._engine.whitelist.list()
        return Response(
            id=request_id,
            status="ok",
            result={
                "entries": [
                    {
                        "kind": e.kind.value,
                        "value": e.value,
                        "added_at": e.added_at,
                        "note": e.note,
                    }
                    for e in entries
                ]
            },
        )

    @staticmethod
    async def _write(writer: asyncio.StreamWriter, response: Response) -> None:
        try:
            await write_message(writer, response)
        except (ConnectionResetError, BrokenPipeError):
            pass

    # ------------------------------------------------------------------ #
    # Quarantine handlers                                                #
    # ------------------------------------------------------------------ #

    def _coerce_pagination(self, args: dict[str, Any]) -> tuple[int, int] | Response:
        offset = args.get("offset", 0)
        limit = args.get("limit", 100)
        if not isinstance(offset, int) or isinstance(offset, bool):
            return Response(id="", status="error", error="'offset' must be an integer")
        if not isinstance(limit, int) or isinstance(limit, bool):
            return Response(id="", status="error", error="'limit' must be an integer")
        return offset, limit

    def _coerce_qid(self, args: dict[str, Any], request_id: str) -> str | Response:
        qid = args.get("id")
        if not isinstance(qid, str) or not qid:
            return Response(
                id=request_id,
                status="error",
                error="missing or invalid 'id' argument",
            )
        return qid

    async def _quarantine_list(self, request_id: str, args: dict[str, Any]) -> Response:
        coerced = self._coerce_pagination(args)
        if isinstance(coerced, Response):
            return Response(id=request_id, status=coerced.status, error=coerced.error)
        offset, limit = coerced
        items = await self._engine.quarantine.list(offset=offset, limit=limit)
        total = (
            await self._engine.quarantine.count()
            if hasattr(self._engine.quarantine, "count")
            else None
        )
        result: dict[str, Any] = {
            "items": [
                {
                    "id": e.id,
                    "original_path": str(e.original_path),
                    "quarantined_at": e.quarantined_at,
                    "verdict": e.verdict.value,
                    "detail": e.detail,
                }
                for e in items
            ],
            "offset": offset,
            "limit": limit,
        }
        if total is not None:
            result["total"] = total
        return Response(id=request_id, status="ok", result=result)

    async def _quarantine_restore(
        self, request_id: str, args: dict[str, Any]
    ) -> Response:
        qid = self._coerce_qid(args, request_id)
        if isinstance(qid, Response):
            return qid
        try:
            await self._engine.quarantine.restore(qid)
        except KeyError:
            return Response(
                id=request_id,
                status="error",
                error=f"no such quarantine id: {qid}",
            )
        except FileExistsError as exc:
            dest = exc.args[0] if exc.args else "<unknown>"
            return Response(
                id=request_id,
                status="error",
                error=f"destination already exists: {dest}",
            )
        return Response(
            id=request_id,
            status="ok",
            result={"restored": qid},
        )

    async def _quarantine_delete(
        self, request_id: str, args: dict[str, Any]
    ) -> Response:
        qid = self._coerce_qid(args, request_id)
        if isinstance(qid, Response):
            return qid
        try:
            await self._engine.quarantine.delete(qid)
        except KeyError:
            return Response(
                id=request_id,
                status="error",
                error=f"no such quarantine id: {qid}",
            )
        return Response(
            id=request_id,
            status="ok",
            result={"deleted": qid},
        )
