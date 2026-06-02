"""Async facade over the antyswirus IPC channel, used by the TUI.

The TUI never touches the IPC layer directly. Instead it depends on
a small set of coroutines defined here. The real implementation
(``IpcClient``) connects to the daemon over its Unix socket. Tests
can substitute a ``FakeClient`` to drive the screens in-process.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Protocol

from antyswirus_lib.client import AntyswirusClient
from antyswirusd.paths import RuntimePaths


@dataclass(slots=True, frozen=True)
class QuarantineItem:
    """A single row in the quarantine list, as the TUI sees it."""

    id: str
    original_path: str
    quarantined_at: float
    verdict: str
    detail: str | None = None


@dataclass(slots=True, frozen=True)
class StatusSnapshot:
    """The bits of the ``status`` IPC response the TUI displays."""

    pid: int = 0
    cache_generation: int = 0
    cache_version: str = ""
    queue_size: int = 0
    workers: int = 0
    active_scans: int = 0
    pending_rescans: int = 0
    last_scan_at: float | None = None
    quarantine_count: int = 0


class StatusProvider(Protocol):
    """The subset of operations the TUI needs.

    Exposed as a ``Protocol`` so the test suite can substitute a
    fake without touching the socket layer.
    """

    async def get_status(self) -> StatusSnapshot: ...
    async def list_quarantine(self) -> list[QuarantineItem]: ...
    async def scan(self, path: str) -> None: ...
    async def restore(self, quarantine_id: str, dest: str) -> None: ...
    async def delete(self, quarantine_id: str) -> None: ...
    async def stop_daemon(self) -> None: ...
    async def close(self) -> None: ...


class IpcClient:
    """``StatusProvider`` that talks to a running ``antyswirusd`` over its socket."""

    def __init__(self, paths: RuntimePaths) -> None:
        self._paths = paths
        self._lock = asyncio.Lock()
        self._conn: AntyswirusClient | None = None

    async def _connect(self) -> AntyswirusClient:
        if self._conn is not None:
            return self._conn
        # Serialise connection establishment so two concurrent
        # callers don't both try to open the socket.
        async with self._lock:
            if self._conn is None:
                self._conn = await AntyswirusClient.connect(self._paths.socket_path)
        return self._conn

    async def _call(self, command: str, **args) -> dict:
        try:
            conn = await self._connect()
            resp = await conn.call(command, **args)
        except (ConnectionRefusedError, FileNotFoundError, OSError):
            # Drop the cached connection so the next call retries.
            self._conn = None
            raise
        if resp.status != "ok":
            raise RuntimeError(resp.error or f"{command} failed")
        return resp.result or {}

    async def get_status(self) -> StatusSnapshot:
        r = await self._call("status")
        return StatusSnapshot(
            pid=int(r.get("pid", 0)),
            cache_generation=int(r.get("cache_generation", 0)),
            cache_version=str(r.get("cache_version", "") or ""),
            queue_size=int(r.get("queue_size", 0)),
            workers=int(r.get("workers", 0)),
            active_scans=int(r.get("active_scans", 0)),
            pending_rescans=int(r.get("pending_rescans", 0)),
            last_scan_at=r.get("last_scan_at"),
            quarantine_count=int(r.get("quarantine_count", 0)),
        )

    async def list_quarantine(self) -> list[QuarantineItem]:
        r = await self._call("quarantine_list")
        return [
            QuarantineItem(
                id=item["id"],
                original_path=item.get("original_path", ""),
                quarantined_at=float(item.get("quarantined_at", 0.0)),
                verdict=str(item.get("verdict", "")),
                detail=item.get("detail"),
            )
            for item in r.get("items", [])
        ]

    async def scan(self, path: str) -> None:
        await self._call("scan", path=path)

    async def restore(self, quarantine_id: str, dest: str) -> None:
        await self._call("quarantine_restore", quarantine_id=quarantine_id, dest=dest)

    async def delete(self, quarantine_id: str) -> None:
        await self._call("quarantine_delete", quarantine_id=quarantine_id)

    async def stop_daemon(self) -> None:
        await self._call("stop")

    async def close(self) -> None:
        if self._conn is None:
            return
        conn, self._conn = self._conn, None
        try:
            await conn.close()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass


@dataclass(slots=True)
class FakeClient:
    """An in-memory ``StatusProvider`` for tests and previews.

    The TUI is decoupled from the IPC layer, so unit tests can drive
    the screens with a FakeClient that returns canned values and
    records every call. ``fail_with`` lets a test simulate a
    daemon-down condition (e.g. ``RuntimeError("not running")``) on
    the next call.
    """

    statuses: list[StatusSnapshot] = field(default_factory=list)
    items: list[QuarantineItem] = field(default_factory=list)
    calls: list[tuple[str, tuple, dict]] = field(default_factory=list)
    fail_with: Exception | None = None

    async def get_status(self) -> StatusSnapshot:
        self.calls.append(("get_status", (), {}))
        if self.fail_with is not None:
            raise self.fail_with
        if self.statuses:
            return self.statuses.pop(0)
        return StatusSnapshot()

    async def list_quarantine(self) -> list[QuarantineItem]:
        self.calls.append(("list_quarantine", (), {}))
        if self.fail_with is not None:
            raise self.fail_with
        return list(self.items)

    async def scan(self, path: str) -> None:
        self.calls.append(("scan", (), {"path": path}))
        if self.fail_with is not None:
            raise self.fail_with

    async def restore(self, quarantine_id: str, dest: str) -> None:
        self.calls.append(
            ("restore", (), {"quarantine_id": quarantine_id, "dest": dest})
        )
        if self.fail_with is not None:
            raise self.fail_with

    async def delete(self, quarantine_id: str) -> None:
        self.calls.append(("delete", (), {"quarantine_id": quarantine_id}))
        if self.fail_with is not None:
            raise self.fail_with

    async def stop_daemon(self) -> None:
        self.calls.append(("stop_daemon", (), {}))
        if self.fail_with is not None:
            raise self.fail_with

    async def close(self) -> None:
        self.calls.append(("close", (), {}))


def make_default_client() -> IpcClient:
    """Build a real ``IpcClient`` for production use."""
    return IpcClient(RuntimePaths.default())


__all__ = [
    "FakeClient",
    "IpcClient",
    "QuarantineItem",
    "StatusProvider",
    "StatusSnapshot",
    "make_default_client",
]
