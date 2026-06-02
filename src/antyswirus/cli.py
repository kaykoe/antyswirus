"""Command-line interface for the ``antyswirus`` client."""

from __future__ import annotations

import asyncio
import os
import re
import signal
from pathlib import Path

import typer
from typer import Context

from antyswirus_lib.hashing import compute_sha256
from antyswirusd.daemon import is_pid_alive, read_pidfile
from antyswirusd.paths import RuntimePaths
from antyswirus_lib.client import AntyswirusClient

DEFAULT_CONFIG_PATH = Path("/etc/antyswirus/antyswirusd.toml")


def _paths() -> RuntimePaths:
    return RuntimePaths.default()


def register(app: typer.Typer) -> None:
    app.command()(status)
    app.command()(scan)
    app.command()(whitelist_add)
    app.command()(whitelist_remove)
    app.command()(whitelist_list)
    app.command()(quarantine_list)
    app.command()(quarantine_restore)
    app.command()(quarantine_delete)
    app.command()(stop)


async def _call(command: str, **args) -> dict:
    paths = _paths()
    pid = read_pidfile(paths.pid_path)
    if pid is None or not is_pid_alive(pid):
        typer.echo("antyswirusd is not running", err=True)
        raise typer.Exit(code=1)
    try:
        async with await AntyswirusClient.connect(paths.socket_path) as client:
            resp = await client.call(command, **args)
    except (ConnectionRefusedError, FileNotFoundError):
        typer.echo("could not connect to antyswirusd IPC socket", err=True)
        raise typer.Exit(code=1)
    if resp.status != "ok":
        typer.echo(f"error: {resp.error}", err=True)
        raise typer.Exit(code=1)
    return resp.result or {}


_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _resolve_sha256(value: str) -> str:
    """Accept a hex string or a file path. Hash the file in the latter case."""
    if _HEX_RE.match(value):
        return value.lower()
    stripped = value[7:] if value.startswith("sha256:") else value
    if _HEX_RE.match(stripped):
        return stripped.lower()
    p = Path(value)
    if p.is_file():
        return compute_sha256(p)
    raise typer.BadParameter(
        f"{value!r} is neither a 64-char SHA-256 hex string nor an existing file"
    )


def status(ctx: Context) -> None:
    """Show antyswirusd's status."""
    r = asyncio.run(_call("status"))
    typer.echo(f"pid:               {r.get('pid')}")
    typer.echo(f"cache generation:  {r.get('cache_generation')}")
    typer.echo(f"cache version:     {r.get('cache_version') or '<unset>'}")
    typer.echo(f"workers:           {r.get('workers')}")
    typer.echo(f"queue size:        {r.get('queue_size')}")
    typer.echo(f"active scans:      {r.get('active_scans')}")


def scan(
    ctx: Context,
    path: Path = typer.Argument(..., help="File or directory to scan."),
) -> None:
    """Request an on-demand scan."""
    r = asyncio.run(_call("scan", path=str(path)))
    typer.echo(f"queued: {r}")


def whitelist_add(
    ctx: Context,
    kind: str = typer.Option(
        ...,
        "--kind",
        "-k",
        help="Whitelist entry kind: 'path' (absolute directory) or 'sha256'.",
    ),
    value: str = typer.Argument(
        ...,
        help=(
            "For --kind path: absolute directory path. "
            "For --kind sha256: a 64-char hex digest, an optional 'sha256:' prefixed digest, "
            "or a path to a file to hash locally."
        ),
    ),
    note: str | None = typer.Option(
        None, "--note", help="Free-form note attached to the entry."
    ),
) -> None:
    """Whitelist a directory or a content hash."""
    if kind == "sha256":
        resolved = _resolve_sha256(value)
        asyncio.run(_call("whitelist_add", kind=kind, value=resolved, note=note))
        typer.echo(f"whitelisted sha256:{resolved}")
    elif kind == "path":
        p = Path(value)
        if not p.is_absolute():
            raise typer.BadParameter("path entries must be absolute (start with '/')")
        asyncio.run(_call("whitelist_add", kind=kind, value=str(p), note=note))
        typer.echo(f"whitelisted directory {p}")
    else:
        raise typer.BadParameter(
            f"unknown --kind {kind!r}; expected 'path' or 'sha256'"
        )


def whitelist_remove(
    ctx: Context,
    kind: str = typer.Option(
        ..., "--kind", "-k", help="Whitelist entry kind: 'path' or 'sha256'."
    ),
    value: str = typer.Argument(
        ..., help="The directory path or SHA-256 hex string to remove."
    ),
) -> None:
    """Remove a whitelist entry."""
    if kind not in ("path", "sha256"):
        raise typer.BadParameter(
            f"unknown --kind {kind!r}; expected 'path' or 'sha256'"
        )
    if kind == "sha256":
        value = _resolve_sha256(value)
    r = asyncio.run(_call("whitelist_remove", kind=kind, value=value))
    typer.echo(f"removed: {r.get('removed')}")


def whitelist_list(ctx: Context) -> None:
    """List all whitelist entries."""
    r = asyncio.run(_call("whitelist_list"))
    entries = r.get("entries", [])
    if not entries:
        typer.echo("whitelist is empty")
        return
    for e in entries:
        kind = e.get("kind")
        val = e.get("value")
        note = f"  # {e['note']}" if e.get("note") else ""
        typer.echo(f"{kind:6s}  {val}{note}")


def quarantine_list(ctx: Context) -> None:
    """List quarantined files (not yet implemented)."""
    r = asyncio.run(_call("quarantine_list"))
    items = r.get("items", [])
    if not items:
        typer.echo("quarantine is empty")
        return
    for it in items:
        typer.echo(f"{it.get('id')}  {it.get('original_path')}  {it.get('verdict')}")


def quarantine_restore(
    ctx: Context,
    quarantine_id: str = typer.Argument(..., help="Quarantine id to restore."),
    dest: Path = typer.Argument(..., help="Destination path."),
) -> None:
    """Restore a quarantined file to ``dest`` (not yet implemented)."""
    r = asyncio.run(
        _call("quarantine_restore", quarantine_id=quarantine_id, dest=str(dest))
    )
    typer.echo(f"ok: {r}")


def quarantine_delete(
    ctx: Context,
    quarantine_id: str = typer.Argument(..., help="Quarantine id to delete."),
) -> None:
    """Permanently delete a quarantined file (not yet implemented)."""
    r = asyncio.run(_call("quarantine_delete", quarantine_id=quarantine_id))
    typer.echo(f"ok: {r}")


def stop(ctx: Context) -> None:
    """Stop the antyswirus daemon."""
    paths = _paths()
    pid = read_pidfile(paths.pid_path)
    if pid is not None and is_pid_alive(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except PermissionError:
            typer.echo(f"no permission to stop pid {pid}", err=True)
            raise typer.Exit(code=1)
    typer.echo("stop requested")
