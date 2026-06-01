"""Command-line interface for the ``antyswirus`` client."""

from __future__ import annotations

import asyncio
import os
import signal
from pathlib import Path

import typer
from typer import Context

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
    pattern: str = typer.Argument(..., help="Glob pattern to whitelist."),
) -> None:
    """Whitelist a path pattern (not yet implemented)."""
    r = asyncio.run(_call("whitelist_add", pattern=pattern))
    typer.echo(f"ok: {r}")


def whitelist_remove(
    ctx: Context,
    pattern: str = typer.Argument(
        ..., help="Glob pattern to remove from the whitelist."
    ),
) -> None:
    """Remove a pattern from the whitelist (not yet implemented)."""
    r = asyncio.run(_call("whitelist_remove", pattern=pattern))
    typer.echo(f"ok: {r}")


def whitelist_list(ctx: Context) -> None:
    """List whitelisted patterns (not yet implemented)."""
    r = asyncio.run(_call("whitelist_list"))
    typer.echo(f"patterns: {r.get('patterns', [])}")


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
