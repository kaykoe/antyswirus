"""Command-line interface for ``antyswirusd``."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path

import typer
from typer import Context

from antyswirusd.config import Config
from antyswirusd.daemon import (
    daemonize,
    is_pid_alive,
    read_pidfile,
    write_pidfile,
)
from antyswirusd.engine import Engine
from antyswirusd.logging_setup import setup_logging
from antyswirusd.paths import RuntimePaths
from antyswirus_lib.client import AntyswirusClient

log = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path("/etc/antyswirus/antyswirusd.toml")


def _paths() -> RuntimePaths:
    return RuntimePaths.default()


def register(app: typer.Typer) -> None:
    app.command()(start)
    app.command()(stop)
    app.command()(status)
    app.command()(scan)
    app.command()(foreground)


def _read_config(config_path: Path | None) -> Config:
    return Config.load(config_path)


def start(
    ctx: Context,
    config: Path = typer.Option(
        DEFAULT_CONFIG_PATH,
        "--config",
        "-c",
        help="Path to antyswirusd.toml. Defaults to /etc/antyswirus/antyswirusd.toml.",
    ),
    foreground: bool = typer.Option(
        False,
        "--foreground",
        "-f",
        help="Run in the foreground instead of daemonising (useful with systemd Type=simple).",
    ),
) -> None:
    """Start the antyswirus daemon."""
    paths = _paths()
    paths.ensure()
    cfg = _read_config(config)

    existing = read_pidfile(paths.pid_path)
    if existing is not None and is_pid_alive(existing):
        typer.echo(f"antyswirusd already running (pid {existing})", err=True)
        raise typer.Exit(code=1)

    if not foreground:
        daemonize(paths.pid_path)
    else:
        write_pidfile(paths.pid_path)

    setup_logging(paths, cfg.log_level)
    log.info("antyswirusd starting (pid %d)", os.getpid())

    asyncio.run(_run(paths, cfg))


async def _run(paths: RuntimePaths, cfg: Config) -> None:
    engine = Engine(paths, cfg)

    loop = asyncio.get_running_loop()

    def _on_signal(signame: str) -> None:
        log.info("received %s; shutting down", signame)
        engine.request_shutdown()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _on_signal, sig.name)

    try:
        await engine.start()
    except Exception:
        log.exception("failed to start engine")
        raise

    try:
        await engine.wait_running()
    finally:
        await engine.stop()
        try:
            paths.pid_path.unlink(missing_ok=True)
        except OSError:
            pass


def stop(ctx: Context) -> None:
    """Stop the antyswirus daemon."""
    paths = _paths()
    pid = read_pidfile(paths.pid_path)
    if pid is None:
        typer.echo("antyswirusd is not running (no pidfile)", err=True)
        raise typer.Exit(code=1)
    if not is_pid_alive(pid):
        typer.echo(f"stale pidfile (pid {pid} not alive); removing", err=True)
        paths.pid_path.unlink(missing_ok=True)
        raise typer.Exit(code=1)
    try:
        os.kill(pid, signal.SIGTERM)
    except PermissionError:
        typer.echo(f"no permission to stop pid {pid}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"sent SIGTERM to antyswirusd (pid {pid})")


def status(ctx: Context) -> None:
    """Print the daemon's status."""
    paths = _paths()
    pid = read_pidfile(paths.pid_path)
    if pid is None or not is_pid_alive(pid):
        typer.echo("antyswirusd is not running")
        raise typer.Exit(code=1)

    async def _query() -> None:
        async with await AntyswirusClient.connect(paths.socket_path) as client:
            resp = await client.call("status")
            if resp.status != "ok":
                typer.echo(f"error: {resp.error}", err=True)
                raise typer.Exit(code=1)
            r = resp.result or {}
            typer.echo(f"pid:               {r.get('pid')}")
            typer.echo(f"cache generation:  {r.get('cache_generation')}")
            typer.echo(f"cache version:     {r.get('cache_version') or '<unset>'}")
            typer.echo(f"workers:           {r.get('workers')}")
            typer.echo(f"queue size:        {r.get('queue_size')}")
            typer.echo(f"active scans:      {r.get('active_scans')}")

    try:
        asyncio.run(_query())
    except (ConnectionRefusedError, FileNotFoundError):
        typer.echo(
            f"antyswirusd pid {pid} is alive but the IPC socket is not reachable",
            err=True,
        )
        raise typer.Exit(code=1)


def scan(
    ctx: Context,
    path: Path = typer.Argument(..., exists=False, help="File or directory to scan."),
) -> None:
    """Request an on-demand scan from a running daemon."""
    paths = _paths()
    pid = read_pidfile(paths.pid_path)
    if pid is None or not is_pid_alive(pid):
        typer.echo("antyswirusd is not running", err=True)
        raise typer.Exit(code=1)

    async def _query() -> None:
        async with await AntyswirusClient.connect(paths.socket_path) as client:
            resp = await client.call("scan", path=str(path))
            if resp.status != "ok":
                typer.echo(f"error: {resp.error}", err=True)
                raise typer.Exit(code=1)
            typer.echo(f"queued: {resp.result}")

    try:
        asyncio.run(_query())
    except (ConnectionRefusedError, FileNotFoundError):
        typer.echo("could not connect to antyswirusd IPC socket", err=True)
        raise typer.Exit(code=1)


def foreground(
    ctx: Context,
    config: Path = typer.Option(
        DEFAULT_CONFIG_PATH,
        "--config",
        "-c",
        help="Path to antyswirusd.toml. Defaults to /etc/antyswirus/antyswirusd.toml.",
    ),
) -> None:
    """Run in the foreground without writing a pidfile.

    Equivalent to ``start --foreground``; useful when running under
    a supervisor that does its own pid management (e.g. systemd
    Type=simple with PIDFile elsewhere).
    """
    ctx.forward(start, foreground=True)
