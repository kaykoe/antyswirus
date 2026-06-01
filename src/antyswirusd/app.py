"""Typer app definition for ``antyswirusd``."""

from __future__ import annotations

import typer

from antyswirusd.cli import register

app = typer.Typer(
    name="antyswirusd",
    help="antyswirus daemon: scans the filesystem for malware.",
    no_args_is_help=True,
    add_completion=False,
)

register(app)
