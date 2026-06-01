"""Typer app definition for the ``antyswirus`` client CLI."""

from __future__ import annotations

import typer

from antyswirus.cli import register

app = typer.Typer(
    name="antyswirus",
    help="antyswirus: control a running antyswirusd.",
    no_args_is_help=True,
    add_completion=False,
)

register(app)
