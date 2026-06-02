"""antyswirus: client CLI for the antyswirus daemon.

Running ``antyswirus`` with no arguments launches the terminal UI
(``antyswirus.tui``). With arguments, the typer subcommand machinery
handles the request as usual.
"""

from __future__ import annotations

import sys

from antyswirus.app import app


def main() -> None:
    if len(sys.argv) <= 1:
        # No subcommand: launch the TUI. We import lazily so that
        # ``antyswirus --help`` and ``antyswirus status`` etc. don't
        # pay the textual import cost.
        from antyswirus.tui import run

        run()
        return
    app()


__all__ = ["app", "main"]
