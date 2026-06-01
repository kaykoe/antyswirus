"""antyswirusd: the antyswirus daemon."""

from antyswirusd.app import app


def main() -> None:
    app()


__all__ = ["app", "main"]
