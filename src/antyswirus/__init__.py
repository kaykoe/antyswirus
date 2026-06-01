"""antyswirus: client CLI for the antyswirusd daemon."""

from antyswirus.app import app


def main() -> None:
    app()


__all__ = ["app", "main"]
