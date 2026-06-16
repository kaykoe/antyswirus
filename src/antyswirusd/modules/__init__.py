"""In-memory implementations of the engine's pluggable modules.

They satisfy the Protocols in ``antyswirus_lib`` so the engine can
run end-to-end. Each one logs every call at DEBUG and returns the
cheapest answer that lets the pipeline continue.
"""

from antyswirusd.modules.hash_repository import StubHashRepository

__all__ = ["StubHashRepository"]
