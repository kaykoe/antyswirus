"""Stub implementations of the engine's pluggable modules.

These satisfy the Protocols defined in ``antyswirus_lib`` so the
engine can run end-to-end. Each one logs every call at DEBUG and
returns the cheapest answer that lets the pipeline continue. They
are swapped for real implementations in ``engine.Engine.__init__``
when those modules land.
"""

from antyswirusd.modules.hash_repository import StubHashRepository
from antyswirusd.modules.quarantine import Quarantine
from antyswirusd.modules.whitelist import Whitelist

__all__ = ["StubHashRepository", "Quarantine", "Whitelist"]
