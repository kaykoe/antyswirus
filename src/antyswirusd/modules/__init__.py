"""Stub implementations of the engine's pluggable modules.

These satisfy the Protocols defined in ``antyswirus_lib`` so the
engine can run end-to-end. Each one logs every call at DEBUG and
returns the cheapest answer that lets the pipeline continue. They
are swapped for real implementations in ``engine.Engine.__init__``
when those modules land.

Note: there is no whitelist stub — the engine uses the real
``WhitelistDb`` directly. A list/dict-based in-memory test double
lives in the test suite.
"""

from antyswirusd.modules.hash_repository import StubHashRepository
from antyswirusd.modules.quarantine import StubQuarantine

__all__ = ["StubHashRepository", "StubQuarantine"]
