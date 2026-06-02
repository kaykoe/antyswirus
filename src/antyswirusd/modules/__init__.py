"""Default implementations of the engine's pluggable modules.

They satisfy the Protocols in ``antyswirus_lib`` so the engine can
run end-to-end. The hash repository is still a stub; the quarantine
is now a SQLite-backed implementation that persists across restarts.
"""

from antyswirusd.modules.hash_repository import StubHashRepository
from antyswirusd.modules.quarantine import PersistentQuarantine, StubQuarantine

__all__ = ["PersistentQuarantine", "StubHashRepository", "StubQuarantine"]
