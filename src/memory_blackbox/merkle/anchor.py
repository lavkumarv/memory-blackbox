"""Compatibility shim -- anchoring now lives in :mod:`memory_blackbox.anchor`.

Anchoring outgrew a single module once it gained real backends, a receipt store,
and its own verification pass, so it moved to a package of its own. This module
re-exports the two names that existed here in 0.1.0 so old imports keep working.

Note that ``Anchor`` is not the same protocol it was in 0.1.0. The old
``publish(root_hex, leaf_count) -> str | None`` was a placeholder that could not
express a receipt, and nothing implemented it beyond the no-op. The current
protocol is documented in :mod:`memory_blackbox.anchor.base`.
"""

from __future__ import annotations

from memory_blackbox.anchor.base import Anchor, NoOpAnchor

__all__ = ["Anchor", "NoOpAnchor"]
