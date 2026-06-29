"""External root anchoring.

Publishing a signed Merkle root to an external, append-only transparency log
(Rekor-style) gives third-party verifiability: even someone who fully controls the
host cannot rewrite history without the discrepancy showing up against the public
log. v1 ships a no-op anchor and relies on the local signed checkpoint; the
``Anchor`` protocol is the seam where a Rekor/Sigstore backend plugs in later.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Anchor(Protocol):
    """Publishes a signed Merkle root to an external transparency log."""

    def publish(self, root_hex: str, leaf_count: int) -> str | None:
        """Publish ``root_hex``; return an external receipt/locator, or ``None``."""
        ...


class NoOpAnchor:
    """Local-only anchor: records nothing externally (the v1 default).

    The signed checkpoint in the local ledger remains the source of truth. Swap in
    a real transparency-log anchor without changing any caller.
    """

    def publish(self, root_hex: str, leaf_count: int) -> str | None:
        return None
