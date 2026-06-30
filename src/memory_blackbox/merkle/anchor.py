"""External root anchoring.

Once a signed Merkle root is published to an external, append-only transparency
log (Rekor-style), even someone who fully controls the host cannot rewrite history
without the discrepancy showing up against the public log -- that is the property
anchoring buys.

**v1 does NOT anchor.** It ships a no-op anchor and relies on the *local* signed
checkpoint. That detects edits, gaps, and tail truncation under an attacker who
cannot forge the signing key, but it does NOT defend against an attacker with full
raw file access who deletes the latest checkpoint(s) and truncates the ledger back
to an earlier checkpoint. Closing that gap requires a real external anchor; the
``Anchor`` protocol is the seam where a Rekor/Sigstore backend plugs in.
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
