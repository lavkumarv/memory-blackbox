"""Integrity verification: chain + Merkle + signatures + external anchors.

Aggregates three independent checks into a single report, each catching what the
one before it cannot:

1. **Hash chain** -- no edits, no gaps, valid signatures.
2. **Merkle checkpoint** -- no deletions, including tail truncation, *relative to
   the newest checkpoint still present locally*.
3. **External anchors** (optional) -- no rollback to an earlier checkpoint, which
   is precisely the case (2) cannot see, because the attacker deletes the recent
   checkpoints along with the rows.

Only the first two run by default. The third needs an anchoring backend, so it
runs when one is passed; without it the report says the check was skipped rather
than implying it passed. This is what the CLI ``verify`` command exits nonzero on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from memory_blackbox.anchor.verify import AnchorReport, verify_anchors
from memory_blackbox.ledger.chain import ChainReport, verify_chain
from memory_blackbox.merkle.tree import MerkleReport, verify_merkle

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from memory_blackbox.anchor.base import Anchor
    from memory_blackbox.ledger.store import LedgerStore


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    """Combined ledger integrity result."""

    ok: bool
    chain: ChainReport
    merkle: MerkleReport
    anchor: AnchorReport | None = None

    @property
    def summary(self) -> str:
        if not self.chain.ok and self.chain.divergence is not None:
            d = self.chain.divergence
            return f"chain {d.kind} at seq {d.seq} ({d.record_id}): {d.detail}"
        if not self.merkle.ok:
            return f"merkle: {self.merkle.detail}"
        if self.anchor is not None and not self.anchor.ok:
            return self.anchor.summary
        anchored = (
            f", {self.anchor.witness_count} external witness(es) verified"
            if self.anchor is not None
            else ", external anchors not checked"
        )
        return f"ok: {self.chain.rows_checked} rows verified, no tampering detected{anchored}"


def verify(
    ledger: LedgerStore,
    public_key: Ed25519PublicKey | None = None,
    *,
    anchor: Anchor | None = None,
    require_witness: bool = True,
) -> IntegrityReport:
    """Verify the full integrity of ``ledger``.

    Pass ``anchor`` to additionally cross-check the ledger against the external
    log it publishes to. ``require_witness`` decides whether an anchored-by-config
    but never-actually-published ledger is a failure; it defaults to True so a
    silently broken anchoring pipeline does not read as a clean bill of health.
    """
    key = public_key if public_key is not None else ledger.public_key
    chain = verify_chain(ledger.connection, key)
    merkle = verify_merkle(ledger.connection, key)
    anchor_report = (
        verify_anchors(ledger, anchor, require_witness=require_witness)
        if anchor is not None
        else None
    )
    ok = chain.ok and merkle.ok and (anchor_report is None or anchor_report.ok)
    return IntegrityReport(ok=ok, chain=chain, merkle=merkle, anchor=anchor_report)
