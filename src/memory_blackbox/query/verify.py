"""Integrity verification: chain + Merkle + signatures.

Aggregates the hash-chain check (no edits, no gaps, valid signatures) and the
Merkle-checkpoint check (no deletions, including tail truncation) into a single
report. This is what the CLI ``verify`` command exits nonzero on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from memory_blackbox.ledger.chain import ChainReport, verify_chain
from memory_blackbox.merkle.tree import MerkleReport, verify_merkle

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from memory_blackbox.ledger.store import LedgerStore


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    """Combined ledger integrity result."""

    ok: bool
    chain: ChainReport
    merkle: MerkleReport

    @property
    def summary(self) -> str:
        if self.ok:
            return f"ok: {self.chain.rows_checked} rows verified, no tampering detected"
        if not self.chain.ok and self.chain.divergence is not None:
            d = self.chain.divergence
            return f"chain {d.kind} at seq {d.seq} ({d.record_id}): {d.detail}"
        return f"merkle: {self.merkle.detail}"


def verify(ledger: LedgerStore, public_key: Ed25519PublicKey | None = None) -> IntegrityReport:
    """Verify the full integrity of ``ledger``."""
    key = public_key if public_key is not None else ledger.public_key
    chain = verify_chain(ledger.connection, key)
    merkle = verify_merkle(ledger.connection, key)
    return IntegrityReport(ok=chain.ok and merkle.ok, chain=chain, merkle=merkle)
