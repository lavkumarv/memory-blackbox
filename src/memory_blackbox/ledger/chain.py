"""Hash-chain verification.

Walks the ledger in ``seq`` order and, for each row, recomputes the entry hash
from the stored payload and the previous row's hash, checks the chain linkage,
and verifies the signature. The first row that fails any check is reported as the
divergence, classified as an edit, a gap (deletion/reorder), or a forgery.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from memory_blackbox.crypto.hashing import b3, b3_raw
from memory_blackbox.crypto.signing import verify


class DivergenceKind(StrEnum):
    EDIT = "edit"  # payload was modified -> entry_hash no longer matches
    GAP = "gap"  # a row was removed or reordered -> broken prev_hash link
    FORGERY = "forgery"  # signature does not verify against the trusted key


@dataclass(frozen=True, slots=True)
class Divergence:
    """The first point at which the chain failed verification."""

    seq: int
    record_id: str
    kind: DivergenceKind
    detail: str


@dataclass(frozen=True, slots=True)
class ChainReport:
    """Result of a chain verification pass."""

    ok: bool
    rows_checked: int
    divergence: Divergence | None = None


def _link_input(payload_json: str, prev_hash: str | None) -> bytes:
    return payload_json.encode("utf-8") + (prev_hash.encode("utf-8") if prev_hash else b"")


def verify_chain(conn: sqlite3.Connection, public_key: Ed25519PublicKey) -> ChainReport:
    """Verify the hash chain and signatures over all ledger rows."""
    prev_hash: str | None = None
    checked = 0

    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    for row in cursor.execute("SELECT * FROM ledger ORDER BY seq ASC"):
        link = _link_input(row["payload_json"], row["prev_hash"])

        # 1. Edit: recomputed entry hash must match the stored one.
        if b3(link) != row["entry_hash"]:
            return ChainReport(
                ok=False,
                rows_checked=checked,
                divergence=Divergence(
                    seq=row["seq"],
                    record_id=row["record_id"],
                    kind=DivergenceKind.EDIT,
                    detail="recomputed entry_hash does not match stored entry_hash",
                ),
            )

        # 2. Gap: this row's prev_hash must equal the prior row's entry_hash.
        if row["prev_hash"] != prev_hash:
            return ChainReport(
                ok=False,
                rows_checked=checked,
                divergence=Divergence(
                    seq=row["seq"],
                    record_id=row["record_id"],
                    kind=DivergenceKind.GAP,
                    detail="prev_hash does not link to the previous row (row removed or reordered)",
                ),
            )

        # 3. Forgery: signature must verify against the trusted public key.
        if not verify(b3_raw(link), row["signature"], public_key):
            return ChainReport(
                ok=False,
                rows_checked=checked,
                divergence=Divergence(
                    seq=row["seq"],
                    record_id=row["record_id"],
                    kind=DivergenceKind.FORGERY,
                    detail="signature does not verify against the trusted key",
                ),
            )

        prev_hash = row["entry_hash"]
        checked += 1

    return ChainReport(ok=True, rows_checked=checked)
