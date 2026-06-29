"""Append-only ledger store (SQLite).

The store is the single writer of the ledger. It is append-only by construction:
there is no update or delete code path, and the schema installs triggers as a
backstop. Each :meth:`append` canonicalizes the record, links it to the previous
row's ``entry_hash``, hashes the link input with BLAKE3, signs the raw digest with
the engine key, and inserts the row. The caller-visible API is synchronous.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

from agent_forensics.crypto.hashing import b3, b3_raw
from agent_forensics.merkle.tree import compute_root
from agent_forensics.model.canonical import canonical_bytes
from agent_forensics.model.records import Kind, LedgerRecord

R = TypeVar("R", bound=LedgerRecord)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from agent_forensics.crypto.keys import KeyPair

# Which record field holds the ledger id, per row kind.
_ID_FIELD: dict[Kind, str] = {
    Kind.write: "record_id",
    Kind.retrieval: "retrieval_id",
    Kind.action: "action_id",
    Kind.rollback: "rollback_id",
}


def _load_schema() -> str:
    return resources.files("agent_forensics.ledger").joinpath("schema.sql").read_text()


class LedgerStore:
    """An append-only, hash-chained ledger backed by SQLite."""

    def __init__(
        self,
        path: Path | str,
        signer: KeyPair,
        *,
        checkpoint_every: int = 1,
    ) -> None:
        self.path = str(path)
        self._signer = signer
        self._checkpoint_every = checkpoint_every
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_load_schema())
        self._conn.commit()
        # In-memory leaf cache for incremental Merkle root computation, loaded
        # from any existing rows so reopening a ledger keeps the tree consistent.
        self._leaves: list[bytes] = [
            row["entry_hash"].encode("utf-8")
            for row in self._conn.execute("SELECT entry_hash FROM ledger ORDER BY seq ASC")
        ]

    # -- write path ---------------------------------------------------------
    def append(self, record: R) -> R:
        """Append ``record`` to the ledger, populating its ledger-set fields."""
        kind = record.kind
        record_id: str = getattr(record, _ID_FIELD[kind])
        namespace = record.namespace

        payload = canonical_bytes(record.model_dump(mode="json"))
        prev_hash = self.last_entry_hash()
        link_input = payload + (prev_hash.encode("utf-8") if prev_hash else b"")
        entry_hash = b3(link_input)
        signature = self._signer.sign(b3_raw(link_input))
        created_at = datetime.now(UTC).isoformat()

        self._conn.execute(
            """
            INSERT INTO ledger
              (record_id, kind, namespace, payload_json, entry_hash, prev_hash,
               signature, signer_kid, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                kind.value,
                namespace,
                payload.decode("utf-8"),
                entry_hash,
                prev_hash,
                signature,
                self._signer.kid,
                created_at,
            ),
        )
        self._conn.commit()

        self._leaves.append(entry_hash.encode("utf-8"))
        if self._checkpoint_every > 0 and len(self._leaves) % self._checkpoint_every == 0:
            self.checkpoint()

        record.entry_hash = entry_hash
        record.prev_hash = prev_hash
        record.signature = signature
        record.signer_kid = self._signer.kid
        return record

    def checkpoint(self) -> str:
        """Write a signed Merkle-root checkpoint over all current rows; return the root."""
        root = compute_root(self._leaves)
        root_hex = "blake3:" + root.hex()
        signature = self._signer.sign(root)
        self._conn.execute(
            """
            INSERT INTO merkle_checkpoints (leaf_count, root, signature, signer_kid, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                len(self._leaves),
                root_hex,
                signature,
                self._signer.kid,
                datetime.now(UTC).isoformat(),
            ),
        )
        self._conn.commit()
        return root_hex

    # -- read path ----------------------------------------------------------
    def last_entry_hash(self) -> str | None:
        row = self._conn.execute(
            "SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["entry_hash"] if row else None

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) AS n FROM ledger").fetchone()["n"])

    def get(self, record_id: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self._conn.execute(
            "SELECT * FROM ledger WHERE record_id = ?", (record_id,)
        ).fetchone()
        return row

    def rows(self) -> Iterator[sqlite3.Row]:
        """Yield all ledger rows in append (``seq``) order."""
        yield from self._conn.execute("SELECT * FROM ledger ORDER BY seq ASC")

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection (read paths and verification)."""
        return self._conn

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._signer.public_key

    def close(self) -> None:
        self._conn.close()
