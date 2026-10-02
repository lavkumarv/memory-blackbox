"""Append-only ledger store (SQLite).

The store is the single writer of the ledger. It is append-only by construction:
there is no update or delete code path, and the schema installs triggers as a
backstop. Each :meth:`append` canonicalizes the record, links it to the previous
row's ``entry_hash``, hashes the link input with BLAKE3, signs the raw digest with
the engine key, and inserts the row. The caller-visible API is synchronous.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

import orjson

from memory_blackbox.crypto.hashing import b3, b3_raw
from memory_blackbox.merkle.tree import compute_root
from memory_blackbox.model.canonical import canonical_bytes
from memory_blackbox.model.records import Kind, LedgerRecord

R = TypeVar("R", bound=LedgerRecord)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from memory_blackbox.crypto.keys import KeyPair

# Which record field holds the ledger id, per row kind.
_ID_FIELD: dict[Kind, str] = {
    Kind.write: "record_id",
    Kind.retrieval: "retrieval_id",
    Kind.action: "action_id",
    Kind.rollback: "rollback_id",
}


def _load_schema() -> str:
    return resources.files("memory_blackbox.ledger").joinpath("schema.sql").read_text()


# Whitelisted so the value can never become a SQL-injection sink (PRAGMA cannot
# be parameterized, so it is interpolated; only these constants are accepted).
_SYNCHRONOUS_MODES = frozenset({"OFF", "NORMAL", "FULL", "EXTRA"})
_QUERY_BATCH = 500


class LedgerStore:
    """An append-only, hash-chained ledger backed by SQLite."""

    def __init__(
        self,
        path: Path | str,
        signer: KeyPair,
        *,
        checkpoint_every: int = 1,
        synchronous: str = "FULL",
    ) -> None:
        if synchronous.upper() not in _SYNCHRONOUS_MODES:
            raise ValueError(f"invalid synchronous mode: {synchronous!r}")
        self.path = str(path)
        self._signer = signer
        self._checkpoint_every = checkpoint_every
        # Callers such as LangGraph record from worker threads. The connection is
        # shared across threads and every append runs under one lock, so two
        # appends can never read the same prev_hash and fork the chain.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self._conn.row_factory = sqlite3.Row
        # The ledger may contain sensitive memory content; keep it owner-only.
        if self.path != ":memory:" and Path(self.path).exists():
            Path(self.path).chmod(0o600)
        # synchronous=OFF/NORMAL trade durability for throughput on the hot write
        # path (the spec's async-flush budget); FULL is the durable default.
        self._conn.execute(f"PRAGMA synchronous = {synchronous.upper()}")
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
        with self._lock:
            return self._append(record)

    def _append(self, record: R) -> R:
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
        with self._lock:
            return self._checkpoint()

    def _checkpoint(self) -> str:
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
        with self._lock:
            row = self._conn.execute(
                "SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return row["entry_hash"] if row else None

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) AS n FROM ledger").fetchone()["n"])

    def get(self, record_id: str) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._conn.execute(
                "SELECT * FROM ledger WHERE record_id = ?", (record_id,)
            ).fetchone()
        return row

    def last_write(self, namespace: str, memory_id: str) -> tuple[str, str] | None:
        """Return ``(record_id, content_hash)`` of the newest write for ``memory_id``."""
        with self._lock:
            row = self._conn.execute(
                """
            SELECT record_id, json_extract(payload_json, '$.content_hash') AS content_hash
            FROM ledger
            WHERE kind = 'write' AND namespace = ?
              AND json_extract(payload_json, '$.memory_id') = ?
            ORDER BY seq DESC LIMIT 1
            """,
                (namespace, memory_id),
            ).fetchone()
        return (row["record_id"], row["content_hash"]) if row else None

    def last_write_hash(self, namespace: str, memory_id: str) -> str | None:
        """Return the content_hash of the newest write for ``memory_id``, or None."""
        found = self.last_write(namespace, memory_id)
        return found[1] if found else None

    def rows(self) -> Iterator[sqlite3.Row]:
        """Yield all ledger rows in append (``seq``) order."""
        yield from self.query("SELECT * FROM ledger ORDER BY seq ASC")

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> Iterator[sqlite3.Row]:
        """Yield the rows of a read-only ``sql`` query, safe alongside writer threads.

        Rows are fetched in batches under the ledger lock, and the lock is released
        between batches, so a long scan never stalls the write path for its whole run.
        """
        with self._lock:
            cursor = self._conn.execute(sql, params)
        while True:
            with self._lock:
                batch = cursor.fetchmany(_QUERY_BATCH)
            if not batch:
                return
            yield from batch

    def payload(self, record_id: str) -> dict[str, Any] | None:
        """Return the parsed signable payload of a record, or None if absent."""
        row = self.get(record_id)
        if row is None:
            return None
        parsed: dict[str, Any] = orjson.loads(row["payload_json"])
        return parsed

    def iter_payloads(self) -> Iterator[tuple[sqlite3.Row, dict[str, Any]]]:
        """Yield each row paired with its parsed payload, in seq order."""
        for row in self.rows():
            yield row, orjson.loads(row["payload_json"])

    @property
    def lock(self) -> threading.RLock:
        """The lock that serializes use of ``connection`` across threads."""
        return self._lock

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection (read paths and verification)."""
        return self._conn

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._signer.public_key

    def close(self) -> None:
        self._conn.close()
