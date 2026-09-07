"""Storage for checkpoints and the anchors published for them."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from importlib import resources

from memory_blackbox.anchor.base import Checkpoint
from memory_blackbox.anchor.receipt import AnchorReceipt


def _load_schema() -> str:
    return resources.files("memory_blackbox.anchor").joinpath("schema.sql").read_text()


class AnchorStore:
    """Reads local checkpoints and records the anchors published for them."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._conn.executescript(_load_schema())
        self._conn.commit()

    # -- checkpoints --------------------------------------------------------
    def checkpoints(self) -> list[Checkpoint]:
        """Return every local signed checkpoint, oldest first."""
        cursor = self._conn.cursor()
        cursor.row_factory = sqlite3.Row
        return [
            Checkpoint(
                checkpoint_id=int(row["id"]),
                leaf_count=int(row["leaf_count"]),
                root=row["root"],
                signature=row["signature"],
                signer_kid=row["signer_kid"],
                created_at=row["created_at"],
            )
            for row in cursor.execute("SELECT * FROM merkle_checkpoints ORDER BY id ASC")
        ]

    def latest_checkpoint(self) -> Checkpoint | None:
        """Return the most recent local checkpoint, or None if there is none."""
        checkpoints = self.checkpoints()
        return checkpoints[-1] if checkpoints else None

    # -- anchors ------------------------------------------------------------
    def record(self, checkpoint: Checkpoint, receipt: AnchorReceipt) -> None:
        """Persist ``receipt`` as the anchor for ``checkpoint``.

        Re-publishing an entry that is already recorded is ignored rather than
        raising: anchoring is idempotent from the caller's point of view.
        """
        self._conn.execute(
            """
            INSERT OR IGNORE INTO anchors
              (checkpoint_id, backend, log_id, locator, leaf_count, root,
               statement_hash, receipt_json, anchored_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checkpoint.checkpoint_id,
                receipt.backend,
                receipt.log_id,
                receipt.locator,
                receipt.statement.leaf_count,
                receipt.statement.root,
                receipt.statement_digest,
                receipt.to_json(),
                receipt.anchored_at,
            ),
        )
        self._conn.commit()

    def anchors(self, backend: str | None = None) -> list[AnchorReceipt]:
        """Return the recorded receipts, oldest first, optionally by backend."""
        cursor = self._conn.cursor()
        cursor.row_factory = sqlite3.Row
        if backend is None:
            rows: Iterator[sqlite3.Row] = cursor.execute(
                "SELECT receipt_json FROM anchors ORDER BY id ASC"
            )
        else:
            rows = cursor.execute(
                "SELECT receipt_json FROM anchors WHERE backend = ? ORDER BY id ASC", (backend,)
            )
        return [AnchorReceipt.from_json(row["receipt_json"]) for row in rows]

    def is_anchored(self, statement_hash: str, backend: str) -> bool:
        """Return True iff a statement with this digest is already anchored here."""
        row = self._conn.execute(
            "SELECT 1 FROM anchors WHERE statement_hash = ? AND backend = ? LIMIT 1",
            (statement_hash, backend),
        ).fetchone()
        return row is not None
