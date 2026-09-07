"""The receipt a backend returns when a checkpoint statement is published.

A receipt is kept locally so verification can re-check the log's proof *offline*,
without trusting the log to answer honestly at verification time. It is deliberately
serializable to JSON: receipts are the artifact an auditor is handed alongside the
ledger.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import orjson

from memory_blackbox.anchor.base import AnchorError, CheckpointStatement


@dataclass(frozen=True, slots=True)
class AnchorReceipt:
    """Proof material returned by a log for one published statement."""

    backend: str
    log_id: str
    locator: str
    statement: CheckpointStatement
    anchored_at: str
    proof: dict[str, Any] = field(default_factory=dict)

    @property
    def statement_digest(self) -> str:
        """The BLAKE3 digest of the statement this receipt covers."""
        return self.statement.digest()

    def to_json(self) -> str:
        """Serialize the receipt for storage in the ``anchors`` table."""
        return orjson.dumps(
            {
                "backend": self.backend,
                "log_id": self.log_id,
                "locator": self.locator,
                "statement": self.statement.to_dict(),
                "anchored_at": self.anchored_at,
                "proof": self.proof,
            },
            option=orjson.OPT_SORT_KEYS,
        ).decode("utf-8")

    @classmethod
    def from_json(cls, raw: str) -> AnchorReceipt:
        """Parse a receipt previously written by :meth:`to_json`."""
        try:
            data = orjson.loads(raw)
        except orjson.JSONDecodeError as exc:
            raise AnchorError(f"malformed anchor receipt: {exc}") from exc
        if not isinstance(data, dict) or "statement" not in data:
            raise AnchorError("malformed anchor receipt: missing statement")
        statement = CheckpointStatement.from_canonical(
            orjson.dumps(data["statement"], option=orjson.OPT_SORT_KEYS)
        )
        proof = data.get("proof") or {}
        return cls(
            backend=str(data.get("backend", "")),
            log_id=str(data.get("log_id", "")),
            locator=str(data.get("locator", "")),
            statement=statement,
            anchored_at=str(data.get("anchored_at", "")),
            proof=proof if isinstance(proof, dict) else {},
        )
