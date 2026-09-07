"""Append-only file witness.

The simplest backend that actually buys the property: a JSON-lines file that the
process only ever appends to, intended to live somewhere the agent and the ledger
host cannot rewrite -- a WORM bucket, a append-only mount, a log-shipping sink, or
simply another machine.

**Its assurance is exactly the independence of that storage, and no more.** On the
same disk with the same permissions as the ledger it detects nothing an attacker
with raw file access cannot also undo. It is the right choice when you control a
separate append-only sink and cannot reach a public log; :mod:`memory_blackbox.anchor.rekor`
is the right choice when you can.

Each line holds the canonical statement plus the ledger key's signature over it,
so a verifier can reject lines that were fabricated by anyone without that key.
Removing lines still requires write access to the witness -- which is the whole
point of putting it out of reach.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import orjson

from memory_blackbox.anchor.base import AnchorError, CheckpointStatement, Witness
from memory_blackbox.anchor.receipt import AnchorReceipt
from memory_blackbox.crypto.hashing import b3, b3_raw
from memory_blackbox.crypto.signing import verify

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from memory_blackbox.crypto.keys import KeyPair

BACKEND_NAME = "file-witness"
_LINE_VERSION = 1


class FileWitnessAnchor:
    """Anchors checkpoint statements to an append-only JSON-lines file."""

    name = BACKEND_NAME

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    @property
    def log_id(self) -> str:
        """A stable identity for this witness file (its resolved path, hashed)."""
        return b3(str(self.path.resolve()).encode("utf-8"))

    # -- publish ------------------------------------------------------------
    def publish(self, statement: CheckpointStatement, signer: KeyPair) -> AnchorReceipt:
        """Append a signed statement line and return its receipt."""
        canonical = statement.canonical()
        signature = signer.sign(b3_raw(canonical))
        anchored_at = datetime.now(UTC).isoformat()
        line = {
            "version": _LINE_VERSION,
            "statement": statement.to_dict(),
            "witness_signature": signature,
            "signer_kid": signer.kid,
            "anchored_at": anchored_at,
        }
        payload = orjson.dumps(line, option=orjson.OPT_SORT_KEYS) + b"\n"

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_APPEND so concurrent writers cannot interleave or overwrite, and so the
        # file is only ever grown by this code path.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)  # a witness that was never durable witnesses nothing
        finally:
            os.close(fd)

        return AnchorReceipt(
            backend=self.name,
            log_id=self.log_id,
            locator=statement.digest(),
            statement=statement,
            anchored_at=anchored_at,
            proof={"witness_signature": signature, "path": str(self.path)},
        )

    # -- read back ----------------------------------------------------------
    def witnesses(self, ledger_identity: str, public_key: Ed25519PublicKey) -> list[Witness]:
        """Return every validly signed witness this file holds for the ledger."""
        return [
            Witness(
                backend=self.name,
                log_id=self.log_id,
                locator=statement.digest(),
                fingerprint=statement.digest(),
                statement=statement,
                integrated_at=str(line.get("anchored_at") or "") or None,
            )
            for line, statement in self._valid_lines(public_key)
            if statement.ledger_id == ledger_identity
        ]

    def fingerprint(self, statement: CheckpointStatement) -> str:
        """The witness file keys statements by their BLAKE3 digest."""
        return statement.digest()

    def verify_receipt(self, receipt: AnchorReceipt) -> tuple[bool, str]:
        """Re-check that the witness file still contains this receipt's statement."""
        signature = receipt.proof.get("witness_signature")
        if not isinstance(signature, str):
            return False, "receipt carries no witness signature"
        digest = receipt.statement_digest
        for _, statement in self._valid_lines_unchecked():
            if statement.digest() == digest:
                return True, "statement present in the witness file"
        return False, f"statement {digest} is absent from {self.path}"

    # -- internals ----------------------------------------------------------
    def _read_lines(self) -> list[dict[str, Any]]:
        """Parse the witness file one line at a time.

        A witness that has been appended to for months can be large, and it is read
        on every verification, so it is streamed rather than slurped.
        """
        if not self.path.exists():
            return []
        lines: list[dict[str, Any]] = []
        with self.path.open(encoding="utf-8") as handle:
            for number, raw in enumerate(handle, start=1):
                if not raw.strip():
                    continue
                try:
                    parsed = orjson.loads(raw)
                except orjson.JSONDecodeError as exc:
                    raise AnchorError(
                        f"corrupt witness line {number} in {self.path}: {exc}"
                    ) from exc
                if isinstance(parsed, dict):
                    lines.append(parsed)
        return lines

    def _valid_lines_unchecked(self) -> list[tuple[dict[str, Any], CheckpointStatement]]:
        """Parse statements without checking signatures (presence checks only)."""
        out: list[tuple[dict[str, Any], CheckpointStatement]] = []
        for line in self._read_lines():
            statement_obj = line.get("statement")
            if not isinstance(statement_obj, dict):
                continue
            raw = orjson.dumps(statement_obj, option=orjson.OPT_SORT_KEYS)
            out.append((line, CheckpointStatement.from_canonical(raw)))
        return out

    def _valid_lines(
        self, public_key: Ed25519PublicKey
    ) -> list[tuple[dict[str, Any], CheckpointStatement]]:
        """Parse statements and drop any whose witness signature does not verify.

        A forged line would otherwise let an attacker who *can* write to the witness
        manufacture a longer history than the ledger ever had, turning a rollback
        check into a false alarm. Unsigned or badly signed lines are simply not
        witnesses.
        """
        return [
            (line, statement)
            for line, statement in self._valid_lines_unchecked()
            if isinstance(line.get("witness_signature"), str)
            and verify(b3_raw(statement.canonical()), str(line["witness_signature"]), public_key)
        ]
