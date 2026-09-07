"""Core anchoring types: what gets published, and the backend seam.

The unit of publication is a :class:`CheckpointStatement` -- a small, canonical
claim of the form *"ledger L, signed by key K, had Merkle root R at length N"*.
It carries **only hashes and counts**: no memory content, no queries, no key
material. That matters because the destination is a public log.

A statement is bound to a ledger by :func:`ledger_id`, which is derived from the
genesis entry hash and the signer kid. Both are fixed the moment the first row is
appended, so the identity is stable for the life of the ledger and cannot be
re-pointed at a different history without changing the id.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import orjson

from memory_blackbox.crypto.hashing import b3
from memory_blackbox.model.canonical import canonical_bytes

if TYPE_CHECKING:
    import sqlite3

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from memory_blackbox.anchor.receipt import AnchorReceipt
    from memory_blackbox.crypto.keys import KeyPair

# Versioned so a verifier can reject statement shapes it does not understand.
ANCHOR_STATEMENT_TYPE = "memory-blackbox.checkpoint/v1"


class AnchorError(RuntimeError):
    """Raised when an anchoring backend cannot publish or read witnesses."""


def ledger_id(conn: sqlite3.Connection) -> str | None:
    """Return the stable identity of the ledger on ``conn``, or None if empty.

    Derived from the genesis row's ``entry_hash`` and ``signer_kid``. A ledger
    that was rebuilt from scratch has a different genesis and therefore a
    different id, which is what makes "no witnesses for my id" a tamper signal
    rather than an ambiguity.
    """
    cursor = conn.execute("SELECT entry_hash, signer_kid FROM ledger ORDER BY seq ASC LIMIT 1")
    row = cursor.fetchone()
    if row is None:
        return None
    entry_hash, signer_kid = row[0], row[1]
    return b3(f"{entry_hash}|{signer_kid}".encode())


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A locally stored signed Merkle checkpoint."""

    checkpoint_id: int
    leaf_count: int
    root: str  # "blake3:<hex>"
    signature: str  # "ed25519:<hex>" over the raw root bytes
    signer_kid: str
    created_at: str


@dataclass(frozen=True, slots=True)
class CheckpointStatement:
    """The canonical, publishable claim about one checkpoint.

    Two statements are the same iff their canonical bytes are identical, so the
    digest is a complete fingerprint of the claim. This is what backends publish
    and what verification matches log entries against.
    """

    ledger_id: str
    signer_kid: str
    leaf_count: int
    root: str
    checkpoint_signature: str
    created_at: str

    @classmethod
    def build(cls, checkpoint: Checkpoint, ledger_identity: str) -> CheckpointStatement:
        """Build the statement for ``checkpoint`` under ``ledger_identity``."""
        return cls(
            ledger_id=ledger_identity,
            signer_kid=checkpoint.signer_kid,
            leaf_count=checkpoint.leaf_count,
            root=checkpoint.root,
            checkpoint_signature=checkpoint.signature,
            created_at=checkpoint.created_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the statement as a plain dict, including its type tag."""
        return {
            "type": ANCHOR_STATEMENT_TYPE,
            "ledger_id": self.ledger_id,
            "signer_kid": self.signer_kid,
            "leaf_count": self.leaf_count,
            "root": self.root,
            "checkpoint_signature": self.checkpoint_signature,
            "created_at": self.created_at,
        }

    def canonical(self) -> bytes:
        """Return the deterministic bytes that get published and signed."""
        # exclude=frozenset(): nothing is pruned -- a statement has no ledger-set
        # fields, and silently dropping a key would change the published claim.
        return canonical_bytes(self.to_dict(), exclude=frozenset())

    def digest(self) -> str:
        """Return the BLAKE3 digest of the canonical bytes (``blake3:<hex>``)."""
        return b3(self.canonical())

    @classmethod
    def from_canonical(cls, raw: bytes) -> CheckpointStatement:
        """Parse canonical statement bytes, rejecting unknown statement types."""
        try:
            data = orjson.loads(raw)
        except orjson.JSONDecodeError as exc:
            raise AnchorError(f"malformed checkpoint statement: {exc}") from exc
        if not isinstance(data, dict):
            raise AnchorError("malformed checkpoint statement: not a JSON object")
        if data.get("type") != ANCHOR_STATEMENT_TYPE:
            raise AnchorError(f"unknown checkpoint statement type: {data.get('type')!r}")
        try:
            return cls(
                ledger_id=str(data["ledger_id"]),
                signer_kid=str(data["signer_kid"]),
                leaf_count=int(data["leaf_count"]),
                root=str(data["root"]),
                checkpoint_signature=str(data["checkpoint_signature"]),
                created_at=str(data["created_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AnchorError(f"malformed checkpoint statement: {exc}") from exc

    def verify_signature(self, public_key: Ed25519PublicKey) -> bool:
        """Return True iff the embedded checkpoint signature covers ``root``."""
        from memory_blackbox.crypto.signing import verify

        prefix = "blake3:"
        if not self.root.startswith(prefix):
            return False
        try:
            root_bytes = bytes.fromhex(self.root[len(prefix) :])
        except ValueError:
            return False
        return verify(root_bytes, self.checkpoint_signature, public_key)


@dataclass(frozen=True, slots=True)
class Witness:
    """One externally held record that a checkpoint statement was published.

    ``statement`` is populated only by backends that store and return the payload.
    The file witness does; a transparency log that persists just the payload hash
    (Rekor's ``rekord`` type, for one) does not. ``fingerprint`` is always present
    and is the backend's own identifier for the statement, so a witness can be
    matched against a local checkpoint without recovering the payload -- which is
    all rollback detection actually needs.
    """

    backend: str
    log_id: str
    locator: str
    fingerprint: str
    statement: CheckpointStatement | None = None
    integrated_at: str | None = None

    @property
    def leaf_count(self) -> int | None:
        """The witnessed ledger length, when the backend returned the statement."""
        return self.statement.leaf_count if self.statement is not None else None

    def describe(self) -> str:
        """A short human-readable identification of this witness."""
        length = f", {self.statement.leaf_count} rows" if self.statement is not None else ""
        when = f" at {self.integrated_at}" if self.integrated_at else ""
        return f"{self.backend}:{self.locator}{length}{when}"


@runtime_checkable
class Anchor(Protocol):
    """Publishes checkpoint statements to an external append-only log.

    A backend has two jobs, and the second is the one that buys the security
    property: ``publish`` puts a statement somewhere the host cannot rewrite, and
    ``witnesses`` reads back *everything* that log holds for this ledger -- including
    entries the local ledger can no longer account for.
    """

    name: str

    def publish(self, statement: CheckpointStatement, signer: KeyPair) -> AnchorReceipt:
        """Publish ``statement``; return a receipt with the log's proof material."""
        ...

    def witnesses(self, ledger_identity: str, public_key: Ed25519PublicKey) -> list[Witness]:
        """Return every witness the log holds for this ledger, newest last.

        Verification never needs the private key, so this side of the seam takes
        only the public one -- an auditor can check anchors without being trusted
        to sign.
        """
        ...

    def fingerprint(self, statement: CheckpointStatement) -> str:
        """Return the identifier this log knows ``statement`` by.

        Verification compares local checkpoints to remote witnesses through this
        function, so a backend that stores only a digest of the payload can still
        be matched exactly against a locally recomputed statement.
        """
        ...

    def verify_receipt(self, receipt: AnchorReceipt) -> tuple[bool, str]:
        """Re-check a stored receipt offline; return ``(ok, detail)``."""
        ...


class NoOpAnchor:
    """The default: anchors nothing, witnesses nothing.

    Selecting this backend means the ledger relies on its local signed checkpoint
    alone, which does **not** detect rollback by an attacker with raw file access.
    :func:`memory_blackbox.anchor.verify.verify_anchors` reports that explicitly
    rather than returning a misleading pass.
    """

    name = "none"

    def publish(self, statement: CheckpointStatement, signer: KeyPair) -> AnchorReceipt:
        raise AnchorError(
            "no anchoring backend is configured: checkpoints are local-only. "
            "Configure a file witness or a transparency log to publish externally."
        )

    def witnesses(self, ledger_identity: str, public_key: Ed25519PublicKey) -> list[Witness]:
        return []

    def fingerprint(self, statement: CheckpointStatement) -> str:
        return statement.digest()

    def verify_receipt(self, receipt: AnchorReceipt) -> tuple[bool, str]:
        return False, "the no-op anchor issues no receipts"
