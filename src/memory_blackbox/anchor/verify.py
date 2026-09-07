"""Cross-checking a local ledger against what an external log witnessed.

The local Merkle checkpoint answers "were rows edited or removed since the last
checkpoint I still hold?". It cannot answer "did I still hold every checkpoint I
made?", because an attacker with raw file access deletes the recent checkpoints
along with the rows, and what is left verifies clean. That is the gap anchoring
closes, and this module is where the closing happens.

The check is an accounting argument, not a cryptographic one. Every checkpoint the
external log holds for this ledger must correspond to a checkpoint the local ledger
can still reproduce. Publication is not retractable, so:

- **rollback** -- history truncated to an earlier point: the checkpoints covering
  the removed tail are still in the log, and the shortened ledger can no longer
  produce their statements.
- **fork** -- history rewritten at the same length: the rewritten prefix hashes to
  a different root, so the witnessed statement no longer matches.
- **wholesale replacement** -- a fresh ledger: its genesis differs, so its
  :func:`ledger_id` differs, and none of the real witnesses are accounted for.

What this does **not** prove:

- That the ledger content is true. A log witnesses that a claim was published, not
  that it was honest.
- That every checkpoint was anchored. An operator who never published a checkpoint
  leaves nothing to be missing; anchoring detects removal of *witnessed* history,
  which is why anchoring cadence sets the blast radius of an undetectable rollback.
- Anything at all under :class:`~memory_blackbox.anchor.base.NoOpAnchor`, which is
  reported as ``no_witness`` rather than as a pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from memory_blackbox.anchor.base import (
    Anchor,
    AnchorError,
    Checkpoint,
    CheckpointStatement,
    Witness,
    ledger_id,
)
from memory_blackbox.anchor.receipt import AnchorReceipt
from memory_blackbox.anchor.store import AnchorStore
from memory_blackbox.merkle.tree import compute_root, current_leaves

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from memory_blackbox.crypto.keys import KeyPair
    from memory_blackbox.ledger.store import LedgerStore


class DivergenceKind(StrEnum):
    """Why an anchor cross-check failed."""

    NO_WITNESS = "no_witness"  # nothing was ever published, so nothing is provable
    ROLLBACK = "rollback"  # ledger is shorter than a witnessed checkpoint
    FORK = "fork"  # a witnessed root does not match the local history
    ORPHANED_WITNESS = "orphaned_witness"  # a published checkpoint the ledger cannot produce
    UNSIGNED_WITNESS = "unsigned_witness"  # witnessed statement not signed by the ledger key
    BAD_RECEIPT = "bad_receipt"  # a locally stored receipt no longer checks out


@dataclass(frozen=True, slots=True)
class AnchorDivergence:
    """One discrepancy between the local ledger and the external log."""

    kind: DivergenceKind
    detail: str
    witness: str | None = None


@dataclass(frozen=True, slots=True)
class AnchorReport:
    """Result of cross-checking a ledger against its external witnesses."""

    ok: bool
    backend: str
    local_rows: int
    local_checkpoints: int
    witness_count: int
    witnessed_rows: int | None = None
    divergences: tuple[AnchorDivergence, ...] = ()

    @property
    def summary(self) -> str:
        if self.divergences:
            first = self.divergences[0]
            extra = f" (+{len(self.divergences) - 1} more)" if len(self.divergences) > 1 else ""
            return f"anchor {first.kind}: {first.detail}{extra}"
        if not self.ok:
            return "anchor check did not run"
        if self.witnessed_rows is not None:
            return (
                f"ok: {self.witness_count} external witness(es) on {self.backend}; "
                f"{self.witnessed_rows} of {self.local_rows} local rows witnessed"
            )
        # A log that keeps no payload can vouch for checkpoints but not row counts.
        return (
            f"ok: {self.witness_count} external witness(es) on {self.backend} "
            f"match local checkpoints ({self.local_rows} rows)"
        )


def anchor_now(ledger: LedgerStore, anchor: Anchor, signer: KeyPair) -> AnchorReceipt:
    """Checkpoint the ledger and publish that checkpoint to ``anchor``.

    Checkpointing first means the anchor always covers every row written so far;
    publishing an older checkpoint would leave the newest rows unwitnessed for no
    reason. Re-publishing an already-anchored checkpoint is not an error, but it
    does create a second log entry, so callers that anchor on a timer should
    prefer :meth:`AnchorStore.is_anchored` to skip no-op publications.
    """
    ledger.checkpoint()
    store = AnchorStore(ledger.connection)
    checkpoint = store.latest_checkpoint()
    if checkpoint is None:
        raise AnchorError("cannot anchor an empty ledger: there is no checkpoint to publish")
    identity = ledger_id(ledger.connection)
    if identity is None:  # pragma: no cover - a checkpoint implies at least one row
        raise AnchorError("cannot anchor an empty ledger: no genesis row")
    statement = CheckpointStatement.build(checkpoint, identity)
    receipt = anchor.publish(statement, signer)
    store.record(checkpoint, receipt)
    return receipt


def verify_anchors(
    ledger: LedgerStore,
    anchor: Anchor,
    *,
    require_witness: bool = True,
) -> AnchorReport:
    """Cross-check ``ledger`` against every witness ``anchor``'s log holds for it.

    ``require_witness`` controls how an unanchored ledger is reported. It defaults
    to True because "nothing was published" and "everything checks out" are very
    different states, and only one of them should read as a pass.
    """
    conn = ledger.connection
    public_key = ledger.public_key
    store = AnchorStore(conn)
    local_rows = ledger.count()
    checkpoints = store.checkpoints()
    identity = ledger_id(conn)

    if identity is None:
        return AnchorReport(
            ok=True,
            backend=anchor.name,
            local_rows=0,
            local_checkpoints=len(checkpoints),
            witness_count=0,
        )

    divergences: list[AnchorDivergence] = []

    # A statement the local ledger can still produce, keyed the way the log keys it.
    local_by_fingerprint: dict[str, Checkpoint] = {}
    for checkpoint in checkpoints:
        statement = CheckpointStatement.build(checkpoint, identity)
        local_by_fingerprint[anchor.fingerprint(statement)] = checkpoint

    witnesses = anchor.witnesses(identity, public_key)

    if not witnesses:
        if require_witness:
            return AnchorReport(
                ok=False,
                backend=anchor.name,
                local_rows=local_rows,
                local_checkpoints=len(checkpoints),
                witness_count=0,
                divergences=(
                    AnchorDivergence(
                        kind=DivergenceKind.NO_WITNESS,
                        detail=(
                            f"no external witness on {anchor.name} for ledger {identity}: "
                            "rollback by an attacker with raw file access is undetectable"
                        ),
                    ),
                ),
            )
        return AnchorReport(
            ok=True,
            backend=anchor.name,
            local_rows=local_rows,
            local_checkpoints=len(checkpoints),
            witness_count=0,
        )

    leaves = current_leaves(conn)
    witnessed_rows = _check_statements(witnesses, leaves, local_rows, public_key, divergences)
    _check_orphans(witnesses, local_by_fingerprint, anchor.name, divergences)
    _check_receipts(store.anchors(anchor.name), anchor, divergences)

    return AnchorReport(
        ok=not divergences,
        backend=anchor.name,
        local_rows=local_rows,
        local_checkpoints=len(checkpoints),
        witness_count=len(witnesses),
        witnessed_rows=witnessed_rows,
        divergences=tuple(divergences),
    )


def _check_statements(
    witnesses: list[Witness],
    leaves: list[bytes],
    local_rows: int,
    public_key: Ed25519PublicKey,
    divergences: list[AnchorDivergence],
) -> int | None:
    """Check witnesses whose payload the log returned, for precise diagnostics.

    Backends that keep only a payload hash contribute nothing here; their
    detection runs through the orphan check instead, which needs no payload.
    """
    witnessed_rows: int | None = None

    for witness in witnesses:
        statement = witness.statement
        if statement is None:
            continue

        if not statement.verify_signature(public_key):
            divergences.append(
                AnchorDivergence(
                    kind=DivergenceKind.UNSIGNED_WITNESS,
                    detail=(
                        f"witnessed checkpoint at {statement.leaf_count} rows is not signed "
                        "by this ledger's key"
                    ),
                    witness=witness.describe(),
                )
            )
            continue

        witnessed_rows = max(witnessed_rows or 0, statement.leaf_count)

        if statement.leaf_count > local_rows:
            divergences.append(
                AnchorDivergence(
                    kind=DivergenceKind.ROLLBACK,
                    detail=(
                        f"log witnessed {statement.leaf_count} rows but the ledger now has "
                        f"{local_rows}: {statement.leaf_count - local_rows} row(s) were removed"
                    ),
                    witness=witness.describe(),
                )
            )
            continue

        expected = "blake3:" + compute_root(leaves[: statement.leaf_count]).hex()
        if expected != statement.root:
            divergences.append(
                AnchorDivergence(
                    kind=DivergenceKind.FORK,
                    detail=(
                        f"the first {statement.leaf_count} rows now hash to {expected}, "
                        f"but {statement.root} was witnessed: history was rewritten"
                    ),
                    witness=witness.describe(),
                )
            )

    return witnessed_rows


def _check_orphans(
    witnesses: list[Witness],
    local_by_fingerprint: dict[str, Checkpoint],
    backend: str,
    divergences: list[AnchorDivergence],
) -> None:
    """Flag published checkpoints the current ledger can no longer reproduce.

    This is the check that works against a log which stores only payload hashes,
    and it is the general form of the rollback and fork checks above: a ledger that
    was altered in any way cannot regenerate the statement it once published.

    It assumes one signing key per ledger. If a key is shared across ledgers, the
    log returns the other ledger's entries too and they read as orphans, so the
    detail says so rather than asserting tampering outright.
    """
    for witness in witnesses:
        if witness.fingerprint in local_by_fingerprint:
            continue
        divergences.append(
            AnchorDivergence(
                kind=DivergenceKind.ORPHANED_WITNESS,
                detail=(
                    f"{backend} holds a published checkpoint ({witness.fingerprint}) that this "
                    "ledger can no longer produce: history was removed or rewritten, or this "
                    "signing key was reused across ledgers"
                ),
                witness=witness.describe(),
            )
        )


def _check_receipts(
    receipts: list[AnchorReceipt],
    anchor: Anchor,
    divergences: list[AnchorDivergence],
) -> None:
    """Re-check each locally stored receipt against its own proof material."""
    for receipt in receipts:
        ok, detail = anchor.verify_receipt(receipt)
        if not ok:
            divergences.append(
                AnchorDivergence(
                    kind=DivergenceKind.BAD_RECEIPT,
                    detail=f"stored receipt for {receipt.locator} does not check out: {detail}",
                    witness=f"{receipt.backend}:{receipt.locator}",
                )
            )
