"""External transparency-log anchoring.

The local signed Merkle checkpoint proves no row was edited or removed *by an
attacker who cannot forge the signing key*. It cannot survive an attacker with
raw file access, who deletes the recent checkpoints and truncates the ledger back
to an earlier one: what remains is internally consistent and verifies clean.

Anchoring closes that gap by publishing each checkpoint to an **external,
append-only log** the attacker does not control. History that was witnessed
externally cannot be unpublished, so a rolled-back or forked local ledger leaves
witnesses it can no longer account for -- and that mismatch is the detection.

See :mod:`memory_blackbox.anchor.verify` for exactly what this does and does not
prove, and ``docs/anchoring.md`` for the operational guide.
"""

from memory_blackbox.anchor.base import (
    ANCHOR_STATEMENT_TYPE,
    Anchor,
    AnchorError,
    Checkpoint,
    CheckpointStatement,
    NoOpAnchor,
    Witness,
    ledger_id,
)
from memory_blackbox.anchor.factory import build_anchor
from memory_blackbox.anchor.file_witness import FileWitnessAnchor
from memory_blackbox.anchor.receipt import AnchorReceipt
from memory_blackbox.anchor.store import AnchorStore
from memory_blackbox.anchor.verify import (
    AnchorDivergence,
    AnchorReport,
    DivergenceKind,
    anchor_now,
    verify_anchors,
)

__all__ = [
    "ANCHOR_STATEMENT_TYPE",
    "Anchor",
    "AnchorDivergence",
    "AnchorError",
    "AnchorReceipt",
    "AnchorReport",
    "AnchorStore",
    "Checkpoint",
    "CheckpointStatement",
    "DivergenceKind",
    "FileWitnessAnchor",
    "NoOpAnchor",
    "Witness",
    "anchor_now",
    "build_anchor",
    "ledger_id",
    "verify_anchors",
]
