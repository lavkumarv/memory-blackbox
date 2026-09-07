"""End-to-end anchoring, and the negative controls that justify it.

The controls matter more than the happy path. Each tampering test asserts *both*
halves of the claim: that local-only verification passes (the documented v1 gap)
and that the anchored cross-check fails. A test that only asserted the second
half would still pass if anchoring flagged everything indiscriminately.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import orjson
import pytest

from memory_blackbox.anchor.base import (
    AnchorError,
    CheckpointStatement,
    NoOpAnchor,
    ledger_id,
)
from memory_blackbox.anchor.file_witness import FileWitnessAnchor
from memory_blackbox.anchor.store import AnchorStore
from memory_blackbox.anchor.verify import DivergenceKind, anchor_now, verify_anchors
from memory_blackbox.crypto import keys
from memory_blackbox.ledger.store import LedgerStore
from memory_blackbox.model.records import ProvenanceRecord, Source, SourceType
from memory_blackbox.query.verify import verify

pytestmark = pytest.mark.integration


@pytest.fixture
def signer() -> keys.KeyPair:
    return keys.generate()


@pytest.fixture
def witness_path(tmp_path: Path) -> Path:
    return tmp_path / "witness" / "anchors.jsonl"


@pytest.fixture
def anchor(witness_path: Path) -> FileWitnessAnchor:
    return FileWitnessAnchor(witness_path)


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / "ledger.db"


@pytest.fixture
def store(ledger_path: Path, signer: keys.KeyPair) -> LedgerStore:
    # checkpoint_every=0 so the tests control exactly when checkpoints happen.
    return LedgerStore(ledger_path, signer, checkpoint_every=0)


def _write(content: str) -> ProvenanceRecord:
    return ProvenanceRecord(content=content, source=Source(source_type=SourceType.user_input))


def _fill(store: LedgerStore, count: int, prefix: str = "e") -> None:
    for i in range(count):
        store.append(_write(f"{prefix}-{i}"))


def _reopen_unlocked(path: Path, signer: keys.KeyPair) -> sqlite3.Connection:
    """Open the ledger with the append-only triggers dropped, as an attacker would."""
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        DROP TRIGGER IF EXISTS ledger_no_update;
        DROP TRIGGER IF EXISTS ledger_no_delete;
        DROP TRIGGER IF EXISTS merkle_checkpoints_no_update;
        DROP TRIGGER IF EXISTS merkle_checkpoints_no_delete;
        DROP TRIGGER IF EXISTS anchors_no_update;
        DROP TRIGGER IF EXISTS anchors_no_delete;
        """
    )
    con.commit()
    return con


def _truncate_to(path: Path, signer: keys.KeyPair, rows: int) -> None:
    """Roll the ledger back to ``rows``, covering the attacker's tracks locally.

    Deleting the newer checkpoints and anchor rows is what makes this attack work
    against local-only verification: what remains is a shorter but perfectly
    self-consistent ledger with a matching signed checkpoint.
    """
    con = _reopen_unlocked(path, signer)
    con.execute("DELETE FROM ledger WHERE seq > ?", (rows,))
    con.execute("DELETE FROM merkle_checkpoints WHERE leaf_count > ?", (rows,))
    con.execute("DELETE FROM anchors WHERE leaf_count > ?", (rows,))
    con.commit()
    con.close()


# --- happy path -------------------------------------------------------------
def test_anchoring_a_clean_ledger_verifies(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair
) -> None:
    _fill(store, 5)
    receipt = anchor_now(store, anchor, signer)

    assert receipt.statement.leaf_count == 5
    report = verify_anchors(store, anchor)
    assert report.ok, report.summary
    assert report.witness_count == 1
    assert report.witnessed_rows == 5


def test_anchoring_publishes_only_hashes_and_counts(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, witness_path: Path
) -> None:
    # The witness may end up in a public log, so a content leak here would be a
    # privacy incident, not a cosmetic issue.
    store.append(_write("patient SSN 123-45-6789 and the launch codes"))
    anchor_now(store, anchor, signer)

    published = witness_path.read_text(encoding="utf-8")
    assert "123-45-6789" not in published
    assert "launch codes" not in published


def test_successive_anchors_accumulate_witnesses(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair
) -> None:
    _fill(store, 3)
    anchor_now(store, anchor, signer)
    _fill(store, 4, prefix="later")
    anchor_now(store, anchor, signer)

    report = verify_anchors(store, anchor)
    assert report.ok, report.summary
    assert report.witness_count == 2
    assert report.witnessed_rows == 7


def test_anchor_receipts_are_recorded_and_re_verifiable(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair
) -> None:
    _fill(store, 3)
    anchor_now(store, anchor, signer)

    receipts = AnchorStore(store.connection).anchors()
    assert len(receipts) == 1
    ok, detail = anchor.verify_receipt(receipts[0])
    assert ok, detail


def test_full_verify_reports_the_anchor_check(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair
) -> None:
    _fill(store, 3)
    anchor_now(store, anchor, signer)

    report = verify(store, anchor=anchor)
    assert report.ok
    assert report.anchor is not None
    assert "external witness" in report.summary


def test_verify_says_anchors_were_not_checked_when_no_anchor_is_passed(
    store: LedgerStore,
) -> None:
    _fill(store, 3)
    store.checkpoint()
    report = verify(store)
    assert report.ok
    assert report.anchor is None
    assert "not checked" in report.summary


# --- the gap this feature closes -------------------------------------------
def test_rollback_passes_local_verification_but_fails_the_anchor_check(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, ledger_path: Path
) -> None:
    _fill(store, 5)
    anchor_now(store, anchor, signer)
    _fill(store, 5, prefix="later")
    anchor_now(store, anchor, signer)
    store.close()

    _truncate_to(ledger_path, signer, rows=5)
    rolled_back = LedgerStore(ledger_path, signer, checkpoint_every=0)

    # This is the documented v1 limitation, asserted rather than assumed:
    # the truncated ledger is internally consistent and verifies clean.
    local_only = verify(rolled_back)
    assert local_only.ok, "local-only verify should not detect this; the anchor should"
    assert rolled_back.count() == 5

    anchored = verify(rolled_back, anchor=anchor)
    assert not anchored.ok
    kinds = {d.kind for d in anchored.anchor.divergences}  # type: ignore[union-attr]
    assert DivergenceKind.ROLLBACK in kinds
    assert "10 rows" in anchored.summary and "now has 5" in anchored.summary


def test_fork_at_the_same_length_is_detected(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, ledger_path: Path
) -> None:
    # Rewriting history and re-appending to the same length defeats a row-count
    # check, so the root comparison has to be what catches it. This attack needs
    # the signing key (truncation does not), and with the key the attacker also
    # re-checkpoints to leave a locally clean ledger behind.
    _fill(store, 6)
    anchor_now(store, anchor, signer)
    store.close()

    _truncate_to(ledger_path, signer, rows=3)
    forked = LedgerStore(ledger_path, signer, checkpoint_every=0)
    _fill(forked, 3, prefix="rewritten")
    forked.checkpoint()
    assert forked.count() == 6

    assert verify(forked).ok, "the rewritten ledger is locally self-consistent"

    report = verify_anchors(forked, anchor)
    assert not report.ok
    kinds = {d.kind for d in report.divergences}
    assert DivergenceKind.FORK in kinds or DivergenceKind.ORPHANED_WITNESS in kinds


def test_wholesale_replacement_leaves_no_matching_witnesses(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, tmp_path: Path
) -> None:
    _fill(store, 4)
    anchor_now(store, anchor, signer)
    original_identity = ledger_id(store.connection)
    store.close()

    # A brand-new ledger under the same key has a different genesis, so a different
    # identity, so none of the real witnesses belong to it.
    replacement = LedgerStore(tmp_path / "replacement.db", signer, checkpoint_every=0)
    _fill(replacement, 4, prefix="fake")
    assert ledger_id(replacement.connection) != original_identity

    report = verify_anchors(replacement, anchor)
    assert not report.ok
    assert report.divergences[0].kind == DivergenceKind.NO_WITNESS


def test_deleting_the_local_anchor_rows_does_not_hide_the_rollback(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, ledger_path: Path
) -> None:
    # The anchors table is a local cache, and the attacker can drop it. The witness
    # lives elsewhere, which is the entire point.
    _fill(store, 6)
    anchor_now(store, anchor, signer)
    store.close()

    con = _reopen_unlocked(ledger_path, signer)
    con.execute("DELETE FROM anchors")
    con.execute("DELETE FROM ledger WHERE seq > 2")
    con.execute("DELETE FROM merkle_checkpoints WHERE leaf_count > 2")
    con.commit()
    con.close()

    tampered = LedgerStore(ledger_path, signer, checkpoint_every=0)
    assert AnchorStore(tampered.connection).anchors() == []

    report = verify_anchors(tampered, anchor)
    assert not report.ok
    assert DivergenceKind.ROLLBACK in {d.kind for d in report.divergences}


# --- witness integrity ------------------------------------------------------
def test_an_unsigned_witness_line_is_ignored(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, witness_path: Path
) -> None:
    # Otherwise anyone who can append to the witness could fabricate a longer
    # history and turn the rollback check into a denial of service.
    _fill(store, 3)
    anchor_now(store, anchor, signer)

    forged = orjson.loads(witness_path.read_text().splitlines()[0])
    forged["statement"]["leaf_count"] = 9_999
    with witness_path.open("a", encoding="utf-8") as handle:
        handle.write(orjson.dumps(forged).decode("utf-8") + "\n")

    report = verify_anchors(store, anchor)
    assert report.ok, report.summary
    assert report.witness_count == 1  # the forged line is not a witness


def test_a_witness_signed_by_another_key_is_ignored(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, witness_path: Path
) -> None:
    _fill(store, 3)
    anchor_now(store, anchor, signer)
    identity = ledger_id(store.connection)
    assert identity is not None

    other = keys.generate()
    other_store = LedgerStore(store.path + ".other", other, checkpoint_every=0)
    _fill(other_store, 8)
    other_store.checkpoint()
    FileWitnessAnchor(witness_path).publish(_statement_for(other_store, identity), other)

    report = verify_anchors(store, anchor)
    assert report.ok, report.summary
    assert report.witness_count == 1


def _statement_for(store: LedgerStore, identity: str) -> CheckpointStatement:
    checkpoint = AnchorStore(store.connection).latest_checkpoint()
    assert checkpoint is not None
    return CheckpointStatement.build(checkpoint, identity)


def test_a_missing_witness_file_is_reported_not_silently_passed(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, witness_path: Path
) -> None:
    _fill(store, 3)
    anchor_now(store, anchor, signer)
    witness_path.unlink()

    report = verify_anchors(store, anchor)
    assert not report.ok
    assert report.divergences[0].kind == DivergenceKind.NO_WITNESS


def test_a_corrupt_witness_line_raises_rather_than_being_skipped(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair, witness_path: Path
) -> None:
    _fill(store, 3)
    anchor_now(store, anchor, signer)
    with witness_path.open("a", encoding="utf-8") as handle:
        handle.write("{ this is not json\n")

    with pytest.raises(AnchorError, match="corrupt witness line"):
        verify_anchors(store, anchor)


# --- the no-op backend ------------------------------------------------------
def test_an_unanchored_ledger_is_reported_as_unwitnessed_not_as_ok(
    store: LedgerStore,
) -> None:
    _fill(store, 3)
    store.checkpoint()

    report = verify_anchors(store, NoOpAnchor())
    assert not report.ok
    assert report.divergences[0].kind == DivergenceKind.NO_WITNESS
    assert "undetectable" in report.divergences[0].detail


def test_require_witness_false_allows_an_unanchored_ledger(store: LedgerStore) -> None:
    _fill(store, 3)
    store.checkpoint()
    assert verify_anchors(store, NoOpAnchor(), require_witness=False).ok


def test_an_empty_ledger_has_nothing_to_anchor(
    store: LedgerStore, anchor: FileWitnessAnchor, signer: keys.KeyPair
) -> None:
    assert verify_anchors(store, anchor).ok
    with pytest.raises(AnchorError, match="empty ledger"):
        anchor_now(store, anchor, signer)
