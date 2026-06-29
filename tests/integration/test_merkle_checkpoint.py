"""Tests for ledger Merkle checkpoints and deletion detection (spec §15.3)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent_forensics.crypto import keys
from agent_forensics.ledger.store import LedgerStore
from agent_forensics.merkle.tree import verify_merkle
from agent_forensics.model.records import ProvenanceRecord, Source, SourceType


@pytest.fixture
def store(tmp_path: Path) -> LedgerStore:
    return LedgerStore(tmp_path / "ledger.db", keys.generate())


def _write(content: str) -> ProvenanceRecord:
    return ProvenanceRecord(content=content, source=Source(source_type=SourceType.user_input))


def _drop_triggers(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.executescript(
        "DROP TRIGGER IF EXISTS ledger_no_update; DROP TRIGGER IF EXISTS ledger_no_delete;"
    )
    con.commit()
    return con


def test_recomputed_root_matches_checkpoint_on_clean_ledger(store: LedgerStore) -> None:
    for i in range(6):
        store.append(_write(f"e-{i}"))
    report = verify_merkle(store.connection, store.public_key)
    assert report.ok
    assert report.leaf_count == 6


def test_empty_ledger_merkle_ok(store: LedgerStore) -> None:
    assert verify_merkle(store.connection, store.public_key).ok


def test_deletion_detected_by_merkle(store: LedgerStore, tmp_path: Path) -> None:
    for i in range(5):
        store.append(_write(f"e-{i}"))
    public_key = store.public_key
    store.close()

    con = _drop_triggers(str(tmp_path / "ledger.db"))
    con.execute("DELETE FROM ledger WHERE seq = 3")
    con.commit()

    report = verify_merkle(con, public_key)
    assert not report.ok
    con.close()


def test_tail_truncation_detected_by_merkle(store: LedgerStore, tmp_path: Path) -> None:
    # Tail truncation is the case the hash chain alone cannot catch.
    for i in range(5):
        store.append(_write(f"e-{i}"))
    public_key = store.public_key
    store.close()

    con = _drop_triggers(str(tmp_path / "ledger.db"))
    con.execute("DELETE FROM ledger WHERE seq = 5")  # remove the last row
    con.commit()

    report = verify_merkle(con, public_key)
    assert not report.ok
    assert "4 rows" in report.detail
    con.close()


def test_forged_checkpoint_signature_detected(store: LedgerStore) -> None:
    for i in range(3):
        store.append(_write(f"e-{i}"))
    # Verifying against a different key than signed the checkpoint -> signature fails.
    report = verify_merkle(store.connection, keys.generate().public_key)
    assert not report.ok
    assert "signature" in report.detail


def test_non_empty_ledger_without_checkpoint_is_flagged(tmp_path: Path) -> None:
    # checkpoint_every=0 disables auto-checkpointing.
    store = LedgerStore(tmp_path / "l.db", keys.generate(), checkpoint_every=0)
    store.append(_write("e-0"))
    report = verify_merkle(store.connection, store.public_key)
    assert not report.ok
    assert "no signed checkpoint" in report.detail


def test_edited_entry_hash_detected_as_root_mismatch(store: LedgerStore, tmp_path: Path) -> None:
    # Editing a value in place keeps the row count, so the truncation check passes
    # and the recomputed-root check is what catches it.
    for i in range(5):
        store.append(_write(f"e-{i}"))
    public_key = store.public_key
    store.close()

    con = _drop_triggers(str(tmp_path / "ledger.db"))
    con.execute("UPDATE ledger SET entry_hash = 'blake3:tampered' WHERE seq = 2")
    con.commit()

    report = verify_merkle(con, public_key)
    assert not report.ok
    assert "recomputed root" in report.detail
    con.close()


def test_checkpoint_cadence_controls_checkpoint_count(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path / "l.db", keys.generate(), checkpoint_every=3)
    for i in range(7):
        store.append(_write(f"e-{i}"))
    n = store.connection.execute("SELECT COUNT(*) AS n FROM merkle_checkpoints").fetchone()["n"]
    assert n == 2  # checkpoints at 3 and 6, the trailing one covered on close/checkpoint
    store.checkpoint()
    report = verify_merkle(store.connection, store.public_key)
    assert report.ok
    assert report.leaf_count == 7
