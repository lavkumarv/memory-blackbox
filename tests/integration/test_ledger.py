"""Tests for the append-only ledger and hash chain (spec §15.2)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from memory_blackbox.crypto import keys
from memory_blackbox.ledger.chain import DivergenceKind, verify_chain
from memory_blackbox.ledger.store import LedgerStore
from memory_blackbox.model.records import (
    ActionRecord,
    ProvenanceRecord,
    RetrievalRecord,
    Source,
    SourceType,
)


@pytest.fixture
def store(tmp_path: Path) -> LedgerStore:
    return LedgerStore(tmp_path / "ledger.db", keys.generate())


def _write(content: str) -> ProvenanceRecord:
    return ProvenanceRecord(content=content, source=Source(source_type=SourceType.user_input))


def _drop_triggers(db_path: str) -> sqlite3.Connection:
    """Open a raw connection and drop the append-only triggers (simulate an attacker)."""
    con = sqlite3.connect(db_path)
    con.executescript(
        "DROP TRIGGER IF EXISTS ledger_no_update; DROP TRIGGER IF EXISTS ledger_no_delete;"
    )
    con.commit()
    return con


def test_append_populates_chain_fields(store: LedgerStore) -> None:
    r1 = store.append(_write("first"))
    r2 = store.append(_write("second"))

    assert r1.prev_hash is None  # genesis
    assert r1.entry_hash is not None
    assert r1.signature is not None and r1.signature.startswith("ed25519:")
    assert r1.signer_kid == store._signer.kid
    assert r2.prev_hash == r1.entry_hash  # linked


def test_append_handles_all_record_kinds(store: LedgerStore) -> None:
    store.append(_write("w"))
    store.append(RetrievalRecord(query="q", returned=["rec-1"], scores=[0.5]))
    store.append(ActionRecord(action_kind="email.send", summary="sent"))
    assert store.count() == 3
    assert verify_chain(store.connection, store.public_key).ok


def test_verify_passes_on_clean_chain(store: LedgerStore) -> None:
    for i in range(5):
        store.append(_write(f"entry-{i}"))
    report = verify_chain(store.connection, store.public_key)
    assert report.ok
    assert report.rows_checked == 5
    assert report.divergence is None


def test_append_only_blocks_update(store: LedgerStore) -> None:
    store.append(_write("x"))
    with pytest.raises(sqlite3.IntegrityError):
        store.connection.execute("UPDATE ledger SET payload_json = 'tampered' WHERE seq = 1")


def test_append_only_blocks_delete(store: LedgerStore) -> None:
    store.append(_write("x"))
    with pytest.raises(sqlite3.IntegrityError):
        store.connection.execute("DELETE FROM ledger WHERE seq = 1")


def test_store_has_no_mutation_methods(store: LedgerStore) -> None:
    # The app-layer guarantee: no update/delete code path exists.
    assert not hasattr(store, "update")
    assert not hasattr(store, "delete")


def test_tamper_detected_at_edited_row(store: LedgerStore, tmp_path: Path) -> None:
    for i in range(4):
        store.append(_write(f"entry-{i}"))
    public_key = store.public_key
    store.close()

    con = _drop_triggers(str(tmp_path / "ledger.db"))
    con.execute('UPDATE ledger SET payload_json = \'{"content":"evil"}\' WHERE seq = 2')
    con.commit()

    report = verify_chain(con, public_key)
    assert not report.ok
    assert report.divergence is not None
    assert report.divergence.seq == 2
    assert report.divergence.kind is DivergenceKind.EDIT
    con.close()


def test_gap_detected_when_row_deleted(store: LedgerStore, tmp_path: Path) -> None:
    appended = [store.append(_write(f"entry-{i}")) for i in range(5)]
    public_key = store.public_key
    store.close()

    con = _drop_triggers(str(tmp_path / "ledger.db"))
    con.execute("DELETE FROM ledger WHERE seq = 3")
    con.commit()

    report = verify_chain(con, public_key)
    assert not report.ok
    assert report.divergence is not None
    # The row that followed the deleted one no longer links correctly.
    assert report.divergence.kind is DivergenceKind.GAP
    assert report.divergence.seq == 4
    con.close()
    assert appended[0].entry_hash is not None


def test_get_returns_row_by_record_id(store: LedgerStore) -> None:
    rec = store.append(_write("findable"))
    row = store.get(rec.record_id)
    assert row is not None
    assert row["record_id"] == rec.record_id
    assert store.get("does-not-exist") is None


def test_rows_yields_in_seq_order(store: LedgerStore) -> None:
    written = [store.append(_write(f"e-{i}")) for i in range(3)]
    seqs = [row["seq"] for row in store.rows()]
    assert seqs == sorted(seqs)
    assert [row["record_id"] for row in store.rows()] == [w.record_id for w in written]


def test_forgery_detected_with_wrong_key(store: LedgerStore) -> None:
    store.append(_write("x"))
    # Verifying against a different key than signed the rows -> forgery.
    report = verify_chain(store.connection, keys.generate().public_key)
    assert not report.ok
    assert report.divergence is not None
    assert report.divergence.kind is DivergenceKind.FORGERY
