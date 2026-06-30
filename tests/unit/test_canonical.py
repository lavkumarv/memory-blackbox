"""Tests for canonical serialization (spec §15.1): golden-file + determinism."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from memory_blackbox.model.canonical import LEDGER_SET_FIELDS, canonical_bytes
from memory_blackbox.model.records import (
    MemoryType,
    ProvenanceRecord,
    Source,
    SourceType,
    TrustLevel,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "canonical_record.json"
_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)


def _fixed_record() -> ProvenanceRecord:
    source = Source(
        source_id="src-fixed-001",
        source_type=SourceType.document_ingest,
        locator="file:///poison.md",
        trust_level=TrustLevel.untrusted,
        trust_score=0.2,
        first_seen=_TS,
        metadata={"b": 2, "a": 1},
    )
    return ProvenanceRecord(
        record_id="rec-fixed-001",
        namespace="demo",
        memory_id="mem-1",
        content="The capital of France is Paris.",
        memory_type=MemoryType.semantic,
        source=source,
        derived_from=["rec-000"],
        created_at=_TS,
    )


def test_canonical_bytes_match_golden_file() -> None:
    """The exact bytes are pinned; any drift in serialization is caught here."""
    expected = FIXTURE.read_bytes()
    assert canonical_bytes(_fixed_record().model_dump(mode="json")) == expected


def test_canonical_bytes_independent_of_key_insertion_order() -> None:
    base = _fixed_record().model_dump(mode="json")
    shuffled = dict(reversed(list(base.items())))
    shuffled["source"] = dict(reversed(list(base["source"].items())))
    assert canonical_bytes(shuffled) == canonical_bytes(base)


def test_canonical_bytes_exclude_ledger_set_fields() -> None:
    payload = _fixed_record().model_dump(mode="json")
    payload["entry_hash"] = "blake3:deadbeef"
    payload["signature"] = "ed25519:deadbeef"
    payload["merkle_leaf"] = "blake3:deadbeef"
    # Ledger-set fields must not affect the canonical (signable) bytes.
    assert canonical_bytes(payload) == FIXTURE.read_bytes()


def test_ledger_set_fields_constant() -> None:
    assert {
        "entry_hash",
        "prev_hash",
        "signature",
        "signer_kid",
        "merkle_leaf",
    } == LEDGER_SET_FIELDS
