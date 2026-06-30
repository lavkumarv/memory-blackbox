"""Tests for record models and validators (spec §15.1)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from memory_blackbox.crypto.hashing import b3
from memory_blackbox.model.records import (
    ActionRecord,
    Finding,
    ProvenanceRecord,
    RetrievalRecord,
    Severity,
    Source,
    SourceType,
    hash_content,
)


def _source() -> Source:
    return Source(source_type=SourceType.user_input)


def test_content_hash_is_derived_when_absent() -> None:
    rec = ProvenanceRecord(content="hello", source=_source())
    assert rec.content_hash == b3(b"hello")


def test_content_hash_accepts_matching_value() -> None:
    content = "hello"
    rec = ProvenanceRecord(content=content, content_hash=hash_content(content), source=_source())
    assert rec.content_hash == hash_content(content)


def test_content_hash_validator_rejects_mismatch() -> None:
    with pytest.raises(ValidationError):
        ProvenanceRecord(content="hello", content_hash="blake3:deadbeef", source=_source())


def test_ledger_set_fields_default_none() -> None:
    rec = ProvenanceRecord(content="x", source=_source())
    assert rec.entry_hash is None
    assert rec.prev_hash is None
    assert rec.signature is None
    assert rec.signer_kid is None
    assert rec.merkle_leaf is None


def test_ids_are_unique_and_sorted() -> None:
    a = ProvenanceRecord(content="a", source=_source())
    b = ProvenanceRecord(content="b", source=_source())
    assert a.record_id != b.record_id
    assert a.record_id < b.record_id  # uuid7 is time-sortable


def test_trust_score_bounds_enforced() -> None:
    with pytest.raises(ValidationError):
        Source(source_type=SourceType.user_input, trust_score=1.5)


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        ProvenanceRecord(content="x", source=_source(), bogus="nope")  # type: ignore[call-arg]


def test_retrieval_query_hash_derived() -> None:
    ret = RetrievalRecord(query="who is the CEO?", returned=["rec-1"], scores=[0.9])
    assert ret.query_hash == b3(b"who is the CEO?")


def test_action_record_fields() -> None:
    action = ActionRecord(action_kind="email.send", summary="emailed payroll")
    assert action.kind.value == "action"
    assert action.context_retrievals == []


def test_finding_requires_severity() -> None:
    finding = Finding(detector_name="injection_scan", severity=Severity.HIGH, message="override")
    assert finding.severity is Severity.HIGH
