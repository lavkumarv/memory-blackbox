"""Tests for semantic drift detection (spec §15.8)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from memory_blackbox.capture.engine import MemoryBlackbox
from memory_blackbox.crypto import keys
from memory_blackbox.detectors.base import DetectorContext
from memory_blackbox.detectors.drift import DriftDetector
from memory_blackbox.embedding import HashingEmbedder, cosine
from memory_blackbox.model.records import (
    ProvenanceRecord,
    Source,
    SourceType,
    TrustLevel,
)
from memory_blackbox.query.drift import drift


def _trusted() -> Source:
    return Source(
        source_id="user",
        source_type=SourceType.user_input,
        trust_level=TrustLevel.trusted,
        locator="user://session",
    )


def _untrusted() -> Source:
    return Source(
        source_id="evil-doc",
        source_type=SourceType.document_ingest,
        trust_level=TrustLevel.untrusted,
        locator="http://evil.test/doc",
    )


def test_hashing_embedder_is_deterministic() -> None:
    a = HashingEmbedder().embed("the capital of France is Paris")
    b = HashingEmbedder().embed("the capital of France is Paris")
    assert a == b
    assert abs(cosine(a, a) - 1.0) < 1e-9


def test_drift_flags_contradicting_untrusted_write(tmp_path: Path) -> None:
    f = MemoryBlackbox.open(tmp_path / "l.db", keys.generate(), detectors=[])
    f.record_write("The capital of France is Paris", _trusted(), namespace="t")
    f.record_write("Paris is the capital city of France", _trusted(), namespace="t")
    f.record_write("France has its capital in Paris", _trusted(), namespace="t")
    poison = f.record_write("The capital of France is Berlin", _untrusted(), namespace="t")

    events = drift(f.ledger, "capital of France")
    assert len(events) == 1
    assert events[0].record_id == poison.record_id
    assert events[0].source_id == "evil-doc"
    assert events[0].timestamp == poison.created_at.isoformat().replace("+00:00", "Z")


def test_drift_quiet_without_contradiction(tmp_path: Path) -> None:
    f = MemoryBlackbox.open(tmp_path / "l.db", keys.generate(), detectors=[])
    f.record_write("The capital of France is Paris", _trusted(), namespace="t")
    f.record_write("Paris is the capital of France indeed", _untrusted(), namespace="t")
    # Untrusted, but agrees with the consensus -> no drift event.
    assert drift(f.ledger, "capital of France") == []


def test_drift_empty_without_trusted_consensus(tmp_path: Path) -> None:
    f = MemoryBlackbox.open(tmp_path / "l.db", keys.generate(), detectors=[])
    f.record_write("The capital of France is Berlin", _untrusted(), namespace="t")
    assert drift(f.ledger, "capital of France") == []


def test_drift_detector_streaming_flags_contradiction() -> None:
    detector = DriftDetector()
    ctx = DetectorContext(namespace="t", now=datetime(2026, 1, 1, tzinfo=UTC))

    for text in (
        "The capital of France is Paris",
        "Paris is the capital city of France",
        "France has its capital in Paris",
    ):
        rec = ProvenanceRecord(content=text, source=_trusted())
        assert detector.inspect(rec, text, ctx) == []  # trusted, builds consensus

    bad = ProvenanceRecord(content="The capital of France is Berlin", source=_untrusted())
    findings = detector.inspect(bad, bad.content, ctx)
    assert findings and findings[0].detector_name == "drift"
