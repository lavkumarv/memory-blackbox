"""Tests for the hosted-vector-DB sidecar (spec §10.6)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from memory_blackbox.capture.engine import Forensics
from memory_blackbox.capture.sidecar import PROVENANCE_TAG, Sidecar
from memory_blackbox.capture.wrapper import ReadMap, WriteMap
from memory_blackbox.crypto import keys
from memory_blackbox.model.records import Source, SourceType


class FakeVectorDB:
    """A stand-in for a hosted vector DB (upsert/query)."""

    def __init__(self) -> None:
        self.upserts: list[dict[str, Any]] = []

    def __call__(self, op: str, payload: dict[str, Any]) -> Any:
        if op == "upsert":
            self.upserts.append(payload)
            return {"status": "ok"}
        if op == "query":
            return {"matches": [{"id": "v-1", "score": 0.7}]}
        return {"status": "ok"}


@pytest.fixture
def forensics(tmp_path: Path) -> Forensics:
    return Forensics.open(tmp_path / "l.db", keys.generate(), detectors=[])


def _sidecar(forensics: Forensics, db: FakeVectorDB) -> Sidecar:
    return Sidecar(
        forensics,
        db,
        namespace="t",
        default_source=Source(source_id="vec", source_type=SourceType.tool_output, locator="db://"),
        upsert_ops={"upsert": WriteMap(content=lambda c: str(c.kwargs.get("text", "")))},
        query_ops={
            "query": ReadMap(
                query=lambda c: str(c.kwargs.get("q", "")),
                returned=lambda c: [m["id"] for m in c.result.get("matches", [])],
            )
        },
    )


def test_upsert_is_recorded_and_tagged(forensics: Forensics) -> None:
    db = FakeVectorDB()
    sidecar = _sidecar(forensics, db)

    response = sidecar.handle("upsert", {"text": "a stored fact", "id": "v-1"})

    assert response == {"status": "ok"}
    assert forensics.ledger.count() == 1
    # The forwarded request was tagged with the provenance record id.
    assert PROVENANCE_TAG in db.upserts[0]


def test_query_is_recorded_and_forwarded_unchanged(forensics: Forensics) -> None:
    db = FakeVectorDB()
    sidecar = _sidecar(forensics, db)
    response = sidecar.handle("query", {"q": "find it"})
    assert response == {"matches": [{"id": "v-1", "score": 0.7}]}
    retrieval = next(r for r in forensics.ledger.rows() if r["kind"] == "retrieval")
    assert "v-1" in retrieval["payload_json"]


def test_unmapped_op_passes_through(forensics: Forensics) -> None:
    db = FakeVectorDB()
    sidecar = _sidecar(forensics, db)
    assert sidecar.handle("describe", {}) == {"status": "ok"}
    assert forensics.ledger.count() == 0
