#!/usr/bin/env python3
"""Sidecar example.

The sidecar is a reverse proxy in front of a hosted vector DB (Pinecone, Qdrant
Cloud, Weaviate, Mongo Atlas). It intercepts upsert (write) and query (read)
operations, records provenance, and forwards the request upstream — returning the
response unchanged. Upserts are *tagged* with the provenance record id so the
stored vector carries a back-reference to its ledger entry.

Run it:

    python examples/sidecar/run.py

Here the upstream is a tiny in-process fake; in production `forward` would call
your hosted vector DB's HTTP/gRPC API.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from memory_blackbox.capture.engine import MemoryBlackbox
from memory_blackbox.capture.sidecar import PROVENANCE_TAG, Sidecar
from memory_blackbox.capture.wrapper import ReadMap, WriteMap
from memory_blackbox.crypto import keys
from memory_blackbox.model.records import Source, SourceType, TrustLevel


class FakeVectorDB:
    """Stands in for a hosted vector DB (upsert/query)."""

    def __init__(self) -> None:
        self.last_upsert: dict[str, Any] = {}

    def __call__(self, op: str, payload: dict[str, Any]) -> Any:
        if op == "upsert":
            self.last_upsert = payload
            return {"status": "ok", "upserted": 1}
        if op == "query":
            return {"matches": [{"id": "vec-1", "score": 0.74}]}
        return {"status": "ok"}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        blackbox = MemoryBlackbox.open(Path(tmp) / "sidecar.db", keys.generate(), detectors=[])
        vector_db = FakeVectorDB()

        sidecar = Sidecar(
            blackbox,
            vector_db,  # forward(op, payload) -> result
            namespace="agent",
            default_source=Source(
                source_id="vector-store",
                source_type=SourceType.rag_retrieval,
                trust_level=TrustLevel.semi_trusted,
                locator="https://my-index.vector-db.example",
            ),
            upsert_ops={
                "upsert": WriteMap(content=lambda c: str(c.kwargs.get("text", ""))),
            },
            query_ops={
                "query": ReadMap(
                    query=lambda c: str(c.kwargs.get("q", "")),
                    returned=lambda c: [m["id"] for m in c.result.get("matches", [])],
                ),
            },
        )

        upserted = sidecar.handle("upsert", {"text": "onboarding policy v2", "id": "vec-1"})
        queried = sidecar.handle("query", {"q": "onboarding policy"})

    print("Upstream responses are forwarded:")
    print("  upsert ->", upserted)
    print("  query  ->", queried)
    print(f"\nThe forwarded upsert was tagged with '{PROVENANCE_TAG}':")
    print("  ", vector_db.last_upsert)
    print(f"\nProvenance captured: {blackbox.ledger.count()} ledger record(s), signed and chained.")


if __name__ == "__main__":
    main()
