"""Detector: a write that contradicts the trusted consensus of its cluster.

The query-side `drift` reconstructs drift events from the whole ledger; this is
its streaming counterpart. It remembers the embeddings of past writes per
namespace and, when an untrusted write lands in a topic cluster dominated by
trusted writes but diverges from their centroid, flags it at write time.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from memory_blackbox.embedding import HashingEmbedder, centroid, cosine
from memory_blackbox.model.records import Finding, Severity, TrustLevel

if TYPE_CHECKING:
    from memory_blackbox.detectors.base import DetectorContext
    from memory_blackbox.embedding import Embedder, Vector
    from memory_blackbox.model.records import ProvenanceRecord

_TRUSTED = {TrustLevel.trusted, TrustLevel.system}
_SUSPECT = {TrustLevel.untrusted, TrustLevel.quarantined, TrustLevel.semi_trusted}


class DriftDetector:
    name = "drift"

    def __init__(
        self,
        embedder: Embedder | None = None,
        *,
        cluster_threshold: float = 0.5,
        contradiction_threshold: float = 0.8,
    ) -> None:
        self.embedder = embedder or HashingEmbedder()
        self.cluster_threshold = cluster_threshold
        self.contradiction_threshold = contradiction_threshold
        self._trusted: dict[str, list[Vector]] = defaultdict(list)

    def inspect(
        self, record: ProvenanceRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]:
        vector = self.embedder.embed(content)
        level = record.source.trust_level
        findings: list[Finding] = []

        neighbors = [
            vec
            for vec in self._trusted[ctx.namespace]
            if cosine(vec, vector) >= self.cluster_threshold
        ]
        if level in _SUSPECT and neighbors:
            similarity = cosine(vector, centroid(neighbors))
            if similarity < self.contradiction_threshold:
                findings.append(
                    Finding(
                        detector_name=self.name,
                        severity=Severity.HIGH,
                        record_id=record.record_id,
                        message="write contradicts the trusted consensus of its topic cluster",
                        evidence={
                            "source_id": record.source.source_id,
                            "similarity": round(similarity, 4),
                        },
                    )
                )

        if level in _TRUSTED:
            self._trusted[ctx.namespace].append(vector)
        return findings
