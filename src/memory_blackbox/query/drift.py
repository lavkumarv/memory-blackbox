"""Drift: detect when an untrusted write contradicts the trusted consensus.

For a topic, gather the writes about it (embedding similarity above a cluster
threshold), form the centroid of the *trusted* members as the consensus, and flag
any untrusted write that sits in the topic cluster yet diverges from that
consensus (similarity below a contradiction threshold). Events are returned in
chronological order, each pointing at the offending source.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from memory_blackbox.embedding import HashingEmbedder, centroid, cosine

if TYPE_CHECKING:
    from memory_blackbox.embedding import Embedder, Vector
    from memory_blackbox.ledger.store import LedgerStore

_TRUSTED = {"trusted", "system"}
_SUSPECT = {"untrusted", "quarantined", "semi_trusted"}


@dataclass(frozen=True, slots=True)
class DriftEvent:
    """A point where an untrusted write diverged from the trusted consensus."""

    topic: str
    record_id: str
    source_id: str | None
    timestamp: str
    similarity: float
    detail: str


def drift(
    ledger: LedgerStore,
    topic_or_cluster: str,
    embedder: Embedder | None = None,
    *,
    cluster_threshold: float = 0.5,
    contradiction_threshold: float = 0.8,
) -> list[DriftEvent]:
    """Return consensus-flip events for a topic, in chronological order."""
    emb = embedder or HashingEmbedder()
    topic_vec = emb.embed(topic_or_cluster)

    cluster: list[tuple[str, dict[str, Any], Vector, str]] = []
    for row, payload in ledger.iter_payloads():
        if payload.get("kind") != "write":
            continue
        vector = emb.embed(str(payload.get("content", "")))
        if cosine(topic_vec, vector) >= cluster_threshold:
            trust = (payload.get("source") or {}).get("trust_level", "untrusted")
            cluster.append((row["record_id"], payload, vector, trust))

    trusted_vectors = [vec for _id, _p, vec, trust in cluster if trust in _TRUSTED]
    if not trusted_vectors:
        return []
    consensus = centroid(trusted_vectors)

    events: list[DriftEvent] = []
    for record_id, payload, vector, trust in cluster:
        if trust not in _SUSPECT:
            continue
        similarity = cosine(vector, consensus)
        if similarity < contradiction_threshold:
            source = payload.get("source") or {}
            events.append(
                DriftEvent(
                    topic=topic_or_cluster,
                    record_id=record_id,
                    source_id=source.get("source_id"),
                    timestamp=str(payload.get("created_at", "")),
                    similarity=round(similarity, 4),
                    detail="untrusted write diverges from the trusted consensus on this topic",
                )
            )
    events.sort(key=lambda e: e.timestamp)
    return events
