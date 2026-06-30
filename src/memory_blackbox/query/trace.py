"""Trace: an action back to the memory writes and sources that caused it.

Walks the provenance DAG backward from an action to its ancestor writes, then
ranks the candidate root causes by suspicion (untrusted first), then recency,
then subgraph centrality (how much each root influenced). The top-ranked root is
the most likely culprit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from memory_blackbox.dag.traverse import backward, forward_closure

if TYPE_CHECKING:
    from memory_blackbox.dag.store import EdgeStore
    from memory_blackbox.ledger.store import LedgerStore

# Lower score = more suspicious = ranked earlier.
_SUSPICION = {
    "quarantined": 0,
    "untrusted": 1,
    "semi_trusted": 2,
    "trusted": 3,
    "system": 4,
}


@dataclass(frozen=True, slots=True)
class TraceRoot:
    """A candidate root-cause write for a traced action."""

    record_id: str
    source_id: str | None
    source_type: str | None
    trust_level: str
    created_at: str
    centrality: int


@dataclass(frozen=True, slots=True)
class ProvenanceTrace:
    """The result of tracing an action to its origins."""

    action_id: str
    roots: list[TraceRoot]
    ancestors: set[str]

    @property
    def primary(self) -> TraceRoot | None:
        return self.roots[0] if self.roots else None


def _recency_key(created_at: str) -> float:
    try:
        return -datetime.fromisoformat(created_at).timestamp()
    except ValueError:
        return 0.0


def trace(ledger: LedgerStore, dag: EdgeStore, action_id: str) -> ProvenanceTrace:
    """Trace ``action_id`` back to ranked candidate root-cause writes."""
    ancestors = backward(dag, action_id)
    roots: list[TraceRoot] = []
    for record_id in ancestors:
        payload = ledger.payload(record_id)
        if payload is None or payload.get("kind") != "write":
            continue
        source = payload.get("source") or {}
        centrality = len(forward_closure(dag, [record_id])) - 1
        roots.append(
            TraceRoot(
                record_id=record_id,
                source_id=source.get("source_id"),
                source_type=source.get("source_type"),
                trust_level=source.get("trust_level", "untrusted"),
                created_at=payload.get("created_at", ""),
                centrality=centrality,
            )
        )
    roots.sort(
        key=lambda r: (
            _SUSPICION.get(r.trust_level, 1),
            _recency_key(r.created_at),
            -r.centrality,
        )
    )
    return ProvenanceTrace(action_id=action_id, roots=roots, ancestors=ancestors)
