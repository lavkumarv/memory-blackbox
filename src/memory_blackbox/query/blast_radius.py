"""Blast radius: the forward closure of a poisoned source.

Resolves a source selector to its seed writes, then returns every record those
seeds could have influenced via the provenance DAG.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from memory_blackbox.dag.traverse import forward_closure

if TYPE_CHECKING:
    from memory_blackbox.dag.store import EdgeStore
    from memory_blackbox.ledger.store import LedgerStore


def _source_matches(payload: dict[str, Any], selector: str) -> bool:
    source = payload.get("source") or {}
    return selector in (
        payload.get("record_id"),
        source.get("source_id"),
        source.get("source_type"),
        source.get("locator"),
    )


def seeds_for(ledger: LedgerStore, selector: str) -> set[str]:
    """Return the write record ids whose source (or id) matches ``selector``."""
    seeds: set[str] = set()
    for row, payload in ledger.iter_payloads():
        if payload.get("kind") == "write" and _source_matches(payload, selector):
            seeds.add(row["record_id"])
    return seeds


def blast_radius(ledger: LedgerStore, dag: EdgeStore, source_selector: str) -> set[str]:
    """Return the set of record ids influenced by the matching source (incl. seeds)."""
    seeds = seeds_for(ledger, source_selector)
    if not seeds:
        return set()
    return forward_closure(dag, seeds)
