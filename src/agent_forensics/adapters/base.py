"""Adapter protocol and reconciliation.

An adapter declares how to capture a specific memory backend: which methods are
writes vs reads, and how to pull content/ids/query/scores out of each call (the
WriteMap/ReadMap extractors the generic wrapper applies). Adapters carry no SDK
import at module load; the concrete ones lazy-import their SDK only if used.

Reconciliation is the honesty check: it finds backend entries that have no
corresponding ledger record (writes that bypassed capture).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_forensics.capture.wrapper import ReadMap, WriteMap
    from agent_forensics.ledger.store import LedgerStore


@dataclass(frozen=True, slots=True)
class Adapter:
    """A capture mapping for a specific memory backend."""

    backend_name: str
    write_methods: dict[str, WriteMap]
    read_methods: dict[str, ReadMap]
    embed: Callable[[str], list[float] | None] | None = field(default=None)


def ledger_memory_ids(ledger: LedgerStore) -> set[str]:
    """Return every backend ``memory_id`` recorded by a ledger write."""
    ids: set[str] = set()
    for _row, payload in ledger.iter_payloads():
        if payload.get("kind") == "write" and payload.get("memory_id"):
            ids.add(str(payload["memory_id"]))
    return ids


def reconcile(ledger: LedgerStore, backend_ids: Iterable[str]) -> list[str]:
    """Return backend ids that have no corresponding ledger write (orphans)."""
    known = ledger_memory_ids(ledger)
    return [bid for bid in backend_ids if bid not in known]
