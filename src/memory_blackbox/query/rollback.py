"""Rollback: quarantine a poisoned source and everything it influenced.

Rollback never deletes or edits ledger rows. It computes the poison plus its
forward closure, and -- when applied -- appends a RollbackEvent and ROLLED_BACK_BY
edges. A record's effective state is *derived*: it is rolled back if any later
RollbackEvent lists it. ``verify()`` therefore still passes after a rollback,
because the forensic record was only appended to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from memory_blackbox.dag.traverse import forward_closure
from memory_blackbox.model.edges import EdgeType
from memory_blackbox.model.records import RecordState, RollbackEvent
from memory_blackbox.query.blast_radius import seeds_for

if TYPE_CHECKING:
    from memory_blackbox.dag.store import EdgeStore
    from memory_blackbox.ledger.store import LedgerStore


@dataclass(frozen=True, slots=True)
class RollbackPlan:
    """A dry-run (or applied) rollback plan."""

    to: str
    scope: str | None
    affected: list[str]
    dry_run: bool
    applied: bool = False
    rollback_id: str | None = None
    reason: str = ""

    @property
    def count(self) -> int:
        return len(self.affected)


def _in_scope(ledger: LedgerStore, record_id: str, scope: str | None) -> bool:
    if scope is None:
        return True
    payload = ledger.payload(record_id)
    return payload is not None and payload.get("namespace") == scope


def _affected(ledger: LedgerStore, dag: EdgeStore, to: str, scope: str | None) -> list[str]:
    seeds = seeds_for(ledger, to)
    if ledger.get(to) is not None:
        seeds.add(to)
    closure = forward_closure(dag, seeds)
    return sorted(rid for rid in closure if _in_scope(ledger, rid, scope))


def rolled_back_ids(ledger: LedgerStore) -> set[str]:
    """Return the set of record ids quarantined by any RollbackEvent."""
    ids: set[str] = set()
    for _row, payload in ledger.iter_payloads():
        if payload.get("kind") == "rollback":
            ids.update(payload.get("affected", []))
    return ids


def effective_state(ledger: LedgerStore, record_id: str) -> str:
    """Return the derived state of a record (rolled_back overrides active)."""
    if record_id in rolled_back_ids(ledger):
        return RecordState.rolled_back.value
    payload = ledger.payload(record_id)
    if payload is None:
        return RecordState.expired.value
    return str(payload.get("state", RecordState.active.value))


def rollback(
    ledger: LedgerStore,
    dag: EdgeStore,
    to: str,
    *,
    scope: str | None = None,
    dry_run: bool = True,
    reason: str = "",
) -> RollbackPlan:
    """Plan (and optionally apply) a rollback of ``to`` and its forward closure."""
    affected = _affected(ledger, dag, to, scope)
    if dry_run:
        return RollbackPlan(to=to, scope=scope, affected=affected, dry_run=True, reason=reason)

    event = RollbackEvent(
        reason=reason,
        to=to,
        scope=scope,
        affected=affected,
        namespace=scope or "default",
    )
    ledger.append(event)
    for record_id in affected:
        if ledger.get(record_id) is not None:
            dag.add_edge(record_id, event.rollback_id, EdgeType.ROLLED_BACK_BY)
    return RollbackPlan(
        to=to,
        scope=scope,
        affected=affected,
        dry_run=False,
        applied=True,
        rollback_id=event.rollback_id,
        reason=reason,
    )
