"""Tests for the query engine: trace, blast, timeline, verify, rollback (spec §15.6)."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from memory_blackbox.capture.engine import MemoryBlackbox
from memory_blackbox.crypto import keys
from memory_blackbox.model.records import Source, SourceType, TrustLevel
from memory_blackbox.query.blast_radius import blast_radius
from memory_blackbox.query.drift import drift
from memory_blackbox.query.rollback import effective_state, rollback, rolled_back_ids
from memory_blackbox.query.timeline import timeline
from memory_blackbox.query.trace import trace
from memory_blackbox.query.verify import verify


@dataclass
class Incident:
    blackbox: MemoryBlackbox
    poison: str
    derived: str
    retrieval: str
    action: str


@pytest.fixture
def incident(tmp_path: Path) -> Incident:
    f = MemoryBlackbox.open(tmp_path / "ledger.db", keys.generate())
    poison_src = Source(
        source_id="evil-doc",
        source_type=SourceType.document_ingest,
        trust_level=TrustLevel.untrusted,
    )
    good_src = Source(
        source_id="user", source_type=SourceType.user_input, trust_level=TrustLevel.trusted
    )
    p = f.record_write("poison about France", poison_src, namespace="t")
    d = f.record_write("derived note", good_src, namespace="t", derived_from=[p.record_id])
    r = f.record_retrieval("France?", returned=[d.record_id], scores=[0.9], namespace="t")
    a = f.record_action(
        "email.send", "sent France info", context_retrievals=[r.retrieval_id], namespace="t"
    )
    return Incident(f, p.record_id, d.record_id, r.retrieval_id, a.action_id)


def test_trace_returns_poison_root_ranked_first(incident: Incident) -> None:
    result = trace(incident.blackbox.ledger, incident.blackbox.dag, incident.action)
    assert result.primary is not None
    assert result.primary.record_id == incident.poison
    assert result.primary.trust_level == "untrusted"
    assert incident.poison in result.ancestors


def test_blast_radius_equals_hand_computed_set(incident: Incident) -> None:
    affected = blast_radius(incident.blackbox.ledger, incident.blackbox.dag, "evil-doc")
    assert affected == {incident.poison, incident.derived, incident.retrieval, incident.action}


def test_blast_radius_unknown_source_is_empty(incident: Incident) -> None:
    assert blast_radius(incident.blackbox.ledger, incident.blackbox.dag, "ghost") == set()


def test_timeline_is_chronological(incident: Incident) -> None:
    events = timeline(incident.blackbox.ledger, "France")
    assert [e.timestamp for e in events] == sorted(e.timestamp for e in events)
    assert events[0].record_id == incident.poison


def test_verify_passes_on_clean_ledger(incident: Incident) -> None:
    assert verify(incident.blackbox.ledger).ok


def test_rollback_dry_run_lists_poison_and_closure(incident: Incident) -> None:
    plan = rollback(incident.blackbox.ledger, incident.blackbox.dag, "evil-doc", scope="t")
    assert plan.dry_run and not plan.applied
    assert set(plan.affected) == {
        incident.poison,
        incident.derived,
        incident.retrieval,
        incident.action,
    }


def test_rollback_apply_marks_rolled_back_and_preserves_verify(incident: Incident) -> None:
    ledger = incident.blackbox.ledger
    before = ledger.count()

    applied = rollback(
        ledger, incident.blackbox.dag, "evil-doc", scope="t", dry_run=False, reason="poison"
    )
    assert applied.applied and applied.rollback_id is not None

    # Affected records are derived as rolled_back...
    assert rolled_back_ids(ledger) == set(applied.affected)
    assert effective_state(ledger, incident.poison) == "rolled_back"
    # ...via an appended rollback event, with no deleted rows...
    assert ledger.count() == before + 1
    # ...and the ledger still verifies (the attack never corrupted the record).
    assert verify(ledger).ok


def test_rollback_scope_filters_namespace(tmp_path: Path) -> None:
    f = MemoryBlackbox.open(tmp_path / "l.db", keys.generate())
    src = Source(source_id="s", source_type=SourceType.document_ingest)
    a = f.record_write("in scope", src, namespace="ns1")
    f.record_write("out of scope", src, namespace="ns2")
    plan = rollback(f.ledger, f.dag, "s", scope="ns1")
    assert plan.affected == [a.record_id]


def test_verify_detects_tamper_through_query(tmp_path: Path) -> None:
    f = MemoryBlackbox.open(tmp_path / "l.db", keys.generate())
    src = Source(source_id="s", source_type=SourceType.user_input)
    for i in range(3):
        f.record_write(f"e{i}", src)
    public_key = f.ledger.public_key
    f.ledger.close()

    con = sqlite3.connect(str(tmp_path / "l.db"))
    con.executescript("DROP TRIGGER IF EXISTS ledger_no_update;")
    con.execute("UPDATE ledger SET payload_json = '{\"x\":1}' WHERE seq = 2")
    con.commit()

    from memory_blackbox.ledger.chain import verify_chain

    assert not verify_chain(con, public_key).ok
    con.close()


def test_drift_placeholder_returns_empty(incident: Incident) -> None:
    assert drift(incident.blackbox.ledger, "France") == []


def test_integrity_report_summary_ok_and_tampered(tmp_path: Path) -> None:
    f = MemoryBlackbox.open(tmp_path / "l.db", keys.generate())
    src = Source(source_id="s", source_type=SourceType.user_input)
    for i in range(3):
        f.record_write(f"e{i}", src)
    assert "ok" in verify(f.ledger).summary
    public_key = f.ledger.public_key
    f.ledger.close()

    con = sqlite3.connect(str(tmp_path / "l.db"))
    con.executescript("DROP TRIGGER IF EXISTS ledger_no_update;")
    con.execute("UPDATE ledger SET payload_json = '{\"x\":1}' WHERE seq = 2")
    con.commit()
    con.close()

    reopened = MemoryBlackbox.open(tmp_path / "l.db", keys.generate())
    report = verify(reopened.ledger, public_key)
    assert not report.ok
    assert "edit" in report.summary


def test_rollback_by_record_id_with_no_scope(incident: Incident) -> None:
    # `to` is a concrete record id (not a source selector); scope=None covers all namespaces.
    plan = rollback(
        incident.blackbox.ledger,
        incident.blackbox.dag,
        incident.poison,
        scope=None,
        dry_run=False,
    )
    assert incident.poison in plan.affected
    assert plan.applied


def test_effective_state_active_and_unknown(incident: Incident) -> None:
    # A record not touched by any rollback is active; an unknown id is expired.
    assert effective_state(incident.blackbox.ledger, incident.poison) == "active"
    assert effective_state(incident.blackbox.ledger, "no-such-id") == "expired"
