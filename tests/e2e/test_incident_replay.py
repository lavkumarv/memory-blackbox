"""End-to-end incident replay -- the headline test (spec §15.12).

This test *is* the demo: a poisoned document is planted, a later turn retrieves it
and acts harmfully, and the toolkit traces, scopes, and rolls back the incident,
after which the re-run is no longer harmful and the ledger still verifies.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from memory_blackbox.capture.engine import Forensics
from memory_blackbox.crypto import keys
from memory_blackbox.demo import DemoOutcome, run_demo
from memory_blackbox.query.verify import verify


@pytest.fixture
def outcome(tmp_path: Path) -> DemoOutcome:
    forensics = Forensics.open(tmp_path / "ledger.db", keys.generate(), detectors=[])
    return run_demo(forensics)


def test_harmful_action_occurs_before_rollback(outcome: DemoOutcome) -> None:
    assert outcome.harmful_before is True


def test_trace_identifies_the_poison_root(outcome: DemoOutcome) -> None:
    assert outcome.trace_primary_id == outcome.poison_id


def test_blast_radius_covers_poison_and_action(outcome: DemoOutcome) -> None:
    assert outcome.poison_id in outcome.blast
    assert outcome.harmful_action_id in outcome.blast


def test_rollback_targets_the_poison(outcome: DemoOutcome) -> None:
    assert outcome.poison_id in outcome.rollback_affected


def test_rerun_after_rollback_is_no_longer_harmful(outcome: DemoOutcome) -> None:
    assert outcome.harmful_after is False


def test_ledger_verifies_throughout(outcome: DemoOutcome) -> None:
    assert outcome.verify_ok is True


def test_rollback_did_not_delete_history(tmp_path: Path) -> None:
    # Append-only holds: rollback appends a RollbackEvent rather than deleting.
    forensics = Forensics.open(tmp_path / "l.db", keys.generate(), detectors=[])
    before_writes = forensics.ledger.count()
    run_demo(forensics)
    # Many rows added, none removed, and the chain + Merkle still verify.
    assert forensics.ledger.count() > before_writes
    assert verify(forensics.ledger).ok
