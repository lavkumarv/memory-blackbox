"""Performance and scale checks (spec §15.13).

Run at a CI-friendly size; the bounds are generous and exist to catch order-of-
magnitude regressions, not to micro-benchmark. The 1M-row target is documented;
this asserts linear-ish behavior at a fraction of it.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_forensics.crypto import keys
from agent_forensics.ledger.store import LedgerStore
from agent_forensics.merkle.tree import verify_merkle
from agent_forensics.model.records import ProvenanceRecord, Source, SourceType
from agent_forensics.query.verify import verify

ROWS = 5_000


@pytest.mark.perf
def test_verify_scales_to_many_rows(tmp_path: Path) -> None:
    store = LedgerStore(
        tmp_path / "scale.db", keys.generate(), checkpoint_every=0, synchronous="OFF"
    )
    source = Source(source_type=SourceType.user_input)
    for i in range(ROWS):
        store.append(ProvenanceRecord(content=f"entry-{i}", source=source))
    store.checkpoint()

    start = time.perf_counter()
    from agent_forensics.ledger.chain import verify_chain

    chain = verify_chain(store.connection, store.public_key)
    merkle = verify_merkle(store.connection, store.public_key)
    elapsed = time.perf_counter() - start

    assert chain.ok and chain.rows_checked == ROWS
    assert merkle.ok
    # Generous bound: full chain + Merkle verification of 5k rows well under 5s.
    assert elapsed < 5.0


@pytest.mark.perf
def test_merkle_state_is_bounded_by_checkpointing(tmp_path: Path) -> None:
    # With cadence-based checkpoints the in-memory leaf cache is the only growth;
    # the checkpoint table stays small (one row per cadence interval).
    store = LedgerStore(tmp_path / "cp.db", keys.generate(), checkpoint_every=500)
    source = Source(source_type=SourceType.user_input)
    for i in range(2_000):
        store.append(ProvenanceRecord(content=f"e-{i}", source=source))
    checkpoints = store.connection.execute("SELECT COUNT(*) FROM merkle_checkpoints").fetchone()[0]
    assert checkpoints == 4  # 2000 / 500


@pytest.mark.perf
def test_verify_full_engine_after_scale(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path / "v.db", keys.generate(), checkpoint_every=256)
    source = Source(source_type=SourceType.user_input)
    for i in range(1_000):
        store.append(ProvenanceRecord(content=f"row-{i}", source=source))
    store.checkpoint()
    assert verify(store).ok
