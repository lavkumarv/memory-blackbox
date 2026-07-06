#!/usr/bin/env python3
"""Runnable incident-replay demo.

A thin runner around ``memory_blackbox.demo.run_demo`` so the scenario can be run
directly:

    python examples/incident_demo/run.py

It is equivalent to ``memory-blackbox demo`` and uses a throwaway ledger.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from memory_blackbox.capture.engine import MemoryBlackbox
from memory_blackbox.crypto import keys
from memory_blackbox.demo import run_demo


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        blackbox = MemoryBlackbox.open(Path(tmp) / "demo.db", keys.generate(), detectors=[])
        outcome = run_demo(blackbox)

    print("=== memory-blackbox incident replay ===\n")
    print(f"Poison planted:        {outcome.poison_id}")
    print(
        f"Harmful action taken:  {outcome.harmful_action_id} "
        f"({'HARMFUL' if outcome.harmful_before else 'safe'})"
    )
    traced = "correct" if outcome.trace_primary_id == outcome.poison_id else "mismatch"
    print(f"trace -> root cause:   {outcome.trace_primary_id} ({traced})")
    print(f"blast radius:          {len(outcome.blast)} record(s)")
    print(f"rollback affected:     {len(outcome.rollback_affected)} record(s)")
    print(
        "Re-run after rollback: "
        + ("still harmful" if outcome.harmful_after else "no longer harmful")
    )
    print(f"Ledger integrity:      {'VERIFIED' if outcome.verify_ok else 'TAMPERED'}")


if __name__ == "__main__":
    main()
