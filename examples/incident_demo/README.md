# Incident demo

The one-command incident replay. A poisoned document is planted in agent memory,
a later turn retrieves it and takes a harmful action, and `memory-blackbox` traces
it to the exact poisoned memory, shows the blast radius, rolls it back, and proves
the re-run is no longer harmful — all while the tamper-evident ledger keeps
verifying.

```bash
memory-blackbox demo
```

The scenario lives in `memory_blackbox.demo` (so it is also the basis of the
end-to-end test `tests/e2e/test_incident_replay.py`). `run.py` here is a thin
runner around it.
