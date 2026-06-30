# Extending memory-blackbox

The two highest-value contributions are **detectors** (a new signal to flag in stored
memory) and **adapters** (capture for a new memory backend). Both are ~20–30 lines.

## Add a detector

Copy [`detector_template.py`](detector_template.py), give it a unique `name`, and
implement `inspect(record, content, ctx) -> list[Finding]`.

```bash
python examples/extending/detector_template.py
```

Map your detector to a threat category in [`../../docs/threat-mapping.md`](../../docs/threat-mapping.md).

## Add an adapter

Copy [`adapter_template.py`](adapter_template.py) and declare your backend's write/read
methods and how to read their arguments and results (`WriteMap`/`ReadMap`).

```bash
python examples/extending/adapter_template.py
```

A backend is only fully supported if its **reads** are captured too (otherwise `trace`
breaks) — always provide `read_methods`, and add a round-trip test.
