# Contributing

Thanks for your interest in `agent-forensics`.

## Development

```bash
uv sync --all-extras
uv run pytest            # tests
uv run ruff check .      # lint
uv run ruff format .     # format
uv run mypy              # types (strict)
make check               # lint + types + tests
```

All changes must keep the suite green, `mypy --strict` and `ruff` clean, and
core-package coverage at or above 90%.

## Hard rules (non-negotiable)

- The ledger is **append-only** — never UPDATE or DELETE ledger rows. Rollbacks
  append new events.
- Reads are logged as **first-class events**.
- Keep provenance write overhead **under 1 ms** (sign/flush may be async).
- The signing key never reaches agent-facing code.
- Keep core dependencies minimal.

## Extending

The two easiest, highest-value contributions, each ~20–30 lines with a copy-paste
template in [`examples/extending/`](examples/extending/):

- **Detectors** — implement the `Detector` protocol (`name`, `inspect`) and add it
  to the pack. Start from [`detector_template.py`](examples/extending/detector_template.py)
  and map it to a threat category in [`docs/threat-mapping.md`](docs/threat-mapping.md).
- **Adapters** — supply `WriteMap`/`ReadMap` extractors for a new memory backend.
  Start from [`adapter_template.py`](examples/extending/adapter_template.py). Capture
  **reads** too, or `trace` breaks — add a round-trip test.

## Licensing

By contributing you agree your contributions are licensed under Apache-2.0 and you
sign off your commits under the [Developer Certificate of Origin](DCO.md):
`git commit -s`.
