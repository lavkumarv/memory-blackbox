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

The two easiest, highest-value contributions:

- **Detectors** — implement the `Detector` protocol (`name`, `inspect`) and add
  it to the pack. ~30 lines plus a test.
- **Adapters** — supply `WriteMap`/`ReadMap` extractors for a new memory backend.

## Licensing

By contributing you agree your contributions are licensed under Apache-2.0 and
sign off your commits (DCO): `git commit -s`.
