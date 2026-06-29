# agent-forensics

> A flight recorder for AI agent memory. When an agent does something bad, trace it back to the
> exact poisoned memory, see the blast radius, and roll it back — without changing how your agent runs.

**agent-forensics** is the DFIR (digital forensics & incident response) layer for AI agent memory.
It intercepts every memory **read** and **write** an agent performs, stamps each with
cryptographically-signed, tamper-evident provenance, and stores those records in an append-only
ledger plus a provenance DAG. After an incident it can trace an action back to the originating
memory write and its source, compute the blast radius of a poisoned source, detect belief drift,
verify the ledger has not been tampered with, and produce a rollback plan.

## Quickstart

```bash
pipx install agent-forensics
agent-forensics init      # create the ledger, signing key, and profile
agent-forensics demo      # plant a poison, then trace, blast-radius, and roll it back
```

`demo` runs the full incident replay end-to-end with zero configuration: a
poisoned document is planted, a later turn retrieves it and acts harmfully, and
the tool traces it to the exact memory, shows the blast radius, rolls it back, and
proves the re-run is no longer harmful — all while the ledger keeps verifying.

## What it does

- **trace** — walk any agent action back to the memory writes and sources that caused it.
- **blast-radius** — compute the forward closure of a poisoned source.
- **drift** — detect when a write contradicts the trusted majority of its semantic cluster.
- **verify** — prove the ledger has not been edited, gapped, or had rows removed.
- **rollback** — produce (and apply) a plan that quarantines poison without deleting history.

## How it integrates

Three capture paths, all backed by the same append-only ledger:

- **Library wrapper** — wrap your memory client in-process (adapters for Mem0,
  Chroma, Letta, pgvector, and the `MEMORY.md`/`CLAUDE.md`/`AGENTS.md` file surface).
- **MCP gateway** — proxy an MCP memory server; backend-agnostic.
- **Sidecar** — reverse proxy in front of a hosted vector DB (Pinecone, Qdrant,
  Weaviate, Mongo Atlas).

`agent-forensics reconcile` is the honesty check: it flags backend entries that
have no ledger record (writes that bypassed capture).

## Integrity model

The ledger is **append-only**: rollbacks append new events, never edit or delete. A BLAKE3
hash-chain proves no row was edited; a periodically-checkpointed, signed Merkle root proves no row
was removed. Every entry is Ed25519-signed by a key the agent never sees.

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run mypy
```

## License

Apache-2.0. See [LICENSE](LICENSE).
