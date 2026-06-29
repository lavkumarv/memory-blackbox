# Roadmap

What is built today and what is planned. The tamper-evident ledger, provenance DAG,
query engine, detector pack, adapters, MCP gateway, sidecar, and CLI are implemented
and tested. The items below are deliberate, scoped follow-ups — listed so intent is
explicit rather than implied.

## Built (v0)

- Append-only ledger: BLAKE3 hash-chain, signed Merkle checkpoints (deletion +
  tail-truncation detection), Ed25519 signatures, `verify`.
- Provenance DAG + queries: `trace`, `blast-radius`, `drift`, `timeline`, `verify`,
  `rollback` (append-only).
- Detector pack: provenance_missing, injection_scan, unicode_smuggling, secrets_pii,
  write_rate, trust_scoring, drift.
- Capture: library wrapper (Mem0, Chroma, Letta, pgvector, memory.md), MCP gateway,
  sidecar; `reconcile` for capture-bypass detection.
- CLI, exporters (Markdown/Mermaid/DOT/SARIF), one-command incident demo.
- Supply chain: signed releases (Sigstore), SLSA provenance, SBOM, Dependabot, CodeQL.

## Integrity & assurance

- **External transparency-log anchoring** (Rekor-style). Closes the v1 limitation
  where a raw-file-access attacker can truncate the ledger back to an earlier local
  checkpoint. The `Anchor` protocol is the seam; this ships a real backend.
- **KMS/HSM-backed signing keys** for server profiles (the `load_from_kms` hook).

## Privacy & compliance

- **Encryption-at-rest** for the ledger/snapshots (AES-256-GCM; encrypted-SQLite).
- **Redaction disposition** — preserve the provenance record (hash + metadata) while
  scrubbing sensitive content flagged by `secrets_pii`.
- **Crypto-shredding** for right-to-erasure: per-subject content keys, delete the key
  to render content irrecoverable while keeping the chain intact (resolves the
  append-only vs. GDPR-erasure tension).
- **Hash-only storage mode** — store `content_hash` + metadata, raw content by
  reference, for highly sensitive entries.

## Scale & operations

- **Retention / TTL policy** and **cold archival** for high-frequency working memory,
  so append-only growth stays bounded in large deployments.
- Incremental Merkle (mountain-range) state for very large ledgers.

## Ecosystem

- Tier-2 adapters (CrewAI, LangGraph, Pinecone/Qdrant/Weaviate/Mongo native clients,
  Vercel AI SDK).
- Detector-pack plugin discovery via entry points (the registry exists; document and
  publish the SDK).
- Standards alignment: keep [`docs/threat-mapping.md`](docs/threat-mapping.md) current
  with OWASP ASI / MITRE ATLAS / CoSAI as they evolve.

Have a use case that needs one of these sooner? Open an issue — production needs
reprioritize the list.
