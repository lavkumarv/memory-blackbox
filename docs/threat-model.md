# Threat Model

> Status: draft skeleton. Expanded as detectors and capture paths land. Detectors are mapped to
> standard taxonomies (OWASP Agentic / ASI06 Memory & Context Poisoning, CoSAI MCP threat catalog)
> as those mappings are finalized.

## Assets

- **The forensic record** — the append-only ledger, hash-chain, Merkle root, and DAG. Its integrity
  *is* the product.
- **The signing key** — whoever holds it can forge provenance. Most sensitive secret in the system.
- **Agent memory content** — may contain PII, secrets, and proprietary logic.

## Adversary capabilities (in scope)

- Poison a source (e.g. a `document_ingest` or `web_fetch`) that the agent later trusts.
- Write to memory through a captured path.
- Attempt to **erase or rewrite the trail**: edit a ledger row, delete a row, or forge a signature.
- Attempt **capture bypass**: write directly to the backend, skipping the wrapper.
- Smuggle instructions via Unicode (zero-width / bidi) or injection phrasing.

## Out of scope (v1)

- Compromise of the host holding the signing key (treated as total compromise; mitigated by KMS/HSM
  in server profiles).
- Side-channel attacks on the crypto primitives.
- Availability/DoS of the backend store itself.

## Mitigations (and where they live)

| Threat | Mitigation | Component |
|--------|-----------|-----------|
| Ledger row edited | BLAKE3 hash-chain; `verify()` reports first divergence | `ledger/chain.py` |
| Ledger row deleted | Signed, checkpointed Merkle root; recomputed root mismatches | `merkle/` |
| Signature forged | Ed25519 over entry hash; key never agent-reachable | `crypto/` |
| Capture bypass | `reconcile` scan flags backend entries with no ledger record | `query` + CLI |
| Missing provenance | `provenance_missing` detector | `detectors/` |
| Instruction smuggling | `injection_scan`, `unicode_smuggling` detectors | `detectors/` |
| Source poisoning over time | `trust_scoring`, `drift`, `write_rate` detectors | `detectors/` |
| Key at rest | 0600 file (local) / KMS/HSM (server); only public key exposed | `crypto/keys.py` |
| Sensitive content at rest | encryption-at-rest, hash-only storage, redaction (planned) | roadmap |

## Residual risk

- The window between an event and its Merkle-root checkpoint is a small gap; checkpoint cadence is a
  tunable trade-off between overhead and tamper-detection latency. External anchoring closes the gap
  for high-assurance deployments.
- **Checkpoint truncation under raw file access (v1).** With the local-only `NoOpAnchor`, verification
  trusts the latest local signed checkpoint. An attacker with raw database access who deletes the
  latest checkpoint rows can truncate the ledger back to an earlier checkpoint and pass both chain and
  Merkle verification — without forging the signing key. Edits, gaps, and truncation *past* the latest
  checkpoint are still caught. External anchoring (publishing roots to a transparency log) is the
  documented mitigation and removes this gap; see `merkle/anchor.py`.
