# memory-blackbox — Architecture

> **Read this first.** This document is the conceptual model: *what* the system is and *why* it is
> shaped this way. The implementation spec (held privately during development) is the *how to build
> it* companion. Where the two ever disagree about record fields or query algorithms, **this document
> and [`docs/spec.md`](docs/spec.md) are authoritative.**

---

## 1. The problem

AI agents accumulate memory — facts, preferences, procedures — over long horizons. That memory is an
attack surface. A poisoned document ingested in February can plant an instruction that only fires in
April, long after the source is forgotten and the attacker is gone. Runtime guardrails *block* live
attacks; nothing *reconstructs* an incident after the fact: which memory caused this action, where
did it come from, what else did it infect, and how do we undo it without lying to ourselves about the
record.

`memory-blackbox` is the DFIR (digital forensics & incident response) layer for agent memory. It is a
**flight recorder**: it observes every memory read and write, stamps each with tamper-evident
provenance, and lets an investigator replay and reason about what happened.

## 2. Design principles

1. **Append-only, always.** The ledger is never edited or truncated. Rollbacks, redactions, and
   quarantines are themselves new appended events. The forensic record must survive the very attack
   it documents.
2. **Reads are first-class.** A `trace` is impossible if retrievals are not logged. Read capture is
   not optional; a backend whose reads we cannot observe is only half-supported.
3. **Integrity is layered.** A hash-chain proves no row was *edited*. A signed, checkpointed Merkle
   root proves no row was *removed*. Ed25519 signatures prove *who* wrote each row. All three are
   checked by `verify()`.
4. **The signing key is privileged.** It lives in the engine/gateway and is never reachable by the
   agent. Only the public key is exposed to agent-facing surfaces.
5. **Capture is nearly free.** Provenance must add < 1 ms to the write path. Signing and flush may be
   batched or asynchronous, but the caller-visible API stays synchronous.
6. **Local-first.** Everything works offline with zero configuration. Telemetry, anchoring to an
   external transparency log, and hosted features are opt-in.

## 3. Data model (authoritative)

Records are immutable, time-sortable (uuid7 ids), and serialized canonically (see §6) before hashing.
Fields marked **(ledger-set)** are populated by the ledger on append — never supplied by the caller.

### 3.1 Enums

- **`SourceType`** — `user_input`, `tool_output`, `document_ingest`, `rag_retrieval`, `web_fetch`,
  `file_read`, `agent_self`, `inter_agent`, `system_seed`.
- **`TrustLevel`** — `system`, `trusted`, `semi_trusted`, `untrusted`, `quarantined`.
- **`MemoryType`** — `working`, `episodic`, `semantic`, `procedural`, `identity`.
- **`RecordState`** — `active`, `quarantined`, `redacted`, `rolled_back`, `expired`.
- **`EdgeType`** — `DERIVED_FROM`, `RETRIEVED`, `INFLUENCED`, `CONTEXTUALIZED`, `CONTRIBUTED_TO`,
  `ROLLED_BACK_BY`.
- **`Severity`** (findings) — `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

### 3.2 Records

**`Source`** — origin of a memory.
`source_id`, `source_type: SourceType`, `locator` (uri/path, optional), `trust_level: TrustLevel`,
`trust_score: float` (0–1), `first_seen: datetime`, `metadata: dict`.

**`ProvenanceRecord`** — a memory **write**.
`record_id` (uuid7), `namespace`, `memory_id` (backend id, optional), `content`, `content_hash`
(`blake3` of canonical content), `memory_type: MemoryType`, `source: Source`,
`derived_from: list[record_id]`, `caused_by_retrieval: list[retrieval_id]`, `state: RecordState`,
`created_at`, **(ledger-set)** `entry_hash`, `prev_hash`, `signature`, `signer_kid`, `merkle_leaf`.

**`RetrievalRecord`** — a memory **read**.
`retrieval_id` (uuid7), `namespace`, `query`, `query_hash`, `returned: list[record_id]`,
`scores: list[float]`, `session_id`, `turn_id`, `created_at`, **(ledger-set)** chain/sig/merkle fields.

**`ActionRecord`** — an agent action attributable to retrieved context.
`action_id` (uuid7), `namespace`, `kind`, `summary`, `context_retrievals: list[retrieval_id]`,
`turn_id`, `session_id`, `created_at`, **(ledger-set)** chain/sig/merkle fields.

**`RollbackEvent`** — an applied rollback (itself appended).
`rollback_id` (uuid7), `namespace`, `reason`, `to` (timestamp or merkle root), `scope`,
`affected: list[record_id]`, `applied_at`, **(ledger-set)** chain/sig/merkle fields.

**`Finding`** — a detector output.
`finding_id`, `detector_name`, `severity: Severity`, `record_id`, `message`, `evidence: dict`,
`created_at`.

**`Edge`** — a provenance-DAG edge. `src`, `dst`, `edge_type: EdgeType`, `created_at`.

### 3.3 Invariants

- `content_hash == blake3(canonical_content)`, validated on construction.
- Ledger-set fields are populated only on append; values supplied by the caller are ignored/rejected.
- `derived_from` / `caused_by_retrieval` referential integrity is checked at **DAG insert time**.

## 4. Integrity architecture

```
write/read/action  ──>  canonical_bytes  ──>  entry_hash = blake3(payload + prev_hash)
                                                  │
                                                  ├─> Ed25519 signature (engine key)
                                                  ├─> ledger row (append-only SQLite)
                                                  └─> Merkle leaf ──> periodic signed root checkpoint
```

- **Hash-chain** — each row links `prev_hash` to the prior row's `entry_hash`. Editing any payload
  breaks the chain at that row; `verify()` reports the first divergence.
- **Merkle tree** — leaves are the `entry_hash` values. Removing a row changes the recomputed root,
  which no longer matches the last signed checkpoint — that is how deletion is detected.
- **Signatures** — every row is signed by the engine key (`signer_kid` records which key). Forgery
  without the private key is infeasible.
- **Anchoring** (future) — the signed root can be published to an external transparency log
  (Rekor-style) for third-party verifiability. v1 keeps a local signed checkpoint and documents the
  upgrade path.

## 5. Provenance DAG

Nodes are records (writes/reads/actions); edges express lineage (`DERIVED_FROM`, `RETRIEVED`,
`CONTRIBUTED_TO`, …). The graph may contain cycles (agents reference their own memory), so all
traversal is cycle-safe via a visited set.

- **backward(node)** — reverse-edge BFS; the basis of `trace`.
- **forward_closure(seed)** — transitive forward set; the basis of `blast_radius`.

## 6. Canonicalization

Deterministic bytes are the foundation of every hash and signature. `canonical_bytes(obj, exclude)`:
drops excluded (ledger-set) fields, recursively sorts keys, serializes with `orjson`
(`OPT_SORT_KEYS`), UTF-8, no insignificant whitespace. The output must be **identical across processes
and machines** — pinned by a golden-file test.

## 7. Query algorithms

- **`trace(action_id) -> ProvenanceTrace`** — from the action, walk `CONTRIBUTED_TO`/`RETRIEVED`
  edges to its context retrievals, then `DERIVED_FROM` back to origin writes and their sources.
  Rank candidate roots by: **untrusted first**, then **recency**, then **subgraph centrality**. The
  top-ranked root is the most likely culprit.
- **`blast_radius(source_selector) -> set[Record]`** — resolve the selector to seed writes, then take
  the forward closure over lineage edges: every record the poison could have influenced.
- **`drift(topic_or_cluster) -> list[DriftEvent]`** — within a semantic cluster, detect consensus
  flips over time, attributing each flip to the write (and source) that caused it.
- **`timeline(topic) -> list[Event]`** — the chronologically ordered narrative of writes, reads, and
  actions touching a topic.
- **`verify() -> IntegrityReport`** — checks the chain, the Merkle root vs. the signed checkpoint, and
  every signature; reports the first divergence (edit / gap / deletion / forgery) or a clean result.
- **`rollback(to, scope, dry_run=True) -> RollbackPlan`** — compute the poison plus its forward
  closure; a dry run returns the plan without mutating anything. Applying it sets those records'
  state to `rolled_back`, appends a `RollbackEvent` with `ROLLED_BACK_BY` edges, and **deletes
  nothing**. `verify()` still passes afterward.

## 8. Capture & integration

One engine (`Forensics`) records writes/reads/actions; three ways to feed it:

- **Library wrapper** — wrap a memory client in-process; an adapter maps the backend's
  add/search/get/delete onto `record_write` / `record_retrieval`.
- **MCP gateway** — an MCP proxy that forwards `tools/call` to a real memory MCP server while logging
  every call. Backend-agnostic; the highest-leverage coverage.
- **Sidecar** — an HTTP/gRPC reverse proxy in front of a hosted vector DB.

**reconcile** scans a backend for entries that have no corresponding ledger record — the safety net
that catches capture-bypass writes. It is a first-class, prominent feature, not an afterthought.

## 9. Threat model

See [`docs/threat-model.md`](docs/threat-model.md). In brief: the adversary can poison sources and
write to memory, and may try to erase the trail — but cannot reach the signing key and cannot edit,
gap, or delete ledger rows without `verify()` detecting it.
