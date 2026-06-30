# ProvenanceRecord Specification

> **Schema version: 1 (draft).** This document is the versioned, authoritative record schema. The
> wire/storage representation is stabilized here so that ledgers remain verifiable across releases.
> Breaking changes bump `schema_version` and ship a migration note.

## Conventions

- **Ids** — uuid7 (time-sortable), rendered as canonical lowercase hex with hyphens.
- **Timestamps** — RFC-3339 in UTC (`...Z`), microsecond precision.
- **Hashes** — `blake3:<hex>` (lowercase, 64 hex chars).
- **Signatures** — `ed25519:<hex>`.
- **Canonical form** — keys recursively sorted, `orjson` `OPT_SORT_KEYS`, UTF-8, no insignificant
  whitespace. Ledger-set fields (`entry_hash`, `prev_hash`, `signature`, `signer_kid`, `merkle_leaf`)
  are **excluded** from the canonical bytes that get hashed/signed.

## Records

The field-level schema is defined in [`../ARCHITECTURE.md` §3](../ARCHITECTURE.md) and implemented as
Pydantic v2 models in `memory_blackbox.model.records`. This document pins the serialization rules and
the storage layout; the model module is the executable source of truth for field types.

### Ledger row layout

| column | type | notes |
|--------|------|-------|
| `seq` | INTEGER PK AUTOINCREMENT | monotonic ordering |
| `record_id` | TEXT UNIQUE | uuid7 |
| `kind` | TEXT | `write` \| `retrieval` \| `action` \| `rollback` |
| `namespace` | TEXT | logical partition |
| `payload_json` | TEXT | canonical record JSON (signable fields only) |
| `entry_hash` | TEXT | `blake3(payload + prev_hash)` |
| `prev_hash` | TEXT NULL | prior row's `entry_hash`; NULL for genesis |
| `signature` | TEXT | Ed25519 over `blake3_raw(payload + prev_hash)` |
| `signer_kid` | TEXT | key id that produced the signature |
| `created_at` | TEXT | RFC-3339 UTC |

### Entry-hash construction

```
payload     = canonical_bytes(record, exclude={entry_hash, prev_hash, signature, signer_kid, merkle_leaf})
link_input  = payload + (prev_hash_bytes or b"")
entry_hash  = "blake3:" + hex(blake3(link_input))
signature   = "ed25519:" + hex(sign(blake3_raw(link_input)))
```

## Versioning policy

- Additive, optional fields → no version bump (forward-compatible).
- Removing/renaming a field, or changing canonicalization → bump `schema_version`, document migration.
- A ledger records the `schema_version` it was written under so `verify()` can apply the right rules.
