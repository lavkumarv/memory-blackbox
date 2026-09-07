# External anchoring

Anchoring publishes each signed Merkle checkpoint to an append-only log outside
the machine that holds the ledger. This page covers what that buys, what it does
not, and how to run it.

## The gap it closes

Without anchoring, `verify` makes two checks:

- the **BLAKE3 hash chain** proves no row was edited and none was removed from the
  middle;
- the latest **signed Merkle checkpoint** proves no row was removed from the tail
  *since that checkpoint was written*.

Both are evaluated against state that lives in the same SQLite file as the ledger.
An attacker with raw file access deletes the recent checkpoint rows along with the
rows they cover, and what remains is a shorter ledger with a valid chain and a
valid checkpoint. It verifies clean. No signing key is needed for this — only
write access to the file.

That is the whole gap: **local verification cannot detect a rollback to a point
the ledger itself once passed through.**

Anchoring closes it by putting the checkpoint somewhere the attacker cannot
reach. Publication is not retractable, so the log still holds a checkpoint that
the shortened ledger can no longer produce. The mismatch is the detection.

There is a test for exactly this claim — `test_rollback_passes_local_verification
_but_fails_the_anchor_check` in `tests/integration/test_anchoring.py` asserts both
halves: that plain `verify` passes on the rolled-back ledger, and that the
anchored check fails.

## What gets published

A **checkpoint statement**: a small canonical JSON object carrying only hashes and
counts.

```json
{
  "type": "memory-blackbox.checkpoint/v1",
  "ledger_id": "blake3:…",
  "signer_kid": "…",
  "leaf_count": 1024,
  "root": "blake3:…",
  "checkpoint_signature": "ed25519:…",
  "created_at": "2026-09-07T…"
}
```

No memory content, no queries, no source locators, no key material. The
destination may be a public log, and the ledger is a map of everything the agent
knows, so this boundary is enforced by test (`test_anchoring_publishes_only_hashes
_and_counts`).

`ledger_id` is derived from the genesis row's entry hash and the signer kid. It is
fixed the moment the first row lands, so a ledger that was rebuilt from scratch
has a different identity and matches none of the real witnesses.

## Backends

### `none` (default)

Publishes nothing. `verify --anchor` reports `no_witness` rather than passing —
"nothing was published" and "everything checks out" must not look alike.

### `file` — append-only file witness

Appends signed statements as JSON lines.

```bash
memory-blackbox anchor --backend file --witness-file /mnt/worm/anchors.jsonl
memory-blackbox verify --anchor --backend file --witness-file /mnt/worm/anchors.jsonl
```

**Its assurance is exactly the independence of that storage, and no more.** On the
same disk with the same permissions as the ledger it detects nothing that an
attacker with raw file access cannot also undo. Point it at a WORM bucket, an
append-only mount, a log-shipping sink, or another host. The default location
(inside the profile) is the convenient case, not the secure one.

Each line is signed with the ledger key, so someone who can append to the witness
but does not hold the key cannot fabricate a longer history and turn the rollback
check into a false alarm.

### `rekor` — Sigstore transparency log

```bash
memory-blackbox anchor --backend rekor
memory-blackbox verify --anchor --backend rekor
```

Publishes a `rekord` entry signed by the ledger's Ed25519 key, defaulting to the
public log at `https://rekor.sigstore.dev`. Use `--rekor-url` for a private
instance.

Two Rekor behaviours shape how this works:

- **Rekor stores the payload's hash, not the payload.** A statement cannot be read
  back out of the log, so verification matches by fingerprint — the SHA-256 of the
  canonical statement, recomputed locally. This is enough: a rolled-back ledger
  cannot regenerate the statement for a checkpoint it no longer holds. It does
  mean witness counts, not row counts, are what you see in `anchor-status`.
- **Rekor indexes entries by signing key.** That is how verification enumerates
  witnesses. It also means **one signing key per ledger**: sharing a key across
  ledgers makes each ledger's entries look like orphans to the other. The
  divergence message says so rather than asserting tampering outright.

`hashedrekord` is not usable here — it presents a pre-hashed message, which pure
Ed25519 cannot verify. `rekord` signs the payload itself, which matches.

Receipts are stored locally and re-verified **offline**: the entry body must commit
to this statement's payload hash, and the stored RFC 6962 inclusion proof must
reconstruct the recorded root. The log is not asked to vouch for itself at
verification time.

## Running it

```bash
# publish the current checkpoint
memory-blackbox anchor --backend file --witness-file /mnt/worm/anchors.jsonl

# what does the log say about this ledger?
memory-blackbox anchor-status --backend file --witness-file /mnt/worm/anchors.jsonl

# full integrity check, including the external cross-check
memory-blackbox verify --anchor --backend file --witness-file /mnt/worm/anchors.jsonl
```

Configuration can come from the environment instead of flags:

| Variable | Meaning |
| --- | --- |
| `MEMORY_BLACKBOX_ANCHOR` | `none` \| `file` \| `rekor` |
| `MEMORY_BLACKBOX_ANCHOR_WITNESS` | witness file path (backend `file`) |
| `MEMORY_BLACKBOX_ANCHOR_REKOR_URL` | Rekor base URL (backend `rekor`) |

From Python:

```python
from memory_blackbox.anchor import FileWitnessAnchor, anchor_now, verify_anchors

anchor = FileWitnessAnchor("/mnt/worm/anchors.jsonl")
anchor_now(blackbox.ledger, anchor, signer)      # checkpoint + publish
report = verify_anchors(blackbox.ledger, anchor)  # cross-check
```

### Cadence

Anchoring is a deliberate act, not a side effect of writing — it reaches the
network, and a local-first tool should not do that unasked. Anchor on a timer or
after significant batches.

**Cadence sets the blast radius of an undetectable rollback.** Rows written after
the last anchor are unwitnessed, so a rollback confined to them is invisible to
this check. Anchoring every hour means at most an hour of history can be quietly
removed.

## What it does not prove

- **Not that the ledger is true.** A log witnesses that a claim was published, not
  that it was honest. Anchoring says "this history was committed to at this time",
  which is a different statement from "this history is accurate".
- **Not that every checkpoint was anchored.** An operator who never published a
  checkpoint leaves nothing to be found missing. This detects removal of
  *witnessed* history.
- **Not availability.** If the log is unreachable, `anchor` fails loudly rather
  than continuing silently; treat an anchoring failure as an operational incident,
  not a warning to skip.
- **Nothing under the `none` backend**, which is why it reports `no_witness`
  instead of a pass.

## Divergence kinds

| Kind | Meaning |
| --- | --- |
| `no_witness` | Nothing was ever published for this ledger; rollback is undetectable |
| `rollback` | The log witnessed more rows than the ledger now has |
| `fork` | A witnessed root does not match the local history at that length |
| `orphaned_witness` | A published checkpoint this ledger can no longer produce |
| `unsigned_witness` | A witnessed statement not signed by this ledger's key |
| `bad_receipt` | A locally stored receipt no longer checks out |

`rollback` and `fork` are reported only by backends that return the payload (the
file witness). Against Rekor the same tampering surfaces as `orphaned_witness`,
which needs no payload — the diagnosis is less specific, the detection is not.

## Verifying against the live public log

The Rekor backend is tested against an in-process fake that implements Rekor's
canonicalization and generates real RFC 6962 proofs, so `verify_receipt` does the
same proof walk it would against production. What a fake cannot confirm is that
the live service accepts this entry shape.

Before relying on the public log in production, run one smoke test with a
throwaway profile:

```bash
export MEMORY_BLACKBOX_HOME=$(mktemp -d)
memory-blackbox init
# ... write a few records ...
memory-blackbox anchor --backend rekor
memory-blackbox verify --anchor --backend rekor
```

Note that entries in a public transparency log are **permanent and public**. The
statement carries only hashes, but the fact that you anchored, and when, is
visible to anyone. Use a private Rekor instance via `--rekor-url` if that matters.
