# Security Policy

`agent-forensics` is a security tool, so we hold it to a security-product standard.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability") rather than a public issue.

- **Acknowledgement SLA:** within 48 hours.
- Please include a description, reproduction steps, and impact.
- We follow coordinated disclosure and will credit reporters who wish to be named.

## The tool's own integrity

The ledger's trust model is the product:

- **Append-only.** No code path updates or deletes ledger rows; rollbacks append.
- **Tamper-evident.** A BLAKE3 hash chain detects edits and gaps; a signed,
  checkpointed Merkle root detects deletions, including tail truncation.
- **Signed.** Every entry is Ed25519-signed by a key the agent never sees
  (0600 file locally; KMS/HSM on servers).
- **Local-first.** No telemetry; nothing leaves the machine by default.

## Supply chain

Releases are built in CI, signed with Sigstore (keyless), ship SLSA build
provenance, and are published to PyPI via OIDC trusted publishing. Core runtime
dependencies are kept minimal to reduce attack surface.
