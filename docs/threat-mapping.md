# Threat mapping

How agent-forensics maps to the agent-security standards. We track these taxonomies
and re-map each release; the goal is that "agent memory forensics" is the named
forensic reference for memory & context poisoning.

> Standards move quarterly. IDs below reflect the taxonomies as tracked at the time
> of writing and are reviewed each release — corrections welcome via PR.

## Detectors → threat categories

| Detector | What it catches | OWASP Agentic (ASI) | MITRE ATLAS | CoSAI MCP |
|----------|-----------------|---------------------|-------------|-----------|
| `provenance_missing` | Untraceable / unsourced memory writes | ASI06 Memory & Context Poisoning | AML.T0051 (LLM data manipulation) | Untrusted tool/memory output |
| `injection_scan` | Imperative-override / instruction smuggling in stored content | ASI01 Prompt Injection · ASI06 | AML.T0051.000 (indirect prompt injection) | Indirect prompt injection via memory |
| `unicode_smuggling` | Zero-width / bidi / tag-char smuggling | ASI01 · ASI06 | AML.T0051 | Hidden-instruction smuggling |
| `secrets_pii` | Credentials / personal data stored in memory | ASI08 Sensitive Information Disclosure | AML.T0057 (LLM data leakage) | Sensitive data in tool/memory I/O |
| `write_rate` | Mass-injection bursts from one source | ASI06 | AML.T0051 | Memory flooding |
| `trust_scoring` | Decaying trust for anomalous sources | ASI06 | — | Source trust modeling |
| `drift` | Belief contradicting the trusted consensus | ASI06 Memory & Context Poisoning | AML.T0051 | Temporal memory poisoning |

## Capabilities → response phase

| Capability | DFIR phase | Standard hook |
|------------|-----------|---------------|
| `trace` | Identification / root cause | ASI06 incident reconstruction |
| `blast-radius` | Scoping / impact | ASI06 blast-radius analysis |
| `verify` | Integrity assurance | tamper-evident audit trail (EU AI Act Art. 12 logging) |
| `rollback` | Containment / recovery | quarantine without history loss |
| `reconcile` | Detection of capture bypass | coverage assurance |

## Positioning vs. runtime tools

Runtime products (OWASP Memory Guard, Microsoft Agent Governance Toolkit, the
runtime offerings from Snyk/Cisco/etc.) own **prevention** — they block the attack
in the moment. agent-forensics owns **reconstruction** — provenance, blast radius,
and rollback after the fact. They are complementary: *they stop it; we tell you which
memory caused it and what to roll back.*

## Compliance framing

A tamper-evident, signed record of *what an agent knew and when* is exactly the
evidence several regimes ask for:

- **EU AI Act** — high-risk logging/record-keeping (Art. 12) obligations.
- **Colorado AI Act** — algorithmic accountability records.
- **HIPAA** — audit trails for healthcare agents handling PHI.

The `secrets_pii` detector plus the planned redaction disposition and per-subject
crypto-shredding (see [`ROADMAP.md`](../ROADMAP.md)) extend this from security into
compliance evidence.
