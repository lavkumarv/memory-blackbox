# Threat mapping

How memory-blackbox maps to the agent-security standards. The goal is that "agent
memory forensics" is the named forensic reference for memory & context poisoning and
for repudiation/untraceability.

> **Last verified:** June 2026 (see Sources). These taxonomies evolve; IDs are
> reviewed each release. Corrections welcome via PR.

We map against **two OWASP artifacts** (they are distinct — don't conflate them):

- **OWASP Top 10 for Agentic Applications 2026** — the ranked list, coded `ASI01`–`ASI10`.
- **OWASP Agentic AI — Threats & Mitigations v1.0** (Feb 2025) — the foundational
  taxonomy, coded `T1`–`T15`.

Plus **MITRE ATLAS** technique IDs (`AML.Txxxx`) and the **CoSAI MCP Security**
threat categories.

## The two threats this whole tool addresses

| OWASP | What it is | How memory-blackbox addresses it |
|-------|-----------|----------------------------------|
| **T1 — Memory Poisoning** (≈ **ASI06** Memory & Context Poisoning) | Malicious data corrupts a memory/RAG/context store so later reasoning is skewed | Captures every write with provenance; `trace`, `blast-radius`, `rollback` reconstruct and contain it |
| **T8 — Repudiation & Untraceability** | No reliable record of what an agent did or knew, so actions can't be attributed | The append-only, signed, tamper-evident ledger + `verify` + `trace` *is* the traceability control |

T8 is the standards hook for the ledger itself: a tamper-evident provenance record
is the direct mitigation for Repudiation & Untraceability.

## Detectors → threat categories

| Detector | OWASP Top 10 (ASI) | OWASP T&M (T1–T15) | MITRE ATLAS | CoSAI MCP |
|----------|--------------------|--------------------|-------------|-----------|
| `provenance_missing` | ASI06 Memory & Context Poisoning | T1 Memory Poisoning · T8 Repudiation & Untraceability | AML.T0070 RAG Poisoning | Memory manipulation |
| `injection_scan` | ASI01 Agent Goal Hijack · ASI06 | T1 Memory Poisoning · T6 Intent Breaking & Goal Manipulation | AML.T0051 LLM Prompt Injection (indirect) | Context poisoning |
| `unicode_smuggling` | ASI01 Agent Goal Hijack · ASI06 | T1 Memory Poisoning | AML.T0051 LLM Prompt Injection (obfuscated/indirect) | Context poisoning |
| `secrets_pii` | — (see OWASP LLM Top 10 · LLM02 Sensitive Information Disclosure) | — | AML.T0057 LLM Data Leakage | Sensitive data exposure |
| `write_rate` | ASI06 Memory & Context Poisoning | T1 Memory Poisoning · T4 Resource Overload | AML.T0070 RAG Poisoning | Memory manipulation (flooding) |
| `trust_scoring` | ASI06 Memory & Context Poisoning | T1 Memory Poisoning | — | Memory manipulation |
| `drift` | ASI06 Memory & Context Poisoning | T1 Memory Poisoning | AML.T0070 RAG Poisoning | Context poisoning (temporal) |

> `secrets_pii` has no clean *agentic* Top-10 home; it maps to the **OWASP Top 10 for
> LLM Applications 2025** item **LLM02 Sensitive Information Disclosure** and to ATLAS
> **AML.T0057 LLM Data Leakage**.

## Capabilities → response phase

| Capability | DFIR phase | Standard hook |
|------------|-----------|----------------|
| `trace` | Identification / root cause | T8 Repudiation & Untraceability · ASI06 reconstruction |
| `blast-radius` | Scoping / impact | ASI06 · T1 impact analysis |
| `verify` | Integrity assurance | T8 Repudiation & Untraceability · EU AI Act Art. 12 logging |
| `rollback` | Containment / recovery | ASI06 · T1 — quarantine without history loss |
| `reconcile` | Detection of capture bypass | T8 — coverage/traceability assurance |

## Positioning vs. runtime tools

Runtime products (OWASP Memory Guard, Microsoft Agent Governance Toolkit, and the
runtime offerings from Snyk/Cisco/etc.) own **prevention** — they block the attack in
the moment. memory-blackbox owns **reconstruction** — provenance, blast radius, and
rollback after the fact. They are complementary: *they stop it; we tell you which
memory caused it and what to roll back.*

## Compliance framing

A tamper-evident, signed record of *what an agent knew and when* is exactly the
evidence several regimes ask for:

- **EU AI Act** — high-risk record-keeping / automatic logging (Art. 12) obligations.
- **Colorado AI Act** — algorithmic accountability records.
- **HIPAA** — audit trails for healthcare agents handling PHI.

The `secrets_pii` detector plus the planned redaction disposition and per-subject
crypto-shredding (see [`ROADMAP.md`](../ROADMAP.md)) extend this from security into
compliance evidence.

## Sources (verified June 2026)

- OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) — OWASP GenAI Security Project:
  <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>
- OWASP Agentic AI — Threats & Mitigations v1.0 (T1–T15) — OWASP GenAI Security Project.
- MITRE ATLAS techniques — <https://atlas.mitre.org/> (AML.T0051 LLM Prompt Injection;
  AML.T0070 RAG Poisoning; AML.T0057 LLM Data Leakage).
- CoSAI MCP Security taxonomy (12 threat categories incl. context poisoning, memory
  manipulation) — Coalition for Secure AI / OASIS:
  <https://www.oasis-open.org/2026/01/27/coalition-for-secure-ai-releases-extensive-taxonomy-for-model-context-protocol-security/>

> Before citing any specific ID in a formal submission, re-check it against the
> current published taxonomy — these move quarterly.
