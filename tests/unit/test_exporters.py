"""Tests for the report exporters (spec §15.11)."""

from __future__ import annotations

from memory_blackbox.exporters import dot, markdown, mermaid, sarif
from memory_blackbox.ledger.chain import ChainReport
from memory_blackbox.merkle.tree import MerkleReport
from memory_blackbox.model.records import Finding, Severity
from memory_blackbox.query.rollback import RollbackPlan
from memory_blackbox.query.timeline import Event
from memory_blackbox.query.trace import ProvenanceTrace, TraceRoot
from memory_blackbox.query.verify import IntegrityReport

_EDGES = [
    ("poison", "derived", "DERIVED_FROM"),
    ("derived", "ret", "RETRIEVED"),
    ("ret", "action", "CONTRIBUTED_TO"),
]


# -- SARIF ------------------------------------------------------------------
def _findings() -> list[Finding]:
    return [
        Finding(detector_name="injection_scan", severity=Severity.HIGH, message="override"),
        Finding(detector_name="unicode_smuggling", severity=Severity.MEDIUM, message="zwsp"),
    ]


def test_sarif_has_required_structure() -> None:
    doc = sarif.findings_to_sarif(_findings())
    # Structural validation of the SARIF 2.1.0 shape.
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "memory-blackbox"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {
        "injection_scan",
        "unicode_smuggling",
    }
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"  # HIGH -> error


def test_sarif_is_json_serializable() -> None:
    import json

    json.dumps(sarif.findings_to_sarif(_findings()))


def test_sarif_empty_findings() -> None:
    doc = sarif.findings_to_sarif([])
    assert doc["runs"][0]["results"] == []


# -- Mermaid ----------------------------------------------------------------
def test_mermaid_provenance_graph() -> None:
    out = mermaid.provenance_graph(_EDGES)
    assert out.startswith("flowchart TD")
    assert "DERIVED_FROM" in out
    assert out.count("-->") == 3


def test_mermaid_timeline_gantt() -> None:
    events = [
        Event(record_id="a", kind="write", timestamp="2026-01-01T00:00:00Z", text="poison planted"),
        Event(
            record_id="b", kind="action", timestamp="2026-02-01T00:00:00Z", text="harmful action"
        ),
    ]
    out = mermaid.timeline_gantt(events)
    assert out.startswith("gantt")
    assert "section write" in out
    assert "section action" in out


# -- DOT --------------------------------------------------------------------
def test_dot_provenance_graph() -> None:
    out = dot.provenance_graph(_EDGES)
    assert out.startswith("digraph provenance {")
    assert out.strip().endswith("}")
    assert out.count("->") == 3


# -- Markdown ---------------------------------------------------------------
def test_markdown_incident_report() -> None:
    trace = ProvenanceTrace(
        action_id="action-1",
        roots=[
            TraceRoot(
                record_id="poison",
                source_id="evil-doc",
                source_type="document_ingest",
                trust_level="untrusted",
                created_at="2026-01-01T00:00:00Z",
                centrality=3,
            )
        ],
        ancestors={"poison", "derived", "ret"},
    )
    plan = RollbackPlan(to="evil-doc", scope="t", affected=["poison", "derived"], dry_run=True)
    integrity = IntegrityReport(
        ok=True,
        chain=ChainReport(ok=True, rows_checked=4),
        merkle=MerkleReport(ok=True, leaf_count=4, detail="ok"),
    )
    report = markdown.incident_report(
        trace=trace,
        blast_radius={"poison", "derived", "ret", "action-1"},
        rollback_plan=plan,
        integrity=integrity,
    )
    assert "# Incident report" in report
    assert "evil-doc" in report
    assert "untrusted" in report
    assert "Roll back **2**" in report
    assert "PASS" in report
