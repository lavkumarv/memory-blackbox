"""Markdown incident-report exporter."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from memory_blackbox.query.rollback import RollbackPlan
    from memory_blackbox.query.trace import ProvenanceTrace
    from memory_blackbox.query.verify import IntegrityReport


def incident_report(
    *,
    trace: ProvenanceTrace,
    blast_radius: set[str],
    rollback_plan: RollbackPlan,
    integrity: IntegrityReport,
) -> str:
    """Render a human-readable incident report for an action."""
    lines: list[str] = []
    lines.append("# Incident report")
    lines.append("")
    lines.append(f"**Action under investigation:** `{trace.action_id}`")
    lines.append("")

    lines.append("## Root cause")
    primary = trace.primary
    if primary is None:
        lines.append("No originating write was found for this action.")
    else:
        lines.append(f"- **Record:** `{primary.record_id}`")
        lines.append(f"- **Source:** `{primary.source_id}` ({primary.source_type})")
        lines.append(f"- **Trust level:** {primary.trust_level}")
        lines.append(f"- **First written:** {primary.created_at}")
        lines.append(f"- **Influence (descendants):** {primary.centrality}")
    lines.append("")

    if len(trace.roots) > 1:
        lines.append("### Other candidate roots")
        for root in trace.roots[1:]:
            lines.append(f"- `{root.record_id}` — {root.trust_level}, source `{root.source_id}`")
        lines.append("")

    lines.append("## Blast radius")
    lines.append(f"{len(blast_radius)} record(s) potentially influenced by the root cause.")
    lines.append("")

    lines.append("## Recommended rollback")
    lines.append(
        f"Roll back **{rollback_plan.count}** record(s)"
        + (f" in scope `{rollback_plan.scope}`" if rollback_plan.scope else "")
        + "."
    )
    for record_id in rollback_plan.affected:
        lines.append(f"- `{record_id}`")
    lines.append("")

    lines.append("## Ledger integrity")
    status = "PASS" if integrity.ok else "FAIL"
    lines.append(f"**{status}** — {integrity.summary}")
    lines.append("")

    return "\n".join(lines)
