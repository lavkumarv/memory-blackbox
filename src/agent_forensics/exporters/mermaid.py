"""Mermaid exporters for provenance subgraphs and timelines."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from agent_forensics.query.timeline import Event


def _node_id(raw: str) -> str:
    # Mermaid node ids must be identifier-safe.
    return "n_" + "".join(ch if ch.isalnum() else "_" for ch in raw)


def provenance_graph(
    edges: Iterable[tuple[str, str, str]], labels: dict[str, str] | None = None
) -> str:
    """Render a provenance subgraph as a Mermaid flowchart."""
    labels = labels or {}
    lines = ["flowchart TD"]
    seen: set[str] = set()
    for src, dst, edge_type in edges:
        for node in (src, dst):
            if node not in seen:
                seen.add(node)
                label = labels.get(node, node[:12])
                lines.append(f'    {_node_id(node)}["{label}"]')
        lines.append(f"    {_node_id(src)} -->|{edge_type}| {_node_id(dst)}")
    return "\n".join(lines)


def timeline_gantt(events: Iterable[Event], title: str = "Incident timeline") -> str:
    """Render an event timeline as a Mermaid gantt chart."""
    lines = [
        "gantt",
        f"    title {title}",
        "    dateFormat YYYY-MM-DDTHH:mm:ss",
        "    axisFormat %H:%M",
    ]
    section = None
    for event in events:
        if event.kind != section:
            section = event.kind
            lines.append(f"    section {section}")
        stamp = event.timestamp.replace("Z", "").split(".")[0]
        label = event.text[:24].replace(":", " ")
        lines.append(f"    {label} :milestone, {stamp}, 0d")
    return "\n".join(lines)
