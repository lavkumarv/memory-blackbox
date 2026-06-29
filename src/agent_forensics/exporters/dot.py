"""Graphviz DOT exporter for provenance subgraphs."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


def _quote(raw: str) -> str:
    return '"' + raw.replace('"', '\\"') + '"'


def provenance_graph(
    edges: Iterable[tuple[str, str, str]], labels: dict[str, str] | None = None
) -> str:
    """Render a provenance subgraph as a Graphviz DOT digraph."""
    labels = labels or {}
    lines = ["digraph provenance {", "  rankdir=TB;", "  node [shape=box];"]
    seen: set[str] = set()
    for src, dst, edge_type in edges:
        for node in (src, dst):
            if node not in seen:
                seen.add(node)
                lines.append(f"  {_quote(node)} [label={_quote(labels.get(node, node[:12]))}];")
        lines.append(f"  {_quote(src)} -> {_quote(dst)} [label={_quote(edge_type)}];")
    lines.append("}")
    return "\n".join(lines)
