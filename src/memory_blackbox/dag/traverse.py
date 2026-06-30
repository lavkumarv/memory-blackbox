"""Cycle-safe DAG traversal.

``backward`` powers ``trace`` (an action back to its origin writes); ``forward_closure``
powers ``blast_radius`` (everything a poisoned source could have influenced). Agents
can create reference loops, so every traversal carries a visited set and never revisits
a node.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable

from memory_blackbox.dag.store import EdgeStore
from memory_blackbox.model.edges import EdgeType


def backward(
    store: EdgeStore,
    node: str,
    edge_types: Iterable[EdgeType] | None = None,
    max_depth: int | None = None,
) -> set[str]:
    """Return all ancestors reachable from ``node`` via reverse edges (excludes ``node``)."""
    types = list(edge_types) if edge_types is not None else None
    visited: set[str] = {node}
    ancestors: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(node, 0)])
    while queue:
        current, depth = queue.popleft()
        if max_depth is not None and depth >= max_depth:
            continue
        for parent in store.in_neighbors(current, types):
            if parent not in visited:
                visited.add(parent)
                ancestors.add(parent)
                queue.append((parent, depth + 1))
    return ancestors


def forward_closure(
    store: EdgeStore,
    seeds: Iterable[str],
    edge_types: Iterable[EdgeType] | None = None,
) -> set[str]:
    """Return the transitive set of descendants of ``seeds`` (includes the seeds)."""
    types = list(edge_types) if edge_types is not None else None
    visited: set[str] = set(seeds)
    queue: deque[str] = deque(visited)
    while queue:
        current = queue.popleft()
        for child in store.out_neighbors(current, types):
            if child not in visited:
                visited.add(child)
                queue.append(child)
    return visited
