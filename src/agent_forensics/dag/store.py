"""Provenance-DAG edge store (SQLite).

Edges record lineage between ledger nodes (writes, reads, actions, rollbacks),
all keyed by ``ledger.record_id``. Referential integrity is enforced at insert
time: both endpoints must exist as nodes. The default existence check queries the
ledger table in the same connection; a custom checker can be injected for tests
or alternative node sources.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from importlib import resources

from agent_forensics.model.edges import EdgeType


class UnknownNodeError(ValueError):
    """Raised when an edge endpoint does not exist as a node."""


def _load_schema() -> str:
    return resources.files("agent_forensics.dag").joinpath("schema.sql").read_text()


class EdgeStore:
    """Stores and queries provenance-DAG edges."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        node_exists: Callable[[str], bool] | None = None,
    ) -> None:
        self._conn = conn
        self._node_exists = node_exists or self._exists_in_ledger
        self._conn.executescript(_load_schema())
        self._conn.commit()

    def _exists_in_ledger(self, node_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM ledger WHERE record_id = ? LIMIT 1", (node_id,)
        ).fetchone()
        return row is not None

    def add_edge(self, src: str, dst: str, edge_type: EdgeType) -> None:
        """Insert a lineage edge after checking both endpoints exist."""
        if not self._node_exists(src):
            raise UnknownNodeError(f"edge source does not exist: {src}")
        if not self._node_exists(dst):
            raise UnknownNodeError(f"edge destination does not exist: {dst}")
        self._conn.execute(
            """
            INSERT OR IGNORE INTO edges (src, dst, edge_type, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (src, dst, edge_type.value, datetime.now(UTC).isoformat()),
        )
        self._conn.commit()

    def out_neighbors(self, node: str, edge_types: Iterable[EdgeType] | None = None) -> list[str]:
        """Return the destinations of edges leaving ``node``."""
        return self._neighbors("dst", "src", node, edge_types)

    def in_neighbors(self, node: str, edge_types: Iterable[EdgeType] | None = None) -> list[str]:
        """Return the sources of edges entering ``node``."""
        return self._neighbors("src", "dst", node, edge_types)

    def _neighbors(
        self,
        select_col: str,
        match_col: str,
        node: str,
        edge_types: Iterable[EdgeType] | None,
    ) -> list[str]:
        query = f"SELECT {select_col} FROM edges WHERE {match_col} = ?"
        params: list[str] = [node]
        if edge_types is not None:
            types = [et.value for et in edge_types]
            placeholders = ",".join("?" for _ in types)
            query += f" AND edge_type IN ({placeholders})"
            params.extend(types)
        return [row[0] for row in self._conn.execute(query, params)]

    def subgraph_edges(self, nodes: Iterable[str]) -> list[tuple[str, str, str]]:
        """Return (src, dst, edge_type) for edges whose both endpoints are in ``nodes``."""
        node_list = list(nodes)
        if not node_list:
            return []
        placeholders = ",".join("?" for _ in node_list)
        query = (
            f"SELECT src, dst, edge_type FROM edges "
            f"WHERE src IN ({placeholders}) AND dst IN ({placeholders})"
        )
        rows = self._conn.execute(query, node_list + node_list)
        return [(row[0], row[1], row[2]) for row in rows]

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) AS n FROM edges").fetchone()[0])
