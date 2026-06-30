"""Tests for the DAG edge store and traversal (spec §15.4)."""

from __future__ import annotations

import sqlite3

import pytest

from memory_blackbox.dag.store import EdgeStore, UnknownNodeError
from memory_blackbox.dag.traverse import backward, forward_closure
from memory_blackbox.model.edges import EdgeType

# Convention: edges encode forward influence/lineage flow, src -> dst
# (parent/origin -> child/derived). backward() walks reverse edges to ancestors;
# forward_closure() walks forward edges to descendants (the blast radius).
D = EdgeType.DERIVED_FROM
C = EdgeType.CONTRIBUTED_TO


def _store(nodes: set[str]) -> EdgeStore:
    """An in-memory edge store whose nodes are an explicit set (no ledger needed)."""
    conn = sqlite3.connect(":memory:")
    return EdgeStore(conn, node_exists=lambda n: n in nodes)


def test_edge_insert_requires_existing_endpoints() -> None:
    store = _store({"a", "b"})
    store.add_edge("a", "b", D)  # ok
    with pytest.raises(UnknownNodeError):
        store.add_edge("a", "ghost", D)
    with pytest.raises(UnknownNodeError):
        store.add_edge("ghost", "b", D)


def test_edge_insert_is_idempotent() -> None:
    store = _store({"a", "b"})
    store.add_edge("a", "b", D)
    store.add_edge("a", "b", D)  # duplicate -> ignored
    assert store.count() == 1


def test_backward_returns_all_ancestors() -> None:
    # a -> c, b -> c, c -> d  (a and b are origins; influence flows to d)
    store = _store({"a", "b", "c", "d"})
    store.add_edge("a", "c", D)
    store.add_edge("b", "c", D)
    store.add_edge("c", "d", D)
    assert backward(store, "d") == {"a", "b", "c"}
    assert backward(store, "c") == {"a", "b"}
    assert backward(store, "a") == set()


def test_backward_respects_max_depth() -> None:
    store = _store({"a", "b", "c", "d"})
    store.add_edge("a", "b", D)
    store.add_edge("b", "c", D)
    store.add_edge("c", "d", D)
    assert backward(store, "d", max_depth=1) == {"c"}
    assert backward(store, "d", max_depth=2) == {"c", "b"}


def test_backward_filters_by_edge_type() -> None:
    store = _store({"a", "b", "x"})
    store.add_edge("a", "b", D)  # b derived from a
    store.add_edge("x", "b", C)  # x contributed to b
    assert backward(store, "b", edge_types=[D]) == {"a"}
    assert backward(store, "b", edge_types=[C]) == {"x"}


def test_forward_closure_returns_transitive_descendants() -> None:
    # a -> b -> d , a -> c -> d
    store = _store({"a", "b", "c", "d"})
    store.add_edge("a", "b", D)
    store.add_edge("a", "c", D)
    store.add_edge("b", "d", D)
    store.add_edge("c", "d", D)
    assert forward_closure(store, ["a"]) == {"a", "b", "c", "d"}
    assert forward_closure(store, ["b"]) == {"b", "d"}


def test_forward_closure_multiple_seeds() -> None:
    store = _store({"a", "b", "c", "z"})
    store.add_edge("a", "c", D)
    store.add_edge("b", "z", D)
    assert forward_closure(store, ["a", "b"]) == {"a", "b", "c", "z"}


def test_traversal_is_cycle_safe() -> None:
    # a -> b -> c -> a (a genuine reference loop): must terminate, not hang.
    store = _store({"a", "b", "c"})
    store.add_edge("a", "b", D)
    store.add_edge("b", "c", D)
    store.add_edge("c", "a", D)
    assert forward_closure(store, ["a"]) == {"a", "b", "c"}
    assert backward(store, "a") == {"b", "c"}


def test_referential_integrity_against_real_ledger(tmp_path: object) -> None:
    from pathlib import Path

    from memory_blackbox.crypto import keys
    from memory_blackbox.ledger.store import LedgerStore
    from memory_blackbox.model.records import ProvenanceRecord, Source, SourceType

    assert isinstance(tmp_path, Path)
    store = LedgerStore(tmp_path / "ledger.db", keys.generate())
    src = Source(source_type=SourceType.user_input)
    r1 = store.append(ProvenanceRecord(content="parent", source=src))
    r2 = store.append(ProvenanceRecord(content="child", source=src))

    edges = EdgeStore(store.connection)  # default checker -> ledger.record_id
    edges.add_edge(r2.record_id, r1.record_id, D)
    assert edges.out_neighbors(r2.record_id) == [r1.record_id]
    with pytest.raises(UnknownNodeError):
        edges.add_edge(r2.record_id, "no-such-record", D)
