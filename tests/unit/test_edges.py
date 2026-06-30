"""Tests for the Edge model (spec §15.1 supporting)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from memory_blackbox.model.edges import Edge, EdgeType


def test_edge_construction() -> None:
    edge = Edge(src="rec-1", dst="rec-2", edge_type=EdgeType.DERIVED_FROM)
    assert edge.src == "rec-1"
    assert edge.edge_type is EdgeType.DERIVED_FROM
    assert edge.created_at is not None


def test_edge_type_values() -> None:
    assert {e.value for e in EdgeType} == {
        "DERIVED_FROM",
        "RETRIEVED",
        "INFLUENCED",
        "CONTEXTUALIZED",
        "CONTRIBUTED_TO",
        "ROLLED_BACK_BY",
    }


def test_edge_rejects_unknown_type() -> None:
    with pytest.raises(ValidationError):
        Edge(src="a", dst="b", edge_type="NOT_A_TYPE")  # type: ignore[arg-type]
