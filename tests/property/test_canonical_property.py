"""Property tests for canonical serialization (spec §15.1)."""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from memory_blackbox.model.canonical import canonical_bytes

# JSON-like values with string keys, nested up to a small depth. Integers are
# bounded to the 64-bit range that JSON/orjson supports (the domain canonical
# bytes operate over, since inputs come from model_dump(mode="json")).
_int64 = st.integers(min_value=-(2**63), max_value=2**63 - 1)
_json = st.recursive(
    st.none() | st.booleans() | _int64 | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(min_size=1), children, max_size=4)
    ),
    max_leaves=20,
)


@given(st.dictionaries(st.text(min_size=1), _json, max_size=6))
def test_same_logical_object_same_bytes_regardless_of_order(obj: dict[str, Any]) -> None:
    """A dict and its reverse-ordered copy canonicalize to identical bytes."""
    reordered = dict(reversed(list(obj.items())))
    assert canonical_bytes(obj) == canonical_bytes(reordered)


@given(st.dictionaries(st.text(min_size=1), _json, max_size=6))
def test_canonical_bytes_are_deterministic(obj: dict[str, Any]) -> None:
    assert canonical_bytes(obj) == canonical_bytes(obj)
