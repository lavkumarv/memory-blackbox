"""Tests for the BLAKE3 Merkle tree primitives (spec §15.3)."""

from __future__ import annotations

import pytest

from agent_forensics.merkle.anchor import Anchor, NoOpAnchor
from agent_forensics.merkle.tree import (
    compute_root,
    hash_leaf,
    hash_node,
    inclusion_proof,
    root_hex,
    verify_proof,
)


def _leaves(n: int) -> list[bytes]:
    return [f"leaf-{i}".encode() for i in range(n)]


def test_empty_tree_root_is_stable() -> None:
    assert compute_root([]) == compute_root([])


def test_single_leaf_root_is_leaf_hash() -> None:
    assert compute_root([b"only"]) == hash_leaf(b"only")


def test_root_changes_when_a_leaf_changes() -> None:
    a = compute_root([b"x", b"y", b"z"])
    b = compute_root([b"x", b"Y", b"z"])
    assert a != b


def test_root_changes_when_a_leaf_is_removed() -> None:
    full = compute_root(_leaves(5))
    removed = compute_root(_leaves(5)[:4])
    assert full != removed


def test_root_hex_format() -> None:
    value = root_hex(_leaves(3))
    assert value.startswith("blake3:")
    assert len(value) == len("blake3:") + 64


def test_domain_separation_leaf_vs_node() -> None:
    # A leaf and an internal node over the same bytes must not collide.
    assert hash_leaf(b"ab") != hash_node(b"a", b"b")


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 9, 16, 17])
def test_inclusion_proof_verifies_for_every_leaf(n: int) -> None:
    leaves = _leaves(n)
    root = compute_root(leaves)
    for i in range(n):
        proof = inclusion_proof(leaves, i)
        assert verify_proof(leaves[i], proof, root)


def test_inclusion_proof_fails_for_wrong_leaf() -> None:
    leaves = _leaves(8)
    root = compute_root(leaves)
    proof = inclusion_proof(leaves, 3)
    assert not verify_proof(b"not-the-leaf", proof, root)


def test_inclusion_proof_out_of_range() -> None:
    with pytest.raises(IndexError):
        inclusion_proof(_leaves(4), 10)


def test_noop_anchor_satisfies_protocol() -> None:
    anchor: Anchor = NoOpAnchor()
    assert anchor.publish("blake3:deadbeef", 5) is None
    assert isinstance(anchor, Anchor)
