"""BLAKE3 Merkle tree over ledger entry hashes.

The hash chain proves no row was *edited*; the Merkle root proves no row was
*removed*. A signed checkpoint records the root over the first ``leaf_count``
rows. Re-deriving the root over the current rows and comparing it to the last
signed checkpoint catches deletion — including tail truncation, which the chain
alone cannot detect because a truncated chain is still internally consistent.

Domain-separated hashing (RFC 6962 style) prevents leaf/node second-preimage
confusion: leaves are prefixed with ``0x00``, internal nodes with ``0x01``.
Odd nodes are promoted unchanged to the next level.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from memory_blackbox.crypto.hashing import b3_raw
from memory_blackbox.crypto.signing import verify

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def hash_leaf(data: bytes) -> bytes:
    """Hash a leaf payload with the leaf domain prefix."""
    return b3_raw(_LEAF_PREFIX + data)


def hash_node(left: bytes, right: bytes) -> bytes:
    """Hash two child nodes with the node domain prefix."""
    return b3_raw(_NODE_PREFIX + left + right)


def compute_root(leaves: list[bytes]) -> bytes:
    """Return the raw Merkle root over ``leaves`` (empty tree -> hash of empty)."""
    if not leaves:
        return b3_raw(b"")
    level = [hash_leaf(leaf) for leaf in leaves]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hash_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote odd node
        level = nxt
    return level[0]


def root_hex(leaves: list[bytes]) -> str:
    """Return the Merkle root as a namespaced ``blake3:<hex>`` string."""
    return "blake3:" + compute_root(leaves).hex()


# A proof step: (sibling_hash, sibling_is_on_the_left).
ProofStep = tuple[bytes, bool]


def inclusion_proof(leaves: list[bytes], index: int) -> list[ProofStep]:
    """Return the inclusion proof for the leaf at ``index``."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    nodes = [hash_leaf(leaf) for leaf in leaves]
    proof: list[ProofStep] = []
    idx = index
    while len(nodes) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                if i == idx:
                    proof.append((nodes[i + 1], False))  # sibling on the right
                elif i + 1 == idx:
                    proof.append((nodes[i], True))  # sibling on the left
                nxt.append(hash_node(nodes[i], nodes[i + 1]))
            else:
                nxt.append(nodes[i])  # promoted: no sibling, no proof step
        idx //= 2
        nodes = nxt
    return proof


def verify_proof(leaf: bytes, proof: list[ProofStep], root: bytes) -> bool:
    """Return ``True`` iff ``leaf`` with ``proof`` reconstructs ``root``."""
    node = hash_leaf(leaf)
    for sibling, sibling_on_left in proof:
        node = hash_node(sibling, node) if sibling_on_left else hash_node(node, sibling)
    return node == root


@dataclass(frozen=True, slots=True)
class MerkleReport:
    """Result of verifying the ledger against its latest signed checkpoint."""

    ok: bool
    leaf_count: int
    detail: str


def current_leaves(conn: sqlite3.Connection) -> list[bytes]:
    """Return the ledger's entry-hash leaves in seq order."""
    cursor = conn.cursor()
    return [
        row[0].encode("utf-8")
        for row in cursor.execute("SELECT entry_hash FROM ledger ORDER BY seq ASC")
    ]


def verify_merkle(conn: sqlite3.Connection, public_key: Ed25519PublicKey) -> MerkleReport:
    """Verify current rows against the latest signed Merkle checkpoint."""
    cursor = conn.cursor()
    cursor.row_factory = sqlite3.Row
    checkpoint = cursor.execute(
        "SELECT * FROM merkle_checkpoints ORDER BY id DESC LIMIT 1"
    ).fetchone()

    leaves = current_leaves(conn)

    if checkpoint is None:
        # No checkpoint yet: nothing removed can be proven, but nothing claims to
        # have been committed either. Treat as ok only when the ledger is empty.
        if leaves:
            return MerkleReport(
                False, len(leaves), "no signed checkpoint exists for a non-empty ledger"
            )
        return MerkleReport(True, 0, "empty ledger, no checkpoint required")

    leaf_count = int(checkpoint["leaf_count"])

    # 1. Verify the checkpoint signature over the raw root bytes.
    root_bytes = bytes.fromhex(checkpoint["root"].removeprefix("blake3:"))
    if not verify(root_bytes, checkpoint["signature"], public_key):
        return MerkleReport(False, leaf_count, "checkpoint signature does not verify")

    # 2. Truncation: fewer rows than the checkpoint committed -> rows were removed.
    if len(leaves) < leaf_count:
        return MerkleReport(
            False,
            leaf_count,
            f"ledger has {len(leaves)} rows but checkpoint committed {leaf_count}",
        )

    # 3. Recompute the root over the committed prefix and compare.
    if compute_root(leaves[:leaf_count]) != root_bytes:
        return MerkleReport(False, leaf_count, "recomputed root does not match signed checkpoint")

    return MerkleReport(True, leaf_count, "ok")
