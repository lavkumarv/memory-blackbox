"""Deterministic canonical serialization.

Every hash and signature in the system is taken over canonical bytes, so this
function is the foundation of all integrity. The output must be identical across
processes and machines for the same logical value — pinned by a golden-file test.

Rules:
1. Drop excluded fields (the ledger-set fields) at every level.
2. Recursively sort object keys.
3. Serialize with ``orjson`` (``OPT_SORT_KEYS``), UTF-8, no insignificant whitespace.
"""

from __future__ import annotations

from typing import Any

import orjson

# Fields populated by the ledger on append; never part of the signable payload.
LEDGER_SET_FIELDS = frozenset({"entry_hash", "prev_hash", "signature", "signer_kid", "merkle_leaf"})


def _prune(value: Any, exclude: frozenset[str]) -> Any:
    if isinstance(value, dict):
        return {k: _prune(v, exclude) for k, v in value.items() if k not in exclude}
    if isinstance(value, (list, tuple)):
        return [_prune(v, exclude) for v in value]
    return value


def canonical_bytes(
    obj: dict[str, Any], exclude: frozenset[str] | set[str] = LEDGER_SET_FIELDS
) -> bytes:
    """Return deterministic canonical bytes for ``obj``, dropping ``exclude`` keys."""
    pruned = _prune(obj, frozenset(exclude))
    return orjson.dumps(pruned, option=orjson.OPT_SORT_KEYS)
