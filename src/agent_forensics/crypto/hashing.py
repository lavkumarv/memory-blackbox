"""BLAKE3 hashing helpers.

Two forms are exposed:

- :func:`b3` returns a namespaced hex string (``"blake3:<hex>"``) used in records
  and the ledger so the algorithm travels with the value.
- :func:`b3_raw` returns the raw 32-byte digest, used as Merkle leaves and as the
  message that gets Ed25519-signed.
"""

from __future__ import annotations

import blake3

HASH_PREFIX = "blake3:"


def b3(data: bytes) -> str:
    """Return the BLAKE3 digest of ``data`` as ``"blake3:<hex>"``."""
    return HASH_PREFIX + blake3.blake3(data).hexdigest()


def b3_raw(data: bytes) -> bytes:
    """Return the raw 32-byte BLAKE3 digest of ``data``."""
    return blake3.blake3(data).digest()
