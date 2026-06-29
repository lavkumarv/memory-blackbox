"""Ed25519 signing and verification.

The engine signs the raw BLAKE3 digest of each ledger entry's link input. Signatures
are namespaced (``"ed25519:<hex>"``) so the scheme travels with the value. Verification
is total: a malformed or wrong signature returns ``False`` rather than raising.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIG_PREFIX = "ed25519:"


def sign(message: bytes, private_key: Ed25519PrivateKey) -> str:
    """Sign ``message`` and return ``"ed25519:<hex>"``."""
    return SIG_PREFIX + private_key.sign(message).hex()


def verify(message: bytes, signature: str, public_key: Ed25519PublicKey) -> bool:
    """Return ``True`` iff ``signature`` is a valid Ed25519 signature of ``message``."""
    if not signature.startswith(SIG_PREFIX):
        return False
    try:
        raw = bytes.fromhex(signature[len(SIG_PREFIX) :])
    except ValueError:
        return False
    try:
        public_key.verify(raw, message)
    except InvalidSignature:
        return False
    return True
