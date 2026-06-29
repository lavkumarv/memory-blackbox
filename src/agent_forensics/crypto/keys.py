"""Ed25519 key generation, persistence, and loading.

The signing key is the most sensitive secret in the system: whoever holds it can
forge provenance. It lives in the engine/gateway and is never exposed to anything
the agent can reach — only the public key crosses that boundary.

Local profile: the private key is persisted to a ``0600`` file. Server profiles
load from an environment variable or a pluggable KMS (the KMS path is a documented
stub in v1).
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from agent_forensics.crypto.hashing import b3_raw
from agent_forensics.crypto.signing import sign

ENV_KEY = "AGENT_FORENSICS_SIGNING_KEY"
ENV_KID = "AGENT_FORENSICS_SIGNING_KID"
_KEY_FILE_VERSION = 1


def _kid_for(public_key: Ed25519PublicKey) -> str:
    """Derive a short, stable key id from the public key."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b3_raw(raw).hex()[:16]


@dataclass(frozen=True, slots=True)
class KeyPair:
    """An Ed25519 keypair plus its derived key id (``kid``)."""

    kid: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def sign(self, message: bytes) -> str:
        """Sign ``message`` with the private key, returning ``"ed25519:<hex>"``."""
        return sign(message, self.private_key)

    def public_key_hex(self) -> str:
        """Return the raw public key as hex (safe to expose to the agent)."""
        return self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _from_private_bytes(raw: bytes) -> KeyPair:
    private_key = Ed25519PrivateKey.from_private_bytes(raw)
    public_key = private_key.public_key()
    return KeyPair(kid=_kid_for(public_key), private_key=private_key, public_key=public_key)


def generate() -> KeyPair:
    """Generate a fresh Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return KeyPair(kid=_kid_for(public_key), private_key=private_key, public_key=public_key)


def save(keypair: KeyPair, path: Path | str) -> Path:
    """Persist ``keypair``'s private key to ``path`` with ``0600`` permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = keypair.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    payload = json.dumps(
        {"version": _KEY_FILE_VERSION, "kid": keypair.kid, "private_key": raw.hex()}
    ).encode("utf-8")
    # Create with restrictive permissions from the start, never world/group readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def load(path: Path | str) -> KeyPair:
    """Load a keypair previously written by :func:`save`."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return _from_private_bytes(bytes.fromhex(data["private_key"]))


def load_from_env(env_key: str = ENV_KEY) -> KeyPair:
    """Load a keypair from a hex-encoded private key in an environment variable."""
    raw_hex = os.environ.get(env_key)
    if not raw_hex:
        raise KeyError(f"environment variable {env_key} is not set")
    return _from_private_bytes(bytes.fromhex(raw_hex))


def load_from_kms(key_ref: str) -> KeyPair:  # pragma: no cover - documented stub for v1
    """Load a signing key from an external KMS/HSM.

    v1 ships the local-file and environment paths; KMS/HSM integration is the
    high-assurance server upgrade and is intentionally not implemented yet.
    """
    raise NotImplementedError(
        "KMS-backed signing keys are not implemented in v1; "
        "use save()/load() (local 0600 file) or load_from_env()."
    )
