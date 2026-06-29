"""Tests for key generation, persistence, and loading (spec §15.1)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from agent_forensics.crypto import keys
from agent_forensics.crypto.signing import verify


def _private_raw(kp: keys.KeyPair) -> bytes:
    return kp.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def test_generate_produces_stable_kid() -> None:
    kp = keys.generate()
    assert len(kp.kid) == 16
    # kid is derived from the public key, so it is reproducible for the same key.
    reloaded = keys._from_private_bytes(_private_raw(kp))
    assert reloaded.kid == kp.kid


def test_save_creates_0600_file(tmp_path: Path) -> None:
    kp = keys.generate()
    path = keys.save(kp, tmp_path / "signing.key")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_save_load_round_trip(tmp_path: Path) -> None:
    kp = keys.generate()
    path = keys.save(kp, tmp_path / "signing.key")
    loaded = keys.load(path)
    assert loaded.kid == kp.kid
    # A signature from the loaded key verifies against the original public key.
    message = b"round-trip message"
    assert verify(message, loaded.sign(message), kp.public_key)


def test_load_from_env_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    kp = keys.generate()
    monkeypatch.setenv(keys.ENV_KEY, _private_raw(kp).hex())
    loaded = keys.load_from_env()
    assert loaded.kid == kp.kid


def test_load_from_env_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(keys.ENV_KEY, raising=False)
    with pytest.raises(KeyError):
        keys.load_from_env()


def test_public_key_hex_is_exposed_safely() -> None:
    kp = keys.generate()
    hex_pub = kp.public_key_hex()
    assert len(hex_pub) == 64  # 32 raw bytes
