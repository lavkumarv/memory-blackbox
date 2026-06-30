"""Tests for Ed25519 signing and verification (spec §15.1)."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from memory_blackbox.crypto.signing import sign, verify


def test_sign_verify_round_trip() -> None:
    priv = Ed25519PrivateKey.generate()
    message = b"the entry hash digest"
    signature = sign(message, priv)
    assert signature.startswith("ed25519:")
    assert verify(message, signature, priv.public_key())


def test_verify_fails_on_flipped_bit() -> None:
    priv = Ed25519PrivateKey.generate()
    message = b"the entry hash digest"
    signature = sign(message, priv)
    tampered = bytearray(message)
    tampered[0] ^= 0x01
    assert not verify(bytes(tampered), signature, priv.public_key())


def test_verify_fails_with_wrong_public_key() -> None:
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    message = b"the entry hash digest"
    signature = sign(message, priv)
    assert not verify(message, signature, other.public_key())


def test_verify_rejects_malformed_signature() -> None:
    priv = Ed25519PrivateKey.generate()
    assert not verify(b"msg", "not-ed25519:deadbeef", priv.public_key())
    assert not verify(b"msg", "ed25519:zzzz", priv.public_key())
