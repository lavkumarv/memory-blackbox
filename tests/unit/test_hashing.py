"""Tests for BLAKE3 hashing helpers (spec §15.1)."""

from __future__ import annotations

from agent_forensics.crypto.hashing import b3, b3_raw

# Published BLAKE3 known-answer vector for the empty input.
EMPTY_BLAKE3 = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"


def test_b3_known_answer_empty() -> None:
    assert b3(b"") == f"blake3:{EMPTY_BLAKE3}"


def test_b3_raw_known_answer_empty() -> None:
    assert b3_raw(b"") == bytes.fromhex(EMPTY_BLAKE3)


def test_b3_format_and_length() -> None:
    digest = b3(b"hello world")
    assert digest.startswith("blake3:")
    assert len(digest) == len("blake3:") + 64


def test_b3_raw_is_32_bytes() -> None:
    assert len(b3_raw(b"hello world")) == 32


def test_b3_distinguishes_inputs() -> None:
    assert b3(b"a") != b3(b"b")


def test_b3_and_b3_raw_agree() -> None:
    assert b3(b"abc") == f"blake3:{b3_raw(b'abc').hex()}"
