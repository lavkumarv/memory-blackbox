"""Embedding hook for semantic drift detection.

Drift needs to know which writes are about the same topic. That requires
embeddings, but CI must run offline and deterministically, so the default is a
dependency-free hashing embedder (normalized bag-of-words over hashed tokens).
A real model (sentence-transformers) can be plugged in behind the ``drift`` extra
without changing any caller.
"""

from __future__ import annotations

import math
import re
from typing import Protocol, runtime_checkable

from memory_blackbox.crypto.hashing import b3_raw

_TOKEN = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    {"the", "a", "an", "of", "is", "are", "to", "in", "on", "and", "or", "it", "its", "was"}
)

Vector = list[float]


@runtime_checkable
class Embedder(Protocol):
    """Maps text to a fixed-length embedding vector."""

    def embed(self, text: str) -> Vector: ...


def _tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS]


def _normalize(vector: Vector) -> Vector:
    norm = math.sqrt(sum(x * x for x in vector))
    if norm == 0.0:
        return vector
    return [x / norm for x in vector]


def cosine(a: Vector, b: Vector) -> float:
    """Cosine similarity of two equal-length vectors."""
    return sum(x * y for x, y in zip(a, b, strict=False))


def centroid(vectors: list[Vector]) -> Vector:
    """Return the L2-normalized mean of ``vectors`` (empty -> empty)."""
    if not vectors:
        return []
    dim = len(vectors[0])
    summed = [0.0] * dim
    for vector in vectors:
        for i, value in enumerate(vector):
            summed[i] += value
    return _normalize([s / len(vectors) for s in summed])


class HashingEmbedder:
    """Deterministic, offline bag-of-words embedder (hashed token frequencies)."""

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def embed(self, text: str) -> Vector:
        vector = [0.0] * self.dim
        for token in _tokenize(text):
            # Stable across processes (unlike the built-in, salted hash()).
            index = int.from_bytes(b3_raw(token.encode("utf-8"))[:4], "big") % self.dim
            vector[index] += 1.0
        return _normalize(vector)
