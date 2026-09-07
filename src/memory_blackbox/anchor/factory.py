"""Build the configured anchoring backend."""

from __future__ import annotations

from typing import TYPE_CHECKING

from memory_blackbox.anchor.base import Anchor, NoOpAnchor
from memory_blackbox.anchor.file_witness import FileWitnessAnchor
from memory_blackbox.config import ANCHOR_FILE, ANCHOR_NONE, ANCHOR_REKOR

if TYPE_CHECKING:
    from memory_blackbox.config import Config


def build_anchor(config: Config) -> Anchor:
    """Return the anchoring backend named by ``config``.

    Rekor is imported lazily so that a local-only install never pays for, or
    accidentally reaches, the network path.
    """
    if config.anchor_backend == ANCHOR_NONE:
        return NoOpAnchor()
    if config.anchor_backend == ANCHOR_FILE:
        return FileWitnessAnchor(config.default_witness_path)
    if config.anchor_backend == ANCHOR_REKOR:
        from memory_blackbox.anchor.rekor import PUBLIC_REKOR_URL, RekorAnchor

        return RekorAnchor(config.rekor_url or PUBLIC_REKOR_URL)
    raise ValueError(f"unknown anchoring backend: {config.anchor_backend!r}")
