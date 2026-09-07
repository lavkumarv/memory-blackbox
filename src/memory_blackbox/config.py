"""Configuration for memory-blackbox.

Resolves the profile location from an explicit path, then the
``MEMORY_BLACKBOX_HOME`` environment variable, then a built-in default. Paths for
the ledger and signing key are derived from the home directory. Defaults are
chosen so that ``init`` -> ``demo`` works with zero configuration.

Anchoring is off by default. It reaches an external service, which a local-first
tool should never do without being asked, so the operator opts in by naming a
backend (see ``docs/anchoring.md``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_HOME = Path.home() / ".memory-blackbox"
ENV_HOME = "MEMORY_BLACKBOX_HOME"
ENV_ANCHOR_BACKEND = "MEMORY_BLACKBOX_ANCHOR"
ENV_ANCHOR_WITNESS = "MEMORY_BLACKBOX_ANCHOR_WITNESS"
ENV_ANCHOR_REKOR_URL = "MEMORY_BLACKBOX_ANCHOR_REKOR_URL"

# Backend names accepted by --backend and the environment.
ANCHOR_NONE = "none"
ANCHOR_FILE = "file"
ANCHOR_REKOR = "rekor"
ANCHOR_BACKENDS = frozenset({ANCHOR_NONE, ANCHOR_FILE, ANCHOR_REKOR})


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved runtime configuration."""

    home: Path = DEFAULT_HOME
    namespace: str = "default"
    async_flush: bool = False
    anchor_backend: str = ANCHOR_NONE
    witness_path: Path | None = None
    rekor_url: str | None = None

    @property
    def ledger_path(self) -> Path:
        return self.home / "ledger.db"

    @property
    def key_path(self) -> Path:
        return self.home / "signing.key"

    @property
    def anchoring(self) -> bool:
        """Whether an external anchoring backend is configured."""
        return self.anchor_backend != ANCHOR_NONE

    @property
    def default_witness_path(self) -> Path:
        """Where the file witness lives when no explicit path is given.

        Inside the profile by default so it works with zero configuration, which
        is also its weakest placement -- an attacker who can rewrite the ledger can
        rewrite a witness sitting beside it. Point ``witness_path`` at independent
        storage for the guarantee to mean anything.
        """
        return self.witness_path or self.home / "witness.jsonl"


def resolve_config(home: Path | str | None = None) -> Config:
    """Resolve the active configuration from an argument, env, or the default."""
    if home is None:
        env = os.environ.get(ENV_HOME)
        home = Path(env) if env else DEFAULT_HOME
    backend = os.environ.get(ENV_ANCHOR_BACKEND, ANCHOR_NONE).strip().lower() or ANCHOR_NONE
    if backend not in ANCHOR_BACKENDS:
        raise ValueError(
            f"{ENV_ANCHOR_BACKEND}={backend!r} is not a known anchoring backend "
            f"({', '.join(sorted(ANCHOR_BACKENDS))})"
        )
    witness = os.environ.get(ENV_ANCHOR_WITNESS)
    return Config(
        home=Path(home),
        anchor_backend=backend,
        witness_path=Path(witness) if witness else None,
        rekor_url=os.environ.get(ENV_ANCHOR_REKOR_URL) or None,
    )
