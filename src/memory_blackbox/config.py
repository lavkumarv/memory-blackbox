"""Configuration for memory-blackbox.

Resolves the profile location from an explicit path, then the
``MEMORY_BLACKBOX_HOME`` environment variable, then a built-in default. Paths for
the ledger and signing key are derived from the home directory. Defaults are
chosen so that ``init`` -> ``demo`` works with zero configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_HOME = Path.home() / ".memory-blackbox"
ENV_HOME = "MEMORY_BLACKBOX_HOME"


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved runtime configuration."""

    home: Path = DEFAULT_HOME
    namespace: str = "default"
    async_flush: bool = False
    anchoring: bool = False

    @property
    def ledger_path(self) -> Path:
        return self.home / "ledger.db"

    @property
    def key_path(self) -> Path:
        return self.home / "signing.key"


def resolve_config(home: Path | str | None = None) -> Config:
    """Resolve the active configuration from an argument, env, or the default."""
    if home is None:
        env = os.environ.get(ENV_HOME)
        home = Path(env) if env else DEFAULT_HOME
    return Config(home=Path(home))
