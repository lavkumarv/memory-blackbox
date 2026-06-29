"""Detector protocol, context, and registry.

Detectors inspect each memory write and emit findings. They are discovered through
a registry (and, later, entry-point plugins) so third parties can ship detector
packs. The concrete built-in pack lands in M7; this module defines the contract the
capture engine calls.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from agent_forensics.model.records import Finding, LedgerRecord


@dataclass(frozen=True, slots=True)
class DetectorContext:
    """Read-only context passed to a detector for a single inspection."""

    namespace: str
    now: datetime
    extra: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class Detector(Protocol):
    """Inspects a record's content and returns zero or more findings."""

    name: str

    def inspect(
        self, record: LedgerRecord, content: str, ctx: DetectorContext
    ) -> list[Finding]: ...


# Registry of named detectors. The built-in pack registers itself in M7.
_REGISTRY: dict[str, Detector] = {}


def register(detector: Detector) -> Detector:
    """Register ``detector`` by its name; returns it for decorator-style use."""
    _REGISTRY[detector.name] = detector
    return detector


def get(name: str) -> Detector:
    return _REGISTRY[name]


def all_detectors() -> list[Detector]:
    return list(_REGISTRY.values())


def pack(names: Iterable[str] | None = None) -> list[Detector]:
    """Return detectors by name, or the whole registry when ``names`` is None."""
    if names is None:
        return all_detectors()
    return [_REGISTRY[n] for n in names]


# The default pack is empty until the built-in detectors register in M7.
DEFAULT_PACK: list[Detector] = []
