"""Timeline: the chronological narrative of events touching a topic."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from memory_blackbox.ledger.store import LedgerStore


@dataclass(frozen=True, slots=True)
class Event:
    """A single ledger event in a topic timeline."""

    record_id: str
    kind: str
    timestamp: str
    text: str


def _event_text(payload: dict[str, Any]) -> str:
    return str(
        payload.get("content")
        or payload.get("query")
        or payload.get("summary")
        or payload.get("reason")
        or ""
    )


def _event_time(payload: dict[str, Any]) -> str:
    return str(payload.get("created_at") or payload.get("applied_at") or "")


def timeline(ledger: LedgerStore, topic: str) -> list[Event]:
    """Return events whose text mentions ``topic``, in chronological order."""
    needle = topic.lower()
    events: list[Event] = []
    for row, payload in ledger.iter_payloads():
        text = _event_text(payload)
        if needle in text.lower():
            events.append(
                Event(
                    record_id=row["record_id"],
                    kind=payload.get("kind", ""),
                    timestamp=_event_time(payload),
                    text=text,
                )
            )
    events.sort(key=lambda e: e.timestamp)
    return events
