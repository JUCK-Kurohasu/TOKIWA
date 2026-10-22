"""Enricher interface: batch-level event mutation that runs BEFORE storage and detection.

Examples: sessionizer (assigns ``event.session_id``), asset mapper (``event.asset_id``), GeoIP/ASN.
Lower ``order`` runs first. Modules under ``tokiwa.enrich`` are auto-imported.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from tokiwa.schemas.events import Event


class Enricher(ABC):
    id: ClassVar[str]
    order: ClassVar[int] = 100

    @abstractmethod
    async def enrich(self, events: list[Event]) -> None:
        """Mutate events in place. Must be fast and must not raise for odd input."""


_ENRICHERS: dict[str, type[Enricher]] = {}


def register_enricher(cls: type[Enricher]) -> type[Enricher]:
    _ENRICHERS[cls.id] = cls
    return cls


def registered_enrichers() -> list[type[Enricher]]:
    return sorted(_ENRICHERS.values(), key=lambda c: c.order)
