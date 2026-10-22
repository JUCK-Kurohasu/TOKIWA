"""Detector interface and registry.

A detector consumes normalized events and returns :class:`AlertDraft` objects. Two flavours:

* stateless matchers (signature rules: SQLi, scanner UA, ...) - look at one event;
* stateful/windowed detectors (rate, cadence, scan, mutation) - keep per-key state in ``ctx.state``.

Register with the decorator; modules under ``tokiwa.detect.detectors`` are imported automatically::

    @register_detector
    class SqliDetector(Detector):
        id = "web.sqli"
        name = "SQL injection attempt"
        description = "..."
        category = AlertCategory.EXPLOIT_ATTEMPT
        kinds = frozenset({EventKind.HTTP})
        mitre = ("T1190",)

        async def process(self, event, ctx):
            ...
            return [self.draft(event, title=..., severity=Severity.HIGH)]
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind


class Detector(ABC):
    id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str] = ""
    category: ClassVar[AlertCategory] = AlertCategory.OTHER
    kinds: ClassVar[frozenset[EventKind]] = frozenset()  # empty = all kinds
    mitre: ClassVar[tuple[str, ...]] = ()
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    enabled_by_default: ClassVar[bool] = True

    def accepts(self, event: Event) -> bool:
        return not self.kinds or event.kind in self.kinds

    @abstractmethod
    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        """Return zero or more alert drafts for this event. Must not raise for odd input."""

    def draft(
        self,
        event: Event | None,
        *,
        title: str,
        severity: Severity | None = None,
        description: str = "",
        confidence: float = 0.7,
        category: AlertCategory | None = None,
        ai_score: float | None = None,
        evidence: list[str] | None = None,
        entities: dict[str, str] | None = None,
        tags: list[str] | None = None,
        fingerprint: str | None = None,
        details: dict[str, Any] | None = None,
        rule_id: str | None = None,
        mitre: list[str] | None = None,
        source_ip: str | None = None,
    ) -> AlertDraft:
        return AlertDraft(
            rule_id=rule_id or self.id,
            title=title,
            description=description,
            severity=severity or self.default_severity,
            confidence=confidence,
            category=category or self.category,
            mitre=list(mitre if mitre is not None else self.mitre),
            ai_score=ai_score,
            source_ip=source_ip if source_ip is not None else (event.source_ip if event else None),
            entities=entities or {},
            evidence_event_ids=evidence if evidence is not None else ([event.id] if event else []),
            tags=tags or [],
            fingerprint=fingerprint,
            details=details or {},
        )


_REGISTRY: dict[str, type[Detector]] = {}


def register_detector(cls: type[Detector]) -> type[Detector]:
    if not getattr(cls, "id", None):
        raise ValueError(f"{cls.__name__} must define a non-empty 'id'")
    existing = _REGISTRY.get(cls.id)
    if existing is not None and existing is not cls and existing.__qualname__ != cls.__qualname__:
        raise ValueError(f"duplicate detector id {cls.id!r}: {existing.__qualname__} vs {cls.__qualname__}")
    _REGISTRY[cls.id] = cls
    return cls


def registered_detectors() -> dict[str, type[Detector]]:
    return dict(_REGISTRY)


# Imported late to avoid a cycle (context imports nothing from here at runtime).
from tokiwa.detect.context import DetectionContext  # noqa: E402
