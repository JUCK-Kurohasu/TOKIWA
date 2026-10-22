"""Shared enums and generic API models."""

from __future__ import annotations

from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def max(cls, *values: Severity) -> Severity:
        return max(values, key=lambda s: s.rank)

    def at_least(self, other: Severity | str) -> bool:
        return self.rank >= Severity(other).rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ActorType(StrEnum):
    """Who is behind an activity. ``ai_agent`` = LLM-driven autonomous tooling (e.g. ARTEX-like agents)."""

    HUMAN = "human"
    AUTOMATED_SCANNER = "automated_scanner"
    AI_AGENT = "ai_agent"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int = 0


class Message(BaseModel):
    message: str
