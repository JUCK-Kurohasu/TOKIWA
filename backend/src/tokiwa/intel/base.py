"""Intel source interface. Sources live in ``tokiwa.intel.sources`` (auto-imported) and register themselves.

A source fetches *raw* records and maps them to :class:`VulnRecord` / :class:`IntelItemIn`. Merging into the
``vulns`` table (multiple sources contribute fields to the same CVE) is done by ``tokiwa.intel.store``.

Network access in CI/sandboxes is often blocked: every source must be testable with recorded fixtures
(tests/fixtures/intel/<source>/...) by injecting an ``httpx.AsyncClient`` with a mock transport.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar

import httpx
from pydantic import BaseModel, Field

from tokiwa.config import Settings
from tokiwa.schemas.intel import VulnRecord


class IntelItemIn(BaseModel):
    source: str
    url: str | None = None
    title: str
    summary: str | None = None
    published: datetime | None = None
    vuln_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


@dataclass
class SourceResult:
    vulns: list[VulnRecord] = field(default_factory=list)
    items: list[IntelItemIn] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class IntelSource(ABC):
    id: ClassVar[str]  # matches the key in IntelSettings.sources
    name: ClassVar[str]

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def enabled(self) -> bool:
        return bool(self.settings.intel.sources.get(self.id, False))

    @abstractmethod
    async def fetch(self, client: httpx.AsyncClient, since: datetime | None) -> SourceResult:
        """Fetch records modified since ``since`` (None = initial/backfill window)."""


_SOURCES: dict[str, type[IntelSource]] = {}


def register_source(cls: type[IntelSource]) -> type[IntelSource]:
    _SOURCES[cls.id] = cls
    return cls


def registered_sources() -> dict[str, type[IntelSource]]:
    return dict(_SOURCES)
