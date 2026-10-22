"""Threat / vulnerability intelligence, assets and LLM advisories."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from tokiwa.schemas.common import ORMModel, Severity


class SoftwareItem(BaseModel):
    vendor: str | None = None
    product: str
    version: str | None = None
    cpe: str | None = None  # cpe:2.3:a:vendor:product:version:...
    ecosystem: str | None = None  # OSV ecosystem (PyPI, npm, Go, Maven, Debian ...)


class AssetKind(StrEnum):
    HOST = "host"
    SERVICE = "service"
    WEB_APP = "web_app"
    LLM_APP = "llm_app"
    NETWORK_DEVICE = "network_device"
    OTHER = "other"


class AssetIn(BaseModel):
    name: str
    kind: AssetKind = AssetKind.HOST
    hostname: str | None = None
    ips: list[str] = Field(default_factory=list)
    software: list[SoftwareItem] = Field(default_factory=list)
    criticality: Severity = Severity.MEDIUM
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None


class Asset(AssetIn, ORMModel):
    id: str
    created_at: datetime
    updated_at: datetime


class VulnRecord(ORMModel):
    """A vulnerability merged across sources (keyed by CVE id when available, else GHSA/JVNDB id)."""

    id: str
    aliases: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)  # kev, nvd, epss, osv, jvn, ghsa, research
    title: str | None = None
    description: str | None = None
    published: datetime | None = None
    modified: datetime | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: Severity | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_date_added: datetime | None = None
    kev_due_date: datetime | None = None
    kev_ransomware: bool | None = None
    cwe: list[str] = Field(default_factory=list)
    affected: list[SoftwareItem] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class MatchStatus(StrEnum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class VulnMatch(ORMModel):
    id: str
    vuln_id: str
    asset_id: str
    software: SoftwareItem | None = None
    reason: str
    confidence: float
    status: MatchStatus
    created_at: datetime


class IntelItem(ORMModel):
    """News / advisory / research article."""

    id: str
    source: str
    url: str | None
    title: str
    summary: str | None
    published: datetime | None
    fetched_at: datetime
    vuln_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    relevance: float | None = None


class Priority(StrEnum):
    P1 = "P1"  # act now (exploited in the wild + exposed asset)
    P2 = "P2"  # this week
    P3 = "P3"  # next maintenance window
    P4 = "P4"  # informational


class ProposedRule(BaseModel):
    """A detection rule proposed by the LLM. Never auto-enabled; validated then queued for human review."""

    kind: str = Field(description="sigma")
    title: str
    content: str = Field(description="Rule body (Sigma YAML)")
    rationale: str


class AdvisoryAnalysis(BaseModel):
    """Fixed LLM output schema for a vulnerability advisory."""

    title: str
    priority: Priority
    summary: str
    exploitation_status: str = Field(description="e.g. exploited in the wild (KEV), PoC public, none known")
    affected_assets: list[str] = Field(
        default_factory=list, description="Asset ids from the provided inventory"
    )
    impact: str
    mitigations: list[str] = Field(default_factory=list)
    detection_opportunities: list[str] = Field(default_factory=list)
    proposed_rules: list[ProposedRule] = Field(default_factory=list, max_length=3)
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class Advisory(ORMModel):
    id: str
    created_at: datetime
    vuln_ids: list[str]
    title: str
    priority: Priority
    status: str  # new / acknowledged / done / dismissed
    analysis: AdvisoryAnalysis
    llm_call_id: str | None = None


class ResearchFinding(BaseModel):
    title: str
    summary: str
    cve_ids: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    exploitation: str = Field(description="in-the-wild / PoC / theoretical / unknown")
    relevance_to_assets: str
    recommended_actions: list[str] = Field(default_factory=list)
    source_urls: list[str] = Field(default_factory=list)


class ResearchOutput(BaseModel):
    """Fixed LLM output schema for periodic web research (0-day watch)."""

    findings: list[ResearchFinding] = Field(default_factory=list, max_length=15)
    overall_assessment: str


class ResearchReport(ORMModel):
    id: str
    created_at: datetime
    topic: str
    output: ResearchOutput
    citations: list[dict[str, Any]] = Field(default_factory=list)
    llm_call_id: str | None = None
