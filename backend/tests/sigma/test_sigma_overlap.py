"""Bundled Sigma web rules vs. native web.* detectors: one alert per finding (audit #76)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml

from tokiwa.config import Settings, default_sigma_rule_dirs
from tokiwa.detect.engine import DetectionEngine
from tokiwa.detect.sigma.overlap import (
    CORROBORATED_TAG,
    NATIVE_OVERLAP,
    NATIVE_SILENT_TAG,
    merge_native_overlap,
)
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

TRAVERSAL_RULE = "sigma:e9c1a34a-6610-4569-b5ae-1a23ce7790ad"


def _draft(rule_id: str, severity: Severity, origin: str | None = "file") -> AlertDraft:
    details = {"rule_origin": origin} if origin else {}
    return AlertDraft(
        rule_id=rule_id,
        title=rule_id,
        severity=severity,
        category=AlertCategory.EXPLOIT_ATTEMPT,
        details=details,
    )


def test_every_bundled_web_rule_is_mapped_to_a_registered_detector(settings: Settings) -> None:
    web_dir = default_sigma_rule_dirs()[0] / "web"
    ids = {yaml.safe_load(p.read_text(encoding="utf-8"))["id"] for p in Path(web_dir).glob("*.yml")}
    assert ids == set(NATIVE_OVERLAP)
    detectors = DetectionEngine(settings).all_detectors()
    assert set(NATIVE_OVERLAP.values()) <= set(detectors)


async def test_native_hit_absorbs_the_sigma_duplicate(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    engine = DetectionEngine(settings)
    drafts = await engine.run([make_http_event("/docs", query="file=guide/../intro.md")])
    by_rule = {d.rule_id: d for d in drafts}
    assert TRAVERSAL_RULE not in by_rule  # was a second, *high* alert next to the native medium one
    native = by_rule["web.path_traversal"]
    assert native.severity == Severity.MEDIUM
    assert native.details["corroborated_by"] == [TRAVERSAL_RULE]
    assert CORROBORATED_TAG in native.tags


async def test_sigma_keeps_its_level_when_the_native_detector_is_disabled(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    settings.detection.disabled_detectors.append("web.path_traversal")
    drafts = await DetectionEngine(settings).run([make_http_event("/docs", query="file=guide/../intro.md")])
    sigma = next(d for d in drafts if d.rule_id == TRAVERSAL_RULE)
    assert sigma.severity == Severity.HIGH
    assert NATIVE_SILENT_TAG not in sigma.tags


def test_sigma_only_hit_is_a_low_fallback_while_native_is_enabled() -> None:
    sigma = _draft(TRAVERSAL_RULE, Severity.HIGH)
    other = _draft("ai.agent_session", Severity.MEDIUM, origin=None)
    out = merge_native_overlap([sigma, other], enabled={"web.path_traversal"})
    assert out == [sigma, other]
    assert sigma.severity == Severity.LOW
    assert sigma.details["native_detector"] == "web.path_traversal"
    assert sigma.details["native_verdict"] == "silent"
    assert sigma.details["sigma_level_severity"] == "high"
    assert NATIVE_SILENT_TAG in sigma.tags


def test_user_rules_are_never_merged() -> None:
    user = _draft(TRAVERSAL_RULE, Severity.HIGH, origin="db")  # same key, but from the rules table
    native = _draft("web.path_traversal", Severity.MEDIUM, origin=None)
    out = merge_native_overlap([user, native], enabled={"web.path_traversal"})
    assert out == [user, native] and user.severity == Severity.HIGH
