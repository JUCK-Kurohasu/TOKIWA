"""SigmaDetector draft mapping and SigmaRuleStore loading / hit batching (no API)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import select

from tokiwa.config import Settings
from tokiwa.db.models.detection import RuleRow
from tokiwa.db.session import session_scope
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.detectors.sigma import SigmaDetector
from tokiwa.detect.sigma import SigmaRuleStore, mitre_from_tags, sync_builtin_rules
from tokiwa.schemas.alerts import AlertCategory
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event

MakeEvent = Callable[..., Event]

AI_RULE = """
title: Agent probe
id: 11111111-2222-4333-8444-555555555555
status: stable
level: critical
description: probe
tags: [attack.reconnaissance, attack.t1595.003, tokiwa.category.ai_agent, tokiwa.ai_score.80]
falsepositives: [lab only]
logsource: {category: webserver}
detection:
  sel:
    cs-uri-stem: /agent-probe
  condition: sel
"""


def store_for(settings: Settings, rules_dir: Path) -> SigmaRuleStore:
    s = settings.model_copy(deep=True)
    s.detection.sigma_rule_dirs = [rules_dir]
    return SigmaRuleStore(s)


def test_mitre_from_tags() -> None:
    tags = ["attack.t1190", "attack.T1059.007", "attack.initial_access", "attack.t1190", "cve.2021-44228"]
    assert mitre_from_tags(tags) == ["T1190", "T1059.007"]


async def test_detector_draft_fields(settings: Settings, tmp_path: Path, make_http_event: MakeEvent) -> None:
    (tmp_path / "probe.yml").write_text(AI_RULE)
    det = SigmaDetector()
    det.store = store_for(settings, tmp_path)
    ev = make_http_event("/agent-probe")
    drafts = await det.process(ev, DetectionContext(settings))
    assert len(drafts) == 1
    d = drafts[0]
    assert d.rule_id == "sigma:11111111-2222-4333-8444-555555555555"
    assert d.severity == Severity.CRITICAL and d.confidence == 0.85
    assert d.category == AlertCategory.AI_AGENT and d.ai_score == 0.8
    assert d.mitre == ["T1595.003"] and "sigma" in d.tags
    assert d.evidence_event_ids == [ev.id] and d.source_ip == ev.source_ip
    assert d.entities == {"host": "app.lab", "path": "/agent-probe"}
    assert d.details["falsepositives"] == ["lab only"] and d.details["rule_origin"] == "file"
    assert await det.process(make_http_event("/other"), DetectionContext(settings)) == []
    # hits are counted in memory only (no DB row linked for pure file rules)
    assert det.store.hits["11111111-2222-4333-8444-555555555555"] == 1
    assert det.store.pending_hits() == {}


def test_invalid_and_duplicate_files_are_skipped(settings: Settings, tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(AI_RULE)
    (tmp_path / "b.yml").write_text(AI_RULE)  # same id
    (tmp_path / "broken.yml").write_text("title: broken\nlogsource: {category: webserver}\ndetection: {}")
    (tmp_path / ".hidden").mkdir()
    (tmp_path / ".hidden" / "c.yml").write_text(AI_RULE.replace("11111111", "22222222"))
    store = store_for(settings, tmp_path)
    store.reload_files()
    assert [lr.key for lr in store.rules()] == ["11111111-2222-4333-8444-555555555555"]
    assert set(store.errors) == {"file:b.yml", "file:broken.yml"}


def test_missing_rule_dir_is_not_fatal(settings: Settings, tmp_path: Path) -> None:
    store = store_for(settings, tmp_path / "does-not-exist")
    assert store.rules() == []


@pytest.mark.usefixtures("db")
async def test_hit_counts_are_batched_and_flushed(
    settings: Settings, tmp_path: Path, make_http_event: MakeEvent
) -> None:
    (tmp_path / "probe.yml").write_text(AI_RULE)
    det = SigmaDetector()
    det.store = store_for(settings, tmp_path)
    stats = await sync_builtin_rules(det.store)
    assert stats == {"created": 1, "updated": 0, "deleted": 0}
    await det.store.reload()
    lr = det.store.rules()[0]
    assert lr.db_id

    ctx = DetectionContext(settings)
    for _ in range(3):
        await det.process(make_http_event("/agent-probe"), ctx)
    assert det.store.pending_hits() == {lr.db_id: 3}
    async with session_scope() as s:
        assert (await s.get(RuleRow, lr.db_id)).hit_count == 0  # type: ignore[union-attr]

    assert await det.store.flush_hits() == 1
    assert det.store.pending_hits() == {}
    async with session_scope() as s:
        row = (await s.execute(select(RuleRow).where(RuleRow.id == lr.db_id))).scalar_one()
        assert row.hit_count == 3

    # re-sync is idempotent; removing the file removes the builtin row
    assert await sync_builtin_rules(det.store) == {"created": 0, "updated": 0, "deleted": 0}
    (tmp_path / "probe.yml").unlink()
    assert (await sync_builtin_rules(det.store))["deleted"] == 1
