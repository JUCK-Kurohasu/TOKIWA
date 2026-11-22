"""``tokiwa data purge|export`` (audit #158, finding L17-04)."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from typer.testing import CliRunner

from tokiwa import cli
from tokiwa.config import Settings
from tokiwa.db import session as dbsession
from tokiwa.db.models.core import AuditRow
from tokiwa.db.models.deception import DeceptionTripRow
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.pipeline.store import store_events
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo
from tokiwa.util import utcnow

SUBJECT = "198.51.100.1"
NEIGHBOUR = "198.51.100.15"  # must not match SUBJECT by substring
PII = "tel=090-1234-5678"


def _event(ip: str, session_id: str, ago: timedelta) -> Event:
    return Event(
        timestamp=utcnow() - ago,
        kind=EventKind.HTTP,
        dataset="gate.http",
        source=Endpoint(ip=ip),
        session_id=session_id,
        http=HttpInfo(method="POST", path="/signup", request_body=PII if ip == SUBJECT else "x=1"),
    )


def _llm(cid: str, text: str, related: dict[str, str] | None = None) -> LLMCallRow:
    return LLMCallRow(
        id=cid, created_at=utcnow(), provider="mock", model="m", tier="fast", purpose="triage", prompt_version="v",
        status="ok", input_tokens=1, output_tokens=1, cache_read_tokens=0, cache_write_tokens=0,
        web_search_requests=0, cost_usd=0.01, latency_ms=1.0, related=related or {}, request_redacted=text,
        response_text="ok",
    )  # fmt: skip


async def _seed() -> dict[str, str]:
    dbsession.init_engine()
    try:
        await dbsession.create_all()
        subj = _event(SUBJECT, "sess-subj", timedelta(days=10))
        recent = _event(SUBJECT, "sess-subj", timedelta(minutes=1))
        other = _event(NEIGHBOUR, "sess-other", timedelta(minutes=1))
        async with dbsession.session_scope() as s:
            await store_events(s, [subj, recent, other])
            now = utcnow()
            for sid, ip in (("sess-subj", SUBJECT), ("sess-other", NEIGHBOUR)):
                s.add(
                    ActorSessionRow(
                        id=sid, source_ip=ip, client_fingerprint="f", first_seen=now, last_seen=now
                    )
                )
            s.add(
                DeceptionTripRow(
                    id="trip-1", timestamp=now, asset_id="a", asset_kind="decoy_path", event_id=subj.id,
                    source_ip=SUBJECT, trip_type="decoy_path", detail={"path": "/.env"},
                )
            )  # fmt: skip
            for aid, ip in (("alert-subj", SUBJECT), ("alert-other", NEIGHBOUR)):
                s.add(
                    AlertRow(
                        id=aid, fingerprint=aid, rule_id="r", detector="d", title="t", severity="high",
                        category="web_attack", source_ip=ip, details={"excerpt": PII},
                    )
                )  # fmt: skip
            s.add(_llm("llm-text", f"evidence: {SUBJECT} sent {PII}"))
            s.add(_llm("llm-related", "no ip here", {"alert_id": "alert-subj"}))
            s.add(_llm("llm-other", f"evidence: {NEIGHBOUR} sent x=1"))
        return {"subj": subj.id, "recent": recent.id, "other": other.id}
    finally:
        await dbsession.dispose_engine()


async def _state() -> dict[str, Any]:
    dbsession.init_engine()
    try:
        async with dbsession.session_scope() as s:
            return {
                "events": set((await s.execute(select(EventRow.id))).scalars()),
                "sessions": set((await s.execute(select(ActorSessionRow.id))).scalars()),
                "trips": set((await s.execute(select(DeceptionTripRow.id))).scalars()),
                "alert_details": {a.id: a.details for a in (await s.execute(select(AlertRow))).scalars()},
                "llm": {c.id: c.request_redacted for c in (await s.execute(select(LLMCallRow))).scalars()},
                "audit": [
                    (a.actor, a.action, a.details) for a in (await s.execute(select(AuditRow))).scalars()
                ],
            }
    finally:
        await dbsession.dispose_engine()


def _run(*args: str) -> str:
    result = CliRunner().invoke(cli.app, ["data", *args])
    assert result.exit_code == 0, result.output
    return result.output


def test_purge_by_ip_is_dry_run_by_default_then_scrubs_every_table(settings: Settings) -> None:
    ids = asyncio.run(_seed())
    out = _run("purge", "--ip", SUBJECT)
    assert "dry run" in out and "events=2" in out and "llm_calls=2" in out
    assert len(asyncio.run(_state())["events"]) == 3  # nothing deleted yet

    out = _run("purge", "--ip", SUBJECT, "--yes")
    assert "purged: events=2, actor_sessions=1, deception_trips=1, alerts=1, llm_calls=2" in out
    st = asyncio.run(_state())
    assert st["events"] == {ids["other"]} and st["sessions"] == {"sess-other"} and st["trips"] == set()
    assert st["alert_details"] == {"alert-subj": {"purged": True}, "alert-other": {"excerpt": PII}}
    assert st["llm"] == {
        "llm-text": None,
        "llm-related": None,
        "llm-other": f"evidence: {NEIGHBOUR} sent x=1",
    }
    actions = [(a, act) for a, act, _ in st["audit"]]
    assert actions == [("cli", "data.purge.dry_run"), ("cli", "data.purge")]
    assert st["audit"][1][2]["counts"]["events"] == 2


def test_purge_by_session_and_before(settings: Settings) -> None:
    ids = asyncio.run(_seed())
    _run("purge", "--session", "sess-subj", "--before", (utcnow() - timedelta(days=1)).isoformat(), "--yes")
    st = asyncio.run(_state())
    assert st["events"] == {ids["recent"], ids["other"]}  # only the old event of that session
    assert st["trips"] == set()  # trip of the purged event


def test_export_by_ip_writes_private_jsonl(settings: Settings, tmp_path: Path) -> None:
    asyncio.run(_seed())
    out = tmp_path / "subject.jsonl"
    result = CliRunner().invoke(cli.app, ["data", "export", "--ip", SUBJECT, "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert oct(out.stat().st_mode & 0o777) == "0o600"
    records = [json.loads(line) for line in out.read_text().splitlines()]
    tables = sorted({r["table"] for r in records})
    assert tables == ["actor_sessions", "alerts", "deception_trips", "events", "llm_calls"]
    assert sum(r["table"] == "events" for r in records) == 2
    assert PII in out.read_text() and NEIGHBOUR not in out.read_text()
    assert asyncio.run(_state())["audit"][-1][1] == "data.export"


def test_selector_validation(settings: Settings) -> None:
    for args in ([], ["--ip", "not-an-ip"], ["--before", "yesterday"]):
        result = CliRunner().invoke(cli.app, ["data", "purge", *args])
        assert result.exit_code != 0, args
