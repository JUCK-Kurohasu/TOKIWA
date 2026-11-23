"""A human status change during automatic triage must survive the triage write (lost update).

Before the fix, triage read the alert, then wrote ``triaging`` / ``triaged`` from that stale read: an analyst who
marked the alert ``false_positive`` while triage was loading its context saw it flip back to ``triaged`` (found by
the web-detect lane while testing audit #166; ``tests/detect/test_alert_suppression.py`` had to turn auto triage
off). The writes are now conditional UPDATEs, so a status a human set is never overwritten.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sqlalchemy import select

from tokiwa.bus import bus
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.llm.mock import MockProvider
from tokiwa.respond import service as respond_service
from tokiwa.schemas.response import ActionProposal
from tokiwa.triage import service as triage_mod
from tokiwa.triage.service import get_triage_service

pytestmark = pytest.mark.usefixtures("db")


async def _set_status(alert_id: str, status: str) -> None:
    """What ``PATCH /alerts/{id}`` commits (a separate session = a separate request)."""
    async with session_scope() as s:
        row = await s.get(AlertRow, alert_id)
        assert row is not None
        row.status = status


async def _status(alert_id: str) -> tuple[str, Any]:
    async with session_scope() as s:
        row = await s.get(AlertRow, alert_id)
        assert row is not None
        return row.status, row.triage


async def _seed(add_alert: Any, add_events: Any, make_http_event: Any, **kw: Any) -> Any:
    ids = await add_events(*(make_http_event(f"/p{i}", ip="203.0.113.10") for i in range(3)))
    return await add_alert(source_ip="203.0.113.10", evidence=ids, **kw)


@pytest.fixture
def proposals(monkeypatch: pytest.MonkeyPatch) -> list[ActionProposal]:
    out: list[ActionProposal] = []

    async def fake_propose(p: ActionProposal) -> None:
        out.append(p)

    monkeypatch.setattr(respond_service, "propose_action", fake_propose)
    return out


async def test_false_positive_while_loading_context_is_kept(
    mock_llm: MockProvider, monkeypatch: pytest.MonkeyPatch, add_alert, add_events, make_http_event, proposals
) -> None:
    """The reproduced race: the analyst's PATCH commits between triage's read and its ``triaging`` write."""
    a = await _seed(add_alert, add_events, make_http_event, severity="critical")
    original = triage_mod.load_context

    async def load_then_analyst_marks_fp(*args: Any, **kw: Any) -> Any:
        ctx = await original(*args, **kw)
        await _set_status(a.id, "false_positive")
        return ctx

    monkeypatch.setattr(triage_mod, "load_context", load_then_analyst_marks_fp)
    await get_triage_service().handle_alert_created(a)
    status, triage = await _status(a.id)
    assert status == "false_positive"
    # The analyst got there first: the automatic run stops before spending an LLM call or proposing a block.
    assert mock_llm.calls == [] and triage is None
    assert proposals == []


async def test_false_positive_during_llm_call_is_kept_and_not_proposed(
    mock_llm: MockProvider, add_alert, add_events, make_http_event, proposals
) -> None:
    """The analyst decides while the model is still answering: the verdict is stored, the status is not."""
    a = await _seed(add_alert, add_events, make_http_event, severity="critical")
    original_structured = mock_llm.complete_structured

    async def analyst_marks_fp_then_answer(**kw: Any) -> Any:
        # Inside the provider call: after triage wrote ``triaging``, before it writes the verdict.
        await _set_status(a.id, "false_positive")
        return await original_structured(**kw)

    mock_llm.complete_structured = analyst_marks_fp_then_answer  # type: ignore[method-assign]
    out = await get_triage_service().triage_alert(a.id)
    status, triage = await _status(a.id)
    assert status == "false_positive"
    assert triage is not None  # the verdict is still recorded for the analyst to read
    assert out is not None and out.status == "false_positive"  # what alert.updated carries
    assert (
        proposals == []
    )  # an alert a human just called a false positive gets no block / rate-limit proposal


async def test_other_human_statuses_are_kept(
    mock_llm: MockProvider, monkeypatch: pytest.MonkeyPatch, add_alert, add_events, make_http_event
) -> None:
    a = await _seed(add_alert, add_events, make_http_event, severity="medium", confidence=0.9)
    original = triage_mod.load_context

    async def load_then_ack(*args: Any, **kw: Any) -> Any:
        ctx = await original(*args, **kw)
        await _set_status(a.id, "acknowledged")
        return ctx

    monkeypatch.setattr(triage_mod, "load_context", load_then_ack)
    out = await get_triage_service().triage_alert(a.id)  # forced (manual) triage still runs to the end
    status, triage = await _status(a.id)
    assert status == "acknowledged" and triage is not None
    assert out is not None and out.status == "acknowledged"


async def test_normal_run_still_moves_new_to_triaged(
    mock_llm: MockProvider, add_alert, add_events, make_http_event, proposals
) -> None:
    a = await _seed(add_alert, add_events, make_http_event, severity="critical")
    seen: list[str] = []
    original_structured = mock_llm.complete_structured

    async def complete_structured(**kw: Any) -> Any:
        seen.append((await _status(a.id))[0])
        return await original_structured(**kw)

    mock_llm.complete_structured = complete_structured  # type: ignore[method-assign]
    await get_triage_service().handle_alert_created(a)
    status, triage = await _status(a.id)
    assert seen and set(seen) == {"triaging"}  # visible as in progress while the model runs
    assert status == "triaged" and triage is not None
    assert proposals  # critical web.sqli -> the rule verdict proposes (unchanged behaviour)


async def test_forced_retriage_of_a_false_positive_keeps_status(
    mock_llm: MockProvider, add_alert, add_events, make_http_event, proposals
) -> None:
    """Re-triage of an alert that was already a false positive: status untouched, proposals as before."""
    a = await _seed(add_alert, add_events, make_http_event, severity="critical", status="false_positive")
    out = await get_triage_service().triage_alert(a.id)
    assert out is not None and out.status == "false_positive"
    assert proposals  # unchanged: only an FP set *during* the run withholds proposals


async def test_patch_false_positive_right_after_ingest_survives_auto_triage(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: Any,
    mock_llm: MockProvider,
) -> None:
    """End to end, as the web-detect lane hit it: ingest -> auto triage in the background -> analyst PATCH."""
    ev = make_http_event("/items", query="id=1%20UNION%20SELECT%20null,version()--")
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [ev.model_dump(mode="json")]}, headers=ingest_headers
    )
    assert r.status_code == 200, r.text
    async with session_scope() as s:
        ids = (await s.execute(select(AlertRow.id).where(AlertRow.rule_id == "web.sqli"))).scalars().all()
    [alert_id] = ids
    r = await client.patch(
        f"/api/v1/alerts/{alert_id}", json={"status": "false_positive"}, headers=admin_headers
    )
    assert r.status_code == 200, r.text
    await bus.drain()
    assert (await _status(alert_id))[0] == "false_positive"
