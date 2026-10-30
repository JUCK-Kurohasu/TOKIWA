"""LLM settings, usage, audit log and connectivity test (docs/api-contract.md "LLM"). OWNER: llm module.

API keys are write-only: no response model here has a field that could carry one.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, time, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from tokiwa.api.deps import AdminUser, CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.llm.base import LLMPurpose, LLMTier, StructuredRequest
from tokiwa.llm.gateway import get_gateway
from tokiwa.llm.mock import register_mock_responder
from tokiwa.llm.models import ModelListing
from tokiwa.llm.prompting import UNTRUSTED_DATA_POLICY
from tokiwa.llm.settings import LLMConfigOut, LLMConfigUpdate, config_view, update_config
from tokiwa.schemas.common import Page
from tokiwa.schemas.system import LLMCall, LLMCallDetail, LLMCallStatus
from tokiwa.util import ensure_utc, utcnow

router = APIRouter(prefix="/api/v1/llm", tags=["llm"])


class LLMUsageDay(BaseModel):
    date: date
    cost_usd: float = 0.0
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    by_purpose: dict[str, float] = Field(default_factory=dict)  # purpose -> cost_usd
    by_purpose_calls: dict[str, int] = Field(default_factory=dict)  # purpose -> calls


class LLMUsageResponse(BaseModel):
    days: list[LLMUsageDay]


class LLMTestResult(BaseModel):
    ok: bool
    provider: str
    model: str
    latency_ms: float
    status: LLMCallStatus
    error: str | None = None


class LLMPing(BaseModel):
    """Minimal schema for the connectivity test (exercises the structured-output path end to end)."""

    ok: bool
    echo: str


@register_mock_responder(LLMPing)
def _mock_ping(system: str, user: str) -> dict[str, object]:
    return {"ok": True, "echo": "pong"}


PING_SYSTEM = (
    'You are a connectivity check for the TOKIWA SIEM. Answer with ok=true and echo="pong".\n\n'
    + UNTRUSTED_DATA_POLICY
)


@router.get("/config", response_model=LLMConfigOut)
async def get_config(_: CurrentUser) -> LLMConfigOut:
    return await config_view()


@router.put("/config", response_model=LLMConfigOut)
async def put_config(body: LLMConfigUpdate, user: AdminUser) -> LLMConfigOut:
    gateway, changes = await update_config(body)
    # changes never contains secret values (only "set"/"cleared").
    await record_audit(user.username, "llm.config.update", "llm.config", {"changes": changes})
    return await config_view(gateway)


@router.get("/models", response_model=ModelListing)
async def list_models(_: CurrentUser) -> ModelListing:
    """Anthropic models selectable in the settings UI (live from the API when possible, else a built-in list)."""
    return await get_gateway().list_models()


@router.get("/usage", response_model=LLMUsageResponse)
async def get_usage(
    session: DbSession,
    _: CurrentUser,
    days: Annotated[int, Query(ge=1, le=366)] = 14,
) -> LLMUsageResponse:
    first = utcnow().date() - timedelta(days=days - 1)
    since = datetime.combine(first, time.min, tzinfo=UTC)
    rows = (
        await session.execute(
            select(
                LLMCallRow.created_at,
                LLMCallRow.purpose,
                LLMCallRow.cost_usd,
                LLMCallRow.input_tokens,
                LLMCallRow.output_tokens,
                LLMCallRow.cache_read_tokens,
                LLMCallRow.cache_write_tokens,
            ).where(LLMCallRow.created_at >= since)
        )
    ).all()
    buckets: dict[date, LLMUsageDay] = {
        first + timedelta(days=i): LLMUsageDay(date=first + timedelta(days=i)) for i in range(days)
    }
    by_purpose: dict[date, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    by_purpose_calls: dict[date, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for created_at, purpose, cost, inp, out, cache_read, cache_write in rows:
        day = ensure_utc(created_at).date()
        bucket = buckets.get(day)
        if bucket is None:
            continue
        bucket.calls += 1
        bucket.cost_usd += float(cost or 0.0)
        bucket.input_tokens += int(inp or 0)
        bucket.output_tokens += int(out or 0)
        bucket.cache_read_tokens += int(cache_read or 0)
        bucket.cache_write_tokens += int(cache_write or 0)
        by_purpose[day][purpose] += float(cost or 0.0)
        by_purpose_calls[day][purpose] += 1
    result = []
    for day, bucket in sorted(buckets.items()):
        bucket.cost_usd = round(bucket.cost_usd, 6)
        bucket.by_purpose = {k: round(v, 6) for k, v in sorted(by_purpose[day].items())}
        bucket.by_purpose_calls = dict(sorted(by_purpose_calls[day].items()))
        result.append(bucket)
    return LLMUsageResponse(days=result)


@router.get("/calls", response_model=Page[LLMCall])
async def list_calls(
    session: DbSession,
    _: CurrentUser,
    purpose: str | None = None,
    status_: Annotated[LLMCallStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[LLMCall]:
    query = select(LLMCallRow)
    count = select(func.count()).select_from(LLMCallRow)
    if purpose:
        query = query.where(LLMCallRow.purpose == purpose)
        count = count.where(LLMCallRow.purpose == purpose)
    if status_ is not None:
        query = query.where(LLMCallRow.status == status_.value)
        count = count.where(LLMCallRow.status == status_.value)
    total = int((await session.execute(count)).scalar_one())
    rows = (
        await session.execute(
            query.order_by(LLMCallRow.created_at.desc(), LLMCallRow.id.desc()).limit(limit).offset(offset)
        )
    ).scalars()
    return Page[LLMCall](
        items=[LLMCall.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.get("/calls/{call_id}", response_model=LLMCallDetail)
async def get_call(call_id: str, session: DbSession, _: AdminUser) -> LLMCallDetail:
    row = await session.get(LLMCallRow, call_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "LLM call not found")
    return LLMCallDetail.model_validate(row)


@router.post("/test", response_model=LLMTestResult)
async def test_llm(_: AdminUser, tier: Literal["fast", "deep"] = "fast") -> LLMTestResult:
    """Health check: one minimal structured call through the gateway (budget, audit and validation apply)."""
    res = await get_gateway().structured(
        StructuredRequest(
            purpose=LLMPurpose.TEST,
            tier=LLMTier(tier),
            system=PING_SYSTEM,
            user='Connectivity check. Respond with {"ok": true, "echo": "pong"}.',
            prompt_version="llm.test@1",
            max_output_tokens=1024,
        ),
        LLMPing,
    )
    return LLMTestResult(
        ok=res.ok and bool(res.output and res.output.ok),
        provider=res.provider,
        model=res.model,
        latency_ms=round(res.latency_ms, 1),
        status=res.status,
        error=res.error,
    )
