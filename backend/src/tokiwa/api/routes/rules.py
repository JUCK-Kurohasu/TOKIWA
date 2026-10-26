"""Detection rules (Sigma): CRUD, validation, approval of LLM proposals.

Every change is committed and then the in-memory rule set is reloaded, so it takes effect for the very next
ingested event. Built-in rules (``source=builtin``) mirror files under ``rules/sigma``: their status can be
changed here, their content only in the file.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.db.models.detection import RuleRow
from tokiwa.detect.sigma import SigmaError, get_rule_store, rule_meta, sync_builtin_rules, validate_rule
from tokiwa.detect.sigma.loader import compile_content
from tokiwa.schemas.common import Page
from tokiwa.schemas.system import Rule, RuleIn, RuleKind, RuleSource, RuleStatus
from tokiwa.util import new_id, utcnow

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


class RuleUpdate(BaseModel):
    content: str | None = None
    status: RuleStatus | None = None


class RuleValidateRequest(BaseModel):
    content: str


class RuleValidation(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    title: str | None = None


class RuleReloadResult(BaseModel):
    active_rules: int
    errors: dict[str, list[str]] = Field(default_factory=dict)


def _invalid(errors: list[str]) -> HTTPException:
    return HTTPException(422, "invalid Sigma rule: " + "; ".join(errors))


def _compile_or_422(content: str) -> Any:
    try:
        return compile_content(content)
    except SigmaError as exc:
        raise _invalid(exc.errors) from exc


async def _get_row(session: DbSession, rule_id: str) -> RuleRow:
    row = await session.get(RuleRow, rule_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    return row


async def _ensure_unique_sigma_id(
    session: DbSession, sigma_id: str | None, exclude: str | None = None
) -> None:
    """Two rules with the same Sigma id would produce indistinguishable alerts (``rule_id=sigma:<id>``)."""
    if not sigma_id:
        return
    rows = (await session.execute(select(RuleRow).where(RuleRow.kind == RuleKind.SIGMA))).scalars().all()
    for r in rows:
        if r.id != exclude and (r.meta or {}).get("sigma_id") == sigma_id:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"a rule with Sigma id {sigma_id!r} already exists ({r.source}: {r.title}); change the 'id'",
            )


async def _commit_and_reload(session: DbSession) -> None:
    await session.commit()
    await get_rule_store().reload()


@router.get("", response_model=Page[Rule])
async def list_rules(
    session: DbSession,
    user: CurrentUser,
    status_: Annotated[RuleStatus | None, Query(alias="status")] = None,
    source: RuleSource | None = None,
    q: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[Rule]:
    await get_rule_store().flush_hits(session)
    stmt = select(RuleRow)
    if status_ is not None:
        stmt = stmt.where(RuleRow.status == status_)
    if source is not None:
        stmt = stmt.where(RuleRow.source == source)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(RuleRow.title.ilike(like), RuleRow.content.ilike(like)))
    total = int((await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one())
    rows = (
        (
            await session.execute(
                stmt.order_by(RuleRow.created_at.desc(), RuleRow.title).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return Page[Rule](items=[Rule.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.post("/validate", response_model=RuleValidation)
async def validate(body: RuleValidateRequest, user: AnalystUser) -> RuleValidation:
    valid, errors, title = validate_rule(body.content)
    return RuleValidation(valid=valid, errors=errors, title=title)


@router.post("/reload", response_model=RuleReloadResult)
async def reload_rules(session: DbSession, user: AnalystUser) -> RuleReloadResult:
    """Re-read rule files (after editing rules/sigma on disk) and the rules table."""
    store = get_rule_store()
    await sync_builtin_rules(store, session)
    await record_audit(user.username, "rule.reload", None, {}, session=session)
    await _commit_and_reload(session)
    return RuleReloadResult(active_rules=len(store.rules()), errors=store.errors)


@router.post("", response_model=Rule)
async def create_rule(body: RuleIn, session: DbSession, user: AnalystUser) -> Rule:
    rule = _compile_or_422(body.content)
    await _ensure_unique_sigma_id(session, rule.id)
    now = utcnow()
    row = RuleRow(
        id=new_id(),
        created_at=now,
        updated_at=now,
        kind=body.kind.value,
        title=rule.title,
        content=body.content,
        status=body.status.value,
        source=RuleSource.USER.value,
        hit_count=0,
        meta={**rule_meta(rule), "created_by": user.username},
    )
    session.add(row)
    await session.flush()
    await record_audit(
        user.username, "rule.create", row.id, {"title": row.title, "status": row.status}, session=session
    )
    result = Rule.model_validate(row)
    await _commit_and_reload(session)
    return result


@router.get("/{rule_id}", response_model=Rule)
async def get_rule(rule_id: str, session: DbSession, user: CurrentUser) -> Rule:
    await get_rule_store().flush_hits(session)
    row = await _get_row(session, rule_id)
    return Rule.model_validate(row)


@router.patch("/{rule_id}", response_model=Rule)
async def update_rule(rule_id: str, body: RuleUpdate, session: DbSession, user: AnalystUser) -> Rule:
    row = await _get_row(session, rule_id)
    changes: dict[str, Any] = {}
    if body.content is not None and body.content != row.content:
        if row.source == RuleSource.BUILTIN:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "built-in rule content is managed in rules/sigma; create a user rule (with a new id) instead",
            )
        rule = _compile_or_422(body.content)
        await _ensure_unique_sigma_id(session, rule.id, exclude=row.id)
        row.content = body.content
        row.title = rule.title
        row.meta = {**(row.meta or {}), **rule_meta(rule)}
        changes["content"] = True
    if body.status is not None and body.status != row.status:
        if body.status == RuleStatus.ACTIVE and row.source != RuleSource.BUILTIN:
            _compile_or_422(row.content)  # never activate something the engine would skip
        changes["status"] = {"from": row.status, "to": body.status.value}
        row.status = body.status.value
    if changes:
        row.updated_at = utcnow()
        await session.flush()
        await record_audit(
            user.username, "rule.update", row.id, {"title": row.title, **changes}, session=session
        )
    result = Rule.model_validate(row)
    if changes:
        await _commit_and_reload(session)
    return result


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: str, session: DbSession, user: AnalystUser) -> Response:
    row = await _get_row(session, rule_id)
    if row.source == RuleSource.BUILTIN:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "built-in rules cannot be deleted; set status=disabled instead"
        )
    await record_audit(user.username, "rule.delete", row.id, {"title": row.title}, session=session)
    await session.delete(row)
    await _commit_and_reload(session)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{rule_id}/approve", response_model=Rule)
async def approve_rule(rule_id: str, session: DbSession, user: AnalystUser) -> Rule:
    """Human approval of a proposed rule (e.g. drafted by the LLM advisor): proposed -> active."""
    row = await _get_row(session, rule_id)
    if row.status != RuleStatus.PROPOSED:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"only proposed rules can be approved (status={row.status})"
        )
    rule = _compile_or_422(row.content)
    await _ensure_unique_sigma_id(session, rule.id, exclude=row.id)
    row.status = RuleStatus.ACTIVE.value
    row.title = rule.title
    row.meta = {**(row.meta or {}), **rule_meta(rule), "approved_by": user.username}
    row.updated_at = utcnow()
    await session.flush()
    await record_audit(
        user.username, "rule.approve", row.id, {"title": row.title, "source": row.source}, session=session
    )
    result = Rule.model_validate(row)
    await _commit_and_reload(session)
    return result
