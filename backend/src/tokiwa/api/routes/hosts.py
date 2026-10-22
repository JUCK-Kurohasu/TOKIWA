"""Hosts: listening-port state per host and port baselines (FR-01/02). Contract: docs/api-contract.md."""

from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select

from tokiwa.api.deps import AnalystUser, CurrentUser, DbSession
from tokiwa.audit import record_audit
from tokiwa.db.models.telemetry import HostPortRow, PortBaselineRow
from tokiwa.schemas.hosts import (
    BaselineLearnRequest,
    HostPort,
    HostSummary,
    PortBaseline,
    PortBaselineIn,
    base_protocol,
    is_wildcard_bind,
    match_baseline,
)
from tokiwa.util import new_id, utcnow

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


async def _baselines(session: DbSession, host: str | None = None) -> list[PortBaselineRow]:
    q = select(PortBaselineRow)
    if host is not None:
        q = q.where(PortBaselineRow.host.in_([host, "*"]))
    return list((await session.execute(q.order_by(PortBaselineRow.port))).scalars().all())


def _allowed(row: HostPortRow, baselines: list[PortBaselineRow]) -> bool:
    return (
        match_baseline(
            baselines, host=row.host, protocol=row.protocol, port=row.port, process_name=row.process_name
        )
        is not None
    )


@router.get("", response_model=list[HostSummary])
async def list_hosts(session: DbSession, _: CurrentUser) -> list[HostSummary]:
    rows = (await session.execute(select(HostPortRow))).scalars().all()
    baselines = await _baselines(session)
    by_host: dict[str, list[HostPortRow]] = defaultdict(list)
    for r in rows:
        by_host[r.host].append(r)
    out: list[HostSummary] = []
    for host, items in sorted(by_host.items()):
        open_rows = [r for r in items if r.open]
        out.append(
            HostSummary(
                host=host,
                ports_open=len(open_rows),
                last_seen=max(r.last_seen for r in items),
                deviations=sum(1 for r in open_rows if not _allowed(r, baselines)),
            )
        )
    return out


@router.get("/ports", response_model=list[HostPort])
async def list_ports(
    session: DbSession,
    _: CurrentUser,
    host: str | None = None,
    open: bool | None = None,
) -> list[HostPort]:
    """Listeners (open and recently closed) with ``allowed`` computed against the baselines."""
    q = select(HostPortRow)
    if host is not None:
        q = q.where(HostPortRow.host == host)
    if open is not None:
        q = q.where(HostPortRow.open.is_(open))
    rows = (
        (await session.execute(q.order_by(HostPortRow.host, HostPortRow.open.desc(), HostPortRow.port)))
        .scalars()
        .all()
    )
    baselines = await _baselines(session, host)
    out: list[HostPort] = []
    for r in rows:
        item = HostPort.model_validate(r)
        item.allowed = _allowed(r, baselines)
        out.append(item)
    return out


@router.get("/baselines", response_model=list[PortBaseline])
async def list_baselines(session: DbSession, _: CurrentUser, host: str | None = None) -> list[PortBaseline]:
    return [PortBaseline.model_validate(r) for r in await _baselines(session, host)]


@router.post("/baselines", response_model=PortBaseline)
async def create_baseline(body: PortBaselineIn, session: DbSession, user: AnalystUser) -> PortBaseline:
    """Allow a listener. Idempotent: the same (host, protocol, port, process) updates the existing entry."""
    host = body.host or "*"
    existing = (
        await session.execute(
            select(PortBaselineRow).where(
                PortBaselineRow.host == host,
                PortBaselineRow.protocol == body.protocol,
                PortBaselineRow.port == body.port,
                PortBaselineRow.process_name.is_(None)
                if body.process_name is None
                else PortBaselineRow.process_name == body.process_name,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.allow_public = body.allow_public
        existing.note = body.note
        row = existing
    else:
        row = PortBaselineRow(
            id=new_id(),
            host=host,
            protocol=body.protocol,
            port=body.port,
            process_name=body.process_name,
            allow_public=body.allow_public,
            note=body.note,
            created_at=utcnow(),
        )
        session.add(row)
    await session.flush()
    await record_audit(
        user.username,
        "hosts.baseline.upsert",
        row.id,
        {"host": host, "protocol": row.protocol, "port": row.port, "process_name": row.process_name},
        session=session,
    )
    return PortBaseline.model_validate(row)


@router.delete("/baselines/{baseline_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_baseline(baseline_id: str, session: DbSession, user: AnalystUser) -> Response:
    row = await session.get(PortBaselineRow, baseline_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "baseline not found")
    details = {"host": row.host, "protocol": row.protocol, "port": row.port, "process_name": row.process_name}
    await session.delete(row)
    await record_audit(user.username, "hosts.baseline.delete", baseline_id, details, session=session)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/baselines/learn", response_model=list[PortBaseline])
async def learn_baselines(
    body: BaselineLearnRequest, session: DbSession, user: AnalystUser
) -> list[PortBaseline]:
    """Baseline every current listener of ``host`` that is not yet allowed. Returns the entries created.

    ``allow_public`` is set for listeners currently bound to all interfaces, so learning accepts the host as
    it is now; tighten individual entries afterwards if needed.
    """
    rows = (
        (
            await session.execute(
                select(HostPortRow).where(HostPortRow.host == body.host, HostPortRow.open.is_(True))
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        known = (
            await session.execute(select(HostPortRow.id).where(HostPortRow.host == body.host).limit(1))
        ).first()
        if known is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown host")
        return []
    baselines = await _baselines(session, body.host)
    now = utcnow()
    created: list[PortBaselineRow] = []
    for r in sorted(rows, key=lambda r: (r.protocol, r.port, r.bind_ip)):
        if _allowed(r, baselines):
            continue
        public = is_wildcard_bind(r.bind_ip)
        # Same port on several binds (0.0.0.0 and ::) -> one entry; public if any bind is public.
        same = next(
            (
                b
                for b in created
                if b.port == r.port
                and b.protocol == base_protocol(r.protocol)
                and b.process_name == r.process_name
            ),
            None,
        )
        if same is not None:
            same.allow_public = same.allow_public or public
            continue
        row = PortBaselineRow(
            id=new_id(),
            host=body.host,
            protocol=base_protocol(r.protocol),
            port=r.port,
            process_name=r.process_name,
            allow_public=public,
            note=f"learned {now.isoformat(timespec='seconds')}",
            created_at=now,
        )
        session.add(row)
        created.append(row)
    await session.flush()
    await record_audit(
        user.username, "hosts.baseline.learn", body.host, {"created": len(created)}, session=session
    )
    return [PortBaseline.model_validate(r) for r in created]
