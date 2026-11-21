"""API token lifecycle shared by ``routes/tokens.py`` and the ``tokiwa token ...`` CLI (audit #163).

Why one module: the CLI is the recovery path when no admin can log in (incident in progress, lost password),
so it must create / list / revoke / rotate with exactly the API's rules and leave the same audit trail.

- Only the SHA-256 hash is stored; the plaintext is returned once by :func:`issue_token` / :func:`rotate_token`.
- ``expires_at`` NULL = never expires (the default, as before). Expired tokens are refused with 401 by
  ``api.deps.require_token_scope`` (:func:`is_expired`).
- Rotation issues a replacement with the same name, scopes and binding and keeps the old token valid for a
  grace period, so sensors can switch over without losing telemetry (the Gate re-reads its token file).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.audit import record_audit
from tokiwa.auth.security import generate_api_token
from tokiwa.db.models.core import ApiTokenRow
from tokiwa.util import ensure_utc, new_id, utcnow


class TokenLookupError(LookupError):
    """No token, or an ambiguous name, for a CLI reference."""


@dataclass(frozen=True, slots=True)
class IssuedToken:
    row: ApiTokenRow
    plaintext: str


def is_expired(row: ApiTokenRow, now: datetime | None = None) -> bool:
    # SQLite returns naive datetimes: normalise before comparing with an aware "now".
    return row.expires_at is not None and ensure_utc(row.expires_at) <= (now or utcnow())


def status_of(row: ApiTokenRow, now: datetime | None = None) -> str:
    if row.revoked:
        return "revoked"
    if is_expired(row, now):
        return "expired"
    return "active"


def _dedupe(values: list[str] | None) -> list[str] | None:
    return list(dict.fromkeys(values)) if values else None


async def issue_token(
    session: AsyncSession,
    *,
    name: str,
    scopes: list[str],
    actor: str,
    expires_in_days: int | None = None,
    allowed_sensor_ids: list[str] | None = None,
    allowed_datasets: list[str] | None = None,
    rotated_from: str | None = None,
    now: datetime | None = None,
) -> IssuedToken:
    now = now or utcnow()
    token, digest, prefix = generate_api_token()
    row = ApiTokenRow(
        id=new_id(),
        name=name,
        token_hash=digest,
        prefix=prefix,
        scopes=list(dict.fromkeys(scopes)),
        created_at=now,
        allowed_sensor_ids=_dedupe(allowed_sensor_ids),
        allowed_datasets=_dedupe(allowed_datasets),
        expires_at=now + timedelta(days=expires_in_days) if expires_in_days else None,
        created_by=actor[:128],
        rotated_from=rotated_from,
    )
    session.add(row)
    await session.flush()
    await record_audit(
        actor,
        "token.create",
        row.id,
        {
            "name": row.name,
            "scopes": row.scopes,
            "prefix": prefix,
            "allowed_sensor_ids": row.allowed_sensor_ids,
            "allowed_datasets": row.allowed_datasets,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "rotated_from": rotated_from,
        },
        session=session,
    )
    return IssuedToken(row=row, plaintext=token)


async def revoke_token(session: AsyncSession, row: ApiTokenRow, *, actor: str) -> bool:
    """Revoke (idempotent). Returns True when the token was active before."""
    if row.revoked:
        return False
    row.revoked = True
    await record_audit(
        actor, "token.revoke", row.id, {"name": row.name, "prefix": row.prefix}, session=session
    )
    return True


async def rotate_token(
    session: AsyncSession,
    row: ApiTokenRow,
    *,
    actor: str,
    grace_hours: int = 24,
    expires_in_days: int | None = None,
    now: datetime | None = None,
) -> IssuedToken:
    """Issue a replacement; the old token expires after ``grace_hours`` (0 = revoked now)."""
    if row.revoked:
        raise ValueError("cannot rotate a revoked token")
    now = now or utcnow()
    if is_expired(row, now):
        raise ValueError("cannot rotate an expired token; create a new one")
    issued = await issue_token(
        session,
        name=row.name,
        scopes=list(row.scopes),
        actor=actor,
        expires_in_days=expires_in_days,
        allowed_sensor_ids=row.allowed_sensor_ids,
        allowed_datasets=row.allowed_datasets,
        rotated_from=row.id,
        now=now,
    )
    if grace_hours <= 0:
        row.revoked = True
        old_until: datetime | None = now
    else:
        until = now + timedelta(hours=grace_hours)
        # never extend an earlier expiry
        old_until = until if row.expires_at is None else min(ensure_utc(row.expires_at), until)
        row.expires_at = old_until
    await record_audit(
        actor,
        "token.rotate",
        row.id,
        {
            "name": row.name,
            "prefix": row.prefix,
            "new_token_id": issued.row.id,
            "new_prefix": issued.row.prefix,
            "old_valid_until": old_until.isoformat() if old_until else None,
            "grace_hours": grace_hours,
        },
        session=session,
    )
    return issued


async def find_token(session: AsyncSession, ref: str) -> ApiTokenRow:
    """Resolve a CLI reference: an exact id, else the single non-revoked token with that name."""
    row = await session.get(ApiTokenRow, ref)
    if row is not None:
        return row
    rows = (
        (
            await session.execute(
                select(ApiTokenRow).where(ApiTokenRow.name == ref, ApiTokenRow.revoked.is_(False))
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        raise TokenLookupError(f"no active token with id or name {ref!r}")
    if len(rows) > 1:
        ids = ", ".join(r.id for r in rows)
        raise TokenLookupError(f"name {ref!r} matches {len(rows)} active tokens; use the id ({ids})")
    return rows[0]
