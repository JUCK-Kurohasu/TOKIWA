"""Mirage service: asset CRUD, default seeding, the in-memory index cache and trip recording.

Public API (keep signatures stable - other modules use them):

- ``create_asset(data: DeceptionAssetIn, *, actor=None) -> DeceptionAsset``
  Used by the respond module's ``deploy_canary`` executor. Generates the token when omitted.
  Raises :class:`DeceptionError` (a ``ValueError``; ``.status_code`` 422 / 409) on invalid input.
- ``delete_asset(asset_id, *, actor=None) -> bool`` / ``disable_asset(asset_id, *, actor=None) -> DeceptionAsset | None``
  Revert of ``deploy_canary`` (False / None when the asset does not exist).
- ``get_index() -> DeceptionIndex``   token / decoy-path lookup for the ``deception.trip`` detector
- ``gate_decoys()``                   rendered ``DecoyRoute`` list + HTML injection (``deception.policy``)

Cache: the index and the rendered decoys are rebuilt lazily when an asset changes (generation counter, bumped
*after* commit), when the DB engine or settings object changes (tests), and at least every 60 s (changes made by
another process, e.g. the CLI). Trip counters are not part of the cache.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.audit import record_audit
from tokiwa.bus import bus
from tokiwa.config import Settings, get_settings
from tokiwa.db import session as dbsession
from tokiwa.db.models.deception import DeceptionTripRow
from tokiwa.db.models.response import DeceptionAssetRow
from tokiwa.db.session import session_scope
from tokiwa.deception import render
from tokiwa.deception.labyrinth import normalize_base
from tokiwa.deception.matcher import DeceptionIndex, Trip, match_event
from tokiwa.deception.tokens import derive_key, flavor_for, generate_token, validate_token
from tokiwa.pipeline.store import get_events
from tokiwa.runtime import on_startup
from tokiwa.schemas.common import Page
from tokiwa.schemas.deception import DeceptionAssetUpdate, DeceptionPreview
from tokiwa.schemas.events import DeceptionInfo, Endpoint, Event, EventKind, HttpInfo
from tokiwa.schemas.response import DeceptionAsset, DeceptionAssetIn, DeceptionKind, DecoyRoute
from tokiwa.util import ensure_utc, new_id, utcnow

log = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 60.0
_RETRY_SECONDS = 5.0
_MAX_NAME = 255
_MAX_PATH = 512
_MAX_TEMPLATE = 64 * 1024
_PATH_RE = re.compile(r"^/[^\s?#]*$")

# (name, path, enabled, description). Path-less canary = hidden snippet injected into upstream HTML.
DEFAULT_CANARIES: list[tuple[str, str | None, bool, str]] = [
    (
        "AI canary: hidden HTML instruction",
        None,
        True,
        "Injected before </body> of upstream HTML responses (GatePolicy.html_injection). "
        "上流 HTML の </body> 直前に挿入される隠し指示。",
    ),
    (
        "AI canary: internal OpenAPI",
        "/api/internal/openapi.json",
        True,
        "Decoy OpenAPI document; the instruction is in info.description only. 説明文にのみ指示を含む偽 OpenAPI。",
    ),
    (
        "AI canary: robots.txt",
        "/robots.txt",
        False,
        "Shadows the upstream robots.txt while enabled. 有効化すると上流の robots.txt を置き換える。",
    ),
    (
        "AI canary: llms.txt",
        "/llms.txt",
        False,
        "Shadows an upstream llms.txt while enabled. 有効化すると上流の llms.txt を置き換える。",
    ),
]


class DeceptionError(ValueError):
    status_code = 422


class DeceptionConflict(DeceptionError):
    status_code = 409


# ---------------------------------------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------------------------------------


@dataclass
class _Cache:
    engine: object
    settings: Settings
    generation: int
    loaded_at: float
    ttl: float
    assets: list[DeceptionAsset]
    index: DeceptionIndex
    key: bytes
    decoys: tuple[list[DecoyRoute], str | None] | None = None

    def site(self) -> render.SiteContext:
        return render.SiteContext(self.settings.deception, self.key, [a for a in self.assets if a.enabled])


_generation = 0
_cache: _Cache | None = None


def invalidate() -> None:
    """Mark the index / rendered decoys stale. Call AFTER the change is committed."""
    global _generation
    _generation += 1


def _db_engine() -> object | None:
    # Deliberately do not create an engine here: detectors may run in contexts without a database
    # (unit tests of other modules); no DB simply means no deception assets.
    return dbsession._engine


async def _load_assets() -> list[DeceptionAsset]:
    async with session_scope() as s:
        rows = (
            (
                await s.execute(
                    select(DeceptionAssetRow).order_by(DeceptionAssetRow.created_at, DeceptionAssetRow.id)
                )
            )
            .scalars()
            .all()
        )
        return [DeceptionAsset.model_validate(r) for r in rows]


async def get_cache(*, force: bool = False) -> _Cache:
    global _cache
    settings = get_settings()
    engine = _db_engine()
    now = time.monotonic()
    c = _cache
    if (
        not force
        and c is not None
        and c.engine is engine
        and c.settings is settings
        and c.generation == _generation
        and now - c.loaded_at < c.ttl
    ):
        return c
    gen = _generation
    assets: list[DeceptionAsset] = []
    ttl = CACHE_TTL_SECONDS
    if engine is not None and settings.deception.enabled:
        try:
            assets = await _load_assets()
        except Exception:
            log.warning("deception: could not load assets (retry in %.0fs)", _RETRY_SECONDS, exc_info=True)
            ttl = _RETRY_SECONDS
    key = derive_key() if engine is not None else b""
    index = DeceptionIndex.build(assets, key=key, settings=settings.deception)
    _cache = _Cache(engine, settings, gen, now, ttl, assets, index, key)
    return _cache


async def get_index(*, force: bool = False) -> DeceptionIndex:
    return (await get_cache(force=force)).index


async def gate_decoys() -> tuple[list[DecoyRoute], str | None]:
    """Rendered decoys for the Gate policy (cached until the next asset change)."""
    cache = await get_cache()
    if cache.decoys is None:
        cache.decoys = render.render_site(cache.site())
    routes, html = cache.decoys
    return [r.model_copy(deep=True) for r in routes], html


# ---------------------------------------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------------------------------------


def _clean_name(name: str | None) -> str:
    n = (name or "").strip()
    if not n:
        raise DeceptionError("name must not be empty")
    if len(n) > _MAX_NAME:
        raise DeceptionError(f"name is longer than {_MAX_NAME} characters")
    return n


def _clean_path(kind: DeceptionKind, path: str | None, settings: Settings) -> str | None:
    p = path.strip() if path else None
    if kind == DeceptionKind.LABYRINTH:
        p = normalize_base(p, settings.deception.labyrinth_prefix) + "*"
    if kind == DeceptionKind.DECOY_PATH and not p:
        raise DeceptionError("decoy_path assets require a path")
    if not p:
        return None
    if len(p) > _MAX_PATH or not _PATH_RE.match(p):
        raise DeceptionError("path must start with '/' and must not contain whitespace, '?' or '#'")
    if "*" in p[:-1]:
        raise DeceptionError("'*' is only allowed at the end of a path (prefix route)")
    if p in ("/", "/*"):
        raise DeceptionError("path '/' would shadow the whole protected site")
    return p


def _clean_template(template: str | None) -> str | None:
    if template is not None and len(template) > _MAX_TEMPLATE:
        raise DeceptionError(f"content_template is larger than {_MAX_TEMPLATE} bytes")
    return template


def _check_token(token: str, settings: Settings) -> str:
    t = token.strip()
    err = validate_token(t, settings.llm.redaction)
    if err:
        raise DeceptionError(err)
    return t


async def _unique_token(s: AsyncSession, kind: DeceptionKind, name: str, description: str | None) -> str:
    flavor = flavor_for(kind, name, description)
    for _ in range(8):
        token = generate_token(flavor)
        exists = await s.scalar(select(DeceptionAssetRow.id).where(DeceptionAssetRow.token == token))
        if exists is None:
            return token
    raise DeceptionError("could not generate a unique token")  # pragma: no cover - astronomically unlikely


async def _check_conflicts(
    s: AsyncSession,
    *,
    path: str | None,
    token: str | None,
    enabled: bool,
    exclude_id: str | None = None,
) -> None:
    if token:
        q = select(DeceptionAssetRow.id).where(DeceptionAssetRow.token == token)
        if exclude_id:
            q = q.where(DeceptionAssetRow.id != exclude_id)
        if await s.scalar(q) is not None:
            raise DeceptionConflict("token is already used by another deception asset")
    if path and enabled:
        q = select(DeceptionAssetRow.id).where(
            DeceptionAssetRow.path == path, DeceptionAssetRow.enabled.is_(True)
        )
        if exclude_id:
            q = q.where(DeceptionAssetRow.id != exclude_id)
        if await s.scalar(q) is not None:
            raise DeceptionConflict(f"an enabled deception asset already serves {path!r}")


# ---------------------------------------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------------------------------------


async def _create(s: AsyncSession, data: DeceptionAssetIn, settings: Settings) -> DeceptionAsset:
    kind = DeceptionKind(data.kind)
    name = _clean_name(data.name)
    path = _clean_path(kind, data.path, settings)
    if data.token is not None and data.token.strip():
        token = _check_token(data.token, settings)
    else:
        token = await _unique_token(s, kind, name, data.description)
    await _check_conflicts(s, path=path, token=token, enabled=data.enabled)
    row = DeceptionAssetRow(
        id=new_id(),
        kind=kind.value,
        name=name,
        path=path,
        token=token,
        content_template=_clean_template(data.content_template),
        description=data.description,
        enabled=data.enabled,
        created_at=utcnow(),
        trip_count=0,
        last_tripped=None,
    )
    s.add(row)
    await s.flush()
    return DeceptionAsset.model_validate(row)


async def create_asset(data: DeceptionAssetIn, *, actor: str | None = None) -> DeceptionAsset:
    """Create a deception asset (token generated when omitted). Raises DeceptionError on invalid input."""
    settings = get_settings()
    async with session_scope() as s:
        asset = await _create(s, data, settings)
        if actor:
            await record_audit(
                actor,
                "deception.asset.create",
                asset.id,
                {"kind": str(asset.kind), "name": asset.name, "path": asset.path},
                session=s,
            )
    invalidate()
    return asset


async def list_assets(kind: DeceptionKind | None = None, enabled: bool | None = None) -> list[DeceptionAsset]:
    async with session_scope() as s:
        q = select(DeceptionAssetRow).order_by(DeceptionAssetRow.created_at, DeceptionAssetRow.id)
        if kind is not None:
            q = q.where(DeceptionAssetRow.kind == kind.value)
        if enabled is not None:
            q = q.where(DeceptionAssetRow.enabled.is_(enabled))
        rows = (await s.execute(q)).scalars().all()
        return [DeceptionAsset.model_validate(r) for r in rows]


async def get_asset(asset_id: str) -> DeceptionAsset | None:
    async with session_scope() as s:
        row = await s.get(DeceptionAssetRow, asset_id)
        return DeceptionAsset.model_validate(row) if row is not None else None


async def update_asset(
    asset_id: str, patch: DeceptionAssetUpdate, *, actor: str | None = None
) -> DeceptionAsset | None:
    """Partial update. ``token: null`` rotates the token (new value generated); ``kind`` is immutable."""
    settings = get_settings()
    fields = patch.model_dump(exclude_unset=True)
    async with session_scope() as s:
        row = await s.get(DeceptionAssetRow, asset_id)
        if row is None:
            return None
        kind = DeceptionKind(row.kind)
        name = _clean_name(fields["name"]) if "name" in fields else row.name
        path = _clean_path(kind, fields["path"], settings) if "path" in fields else row.path
        enabled = fields["enabled"] if fields.get("enabled") is not None else row.enabled
        token_changed = False
        token = row.token
        if "token" in fields:
            raw = fields["token"]
            token = (
                _check_token(raw, settings)
                if raw and raw.strip()
                else await _unique_token(s, kind, name, row.description)
            )
            token_changed = token != row.token
        await _check_conflicts(
            s, path=path, token=token if token_changed else None, enabled=enabled, exclude_id=row.id
        )
        row.name = name
        row.path = path
        row.enabled = enabled
        row.token = token
        if "content_template" in fields:
            row.content_template = _clean_template(fields["content_template"])
        if "description" in fields:
            row.description = fields["description"]
        await s.flush()
        asset = DeceptionAsset.model_validate(row)
        if actor:
            changed = sorted(k for k in fields if k != "token") + (
                ["token(rotated)"] if token_changed else []
            )
            await record_audit(actor, "deception.asset.update", asset.id, {"changed": changed}, session=s)
    invalidate()
    return asset


async def delete_asset(asset_id: str, *, actor: str | None = None) -> bool:
    """Delete an asset (its trip history is kept). Seeded defaults come back on restart while configured."""
    async with session_scope() as s:
        row = await s.get(DeceptionAssetRow, asset_id)
        if row is None:
            return False
        details = {"kind": row.kind, "name": row.name, "path": row.path}
        await s.delete(row)
        if actor:
            await record_audit(actor, "deception.asset.delete", asset_id, details, session=s)
    invalidate()
    return True


async def disable_asset(asset_id: str, *, actor: str | None = None) -> DeceptionAsset | None:
    """Stop serving/detecting an asset but keep it (reversible). Used by respond's deploy_canary revert."""
    return await update_asset(asset_id, DeceptionAssetUpdate(enabled=False), actor=actor)


async def preview_asset(asset_id: str, path: str | None = None) -> DeceptionPreview | None:
    asset = await get_asset(asset_id)
    if asset is None:
        return None
    cache = await get_cache()
    site = cache.site()
    if not site.key:
        site.key = derive_key()
    return render.preview(asset, site, path)


# ---------------------------------------------------------------------------------------------------------
# seeding
# ---------------------------------------------------------------------------------------------------------


async def seed_defaults() -> list[DeceptionAsset]:
    """Create configured default assets that do not exist yet (idempotent, keyed by kind + path).

    Existing assets are never modified, so an operator's "disabled" choice survives restarts.
    """
    settings = get_settings()
    d = settings.deception
    if not d.enabled:
        return []
    created: list[DeceptionAsset] = []
    async with session_scope() as s:
        rows = (await s.execute(select(DeceptionAssetRow.kind, DeceptionAssetRow.path))).all()
        have: set[tuple[str, str | None]] = {(str(k), p) for k, p in rows}

        async def _try(data: DeceptionAssetIn) -> None:
            try:
                asset = await _create(s, data, settings)
            except DeceptionError as exc:
                log.warning("deception: default asset %r skipped: %s", data.name, exc)
                return
            created.append(asset)
            have.add((str(asset.kind), asset.path))

        for raw in d.decoy_paths:
            p = raw.strip()
            if not p or (DeceptionKind.DECOY_PATH.value, p) in have:
                continue
            await _try(
                DeceptionAssetIn(
                    kind=DeceptionKind.DECOY_PATH,
                    name=f"Decoy {p}",
                    path=p,
                    description="Seeded from deception.decoy_paths. 設定 deception.decoy_paths から作成。",
                )
            )
        if d.ai_canaries:
            for name, path, enabled, desc in DEFAULT_CANARIES:
                if (DeceptionKind.AI_CANARY.value, path) in have:
                    continue
                await _try(
                    DeceptionAssetIn(
                        kind=DeceptionKind.AI_CANARY, name=name, path=path, enabled=enabled, description=desc
                    )
                )
        if d.labyrinth_enabled and not any(k == DeceptionKind.LABYRINTH.value for k, _ in have):
            await _try(
                DeceptionAssetIn(
                    kind=DeceptionKind.LABYRINTH,
                    name="Labyrinth",
                    description="Seeded because deception.labyrinth_enabled is true. 迷路（自動生成ページ網）。",
                )
            )
        if created:
            await record_audit(
                "system", "deception.seed", None, {"created": [a.name for a in created]}, session=s
            )
    if created:
        invalidate()
    return created


# ---------------------------------------------------------------------------------------------------------
# trips
# ---------------------------------------------------------------------------------------------------------


def _trip_detail(e: Event, t: Trip) -> dict[str, Any]:
    h = e.http
    return {
        "asset_name": t.asset.name,
        "token": t.token,
        "fields": t.fields,
        "slots": t.slots,
        "path": h.path if h else None,
        "method": h.method if h else None,
        "user_agent": h.user_agent if h else None,
        "depth": t.depth,
    }


async def record_trips(events: Sequence[Event]) -> list[tuple[Event, Trip]]:
    """Match stored events, append trip rows, bump trip_count/last_tripped and publish ``deception.tripped``."""
    if not events or not get_settings().deception.enabled:
        return []
    index = await get_index()
    if index.empty:
        return []
    found: list[tuple[Event, Trip]] = []
    for e in events:
        try:
            found.extend((e, t) for t in match_event(e, index))
        except Exception:
            log.exception("deception: matching event %s failed", e.id)
    if not found:
        return []
    per_asset: dict[str, tuple[int, datetime]] = {}
    async with session_scope() as s:
        for e, t in found:
            ts = ensure_utc(e.timestamp)
            s.add(
                DeceptionTripRow(
                    id=new_id(),
                    created_at=utcnow(),
                    timestamp=ts,
                    asset_id=t.asset.id,
                    asset_kind=t.asset.kind.value,
                    event_id=e.id,
                    source_ip=e.source_ip,
                    trip_type=t.trip_type.value,
                    ai_followed=t.ai_followed,
                    detail=_trip_detail(e, t),
                )
            )
            n, last = per_asset.get(t.asset.id, (0, ts))
            per_asset[t.asset.id] = (n + 1, max(last, ts))
        for asset_id, (n, last) in per_asset.items():
            await s.execute(
                update(DeceptionAssetRow)
                .where(DeceptionAssetRow.id == asset_id)
                .values(trip_count=DeceptionAssetRow.trip_count + n, last_tripped=last)
                .execution_options(synchronize_session=False)
            )
    for e, t in found:
        await bus.publish(
            "deception.tripped",
            {
                "asset_id": t.asset.id,
                "asset_kind": t.asset.kind.value,
                "asset_name": t.asset.name,
                "event_id": e.id,
                "source_ip": e.source_ip,
                "session_id": e.session_id,
                "trip_type": t.trip_type.value,
                "ai_canary_followed": t.ai_followed,
                "timestamp": ensure_utc(e.timestamp).isoformat(),
            },
        )
    return found


def _trip_event(row: DeceptionTripRow, ev: Event | None) -> Event:
    detail = row.detail or {}
    info = DeceptionInfo(
        asset_id=row.asset_id, asset_kind=row.asset_kind, token=detail.get("token"), detail=row.trip_type
    )
    tags = ["deception:trip", f"deception:{row.trip_type}"]
    if ev is None:  # event purged by retention: synthesize from the trip row
        path = detail.get("path")
        return Event(
            id=row.event_id,
            timestamp=row.timestamp,
            kind=EventKind.DECEPTION,
            dataset="deception.trip",
            source=Endpoint(ip=row.source_ip) if row.source_ip else None,
            http=HttpInfo(path=path, method=detail.get("method"), user_agent=detail.get("user_agent"))
            if path
            else None,
            deception=info,
            tags=tags,
        )
    out = ev.model_copy(deep=True)
    if out.deception is None:
        out.deception = info
    else:
        out.deception.asset_id = out.deception.asset_id or info.asset_id
        out.deception.asset_kind = out.deception.asset_kind or info.asset_kind
        out.deception.token = out.deception.token or info.token
        out.deception.detail = out.deception.detail or info.detail
    out.tags = list(dict.fromkeys([*out.tags, *tags]))
    return out


async def list_trips(
    *, asset_id: str | None = None, source_ip: str | None = None, limit: int = 50, offset: int = 0
) -> Page[Event]:
    """Trip history, newest first, as events annotated with ``deception`` info (one item per trip)."""
    async with session_scope() as s:
        q = select(DeceptionTripRow)
        cq = select(func.count()).select_from(DeceptionTripRow)
        if asset_id:
            q = q.where(DeceptionTripRow.asset_id == asset_id)
            cq = cq.where(DeceptionTripRow.asset_id == asset_id)
        if source_ip:
            q = q.where(DeceptionTripRow.source_ip == source_ip)
            cq = cq.where(DeceptionTripRow.source_ip == source_ip)
        total = int((await s.execute(cq)).scalar_one())
        rows = (
            (
                await s.execute(
                    q.order_by(DeceptionTripRow.timestamp.desc(), DeceptionTripRow.id.desc())
                    .limit(limit)
                    .offset(offset)
                )
            )
            .scalars()
            .all()
        )
        events = {e.id: e for e in await get_events(s, list(dict.fromkeys(r.event_id for r in rows)))}
        items = [_trip_event(r, events.get(r.event_id)) for r in rows]
    return Page[Event](items=items, total=total, limit=limit, offset=offset)


# ---------------------------------------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------------------------------------


async def _on_events_ingested(events: Sequence[Event]) -> None:
    try:
        await record_trips(list(events))
    except Exception:
        log.exception("deception: recording trips failed")


@on_startup
async def _deception_startup() -> None:
    bus.subscribe("event.ingested", _on_events_ingested)
    settings = get_settings()
    sensitive = {h.lower() for h in settings.llm.redaction.sensitive_headers}
    if settings.deception.canary_header.lower() in sensitive:
        log.warning(
            "deception.canary_header %r is in llm.redaction.sensitive_headers: its value is masked before "
            "detection, so AI-canary header follow-ups cannot be detected",
            settings.deception.canary_header,
        )
    if not settings.deception.enabled:
        return
    try:
        created = await seed_defaults()
        if created:
            log.info("deception: seeded %d default asset(s)", len(created))
    except Exception:
        log.exception("deception: seeding default assets failed")
    invalidate()
    try:
        await get_cache(force=True)
    except Exception:
        log.exception("deception: building the index failed")
