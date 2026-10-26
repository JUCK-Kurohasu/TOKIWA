"""Service (DB) + API integration: seeding, CRUD, gate decoys, ingest -> alerts, trips."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import httpx
import pytest
from sqlalchemy import select

from tokiwa.auth.security import hash_password
from tokiwa.bus import bus
from tokiwa.db.models.core import AuditRow, UserRow
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.deception import service
from tokiwa.deception.policy import build_gate_decoys
from tokiwa.deception.tokens import Slot, derive_key, honey_values
from tokiwa.llm.redact import redact_headers
from tokiwa.pipeline.service import process_events
from tokiwa.schemas.deception import DeceptionAssetUpdate
from tokiwa.schemas.events import Event
from tokiwa.schemas.response import DeceptionAssetIn, DeceptionKind
from tokiwa.util import new_id

MakeEvent = Callable[..., Event]
API = "/api/v1/deception"


async def _alerts(ids: list[str]) -> list[AlertRow]:
    async with session_scope() as s:
        return list((await s.execute(select(AlertRow).where(AlertRow.id.in_(ids)))).scalars().all())


# ------------------------------------------------------------------ service (db fixture only)


@pytest.mark.usefixtures("db")
async def test_create_generates_flavored_token_and_audits() -> None:
    a = await service.create_asset(
        DeceptionAssetIn(kind=DeceptionKind.HONEYTOKEN, name="aws backup key"), actor="alice"
    )
    assert a.token and a.token.startswith("AKIA") and len(a.token) == 24
    c = await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.AI_CANARY, name="respond canary"))
    assert c.token and c.token.startswith("dbg_")
    lab = await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.LABYRINTH, name="maze"))
    assert lab.path == "/archive/*"
    async with session_scope() as s:
        audits = (
            await s.execute(select(AuditRow).where(AuditRow.action == "deception.asset.create"))
        ).scalars()
        assert [r.actor for r in audits] == ["alice"]


@pytest.mark.usefixtures("db")
@pytest.mark.parametrize(
    ("data", "code"),
    [
        ({"kind": "decoy_path", "name": "x"}, 422),  # path required
        ({"kind": "decoy_path", "name": "x", "path": "no-slash"}, 422),
        ({"kind": "decoy_path", "name": "x", "path": "/"}, 422),
        ({"kind": "decoy_path", "name": "x", "path": "/a*b"}, 422),
        ({"kind": "decoy_path", "name": " ", "path": "/a"}, 422),
        ({"kind": "honeytoken", "name": "x", "token": "AKIAABCDEFGHIJKLMNOP"}, 422),  # would be masked
    ],
)
async def test_create_validation(data: dict[str, str], code: int) -> None:
    with pytest.raises(service.DeceptionError) as exc:
        await service.create_asset(DeceptionAssetIn.model_validate(data))
    assert exc.value.status_code == code


@pytest.mark.usefixtures("db")
async def test_conflicts_update_rotate_delete() -> None:
    a = await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.DECOY_PATH, name="a", path="/old.sql"))
    with pytest.raises(service.DeceptionConflict):
        await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.DECOY_PATH, name="b", path="/old.sql"))
    with pytest.raises(service.DeceptionConflict):
        await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.HONEYTOKEN, name="c", token=a.token))
    # a disabled duplicate path is allowed (only one can be served)
    await service.create_asset(
        DeceptionAssetIn(kind=DeceptionKind.DECOY_PATH, name="b", path="/old.sql", enabled=False)
    )
    rotated = await service.update_asset(a.id, DeceptionAssetUpdate(token=None, path="/new.sql"), actor="bob")
    assert rotated is not None and rotated.token != a.token and rotated.path == "/new.sql"
    idx = await service.get_index()
    assert rotated.token in idx.tokens and a.token not in idx.tokens  # cache invalidated after commit
    off = await service.update_asset(a.id, DeceptionAssetUpdate(enabled=False))
    assert off is not None and not off.enabled
    assert a.id not in (await service.get_index()).assets
    assert await service.update_asset(new_id(), DeceptionAssetUpdate(name="x")) is None
    assert await service.delete_asset(a.id, actor="bob")
    assert not await service.delete_asset(a.id)


@pytest.mark.usefixtures("db")
async def test_seed_defaults_is_idempotent_and_respects_disable() -> None:
    created = await service.seed_defaults()
    kinds = sorted((str(a.kind), a.path or "", a.enabled) for a in created)
    assert len([k for k in kinds if k[0] == "decoy_path"]) == 5
    assert ("ai_canary", "", True) in kinds and ("ai_canary", "/robots.txt", False) in kinds
    env = next(a for a in created if a.path == "/.env")
    await service.update_asset(env.id, DeceptionAssetUpdate(enabled=False))
    assert await service.seed_defaults() == []
    again = await service.get_asset(env.id)
    assert again is not None and not again.enabled


@pytest.mark.usefixtures("db")
async def test_build_gate_decoys_only_enabled(settings) -> None:  # type: ignore[no-untyped-def]
    await service.seed_defaults()
    routes, html = await build_gate_decoys()
    paths = {r.path for r in routes}
    assert {"/.env", "/backup.sql", "/.git/config", "/api/internal/openapi.json"} <= paths
    assert "/robots.txt" not in paths and "/llms.txt" not in paths  # seeded disabled
    assert html is not None and "X-Debug-Auth" in html
    env = next(a for a in await service.list_assets() if a.path == "/.env")
    await service.update_asset(env.id, DeceptionAssetUpdate(enabled=False))
    routes, _ = await build_gate_decoys()
    assert "/.env" not in {r.path for r in routes}
    assert all(r.asset_id != env.id for r in routes)
    settings.deception.enabled = False
    assert await build_gate_decoys() == ([], None)


async def test_index_without_database_is_empty(settings) -> None:  # type: ignore[no-untyped-def]
    assert (await service.get_index()).empty
    assert await build_gate_decoys() == ([], None)


@pytest.mark.usefixtures("db")
async def test_record_trips_counts_publishes_and_lists(make_http_event: MakeEvent) -> None:
    await service.seed_defaults()
    env = next(a for a in await service.list_assets() if a.path == "/.env")
    q = bus.listen()
    events = [make_http_event("/.env"), make_http_event("/.env", ip="198.51.100.7"), make_http_event("/ok")]
    await process_events(events)  # stores events (no subscriber registered in this test)
    found = await service.record_trips(events)
    assert len(found) == 2
    asset = await service.get_asset(env.id)
    assert asset is not None and asset.trip_count == 2 and asset.last_tripped is not None
    tripped = []
    while not q.empty():
        topic, payload = q.get_nowait()
        if topic == "deception.tripped":
            tripped.append(payload)
    bus.unlisten(q)
    assert {p["source_ip"] for p in tripped} == {"203.0.113.10", "198.51.100.7"}
    assert all(p["asset_id"] == env.id and p["trip_type"] == "decoy_path" for p in tripped)
    page = await service.list_trips(asset_id=env.id)
    assert page.total == 2 and len(page.items) == 2
    assert all(e.deception and e.deception.asset_id == env.id for e in page.items)
    assert (await service.list_trips(source_ip="198.51.100.7")).total == 1


# ------------------------------------------------------------------ API (app startup seeds defaults)


async def test_api_crud_preview_and_permissions(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    assert (await client.get(f"{API}/assets")).status_code == 401
    seeded = (await client.get(f"{API}/assets", headers=admin_headers)).json()
    assert any(a["path"] == "/.env" for a in seeded)
    assert len((await client.get(f"{API}/assets?kind=ai_canary", headers=admin_headers)).json()) == 4

    r = await client.post(
        f"{API}/assets",
        json={"kind": "honeytoken", "name": "db creds", "path": "/.pgpass"},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    asset = r.json()
    assert asset["token"].startswith("app_rw_") and asset["trip_count"] == 0
    bad = await client.post(f"{API}/assets", json={"kind": "decoy_path", "name": "x"}, headers=admin_headers)
    assert bad.status_code == 422
    dup = await client.post(
        f"{API}/assets", json={"kind": "decoy_path", "name": "y", "path": "/.pgpass"}, headers=admin_headers
    )
    assert dup.status_code == 409

    pv = (await client.get(f"{API}/preview/{asset['id']}", headers=admin_headers)).json()
    assert pv["path"] == "/.pgpass" and asset["token"] in pv["body"] and pv["served"] is True
    html_canary = next(a for a in seeded if a["kind"] == "ai_canary" and a["path"] is None)
    pv = (await client.get(f"{API}/preview/{html_canary['id']}", headers=admin_headers)).json()
    assert pv["path"] is None and html_canary["token"] in pv["body"] and "aria-hidden" in pv["body"]

    r = await client.patch(f"{API}/assets/{asset['id']}", json={"enabled": False}, headers=admin_headers)
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert (await client.delete(f"{API}/assets/{asset['id']}", headers=admin_headers)).status_code == 204
    assert (await client.get(f"{API}/assets/{asset['id']}", headers=admin_headers)).status_code == 404
    assert (await client.get(f"{API}/preview/{asset['id']}", headers=admin_headers)).status_code == 404

    async with session_scope() as s:
        s.add(
            UserRow(
                id=new_id(), username="viewer", password_hash=hash_password("viewer-password"), role="viewer"
            )
        )
    login = await client.post(
        "/api/v1/auth/login", json={"username": "viewer", "password": "viewer-password"}
    )
    viewer = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert (await client.get(f"{API}/assets", headers=viewer)).status_code == 200
    assert (
        await client.post(f"{API}/assets", json={"kind": "ai_canary", "name": "v"}, headers=viewer)
    ).status_code == 403
    assert (await client.get(f"{API}/preview/{html_canary['id']}", headers=viewer)).status_code == 403


async def test_ingest_decoy_path_creates_critical_alert_and_trip(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    ev = make_http_event("/.env", status=200)
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [ev.model_dump(mode="json")]}, headers=ingest_headers
    )
    assert r.status_code == 200, r.text
    alerts = [a for a in await _alerts(r.json()["alert_ids"]) if a.detector == "deception.trip"]
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity == "critical" and a.category == "deception" and a.details["trip_type"] == "decoy_path"
    await bus.drain()
    trips = (await client.get(f"{API}/trips", headers=admin_headers)).json()
    assert trips["total"] == 1 and trips["items"][0]["id"] == ev.id
    assert trips["items"][0]["deception"]["asset_id"] == a.details["asset_id"]
    asset = (await client.get(f"{API}/assets/{a.details['asset_id']}", headers=admin_headers)).json()
    assert asset["trip_count"] == 1 and asset["last_tripped"] is not None


async def test_ingest_ai_canary_header_is_ai_agent(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    assets = (await client.get(f"{API}/assets?kind=ai_canary", headers=admin_headers)).json()
    token = next(a["token"] for a in assets if a["path"] is None)
    # what the Gate ships: headers redacted (the canary header is not sensitive, so the value survives)
    headers = redact_headers({"User-Agent": "python-httpx/0.28", "X-Debug-Auth": token})
    ev = make_http_event("/api/products", headers=headers)
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [ev.model_dump(mode="json")]}, headers=ingest_headers
    )
    alerts = [a for a in await _alerts(r.json()["alert_ids"]) if a.detector == "deception.trip"]
    assert len(alerts) == 1
    a = alerts[0]
    assert a.category == "ai_agent" and a.ai_score == pytest.approx(0.99) and a.severity == "critical"
    assert "ai_canary" in a.tags and a.details["ai_canary_followed"] is True
    await bus.drain()
    trips = (await client.get(f"{API}/trips", headers=admin_headers)).json()
    assert trips["items"][0]["deception"]["detail"] == "ai_canary_followed"


async def test_decoy_derived_canary_path_follow(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
    ingest_headers: dict[str, str],
    make_http_event: MakeEvent,
) -> None:
    env = next(
        a for a in (await client.get(f"{API}/assets", headers=admin_headers)).json() if a["path"] == "/.env"
    )
    canary = honey_values(DeceptionKind.DECOY_PATH, env["token"], derive_key())[Slot.CANARY]
    pv = (await client.get(f"{API}/preview/{env['id']}", headers=admin_headers)).json()
    assert canary in pv["body"] and f"/api/internal/{canary}*" in pv["extra_paths"]
    ev = make_http_event(f"/api/internal/{canary}/users")
    r = await client.post(
        "/api/v1/ingest/events", json={"events": [ev.model_dump(mode="json")]}, headers=ingest_headers
    )
    alerts = [a for a in await _alerts(r.json()["alert_ids"]) if a.detector == "deception.trip"]
    assert [a.category for a in alerts] == ["ai_agent"]


async def test_respond_deploy_canary_contract(client: httpx.AsyncClient) -> None:
    """respond's deploy_canary executor calls service.create_asset(DeceptionAssetIn); it must reach the gate."""
    a = await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.AI_CANARY, name="deployed by respond"))
    routes, html = await build_gate_decoys()
    assert f"/api/internal/{a.token}*" in {r.path for r in routes}
    assert html is not None and a.token in html
    await asyncio.sleep(0)


@pytest.mark.usefixtures("db")
async def test_respond_revert_contract_disable_and_delete() -> None:
    a = await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.AI_CANARY, name="deploy_canary"))
    assert a.token in (await service.get_index()).tokens
    off = await service.disable_asset(a.id, actor="policy")
    assert off is not None and not off.enabled
    assert a.token not in (await service.get_index()).tokens
    assert await service.disable_asset(new_id()) is None
    assert await service.delete_asset(a.id)
    assert await service.get_asset(a.id) is None
