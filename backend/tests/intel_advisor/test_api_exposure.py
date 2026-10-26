"""Assets / intel-advice API, asset mapper enricher and the alert-driven vuln_exposure detector."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from sqlalchemy import select

from tokiwa.auth.security import create_access_token
from tokiwa.bus import bus
from tokiwa.db.models.core import UserRow
from tokiwa.db.models.detection import AlertRow
from tokiwa.db.session import session_scope
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import get_detection_engine
from tokiwa.enrich.asset_mapper import AssetIndex, AssetMapper, invalidate_asset_index
from tokiwa.intel.matcher import run_matching
from tokiwa.llm.mock import MockProvider
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Endpoint, Event, EventKind, HostInfo, HttpInfo, NetworkInfo
from tokiwa.util import new_id, utcnow

from ._helpers import APACHE_AFFECTED, APACHE_SW, add_asset, add_vuln

API = "/api/v1"


@register_detector
class _TestAttackDetector(Detector):
    id = "test.intel_attack"
    name = "test attack"
    category = AlertCategory.EXPLOIT_ATTEMPT
    kinds = frozenset({EventKind.HTTP})
    enabled_by_default = False  # enabled explicitly in tests

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        if event.http and event.http.path == "/__intel_attack":
            return [self.draft(event, title="exploit attempt", severity=Severity.HIGH)]
        return []


# ------------------------------------------------------------------------------------------------ asset mapper


def test_asset_index_lookups() -> None:
    idx = AssetIndex.build(
        [
            ("a-web", "web-1.lab", ["10.0.0.5"]),
            ("a-net", None, ["10.0.0.0/24"]),
            ("a-sub", None, ["10.0.0.128/25", "not-an-ip"]),
            ("a-v6", None, ["2001:db8::1"]),
        ]
    )
    ev = Event(kind=EventKind.HTTP, dataset="t", destination=Endpoint(ip="10.0.0.5"))
    assert idx.lookup_event(ev) == "a-web"
    assert idx.lookup_ip("10.0.0.7") == "a-net"
    assert idx.lookup_ip("10.0.0.200") == "a-sub"  # most specific network wins
    assert idx.lookup_ip("::ffff:10.0.0.5") == "a-web"
    assert idx.lookup_ip("[2001:db8::1]") == "a-v6"
    http = Event(kind=EventKind.HTTP, dataset="t", http=HttpInfo(host="WEB-1.lab:8443"))
    assert idx.lookup_event(http) == "a-web"
    host = Event(kind=EventKind.PORT_SNAPSHOT, dataset="t", host=HostInfo(name="web-1.lab."))
    assert idx.lookup_event(host) == "a-web"
    outbound = Event(
        kind=EventKind.CONNECTION,
        dataset="t",
        source=Endpoint(ip="10.0.0.5"),
        destination=Endpoint(ip="198.51.100.1"),
        network=NetworkInfo(direction="outbound"),
    )
    assert idx.lookup_event(outbound) == "a-web"
    inbound = outbound.model_copy(update={"network": NetworkInfo(direction="inbound")})
    assert idx.lookup_event(inbound) is None


@pytest.mark.usefixtures("db")
async def test_asset_mapper_enricher_reloads_on_invalidate() -> None:
    mapper = AssetMapper()
    ev = Event(kind=EventKind.HTTP, dataset="t", destination=Endpoint(ip="10.9.9.9"))
    await mapper.enrich([ev])
    assert ev.asset_id is None
    asset_id = await add_asset("late", ips=["10.9.9.9"])
    invalidate_asset_index()
    ev2 = Event(kind=EventKind.HTTP, dataset="t", destination=Endpoint(ip="10.9.9.9"))
    preset = Event(kind=EventKind.HTTP, dataset="t", destination=Endpoint(ip="10.9.9.9"), asset_id="keep")
    await mapper.enrich([ev2, preset])
    assert ev2.asset_id == asset_id and preset.asset_id == "keep"


# ------------------------------------------------------------------------------------------------ vuln_exposure


async def _exposure_alerts() -> list[AlertRow]:
    async with session_scope() as s:
        stmt = select(AlertRow).where(AlertRow.rule_id == "intel.vuln_exposure")
        return list((await s.execute(stmt)).scalars())


async def test_vuln_exposure_alert_on_attack_against_kev_asset(
    client: httpx.AsyncClient,
    ingest_headers: dict[str, str],
    make_http_event: Callable[..., Event],
    mock_llm: MockProvider,
) -> None:
    await add_vuln("CVE-2099-4000", kev=True, affected=APACHE_AFFECTED)
    asset_id = await add_asset("web-1", software=[APACHE_SW], ips=["10.0.0.5"])  # make_http_event dest IP
    await run_matching()
    await bus.drain()
    get_detection_engine().overrides["test.intel_attack"] = True

    async def ingest(path: str) -> None:
        body = {"events": [make_http_event(path).model_dump(mode="json")]}
        r = await client.post(f"{API}/ingest/events", json=body, headers=ingest_headers)
        assert r.status_code == 200, r.text
        await bus.drain()

    await ingest("/harmless")  # no attack alert -> no exposure alert
    assert await _exposure_alerts() == []

    await ingest("/__intel_attack")
    [alert] = await _exposure_alerts()
    assert alert.severity == "critical" and alert.category == "vuln_exposure"
    assert alert.entities["asset_id"] == asset_id and alert.entities["cve"] == "CVE-2099-4000"
    assert alert.details["vulns"][0]["kev"] is True
    assert alert.evidence_event_ids

    await ingest("/__intel_attack")  # repeated attack is deduplicated upstream -> still one exposure alert
    [again] = await _exposure_alerts()
    assert again.id == alert.id

    # a fresh attack alert while the detector is disabled must not produce an exposure alert
    get_detection_engine().overrides["intel.vuln_exposure"] = False
    async with session_scope() as s:
        for row in (await s.execute(select(AlertRow))).scalars():
            row.status = "resolved"
    await ingest("/__intel_attack")
    assert len(await _exposure_alerts()) == 1


# --------------------------------------------------------------------------------------------------------- API


async def test_assets_crud_and_matching(
    client: httpx.AsyncClient, admin_headers: dict[str, str], mock_llm: MockProvider
) -> None:
    h = admin_headers
    assert (await client.get(f"{API}/assets")).status_code == 401
    await add_vuln("CVE-2099-5000", kev=True, affected=APACHE_AFFECTED, references=["https://nvd.nist.gov/x"])

    bad = await client.post(f"{API}/assets", json={"name": "x", "ips": ["999.1.1.1"]}, headers=h)
    assert bad.status_code == 422
    r = await client.post(
        f"{API}/assets",
        json={
            "name": "web-1",
            "ips": ["10.0.0.5", "10.0.1.0/24"],
            "software": [APACHE_SW],
            "criticality": "high",
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    asset = r.json()
    await bus.drain()  # background matching -> intel.vuln_matched -> P1 advisory

    listed = (await client.get(f"{API}/assets", params={"q": "web"}, headers=h)).json()
    assert listed["total"] == 1 and listed["items"][0]["ips"] == ["10.0.0.5", "10.0.1.0/24"]
    assert (await client.get(f"{API}/assets", params={"kind": "llm_app"}, headers=h)).json()["total"] == 0
    assert (await client.get(f"{API}/assets/{asset['id']}", headers=h)).json()["name"] == "web-1"
    assert (await client.get(f"{API}/assets/nope", headers=h)).status_code == 404

    m = (await client.get(f"{API}/intel/matches", params={"status": "open"}, headers=h)).json()
    assert m["total"] == 1
    match = m["items"][0]
    assert match["asset_name"] == "web-1" and match["kev"] is True and match["vuln_id"] == "CVE-2099-5000"

    advisories = (await client.get(f"{API}/intel/advisories", params={"priority": "P1"}, headers=h)).json()
    assert advisories["total"] == 1
    adv = advisories["items"][0]
    assert adv["analysis"]["affected_assets"] == [asset["id"]] and "_meta" not in adv["analysis"]
    by_vuln = (
        await client.get(f"{API}/intel/advisories", params={"vuln_id": "CVE-2099-5000"}, headers=h)
    ).json()
    assert [a["id"] for a in by_vuln["items"]] == [adv["id"]]

    # generate: dedup returns the existing advisory, force creates a new one, unknown vuln -> 404
    gen = await client.post(f"{API}/intel/advisories/generate", json={"vuln_id": "CVE-2099-5000"}, headers=h)
    assert gen.status_code == 200 and gen.json()["id"] == adv["id"]
    forced = await client.post(
        f"{API}/intel/advisories/generate", json={"vuln_id": "CVE-2099-5000", "force": True}, headers=h
    )
    assert forced.json()["id"] != adv["id"]
    assert (
        await client.post(f"{API}/intel/advisories/generate", json={"vuln_id": "CVE-0000-1"}, headers=h)
    ).status_code == 404
    assert (await client.get(f"{API}/intel/advisories/{adv['id']}", headers=h)).json()["id"] == adv["id"]

    # analyst actions
    r = await client.patch(f"{API}/intel/matches/{match['id']}", json={"status": "accepted"}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    r = await client.patch(f"{API}/intel/advisories/{adv['id']}", json={"status": "acknowledged"}, headers=h)
    assert r.json()["status"] == "acknowledged"
    assert (
        await client.patch(f"{API}/intel/advisories/{adv['id']}", json={"status": "bogus"}, headers=h)
    ).status_code == 422

    # patching the software to a fixed version closes the open match (accepted stays accepted)
    r = await client.patch(
        f"{API}/assets/{asset['id']}", json={"software": [{**APACHE_SW, "version": "2.4.62"}]}, headers=h
    )
    assert r.status_code == 200 and r.json()["software"][0]["version"] == "2.4.62"
    rescan = (await client.post(f"{API}/intel/matches/rescan", headers=h)).json()
    assert rescan["new"] == 0
    after = (await client.get(f"{API}/intel/matches", headers=h)).json()["items"]
    assert [x["status"] for x in after] == ["accepted"]

    assert (await client.delete(f"{API}/assets/{asset['id']}", headers=h)).status_code == 204
    assert (await client.get(f"{API}/intel/matches", headers=h)).json()["total"] == 0
    assert (await client.delete(f"{API}/assets/{asset['id']}", headers=h)).status_code == 404


async def test_research_api_and_viewer_permissions(
    client: httpx.AsyncClient, admin_headers: dict[str, str], mock_llm: MockProvider
) -> None:
    h = admin_headers
    r = await client.post(f"{API}/intel/research/run", json={"topic": "AI agent attacks"}, headers=h)
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["topic"] == "AI agent attacks" and report["output"]["findings"] == []
    listed = (await client.get(f"{API}/intel/research", headers=h)).json()
    assert listed["total"] == 1 and listed["items"][0]["id"] == report["id"]
    assert (await client.get(f"{API}/intel/research/{report['id']}", headers=h)).status_code == 200
    assert (await client.get(f"{API}/intel/research/nope", headers=h)).status_code == 404

    async with session_scope() as s:
        viewer = UserRow(
            id=new_id(), username="viewer1", password_hash="x", role="viewer", created_at=utcnow()
        )
        s.add(viewer)
    token, _ = create_access_token(viewer.id, viewer.username, viewer.role)
    vh = {"Authorization": f"Bearer {token}"}
    assert (await client.get(f"{API}/assets", headers=vh)).status_code == 200
    assert (await client.get(f"{API}/intel/matches", headers=vh)).status_code == 200
    assert (await client.post(f"{API}/assets", json={"name": "x"}, headers=vh)).status_code == 403
    assert (await client.post(f"{API}/intel/research/run", json={}, headers=vh)).status_code == 403
    assert (
        await client.post(f"{API}/intel/advisories/generate", json={"vuln_id": "CVE-1"}, headers=vh)
    ).status_code == 403
