"""Intel test helpers: fixture loading and an httpx.MockTransport that emulates every feed endpoint."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from tokiwa.intel import sync as intel_sync
from tokiwa.intel.sources import _common

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "intel"

Handler = Callable[[httpx.Request], httpx.Response]


def fixture_bytes(rel: str) -> bytes:
    return (FIXTURES / rel).read_bytes()


def fixture_json(rel: str) -> Any:
    return json.loads(fixture_bytes(rel))


def _epss(request: httpx.Request) -> httpx.Response:
    wanted = set(request.url.params.get("cve", "").split(","))
    doc = fixture_json("epss/epss.json")
    doc["data"] = [r for r in doc["data"] if r["cve"] in wanted]
    doc["total"] = len(doc["data"])
    return httpx.Response(200, json=doc)


def _nvd(request: httpx.Request) -> httpx.Response:
    start = int(request.url.params.get("startIndex", "0"))
    return httpx.Response(200, content=fixture_bytes("nvd/page1.json" if start == 0 else "nvd/page2.json"))


def _ghsa(request: httpx.Request) -> httpx.Response:
    if "after" in request.url.params:
        return httpx.Response(200, content=fixture_bytes("ghsa/page2.json"))
    nxt = "https://api.github.com/advisories?per_page=100&type=reviewed&after=Y3Vyc29yOnYyOpK0"
    return httpx.Response(
        200, content=fixture_bytes("ghsa/page1.json"), headers={"Link": f'<{nxt}>; rel="next"'}
    )


def _osv(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/querybatch":
        return httpx.Response(200, content=fixture_bytes("osv/querybatch.json"))
    vid = request.url.path.rsplit("/", 1)[-1]
    path = FIXTURES / "osv" / "vulns" / f"{vid}.json"
    if not path.is_file():
        return httpx.Response(404, json={"code": 5, "message": "Bug not found."})
    return httpx.Response(200, content=path.read_bytes())


def _jvn(request: httpx.Request) -> httpx.Response:
    page = "jvn/overview_p1.xml" if request.url.params.get("startItem") == "1" else "jvn/overview_p2.xml"
    return httpx.Response(200, content=fixture_bytes(page), headers={"Content-Type": "application/xml"})


def default_routes() -> dict[tuple[str, str], Handler]:
    """(host, path-prefix) -> handler. Hosts/paths are the real production endpoints."""
    return {
        ("www.cisa.gov", "/sites/default/files/feeds/known_exploited_vulnerabilities.json"): lambda r: (
            httpx.Response(200, content=fixture_bytes("kev/known_exploited_vulnerabilities.json"))
        ),
        ("api.first.org", "/data/v1/epss"): _epss,
        ("services.nvd.nist.gov", "/rest/json/cves/2.0"): _nvd,
        ("api.github.com", "/advisories"): _ghsa,
        ("api.osv.dev", "/v1/"): _osv,
        ("jvndb.jvn.jp", "/myjvn"): _jvn,
        ("www.jpcert.or.jp", "/rss/jpcert.rdf"): lambda r: httpx.Response(
            200, content=fixture_bytes("rss/jpcert.rdf")
        ),
        ("www.ipa.go.jp", "/security/alert-rss.rdf"): lambda r: httpx.Response(404, text="not found"),
        ("www.cisa.gov", "/cybersecurity-advisories/all.xml"): lambda r: httpx.Response(
            200, content=fixture_bytes("rss/cisa.xml")
        ),
        ("feeds.feedburner.com", "/TheHackersNews"): lambda r: httpx.Response(
            200, content=fixture_bytes("rss/thehackernews.atom")
        ),
        ("www.bleepingcomputer.com", "/feed/"): lambda r: httpx.Response(200, content=b"<html>not a feed"),
    }


class FeedRouter:
    def __init__(self) -> None:
        self.routes = default_routes()
        self.calls: list[httpx.Request] = []

    def set(self, host: str, path: str, handler: Handler) -> None:
        self.routes[(host, path)] = handler

    def requests_to(self, host: str) -> list[httpx.Request]:
        return [r for r in self.calls if r.url.host == host]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        for (host, prefix), handler in sorted(self.routes.items(), key=lambda kv: -len(kv[0][1])):
            if request.url.host == host and request.url.path.startswith(prefix):
                return handler(request)
        return httpx.Response(599, text=f"unrouted {request.url}")

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self), follow_redirects=True)


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record rate-limit sleeps instead of waiting."""
    slept: list[float] = []

    async def fake(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(_common, "_SLEEP", fake)
    return slept


@pytest.fixture
def feeds(no_sleep: list[float]) -> Iterator[FeedRouter]:
    """Route every intel HTTP request (also from background syncs) to the fixture router."""
    router = FeedRouter()
    intel_sync.set_client_factory(router.client)
    yield router
    intel_sync.set_client_factory(None)
