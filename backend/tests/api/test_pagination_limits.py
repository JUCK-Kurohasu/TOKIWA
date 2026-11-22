"""#94: a huge ``?offset`` is a 422 on every list route, never an OverflowError 500 from the DB driver."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from tokiwa.api.pagination import MAX_OFFSET, _too_large

HUGE = "99999999999999999999"  # > 2**64: the value that crashed /alerts with OverflowError


def _offset_routes(app: FastAPI) -> list[str]:
    """GET routes without path parameters that accept ``?offset`` (via PageParams or their own Query).

    Read from the OpenAPI document (public API) rather than the router internals.
    """
    paths = []
    for path, ops in app.openapi()["paths"].items():
        get = ops.get("get")
        if get is None or "{" in path:
            continue
        if any(p.get("in") == "query" and p.get("name") == "offset" for p in get.get("parameters", [])):
            paths.append(path)
    return sorted(paths)


async def test_every_offset_route_rejects_huge_offset(
    app: FastAPI, client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    paths = _offset_routes(app)
    # Both kinds must be present, or the test would silently cover nothing: PageParams users and own-Query routes.
    assert "/api/v1/events" in paths and "/api/v1/alerts" in paths, paths
    for path in paths:
        r = await client.get(path, params={"offset": HUGE}, headers=admin_headers)
        assert r.status_code == 422, (path, r.status_code, r.text[:200])
        assert any(err["loc"][-1] == "offset" for err in r.json()["detail"]), (path, r.text[:200])


@pytest.mark.parametrize("path", ["/api/v1/alerts", "/api/v1/events"])
async def test_offset_bounds(path: str, client: httpx.AsyncClient, admin_headers: dict[str, str]) -> None:
    ok = await client.get(path, params={"offset": str(MAX_OFFSET)}, headers=admin_headers)
    assert ok.status_code == 200, ok.text
    assert ok.json()["items"] == []
    too_far = await client.get(path, params={"offset": str(MAX_OFFSET + 1)}, headers=admin_headers)
    assert too_far.status_code == 422
    # Thousands of digits: no int() blow-up (Python's int-from-str digit limit) and the echo is clipped.
    giant = await client.get(path, params={"offset": "9" * 5000}, headers=admin_headers)
    assert giant.status_code == 422
    assert len(giant.text) < 2000
    # Repeated parameter: every value is checked, not just the one FastAPI happens to pick.
    dup = await client.get(f"{path}?offset=1&offset={HUGE}", headers=admin_headers)
    assert dup.status_code == 422


def test_too_large_only_flags_plain_big_integers() -> None:
    assert _too_large(HUGE)
    assert _too_large(str(MAX_OFFSET + 1))
    assert _too_large("+" + str(MAX_OFFSET + 1))
    assert not _too_large(str(MAX_OFFSET))
    assert not _too_large("000000000000000000001")
    assert not _too_large("0")
    # Not integers: left to the route's own validation.
    assert not _too_large("-5")
    assert not _too_large("1e9")
    assert not _too_large("abc")
    assert not _too_large("１２３４５６７８")  # full-width digits


async def test_negative_and_non_numeric_offset_still_422(
    client: httpx.AsyncClient, admin_headers: dict[str, str]
) -> None:
    for value in ("-1", "abc"):
        r = await client.get("/api/v1/alerts", params={"offset": value}, headers=admin_headers)
        assert r.status_code == 422
