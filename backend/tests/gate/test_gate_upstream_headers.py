"""What the Gate sends upstream on behalf of a client: nothing the client did not send (cookies, httpx defaults)."""

from __future__ import annotations

from gate_helpers import (
    CLIENT_IP,
    FakeServer,
    GateFactory,
    Upstream,
    asgi_call,
    client_for,
    events_of,
    http_scope,
)

from tokiwa.gate.capture import PRIORITY_HEADERS
from tokiwa.gate.proxy import STRIPPED_CLIENT_HEADERS
from tokiwa.schemas.response import DecoyRoute


def test_every_stripped_header_stays_visible_in_events() -> None:
    """What the Gate removes before forwarding is exactly what an event must still show (spoofing attempts)."""
    assert {h.decode() for h in STRIPPED_CLIENT_HEADERS} <= PRIORITY_HEADERS


async def test_httpx_defaults_are_not_added_for_the_client(
    make_gate: GateFactory, upstream: Upstream
) -> None:
    """Audit #149: a client without User-Agent / Accept / Accept-Encoding must not become python-httpx."""
    app, _ = await make_gate()
    sent = await asgi_call(app, http_scope("/bare", b"/bare", headers=[(b"host", b"shop.example")]))
    assert sent[0]["status"] == 200
    names = {k for k, _ in upstream.requests[0]["headers"]}
    assert not names & {"user-agent", "accept", "accept-encoding", "cookie"}, names
    assert "host" in names and upstream.header(0, "x-real-ip") == [CLIENT_IP]


async def test_client_headers_are_forwarded_as_sent(make_gate: GateFactory, upstream: Upstream) -> None:
    app, _ = await make_gate()
    headers = [(b"host", b"shop.example"), (b"user-agent", b"curl/8.5.0"), (b"accept", b"text/html")]
    await asgi_call(app, http_scope("/x", b"/x", headers=headers))
    assert upstream.header(0, "user-agent") == ["curl/8.5.0"]
    assert upstream.header(0, "accept") == ["text/html"]
    assert upstream.header(0, "accept-encoding") == []


async def test_spoofed_client_address_is_stripped_and_marked(
    make_gate: GateFactory, upstream: Upstream, fake_server: FakeServer
) -> None:
    app, gate = await make_gate()
    headers = [
        (b"host", b"shop.example"),
        (b"x-real-ip", b"10.0.0.1"),
        (b"cf-connecting-ip", b"10.0.0.1"),
        (b"forwarded", b"for=10.0.0.1;proto=https"),
    ]
    await asgi_call(app, http_scope("/admin", b"/admin", headers=headers))
    assert upstream.header(0, "x-real-ip") == [CLIENT_IP]
    assert upstream.header(0, "cf-connecting-ip") == []
    assert upstream.header(0, "forwarded") == [f"for={CLIENT_IP};proto=http;host=shop.example"]
    (event,) = await events_of(gate, fake_server)
    assert "gate:client_ip_header" in event["tags"]
    assert event["labels"]["gate.stripped_headers"] == "cf-connecting-ip,forwarded,x-real-ip"
    assert event["http"]["headers"]["cf-connecting-ip"] == "10.0.0.1"  # the claim itself is evidence


async def test_forward_client_headers_setting(make_gate: GateFactory, upstream: Upstream) -> None:
    app, _ = await make_gate(forward_client_headers=["CF-Connecting-IP"])
    headers = [(b"host", b"shop.example"), (b"cf-connecting-ip", b"198.51.100.4"), (b"x-real-ip", b"1.1.1.1")]
    await asgi_call(app, http_scope("/", b"/", headers=headers))
    assert upstream.header(0, "cf-connecting-ip") == ["198.51.100.4"]
    assert upstream.header(0, "x-real-ip") == [CLIENT_IP]


async def test_route_override_is_stripped_and_matched_against_decoys(
    make_gate: GateFactory, upstream: Upstream, fake_server: FakeServer
) -> None:
    """Audit #147: X-Original-URL never reaches the upstream, and pointing it at a decoy trips the decoy."""
    fake_server.set_policy(
        "v1", decoys=[DecoyRoute(asset_id="env", kind="decoy_path", path="/.env", body="DB_PASSWORD=x")]
    )
    app, gate = await make_gate()
    base = [(b"host", b"shop.example")]
    sent = await asgi_call(
        app, http_scope("/static/app.js", b"/static/app.js", headers=[*base, (b"x-original-url", b"/.env")])
    )
    assert sent[0]["status"] == 200 and b"DB_PASSWORD" in sent[1]["body"]
    assert upstream.requests == []
    await asgi_call(
        app, http_scope("/static/app.js", b"/static/app.js", headers=[*base, (b"x-rewrite-url", b"/about")])
    )
    assert len(upstream.requests) == 1 and upstream.header(0, "x-rewrite-url") == []
    events = await events_of(gate, fake_server)
    decoy_http, decoy_trip, proxied = events
    assert decoy_trip["kind"] == "deception" and decoy_trip["deception"]["asset_id"] == "env"
    assert "gate:route_override" in decoy_http["tags"] and "gate:decoy" in decoy_http["tags"]
    assert "gate:route_override" in proxied["tags"] and "gate:client_ip_header" in proxied["tags"]
    assert proxied["http"]["headers"]["x-rewrite-url"] == "/about"


async def test_upstream_cookies_are_never_replayed_to_other_clients(
    make_gate: GateFactory, upstream: Upstream
) -> None:
    """One shared httpx client serves every visitor: a Set-Cookie for A must not ride along B's request."""
    app, gate = await make_gate()
    async with client_for(app, ip="198.51.100.1") as alice:
        r = await alice.get("/cookies")  # upstream answers with Set-Cookie: a=1 / b=2
        assert r.status_code == 200
        assert len(r.headers.get_list("set-cookie")) == 2  # still forwarded to the client itself
    async with client_for(app, ip="198.51.100.2") as bob:
        for _ in range(3):
            assert (await bob.get("/me")).status_code == 200
    assert all(not upstream.header(i, "cookie") for i in range(1, 4))
    assert len(gate.upstream_client.cookies.jar) == 0
    assert len(gate.server_client.cookies.jar) == 0


async def test_client_cookie_is_forwarded_unchanged(make_gate: GateFactory, upstream: Upstream) -> None:
    app, _ = await make_gate()
    async with client_for(app) as c:
        await c.get("/cookies")
        await c.get("/me", headers={"Cookie": "sid=mine"})
    assert upstream.header(1, "cookie") == ["sid=mine"]
