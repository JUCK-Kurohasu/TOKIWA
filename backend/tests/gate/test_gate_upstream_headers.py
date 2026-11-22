"""What the Gate sends upstream on behalf of a client: nothing the client did not send (cookies, httpx defaults)."""

from __future__ import annotations

from gate_helpers import GateFactory, Upstream, client_for


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
