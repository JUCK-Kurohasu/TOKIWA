from __future__ import annotations

from gate_helpers import FakeTime

from tokiwa.gate.ratelimit import TokenBucketLimiter


def test_burst_then_429_then_refill() -> None:
    t = FakeTime()
    limiter = TokenBucketLimiter(clock=t.clock)
    assert [limiter.allow("1.2.3.4", 3)[0] for _ in range(3)] == [True, True, True]
    allowed, retry_after = limiter.allow("1.2.3.4", 3)
    assert not allowed
    assert retry_after == 20  # 3/min -> one token every 20 s
    t.advance(20)
    assert limiter.allow("1.2.3.4", 3) == (True, 0.0)
    assert limiter.allow("1.2.3.4", 3)[0] is False


def test_buckets_are_per_client() -> None:
    t = FakeTime()
    limiter = TokenBucketLimiter(clock=t.clock)
    assert limiter.allow("a", 1)[0]
    assert not limiter.allow("a", 1)[0]
    assert limiter.allow("b", 1)[0]


def test_zero_limit_denies() -> None:
    limiter = TokenBucketLimiter()
    assert limiter.allow("a", 0) == (False, 60.0)


def test_limit_change_rescales_bucket() -> None:
    t = FakeTime()
    limiter = TokenBucketLimiter(clock=t.clock)
    for _ in range(10):
        assert limiter.allow("a", 10)[0]
    # bucket empty at 10/min; policy tightens to 2/min: still empty, must wait 30 s for a token
    allowed, retry = limiter.allow("a", 2)
    assert not allowed and retry == 30
    t.advance(30)
    assert limiter.allow("a", 2)[0]


def test_lru_bound() -> None:
    limiter = TokenBucketLimiter(max_keys=100)
    for i in range(1000):
        limiter.allow(f"10.0.{i // 256}.{i % 256}", 5)
    assert len(limiter) == 100
    limiter.reset()
    assert len(limiter) == 0


async def test_cidr_rate_limit_is_one_budget_for_the_range(make_gate, fake_server) -> None:  # type: ignore[no-untyped-def]
    """Audit #142: rotating through addresses inside a rate-limited range no longer gives each a fresh bucket."""
    from gate_helpers import client_for

    fake_server.set_policy("v1", rate_limited={"198.51.100.0/24": 2})
    app, _gate = await make_gate()
    codes = []
    for i in range(1, 5):
        async with client_for(app, ip=f"198.51.100.{i}") as c:
            codes.append((await c.get("/")).status_code)
    assert codes == [200, 200, 429, 429]


async def test_ipv6_clients_share_their_64(make_gate, fake_server) -> None:  # type: ignore[no-untyped-def]
    """A single-address IPv6 limit applies per /64 (ADR-0008): a client cannot rotate inside its own /64."""
    from gate_helpers import client_for

    fake_server.set_policy("v1", rate_limited={"2001:db8:1:2::/64": 1})
    app, gate = await make_gate()
    async with client_for(app, ip="2001:db8:1:2::10") as c:
        assert (await c.get("/")).status_code == 200
    async with client_for(app, ip="2001:db8:1:2::abcd") as c:
        assert (await c.get("/")).status_code == 429


def test_client_bucket_key() -> None:
    from tokiwa.gate.netmatch import client_bucket_key

    assert client_bucket_key("203.0.113.5") == "203.0.113.5"
    assert client_bucket_key("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64"
    assert client_bucket_key("::ffff:203.0.113.5") == "203.0.113.5"
    assert client_bucket_key(None) == "unknown"


async def test_inflight_cap_counts_the_ipv6_64(make_gate) -> None:  # type: ignore[no-untyped-def]
    import asyncio

    from gate_helpers import http_scope

    app, gate = await make_gate(max_requests_per_client=1, body_idle_timeout_seconds=0)
    release = asyncio.Event()
    sent: list[dict] = []

    async def receive_hold() -> dict:
        if not sent:
            sent.append({})
            return {"type": "http.request", "body": b"a", "more_body": True}
        await release.wait()
        return {"type": "http.disconnect"}

    async def send(_m: dict) -> None:
        return None

    scope = http_scope("/upload", b"/upload", ip="2001:db8:1:2::1", method="POST")
    scope["headers"] = [*scope["headers"], (b"content-length", b"10")]
    task = asyncio.create_task(app(scope, receive_hold, send))
    for _ in range(50):
        await asyncio.sleep(0)
    assert gate._inflight["2001:db8:1:2::/64"] == 1
    statuses: list[int] = []

    async def capture(m: dict) -> None:
        if m["type"] == "http.response.start":
            statuses.append(m["status"])

    async def receive_done() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    await app(http_scope("/", b"/", ip="2001:db8:1:2::ffff"), receive_done, capture)
    assert statuses == [429]  # another address in the same /64
    release.set()
    await asyncio.wait_for(task, timeout=5)
