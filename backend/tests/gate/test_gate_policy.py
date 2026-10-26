from __future__ import annotations

import httpx
import pytest
from gate_helpers import FakeServer

from tokiwa.gate.netmatch import parse_ip
from tokiwa.gate.policy import CompiledPolicy, DecoyMatcher, PolicyManager, normalize_path
from tokiwa.schemas.response import DecoyRoute, GatePolicy
from tokiwa.util import utcnow


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/", "/"),
        ("", "/"),
        ("/.env", "/.env"),
        ("//.env", "/.env"),
        ("/static/../.env", "/.env"),
        ("/a/./b/", "/a/b/"),
        ("/../../etc/passwd", "/etc/passwd"),
        ("/admin/", "/admin/"),
        ("/admin/x/..", "/admin/"),
    ],
)
def test_normalize_path(raw: str, expected: str) -> None:
    assert normalize_path(raw) == expected


def _route(path: str, asset: str = "a") -> DecoyRoute:
    return DecoyRoute(asset_id=asset, kind="decoy_path", path=path, body=asset)


def test_decoy_matcher_exact_prefix_and_longest_prefix() -> None:
    matcher, rejected = DecoyMatcher.build(
        [_route("/.env", "env"), _route("/admin/*", "admin"), _route("/admin/secret/*", "secret")]
    )
    assert rejected == []
    assert matcher.match("/.env").asset_id == "env"  # type: ignore[union-attr]
    assert matcher.match("//.env").asset_id == "env"  # type: ignore[union-attr]
    assert matcher.match("/js/../.env").asset_id == "env"  # type: ignore[union-attr]
    assert matcher.match("/.env.bak") is None
    assert matcher.match("/admin/users").asset_id == "admin"  # type: ignore[union-attr]
    assert matcher.match("/admin/secret/keys").asset_id == "secret"  # type: ignore[union-attr]
    assert matcher.match("/administrator") is None  # "/admin/*" is a directory prefix
    assert matcher.match("/") is None


def test_catch_all_decoys_are_rejected() -> None:
    """A '*' or '/*' decoy would replace the protected site for every visitor: refuse it."""
    matcher, rejected = DecoyMatcher.build([_route("*"), _route("/*"), _route("/.git/*")])
    assert rejected == ["*", "/*"]
    assert matcher.match("/index.html") is None
    assert matcher.match("/.git/config") is not None


def test_compile_caps_tarpit_and_reports_invalid() -> None:
    policy = GatePolicy(
        version="v1",
        generated_at=utcnow(),
        blocked=["198.51.100.0/24", "bogus"],
        rate_limited={"203.0.113.0/24": 60, "203.0.113.0/24 ": 10},
        tarpit={"192.0.2.1": 120_000, "192.0.2.2": -5},
        deceive=["2001:db8::/32"],
        decoys=[_route("/*")],
        html_injection="",
    )
    compiled = CompiledPolicy.compile(policy)
    assert compiled.tarpit.lookup(parse_ip("192.0.2.1")) == ("192.0.2.1/32", 30_000)
    assert compiled.tarpit.lookup(parse_ip("192.0.2.2")) == ("192.0.2.2/32", 0)
    assert compiled.rate_limited.lookup(parse_ip("203.0.113.5")) == ("203.0.113.0/24", 10)  # stricter wins
    assert "2001:db8::5" in compiled.deceive
    assert compiled.html_injection is None  # empty string = disabled
    assert set(compiled.invalid_entries) == {"bogus", "decoy:/*"}
    summary = compiled.summary()
    assert summary["blocked"] == 1 and summary["invalid_entries"] == 2


async def test_policy_manager_swaps_only_on_version_change(fake_server: FakeServer) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_server.handler)) as client:
        manager = PolicyManager(client, "http://tokiwa.test/", "tkw_secret", refresh_seconds=5)
        assert manager.current.version is None  # nothing enforced before the first fetch

        fake_server.set_policy("v1", blocked=["198.51.100.0/24"])
        assert await manager.refresh() is True
        first = manager.current
        assert "198.51.100.9" in first.blocked
        assert fake_server.tokens[-1] == "tkw_secret"

        assert await manager.refresh() is False  # same version: compiled tables kept as-is
        assert manager.current is first

        fake_server.set_policy("v2", blocked=[])
        assert await manager.refresh() is True
        assert "198.51.100.9" not in manager.current.blocked
        assert manager.swaps == 2 and manager.errors == 0


@pytest.mark.parametrize("failure", ["down", "500", "garbage", "missing"])
async def test_policy_manager_keeps_last_policy_on_failure(fake_server: FakeServer, failure: str) -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake_server.handler)) as client:
        manager = PolicyManager(client, "http://tokiwa.test", "tkw", refresh_seconds=5)
        fake_server.set_policy("v1", blocked=["198.51.100.0/24"])
        await manager.refresh()

        if failure == "down":
            fake_server.down = True
        elif failure == "500":
            fake_server.policy_status = 500
        elif failure == "missing":
            fake_server.policy = None  # endpoint answers 404 (e.g. respond module not deployed yet)
        else:
            fake_server.raw_policy = {"version": 1, "blocked": "nope"}

        assert await manager.refresh() is False  # never raises
        assert manager.current.version == "v1"  # fail-static: last known policy stays enforced
        assert "198.51.100.1" in manager.current.blocked
        assert manager.errors == 1 and manager.last_error
        stats = manager.stats()
        assert stats["version"] == "v1" and stats["errors"] == 1
