"""Audit #32: a Gate restarted while the TOKIWA server is unreachable keeps enforcing the last policy it fetched.

Before, the policy lived only in memory: crash / redeploy / host reboot during a server outage started the Gate
with an empty policy, so every blocked or deceived attacker passed until the server came back.
"""

from __future__ import annotations

import os
import stat
import time
from datetime import timedelta
from pathlib import Path

import httpx
from gate_helpers import FakeServer

from tokiwa.gate.netmatch import parse_ip
from tokiwa.gate.policy import PolicyManager
from tokiwa.schemas.response import GatePolicy
from tokiwa.util import utcnow


def _manager(fake_server: FakeServer, cache: Path, **kw: object) -> PolicyManager:
    client = httpx.AsyncClient(transport=httpx.MockTransport(fake_server.handler))
    return PolicyManager(client, "http://tokiwa.test", "tkw_x", cache_file=cache, **kw)  # type: ignore[arg-type]


async def test_restart_during_outage_keeps_blocking(fake_server: FakeServer, tmp_path: Path) -> None:
    cache = tmp_path / "state" / "gate-policy.json"
    fake_server.set_policy("v1", blocked=["198.51.100.7"], deceive=["203.0.113.9"])
    first = _manager(fake_server, cache)
    assert await first.refresh() is True
    assert cache.is_file()
    assert stat.S_IMODE(os.stat(cache).st_mode) == 0o600

    fake_server.policy_status = 503  # server down; the Gate restarts
    restarted = _manager(fake_server, cache)
    assert restarted.load_cache() is True
    await restarted.refresh()  # fails: the saved policy stays in force
    assert restarted.current.blocked.lookup(parse_ip("198.51.100.7")) is not None
    assert restarted.current.deceive.lookup(parse_ip("203.0.113.9")) is not None
    assert restarted.stats()["source"] == "cache"

    fake_server.policy_status = 200
    fake_server.set_policy("v2", blocked=[])
    assert await restarted.refresh() is True
    assert restarted.current.blocked.lookup(parse_ip("198.51.100.7")) is None
    assert restarted.stats()["source"] == "server"


async def test_cached_entries_keep_their_absolute_expiry(fake_server: FakeServer, tmp_path: Path) -> None:
    """Reloading must not give a block its full TTL back, and an entry already past its expiry is dropped."""
    cache = tmp_path / "gate-policy.json"
    generated = utcnow() - timedelta(minutes=50)
    policy = GatePolicy(
        version="v1",
        generated_at=generated,
        blocked=["198.51.100.1", "198.51.100.2"],
        entry_expires_at={
            "blocked": {
                "198.51.100.1": generated + timedelta(minutes=60),  # 10 minutes left
                "198.51.100.2": generated + timedelta(minutes=40),  # already expired
            }
        },
    )
    cache.write_text(policy.model_dump_json())
    now = [1000.0]
    manager = _manager(fake_server, cache, clock=lambda: now[0])
    assert manager.load_cache() is True
    assert manager.current.blocked.lookup(parse_ip("198.51.100.1")) is not None
    assert manager.current.blocked.lookup(parse_ip("198.51.100.2")) is None
    now[0] += 11 * 60  # 11 minutes later: past the absolute expiry (not 60 minutes from reload)
    assert manager.current.blocked.lookup(parse_ip("198.51.100.1")) is None


async def test_too_old_or_broken_cache_is_not_enforced(fake_server: FakeServer, tmp_path: Path) -> None:
    cache = tmp_path / "gate-policy.json"
    old = GatePolicy(version="v1", generated_at=utcnow() - timedelta(hours=200), blocked=["198.51.100.1"])
    cache.write_text(old.model_dump_json())
    stale = time.time() - 200 * 3600
    os.utime(cache, (stale, stale))  # neither changed nor confirmed for 200 h
    assert _manager(fake_server, cache).load_cache() is False  # default limit 168 h
    assert _manager(fake_server, cache, cache_max_age_hours=0).load_cache() is True  # 0 = no limit
    cache.write_text("{not json")
    assert _manager(fake_server, cache).load_cache() is False
    assert _manager(fake_server, tmp_path / "missing.json").load_cache() is False


async def test_unwritable_cache_does_not_break_refresh(fake_server: FakeServer, tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")  # a file where the directory should be: mkdir fails
    fake_server.set_policy("v1", blocked=["198.51.100.7"])
    manager = _manager(fake_server, blocker / "sub" / "gate-policy.json")
    assert await manager.refresh() is True
    assert manager.current.blocked.lookup(parse_ip("198.51.100.7")) is not None


def test_cache_path_defaults_and_opt_out(settings) -> None:  # type: ignore[no-untyped-def]
    from tokiwa.config import GateSettings
    from tokiwa.gate.app import _policy_cache_file

    default = _policy_cache_file(GateSettings(sensor_id="edge/1"))
    assert default == settings.server.data_dir / "gate-policy-edge_1.json"
    assert _policy_cache_file(GateSettings(persist_policy=False)) is None
    assert _policy_cache_file(GateSettings(policy_cache_file=Path("/x/p.json"))) == Path("/x/p.json")


async def test_unchanged_policy_confirmed_recently_still_loads(
    fake_server: FakeServer, tmp_path: Path
) -> None:
    """A policy that has not changed for weeks (e.g. decoys only) but that the server confirmed recently is current."""
    cache = tmp_path / "gate-policy.json"
    policy = fake_server.set_policy("v1", deceive=["203.0.113.9"])
    policy.generated_at = utcnow() - timedelta(days=30)
    manager = _manager(fake_server, cache)
    assert await manager.refresh() is True  # saved
    stale = time.time() - 2 * 3600
    os.utime(cache, (stale, stale))
    assert await manager.refresh() is False  # unchanged: the saved copy is marked as confirmed
    assert time.time() - cache.stat().st_mtime < 60
    fake_server.policy_status = 503
    restarted = _manager(fake_server, cache)
    assert restarted.load_cache() is True
    assert restarted.current.deceive.lookup(parse_ip("203.0.113.9")) is not None
