"""Gate policy: aggregation (CIDR collapse, duplicates, strictest values), version hash, decoys, endpoint."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import pytest

from tokiwa.db.models.response import ResponseActionRow
from tokiwa.db.session import session_scope
from tokiwa.deception import policy as deception_policy
from tokiwa.respond.policy import build_gate_policy
from tokiwa.schemas.response import DecoyRoute
from tokiwa.util import new_id, utcnow


async def _row(action_type: str, target: str, status: str = "active", **kw: Any) -> str:
    now = utcnow()
    rid = new_id()
    async with session_scope() as s:
        s.add(
            ResponseActionRow(
                id=rid,
                created_at=now,
                updated_at=now,
                action_type=action_type,
                target=target,
                params=kw.pop("params", {}),
                reason="",
                proposed_by="user",
                status=status,
                reversible=True,
                ttl_minutes=60,
                expires_at=kw.pop("expires_at", now + timedelta(minutes=60)),
                result={},
                **kw,
            )
        )
    return rid


@pytest.mark.usefixtures("db")
async def test_policy_aggregates_and_collapses() -> None:
    await _row("block_ip", "203.0.113.5")
    await _row("block_ip", "203.0.113.0/24")  # contains the host above
    await _row("block_ip", "203.0.113.5")  # duplicate row (e.g. re-proposed after expiry)
    await _row("block_ip", "198.51.100.0/25")
    await _row("block_ip", "198.51.100.128/25")  # adjacent -> /24
    await _row("block_ip", "2001:db8::1")
    await _row("block_ip", "192.0.2.1")
    await _row("rate_limit", "192.0.2.10", params={"requests_per_minute": 30})
    await _row("rate_limit", "192.0.2.10", params={"requests_per_minute": 10})  # strictest wins
    await _row("rate_limit", "192.0.2.11")  # default rpm
    await _row("tarpit", "192.0.2.20", params={"delay_ms": 500})
    await _row("tarpit", "192.0.2.20", params={"delay_ms": 4000})  # strictest (longest) wins
    await _row("deceive", "192.0.2.30")
    await _row("deceive", "192.0.2.31")
    policy = await build_gate_policy()
    assert policy.blocked == ["192.0.2.1", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::1"]
    assert policy.rate_limited == {"192.0.2.10": 10, "192.0.2.11": 60}
    assert policy.tarpit == {"192.0.2.20": 4000}
    assert policy.deceive == ["192.0.2.30/31"]


@pytest.mark.usefixtures("db")
async def test_policy_only_includes_active_unexpired() -> None:
    for status in ("proposed", "approved", "expired", "reverted", "rejected", "failed"):
        await _row("block_ip", "203.0.113.1", status=status)
    await _row(
        "block_ip", "203.0.113.2", expires_at=utcnow() - timedelta(seconds=1)
    )  # expiry job not run yet
    await _row("notify", "incident-1")  # not a gate action
    await _row("nftables_block", "203.0.113.3")  # host firewall, not the gate
    await _row("block_ip", "203.0.113.4", expires_at=None)
    assert (await build_gate_policy()).blocked == ["203.0.113.4"]


@pytest.mark.usefixtures("db")
async def test_version_is_a_content_hash() -> None:
    empty1 = await build_gate_policy()
    empty2 = await build_gate_policy(now=utcnow() + timedelta(seconds=5))
    assert empty1.version == empty2.version and len(empty1.version) == 64
    assert empty1.generated_at != empty2.generated_at
    rid = await _row("block_ip", "203.0.113.9")
    changed = await build_gate_policy()
    assert changed.version != empty1.version
    async with session_scope() as s:
        row = await s.get(ResponseActionRow, rid)
        assert row is not None
        row.status = "reverted"
    assert (await build_gate_policy()).version == empty1.version


@pytest.mark.usefixtures("db")
async def test_decoys_are_merged_and_failures_tolerated(monkeypatch: pytest.MonkeyPatch) -> None:
    decoy = DecoyRoute(asset_id="a1", kind="decoy_path", path="/.env", body="AWS_KEY=TOKIWA-FAKE")

    async def fake_decoys() -> tuple[list[DecoyRoute], str | None]:
        return [decoy], "<!-- canary -->"

    base = await build_gate_policy()
    monkeypatch.setattr(deception_policy, "build_gate_decoys", fake_decoys)
    with_decoys = await build_gate_policy()
    assert with_decoys.decoys == [decoy]
    assert with_decoys.html_injection == "<!-- canary -->"
    assert with_decoys.version != base.version

    async def broken() -> tuple[list[DecoyRoute], str | None]:
        raise RuntimeError("deception bug")

    monkeypatch.setattr(deception_policy, "build_gate_decoys", broken)
    await _row("block_ip", "203.0.113.9")
    degraded = await build_gate_policy()
    assert degraded.blocked == ["203.0.113.9"] and degraded.decoys == []


async def test_gate_policy_endpoint_auth_and_etag(
    client: httpx.AsyncClient, ingest_headers: dict[str, str], admin_headers: dict[str, str]
) -> None:
    from tokiwa.cli import _create_token

    assert (await client.get("/api/v1/gate/policy")).status_code == 401
    assert (await client.get("/api/v1/gate/policy", headers=admin_headers)).status_code == 401  # JWT != token
    ingest_only = await _create_token("ingest-only", ["ingest"])
    r403 = await client.get("/api/v1/gate/policy", headers={"X-Tokiwa-Token": ingest_only})
    assert r403.status_code == 403

    await _row("block_ip", "203.0.113.9")
    r = await client.get("/api/v1/gate/policy", headers=ingest_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["blocked"] == ["203.0.113.9"]
    assert r.headers["etag"] == f'"{body["version"]}"'
    cached = await client.get(
        "/api/v1/gate/policy", headers={**ingest_headers, "If-None-Match": r.headers["etag"]}
    )
    assert cached.status_code == 304 and cached.content == b""
    stale = await client.get("/api/v1/gate/policy", headers={**ingest_headers, "If-None-Match": '"old"'})
    assert stale.status_code == 200
