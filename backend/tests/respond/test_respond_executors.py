"""Executors: nftables fixed argv (mocked subprocess), webhook (mocked HTTP, SSRF), deploy_canary, notify."""

from __future__ import annotations

import asyncio
import json
import sys
import types
from collections.abc import Sequence
from typing import Any

import httpx
import pytest
import respx

from tokiwa.db.models.response import NotificationChannelRow
from tokiwa.db.session import session_scope
from tokiwa.respond import executors
from tokiwa.respond.executors import (
    ExecutionRequest,
    ExecutorError,
    build_nft_add_argv,
    build_nft_delete_argv,
    get_executor,
)
from tokiwa.respond.service import approve_action, propose_action, revert_action
from tokiwa.schemas.response import ActionProposal, ActionStatus
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow


def _req(t: ActionType, target: str, **kw: Any) -> ExecutionRequest:
    return ExecutionRequest(action_id=new_id(), action_type=t, target=target, **kw)


class _RunRecorder:
    def __init__(self, code: int = 0, output: str = "") -> None:
        self.calls: list[list[str]] = []
        self.code, self.output = code, output

    async def __call__(self, argv: Sequence[str], timeout: float = 15.0) -> tuple[int, str]:
        self.calls.append(list(argv))
        return self.code, self.output


# ---------------------------------------------------------------- nftables


def test_nft_argv_is_a_fixed_template() -> None:
    assert build_nft_add_argv("nft", "203.0.113.9", 3600) == [
        "nft", "add", "element", "inet", "tokiwa", "blocklist", "{", "203.0.113.9", "timeout", "3600s", "}",
    ]  # fmt: skip
    assert build_nft_add_argv("/usr/sbin/nft", "2001:db8::1", 60)[5] == "blocklist6"
    assert build_nft_delete_argv("nft", "203.0.113.9") == [
        "nft", "delete", "element", "inet", "tokiwa", "blocklist", "{", "203.0.113.9", "}",
    ]  # fmt: skip
    for bad in ["203.0.113.9; reboot", "203.0.113.0/24", "$(id)", "1.2.3.4 } ; flush ruleset {"]:
        with pytest.raises(ValueError):
            build_nft_add_argv("nft", bad, 60)


async def test_nft_disabled_always_fails(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    run = _RunRecorder()
    monkeypatch.setattr(executors, "run_argv", run)
    ex = get_executor(ActionType.NFTABLES_BLOCK)
    with pytest.raises(ExecutorError, match="disabled"):
        await ex.apply(_req(ActionType.NFTABLES_BLOCK, "203.0.113.9", ttl_seconds=60))
    result = await ex.revert(_req(ActionType.NFTABLES_BLOCK, "203.0.113.9"))
    assert "skipped" in result
    assert run.calls == []


async def test_nft_enabled_runs_argv_and_reports_errors(configure, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    configure(nftables_enabled=True)
    run = _RunRecorder()
    monkeypatch.setattr(executors, "run_argv", run)
    ex = get_executor(ActionType.NFTABLES_BLOCK)
    out = await ex.apply(_req(ActionType.NFTABLES_BLOCK, "203.0.113.9", ttl_seconds=600))
    assert out == {"nft_set": "blocklist", "nft_timeout_seconds": 600}
    assert run.calls[-1][-4:] == ["203.0.113.9", "timeout", "600s", "}"]
    with pytest.raises(ExecutorError, match="requires a TTL"):
        await ex.apply(_req(ActionType.NFTABLES_BLOCK, "203.0.113.9"))
    run.code, run.output = 1, "Error: No such file or directory"
    with pytest.raises(ExecutorError, match="exited with 1"):
        await ex.apply(_req(ActionType.NFTABLES_BLOCK, "203.0.113.9", ttl_seconds=60))


async def test_run_argv_uses_exec_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"", b""

    async def fake_exec(*args: str, **kwargs: Any) -> FakeProc:
        seen["args"], seen["kwargs"] = args, kwargs
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    argv = build_nft_add_argv("nft", "203.0.113.9", 60)
    assert await executors.run_argv(argv) == (0, "")
    assert list(seen["args"]) == argv
    assert "shell" not in seen["kwargs"]


@pytest.mark.usefixtures("db")
async def test_nft_end_to_end_through_approval(configure, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    configure(nftables_enabled=True, nftables_binary="/usr/sbin/nft")
    run = _RunRecorder()
    monkeypatch.setattr(executors, "run_argv", run)
    a = await propose_action(
        ActionProposal(
            action_type=ActionType.NFTABLES_BLOCK, target="203.0.113.50", reason="x", ttl_minutes=10
        )
    )
    assert a is not None and run.calls == []  # proposing never touches the firewall
    active = await approve_action(a.id, actor="alice")
    assert active.status is ActionStatus.ACTIVE
    assert run.calls == [build_nft_add_argv("/usr/sbin/nft", "203.0.113.50", 600)]
    await revert_action(a.id, actor="alice")
    assert run.calls[-1] == build_nft_delete_argv("/usr/sbin/nft", "203.0.113.50")


@pytest.mark.usefixtures("db")
async def test_nft_disabled_end_to_end_fails(monkeypatch: pytest.MonkeyPatch, settings) -> None:  # type: ignore[no-untyped-def]
    run = _RunRecorder()
    monkeypatch.setattr(executors, "run_argv", run)
    a = await propose_action(
        ActionProposal(action_type=ActionType.NFTABLES_BLOCK, target="203.0.113.51", reason="x")
    )
    assert a is not None
    done = await approve_action(a.id, actor="alice")
    assert done.status is ActionStatus.FAILED and "disabled" in done.result["error"]
    assert run.calls == []


# ---------------------------------------------------------------- gate-backed


async def test_gate_executors_are_db_only_and_idempotent(settings) -> None:  # type: ignore[no-untyped-def]
    for t in (ActionType.BLOCK_IP, ActionType.RATE_LIMIT, ActionType.TARPIT, ActionType.DECEIVE):
        ex = get_executor(t)
        req = _req(t, "203.0.113.9", ttl_seconds=60)
        assert await ex.apply(req) == await ex.apply(req) == {"enforced_by": "gate_policy"}
        assert (await ex.revert(req))["removed"] is True


# ---------------------------------------------------------------- webhook


async def test_webhook_posts_fixed_payload_to_named_endpoint(configure) -> None:  # type: ignore[no-untyped-def]
    configure(webhook_urls={"soar": "https://soar.example.com/hooks/SECRET"})
    ex = get_executor(ActionType.WEBHOOK)
    with respx.mock() as mock:
        route = mock.post("https://soar.example.com/hooks/SECRET").mock(return_value=httpx.Response(202))
        out = await ex.apply(
            _req(ActionType.WEBHOOK, "203.0.113.9", params={"endpoint": "soar"}, incident_id="inc1")
        )
    assert out == {"endpoint": "soar", "status_code": 202}
    body = json.loads(route.calls.last.request.content)
    assert body["target"] == "203.0.113.9" and body["incident_id"] == "inc1"
    assert "reason" not in body  # never forwards free text (possibly LLM-generated)


async def test_webhook_ssrf_guard(configure) -> None:  # type: ignore[no-untyped-def]
    configure(
        webhook_urls={
            "meta": "http://169.254.169.254/latest",
            "internal": "https://internal.example.com/hook",
            "other": "https://other.example.com/hook",
        },
        webhook_allowed_hosts=["internal.example.com", "169.254.169.254"],
    )
    ex = get_executor(ActionType.WEBHOOK)
    for name in ("meta", "internal"):  # allow-listed but private -> still refused
        with pytest.raises(ExecutorError, match="non-public"):
            await ex.apply(_req(ActionType.WEBHOOK, "203.0.113.9", params={"endpoint": name}))
    with pytest.raises(ExecutorError, match="allowed host"):
        await ex.apply(_req(ActionType.WEBHOOK, "203.0.113.9", params={"endpoint": "other"}))
    with pytest.raises(ExecutorError, match="not configured"):
        await ex.apply(_req(ActionType.WEBHOOK, "203.0.113.9", params={"endpoint": "missing"}))


async def test_webhook_private_allowed_when_toggled_off(configure) -> None:  # type: ignore[no-untyped-def]
    configure(webhook_urls={"default": "http://10.0.0.7:9000/hook"}, webhook_block_private=False)
    with respx.mock() as mock:
        mock.post("http://10.0.0.7:9000/hook").mock(return_value=httpx.Response(200))
        out = await get_executor(ActionType.WEBHOOK).apply(_req(ActionType.WEBHOOK, "203.0.113.9"))
    assert out["status_code"] == 200


# ---------------------------------------------------------------- deploy_canary


async def test_deploy_canary_fails_without_deception_service(
    settings, monkeypatch: pytest.MonkeyPatch
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setitem(sys.modules, "tokiwa.deception.service", None)  # import -> ImportError
    with pytest.raises(ExecutorError, match="not available"):
        await get_executor(ActionType.DEPLOY_CANARY).apply(
            _req(ActionType.DEPLOY_CANARY, "/canary.zip", params={"kind": "decoy_path"})
        )


async def test_deploy_canary_uses_deception_service(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    created: list[Any] = []
    deleted: list[str] = []
    fake = types.ModuleType("tokiwa.deception.service")

    async def create_asset(asset_in: Any) -> Any:
        created.append(asset_in)
        return types.SimpleNamespace(id="asset-1")

    async def delete_asset(asset_id: str) -> None:
        deleted.append(asset_id)

    fake.create_asset = create_asset  # type: ignore[attr-defined]
    fake.delete_asset = delete_asset  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "tokiwa.deception.service", fake)
    ex = get_executor(ActionType.DEPLOY_CANARY)
    out = await ex.apply(_req(ActionType.DEPLOY_CANARY, "/canary.zip", params={"kind": "honeytoken"}))
    assert out == {"asset_id": "asset-1"}
    assert created[0].path == "/canary.zip" and created[0].kind.value == "honeytoken"
    await ex.revert(_req(ActionType.DEPLOY_CANARY, "/canary.zip", state={"asset_id": "asset-1"}))
    assert deleted == ["asset-1"]


# ---------------------------------------------------------------- notify


@pytest.mark.usefixtures("db")
async def test_notify_executor_sends_validated_fields_only() -> None:
    async with session_scope() as s:
        s.add(
            NotificationChannelRow(
                id=new_id(),
                kind="webhook",
                name="soc",
                config={"url": "https://hooks.example.com/x"},
                min_severity="critical",
                enabled=True,
                created_at=utcnow(),
            )
        )
    with respx.mock() as mock:
        route = mock.post("https://hooks.example.com/x").mock(return_value=httpx.Response(200))
        out = await get_executor(ActionType.NOTIFY).apply(_req(ActionType.NOTIFY, "203.0.113.9"))
    assert out["deliveries"][0]["ok"] is True
    body = json.loads(route.calls.last.request.content)
    assert body["data"]["target"] == "203.0.113.9"


@pytest.mark.usefixtures("db")
async def test_notify_executor_without_channels_fails() -> None:
    with pytest.raises(ExecutorError, match="notification failed"):
        await get_executor(ActionType.NOTIFY).apply(_req(ActionType.NOTIFY, "incident-1"))
