"""Executors: one per :class:`ActionType`, behind the ``Executor.apply / revert`` interface.

Executors only ever receive an :class:`ExecutionRequest` built from a :class:`ValidatedAction` - a normalized
IP/CIDR or safe identifier, allow-listed typed params and a TTL. They never receive the proposal's free-text
``reason`` (which may come from an LLM), never build shell strings, and are only invoked by
:func:`tokiwa.respond.service._execute` after a recorded approval.

- block_ip / rate_limit / tarpit / deceive: DB state only; the Gate pulls it via ``/api/v1/gate/policy``.
- deploy_canary: asks ``tokiwa.deception.service`` to create a decoy asset (fails if unavailable).
- notify: pages humans through ``tokiwa.notify.service``.
- webhook: POSTs a fixed JSON document to a *named* endpoint from ``response.webhook_urls`` (SSRF-guarded).
- nftables_block: disabled unless ``response.nftables_enabled``; runs a fixed argv template with
  ``asyncio.create_subprocess_exec`` (no shell).
"""

from __future__ import annotations

import asyncio
import importlib
import ipaddress
import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from tokiwa.config import get_settings
from tokiwa.schemas.triage import ActionType

log = logging.getLogger(__name__)


class ExecutorError(Exception):
    """Execution failed. The message is stored in ``result.error`` and shown to users (keep it safe)."""


@dataclass(frozen=True)
class ExecutionRequest:
    action_id: str
    action_type: ActionType
    target: str
    params: Mapping[str, str | int] = field(default_factory=dict)
    ttl_seconds: int | None = None
    incident_id: str | None = None
    alert_id: str | None = None
    # Output of a previous apply() (e.g. the canary asset id), used by revert().
    state: Mapping[str, Any] = field(default_factory=dict)


class Executor(ABC):
    action_types: ClassVar[frozenset[ActionType]]

    @abstractmethod
    async def apply(self, req: ExecutionRequest) -> dict[str, Any]:
        """Put the action into effect. Returns a JSON-safe result merged into ``ResponseAction.result``."""

    @abstractmethod
    async def revert(self, req: ExecutionRequest) -> dict[str, Any]:
        """Undo the action (idempotent)."""


class GatePolicyExecutor(Executor):
    """The action's ``active`` row *is* the enforcement: the Gate polls the aggregated policy."""

    action_types = frozenset(
        {ActionType.BLOCK_IP, ActionType.RATE_LIMIT, ActionType.TARPIT, ActionType.DECEIVE}
    )

    async def apply(self, req: ExecutionRequest) -> dict[str, Any]:
        return {"enforced_by": "gate_policy"}

    async def revert(self, req: ExecutionRequest) -> dict[str, Any]:
        return {"enforced_by": "gate_policy", "removed": True}


class DeployCanaryExecutor(Executor):
    action_types = frozenset({ActionType.DEPLOY_CANARY})

    @staticmethod
    def _service() -> Any:
        try:
            return importlib.import_module("tokiwa.deception.service")
        except ImportError as exc:
            raise ExecutorError("deception service is not available") from exc

    async def apply(self, req: ExecutionRequest) -> dict[str, Any]:
        from tokiwa.schemas.response import DeceptionAssetIn, DeceptionKind

        svc = self._service()
        create = getattr(svc, "create_asset", None)
        if create is None:
            raise ExecutorError("deception service does not provide create_asset()")
        asset_in = DeceptionAssetIn(
            kind=DeceptionKind(str(req.params.get("kind", "decoy_path"))),
            name=f"canary {req.target}"[:255],
            path=req.target,
            description=f"deployed by response action {req.action_id}",
        )
        asset = await create(asset_in)
        asset_id = asset.get("id") if isinstance(asset, Mapping) else getattr(asset, "id", None)
        if not asset_id:
            raise ExecutorError("deception service returned no asset id")
        return {"asset_id": str(asset_id)}

    async def revert(self, req: ExecutionRequest) -> dict[str, Any]:
        asset_id = req.state.get("asset_id")
        if not asset_id:
            return {"removed": False, "note": "no asset id recorded"}
        svc = self._service()
        remove = getattr(svc, "delete_asset", None) or getattr(svc, "disable_asset", None)
        if remove is None:
            raise ExecutorError("deception service does not provide delete_asset()/disable_asset()")
        await remove(str(asset_id))
        return {"removed": True, "asset_id": str(asset_id)}


class NotifyExecutor(Executor):
    action_types = frozenset({ActionType.NOTIFY})

    async def apply(self, req: ExecutionRequest) -> dict[str, Any]:
        from tokiwa.notify.outbound import DeliveryError
        from tokiwa.notify.service import send_action_notice

        channel = req.params.get("channel_id")
        try:
            results = await send_action_notice(
                action_id=req.action_id,
                target=req.target,
                incident_id=req.incident_id,
                alert_id=req.alert_id,
                channel_id=str(channel) if channel else None,
            )
        except DeliveryError as exc:
            raise ExecutorError(f"notification failed: {exc}") from None
        return {"deliveries": [r.model_dump() for r in results]}

    async def revert(self, req: ExecutionRequest) -> dict[str, Any]:
        return {"note": "notifications cannot be reverted"}


class WebhookExecutor(Executor):
    action_types = frozenset({ActionType.WEBHOOK})

    async def apply(self, req: ExecutionRequest) -> dict[str, Any]:
        from tokiwa.notify.outbound import DeliveryError, OutboundBlocked, post_json

        settings = get_settings().response
        endpoint = str(req.params.get("endpoint", "default"))
        url = settings.webhook_urls.get(endpoint)
        if not url:
            raise ExecutorError(f"webhook endpoint {endpoint!r} is not configured")
        payload = {
            "source": "tokiwa",
            "event": "response_action",
            "action_id": req.action_id,
            "action_type": req.action_type.value,
            "target": req.target,
            "ttl_seconds": req.ttl_seconds,
            "incident_id": req.incident_id,
            "alert_id": req.alert_id,
        }
        try:
            status = await post_json(
                url,
                payload,
                allowed_hosts=settings.webhook_allowed_hosts,
                block_private=settings.webhook_block_private,
                timeout=settings.webhook_timeout_seconds,
            )
        except (OutboundBlocked, DeliveryError) as exc:
            raise ExecutorError(f"webhook {endpoint!r} failed: {exc}") from None
        return {"endpoint": endpoint, "status_code": status}

    async def revert(self, req: ExecutionRequest) -> dict[str, Any]:
        return {"note": "webhook hand-offs cannot be reverted from TOKIWA"}


# ---------------------------------------------------------------- nftables (fixed template)

NFT_FAMILY = "inet"
NFT_TABLE = "tokiwa"
NFT_SET_V4 = "blocklist"
NFT_SET_V6 = "blocklist6"


def _nft_set_and_addr(ip: str) -> tuple[str, str]:
    addr = ipaddress.ip_address(ip)  # raises ValueError for anything that is not a bare IP
    return (NFT_SET_V4 if addr.version == 4 else NFT_SET_V6), str(addr)


def build_nft_add_argv(binary: str, ip: str, ttl_seconds: int) -> list[str]:
    """``nft add element inet tokiwa blocklist { <ip> timeout <ttl>s }`` as an argv list."""
    set_name, addr = _nft_set_and_addr(ip)
    ttl = int(ttl_seconds)
    if ttl < 1:
        raise ValueError("ttl must be positive")
    return [binary, "add", "element", NFT_FAMILY, NFT_TABLE, set_name, "{", addr, "timeout", f"{ttl}s", "}"]


def build_nft_delete_argv(binary: str, ip: str) -> list[str]:
    """``nft delete element inet tokiwa blocklist { <ip> }`` as an argv list."""
    set_name, addr = _nft_set_and_addr(ip)
    return [binary, "delete", "element", NFT_FAMILY, NFT_TABLE, set_name, "{", addr, "}"]


async def run_argv(argv: Sequence[str], timeout: float = 15.0) -> tuple[int, str]:
    """Run a fixed argv without a shell. Tests replace this function (no subprocess in tests)."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise ExecutorError("nft timed out") from None
    text = (err or out or b"").decode(errors="replace").strip()
    return int(proc.returncode or 0), text[:500]


class NftablesExecutor(Executor):
    action_types = frozenset({ActionType.NFTABLES_BLOCK})

    async def apply(self, req: ExecutionRequest) -> dict[str, Any]:
        settings = get_settings().response
        if not settings.nftables_enabled:
            raise ExecutorError("nftables executor is disabled (response.nftables_enabled=false)")
        if not req.ttl_seconds:
            raise ExecutorError("nftables_block requires a TTL")
        try:
            argv = build_nft_add_argv(settings.nftables_binary, req.target, req.ttl_seconds)
        except ValueError as exc:
            raise ExecutorError(f"invalid nftables target: {exc}") from None
        try:
            code, output = await run_argv(argv)
        except OSError as exc:
            raise ExecutorError(f"cannot run nft: {type(exc).__name__}") from None
        if code != 0:
            raise ExecutorError(f"nft exited with {code}: {output}")
        return {"nft_set": argv[5], "nft_timeout_seconds": req.ttl_seconds}

    async def revert(self, req: ExecutionRequest) -> dict[str, Any]:
        settings = get_settings().response
        if not settings.nftables_enabled:
            # Never run nft while disabled; the element still disappears via its kernel-side timeout.
            return {"skipped": "nftables disabled; element expires via its nft timeout"}
        try:
            argv = build_nft_delete_argv(settings.nftables_binary, req.target)
        except ValueError as exc:
            raise ExecutorError(f"invalid nftables target: {exc}") from None
        try:
            code, output = await run_argv(argv)
        except OSError as exc:
            raise ExecutorError(f"cannot run nft: {type(exc).__name__}") from None
        if code != 0:
            raise ExecutorError(f"nft exited with {code}: {output}")
        return {"removed": True}


_EXECUTORS: dict[ActionType, Executor] = {}
for _cls in (GatePolicyExecutor, DeployCanaryExecutor, NotifyExecutor, WebhookExecutor, NftablesExecutor):
    _instance = _cls()
    for _t in _cls.action_types:
        _EXECUTORS[_t] = _instance

if set(_EXECUTORS) != set(ActionType):  # pragma: no cover - guards future ActionType additions
    raise RuntimeError("every ActionType needs an executor")


def get_executor(action_type: ActionType) -> Executor:
    return _EXECUTORS[action_type]
