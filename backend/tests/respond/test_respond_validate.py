"""Proposal validation: targets, protected networks, TTL caps, allow-listed params."""

from __future__ import annotations

from typing import Any

import pytest

from tokiwa.config import ResponseSettings
from tokiwa.respond import validate
from tokiwa.respond.validate import ActionValidationError, validate_action
from tokiwa.schemas.triage import ActionType


def _s(**kw: Any) -> ResponseSettings:
    return ResponseSettings(**kw)


def _v(
    action_type: ActionType | str,
    target: str,
    params: dict[str, Any] | None = None,
    ttl: int | None = None,
    **kw: Any,
):  # type: ignore[no-untyped-def]
    return validate_action(action_type, target, params, ttl, settings=_s(**kw))


# ---------------------------------------------------------------- network targets


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("203.0.113.9", "203.0.113.9"),
        (" 203.0.113.9 ", "203.0.113.9"),
        ("203.0.113.9/32", "203.0.113.9"),
        ("203.0.113.77/24", "203.0.113.0/24"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:DB8:0:0::/64", "2001:db8::/64"),
        ("::ffff:203.0.113.9", "203.0.113.9"),
    ],
)
def test_network_targets_are_normalized(raw: str, normalized: str) -> None:
    assert _v(ActionType.BLOCK_IP, raw).target == normalized


@pytest.mark.parametrize(
    "target",
    [
        "evil.example.com",
        "203.0.113.9; rm -rf /",
        "$(reboot)",
        "",
        "203.0.113.9 203.0.113.10",
        "fe80::1%eth0",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "255.255.255.255",
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/8",  # broader than min_prefix_v4=16
        "2001:db8::/32",  # broader than min_prefix_v6=48
        "127.0.0.1",  # protected by default
        "127.0.0.0/16",
        "::1",
    ],
)
def test_invalid_or_dangerous_network_targets_rejected(target: str) -> None:
    with pytest.raises(ActionValidationError):
        _v(ActionType.BLOCK_IP, target)


def test_protected_cidr_overlap_in_both_directions() -> None:
    kw = {"protected_cidrs": ["10.10.0.0/16"], "min_prefix_v4": 8}
    with pytest.raises(ActionValidationError, match="protected"):
        _v(ActionType.BLOCK_IP, "10.10.5.5", **kw)  # inside protected
    with pytest.raises(ActionValidationError, match="protected"):
        _v(ActionType.TARPIT, "10.0.0.0/8", **kw)  # contains protected
    assert _v(ActionType.BLOCK_IP, "10.11.0.1", **kw).target == "10.11.0.1"


def test_server_own_addresses_are_protected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validate, "_server_addresses", lambda: ("198.51.100.77", "fe80::1"))
    with pytest.raises(ActionValidationError, match="protected"):
        _v(ActionType.DECEIVE, "198.51.100.77")
    assert _v(ActionType.DECEIVE, "198.51.100.77", protect_server_addresses=False).target == "198.51.100.77"


def test_private_targets_toggle() -> None:
    assert _v(ActionType.BLOCK_IP, "192.168.1.5").target == "192.168.1.5"  # lab default: allowed
    with pytest.raises(ActionValidationError, match="private"):
        _v(ActionType.BLOCK_IP, "192.168.1.5", block_private_targets=True)
    with pytest.raises(ActionValidationError, match="private"):
        _v(ActionType.RATE_LIMIT, "fd00::/64", block_private_targets=True)


def test_nftables_accepts_single_ip_only() -> None:
    assert _v(ActionType.NFTABLES_BLOCK, "203.0.113.9").target == "203.0.113.9"
    with pytest.raises(ActionValidationError, match="single IP"):
        _v(ActionType.NFTABLES_BLOCK, "203.0.113.0/24")


# ---------------------------------------------------------------- other target kinds


def test_deploy_canary_target_is_a_safe_path() -> None:
    assert _v(ActionType.DEPLOY_CANARY, "/backup-2026.zip").target == "/backup-2026.zip"
    for bad in ["backup.zip", "/../etc/passwd", "//x", "/a b", "/x?y=1", "http://x/"]:
        with pytest.raises(ActionValidationError):
            _v(ActionType.DEPLOY_CANARY, bad)


def test_notify_and_webhook_targets() -> None:
    assert _v(ActionType.NOTIFY, "incident-123").target == "incident-123"
    assert _v(ActionType.NOTIFY, "127.0.0.1").target == "127.0.0.1"  # only mentioned, not blocked
    with pytest.raises(ActionValidationError):
        _v(ActionType.NOTIFY, "hello world; curl x")
    hooks = {"webhook_urls": {"default": "https://soar.example.com/hook"}}
    assert _v(ActionType.WEBHOOK, "203.0.113.0/24", **hooks).target == "203.0.113.0/24"
    with pytest.raises(ActionValidationError, match="protected"):
        _v(ActionType.WEBHOOK, "127.0.0.1", **hooks)  # handed to a firewall -> lockout guard applies


def test_unknown_action_type_and_bad_reference_ids() -> None:
    with pytest.raises(ActionValidationError, match="unknown action type"):
        _v("shell_exec", "203.0.113.9")
    with pytest.raises(ActionValidationError, match="incident_id"):
        validate_action(ActionType.BLOCK_IP, "203.0.113.9", incident_id="../../x", settings=_s())


# ---------------------------------------------------------------- TTL


def test_ttl_default_cap_and_one_shot() -> None:
    assert _v(ActionType.BLOCK_IP, "203.0.113.9").ttl_minutes == 60
    capped = _v(ActionType.BLOCK_IP, "203.0.113.9", ttl=99_999, max_ttl_minutes=120)
    assert capped.ttl_minutes == 120
    assert any("capped" in n for n in capped.notes)
    with pytest.raises(ActionValidationError, match="ttl"):
        _v(ActionType.BLOCK_IP, "203.0.113.9", ttl=0)
    one_shot = _v(ActionType.NOTIFY, "x", ttl=30)
    assert one_shot.ttl_minutes is None and not one_shot.reversible
    assert _v(ActionType.DEPLOY_CANARY, "/x").ttl_minutes == 60


# ---------------------------------------------------------------- params


def test_params_allow_list_and_types() -> None:
    assert dict(_v(ActionType.RATE_LIMIT, "203.0.113.9").params) == {"requests_per_minute": 60}
    assert dict(_v(ActionType.RATE_LIMIT, "203.0.113.9", {"requests_per_minute": 5}).params) == {
        "requests_per_minute": 5
    }
    assert dict(_v(ActionType.TARPIT, "203.0.113.9").params) == {"delay_ms": 2000}
    assert dict(_v(ActionType.BLOCK_IP, "203.0.113.9").params) == {}
    bad: list[tuple[ActionType, dict[str, Any]]] = [
        (ActionType.BLOCK_IP, {"command": "iptables -F"}),
        (ActionType.RATE_LIMIT, {"requests_per_minute": "10"}),
        (ActionType.RATE_LIMIT, {"requests_per_minute": True}),
        (ActionType.RATE_LIMIT, {"requests_per_minute": 0}),
        (ActionType.TARPIT, {"delay_ms": 60_000}),
        (ActionType.DEPLOY_CANARY, {"kind": "beacon"}),
        (ActionType.NOTIFY, {"channel_id": "../../x"}),
        (ActionType.NFTABLES_BLOCK, {"table": "filter"}),
    ]
    for atype, params in bad:
        target = (
            "/x"
            if atype is ActionType.DEPLOY_CANARY
            else ("x" if atype is ActionType.NOTIFY else "203.0.113.9")
        )
        with pytest.raises(ActionValidationError):
            _v(atype, target, params)


def test_webhook_endpoint_must_be_configured_by_name() -> None:
    with pytest.raises(ActionValidationError, match="not configured"):
        _v(ActionType.WEBHOOK, "203.0.113.9")
    with pytest.raises(ActionValidationError):
        _v(
            ActionType.WEBHOOK,
            "203.0.113.9",
            {"endpoint": "http://169.254.169.254/"},
            webhook_urls={"default": "https://soar.example.com/hook"},
        )
    ok = _v(
        ActionType.WEBHOOK, "203.0.113.9", {"endpoint": "soar"}, webhook_urls={"soar": "https://s.example/h"}
    )
    assert dict(ok.params) == {"endpoint": "soar"}
