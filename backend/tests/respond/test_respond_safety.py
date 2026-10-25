"""FR-12 acceptance: no executor runs without approval unless auto-approve is explicitly enabled for that type.

Two kinds of proof:
1. Behavioural: every action type, under every non-qualifying policy combination, stays ``proposed`` and no
   executor is called - through propose, the bus, the expiry job and the gate policy.
2. Structural (AST): ``Executor.apply`` has exactly one call site (``_execute``), ``_execute`` is only called
   by ``approve_action``, and ``approve_action`` is only called by the analyst-only API route and by
   ``create_proposal`` inside an ``if auto_approve_allowed(...)`` guard.
"""

from __future__ import annotations

import ast
import asyncio
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

import tokiwa
from tokiwa.bus import bus
from tokiwa.respond import service
from tokiwa.respond.policy import auto_approve_allowed, build_gate_policy
from tokiwa.respond.service import ActionStateError, approve_action, expire_due_actions, propose_action
from tokiwa.schemas.response import ActionProposal, ActionProposer, ActionStatus
from tokiwa.schemas.triage import ActionType
from tokiwa.util import utcnow

SRC = Path(tokiwa.__file__).resolve().parent

TARGETS = {
    ActionType.BLOCK_IP: "203.0.113.1",
    ActionType.RATE_LIMIT: "203.0.113.2",
    ActionType.TARPIT: "203.0.113.3",
    ActionType.DECEIVE: "203.0.113.4",
    ActionType.DEPLOY_CANARY: "/canary.txt",
    ActionType.NOTIFY: "incident-1",
    ActionType.WEBHOOK: "203.0.113.5",
    ActionType.NFTABLES_BLOCK: "203.0.113.6",
}


def _proposal(t: ActionType, by: ActionProposer = ActionProposer.LLM) -> ActionProposal:
    return ActionProposal(action_type=t, target=TARGETS[t], reason="LLM says block it", proposed_by=by)


# ---------------------------------------------------------------- behavioural


@pytest.mark.usefixtures("db")
@pytest.mark.parametrize(
    "policy",
    [
        {},  # defaults: auto-approve off
        {"auto_approve_enabled": False, "auto_approve_actions": [t.value for t in ActionType]},
        {"auto_approve_enabled": True, "auto_approve_actions": []},
    ],
    ids=["defaults", "listed-but-disabled", "enabled-but-empty"],
)
async def test_nothing_executes_without_approval(spy, configure, policy) -> None:  # type: ignore[no-untyped-def]
    configure(webhook_urls={"default": "https://soar.example.com/hook"}, **policy)
    for t in ActionType:
        for by in ActionProposer:
            action = await propose_action(_proposal(t, by))
            assert action is not None, t
            assert action.status is ActionStatus.PROPOSED
            assert action.approved_by is None
    await bus.drain()
    assert await expire_due_actions(now=utcnow() + timedelta(days=30)) == 0
    policy_doc = await build_gate_policy()
    assert policy_doc.blocked == [] and policy_doc.rate_limited == {} and policy_doc.tarpit == {}
    assert policy_doc.deceive == []
    assert spy.applied == [] and spy.reverted == []


@pytest.mark.usefixtures("db")
async def test_auto_approve_only_for_listed_type(spy, configure) -> None:  # type: ignore[no-untyped-def]
    configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"])
    rl = await propose_action(_proposal(ActionType.RATE_LIMIT))
    assert rl is not None and rl.status is ActionStatus.PROPOSED
    assert spy.applied == []
    blk = await propose_action(_proposal(ActionType.BLOCK_IP))
    assert blk is not None
    assert blk.status is ActionStatus.ACTIVE
    assert blk.approved_by == "policy"
    assert [r.action_type for r in spy.applied] == [ActionType.BLOCK_IP]
    assert (await build_gate_policy()).blocked == ["203.0.113.1"]


def test_auto_approve_truth_table(settings) -> None:  # type: ignore[no-untyped-def]
    base = settings.response
    for enabled in (False, True):
        for listed in ([], ["block_ip"], ["rate_limit"], [" block_ip "]):
            s = base.model_copy(update={"auto_approve_enabled": enabled, "auto_approve_actions": listed})
            expected = enabled and "block_ip" in [x.strip() for x in listed]
            assert auto_approve_allowed(ActionType.BLOCK_IP, s) is expected


@pytest.mark.usefixtures("db")
async def test_execute_refuses_unapproved_rows(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_proposal(ActionType.BLOCK_IP))
    assert a is not None
    with pytest.raises(ActionStateError, match="not been approved"):
        await service._execute(a.id)
    await service.reject_action(a.id, actor="bob")
    with pytest.raises(ActionStateError):
        await service._execute(a.id)
    assert spy.applied == []


@pytest.mark.usefixtures("db")
async def test_concurrent_approvals_execute_once(spy) -> None:  # type: ignore[no-untyped-def]
    a = await propose_action(_proposal(ActionType.BLOCK_IP))
    assert a is not None
    results = await asyncio.gather(
        *(approve_action(a.id, actor=f"user{i}") for i in range(5)), return_exceptions=True
    )
    ok = [r for r in results if not isinstance(r, BaseException)]
    errors = [r for r in results if isinstance(r, BaseException)]
    assert len(ok) == 1 and all(isinstance(e, ActionStateError) for e in errors)
    assert len(spy.applied) == 1


async def test_api_requires_human_analyst(client: httpx.AsyncClient, make_user, ingest_headers, spy) -> None:  # type: ignore[no-untyped-def]
    analyst = await make_user("analyst")
    viewer = await make_user("viewer")
    r = await client.post(
        "/api/v1/response/actions",
        json={"action_type": "block_ip", "target": "203.0.113.9", "reason": "x", "proposed_by": "policy"},
        headers=analyst,
    )
    assert r.status_code == 200, r.text
    action = r.json()
    assert action["status"] == "proposed" and action["proposed_by"] == "user"  # cannot spoof "policy"
    url = f"/api/v1/response/actions/{action['id']}/approve"
    assert (await client.post(url)).status_code == 401
    assert (await client.post(url, headers=ingest_headers)).status_code == 401  # sensor tokens cannot approve
    assert (await client.post(url, headers=viewer)).status_code == 403
    assert spy.applied == []
    ok = await client.post(url, headers=analyst)
    assert ok.status_code == 200 and ok.json()["status"] == "active"
    assert len(spy.applied) == 1


# ---------------------------------------------------------------- structural (AST)


class _CallIndex(ast.NodeVisitor):
    """Collect (module, enclosing function, call node, enclosing if-tests) for every call."""

    def __init__(self, module: str) -> None:
        self.module = module
        self.funcs: list[str] = []
        self.ifs: list[ast.expr] = []
        self.calls: list[tuple[str, str, ast.Call, list[ast.expr]]] = []

    def _func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.funcs.append(node.name)
        self.generic_visit(node)
        self.funcs.pop()

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        self.ifs.append(node.test)
        for child in node.body:
            self.visit(child)
        self.ifs.pop()
        for child in node.orelse:
            self.visit(child)

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((self.module, self.funcs[-1] if self.funcs else "<module>", node, list(self.ifs)))
        self.generic_visit(node)


def _index() -> list[tuple[str, str, ast.Call, list[ast.expr]]]:
    calls: list[tuple[str, str, ast.Call, list[ast.expr]]] = []
    for path in SRC.rglob("*.py"):
        module = str(path.relative_to(SRC.parent).with_suffix("")).replace("/", ".")
        idx = _CallIndex(module)
        idx.visit(ast.parse(path.read_text(encoding="utf-8")))
        calls.extend(idx.calls)
    return calls


def _name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _mentions(node: ast.AST, name: str) -> bool:
    return any(
        (isinstance(n, ast.Name) and n.id == name) or (isinstance(n, ast.Attribute) and n.attr == name)
        for n in ast.walk(node)
    )


def test_executor_apply_has_a_single_call_site() -> None:
    sites = [
        (mod, fn)
        for mod, fn, call, _ in _index()
        if _name(call) == "apply"
        and isinstance(call.func, ast.Attribute)
        and (_mentions(call.func.value, "get_executor") or _mentions(call.func.value, "_EXECUTORS"))
    ]
    assert sites == [("tokiwa.respond.service", "_execute")]
    # Nobody outside the respond service reaches into the executor registry.
    users = {mod for mod, _, call, _ in _index() if _name(call) == "get_executor"}
    assert users == {"tokiwa.respond.service"}


def test_execute_is_only_reached_through_approval() -> None:
    callers = {(mod, fn) for mod, fn, call, _ in _index() if _name(call) == "_execute"}
    assert callers == {("tokiwa.respond.service", "approve_action")}


def test_approve_action_callers_are_human_route_or_policy_guard() -> None:
    callers = [(mod, fn, ifs) for mod, fn, call, ifs in _index() if _name(call) == "approve_action"]
    by_site = {(mod, fn) for mod, fn, _ in callers}
    assert by_site == {
        ("tokiwa.api.routes.response", "approve"),
        ("tokiwa.respond.service", "create_proposal"),
    }
    for mod, _fn, ifs in callers:
        if mod == "tokiwa.respond.service":
            assert any(_mentions(test, "auto_approve_allowed") for test in ifs), (
                "auto-approve must be guarded"
            )


def test_route_approve_requires_analyst_role() -> None:
    from typing import get_type_hints

    from tokiwa.api.deps import AnalystUser
    from tokiwa.api.routes import response as routes

    for fn in (routes.approve, routes.reject, routes.revert, routes.propose):
        assert get_type_hints(fn, include_extras=True)["user"] == AnalystUser


def test_no_shell_execution_in_respond() -> None:
    import re

    text = "".join(p.read_text(encoding="utf-8") for p in (SRC / "respond").rglob("*.py"))
    for forbidden in ("create_subprocess_shell", "shell=True", "os.system", "os.popen", "import subprocess"):
        assert forbidden not in text, forbidden
    assert not re.search(
        r"(?<!asyncio\.)subprocess\.(run|Popen|call|check_call|check_output|getoutput)", text
    )
    # The only process spawn is the fixed-argv nft runner.
    assert text.count("create_subprocess_exec(") == 1
