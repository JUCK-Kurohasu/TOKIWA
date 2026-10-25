"""Fixtures for respond tests: executor spies, config overrides, users with roles, a deterministic host."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from tokiwa.auth.security import create_access_token, hash_password
from tokiwa.config import reset_settings_cache
from tokiwa.db.models.core import UserRow
from tokiwa.db.session import session_scope
from tokiwa.notify import outbound
from tokiwa.respond import executors, validate
from tokiwa.respond.executors import ExecutionRequest, Executor, ExecutorError
from tokiwa.schemas.triage import ActionType
from tokiwa.util import new_id, utcnow


class SpyExecutor(Executor):
    """Records every apply/revert. Replaces all real executors so tests can prove what ran."""

    action_types = frozenset(ActionType)

    def __init__(self) -> None:
        self.applied: list[ExecutionRequest] = []
        self.reverted: list[ExecutionRequest] = []
        self.fail_apply: str | None = None
        self.fail_revert: str | None = None

    async def apply(self, req: ExecutionRequest) -> dict[str, Any]:
        self.applied.append(req)
        if self.fail_apply:
            raise ExecutorError(self.fail_apply)
        return {"spy": "applied"}

    async def revert(self, req: ExecutionRequest) -> dict[str, Any]:
        self.reverted.append(req)
        if self.fail_revert:
            raise ExecutorError(self.fail_revert)
        return {"spy": "reverted"}


@pytest.fixture(autouse=True)
def _deterministic_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """This machine's interface addresses must not influence validation; no DNS either."""
    monkeypatch.setattr(validate, "_server_addresses", lambda: ())

    async def fake_resolve(host: str, port: int) -> list[str]:
        return {"internal.example.com": ["10.1.2.3"]}.get(host, ["93.184.215.14"])

    monkeypatch.setattr(outbound, "_resolve", fake_resolve)


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> SpyExecutor:
    s = SpyExecutor()
    monkeypatch.setattr(executors, "_EXECUTORS", dict.fromkeys(ActionType, s))
    return s


@pytest.fixture
def configure(monkeypatch: pytest.MonkeyPatch, settings: Any) -> Callable[..., None]:
    """configure(auto_approve_enabled=True, auto_approve_actions=["block_ip"]) -> response.* env overrides."""

    def _set(section: str = "response", **values: Any) -> None:
        for key, value in values.items():
            raw = value if isinstance(value, str) else json.dumps(value)
            monkeypatch.setenv(f"TOKIWA_{section.upper()}__{key.upper()}", raw)
        reset_settings_cache()

    return _set


@pytest.fixture
def make_user() -> Callable[[str], Awaitable[dict[str, str]]]:
    async def _make(role: str) -> dict[str, str]:
        row = UserRow(
            id=new_id(),
            username=f"{role}-{new_id()[-8:]}",
            password_hash=hash_password("correct-horse-battery"),
            role=role,
            created_at=utcnow(),
        )
        async with session_scope() as s:
            s.add(row)
        token, _ = create_access_token(row.id, row.username, row.role)
        return {"Authorization": f"Bearer {token}"}

    return _make
