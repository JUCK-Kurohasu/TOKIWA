"""`tokiwa user create` / `tokiwa user reset-password` (#163 c/d)."""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import select
from typer.testing import CliRunner

from tokiwa import cli
from tokiwa.auth.security import verify_password
from tokiwa.config import Settings
from tokiwa.db.models.auth import AUTH_STATE_ID, AuthStateRow
from tokiwa.db.models.core import AuditRow, UserRow
from tokiwa.db.session import create_all, dispose_engine, init_engine, session_scope

PW = "correct-horse-battery"


def _invoke(*args: str, password: str = PW) -> Any:
    return CliRunner().invoke(cli.app, ["user", *args], input=f"{password}\n{password}\n")


def _query(fn: Any) -> Any:
    async def run() -> Any:
        init_engine()
        try:
            await create_all()
            async with session_scope() as s:
                return await fn(s)
        finally:
            await dispose_engine()

    return asyncio.run(run())


async def _user(s: Any, name: str) -> UserRow | None:
    return await s.scalar(select(UserRow).where(UserRow.username == name))


def test_create_user_marks_setup_done_and_audits(settings: Settings) -> None:
    r = _invoke("create", "root", "--role", "admin")
    assert r.exit_code == 0, r.output
    assert "created user root (admin)" in r.output

    async def check(s: Any) -> tuple[Any, ...]:
        row = await _user(s, "root")
        state = await s.get(AuthStateRow, AUTH_STATE_ID)
        actions = list((await s.execute(select(AuditRow.action, AuditRow.actor))).all())
        return row, state, actions

    row, state, actions = _query(check)
    assert row is not None and row.role == "admin" and verify_password(PW, row.password_hash)
    assert state is not None and state.setup_completed_at is not None
    assert ("user.create", "cli") in actions


def test_duplicate_user_prints_a_message_not_a_traceback(settings: Settings) -> None:
    assert _invoke("create", "root", "--role", "admin").exit_code == 0
    r = _invoke("create", "root", "--role", "admin", password="another-password-1")
    assert r.exit_code == 1
    assert "already exists" in r.output and "reset-password" in r.output
    assert "Traceback" not in r.output and "scrypt$" not in r.output and "INSERT" not in r.output


def test_invalid_role_and_short_password_are_rejected(settings: Settings) -> None:
    r = _invoke("create", "bob", "--role", "superuser")
    assert r.exit_code == 1 and "invalid input" in r.output
    r = _invoke("create", "bob", password="short")
    assert r.exit_code == 1 and "password" in r.output
    assert _query(lambda s: _user(s, "bob")) is None


def test_reset_password_revokes_logins_and_audits(settings: Settings) -> None:
    assert _invoke("create", "carol").exit_code == 0
    before = _query(lambda s: _user(s, "carol"))
    old_token_version = before.token_version
    r = _invoke("reset-password", "carol", password="a-new-long-password")
    assert r.exit_code == 0, r.output

    async def check(s: Any) -> tuple[Any, ...]:
        row = await _user(s, "carol")
        audit = await s.scalar(select(AuditRow).where(AuditRow.action == "user.password_reset"))
        return row, audit

    row, audit = _query(check)
    assert verify_password("a-new-long-password", row.password_hash)
    assert not verify_password(PW, row.password_hash)
    assert row.token_version == old_token_version + 1, "existing JWTs of the user stop working"
    assert audit is not None and audit.actor == "cli" and audit.details["username"] == "carol"
    assert "a-new-long-password" not in repr(audit.details)


def test_reset_password_for_unknown_user(settings: Settings) -> None:
    r = _invoke("reset-password", "nobody", password="a-new-long-password")
    assert r.exit_code == 1 and "no such user" in r.output


def test_engine_hides_sql_parameters(settings: Settings) -> None:
    engine = init_engine()
    try:
        assert engine.sync_engine.hide_parameters is True
    finally:
        asyncio.run(dispose_engine())
