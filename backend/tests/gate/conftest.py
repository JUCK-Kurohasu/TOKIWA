"""Fixtures for gate tests (helpers live in ``gate_helpers`` -- a unique module name, unlike ``conftest``)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from gate_helpers import FakeServer, FakeTime, GateFactory, Upstream
from starlette.applications import Starlette

from tokiwa.config import GateSettings, Settings
from tokiwa.gate.app import Gate, GateOptions, create_gate_app, gate_of


@pytest.fixture
def fake_server() -> FakeServer:
    return FakeServer()


@pytest.fixture
def upstream() -> Upstream:
    return Upstream()


@pytest.fixture
def fake_time() -> FakeTime:
    return FakeTime()


@pytest.fixture
async def make_gate(
    settings: Settings, fake_server: FakeServer, upstream: Upstream, fake_time: FakeTime
) -> AsyncIterator[GateFactory]:
    """Factory: ``app, gate = await make_gate(capture_body_bytes=16, options=GateOptions(...))``."""
    created: list[Gate] = []

    async def factory(
        *,
        options: GateOptions | None = None,
        upstream_transport: httpx.AsyncBaseTransport | None = None,
        fetch_policy: bool = True,
        **overrides: Any,
    ) -> tuple[Starlette, Gate]:
        gate_settings = GateSettings(
            upstream="http://upstream.test",
            server_url="http://tokiwa.test",
            ingest_token="tkw_test_token",
            sensor_id="gate-test",
            **overrides,
        )
        app = create_gate_app(
            gate_settings,
            options=options,
            upstream_transport=upstream_transport or httpx.ASGITransport(app=upstream.app),
            server_transport=httpx.MockTransport(fake_server.handler),
            sleep=fake_time.sleep,
            clock=fake_time.clock,
        )
        gate = gate_of(app)
        created.append(gate)
        if fetch_policy:
            await gate.policy.refresh()
        return app, gate

    yield factory
    for gate in created:
        await gate.upstream_client.aclose()
        await gate.server_client.aclose()
