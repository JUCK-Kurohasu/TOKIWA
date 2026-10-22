"""``tokiwa agent`` CLI and the Agent loop (host sensor + log tail -> shipper -> mocked server)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from typer.testing import CliRunner

from tokiwa.cli import app as root_app
from tokiwa.config import Settings
from tokiwa.schemas.events import Event, EventKind, PortInfo
from tokiwa.sensors.agent import Agent, build_sources
from tokiwa.sensors.cli import build_settings
from tokiwa.sensors.host import HostSensor
from tokiwa.sensors.normalize import ParseContext
from tokiwa.sensors.shipper import Shipper

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "logs"


@pytest.mark.usefixtures("settings")
def test_agent_subcommand_registered() -> None:
    result = CliRunner().invoke(root_app, ["agent", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output and "once" in result.output


@pytest.mark.usefixtures("settings")
def test_once_print_outputs_json() -> None:
    result = CliRunner().invoke(
        root_app,
        [
            "agent",
            "once",
            "--print",
            "--no-host-sensor",
            "--nginx",
            str(FIXTURES / "nginx_access.json"),
            "--suricata",
            str(FIXTURES / "suricata_eve.json"),
            "--zeek-dir",
            str(FIXTURES / "zeek"),
        ],
    )
    assert result.exit_code == 0, result.output
    docs = json.loads(result.output)
    datasets = {d["dataset"] for d in docs}
    assert {"nginx.access", "suricata.eve", "zeek.conn", "zeek.http", "zeek.notice"} <= datasets
    assert all(Event.model_validate(d) for d in docs)
    assert "supersecretvalue123" not in result.output


def test_build_settings_overrides(settings: Settings) -> None:
    cfg = build_settings(
        server_url="http://srv:9000", token="tkw_x", interval=3.0, host_sensor=False, nginx=[Path("/a.json")]
    )
    assert cfg.server_url == "http://srv:9000" and cfg.interval_seconds == 3.0 and cfg.host_sensor is False
    assert cfg.ingest_token is not None and cfg.ingest_token.get_secret_value() == "tkw_x"
    assert cfg.nginx_json_logs == [Path("/a.json")]
    untouched = build_settings()
    assert untouched.server_url == settings.agent.server_url and untouched.ingest_token is None


def test_build_sources_zeek_dir_and_single_file(settings: Settings) -> None:
    cfg = settings.agent.model_copy(
        update={"zeek_log_dirs": [FIXTURES / "zeek", FIXTURES / "zeek_json" / "notice.log"]}
    )
    sources = build_sources(cfg, ParseContext(), "beginning")
    names = sorted(s.tailer.path.name for s in sources)
    assert names == ["conn.log", "http.log", "notice.log", "notice.log"]


class _FakeHostSensor:
    def __init__(self) -> None:
        self.calls = 0

    async def poll(self) -> list[Event]:
        self.calls += 1
        return [Event(kind=EventKind.PORT_SNAPSHOT, dataset="host.ports", port=PortInfo())]


async def test_agent_run_ships_host_and_log_events(settings: Settings, tmp_path: Path) -> None:
    log_path = tmp_path / "access.json"
    log_path.write_text('{"request_method":"GET","request_uri":"/old","status":"200"}\n')
    received: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Tokiwa-Token"] == "tkw_test"
        received.extend(json.loads(request.content)["events"])
        return httpx.Response(200, json={"accepted": 1, "alerts": 0, "alert_ids": []})

    cfg = settings.agent.model_copy(
        update={"interval_seconds": 0.5, "log_poll_seconds": 0.05, "nginx_json_logs": [log_path]}
    )
    host = _FakeHostSensor()
    shipper = Shipper("http://tokiwa.test", "tkw_test", transport=httpx.MockTransport(handler))
    agent = Agent(cfg, host_sensor=cast(HostSensor, host), shipper=shipper)
    stop = asyncio.Event()
    task = asyncio.create_task(agent.run(stop))
    await asyncio.sleep(0.15)
    with log_path.open("a") as fh:
        fh.write('{"request_method":"GET","request_uri":"/new","status":"404"}\n')
    for _ in range(100):
        if any(e.get("dataset") == "nginx.access" for e in received):
            break
        await asyncio.sleep(0.02)
    stop.set()
    await asyncio.wait_for(task, timeout=5)

    paths = [e["http"]["path"] for e in received if e.get("dataset") == "nginx.access"]
    assert paths == ["/new"]  # default start_at=end: existing lines are not replayed
    assert any(e["kind"] == "port_snapshot" for e in received)
    assert host.calls >= 1
