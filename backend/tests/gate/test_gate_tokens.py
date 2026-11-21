"""Gate token hot reload (audit #163 (b)): token file re-read on change and after 401, events kept queued."""

from __future__ import annotations

import os
from pathlib import Path

import httpx
from gate_helpers import FakeServer

from tokiwa.config import GateSettings
from tokiwa.gate.cli import resolve_settings
from tokiwa.gate.policy import PolicyManager
from tokiwa.gate.shipper import EventShipper
from tokiwa.gate.tokens import TokenSource
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo

OLD, NEW = "tkw_old", "tkw_new"


def _event(i: int) -> Event:
    return Event(
        kind=EventKind.HTTP,
        dataset="gate.http",
        sensor_id="gate-test",
        source=Endpoint(ip="203.0.113.7"),
        http=HttpInfo(method="GET", path=f"/p/{i}", status=200),
        labels={"i": str(i)},
    )


class RotatingServer(FakeServer):
    """Accepts only ``valid`` tokens; anything else gets 401 (revoked / expired after a rotation)."""

    def __init__(self, valid: set[str]) -> None:
        super().__init__()
        self.valid = valid

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("x-tokiwa-token") not in self.valid:
            self.tokens.append(request.headers.get("x-tokiwa-token"))
            return httpx.Response(401, json={"detail": "invalid API token"})
        return super().handler(request)


def _write(path: Path, value: str, bump: int = 0) -> None:
    path.write_text(value + "\n", encoding="utf-8")
    st = path.stat()
    # make the change visible even on filesystems with coarse mtime resolution
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + bump * 1_000_000_000))


def test_token_source_reloads_on_change_and_keeps_token_on_bad_file(tmp_path: Path) -> None:
    path = tmp_path / "gate.token"
    _write(path, OLD)
    now = [0.0]
    src = TokenSource("tkw_env", path, check_interval=1.0, clock=lambda: now[0])
    assert src.get() == OLD  # the file wins over the env/flag value
    _write(path, NEW, bump=1)
    assert src.get() == OLD  # stat is rate-limited
    now[0] = 1.5
    assert src.get() == NEW and src.reloads == 1
    # empty (half-written) or missing file: keep the last good token, never send an empty one
    _write(path, "", bump=2)
    now[0] = 3.0
    assert src.get() == NEW
    path.unlink()
    now[0] = 4.5
    assert src.get() == NEW
    assert src.reload() is False
    assert TokenSource("tkw_static").reload() is False  # no file: nothing to reload


async def test_shipper_401_rereads_token_file_and_resends(tmp_path: Path) -> None:
    path = tmp_path / "gate.token"
    _write(path, OLD)
    server = RotatingServer({NEW})
    client = httpx.AsyncClient(transport=httpx.MockTransport(server.handler))
    src = TokenSource(None, path, check_interval=3600)  # only the 401 path can notice the change
    shipper = EventShipper(client, "http://tokiwa.test", src, batch_size=3, flush_interval=0.05)
    async with client:
        for i in range(4):
            shipper.submit(_event(i))
        _write(path, NEW, bump=1)  # operator rotated the token and wrote the new one
        assert await shipper.flush() == 4
    assert [int(e["labels"]["i"]) for e in server.events] == [0, 1, 2, 3]
    assert shipper.stats.dropped_rejected == 0
    assert server.tokens.count(OLD) == 1  # one 401, then the new token from the file


async def test_shipper_keeps_events_queued_while_token_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "gate.token"
    _write(path, OLD)
    server = RotatingServer({NEW})
    client = httpx.AsyncClient(transport=httpx.MockTransport(server.handler))
    shipper = EventShipper(
        client, "http://tokiwa.test", TokenSource(None, path), batch_size=3, flush_interval=0.05, max_queue=10
    )
    async with client:
        for i in range(4):
            shipper.submit(_event(i))
        assert await shipper.flush() == 0
        assert len(shipper) == 4  # not dropped: waiting for a valid token
        assert shipper.stats.dropped_rejected == 0 and "401" in (shipper.stats.last_error or "")
        _write(path, NEW, bump=1)
        assert await shipper.flush() == 4
    assert len(server.events) == 4


async def test_policy_manager_401_rereads_token_file(tmp_path: Path) -> None:
    path = tmp_path / "gate.token"
    _write(path, OLD)
    server = RotatingServer({NEW})
    server.set_policy("v1", blocked=["198.51.100.0/24"])
    async with httpx.AsyncClient(transport=httpx.MockTransport(server.handler)) as client:
        manager = PolicyManager(client, "http://tokiwa.test", TokenSource(None, path, check_interval=3600))
        assert await manager.refresh() is False and "401" in (manager.last_error or "")
        _write(path, NEW, bump=1)
        assert await manager.refresh() is True
        assert manager.current.version == "v1"


def test_resolve_settings_keeps_token_file_for_reload(tmp_path: Path) -> None:
    path = tmp_path / "gate.token"
    _write(path, OLD)
    s = resolve_settings(GateSettings(), token_file=path)
    assert s.token_file == path and s.ingest_token is not None
    s2 = resolve_settings(GateSettings(), token="tkw_flag", token_file=path)
    assert s2.token_file is None  # an explicit --token is not reloaded
