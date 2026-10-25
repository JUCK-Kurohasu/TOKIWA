"""System info, background jobs (list / manual run) and the audit log viewer."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import httpx
import pytest

from tokiwa import __version__, runtime
from tokiwa.api.routes import system as system_routes

JOB = "test.api_core_job"


class _Gate:
    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.calls = 0

    async def __call__(self) -> None:
        self.calls += 1
        await self.release.wait()


@pytest.fixture
def test_job() -> Iterator[_Gate]:
    gate = _Gate()
    runtime.periodic(JOB, 3600, initial_delay=3600)(gate)
    yield gate
    gate.release.set()
    runtime.jobs().pop(JOB, None)


async def test_system_info(
    client: httpx.AsyncClient, viewer_headers: dict[str, str], test_job: _Gate
) -> None:
    r = await client.get("/api/v1/system/info", headers=viewer_headers)
    assert r.status_code == 200, r.text
    info = r.json()
    assert info["version"] == __version__
    assert info["env"] == "test"
    assert info["llm_provider"] == "mock" and info["llm_available"] is True
    assert info["database"] == "sqlite"  # backend name only, never the URL
    assert "tokiwa.db" not in r.text
    assert isinstance(info["detectors"], int) and info["detectors"] >= 0
    assert JOB in [j["name"] for j in info["jobs"]]


async def test_list_jobs(client: httpx.AsyncClient, viewer_headers: dict[str, str], test_job: _Gate) -> None:
    r = await client.get("/api/v1/system/jobs", headers=viewer_headers)
    assert r.status_code == 200
    jobs = {j["name"]: j for j in r.json()}
    assert jobs[JOB]["interval_seconds"] == 3600
    assert jobs[JOB]["running"] is False and jobs[JOB]["run_count"] == 0
    names = [j["name"] for j in r.json()]
    assert names == sorted(names)


async def test_run_job_in_background(
    client: httpx.AsyncClient, admin_headers: dict[str, str], test_job: _Gate
) -> None:
    r = await client.post(f"/api/v1/system/jobs/{JOB}/run", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["name"] == JOB
    assert r.json()["running"] is True  # returned immediately while the job is still running
    # Triggering again while running does not start a second run.
    again = await client.post(f"/api/v1/system/jobs/{JOB}/run", headers=admin_headers)
    assert again.status_code == 200 and again.json()["running"] is True
    assert test_job.calls == 1

    test_job.release.set()
    job = runtime.jobs()[JOB]
    await asyncio.wait_for(asyncio.gather(*list(system_routes._manual_runs)), timeout=5)
    assert job.run_count == 1 and not job.running
    listed = {j["name"]: j for j in (await client.get("/api/v1/system/jobs", headers=admin_headers)).json()}
    assert listed[JOB]["run_count"] == 1 and listed[JOB]["last_error"] is None

    audit = (
        await client.get("/api/v1/audit", params={"action": "system.job.run"}, headers=admin_headers)
    ).json()
    assert audit["total"] == 2
    assert {e["target"] for e in audit["items"]} == {JOB}

    assert (await client.post("/api/v1/system/jobs/nope/run", headers=admin_headers)).status_code == 404


async def test_run_job_requires_admin(
    client: httpx.AsyncClient, role_headers: dict[str, dict[str, str]], test_job: _Gate
) -> None:
    assert (await client.post(f"/api/v1/system/jobs/{JOB}/run")).status_code == 401
    for role in ("viewer", "analyst"):
        r = await client.post(f"/api/v1/system/jobs/{JOB}/run", headers=role_headers[role])
        assert r.status_code == 403, role
    assert test_job.calls == 0


async def test_system_read_endpoints_require_login(client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/system/info", "/api/v1/system/jobs"):
        assert (await client.get(path)).status_code == 401


async def test_audit_log(client: httpx.AsyncClient, role_headers: dict[str, dict[str, str]]) -> None:
    admin = role_headers["admin"]  # role_headers already created an analyst and a viewer (2x user.create)
    await client.post("/api/v1/tokens", json={"name": "t1"}, headers=admin)

    r = await client.get("/api/v1/audit", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 3 and body["limit"] == 50 and body["offset"] == 0
    assert [e["action"] for e in body["items"]] == ["token.create", "user.create", "user.create"]
    assert all(e["actor"] == "admin" for e in body["items"])

    page = (await client.get("/api/v1/audit", params={"limit": 1, "offset": 1}, headers=admin)).json()
    assert page["total"] == 3 and [e["action"] for e in page["items"]] == ["user.create"]
    only = (await client.get("/api/v1/audit", params={"action": "token.create"}, headers=admin)).json()
    assert only["total"] == 1 and only["items"][0]["details"]["name"] == "t1"
    by_actor = (await client.get("/api/v1/audit", params={"actor": "someone"}, headers=admin)).json()
    assert by_actor["total"] == 0
    assert (await client.get("/api/v1/audit", params={"limit": 501}, headers=admin)).status_code == 422

    assert (await client.get("/api/v1/audit")).status_code == 401
    for role in ("viewer", "analyst"):
        assert (await client.get("/api/v1/audit", headers=role_headers[role])).status_code == 403
