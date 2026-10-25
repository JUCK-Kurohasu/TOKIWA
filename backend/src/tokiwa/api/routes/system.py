"""System information and background jobs.

``POST /system/jobs/{name}/run`` (admin) starts the job in the background and returns immediately; the UI
polls ``GET /system/jobs`` for completion. A job that is already running is not started twice.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, status
from sqlalchemy.engine import make_url

from tokiwa import __version__, runtime
from tokiwa.api.deps import AdminUser, CurrentUser
from tokiwa.audit import record_audit
from tokiwa.config import get_settings
from tokiwa.detect.engine import get_detection_engine
from tokiwa.llm.gateway import get_gateway
from tokiwa.schemas.system import JobInfo, SystemInfo

router = APIRouter(prefix="/api/v1/system", tags=["system"])

# Strong references so manually triggered job runs are not garbage-collected mid-flight.
_manual_runs: set[asyncio.Task[None]] = set()


def _job_infos() -> list[JobInfo]:
    settings = get_settings()
    return [job.info(settings) for _, job in sorted(runtime.jobs().items())]


def _database_backend() -> str:
    """Backend name only (e.g. "sqlite", "postgresql") - never the URL, which may embed credentials."""
    try:
        return make_url(get_settings().database.url).get_backend_name()
    except Exception:
        return "unknown"


@router.get("/info", response_model=SystemInfo)
async def system_info(user: CurrentUser) -> SystemInfo:
    settings = get_settings()
    provider = get_gateway().provider
    try:
        available = bool(provider.available())
    except Exception:
        available = False
    return SystemInfo(
        version=__version__,
        env=settings.env,
        llm_provider=provider.name,
        llm_available=available,
        database=_database_backend(),
        detectors=len(get_detection_engine().all_detectors()),
        jobs=_job_infos(),
    )


@router.get("/jobs", response_model=list[JobInfo])
async def list_jobs(user: CurrentUser) -> list[JobInfo]:
    return _job_infos()


@router.post("/jobs/{name}/run", response_model=JobInfo)
async def run_job(name: str, admin: AdminUser) -> JobInfo:
    job = runtime.jobs().get(name)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    already_running = job.running
    if not already_running:
        task = asyncio.create_task(job.run_once(), name=f"job-manual:{name}")
        _manual_runs.add(task)
        task.add_done_callback(_manual_runs.discard)
        await asyncio.sleep(0)  # let run_once flip ``running`` so the response reflects the started run
    await record_audit(admin.username, "system.job.run", name, {"already_running": already_running})
    return job.info(get_settings())
