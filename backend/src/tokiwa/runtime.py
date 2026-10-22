"""Lifecycle hooks and periodic jobs.

Modules register background work without touching the app factory::

    from tokiwa.runtime import on_startup, periodic

    @on_startup
    async def _subscribe() -> None:
        bus.subscribe("alert.created", handle_alert)

    @periodic("intel.sync", every_seconds=lambda s: s.intel.sync_interval_minutes * 60, initial_delay=30)
    async def sync_intel() -> None:
        ...

Startup hooks/jobs are discovered by importing ``tokiwa.services`` packages listed in ``SERVICE_PACKAGES``.
Jobs can be triggered manually via ``POST /api/v1/system/jobs/{name}/run``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime

from tokiwa.config import Settings, get_settings
from tokiwa.schemas.system import JobInfo
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

Hook = Callable[[], Awaitable[None]]

# Packages imported at startup so their @on_startup / @periodic registrations happen.
SERVICE_PACKAGES = [
    "tokiwa.detect",
    "tokiwa.enrich",
    "tokiwa.correlate",
    "tokiwa.triage",
    "tokiwa.intel",
    "tokiwa.respond",
    "tokiwa.deception",
    "tokiwa.notify",
    "tokiwa.copilot",
    "tokiwa.llm",
]

_startup: list[Hook] = []
_shutdown: list[Hook] = []


@dataclass
class Job:
    name: str
    func: Hook
    every: Callable[[Settings], float] | float
    initial_delay: float = 5.0
    enabled: Callable[[Settings], bool] | None = None
    running: bool = False
    last_started: datetime | None = None
    last_finished: datetime | None = None
    last_error: str | None = None
    run_count: int = 0
    _task: asyncio.Task[None] | None = field(default=None, repr=False)

    def interval(self, settings: Settings) -> float:
        return float(self.every(settings) if callable(self.every) else self.every)

    def is_enabled(self, settings: Settings) -> bool:
        return True if self.enabled is None else bool(self.enabled(settings))

    async def run_once(self) -> None:
        if self.running:
            return
        self.running = True
        self.last_started = utcnow()
        try:
            await self.func()
            self.last_error = None
        except Exception as exc:
            log.exception("job %s failed", self.name)
            self.last_error = f"{type(exc).__name__}: {exc}"
        finally:
            self.running = False
            self.last_finished = utcnow()
            self.run_count += 1

    def info(self, settings: Settings) -> JobInfo:
        return JobInfo(
            name=self.name,
            interval_seconds=self.interval(settings),
            running=self.running,
            last_started=self.last_started,
            last_finished=self.last_finished,
            last_error=self.last_error,
            run_count=self.run_count,
        )


_jobs: dict[str, Job] = {}


def on_startup(func: Hook) -> Hook:
    if func not in _startup:
        _startup.append(func)
    return func


def on_shutdown(func: Hook) -> Hook:
    if func not in _shutdown:
        _shutdown.append(func)
    return func


def periodic(
    name: str,
    every_seconds: Callable[[Settings], float] | float,
    *,
    initial_delay: float = 5.0,
    enabled: Callable[[Settings], bool] | None = None,
) -> Callable[[Hook], Hook]:
    def deco(func: Hook) -> Hook:
        _jobs[name] = Job(
            name=name, func=func, every=every_seconds, initial_delay=initial_delay, enabled=enabled
        )
        return func

    return deco


def jobs() -> dict[str, Job]:
    return _jobs


def load_service_packages() -> None:
    from tokiwa.plugins import import_submodules

    for pkg in SERVICE_PACKAGES:
        import_submodules(pkg)


async def _job_loop(job: Job, settings: Settings) -> None:
    await asyncio.sleep(job.initial_delay)
    while True:
        if job.is_enabled(settings):
            await job.run_once()
        await asyncio.sleep(max(1.0, job.interval(settings)))


async def start(*, run_jobs: bool = True) -> None:
    settings = get_settings()
    for hook in list(_startup):
        await hook()
    if run_jobs:
        for job in _jobs.values():
            job._task = asyncio.create_task(_job_loop(job, settings), name=f"job:{job.name}")


async def stop() -> None:
    for job in _jobs.values():
        if job._task is not None:
            job._task.cancel()
            job._task = None
    for hook in list(_shutdown):
        try:
            await hook()
        except Exception:
            log.exception("shutdown hook failed")
