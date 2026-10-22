"""Evaluation harness: replay a labelled dataset through the real TOKIWA pipeline and collect what it produced.

Flow (``tokiwa eval run``):

1. read the dataset, split ground truth from the events (labels never reach detectors or the LLM);
2. point TOKIWA at a throw-away SQLite DB under ``<out>/work`` and pick the LLM provider (``mock`` or ``live``);
3. start the runtime like the server does (service packages + ``@on_startup`` hooks, no periodic jobs), so
   correlation/triage subscribers registered by other modules take part exactly as in production;
4. feed events in Gate-like batches (1 s windows, <=100 events) in timestamp order, either as fast as possible
   (``speed=0``) or paced (``speed=1`` real time, ``speed=10`` ten times faster). Timestamps are shifted so the
   dataset ends "now" (relative timing — the rhythm features — is preserved);
5. wait for the bus to drain (async triage), then read alerts / incidents / actor sessions / LLM calls back.

The harness works with whatever detectors/enrichers are registered at the time; metrics simply reflect that.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import select

from tokiwa import runtime
from tokiwa.bus import bus
from tokiwa.config import get_settings, reset_settings_cache
from tokiwa.db.models.detection import AlertRow, IncidentRow
from tokiwa.db.models.llm import LLMCallRow
from tokiwa.db.models.telemetry import ActorSessionRow, EventRow
from tokiwa.db.session import create_all, dispose_engine, init_engine, session_scope
from tokiwa.detect.engine import get_detection_engine, reset_detection_engine
from tokiwa.llm import gateway as gw
from tokiwa.pipeline.service import get_enrichers, process_events, reset_enrichers
from tokiwa.schemas.events import Event
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

LLMMode = Literal["mock", "live"]


class EvalError(RuntimeError):
    pass


@dataclass
class ReplayOptions:
    llm: LLMMode = "mock"
    speed: float = 0.0
    batch_window_seconds: float = 1.0
    batch_size: int = 100
    drain_timeout: float | None = None  # default: 60 s (mock) / 900 s (live)
    detector_overrides: dict[str, bool] = field(default_factory=dict)
    budget_usd: float | None = None
    max_sleep_seconds: float = 30.0


@dataclass
class RunResults:
    events: list[dict[str, Any]] = field(default_factory=list)  # id, session_id, source_ip
    alerts: list[dict[str, Any]] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)
    llm_calls: list[dict[str, Any]] = field(default_factory=list)
    batch_latencies_ms: list[float] = field(default_factory=list)
    batch_sizes: list[int] = field(default_factory=list)
    triage_latencies_s: list[float] = field(default_factory=list)
    triage_latency_source: str = "none"
    replay_seconds: float = 0.0
    drain_seconds: float = 0.0
    detectors_enabled: list[str] = field(default_factory=list)
    detectors_registered: list[str] = field(default_factory=list)
    enrichers: list[str] = field(default_factory=list)
    llm_provider: str = "mock"
    ai_agent_threshold: float = 0.7
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------- isolation


def _reset_singletons() -> None:
    reset_settings_cache()
    reset_detection_engine()
    reset_enrichers()
    gw.set_gateway(None)
    bus.clear()


@contextmanager
def scoped_env(values: dict[str, str]) -> Iterator[None]:
    """Temporarily set TOKIWA_* env vars and rebuild the process-wide singletons around them."""
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    _reset_singletons()
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        _reset_singletons()


def _prepare_work_dir(work_dir: Path, opts: ReplayOptions) -> dict[str, str]:
    work_dir.mkdir(parents=True, exist_ok=True)
    return eval_env(work_dir, opts)


def eval_env(work_dir: Path, opts: ReplayOptions) -> dict[str, str]:
    db_path = work_dir / "eval.db"
    for suffix in ("", "-wal", "-shm"):
        p = Path(f"{db_path}{suffix}")
        if p.exists():
            p.unlink()
    env = {
        "TOKIWA_DATABASE__URL": f"sqlite+aiosqlite:///{db_path}",
        "TOKIWA_SERVER__DATA_DIR": str(work_dir / "data"),
    }
    if opts.llm == "mock":
        env["TOKIWA_LLM__PROVIDER"] = "mock"
    if opts.budget_usd is not None:
        env["TOKIWA_LLM__DAILY_BUDGET_USD"] = str(opts.budget_usd)
    return env


# ---------------------------------------------------------------------------------------- batching


def rebase(events: Sequence[Event], speed: float) -> list[Event]:
    """Sort by time and shift timestamps so the dataset ends now (fast) or starts now (paced)."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    if not ordered:
        return []
    now = utcnow()
    shift = (now - ordered[-1].timestamp) if speed <= 0 else (now - ordered[0].timestamp)
    for e in ordered:
        e.timestamp = e.timestamp + shift
    return ordered


def make_batches(events: Sequence[Event], *, window_seconds: float, max_size: int) -> list[list[Event]]:
    batches: list[list[Event]] = []
    cur: list[Event] = []
    start: datetime | None = None
    for e in events:
        if cur and (
            len(cur) >= max_size or start is None or e.timestamp - start > timedelta(seconds=window_seconds)
        ):
            batches.append(cur)
            cur = []
        if not cur:
            start = e.timestamp
        cur.append(e)
    if cur:
        batches.append(cur)
    return batches


# ---------------------------------------------------------------------------------------- observer


class _TriageObserver:
    """Watches bus traffic (same stream the SSE endpoint relays) to time alert -> triage."""

    def __init__(self) -> None:
        self.created: dict[str, float] = {}
        self.triaged: dict[str, float] = {}

    def handle(self, topic: str, payload: Any) -> None:
        if not topic.startswith(("alert.", "incident.")):
            return
        oid = payload.get("id") if isinstance(payload, dict) else getattr(payload, "id", None)
        if not oid:
            return
        key = f"{topic.split('.', 1)[0]}:{oid}"
        now = time.perf_counter()
        if topic.endswith(".created"):
            self.created.setdefault(key, now)
        triage = payload.get("triage") if isinstance(payload, dict) else getattr(payload, "triage", None)
        if triage is not None:
            self.triaged.setdefault(key, now)

    async def consume(self, q: asyncio.Queue[tuple[str, Any]]) -> None:
        while True:
            topic, payload = await q.get()
            try:
                self.handle(topic, payload)
            except Exception:
                log.exception("observer failed on %s", topic)

    def latencies(self) -> list[float]:
        return [self.triaged[k] - self.created[k] for k in self.triaged if k in self.created]


# ---------------------------------------------------------------------------------------- replay


async def _start_services() -> list[str]:
    """Like ``runtime.start(run_jobs=False)`` but one failing hook does not abort the evaluation."""
    runtime.load_service_packages()
    failures: list[str] = []
    hooks = getattr(runtime, "_startup", None)
    if hooks is None:  # pragma: no cover - runtime API changed
        await runtime.start(run_jobs=False)
        return failures
    for hook in list(hooks):
        try:
            await hook()
        except Exception as exc:
            log.exception("startup hook %r failed during eval", hook)
            failures.append(
                f"startup hook {getattr(hook, '__qualname__', hook)} failed: {type(exc).__name__}: {exc}"
            )
    return failures


def _row(row: Any) -> dict[str, Any]:
    return {c.key: getattr(row, c.key) for c in row.__table__.columns}


async def _collect(results: RunResults) -> None:
    async with session_scope() as s:
        rows = (await s.execute(select(EventRow.id, EventRow.session_id, EventRow.source_ip))).all()
        results.events = [{"id": r[0], "session_id": r[1], "source_ip": r[2]} for r in rows]
        results.alerts = [_row(r) for r in (await s.execute(select(AlertRow))).scalars()]
        results.incidents = [_row(r) for r in (await s.execute(select(IncidentRow))).scalars()]
        results.sessions = [_row(r) for r in (await s.execute(select(ActorSessionRow))).scalars()]
        calls = (await s.execute(select(LLMCallRow))).scalars()
        results.llm_calls = [
            {k: v for k, v in _row(r).items() if k not in ("request_redacted", "response_text")}
            for r in calls
        ]


async def replay(events: Sequence[Event], work_dir: Path, opts: ReplayOptions | None = None) -> RunResults:
    """Replay label-free ``events`` through the pipeline in an isolated environment and return raw results."""
    opts = opts or ReplayOptions()
    env = await asyncio.to_thread(_prepare_work_dir, work_dir, opts)
    with scoped_env(env):
        return await _replay_inner(list(events), opts)


async def _replay_inner(events: list[Event], opts: ReplayOptions) -> RunResults:
    settings = get_settings()
    res = RunResults(ai_agent_threshold=settings.detection.ai_agent_threshold)
    provider = gw.build_provider(settings)
    res.llm_provider = provider.name
    if opts.llm == "live" and provider.name == "mock":
        raise EvalError(
            "--llm live requested but no LLM provider is configured "
            "(set ANTHROPIC_API_KEY or TOKIWA_LLM__OPENAI_BASE_URL); refusing to fall back to mock silently"
        )
    gw.set_gateway(gw.LLMGateway(provider=provider, settings=settings))

    init_engine()
    try:
        await create_all()
        await _run_pipeline(events, opts, res)
    finally:
        await dispose_engine()
    return res


async def _run_pipeline(events: list[Event], opts: ReplayOptions, res: RunResults) -> None:
    res.notes.extend(await _start_services())
    engine = get_detection_engine()
    engine.load()
    engine.overrides.update(opts.detector_overrides)
    res.detectors_registered = sorted(engine.all_detectors())
    res.detectors_enabled = sorted(d.id for d in engine.enabled_detectors())
    res.enrichers = [e.id for e in get_enrichers()]
    if not res.detectors_enabled:
        res.notes.append("no detectors enabled: every detection metric will be 0")

    observer = _TriageObserver()
    queue = bus.listen(maxsize=1_000_000)
    consumer = asyncio.create_task(observer.consume(queue))
    try:
        ordered = rebase(events, opts.speed)
        batches = make_batches(ordered, window_seconds=opts.batch_window_seconds, max_size=opts.batch_size)
        started = time.perf_counter()
        prev: datetime | None = None
        for batch in batches:
            if opts.speed > 0 and prev is not None:
                gap = (batch[0].timestamp - prev).total_seconds() / opts.speed
                await asyncio.sleep(min(max(gap, 0.0), opts.max_sleep_seconds))
            prev = batch[0].timestamp
            t0 = time.perf_counter()
            await process_events(batch)
            res.batch_latencies_ms.append((time.perf_counter() - t0) * 1000)
            res.batch_sizes.append(len(batch))
            await asyncio.sleep(0)  # let bus subscribers make progress, like a live server would
        res.replay_seconds = time.perf_counter() - started
        timeout = opts.drain_timeout or (900.0 if opts.llm == "live" else 60.0)
        t0 = time.perf_counter()
        try:
            await bus.drain(timeout=timeout)
        except TimeoutError:
            res.notes.append(f"bus did not drain within {timeout:.0f}s; late triage results are missing")
        res.drain_seconds = time.perf_counter() - t0
        await asyncio.sleep(0)
    finally:
        bus.unlisten(queue)
        while not queue.empty():
            observer.handle(*queue.get_nowait())
        consumer.cancel()
        try:
            await runtime.stop()
        except Exception:
            log.exception("runtime.stop failed during eval")

    await _collect(res)
    lat = observer.latencies()
    if lat:
        res.triage_latencies_s, res.triage_latency_source = lat, "bus"
    else:
        fallback = [
            (a["updated_at"] - a["created_at"]).total_seconds()
            for a in res.alerts
            if a.get("triage") and a.get("updated_at") and a.get("created_at")
        ]
        if fallback:
            res.triage_latencies_s, res.triage_latency_source = fallback, "db_updated_at"
