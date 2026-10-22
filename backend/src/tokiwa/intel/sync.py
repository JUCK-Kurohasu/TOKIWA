"""Periodic intel feed synchronisation with per-source state.

- Job ``intel.sync`` runs every ``intel.sync_interval_minutes`` (when ``intel.enabled``); it can also be started
  from ``POST /api/v1/intel/sync`` (background task) or ``tokiwa intel sync``.
- State lives in ``settings_kv["intel.sync_state"]`` as ``{source_id: {...}}`` with ``last_sync`` (start time of
  the last run without errors; used as ``since`` next time), ``last_attempt``, ``last_error``, ``records``
  (records returned by the last run), ``vulns_created/updated``, ``items_created``, ``duration_ms``.
  ``last_sync`` is *not* advanced when a run reports errors, so the same window is retried.
- Isolation: each source runs in its own try/except and its own DB transaction; one failing source never
  affects the others. Phase 1 sources run concurrently (DB writes are serialised by a lock); sources marked
  ``run_last`` (EPSS) run afterwards so they can score the CVEs gathered in phase 1.
- Optional source hook ``async prepare(collected_cves: set[str])`` lets targeted sources (EPSS, OSV) load
  their inputs from the DB before ``fetch``.
- ``intel.vuln_updated`` events are published after each source's transaction committed.
"""

from __future__ import annotations

import asyncio
import logging
import time
import weakref
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel

from tokiwa.config import Settings, get_settings
from tokiwa.db.session import session_scope
from tokiwa.intel.base import IntelSource, SourceResult, registered_sources
from tokiwa.intel.sources._common import USER_AGENT, is_cve, parse_dt
from tokiwa.intel.store import publish_updates, upsert_items, upsert_vulns
from tokiwa.plugins import import_submodules
from tokiwa.runtime import periodic
from tokiwa.settings_store import get_setting, set_setting
from tokiwa.util import utcnow

log = logging.getLogger(__name__)

STATE_KEY = "intel.sync_state"
HTTP_TIMEOUT = httpx.Timeout(60.0, connect=15.0)
MAX_ERROR_CHARS = 1000


class SyncInProgressError(RuntimeError):
    pass


class SourceStatus(BaseModel):
    """``GET /api/v1/intel/sources`` item. Contract fields first; the rest are additive details."""

    id: str
    name: str
    enabled: bool
    last_sync: datetime | None = None
    last_error: str | None = None
    records: int = 0
    last_attempt: datetime | None = None
    vulns_created: int = 0
    vulns_updated: int = 0
    items_created: int = 0
    duration_ms: int | None = None
    running: bool = False
    attribution: str | None = None


def default_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True, headers={"User-Agent": USER_AGENT})


@dataclass
class _LoopState:
    """Locks are per event loop: an asyncio.Lock binds to the loop that first waits on it."""

    sync: asyncio.Lock = field(default_factory=asyncio.Lock)
    store: asyncio.Lock = field(default_factory=asyncio.Lock)
    state: asyncio.Lock = field(default_factory=asyncio.Lock)
    running_sources: set[str] = field(default_factory=set)
    background: set[asyncio.Task[Any]] = field(default_factory=set)


_client_factory: Callable[[], httpx.AsyncClient] = default_client
_per_loop: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, _LoopState] = weakref.WeakKeyDictionary()


def _ls() -> _LoopState:
    loop = asyncio.get_running_loop()
    st = _per_loop.get(loop)
    if st is None:
        st = _per_loop[loop] = _LoopState()
    return st


def set_client_factory(factory: Callable[[], httpx.AsyncClient] | None) -> None:
    """Tests / embedding: replace how the HTTP client is built (``None`` restores the default)."""
    global _client_factory
    _client_factory = factory or default_client


def load_sources() -> dict[str, type[IntelSource]]:
    import_submodules("tokiwa.intel.sources")
    return registered_sources()


def is_running() -> bool:
    return _ls().sync.locked()


def plan_sources(
    source_ids: Sequence[str] | None = None, settings: Settings | None = None
) -> list[IntelSource]:
    """Instantiate the sources a run would use. Unknown ids raise ``KeyError``; disabled ones are dropped
    (configuration wins over ad-hoc requests), and nothing runs when ``intel.enabled`` is false."""
    settings = settings or get_settings()
    registry = load_sources()
    if source_ids:
        unknown = [s for s in source_ids if s not in registry]
        if unknown:
            raise KeyError(f"unknown intel source(s): {', '.join(unknown)}")
    if not settings.intel.enabled:
        return []
    wanted = list(source_ids) if source_ids else list(registry)
    return [src for src in (registry[sid](settings) for sid in wanted) if src.enabled()]


async def load_state() -> dict[str, dict[str, Any]]:
    raw = await get_setting(STATE_KEY, {})
    return {k: dict(v) for k, v in raw.items() if isinstance(v, dict)}


async def _save_entry(source_id: str, entry: dict[str, Any]) -> None:
    async with _ls().state:
        state = await load_state()
        state[source_id] = entry
        await set_setting(STATE_KEY, state)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


async def _run_source(
    source: IntelSource, client: httpx.AsyncClient, previous: dict[str, Any], collected: set[str]
) -> dict[str, Any]:
    started = utcnow()
    t0 = time.monotonic()
    since = parse_dt(previous.get("last_sync"))
    entry: dict[str, Any] = {**previous, "last_attempt": _iso(started)}
    ls = _ls()
    ls.running_sources.add(source.id)
    try:
        prepare = getattr(source, "prepare", None)
        if prepare is not None:
            await prepare(set(collected))
        result: SourceResult = await source.fetch(client, since)
        async with ls.store, session_scope() as session:
            vres = await upsert_vulns(session, result.vulns)
            ires = await upsert_items(session, result.items)
        await publish_updates(vres.updates)
        collected.update(v for v in vres.ids if is_cve(v))
        errors = result.errors
        entry.update(
            last_error="; ".join(errors)[:MAX_ERROR_CHARS] if errors else None,
            records=len(result.vulns) + len(result.items),
            vulns_created=vres.created,
            vulns_updated=vres.updated,
            items_created=ires.created,
        )
        if not errors:
            entry["last_sync"] = _iso(started)
        log.info(
            "intel %s: %d records (vulns +%d ~%d, items +%d)%s",
            source.id,
            entry["records"],
            vres.created,
            vres.updated,
            ires.created,
            f" with {len(errors)} error(s)" if errors else "",
        )
    except Exception as exc:  # isolation: a broken source must not stop the others
        log.exception("intel source %s failed", source.id)
        entry.update(last_error=f"{type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS], records=0)
    finally:
        ls.running_sources.discard(source.id)
        entry["duration_ms"] = int((time.monotonic() - t0) * 1000)
    await _save_entry(source.id, entry)
    return entry


async def run_sync(
    source_ids: Sequence[str] | None = None,
    *,
    client: httpx.AsyncClient | None = None,
    settings: Settings | None = None,
) -> dict[str, dict[str, Any]]:
    """Run one sync pass over the enabled sources (or the given subset). Returns the per-source state entries.

    Raises ``KeyError`` for unknown source ids and :class:`SyncInProgressError` if a pass is already running.
    See :func:`plan_sources` for which sources run.
    """
    sources = plan_sources(source_ids, settings)
    lock = _ls().sync
    if lock.locked():
        raise SyncInProgressError("intel sync already running")
    async with lock:
        state = await load_state()
        own_client = client is None
        http = client or _client_factory()
        collected: set[str] = set()
        out: dict[str, dict[str, Any]] = {}
        try:
            first = [s for s in sources if not getattr(s, "run_last", False)]
            last = [s for s in sources if getattr(s, "run_last", False)]
            entries = await asyncio.gather(
                *(_run_source(s, http, state.get(s.id, {}), collected) for s in first)
            )
            out.update({s.id: e for s, e in zip(first, entries, strict=True)})
            for s in last:
                out[s.id] = await _run_source(s, http, state.get(s.id, {}), collected)
        finally:
            if own_client:
                await http.aclose()
        return out


def start_background_sync(source_ids: Sequence[str] | None = None) -> asyncio.Task[Any]:
    """Schedule ``run_sync`` without awaiting it (manual sync API). Caller checks ``is_running`` first."""

    async def _runner() -> None:
        try:
            await run_sync(source_ids)
        except SyncInProgressError:
            log.info("intel sync already running; manual request ignored")
        except Exception:
            log.exception("background intel sync failed")

    task = asyncio.create_task(_runner(), name="intel-sync-manual")
    bg = _ls().background
    bg.add(task)
    task.add_done_callback(bg.discard)
    return task


async def wait_background(timeout: float = 30.0) -> None:
    """Tests: wait for manual sync tasks to finish."""
    bg = _ls().background
    async with asyncio.timeout(timeout):
        while bg:
            await asyncio.gather(*list(bg), return_exceptions=True)


async def source_statuses(settings: Settings | None = None) -> list[SourceStatus]:
    settings = settings or get_settings()
    state = await load_state()
    running = _ls().running_sources
    out: list[SourceStatus] = []
    for sid, cls in load_sources().items():
        entry = state.get(sid, {})
        out.append(
            SourceStatus(
                id=sid,
                name=cls.name,
                enabled=bool(settings.intel.enabled and cls(settings).enabled()),
                last_sync=parse_dt(entry.get("last_sync")),
                last_error=entry.get("last_error"),
                records=int(entry.get("records") or 0),
                last_attempt=parse_dt(entry.get("last_attempt")),
                vulns_created=int(entry.get("vulns_created") or 0),
                vulns_updated=int(entry.get("vulns_updated") or 0),
                items_created=int(entry.get("items_created") or 0),
                duration_ms=entry.get("duration_ms"),
                running=sid in running,
                attribution=getattr(cls, "attribution", None),
            )
        )
    return out


@periodic(
    "intel.sync",
    every_seconds=lambda s: s.intel.sync_interval_minutes * 60,
    initial_delay=60,
    enabled=lambda s: s.intel.enabled,
)
async def intel_sync_job() -> None:
    try:
        await run_sync()
    except SyncInProgressError:
        log.info("intel.sync skipped: a sync is already running")
