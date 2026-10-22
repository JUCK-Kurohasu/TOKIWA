"""Sigma rule loading: files (``settings.detection.sigma_rule_dirs``) + the ``rules`` table.

* File rules are the built-in rule set. At startup they are mirrored into ``rules`` as ``source=builtin`` rows
  (``meta.rule_key`` links row <-> file) so the UI can list/disable them and hit counts persist. The file stays
  authoritative for the content; the row only carries status and hit_count.
* DB rules (``source=user|llm``) are evaluated when ``status=active``. ``proposed`` (e.g. LLM drafts) never
  fire until a human approves them.
* Invalid rules are skipped and logged (``store.errors`` keeps the latest problems per source).
* Hit counts are accumulated in memory and written in batches (periodic job, shutdown, and before the rules
  API reads them) - the detection hot path never touches the DB.

The store lives on the ``sigma`` detector instance, so resetting the detection engine (tests, restarts) yields a
fresh store. Use :func:`get_rule_store` everywhere else.
"""

from __future__ import annotations

import logging
import weakref
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from tokiwa.config import Settings, get_settings
from tokiwa.db.models.detection import RuleRow
from tokiwa.db.session import session_scope
from tokiwa.detect.sigma.evaluator import SigmaRule
from tokiwa.detect.sigma.mapping import rule_meta
from tokiwa.detect.sigma.parser import SigmaError, parse_rule
from tokiwa.runtime import on_shutdown, on_startup, periodic
from tokiwa.schemas.events import EventKind
from tokiwa.schemas.system import RuleKind, RuleSource, RuleStatus
from tokiwa.util import new_id, utcnow

log = logging.getLogger(__name__)

SIGMA_DETECTOR_ID = "sigma"
_BACKEND_DIR = (
    Path(__file__).resolve().parents[4]
)  # backend/ (default rule dir "../rules/sigma" is relative to it)


@lru_cache(maxsize=2048)
def _parse_cached(content: str) -> SigmaRule | SigmaError:
    """Parsing is deterministic and settings-independent, so compiled rules are shared by content."""
    try:
        return parse_rule(content)
    except SigmaError as exc:
        return exc


def compile_content(content: str) -> SigmaRule:
    """Parse with caching. Raises SigmaError."""
    res = _parse_cached(content)
    if isinstance(res, SigmaError):
        raise res
    return res


@dataclass
class LoadedRule:
    """A compiled rule plus where it came from."""

    key: str  # stable identity: Sigma ``id``; else "file:<relpath>" / "db:<row id>"
    rule: SigmaRule
    origin: Literal["file", "db"]
    content: str
    path: str | None = None  # file rules: path relative to its rule directory
    db_id: str | None = None  # ``rules`` row id (hit counts, API link)
    source: str = RuleSource.BUILTIN.value

    @property
    def rule_id(self) -> str:
        """Alert ``rule_id``."""
        return f"sigma:{self.key}"


_STORES: weakref.WeakSet[SigmaRuleStore] = weakref.WeakSet()


class SigmaRuleStore:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings
        self._rules: list[LoadedRule] = []
        self._by_kind: dict[EventKind, list[LoadedRule]] = {}
        self._pending: Counter[str] = Counter()
        self.hits: Counter[str] = Counter()  # in-memory hits per rule key since process start
        self.errors: dict[str, list[str]] = {}
        self.loaded = False
        self.db_loaded = False
        _STORES.add(self)

    @property
    def settings(self) -> Settings:
        return self._settings or get_settings()

    # ---- files ---------------------------------------------------------------------------------------

    def rule_dirs(self) -> list[Path]:
        dirs: list[Path] = []
        for p in self.settings.detection.sigma_rule_dirs:
            p = Path(p).expanduser()
            candidates = [p] if p.is_absolute() else [Path.cwd() / p, _BACKEND_DIR / p]
            found = next((c.resolve() for c in candidates if c.is_dir()), None)
            if found is None:
                log.warning("sigma rule dir %s not found", p)
            elif found not in dirs:
                dirs.append(found)
        return dirs

    def load_file_rules(self, errors: dict[str, list[str]] | None = None) -> list[LoadedRule]:
        out: list[LoadedRule] = []
        seen: dict[str, str] = {}
        for d in self.rule_dirs():
            files = sorted({*d.rglob("*.yml"), *d.rglob("*.yaml")})
            for f in files:
                rel = f.relative_to(d).as_posix()
                if any(part.startswith(".") for part in f.relative_to(d).parts):
                    continue
                try:
                    content = f.read_text(encoding="utf-8")
                except OSError as exc:
                    log.warning("cannot read sigma rule %s: %s", f, exc)
                    continue
                try:
                    rule = compile_content(content)
                except SigmaError as exc:
                    log.warning("invalid sigma rule %s skipped: %s", f, "; ".join(exc.errors))
                    if errors is not None:
                        errors[f"file:{rel}"] = list(exc.errors)
                    continue
                key = rule.id or f"file:{rel.rsplit('.', 1)[0]}"
                if key in seen:
                    msg = f"duplicate rule id {key!r} (also in {seen[key]}); skipped"
                    log.warning("sigma rule %s: %s", f, msg)
                    if errors is not None:
                        errors[f"file:{rel}"] = [msg]
                    continue
                seen[key] = rel
                out.append(LoadedRule(key=key, rule=rule, origin="file", content=content, path=rel))
        return out

    def reload_files(self) -> None:
        """Files only (no DB). Used before the first DB reload and in DB-less contexts."""
        errors: dict[str, list[str]] = {}
        self._set(self.load_file_rules(errors), errors)
        self.db_loaded = False

    def ensure_loaded(self) -> None:
        if not self.loaded:
            self.reload_files()

    # ---- files + DB ----------------------------------------------------------------------------------

    async def reload(self, session: AsyncSession | None = None) -> None:
        """Rebuild the active rule set from files and the ``rules`` table (call after any rule change)."""
        errors: dict[str, list[str]] = {}
        files = {lr.key: lr for lr in self.load_file_rules(errors)}
        try:
            rows = await self._fetch_rows(session)
        except Exception:
            log.warning("rules table unavailable; using Sigma file rules only", exc_info=True)
            self._set(list(files.values()), errors)
            self.db_loaded = False
            return
        db_rules: list[LoadedRule] = []
        for row in rows:
            meta = row.meta or {}
            if row.source == RuleSource.BUILTIN:
                lr = files.get(str(meta.get("rule_key")))
                if lr is None:
                    continue
                lr.db_id = row.id
                if row.status != RuleStatus.ACTIVE:
                    files.pop(lr.key, None)
                continue
            if row.status != RuleStatus.ACTIVE:
                continue
            try:
                rule = compile_content(row.content)
            except SigmaError as exc:
                log.warning("invalid sigma rule in DB (%s) skipped: %s", row.id, "; ".join(exc.errors))
                errors[f"db:{row.id}"] = list(exc.errors)
                continue
            db_rules.append(
                LoadedRule(
                    key=rule.id or f"db:{row.id}",
                    rule=rule,
                    origin="db",
                    content=row.content,
                    db_id=row.id,
                    source=row.source,
                )
            )
        self._set([*files.values(), *db_rules], errors)
        self.db_loaded = True

    @staticmethod
    async def _fetch_rows(session: AsyncSession | None) -> list[RuleRow]:
        stmt = select(RuleRow).where(RuleRow.kind == RuleKind.SIGMA).order_by(RuleRow.created_at)
        if session is not None:
            return list((await session.execute(stmt)).scalars().all())
        async with session_scope() as s:
            return list((await s.execute(stmt)).scalars().all())

    def _set(self, rules: list[LoadedRule], errors: dict[str, list[str]]) -> None:
        by_kind: dict[EventKind, list[LoadedRule]] = {}
        for lr in rules:
            for k in lr.rule.kinds:
                by_kind.setdefault(k, []).append(lr)
        # Swap atomically: detectors iterating the old lists are unaffected.
        self._rules = rules
        self._by_kind = by_kind
        self.errors = errors
        self.loaded = True
        log.info("sigma: %d active rules loaded (%d invalid)", len(rules), len(errors))

    # ---- access --------------------------------------------------------------------------------------

    def rules(self) -> list[LoadedRule]:
        self.ensure_loaded()
        return list(self._rules)

    def rules_for(self, kind: EventKind) -> list[LoadedRule]:
        self.ensure_loaded()
        return self._by_kind.get(kind, [])

    def get(self, key: str) -> LoadedRule | None:
        return next((lr for lr in self.rules() if lr.key == key), None)

    # ---- hit counts ----------------------------------------------------------------------------------

    def record_hit(self, lr: LoadedRule) -> None:
        self.hits[lr.key] += 1
        if lr.db_id:
            self._pending[lr.db_id] += 1

    def pending_hits(self) -> dict[str, int]:
        return dict(self._pending)

    async def flush_hits(self, session: AsyncSession | None = None) -> int:
        """Write accumulated hit counts (``hit_count = hit_count + n``). Returns the number of rules touched."""
        if not self._pending:
            return 0
        pending, self._pending = self._pending, Counter()
        try:
            if session is not None:
                await _apply_hits(session, pending)
            else:
                async with session_scope() as s:
                    await _apply_hits(s, pending)
        except Exception:
            log.exception("failed to flush sigma hit counts; will retry")
            self._pending.update(pending)
            return 0
        return len(pending)


async def _apply_hits(session: AsyncSession, pending: Counter[str]) -> None:
    for db_id, n in pending.items():
        await session.execute(
            update(RuleRow)
            .where(RuleRow.id == db_id)
            # keep updated_at: it means "content/status changed", not "fired"
            .values(hit_count=RuleRow.hit_count + n, updated_at=RuleRow.updated_at)
        )


async def sync_builtin_rules(store: SigmaRuleStore, session: AsyncSession | None = None) -> dict[str, int]:
    """Mirror file rules into ``rules`` as ``source=builtin`` rows (content follows the file; status kept)."""
    if session is None:
        async with session_scope() as s:
            return await sync_builtin_rules(store, s)
    files = store.load_file_rules()
    rows = (
        (await session.execute(select(RuleRow).where(RuleRow.source == RuleSource.BUILTIN))).scalars().all()
    )
    by_key: dict[str, RuleRow] = {}
    stats = {"created": 0, "updated": 0, "deleted": 0}
    for row in rows:
        key = (row.meta or {}).get("rule_key")
        if not key or key in by_key:
            await session.delete(row)
            stats["deleted"] += 1
            continue
        by_key[str(key)] = row
    now = utcnow()
    for lr in files:
        meta = {**rule_meta(lr.rule), "rule_key": lr.key, "path": lr.path}
        existing = by_key.pop(lr.key, None)
        if existing is None:
            session.add(
                RuleRow(
                    id=new_id(),
                    created_at=now,
                    updated_at=now,
                    kind=RuleKind.SIGMA.value,
                    title=lr.rule.title,
                    content=lr.content,
                    status=RuleStatus.ACTIVE.value,
                    source=RuleSource.BUILTIN.value,
                    hit_count=0,
                    meta=meta,
                )
            )
            stats["created"] += 1
        elif existing.content != lr.content or existing.meta != meta or existing.title != lr.rule.title:
            existing.content = lr.content
            existing.title = lr.rule.title
            existing.meta = meta
            existing.updated_at = now
            stats["updated"] += 1
    for stale in by_key.values():  # file removed -> row removed
        await session.delete(stale)
        stats["deleted"] += 1
    await session.flush()
    return stats


_fallback_store: SigmaRuleStore | None = None


def get_rule_store() -> SigmaRuleStore:
    """The store used by the current detection engine's ``sigma`` detector."""
    global _fallback_store
    from tokiwa.detect.engine import get_detection_engine

    det = get_detection_engine().all_detectors().get(SIGMA_DETECTOR_ID)
    store = getattr(det, "store", None)
    if isinstance(store, SigmaRuleStore):
        return store
    if _fallback_store is None:  # detector failed to import; keep the API usable
        _fallback_store = SigmaRuleStore()
    return _fallback_store


def live_stores() -> Iterable[SigmaRuleStore]:
    return list(_STORES)


@on_startup
async def _sigma_startup() -> None:
    store = get_rule_store()
    try:
        stats = await sync_builtin_rules(store)
        log.info("sigma builtin rules synced: %s", stats)
    except Exception:
        log.exception("failed to sync builtin Sigma rules into the rules table")
    await store.reload()


@periodic("sigma.flush_hits", every_seconds=60.0, initial_delay=60.0)
async def flush_sigma_hits() -> None:
    for store in live_stores():
        await store.flush_hits()


@on_shutdown
async def _sigma_shutdown() -> None:
    for store in live_stores():
        await store.flush_hits()
