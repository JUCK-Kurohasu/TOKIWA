"""Make every string the ORM writes storable on any supported database (audit #25).

Telemetry is attacker-controlled, and detectors copy it into other tables (alert titles / entities / details,
actor sessions, deception trips). PostgreSQL rejects three kinds of value that SQLite silently accepts:

- a string longer than a ``VARCHAR(n)`` column (``StringDataRightTruncationError``),
- U+0000 in ``text`` / ``varchar`` / ``jsonb`` (``CharacterNotInRepertoireError`` / ``UntranslatableCharacter``),
- a lone UTF-16 surrogate (``\\ud800``), which cannot be encoded as UTF-8 at all.

Any one of them fails the whole flush, so one crafted request made the ingest batch answer 500 and the sensor
re-sent it forever. Validating each detector's output would leave the next new column open; a single
``before_flush`` hook over every mapped String / Text / JSON attribute closes the class.

Rules: NUL is removed, a lone surrogate becomes U+FFFD, and a ``String(n)`` value is cut to ``n`` characters.
Primary-key columns are only cleaned, never cut: shortening an id could make two rows collide, so ids are made
valid before they get here (:func:`tokiwa.pipeline.service.process_events`). JSON is the source of truth for an
event (``events.data``); the length-limited columns are summaries, so cutting them loses nothing.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy import JSON, String, event, inspect
from sqlalchemy.orm import Session, UOWTransaction

log = logging.getLogger(__name__)

_SURROGATE = re.compile(r"[\ud800-\udfff]")
_MAX_DEPTH = 64  # deeper JSON is left as is (the Event model already caps sizes)


def clean_text(value: str) -> str:
    """``value`` without NUL and with lone surrogates replaced (identity when already clean)."""
    if "\x00" in value:
        value = value.replace("\x00", "")
    if _SURROGATE.search(value):
        value = _SURROGATE.sub("�", value)
    return value


def clean_json(value: Any, _depth: int = 0) -> Any:
    """Recursively clean strings (keys and values) in JSON-like data; returns the same object when clean."""
    if isinstance(value, str):
        return clean_text(value)
    if _depth >= _MAX_DEPTH:
        return value
    if isinstance(value, dict):
        out: dict[Any, Any] | None = None
        for k, v in value.items():
            ck = clean_text(k) if isinstance(k, str) else k
            cv = clean_json(v, _depth + 1)
            if out is None and (ck is not k or cv is not v):
                out = {}
                for k2, v2 in value.items():  # copy the clean prefix
                    if k2 is k:
                        break
                    out[k2] = v2
            if out is not None:
                out[ck] = cv
        return value if out is None else out
    if isinstance(value, list | tuple):
        items = [clean_json(v, _depth + 1) for v in value]
        if all(a is b for a, b in zip(items, value, strict=True)):
            return value
        return items
    return value


def _clean_object(obj: object) -> None:
    state = inspect(obj, raiseerr=False)
    if state is None:
        return
    for attr in state.mapper.column_attrs:
        if len(attr.columns) != 1:
            continue
        column = attr.columns[0]
        value = getattr(obj, attr.key, None)
        if value is None:
            continue
        if isinstance(value, str) and isinstance(column.type, String):
            cleaned = clean_text(value)
            length = column.type.length
            if length and len(cleaned) > length and not column.primary_key:
                cleaned = cleaned[:length]
            if cleaned is not value and cleaned != value:
                setattr(obj, attr.key, cleaned)
        elif isinstance(column.type, JSON) and isinstance(value, dict | list | str):
            cleaned_json = clean_json(value)
            if cleaned_json is not value:
                setattr(obj, attr.key, cleaned_json)


def _before_flush(session: Session, _ctx: UOWTransaction, _instances: object) -> None:
    for obj in (*session.new, *session.dirty):
        try:
            _clean_object(obj)
        except Exception:  # never block a flush because of the sanitizer itself
            log.exception("could not sanitize %s before flush", type(obj).__name__)


def install() -> None:
    """Register the hook on every ORM session (idempotent). AsyncSession flushes through a sync Session."""
    if not event.contains(Session, "before_flush", _before_flush):
        event.listen(Session, "before_flush", _before_flush)
