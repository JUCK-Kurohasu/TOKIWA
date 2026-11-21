"""Role-based projection of raw telemetry (audit #157).

Raw events carry request bodies, query strings, header values, process command lines and LLM prompts: personal
data and, occasionally, secrets that slipped past redaction. The LLM call detail holding the same content is
admin-only, but events, sessions, alert evidence and deception trips were readable by every logged-in user.

Policy: ``analyst`` and ``admin`` see events as stored. A ``viewer`` (read-only accounts for outsourced SOC,
management dashboards, auditors) gets a **masked projection** instead of a 403, so every page keeps working and
still shows who / when / which path / which status / which detector:

- masked: ``http.query``, ``http.request_body``, header values (except a few non-sensitive ones), the query part
  of ``http.referrer``, ``raw``, ``message`` of non-Gate datasets (sensor log lines can contain the full request),
  ``process.cmdline`` (also under ``network.process``), ``llm_app.prompt``, ``deception.token``;
- kept: kind, dataset, timestamps, source/destination, method, host, path, status, sizes, user agent, labels, tags.

Paths themselves can hold personal data (``/users/hanako@example.com``); they stay visible because the triage
views are useless without them. Tighten here if needed.
"""

from __future__ import annotations

from tokiwa.schemas.events import Event
from tokiwa.schemas.system import Role, User

REDACTED = "[redacted: analyst role required]"
VISIBLE_HEADERS = frozenset({"user-agent", "host", "content-type", "accept", "content-length"})
RAW_ROLES = frozenset({Role.ADMIN, Role.ANALYST})


def can_view_raw(user: User) -> bool:
    return user.role in RAW_ROLES


def mask_event(event: Event) -> Event:
    """Viewer projection of one event (a copy; the input is not modified)."""
    e = event.model_copy(deep=True)
    if e.http is not None:
        h = e.http
        if h.query:
            h.query = REDACTED
        if h.request_body:
            h.request_body = REDACTED
        h.headers = {k: (v if k.lower() in VISIBLE_HEADERS else REDACTED) for k, v in h.headers.items()}
        if h.referrer and "?" in h.referrer:
            h.referrer = h.referrer.split("?", 1)[0] + "?" + REDACTED
    e.raw = None
    if e.message and not e.dataset.startswith("gate."):
        e.message = REDACTED
    for proc in (e.process, e.network.process if e.network else None):
        if proc is not None and proc.cmdline:
            proc.cmdline = REDACTED
    if e.llm_app is not None and e.llm_app.prompt:
        e.llm_app.prompt = REDACTED
    if e.deception is not None and e.deception.token:
        e.deception.token = REDACTED
    return e


def project_event(event: Event, user: User) -> Event:
    return event if can_view_raw(user) else mask_event(event)


def project_events(events: list[Event], user: User) -> list[Event]:
    return events if can_view_raw(user) else [mask_event(e) for e in events]
