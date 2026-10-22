"""Small helpers shared by the ``ai.*`` / ``llm_app.*`` detectors (kept out of ``detect/detectors`` so the
auto-importer does not treat them as a detector family)."""

from __future__ import annotations

from tokiwa.aidetect.fingerprints import actor_key
from tokiwa.schemas.events import Event


def event_actor_key(event: Event) -> str:
    h = event.http
    ua = (h.user_agent or (h.headers or {}).get("user-agent")) if h else None
    return actor_key(event.session_id, event.source_ip, ua, h.headers if h else None)


def base_entities(event: Event) -> dict[str, str]:
    """Correlation entities: ``session_id`` (actor session), ``host`` and ``path`` when known."""
    ent: dict[str, str] = {}
    if event.session_id:
        ent["session_id"] = event.session_id
    h = event.http
    if h is not None:
        if h.host:
            ent["host"] = h.host[:255]
        if h.path:
            ent["path"] = h.path.split("?", 1)[0][:255]
    return ent


def referer_of(event: Event) -> str | None:
    h = event.http
    if h is None:
        return None
    return h.referrer or (h.headers or {}).get("referer")


def clip(text: str | None, n: int = 200) -> str:
    return (text or "")[:n]
