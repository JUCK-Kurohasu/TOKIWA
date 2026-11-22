"""Could someone other than the client have made it send this trip? (audit #133: framing through deception)

A deception trip used to be decisive on its own: one GET of ``/api/internal/<canary>/`` became a critical
``ai_agent`` alert, an AI-agent session and a ``block_ip`` proposal. But the canary value is readable by anyone
who loads a protected page, so a third party can make *other people's* clients send that request:

* a browser loading ``<img src="https://<site>/api/internal/<value>/">`` from a forum, a mail or a user post
  on the protected site itself (no script needed; the visitor never sees it);
* a link that a person clicks, or that a link-preview bot / mail scanner / crawler fetches.

What the request itself tells us, and how much each trip is worth:

``induced`` - the browser says the request was not a deliberate top-level visit: ``Sec-Fetch-Site`` is
    ``cross-site`` / ``same-site``, ``Sec-Fetch-Dest`` is a sub-resource (``image``, ``script``, ``iframe`` ...),
    it is a prefetch, or ``Origin`` / ``Referer`` names another host. Any trip type is downgraded to *low* and
    never attributes an AI agent (so no rule-based block proposal can be built on it).
``passive`` - an AI-canary value appears only where a link, an image or a form can put it (path, query, body,
    Referer ...). A link-preview bot or a mail scanner sends no ``Sec-Fetch-*`` headers, so this is *medium*
    without AI attribution; other alerts of the same source (an exploit attempt ...) still raise the incident.
``direct`` - everything else: the value is in a request header that only the client itself can set (the
    ``deception.canary_header`` the instruction asks for, another custom header, the User-Agent), or a
    non-canary trip (decoy path, honeytoken, labyrinth) without induced signals. Unchanged: decisive.

Trade-off (documented in docs/deception.md): a client can *claim* to be an induced browser request by sending
those headers itself. Its trips are then recorded and alerted as *low* instead of being dropped, and the switch
``deception.downgrade_browser_induced`` turns the induced rule off. Decoy-path and honeytoken trips fetched by a
non-browser link fetcher (no ``Sec-Fetch-*``) stay critical - see the audit notes for the residual risk.
"""

from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlsplit

from tokiwa.schemas.events import Event

# Fields a link, an <img>, a plain HTML form or a link-preview bot can fill with an attacker-chosen value.
# Request headers are deliberate except these (the browser sets them from the page that embedded the request).
LINK_REACHABLE_FIELDS = frozenset(
    {
        "http.path",
        "http.query",
        "http.request_body",
        "http.referrer",
        "http.host",
        "http.headers.referer",
        "http.headers.origin",
        "http.headers.host",
        "message",  # the Gate / adapters put the request line here
        "raw",  # raw access-log records contain the request line and Referer
        "deception.token",  # set by the sending sensor; where it came from is unknown
    }
)

# Sec-Fetch-Dest values of a deliberate request: a top-level visit or fetch()/XHR from the site's own page.
_DELIBERATE_DESTS = frozenset({"", "document", "empty"})
_INDUCING_SITES = frozenset({"cross-site", "same-site"})


class Provenance(StrEnum):
    DIRECT = "direct"
    PASSIVE = "passive"
    INDUCED = "induced"


def field_is_link_reachable(field: str) -> bool:
    return field in LINK_REACHABLE_FIELDS


def _host_of_header(value: str | None) -> str | None:
    if not value:
        return None
    try:
        host = urlsplit("//" + value.strip()).hostname
    except ValueError:
        return None
    return host or None


def _host_of_url(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None  # relative / redacted / garbage: no evidence either way
    try:
        return parts.hostname or None
    except ValueError:
        return None


def induced_by(event: Event) -> list[str]:
    """Reasons the request looks browser-induced (cross-site / sub-resource / foreign Referer). Empty = none.

    Only what the event carries: the Gate keeps ``sec-fetch-*``, ``origin`` and ``referer`` (not sensitive).
    """
    h = event.http
    if h is None:
        return []
    hdr = {k.lower(): v for k, v in h.headers.items()}
    reasons: list[str] = []
    site = (hdr.get("sec-fetch-site") or "").strip().lower()
    if site in _INDUCING_SITES:
        reasons.append(f"sec-fetch-site={site}")
    dest = (hdr.get("sec-fetch-dest") or "").strip().lower()
    if dest not in _DELIBERATE_DESTS:
        reasons.append(f"sec-fetch-dest={dest[:32]}")
    # TODO(verify): which browsers send Sec-Purpose / Purpose for link prefetch and prerender (Chromium does).
    purpose = f"{hdr.get('sec-purpose') or ''} {hdr.get('purpose') or ''}".lower()
    if "prefetch" in purpose or "prerender" in purpose:
        reasons.append("prefetch")
    own = _host_of_header(h.host or hdr.get("host"))
    origin = (hdr.get("origin") or "").strip()
    if origin.lower() == "null":
        reasons.append("origin=null")  # sandboxed iframe, data: / file: page
    elif own:
        oh = _host_of_url(origin)
        if oh and oh != own:
            reasons.append(f"origin={oh[:64]}")
    if own:
        rh = _host_of_url(h.referrer or hdr.get("referer"))
        if rh and rh != own:
            reasons.append(f"referer={rh[:64]}")
    return reasons


def decisive_canary_hit(event: Event) -> bool:
    """May a Gate ``kind=deception`` event of an ``ai_canary`` asset decide "AI agent" for its session alone?

    Used by the sessionizer (``aidetect.sessions``), which used to count every served canary route as a decisive
    follow - the landing route ``/api/internal/<value>/`` but also the canary pages (``/api/internal/openapi.json``
    is seeded enabled and linked from the hidden HTML), so one ``<img>`` or one link-following crawler turned its
    source into an AI agent with score 0.99 (#133). Decisive only when the client sent a known canary value in
    the canary header itself and the request does not look browser-induced. Events without HTTP details keep the
    old behaviour (no evidence either way).
    """
    h = event.http
    if h is None:
        return True
    from tokiwa.config import get_settings

    cfg = get_settings().deception
    if cfg.downgrade_browser_induced and induced_by(event):
        return False
    name = cfg.canary_header.lower()
    value = next((v for k, v in h.headers.items() if k.lower() == name), "").strip()
    if not value:
        return False  # page / path fetch only: a link or an <img> can make anyone do that
    from tokiwa.deception.service import cached_index
    from tokiwa.deception.tokens import Slot

    index = cached_index()
    if index is None or index.empty:
        return True  # no index yet: the header name alone only appears in the canary text
    return any(
        (ref := index.tokens.get(v)) is not None and ref.slot == Slot.CANARY for v in index.find_tokens(value)
    )
