"""RSS / RDF / Atom news & advisory feeds (``intel.rss_feeds``: JPCERT/CC, IPA, CISA, The Hacker News, …).

Feeds are fetched with httpx (size-capped, retried) and parsed by ``feedparser`` (handles RSS 0.9x/1.0(RDF)/2.0
and Atom; https://feedparser.readthedocs.io/). Each entry becomes an ``IntelItemIn``:

- ``source`` = ``rss:<feed host>`` so the UI can filter per publisher (``/intel/news?source=rss`` matches all).
- ``vuln_ids`` = CVE ids found in title / summary / content (regex ``CVE-YYYY-NNNN+``).
- ``summary`` = text with HTML stripped, truncated to ``MAX_SUMMARY_CHARS``.
- De-duplication happens in ``intel.store.upsert_items`` via ``url_hash`` (sha256 of the normalised link).

Feed content is untrusted: it is stored as plain text and must go through ``untrusted_block`` before any LLM
sees it (intel-advisor's job). One failing feed is reported in ``errors`` and does not stop the others.
Terms: each publisher's own terms apply; TOKIWA stores title/summary/link only (no full-article copies).
"""

from __future__ import annotations

import html
import logging
import re
from datetime import UTC, datetime
from typing import Any

import feedparser
import httpx

from tokiwa.config import Settings
from tokiwa.intel.base import IntelItemIn, IntelSource, SourceResult, register_source
from tokiwa.intel.sources._common import (
    FetchError,
    Sleep,
    default_sleep,
    extract_cves,
    fetch,
    parse_dt,
    unique,
    url_host,
)

log = logging.getLogger(__name__)

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_ENTRIES_PER_FEED = 200
MAX_SUMMARY_CHARS = 2000
MAX_TAGS = 10
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def strip_html(value: str | None) -> str | None:
    if not value:
        return None
    text = _WS_RE.sub(" ", html.unescape(_TAG_RE.sub(" ", value))).strip()
    return text or None


def _entry_time(entry: Any) -> datetime | None:
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        t = entry.get(key)
        if t:  # time.struct_time, already normalised to UTC by feedparser
            year, month, day, hour, minute, second = t[:6]
            return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    for key in ("published", "updated", "dc_date"):
        if entry.get(key):
            dt = parse_dt(entry.get(key))
            if dt is not None:
                return dt
    return None


def parse_feed(content: bytes, feed_url: str) -> tuple[list[IntelItemIn], str | None]:
    """Parse one feed document. Returns (items, error)."""
    parsed = feedparser.parse(content, response_headers={"content-location": feed_url})
    entries = parsed.get("entries") or []
    if parsed.get("bozo") and not entries:
        return [], f"rss: {url_host(feed_url)}: unparseable feed ({parsed.get('bozo_exception')})"
    host = url_host(feed_url)
    feed_title = strip_html((parsed.get("feed") or {}).get("title"))
    items: list[IntelItemIn] = []
    for entry in entries[:MAX_ENTRIES_PER_FEED]:
        title = strip_html(entry.get("title"))
        link = entry.get("link") or None
        if not title and not link:
            continue
        summary = strip_html(entry.get("summary") or entry.get("description"))
        content_text = " ".join(strip_html(c.get("value")) or "" for c in entry.get("content") or [])
        tags = [str(t.get("term")) for t in entry.get("tags") or [] if t.get("term")]
        if feed_title:
            tags.append(feed_title)
        items.append(
            IntelItemIn(
                source=f"rss:{host}",
                url=link,
                title=title or link or "(untitled)",
                summary=summary[:MAX_SUMMARY_CHARS] if summary else None,
                published=_entry_time(entry),
                vuln_ids=extract_cves(title, summary, content_text),
                tags=unique(tags)[:MAX_TAGS],
            )
        )
    return items, None


@register_source
class RssSource(IntelSource):
    id = "rss"
    name = "RSS / Atom feeds"
    attribution = "Each feed's publisher (see item links)"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.sleep: Sleep = default_sleep

    async def fetch(self, client: httpx.AsyncClient, since: datetime | None) -> SourceResult:
        result = SourceResult()
        for url in self.settings.intel.rss_feeds:
            try:
                resp = await fetch(
                    client,
                    "GET",
                    url,
                    headers={
                        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"
                    },
                    max_bytes=MAX_FEED_BYTES,
                    sleep=self.sleep,
                )
            except FetchError as exc:
                result.errors.append(f"rss: {url_host(url)}: {exc}")
                continue
            items, error = parse_feed(resp.content, url)  # configured URL: stable source label
            if error:
                result.errors.append(error)
            result.items.extend(items)
        log.info("rss: %d items from %d feeds", len(result.items), len(self.settings.intel.rss_feeds))
        return result
