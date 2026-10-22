"""Helpers shared by the intel source adapters (ID normalisation, dates, CPE, HTTP with retry + size cap).

This module starts with ``_`` so ``tokiwa.plugins.import_submodules`` does not treat it as a source plugin.

Why a custom HTTP wrapper instead of ``client.get``:

- Every feed is *untrusted input*: responses are read with a hard byte cap so a hostile/misconfigured feed
  cannot exhaust memory.
- Public vulnerability APIs throttle aggressively (NVD answers 403/503 when its rolling window is exceeded),
  so retry with backoff and ``Retry-After`` is built in.
- ``sleep`` is injectable so tests never wait for real rate-limit delays.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, date, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from tokiwa import __version__
from tokiwa.schemas.common import Severity
from tokiwa.schemas.intel import SoftwareItem
from tokiwa.util import ensure_utc

Sleep = Callable[[float], Awaitable[None]]

USER_AGENT = f"TOKIWA/{__version__} (vulnerability-intel-sync)"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024  # the full NVD page (2000 CVEs) is ~10-30 MB; KEV ~1.5 MB
RETRY_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 120.0

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CVE_FULL_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_URL_RE = re.compile(r"https?://[^\s;,<>\"']+")


class FetchError(Exception):
    """A feed request failed after retries (message never contains credentials)."""


_SLEEP: Sleep = asyncio.sleep  # tests replace this module attribute to skip real rate-limit waits


async def default_sleep(seconds: float) -> None:
    """Rate-limit / backoff sleep used by every source (resolved at call time so tests can patch ``_SLEEP``)."""
    await _SLEEP(seconds)


# ---------------------------------------------------------------------------- ids


def is_cve(value: str | None) -> bool:
    return bool(value) and bool(_CVE_FULL_RE.match(value or ""))


def normalize_vuln_id(value: str) -> str:
    """Canonical spelling: ``CVE-…`` upper-case, ``GHSA-xxxx-xxxx-xxxx`` (prefix upper, body lower as GitHub
    publishes it), ``JVNDB-…`` upper-case. Unknown schemes (PYSEC-, GO-, RUSTSEC- …) are only stripped."""
    v = value.strip()
    upper = v.upper()
    if upper.startswith("CVE-"):
        return upper
    if upper.startswith("GHSA-"):
        return "GHSA-" + v[5:].lower()
    if upper.startswith("JVNDB-"):
        return upper
    return v


def extract_cves(*texts: str | None) -> list[str]:
    """Unique CVE ids (upper-case, first-seen order) mentioned in free text."""
    seen: dict[str, None] = {}
    for text in texts:
        if not text:
            continue
        for m in CVE_RE.findall(text):
            seen.setdefault(m.upper(), None)
    return list(seen)


def extract_urls(text: str | None) -> list[str]:
    return unique(_URL_RE.findall(text or ""))


def unique(values: Iterable[str]) -> list[str]:
    out: dict[str, None] = {}
    for v in values:
        if v:
            out.setdefault(v, None)
    return list(out)


def url_host(url: str) -> str:
    return (urlsplit(url).hostname or url).lower()


# ---------------------------------------------------------------------------- dates


def parse_dt(value: Any) -> datetime | None:
    """ISO-8601 (with/without offset, ``Z``, date-only) -> aware UTC. Naive values are assumed to be UTC
    (NVD 2.0 timestamps such as ``2024-01-10T15:15:08.123`` carry no offset and are UTC)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    s = str(value).strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        return ensure_utc(datetime.fromisoformat(s))
    except ValueError:
        pass
    try:
        return ensure_utc(parsedate_to_datetime(s))  # RFC 2822 (RSS pubDate)
    except (TypeError, ValueError, IndexError):
        return None


def http_date(dt: datetime) -> str:
    """RFC 9110 IMF-fixdate for ``If-Modified-Since``."""
    return ensure_utc(dt).strftime("%a, %d %b %Y %H:%M:%S GMT")


# ---------------------------------------------------------------------------- severity


_SEVERITY_WORDS = {
    "none": Severity.INFO,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,  # GitHub / OSV database_specific wording
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def severity_from_text(value: str | None) -> Severity | None:
    if not value:
        return None
    return _SEVERITY_WORDS.get(str(value).strip().lower())


def severity_from_score(score: float | None) -> Severity | None:
    """CVSS v3.x/v4.0 qualitative rating scale (FIRST CVSS v3.1 spec §5, v4.0 spec)."""
    if score is None:
        return None
    if score == 0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def to_float(value: Any) -> float | None:
    try:
        return None if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------- CPE

_CPE23_SPLIT = re.compile(r"(?<!\\):")


def cpe23_fields(cpe: str) -> list[str] | None:
    """Split a CPE 2.3 formatted string (``cpe:2.3:part:vendor:product:version:update:…``) honouring ``\\:``
    escapes. Returns the 11 attribute values after the ``cpe:2.3`` prefix, or None if malformed."""
    parts = _CPE23_SPLIT.split(cpe.strip())
    if len(parts) < 5 or parts[0].lower() != "cpe" or parts[1] != "2.3":
        return None
    attrs = parts[2:]
    attrs += ["*"] * (11 - len(attrs))
    return attrs[:11]


def cpe22_to_23(uri: str) -> str | None:
    """Convert a CPE 2.2 URI (``cpe:/a:vendor:product:version``, as used by JVN iPedia) to a CPE 2.3 formatted
    string with ``*`` for missing attributes. Packed ``~`` editions and percent-encoding are kept verbatim
    (good enough for vendor/product/version matching; full NISTIR 7695 binding is out of scope)."""
    s = uri.strip()
    if not s.lower().startswith("cpe:/"):
        return None
    comps = s[5:].split(":")
    if not comps or comps[0] not in {"a", "o", "h"}:
        return None
    comps = [c if c else "*" for c in comps]
    comps += ["*"] * (11 - len(comps))
    return "cpe:2.3:" + ":".join(comps[:11])


def _cpe_value(value: str) -> str | None:
    if value in {"*", "-", ""}:
        return None
    return value.replace("\\", "")


def software_from_cpe(cpe23: str) -> SoftwareItem | None:
    attrs = cpe23_fields(cpe23)
    if attrs is None:
        return None
    product = _cpe_value(attrs[2])
    if product is None:
        return None
    return SoftwareItem(vendor=_cpe_value(attrs[1]), product=product, version=_cpe_value(attrs[3]), cpe=cpe23)


def software_key(item: SoftwareItem) -> tuple[str, str, str, str, str]:
    return (
        (item.vendor or "").lower(),
        item.product.lower(),
        item.version or "",
        item.cpe or "",
        (item.ecosystem or "").lower(),
    )


def unique_software(items: Iterable[SoftwareItem], limit: int | None = None) -> list[SoftwareItem]:
    seen: set[tuple[str, str, str, str, str]] = set()
    out: list[SoftwareItem] = []
    for item in items:
        key = software_key(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if limit is not None and len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------- HTTP


def _retry_after_seconds(resp: httpx.Response) -> float | None:
    value = resp.headers.get("retry-after")
    if not value:
        return None
    try:
        return min(MAX_RETRY_AFTER_SECONDS, max(0.0, float(value)))
    except ValueError:
        when = parse_dt(value)
        if when is None:
            return None
        delta = (when - datetime.now(UTC)).total_seconds()
        return min(MAX_RETRY_AFTER_SECONDS, max(0.0, delta))


def _safe_url(url: httpx.URL | str) -> str:
    """URL without the query string (keeps error messages short; credentials never travel in queries here)."""
    u = httpx.URL(str(url))
    return str(u.copy_with(query=None))


async def fetch(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: Any = None,
    headers: dict[str, str] | None = None,
    retries: int = 2,
    retry_statuses: frozenset[int] = RETRY_STATUSES,
    base_delay: float = 2.0,
    sleep: Sleep = default_sleep,
    max_bytes: int = MAX_RESPONSE_BYTES,
    ok_statuses: frozenset[int] = frozenset({200, 304}),
) -> httpx.Response:
    """Request with retry/backoff and a response-size cap. Raises :class:`FetchError` on final failure."""
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    attempt = 0
    while True:
        delay: float | None = None
        try:
            async with client.stream(method, url, params=params, json=json_body, headers=hdrs) as resp:
                if resp.status_code in retry_statuses and attempt < retries:
                    delay = _retry_after_seconds(resp)
                    if delay is None:
                        delay = base_delay * (2**attempt)
                else:
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > max_bytes:
                            raise FetchError(f"response from {_safe_url(resp.url)} exceeds {max_bytes} bytes")
                        chunks.append(chunk)
                    out = httpx.Response(
                        resp.status_code, headers=resp.headers, content=b"".join(chunks), request=resp.request
                    )
                    if out.status_code not in ok_statuses:
                        raise FetchError(f"HTTP {out.status_code} from {_safe_url(out.request.url)}")
                    return out
        except httpx.TransportError as exc:
            if attempt >= retries:
                raise FetchError(f"{type(exc).__name__} for {_safe_url(url)}: {exc}") from exc
            delay = base_delay * (2**attempt)
        attempt += 1
        await sleep(delay)
