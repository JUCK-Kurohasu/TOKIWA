"""Helpers shared by the log adapters: lenient coercion, timestamps, redaction and raw-record truncation.

Log records come from software we do not control (and their string fields from remote parties), so every
helper here is total: odd input yields ``None`` instead of an exception.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime, tzinfo
from typing import Any
from urllib.parse import urlsplit

from tokiwa.llm.redact import redact_headers, redact_obj, redact_text
from tokiwa.schemas.events import HostInfo
from tokiwa.util import ensure_utc, utcnow

RAW_LIMIT_BYTES = 4096
_EMPTY = {"", "-", "(empty)"}
# Keys whose values must never leave the host, whatever they contain (Zeek http.log has ``password``).
# Account names from HTTP authentication are personal data and not needed for detection (data handling, #169):
# Zeek http.log ``username`` (Basic auth user, base/protocols/http/main.zeek), nginx ``$remote_user``,
# Caddy access log ``user_id`` (modules/caddyhttp/server.go).
_SENSITIVE_KEYS = {
    "username",
    "remote_user",
    "user_id",
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "http_authorization",
    "http_cookie",
    "http_proxy_authorization",
    "sent_http_set_cookie",
    "x-api-key",
    "http_x_api_key",
}


@dataclass
class ParseStats:
    """What a log source could not read faithfully (audit #131: format mistakes must not be silent).

    ``unparsed``: lines that are not a record of the expected format (invalid JSON, Zeek TSV without header);
    ``bad_time``: records whose timestamp could not be interpreted (the event got the collection time);
    ``naive_time``: timestamps without a UTC offset read as UTC because ``agent.log_timezone`` is unset;
    ``recovered``: nginx ``escape=default`` lines (``\\xHH``) decoded instead of dropped.
    Records that are skipped on purpose (Suricata ``stats``, non-access JSON, Zeek header lines) are not counted.
    """

    unparsed: int = 0
    bad_time: int = 0
    naive_time: int = 0
    recovered: int = 0

    def snapshot(self) -> ParseStats:
        return ParseStats(**{f.name: getattr(self, f.name) for f in fields(self)})

    def minus(self, other: ParseStats) -> ParseStats:
        return ParseStats(**{f.name: getattr(self, f.name) - getattr(other, f.name) for f in fields(self)})

    def any(self) -> bool:
        return any(getattr(self, f.name) for f in fields(self))


@dataclass(frozen=True)
class ParseContext:
    """Who/where a log line was read: stamped on every event the adapters produce.

    ``tz`` reads offset-less timestamps (``agent.log_timezone``; None = UTC, counted in ``stats.naive_time``).
    ``stats`` is per log source (the agent gives each source its own context).
    """

    sensor_id: str | None = None
    host: HostInfo | None = None
    tz: tzinfo | None = None
    stats: ParseStats = field(default_factory=ParseStats)


def none_if_empty(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return None if s in _EMPTY else s


def to_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else None
    s = str(value).strip()
    if s in _EMPTY:
        return None
    try:
        return int(s)
    except ValueError:
        try:
            f = float(s)
        except ValueError:
            return None
        return int(f) if math.isfinite(f) else None


def to_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        f = float(value)
    else:
        s = str(value).strip()
        if s in _EMPTY:
            return None
        try:
            f = float(s)
        except ValueError:
            return None
    return f if math.isfinite(f) else None


def to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    s = none_if_empty(value)
    if s is None:
        return None
    if s.lower() in {"t", "true", "1", "yes"}:
        return True
    if s.lower() in {"f", "false", "0", "no"}:
        return False
    return None


_WALL_FRACTION = re.compile(r"^(.*\.\d{6})\d+$")  # %f takes at most 6 digits (Caddy ``wall_nano``)
_TIME_FORMATS = (
    "%d/%b/%Y:%H:%M:%S %z",  # nginx $time_local, Caddy common_log
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f",  # Caddy wall_milli / wall_nano (local wall clock, no offset)
    "%Y/%m/%d %H:%M:%S",  # Caddy wall
)


def _parse_time(value: Any) -> tuple[datetime | None, bool]:
    """(datetime as parsed, had no UTC offset). Epoch numbers are UTC by definition."""
    if value is None or isinstance(value, bool):
        return None, False
    f = to_float(value) if isinstance(value, int | float) or _numeric(value) else None
    if f is not None:
        # seconds / milliseconds / microseconds / nanoseconds since the epoch (any date before year 5138)
        for limit, div in ((1e17, 1e9), (1e14, 1e6), (1e11, 1e3)):
            if abs(f) > limit:
                f /= div
                break
        try:
            return datetime.fromtimestamp(f, tz=UTC), False
        except (OverflowError, OSError, ValueError):
            return None, False
    s = str(value).strip()
    if not s or s in _EMPTY:
        return None, False
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt, dt.tzinfo is None
    except ValueError:
        pass
    s = _WALL_FRACTION.sub(r"\1", s)
    for fmt in _TIME_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
        except ValueError:
            continue
        return dt, dt.tzinfo is None
    return None, False


def parse_ts(value: Any, *, tz: tzinfo | None = None) -> datetime | None:
    """Epoch (s/ms/us/ns, number or numeric string), ISO 8601 (incl. ``+0000``), nginx ``$time_local`` or Caddy
    wall clock -> aware UTC datetime. Offset-less values are read in ``tz`` (default UTC)."""
    dt, naive = _parse_time(value)
    if dt is None:
        return None
    if naive and tz is not None:
        dt = dt.replace(tzinfo=tz)
    return ensure_utc(dt)


def event_time(value: Any, ctx: ParseContext) -> datetime:
    """Timestamp of a log record, counting what had to be guessed (audit #131). Missing -> collection time."""
    if value is None or (isinstance(value, str) and value.strip() in _EMPTY):
        return utcnow()
    dt, naive = _parse_time(value)
    if dt is None:
        ctx.stats.bad_time += 1
        return utcnow()
    if naive:
        if ctx.tz is None:
            ctx.stats.naive_time += 1
        else:
            dt = dt.replace(tzinfo=ctx.tz)
    return ensure_utc(dt)


def _numeric(value: Any) -> bool:
    try:
        float(str(value).strip())
    except ValueError:
        return False
    return True


def split_uri(uri: str | None) -> tuple[str | None, str | None]:
    """``/a/b?x=1`` -> (``/a/b``, ``x=1``). Absolute-form request targets keep only path + query."""
    if not uri:
        return None, None
    if "://" in uri[:16]:
        try:
            parts = urlsplit(uri)
        except ValueError:
            return uri, None
        return parts.path or "/", parts.query or None
    path, sep, query = uri.partition("?")
    return path or ("/" if sep else None), (query or None)


def split_hostport(value: str | None) -> tuple[str | None, int | None]:
    """``1.2.3.4:80`` / ``[::1]:80`` / ``example.com`` -> (host, port)."""
    s = none_if_empty(value)
    if s is None:
        return None, None
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host or None, to_int(rest.lstrip(":")) if rest.startswith(":") else None
    if s.count(":") == 1:
        host, _, port = s.partition(":")
        return host or None, to_int(port)
    return s, None  # bare IPv6 or hostname


def normalize_ip(ip: Any) -> str | None:
    s = none_if_empty(ip)
    if s is None:
        return None
    if s.lower().startswith("::ffff:") and "." in s:
        return s[7:]
    return s


def http_version(protocol: Any) -> str | None:
    """``HTTP/1.1`` -> ``1.1``."""
    s = none_if_empty(protocol)
    if s is None:
        return None
    return s.split("/", 1)[1] if "/" in s else s


def red(value: Any) -> str | None:
    """Redact a remote-controlled string (path, query, UA, referrer)."""
    s = none_if_empty(value)
    return redact_text(s) if s is not None else None


def clean_headers(headers: dict[str, Any]) -> dict[str, str]:
    """Lower-case names, join multi-value lists, drop empties, then mask secrets."""
    flat: dict[str, str] = {}
    for k, v in headers.items():
        if isinstance(v, list | tuple):
            v = ", ".join(str(x) for x in v)
        sv = none_if_empty(v)
        if sv is not None:
            flat[str(k).lower()] = sv
    return redact_headers(flat)


def _mask_keys(obj: Any, depth: int = 0) -> Any:
    if depth > 12:
        return "[REDACTED:depth]"
    if isinstance(obj, dict):
        # Header lists such as Suricata's [{"name": "Cookie", "value": "..."}]
        name = obj.get("name")
        if isinstance(name, str) and name.lower() in _SENSITIVE_KEYS and "value" in obj:
            return {**obj, "value": "[REDACTED:secret]"}
        out: dict[str, Any] = {}
        for k, v in obj.items():
            key = str(k)
            if key.lower().rsplit(".", 1)[-1] in _SENSITIVE_KEYS and none_if_empty(v) is not None:
                out[key] = "[REDACTED:secret]"
            else:
                out[key] = _mask_keys(v, depth + 1)
        return out
    if isinstance(obj, list | tuple):
        return [_mask_keys(v, depth + 1) for v in obj]
    return obj


def truncate_raw(record: dict[str, Any], limit: int = RAW_LIMIT_BYTES) -> dict[str, Any]:
    """Redact the original record and cap it at ``limit`` bytes of JSON (kept for forensics only)."""
    redacted = redact_obj(_mask_keys(record))
    if not isinstance(redacted, dict):
        redacted = {"value": redacted}
    text = json.dumps(redacted, ensure_ascii=False, default=str)
    if len(text.encode("utf-8")) <= limit:
        return redacted
    clipped = text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")
    return {"_truncated": True, "_bytes": len(text.encode("utf-8")), "text": clipped}


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_json_object(line: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(line)
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None
