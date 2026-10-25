"""nginx JSON access log -> HTTP :class:`Event` (dataset ``nginx.access``).

The recommended ``log_format`` is in ``lab/nginx/tokiwa-json.conf`` (``escape=json``, every value quoted).
Keys are nginx variable names without ``$``; ``http_*`` / ``sent_http_*`` become request / response headers.
Unknown or missing keys are tolerated so hand-written formats (``request`` instead of ``request_uri``,
``msec`` instead of ``time_iso8601`` ...) work too.
"""

from __future__ import annotations

from typing import Any

from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo
from tokiwa.sensors.logtail import LineParser
from tokiwa.sensors.normalize import (
    ParseContext,
    clean_headers,
    http_version,
    load_json_object,
    none_if_empty,
    normalize_ip,
    parse_ts,
    red,
    split_uri,
    to_float,
    to_int,
    truncate_raw,
)
from tokiwa.util import utcnow

DATASET = "nginx.access"
_TIME_KEYS = ("time_iso8601", "time", "timestamp", "@timestamp", "msec", "time_local")
# Request variables that are not headers but carry header values.
_EXTRA_HEADERS = {"content_type": "content-type", "content_length": "content-length"}


def _first(rec: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        v = rec.get(k)
        if none_if_empty(v) is not None:
            return v
    return None


def parse_nginx_record(rec: dict[str, Any], ctx: ParseContext) -> Event | None:
    method = none_if_empty(rec.get("request_method"))
    uri = none_if_empty(rec.get("request_uri"))
    protocol = none_if_empty(rec.get("server_protocol"))
    request_line = none_if_empty(rec.get("request"))
    if request_line and (method is None or uri is None):
        parts = request_line.split(" ")
        if len(parts) >= 2:
            method = method or parts[0]
            uri = uri or parts[1]
            if len(parts) >= 3:
                protocol = protocol or parts[2]
    if uri is not None:
        path, query = split_uri(uri)
    else:
        path, query = none_if_empty(rec.get("uri")), none_if_empty(rec.get("args"))
    if method is None and path is None:
        return None  # not an access log record

    headers_in: dict[str, Any] = {}
    for key, value in rec.items():
        if key.startswith("http_"):
            headers_in[key[5:].replace("_", "-")] = value
        elif key in _EXTRA_HEADERS:
            headers_in[_EXTRA_HEADERS[key]] = value
    headers = clean_headers(headers_in)

    request_time = to_float(rec.get("request_time"))
    http = HttpInfo(
        method=method.upper() if method else None,
        scheme=none_if_empty(rec.get("scheme")),
        host=none_if_empty(_first(rec, "host", "server_name")),
        path=red(path),
        query=red(query),
        headers=headers,
        user_agent=headers.get("user-agent"),
        referrer=headers.get("referer"),
        content_type=headers.get("content-type"),
        request_body_size=to_int(rec.get("content_length")),
        status=to_int(rec.get("status")),
        response_size=to_int(_first(rec, "body_bytes_sent", "bytes_sent")),
        response_content_type=none_if_empty(rec.get("sent_http_content_type")),
        duration_ms=request_time * 1000.0 if request_time is not None else None,
        http_version=http_version(protocol),
    )
    return Event(
        timestamp=parse_ts(_first(rec, *_TIME_KEYS)) or utcnow(),
        kind=EventKind.HTTP,
        dataset=DATASET,
        sensor_id=ctx.sensor_id,
        host=ctx.host,
        source=Endpoint(
            ip=normalize_ip(_first(rec, "remote_addr", "client_ip")), port=to_int(rec.get("remote_port"))
        ),
        destination=Endpoint(
            ip=normalize_ip(rec.get("server_addr")),
            port=to_int(rec.get("server_port")),
            hostname=http.host,
        ),
        http=http,
        labels={"request_id": str(rec["request_id"])} if none_if_empty(rec.get("request_id")) else {},
        raw=truncate_raw(rec),
    )


class NginxJsonParser(LineParser):
    name = "nginx"

    def __init__(self, ctx: ParseContext) -> None:
        self.ctx = ctx

    def parse(self, line: str) -> list[Event]:
        rec = load_json_object(line)
        if rec is None:
            return []
        ev = parse_nginx_record(rec, self.ctx)
        return [ev] if ev is not None else []
