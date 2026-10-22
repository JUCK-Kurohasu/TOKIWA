"""Caddy v2 structured access log (``log { format json }``) -> HTTP :class:`Event` (dataset ``caddy.access``).

Shape (Caddy 2.5+)::

    {"level":"info","ts":1729591200.12,"logger":"http.log.access.log0","msg":"handled request",
     "request":{"remote_ip":"203.0.113.7","remote_port":"51234","client_ip":"203.0.113.7","proto":"HTTP/1.1",
                "method":"GET","host":"app.lab","uri":"/x?y=1","headers":{"User-Agent":["curl/8.5"]},
                "tls":{...}},
     "bytes_read":0,"duration":0.0012,"size":512,"status":200,"resp_headers":{"Content-Type":["text/html"]}}

Older versions use ``request.remote_addr`` (``ip:port``). ``ts`` / ``duration`` may be numbers (default) or
strings when ``time_format`` / ``duration_format`` are customised; both are accepted where unambiguous.
Header values are lists; they are joined and masked. Caddy serialises headers as a Go map, so key order is
not the client's order and ``header_order`` is left empty.
"""

from __future__ import annotations

from typing import Any

from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo
from tokiwa.sensors.logtail import LineParser
from tokiwa.sensors.normalize import (
    ParseContext,
    as_dict,
    clean_headers,
    http_version,
    load_json_object,
    none_if_empty,
    normalize_ip,
    parse_ts,
    red,
    split_hostport,
    split_uri,
    to_float,
    to_int,
    truncate_raw,
)
from tokiwa.util import utcnow

DATASET = "caddy.access"


def parse_caddy_record(rec: dict[str, Any], ctx: ParseContext) -> Event | None:
    req = rec.get("request")
    if not isinstance(req, dict):
        return None
    raw_headers = as_dict(req.get("headers"))
    headers = clean_headers(raw_headers)
    resp_headers_raw = as_dict(rec.get("resp_headers"))
    resp_headers = clean_headers(resp_headers_raw)

    ip = normalize_ip(req.get("client_ip") or req.get("remote_ip"))
    port = to_int(req.get("remote_port"))
    if ip is None and req.get("remote_addr"):
        h, p = split_hostport(str(req["remote_addr"]))
        ip, port = normalize_ip(h), p
    host_header = none_if_empty(req.get("host"))
    dest_host, dest_port = split_hostport(host_header)
    path, query = split_uri(none_if_empty(req.get("uri")))
    duration = rec.get("duration")
    duration_s = to_float(duration) if isinstance(duration, int | float) else None

    http = HttpInfo(
        method=(none_if_empty(req.get("method")) or "").upper() or None,
        scheme="https" if req.get("tls") else "http",
        host=host_header,
        path=red(path),
        query=red(query),
        headers=headers,
        user_agent=headers.get("user-agent"),
        referrer=headers.get("referer"),
        content_type=headers.get("content-type"),
        request_body_size=to_int(rec.get("bytes_read")),
        status=to_int(rec.get("status")),
        response_size=to_int(rec.get("size")),
        response_content_type=resp_headers.get("content-type"),
        duration_ms=duration_s * 1000.0 if duration_s is not None else None,
        http_version=http_version(req.get("proto")),
    )
    # Raw keeps the masked headers only (never the original Cookie / Authorization values).
    raw = dict(rec)
    raw["request"] = {**req, "headers": headers}
    if resp_headers_raw:
        raw["resp_headers"] = resp_headers
    return Event(
        timestamp=parse_ts(rec.get("ts")) or utcnow(),
        kind=EventKind.HTTP,
        dataset=DATASET,
        sensor_id=ctx.sensor_id,
        host=ctx.host,
        source=Endpoint(ip=ip, port=port),
        destination=Endpoint(hostname=dest_host, port=dest_port),
        http=http,
        labels={"logger": str(rec["logger"])} if rec.get("logger") else {},
        raw=truncate_raw(raw),
    )


class CaddyJsonParser(LineParser):
    name = "caddy"

    def __init__(self, ctx: ParseContext) -> None:
        self.ctx = ctx

    def parse(self, line: str) -> list[Event]:
        rec = load_json_object(line)
        if rec is None:
            return []
        ev = parse_caddy_record(rec, self.ctx)
        return [ev] if ev is not None else []
