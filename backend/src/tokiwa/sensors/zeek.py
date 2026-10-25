"""Zeek ``conn.log`` / ``http.log`` / ``notice.log`` -> :class:`Event`, TSV (ASCII writer) and JSON.

* TSV: the ``#separator`` / ``#fields`` / ``#types`` header defines the columns. When tailing starts at the
  end of a file, the header is fetched with :meth:`FileTailer.read_head` (see ``wants_header``).
* JSON (``LogAscii::use_json=T``): flat keys such as ``id.orig_h``; ``ts`` is epoch seconds or ISO 8601.

Mapping: conn -> CONNECTION (``zeek.conn``), http -> HTTP (``zeek.http``), notice -> IDS_ALERT
(``zeek.notice``). Direction comes from ``local_orig``/``local_resp`` (requires ``Site::local_nets``).
"""

from __future__ import annotations

import re
from typing import Any

from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo, IdsInfo, NetworkInfo
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
    to_bool,
    to_float,
    to_int,
    truncate_raw,
)
from tokiwa.util import utcnow

SUPPORTED = ("conn", "http", "notice")
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _unescape(value: str) -> str:
    return _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), value)


def log_type_from_name(name: str) -> str | None:
    """``conn.log`` / ``conn.10:00:00-11:00:00.log`` / ``http.json`` -> ``conn`` / ``http``."""
    stem = name.split(".", 1)[0].lower()
    return stem if stem in SUPPORTED else None


def _direction(rec: dict[str, Any]) -> str | None:
    lo, lr = to_bool(rec.get("local_orig")), to_bool(rec.get("local_resp"))
    if lo is None or lr is None:
        return None
    if lo and lr:
        return "internal"
    if lo:
        return "outbound"
    if lr:
        return "inbound"
    return None


def _first_of(value: Any) -> str | None:
    if isinstance(value, list):
        return none_if_empty(value[0]) if value else None
    return none_if_empty(value)


def zeek_record_to_event(rec: dict[str, Any], log_type: str | None, ctx: ParseContext) -> Event | None:
    log_type = (none_if_empty(rec.get("_path")) or log_type or "").lower()
    if log_type not in SUPPORTED:
        return None
    src = Endpoint(ip=normalize_ip(rec.get("id.orig_h")), port=to_int(rec.get("id.orig_p")))
    dst = Endpoint(ip=normalize_ip(rec.get("id.resp_h")), port=to_int(rec.get("id.resp_p")))
    labels = {"zeek.uid": str(rec["uid"])} if none_if_empty(rec.get("uid")) else {}
    base: dict[str, Any] = {
        "timestamp": parse_ts(rec.get("ts")) or utcnow(),
        "dataset": f"zeek.{log_type}",
        "sensor_id": ctx.sensor_id,
        "host": ctx.host,
        "labels": labels,
        "raw": truncate_raw(rec),
    }
    if log_type == "conn":
        duration = to_float(rec.get("duration"))
        pkts = [to_int(rec.get("orig_pkts")), to_int(rec.get("resp_pkts"))]
        service = none_if_empty(rec.get("service"))
        if isinstance(rec.get("service"), list):
            service = ",".join(str(s) for s in rec["service"]) or None
        return Event(
            kind=EventKind.CONNECTION,
            source=src,
            destination=dst,
            network=NetworkInfo(
                transport=none_if_empty(rec.get("proto")),
                protocol=service,
                direction=_direction(rec),
                state=none_if_empty(rec.get("conn_state")),
                # From the originator's point of view: out = sent by the source.
                bytes_out=to_int(rec.get("orig_bytes")),
                bytes_in=to_int(rec.get("resp_bytes")),
                packets=sum(p for p in pkts if p is not None) if any(p is not None for p in pkts) else None,
                duration_ms=duration * 1000.0 if duration is not None else None,
            ),
            **base,
        )
    if log_type == "http":
        path, query = split_uri(none_if_empty(rec.get("uri")))
        ua = none_if_empty(rec.get("user_agent"))
        return Event(
            kind=EventKind.HTTP,
            source=src,
            destination=Endpoint(ip=dst.ip, port=dst.port, hostname=none_if_empty(rec.get("host"))),
            http=HttpInfo(
                method=none_if_empty(rec.get("method")),
                host=none_if_empty(rec.get("host")),
                path=red(path),
                query=red(query),
                headers=clean_headers({"user-agent": ua} if ua else {}),
                user_agent=red(ua),
                referrer=red(rec.get("referrer")),
                request_body_size=to_int(rec.get("request_body_len")),
                status=to_int(rec.get("status_code")),
                response_size=to_int(rec.get("response_body_len")),
                response_content_type=_first_of(rec.get("resp_mime_types")),
                http_version=http_version(rec.get("version")),
            ),
            network=NetworkInfo(transport="tcp", protocol="http"),
            **base,
        )
    # notice
    note = none_if_empty(rec.get("note"))
    actions = rec.get("actions")
    action = ",".join(str(a) for a in actions) if isinstance(actions, list) else none_if_empty(actions)
    src_ip = normalize_ip(rec.get("src")) or src.ip
    dst_ip = normalize_ip(rec.get("dst")) or dst.ip
    if none_if_empty(rec.get("sub")):
        labels["zeek.sub"] = str(rec["sub"])[:255]
    return Event(
        kind=EventKind.IDS_ALERT,
        message=red(rec.get("msg")) or note,
        source=Endpoint(ip=src_ip, port=src.port if src_ip == src.ip else None),
        destination=Endpoint(ip=dst_ip, port=to_int(rec.get("p")) or dst.port),
        ids=IdsInfo(
            engine="zeek",
            signature=note,
            category=note.split("::", 1)[0] if note else None,
            action=action,
        ),
        network=NetworkInfo(transport=none_if_empty(rec.get("proto"))),
        **base,
    )


class ZeekParser(LineParser):
    """Stateful: remembers the TSV header of the file being tailed."""

    name = "zeek"

    def __init__(self, ctx: ParseContext, log_type: str | None = None) -> None:
        self.ctx = ctx
        self.log_type = log_type
        self.separator = "\t"
        self.set_separator = ","
        self.empty_field = "(empty)"
        self.unset_field = "-"
        self.fields: list[str] | None = None
        self.types: list[str] | None = None

    # -- header ---------------------------------------------------------------------------------------
    def _header(self, line: str) -> None:
        if line.startswith("#separator"):
            value = line[len("#separator") :].strip()
            self.separator = _unescape(value) or "\t"
            return
        key, _, value = line[1:].partition(self.separator)
        if key == "set_separator":
            self.set_separator = _unescape(value)
        elif key == "empty_field":
            self.empty_field = value
        elif key == "unset_field":
            self.unset_field = value
        elif key == "path":
            self.log_type = value.strip() or self.log_type
        elif key == "fields":
            self.fields = value.split(self.separator)
        elif key == "types":
            self.types = value.split(self.separator)

    def wants_header(self, line: str) -> bool:
        return self.fields is None and not line.startswith("#") and not line.lstrip().startswith("{")

    def feed_header(self, lines: list[str]) -> None:
        for line in lines:
            if not line.startswith("#"):
                break
            self._header(line)

    # -- records --------------------------------------------------------------------------------------
    def _tsv_record(self, line: str) -> dict[str, Any] | None:
        if self.fields is None:
            return None
        values = line.split(self.separator)
        rec: dict[str, Any] = {}
        types = self.types or []
        for i, (name, value) in enumerate(zip(self.fields, values, strict=False)):
            if value == self.unset_field:
                continue
            typ = types[i] if i < len(types) else ""
            if value == self.empty_field:
                rec[name] = [] if typ.startswith(("set[", "vector[")) else ""
            elif typ.startswith(("set[", "vector[")):
                rec[name] = [_unescape(v) for v in value.split(self.set_separator)]
            else:
                rec[name] = _unescape(value)
        return rec

    def parse(self, line: str) -> list[Event]:
        if line.startswith("#"):
            self._header(line)  # a later header block (rotated file read from the start) replaces the old
            return []
        rec = load_json_object(line) if line.lstrip().startswith("{") else self._tsv_record(line)
        if rec is None:
            return []
        ev = zeek_record_to_event(rec, self.log_type, self.ctx)
        return [ev] if ev is not None else []
