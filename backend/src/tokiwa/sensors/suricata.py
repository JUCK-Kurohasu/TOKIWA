"""Suricata EVE JSON -> :class:`Event` (dataset ``suricata.eve``; the EVE type is in ``labels``).

Mapping: ``alert`` -> IDS_ALERT, ``http`` -> HTTP, ``flow`` -> CONNECTION, ``dns`` -> DNS. Other event types
(stats, tls, fileinfo, anomaly ...) are skipped for now.

Field names follow the EVE format documentation (``src_ip``/``dest_ip``/``proto``/``app_proto``,
``alert.signature_id``/``alert.severity`` with 1 = most severe). DNS records changed shape across Suricata
versions (v1 one record per answer, v2 grouped ``answers``, v3 ``queries``/``answers`` arrays); all are read.
TODO(verify): DNS v3 field layout against a Suricata 8 sample once the lab runs it.
"""

from __future__ import annotations

from typing import Any

from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo, IdsInfo, NetworkInfo
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
    split_uri,
    to_int,
    truncate_raw,
)
from tokiwa.util import utcnow

DATASET = "suricata.eve"


def _http_info(h: dict[str, Any], app_proto_tls: bool = False) -> HttpInfo:
    req_headers: dict[str, Any] = {}
    for item in h.get("request_headers") or []:
        if isinstance(item, dict) and item.get("name"):
            req_headers[str(item["name"])] = item.get("value", "")
    if h.get("http_user_agent") and "user-agent" not in {k.lower() for k in req_headers}:
        req_headers["user-agent"] = h["http_user_agent"]
    headers = clean_headers(req_headers)
    path, query = split_uri(none_if_empty(h.get("url")))
    return HttpInfo(
        method=none_if_empty(h.get("http_method")),
        scheme="https" if app_proto_tls else "http",
        host=none_if_empty(h.get("hostname")),
        path=red(path),
        query=red(query),
        headers=headers,
        user_agent=red(h.get("http_user_agent")),
        referrer=red(h.get("http_refer")),
        status=to_int(h.get("status")),
        response_size=to_int(h.get("length")),
        response_content_type=none_if_empty(h.get("http_content_type")),
        http_version=http_version(h.get("protocol")),
    )


def _duration_ms(flow: dict[str, Any]) -> float | None:
    start, end = parse_ts(flow.get("start")), parse_ts(flow.get("end"))
    if start and end and end >= start:
        return (end - start).total_seconds() * 1000.0
    age = to_int(flow.get("age"))
    return age * 1000.0 if age is not None else None


def _dns_fields(dns: dict[str, Any]) -> dict[str, str]:
    labels: dict[str, str] = {}
    rrname = dns.get("rrname")
    rrtype = dns.get("rrtype")
    queries = dns.get("queries")
    if not rrname and isinstance(queries, list) and queries and isinstance(queries[0], dict):
        rrname, rrtype = queries[0].get("rrname"), queries[0].get("rrtype")
    if rrname:
        labels["dns.query"] = str(rrname)[:255]
    if rrtype:
        labels["dns.rrtype"] = str(rrtype)
    if dns.get("type"):
        labels["dns.type"] = str(dns["type"])
    if dns.get("rcode"):
        labels["dns.rcode"] = str(dns["rcode"])
    answers: list[str] = []
    if dns.get("rdata"):
        answers.append(str(dns["rdata"]))
    for a in dns.get("answers") or []:
        if isinstance(a, dict) and a.get("rdata"):
            answers.append(str(a["rdata"]))
    grouped = dns.get("grouped")
    if isinstance(grouped, dict):
        for values in grouped.values():
            if isinstance(values, list):
                answers.extend(str(v) for v in values if not isinstance(v, dict))
    if answers:
        labels["dns.answers"] = ",".join(answers[:10])[:512]
    return labels


def parse_eve_record(rec: dict[str, Any], ctx: ParseContext) -> Event | None:
    etype = none_if_empty(rec.get("event_type"))
    if etype not in {"alert", "http", "flow", "dns"}:
        return None
    transport = (none_if_empty(rec.get("proto")) or "").lower() or None
    app_proto = none_if_empty(rec.get("app_proto"))
    labels: dict[str, str] = {"suricata.event_type": etype}
    if rec.get("flow_id") is not None:
        labels["flow_id"] = str(rec["flow_id"])
    if rec.get("community_id"):
        labels["community_id"] = str(rec["community_id"])
    if rec.get("in_iface"):
        labels["in_iface"] = str(rec["in_iface"])
    base: dict[str, Any] = {
        "timestamp": parse_ts(rec.get("timestamp")) or utcnow(),
        "dataset": DATASET,
        "sensor_id": ctx.sensor_id,
        "host": ctx.host,
        "source": Endpoint(ip=normalize_ip(rec.get("src_ip")), port=to_int(rec.get("src_port"))),
        "destination": Endpoint(ip=normalize_ip(rec.get("dest_ip")), port=to_int(rec.get("dest_port"))),
        "labels": labels,
        "raw": truncate_raw(rec),
    }
    http_rec = rec.get("http") if isinstance(rec.get("http"), dict) else None
    tls = app_proto in {"tls", "http2"} and rec.get("tls") is not None

    if etype == "alert":
        a = as_dict(rec.get("alert"))
        ids = IdsInfo(
            engine="suricata",
            signature=none_if_empty(a.get("signature")),
            signature_id=to_int(a.get("signature_id")),
            category=none_if_empty(a.get("category")),
            severity=to_int(a.get("severity")),
            action=none_if_empty(a.get("action")),
        )
        return Event(
            kind=EventKind.IDS_ALERT,
            message=ids.signature,
            ids=ids,
            http=_http_info(http_rec, tls) if http_rec else None,
            network=NetworkInfo(transport=transport, protocol=app_proto),
            **base,
        )
    if etype == "http":
        if http_rec is None:
            return None
        return Event(
            kind=EventKind.HTTP,
            http=_http_info(http_rec, tls),
            network=NetworkInfo(transport=transport, protocol="http"),
            **base,
        )
    if etype == "flow":
        flow = as_dict(rec.get("flow"))
        tcp = as_dict(rec.get("tcp"))
        pkts = [to_int(flow.get("pkts_toserver")), to_int(flow.get("pkts_toclient"))]
        return Event(
            kind=EventKind.CONNECTION,
            network=NetworkInfo(
                transport=transport,
                protocol=app_proto,
                state=none_if_empty(tcp.get("state")) or none_if_empty(flow.get("state")),
                bytes_out=to_int(flow.get("bytes_toserver")),
                bytes_in=to_int(flow.get("bytes_toclient")),
                packets=sum(p for p in pkts if p is not None) if any(p is not None for p in pkts) else None,
                duration_ms=_duration_ms(flow),
            ),
            **base,
        )
    # dns
    dns = as_dict(rec.get("dns"))
    dns_labels = _dns_fields(dns)
    labels.update(dns_labels)
    parts = ["dns", *(dns_labels.get(k) for k in ("dns.type", "dns.query", "dns.rrtype"))]
    return Event(
        kind=EventKind.DNS,
        message=" ".join(p for p in parts if p),
        network=NetworkInfo(transport=transport, protocol="dns"),
        **base,
    )


class SuricataEveParser(LineParser):
    name = "suricata"

    def __init__(self, ctx: ParseContext) -> None:
        self.ctx = ctx

    def parse(self, line: str) -> list[Event]:
        rec = load_json_object(line)
        if rec is None:
            return []
        ev = parse_eve_record(rec, self.ctx)
        return [ev] if ev is not None else []
