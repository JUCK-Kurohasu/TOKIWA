"""Import ARTEX (ARTEX-JP) recorded traffic as a labelled TOKIWA dataset (purple-team evaluation, FR-20).

ARTEX records every target HTTP exchange through its MITM proxy. Formats observed in the ARTEX-JP source tree
(read for the format only — AGPL-3.0, no code reused; see docs/purple-team.md):

1. **Task-archive traffic snapshot** ``traffic/traffic.json`` (``{"version": 1, "exchanges": [...], "blobs": [...]}``)
   with large bodies under ``traffic/blobs/<sha256>.bin``. Each exchange carries ``id`` (``<unix>-<seq>``), ``ts``
   (unix seconds), ``host``, ``method``, ``url``, ``status``, ``content_type``, ``req_len``, ``resp_len``,
   ``req_head``/``resp_head`` (raw header blocks), ``req_body``/``resp_body`` (base64, Go ``[]byte``) and
   ``req_blob``/``resp_blob`` (hash when spilled). The archive itself is ``.tar.zst``: extract it first
   (``tar --zstd -xf task-....tar.zst``) — Python 3.12's stdlib has no zstd.
2. **Findings evidence ZIP**: ``evidence/<finding>/<binding>/manifest.json`` (binding + ``snapshot`` with ``url``,
   ``method``, ``status``, ``captured_at``, ``req_head``...) next to ``request.http`` / ``response.http``.
3. **Recorder index** ``<traffic dir>/_index/index.sqlite`` (tables ``exchanges`` + ``exchange_bodies``), opened
   read-only.
4. **API dumps**: JSON / JSONL of ``{"req": "<raw request>", "resp": "<raw response>"}`` objects as returned by
   ``GET /api/traffic/exchange?id=`` (optionally with ``id``/``ts``/``url``).

Raw request heads look like ``"GET /path?x=1 HTTP/1.1\\nHost: target\\nUser-Agent: ...\\n"``; response heads like
``"HTTP 200\\nContent-Type: ...\\n"``.

Caveats (TODO(verify) against newer ARTEX releases): timestamps have 1 s resolution, so exchanges within the same
second are spread evenly in ``<seq>`` order — sub-second rhythm features are approximate. ARTEX stores traffic
in plain text (no redaction); the importer applies :mod:`tokiwa.llm.redact` to headers, query and body. ARTEX
does not record its own client address, so ``source_ip`` is synthetic (``--source-ip``).
"""

from __future__ import annotations

import base64
import binascii
import io
import ipaddress
import json
import sqlite3
import tarfile
import zipfile
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tokiwa.llm.redact import redact_headers, redact_text
from tokiwa.schemas.events import Endpoint, Event, EventKind, HttpInfo

DEFAULT_SOURCE_IP = "198.51.100.200"
MAX_BODY_CHARS = 4096
_TEXTUAL = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded", "graphql")


class ArtexImportError(ValueError):
    pass


@dataclass
class RawExchange:
    id: str
    ts: float | None
    url: str
    method: str
    status: int | None
    req_head: str
    req_body: bytes = b""
    resp_head: str = ""
    req_len: int | None = None
    resp_len: int | None = None
    content_type: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------------------------------ parsing


def parse_head(head: str) -> tuple[str, list[tuple[str, str]]]:
    """Split a raw HTTP head into (start line, [(name, value)]). Tolerates CRLF and a trailing body."""
    lines = head.replace("\r\n", "\n").split("\n")
    start = lines[0].strip() if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            break
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers.append((name.strip(), value.strip()))
    return start, headers


def _status_from_head(head: str) -> int | None:
    start, _ = parse_head(head)
    parts = start.split()
    if len(parts) >= 2 and parts[0].upper().startswith("HTTP") and parts[1].isdigit():
        return int(parts[1])
    return None


def _split_raw(raw: str) -> tuple[str, str]:
    """Raw HTTP message -> (head, body)."""
    text = raw.replace("\r\n", "\n")
    head, sep, body = text.partition("\n\n")
    return head, body if sep else ""


def _b64(value: Any) -> bytes:
    if not value:
        return b""
    if isinstance(value, bytes):
        return value
    try:
        return base64.b64decode(str(value), validate=False)
    except (binascii.Error, ValueError):
        return str(value).encode("utf-8", "replace")


def _ts_from_id(ex_id: str) -> float | None:
    head = ex_id.split("-", 1)[0]
    return float(head) if head.isdigit() else None


def _seq_from_id(ex_id: str) -> int:
    tail = ex_id.rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() else 0


# ------------------------------------------------------------------------------------------ sources


def _from_archive_doc(doc: dict[str, Any], blob_reader: Any = None) -> Iterator[RawExchange]:
    version = doc.get("version")
    if version not in (None, 1):
        raise ArtexImportError(f"unsupported ARTEX traffic archive version {version!r} (expected 1)")
    for ex in doc.get("exchanges") or []:
        if not isinstance(ex, dict):
            continue
        body = _b64(ex.get("req_body"))
        if ex.get("req_blob") and blob_reader is not None:
            body = blob_reader(str(ex["req_blob"])) or body
        yield RawExchange(
            id=str(ex.get("id") or ""),
            ts=float(ex["ts"]) if isinstance(ex.get("ts"), int | float) else None,
            url=str(ex.get("url") or ""),
            method=str(ex.get("method") or ""),
            status=int(ex["status"]) if isinstance(ex.get("status"), int) else None,
            req_head=str(ex.get("req_head") or ""),
            req_body=body,
            resp_head=str(ex.get("resp_head") or ""),
            req_len=ex.get("req_len"),
            resp_len=ex.get("resp_len"),
            content_type=str(ex.get("content_type") or ""),
        )


def _from_api_objects(objs: Iterable[Any]) -> Iterator[RawExchange]:
    for n, obj in enumerate(objs):
        if not isinstance(obj, dict):
            continue
        if "req_head" in obj:  # archive-shaped exchange in a plain list
            yield from _from_archive_doc({"exchanges": [obj]})
            continue
        if "req" not in obj:
            continue
        head, body = _split_raw(str(obj.get("req") or ""))
        resp_head, _ = _split_raw(str(obj.get("resp") or ""))
        ex_id = str(obj.get("id") or f"api-{n:06d}")
        ts = obj.get("ts")
        yield RawExchange(
            id=ex_id,
            ts=float(ts) if isinstance(ts, int | float) else _ts_from_id(ex_id),
            url=str(obj.get("url") or ""),
            method="",
            status=_status_from_head(resp_head),
            req_head=head,
            req_body=body.encode(),
            resp_head=resp_head,
        )


def _from_evidence_zip(zf: zipfile.ZipFile) -> Iterator[RawExchange]:
    names = set(zf.namelist())
    for name in sorted(names):
        if not (name.startswith("evidence/") and name.endswith("/manifest.json")):
            continue
        prefix = name[: -len("manifest.json")]
        manifest = json.loads(zf.read(name))
        snap = manifest.get("snapshot") or {}
        body = b""
        if f"{prefix}request.http" in names:
            _, body_text = _split_raw(zf.read(f"{prefix}request.http").decode("utf-8", "replace"))
            body = body_text.encode()
        ex_id = str(snap.get("source_traffic_id") or snap.get("id") or prefix)
        yield RawExchange(
            id=ex_id,
            ts=float(snap["captured_at"])
            if isinstance(snap.get("captured_at"), int | float)
            else _ts_from_id(ex_id),
            url=str(snap.get("url") or ""),
            method=str(snap.get("method") or ""),
            status=int(snap["status"]) if isinstance(snap.get("status"), int) else None,
            req_head=str(snap.get("req_head") or ""),
            req_body=body,
            resp_head=str(snap.get("resp_head") or ""),
            req_len=snap.get("req_len"),
            resp_len=snap.get("resp_len"),
            content_type=str(snap.get("content_type") or ""),
            extra={"role": manifest.get("role")},
        )


def _from_sqlite(path: Path) -> Iterator[RawExchange]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT e.id, e.ts, e.url, e.method, e.status, e.content_type, e.req_len, e.resp_len, "
            "b.req_head, b.req_body, b.resp_head FROM exchanges e LEFT JOIN exchange_bodies b ON b.id = e.id "
            "ORDER BY e.ts, e.id"
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise ArtexImportError(f"{path}: not an ARTEX traffic index ({exc})") from exc
    finally:
        conn.close()
    for r in rows:
        yield RawExchange(
            id=str(r[0]),
            ts=float(r[1]) if r[1] is not None else None,
            url=str(r[2] or ""),
            method=str(r[3] or ""),
            status=int(r[4]) if r[4] is not None else None,
            content_type=str(r[5] or ""),
            req_len=r[6],
            resp_len=r[7],
            req_head=str(r[8] or ""),
            req_body=bytes(r[9] or b""),
            resp_head=str(r[10] or ""),
        )


def _from_tar(path: Path) -> Iterator[RawExchange]:
    with tarfile.open(path, "r:*") as tf:
        members = {m.name: m for m in tf.getmembers() if m.isfile()}
        docs = [n for n in members if n.endswith("traffic/traffic.json") or n == "traffic.json"]
        if not docs:
            raise ArtexImportError(f"{path}: no traffic/traffic.json inside the archive")
        for doc_name in docs:
            base = doc_name[: -len("traffic.json")]

            def read_blob(h: str, base: str = base) -> bytes | None:
                m = members.get(f"{base}blobs/{h}.bin")
                f = tf.extractfile(m) if m is not None else None
                return f.read() if f is not None else None

            fh = tf.extractfile(members[doc_name])
            if fh is None:
                continue
            yield from _from_archive_doc(json.loads(fh.read()), read_blob)


def read_artex(path: Path) -> list[RawExchange]:
    """Read raw ARTEX exchanges from any supported container (see module docstring)."""
    if not path.exists():
        raise ArtexImportError(f"{path} does not exist")
    name = path.name.lower()
    if path.is_dir():
        docs = sorted(path.rglob("traffic.json"))
        if docs:
            return [ex for doc in docs for ex in read_artex(doc)]
        idx = sorted(path.rglob("index.sqlite"))
        if idx:
            return list(_from_sqlite(idx[0]))
        raise ArtexImportError(f"{path}: no traffic.json or index.sqlite found")
    if name.endswith(".zst"):
        raise ArtexImportError(
            f"{path}: decompress first (tar --zstd -xf {path.name}) and import the directory"
        )
    if name.endswith((".tar", ".tar.gz", ".tgz")):
        return list(_from_tar(path))
    if name.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            return list(_from_evidence_zip(zf))
    if name.endswith((".sqlite", ".db", ".sqlite3")):
        return list(_from_sqlite(path))
    text = path.read_text(encoding="utf-8")
    if name.endswith(".jsonl"):
        return list(_from_api_objects(json.loads(line) for line in io.StringIO(text) if line.strip()))
    doc = json.loads(text)
    if isinstance(doc, dict) and "exchanges" in doc:
        blobs = path.parent / "blobs"

        def read_blob(h: str) -> bytes | None:
            p = blobs / f"{h}.bin"
            return p.read_bytes() if p.is_file() and p.parent == blobs else None

        return list(_from_archive_doc(doc, read_blob))
    if isinstance(doc, list):
        return list(_from_api_objects(doc))
    if isinstance(doc, dict) and "req" in doc:
        return list(_from_api_objects([doc]))
    raise ArtexImportError(f"{path}: unrecognised ARTEX traffic format")


# ------------------------------------------------------------------------------------------ to events


def _spread_timestamps(exchanges: list[RawExchange]) -> dict[str, datetime]:
    """Second-resolution ts -> distinct, ordered datetimes (exchanges in one second spread by seq)."""
    groups: dict[float, list[RawExchange]] = defaultdict(list)
    fallback = 0.0
    for ex in exchanges:
        ts = ex.ts if ex.ts is not None else _ts_from_id(ex.id)
        if ts is None:
            fallback += 1.0
            ts = fallback
        groups[ts].append(ex)
    out: dict[str, datetime] = {}
    for ts, items in groups.items():
        items.sort(key=lambda e: (_seq_from_id(e.id), e.id))
        for i, ex in enumerate(items):
            out[ex.id] = datetime.fromtimestamp(ts, UTC) + timedelta(seconds=i / len(items))
    return out


def raw_to_event(
    ex: RawExchange, ts: datetime, *, source_ip: str, session: str | None, index: int
) -> Event | None:
    start, header_list = parse_head(ex.req_head)
    parts = start.split()
    method = (ex.method or (parts[0] if parts else "")).upper() or "GET"
    target = parts[1] if len(parts) >= 2 else "/"
    proto = parts[2] if len(parts) >= 3 else "HTTP/1.1"
    headers: dict[str, str] = {}
    for k, v in header_list:
        lk = k.lower()
        headers[lk] = f"{headers[lk]}, {v}" if lk in headers else v
    url = ex.url or f"http://{headers.get('host', 'unknown')}{target}"
    u = urlsplit(url)
    if not u.hostname:
        return None
    body_text: str | None = None
    ctype = headers.get("content-type", "")
    if ex.req_body and (not ctype or any(t in ctype.lower() for t in _TEXTUAL)):
        body_text = ex.req_body[:MAX_BODY_CHARS].decode("utf-8", "replace")
    try:
        port = u.port
    except ValueError:
        port = None
    try:
        dest_ip: str | None = str(ipaddress.ip_address(u.hostname))
    except ValueError:
        dest_ip = None
    dest = Endpoint(ip=dest_ip, port=port, hostname=u.hostname)
    _, resp_headers = parse_head(ex.resp_head)
    resp_ctype = next((v for k, v in resp_headers if k.lower() == "content-type"), ex.content_type or None)
    return Event(
        timestamp=ts,
        kind=EventKind.HTTP,
        dataset="artex.traffic",
        sensor_id="artex-import",
        source=Endpoint(ip=source_ip),
        destination=dest,
        http=HttpInfo(
            method=method,
            scheme=u.scheme or "http",
            host=u.hostname,
            path=u.path or "/",
            query=redact_text(u.query) if u.query else None,
            headers=redact_headers(headers),
            header_order=[k.lower() for k, _ in header_list],
            user_agent=headers.get("user-agent"),
            referrer=headers.get("referer"),
            content_type=ctype or None,
            request_body_size=int(ex.req_len) if isinstance(ex.req_len, int) else len(ex.req_body),
            request_body=redact_text(body_text) if body_text else None,
            status=ex.status if ex.status is not None else _status_from_head(ex.resp_head),
            response_size=int(ex.resp_len) if isinstance(ex.resp_len, int) else None,
            response_content_type=resp_ctype,
            http_version=proto.split("/", 1)[1] if "/" in proto else None,
        ),
        labels={
            "actor": "ai_agent",
            "profile": "artex",
            "session": session or f"artex:{u.hostname}",
            "attack": "artex",
            "source": "artex",
            "artex_id": ex.id or str(index),
        },
    )


def _host_of(r: RawExchange) -> str:
    if r.url:
        return (urlsplit(r.url).hostname or "").lower()
    _, headers = parse_head(r.req_head)
    host = next((v for k, v in headers if k.lower() == "host"), "")
    return urlsplit(f"//{host}").hostname or ""


def import_artex(
    path: Path,
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    session: str | None = None,
    host: str | None = None,
) -> list[Event]:
    """Read ARTEX traffic and convert it to labelled events (``actor=ai_agent``), optionally for one host only."""
    raws = read_artex(path)
    if host:
        raws = [r for r in raws if _host_of(r) == host.lower()]
    seen: set[str] = set()
    for i, r in enumerate(raws):
        if not r.id or r.id in seen:
            r.id = f"{r.id or 'ex'}#{i}"
        seen.add(r.id)
    stamps = _spread_timestamps(raws)
    events = []
    for i, r in enumerate(raws):
        ev = raw_to_event(r, stamps[r.id], source_ip=source_ip, session=session, index=i)
        if ev is not None:
            events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events
