"""Reverse-proxy mechanics: header hygiene, upstream target, response rewriting for HTML canary injection.

Kept free of policy logic so it can be unit-tested in isolation (the request flow lives in ``gate.app``).
"""

from __future__ import annotations

import codecs
import re
import zlib
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote

import httpx

Headers = list[tuple[bytes, bytes]]

# RFC 9110 §7.6.1 + legacy proxy headers. Never forwarded in either direction.
HOP_BY_HOP = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"proxy-connection",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
    }
)
FORWARDED_HEADERS = frozenset({b"x-forwarded-for", b"x-forwarded-proto", b"x-forwarded-host"})
_DECODABLE = frozenset({"gzip", "x-gzip", "deflate", "identity"})
_BODY_CLOSE = re.compile(rb"</body\s*>", re.IGNORECASE)
_CHARSET = re.compile(r"charset\s*=\s*\"?([A-Za-z0-9._:-]+)", re.IGNORECASE)


def connection_tokens(headers: Iterable[tuple[bytes, bytes]]) -> set[bytes]:
    """Header names listed in ``Connection:`` are hop-by-hop for this message too (RFC 9110 §7.6.1)."""
    tokens: set[bytes] = set()
    for k, v in headers:
        if k.lower() == b"connection":
            tokens.update(t.strip().lower() for t in v.split(b",") if t.strip())
    return tokens


def strip_hop_by_hop(headers: Iterable[tuple[bytes, bytes]]) -> Headers:
    headers = list(headers)
    drop = HOP_BY_HOP | connection_tokens(headers)
    return [(k.lower(), v) for k, v in headers if k.lower() not in drop]


def restrict_accept_encoding(value: bytes) -> bytes:
    """Keep only codings the gate can decode, so HTML canary injection also works for brotli/zstd clients."""
    kept = []
    for part in value.split(b","):
        coding = part.split(b";", 1)[0].strip().lower().decode("latin-1")
        if coding in _DECODABLE:
            kept.append(part.strip())
    return b", ".join(kept) if kept else b"identity"


def forwarded_request_headers(
    raw: Headers,
    *,
    peer_ip: str | None,
    scheme: str,
    trust_forwarded_for: bool,
    preserve_host: bool,
    upstream_host: str,
    restrict_encoding: bool,
) -> Headers:
    """Headers sent upstream.

    - hop-by-hop removed; ``Content-Length`` dropped when the client used ``Transfer-Encoding`` (smuggling hygiene)
    - ``X-Forwarded-*``: when the client side is *not* trusted, client-supplied values are discarded and replaced
      by what the gate observed (an attacker cannot spoof its address to the upstream app through the gate);
      when trusted (``trust_forwarded_for``), the peer is appended to the existing chain as usual.
    """
    had_te = any(k.lower() == b"transfer-encoding" for k, _ in raw)
    out = strip_hop_by_hop(raw)
    original_host = next((v for k, v in out if k == b"host"), b"")
    incoming: dict[bytes, bytes] = {}
    for k, v in out:
        if k in FORWARDED_HEADERS:  # repeated header lines form one comma-separated list
            incoming[k] = incoming[k] + b", " + v if k in incoming else v
    out = [(k, v) for k, v in out if k not in FORWARDED_HEADERS]
    if had_te:
        out = [(k, v) for k, v in out if k != b"content-length"]
    if not preserve_host:
        out = [(k, v) for k, v in out if k != b"host"]
        out.append((b"host", upstream_host.encode("latin-1")))
    if restrict_encoding:
        out = [(k, restrict_accept_encoding(v) if k == b"accept-encoding" else v) for k, v in out]

    peer = (peer_ip or "unknown").encode("latin-1")
    if trust_forwarded_for and incoming.get(b"x-forwarded-for"):
        xff = incoming[b"x-forwarded-for"] + b", " + peer
    else:
        xff = peer
    proto = incoming.get(b"x-forwarded-proto") if trust_forwarded_for else None
    fhost = incoming.get(b"x-forwarded-host") if trust_forwarded_for else None
    out.append((b"x-forwarded-for", xff))
    out.append((b"x-forwarded-proto", proto or scheme.encode("latin-1")))
    if fhost or original_host:
        out.append((b"x-forwarded-host", fhost or original_host))
    return out


class UpstreamTarget:
    """The configured upstream (``http://127.0.0.1:3000`` or with a path prefix ``http://app:3000/base``)."""

    def __init__(self, upstream: str) -> None:
        base = httpx.URL(upstream)
        if base.scheme not in ("http", "https") or not base.host:
            raise ValueError(f"upstream must be an http(s) URL with a host, got {upstream!r}")
        self.base = base
        self.prefix = base.raw_path.split(b"?", 1)[0].rstrip(b"/")
        self.host_header = base.netloc.decode("ascii")

    def resolve(self, raw_path: bytes, query_string: bytes) -> tuple[httpx.URL, bytes]:
        """Return ``(url, raw_target)``.

        ``raw_target`` is sent verbatim as the HTTP request-target (httpcore ``target`` extension), so the gate is
        transparent like ``proxy_pass`` without a URI -- httpx would otherwise normalize ``/a/../b`` and change
        what the application sees. ``url`` carries scheme/host/port and a best-effort path for transports that
        ignore the extension (e.g. in-process ASGI upstreams in tests).
        """
        target = self.prefix + (raw_path or b"/")
        if query_string:
            target += b"?" + query_string
        try:
            url = self.base.copy_with(raw_path=target)
        except (httpx.InvalidURL, ValueError, TypeError):
            url = self.base.copy_with(raw_path=self.prefix or b"/")
        return url, target


def raw_path_of(scope: Mapping[str, Any]) -> bytes:
    raw = scope.get("raw_path")
    if isinstance(raw, bytes) and raw:
        return raw.split(b"?", 1)[0]
    path = scope.get("path")
    return quote(path if isinstance(path, str) else "/", safe="/:@!$&'()*+,;=-._~%").encode("ascii")


# ---------------------------------------------------------------------------------------------- injection


def charset_of(content_type: str | None) -> str:
    if content_type:
        m = _CHARSET.search(content_type)
        if m:
            try:
                return codecs.lookup(m.group(1)).name
            except LookupError:
                pass
    return "utf-8"


def encode_snippet(snippet: str, content_type: str | None) -> bytes:
    return snippet.encode(charset_of(content_type), errors="xmlcharrefreplace")


def inject_before_body_close(html: bytes, snippet: bytes) -> bytes | None:
    """Insert ``snippet`` right before the *last* ``</body>``. None when there is no ``</body>`` (fragment/JSON)."""
    last = None
    for last in _BODY_CLOSE.finditer(html):  # noqa: B007 - we want the final match
        pass
    if last is None:
        return None
    return html[: last.start()] + snippet + html[last.start() :]


def decode_content(raw: bytes, content_encoding: str, limit: int) -> bytes | None:
    """Undo ``Content-Encoding`` when it is safe and possible.

    Returns None for unsupported codings (br, zstd, stacked codings), corrupt/truncated streams, or output larger
    than ``limit`` (decompression-bomb guard) -- the caller then passes the original bytes through untouched.
    """
    enc = content_encoding.strip().lower()
    if enc in ("", "identity"):
        return raw if len(raw) <= limit else None
    if enc in ("gzip", "x-gzip"):
        candidates = [16 + zlib.MAX_WBITS]
    elif enc == "deflate":
        candidates = [zlib.MAX_WBITS, -zlib.MAX_WBITS]  # zlib-wrapped (correct) or raw (common in the wild)
    else:
        return None
    for wbits in candidates:
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(raw, limit + 1)
        except zlib.error:
            continue
        if len(out) > limit or d.unconsumed_tail:
            return None
        if not d.eof:
            continue
        return out
    return None
