from __future__ import annotations

import gzip
import zlib

import pytest

from tokiwa.gate.proxy import (
    UpstreamTarget,
    decode_content,
    encode_snippet,
    forwarded_request_headers,
    inject_before_body_close,
    raw_path_of,
    restrict_accept_encoding,
    strip_hop_by_hop,
)


def test_strip_hop_by_hop_including_connection_tokens() -> None:
    headers = [
        (b"Host", b"a"),
        (b"Connection", b"keep-alive, X-Private"),
        (b"Keep-Alive", b"timeout=5"),
        (b"X-Private", b"1"),
        (b"TE", b"trailers"),
        (b"Transfer-Encoding", b"chunked"),
        (b"Proxy-Authorization", b"Basic xyz"),
        (b"Upgrade", b"h2c"),
        (b"Accept", b"*/*"),
    ]
    assert strip_hop_by_hop(headers) == [(b"host", b"a"), (b"accept", b"*/*")]


def _fwd(raw: list[tuple[bytes, bytes]], **kw: object) -> dict[bytes, bytes]:
    args: dict[str, object] = {
        "peer_ip": "203.0.113.7",
        "scheme": "http",
        "trust_forwarded_for": False,
        "preserve_host": True,
        "upstream_host": "127.0.0.1:3000",
        "restrict_encoding": False,
    }
    args.update(kw)
    out = forwarded_request_headers(raw, **args)  # type: ignore[arg-type]
    names = [k for k, _ in out]
    assert len(names) == len(set(names)), names
    return dict(out)


def test_untrusted_client_cannot_spoof_forwarded_headers() -> None:
    out = _fwd(
        [
            (b"host", b"shop.example"),
            (b"x-forwarded-for", b"127.0.0.1"),
            (b"x-forwarded-proto", b"https"),
            (b"x-forwarded-host", b"admin.internal"),
        ]
    )
    assert out[b"x-forwarded-for"] == b"203.0.113.7"
    assert out[b"x-forwarded-proto"] == b"http"
    assert out[b"x-forwarded-host"] == b"shop.example"
    assert out[b"host"] == b"shop.example"


def test_trusted_chain_is_appended() -> None:
    out = _fwd(
        [
            (b"host", b"shop.example"),
            (b"x-forwarded-for", b"198.51.100.1"),
            (b"X-Forwarded-For", b"198.51.100.2"),
            (b"x-forwarded-proto", b"https"),
        ],
        trust_forwarded_for=True,
    )
    assert out[b"x-forwarded-for"] == b"198.51.100.1, 198.51.100.2, 203.0.113.7"
    assert out[b"x-forwarded-proto"] == b"https"


def test_rewrite_host_and_te_smuggling_hygiene() -> None:
    out = _fwd(
        [(b"host", b"shop.example"), (b"transfer-encoding", b"chunked"), (b"content-length", b"5")],
        preserve_host=False,
    )
    assert out[b"host"] == b"127.0.0.1:3000"
    assert b"content-length" not in out and b"transfer-encoding" not in out
    assert out[b"x-forwarded-host"] == b"shop.example"


def test_accept_encoding_restricted_only_when_injecting() -> None:
    raw = [(b"accept-encoding", b"gzip, deflate, br, zstd")]
    assert _fwd(raw)[b"accept-encoding"] == b"gzip, deflate, br, zstd"
    assert _fwd(raw, restrict_encoding=True)[b"accept-encoding"] == b"gzip, deflate"
    assert restrict_accept_encoding(b"br;q=1.0, zstd") == b"identity"
    assert restrict_accept_encoding(b"gzip;q=0.8, br") == b"gzip;q=0.8"


def test_upstream_target_keeps_raw_target() -> None:
    target = UpstreamTarget("http://app.internal:3000/base/")
    url, raw = target.resolve(b"/static/../admin%2Fx", b"q=%27or%201=1--")
    assert raw == b"/base/static/../admin%2Fx?q=%27or%201=1--"
    assert url.host == "app.internal" and url.port == 3000
    assert target.host_header == "app.internal:3000"
    assert UpstreamTarget("http://h").resolve(b"", b"")[1] == b"/"
    with pytest.raises(ValueError):
        UpstreamTarget("ftp://h")


def test_raw_path_fallback() -> None:
    assert raw_path_of({"raw_path": b"/a%20b"}) == b"/a%20b"
    assert raw_path_of({"path": "/a b"}) == b"/a%20b"


def test_inject_before_last_body_close() -> None:
    html = b"<html><body><p>x</p><!-- </body> in a comment --></BODY ></html>"
    out = inject_before_body_close(html, b"<i>c</i>")
    assert out == b"<html><body><p>x</p><!-- </body> in a comment --><i>c</i></BODY ></html>"
    assert inject_before_body_close(b"<div>frag</div>", b"x") is None


def test_encode_snippet_follows_charset() -> None:
    assert encode_snippet("注意", "text/html; charset=Shift_JIS") == "注意".encode("shift_jis")
    assert encode_snippet("注意", "text/html; charset=iso-8859-1") == b"&#27880;&#24847;"
    assert encode_snippet("注意", "text/html; charset=bogus") == "注意".encode()
    assert encode_snippet("x", None) == b"x"


def test_decode_content() -> None:
    data = b"<html><body>hello</body></html>" * 10
    assert decode_content(data, "", 10_000) == data
    assert decode_content(gzip.compress(data), "gzip", 10_000) == data
    assert decode_content(zlib.compress(data), "deflate", 10_000) == data
    raw_deflate = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    assert decode_content(raw_deflate.compress(data) + raw_deflate.flush(), "deflate", 10_000) == data
    assert decode_content(b"opaque", "br", 10_000) is None
    assert decode_content(gzip.compress(data), "gzip, gzip", 10_000) is None
    assert decode_content(gzip.compress(data)[:20], "gzip", 10_000) is None  # truncated
    assert decode_content(b"not gzip at all", "gzip", 10_000) is None
    assert decode_content(data, "identity", 10) is None  # over the limit


def test_decode_content_bomb_guard() -> None:
    bomb = gzip.compress(b"\x00" * 50_000_000)  # ~50 KB compressed -> 50 MB
    assert len(bomb) < 100_000
    assert decode_content(bomb, "gzip", 1_000_000) is None
