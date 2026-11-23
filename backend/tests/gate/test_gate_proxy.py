from __future__ import annotations

import gzip
import zlib

import pytest

from tokiwa.gate.proxy import (
    UpstreamTarget,
    decode_content,
    encode_snippet,
    forwarded_element,
    forwarded_request_headers,
    inject_before_body_close,
    raw_path_of,
    restrict_accept_encoding,
    strip_hop_by_hop,
    stripped_client_headers,
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


SPOOF = [
    (b"host", b"shop.example"),
    (b"Forwarded", b"for=198.51.100.9;proto=https"),
    (b"X-Real-IP", b"198.51.100.9"),
    (b"True-Client-IP", b"198.51.100.9"),
    (b"CF-Connecting-IP", b"198.51.100.9"),
    (b"X-Client-IP", b"198.51.100.9"),
    (b"X-Cluster-Client-IP", b"198.51.100.9"),
    (b"Fastly-Client-IP", b"198.51.100.9"),
    (b"X-Forwarded-Port", b"443"),
    (b"X-Forwarded-Prefix", b"/admin"),
    (b"X-Forwarded-Ssl", b"on"),
    (b"X-Original-URL", b"/.env"),
    (b"X-Rewrite-URL", b"/admin/config.php"),
    (b"accept", b"*/*"),
]


def test_client_address_and_route_claims_are_replaced() -> None:
    """Audit #138/#147: only the Gate's own view of the client reaches the upstream, whichever header it reads."""
    out = _fwd(SPOOF)
    removed = {k.lower() for k, _ in SPOOF} - {b"host", b"accept", b"forwarded", b"x-real-ip"}
    assert not removed & set(out), removed & set(out)
    assert out[b"x-real-ip"] == b"203.0.113.7"
    assert out[b"forwarded"] == b"for=203.0.113.7;proto=http;host=shop.example"
    assert out[b"x-forwarded-for"] == b"203.0.113.7" and out[b"accept"] == b"*/*"
    assert stripped_client_headers(SPOOF, frozenset()) == sorted(
        k.decode().lower() for k, _ in SPOOF if k.lower() not in (b"host", b"accept")
    )


def test_trusted_mode_keeps_the_xff_chain_and_never_builds_forwarded_from_it() -> None:
    raw = [
        (b"host", b"shop.example"),
        (b"x-forwarded-for", b"1.2.3.4;proto=https;host=evil.example, 198.51.100.20"),
        (b"x-forwarded-proto", b"https"),
        (b"forwarded", b"for=6.6.6.6"),
    ]
    out = _fwd(raw, trust_forwarded_for=True, client_ip="198.51.100.20")
    assert out[b"x-forwarded-for"] == b"1.2.3.4;proto=https;host=evil.example, 198.51.100.20, 203.0.113.7"
    assert out[b"forwarded"] == b"for=198.51.100.20;proto=https;host=shop.example"
    assert out[b"x-real-ip"] == b"198.51.100.20"


def test_forwarded_element_quotes_ipv6_and_odd_hosts() -> None:
    assert forwarded_element("2001:db8::1", "https", "shop.example:8443") == (
        b'for="[2001:db8::1]";proto=https;host="shop.example:8443"'
    )
    assert (
        forwarded_element(None, "http", 'x";for=1.1.1.1') == b'for=unknown;proto=http;host="x\\";for=1.1.1.1"'
    )
    assert forwarded_element("::ffff:192.0.2.1", "http", None) == b"for=192.0.2.1;proto=http"


def test_pass_through_keeps_named_headers_from_a_trusted_front_proxy() -> None:
    keep = frozenset({b"cf-connecting-ip", b"x-real-ip"})
    out = _fwd(SPOOF, pass_through=keep)
    assert out[b"cf-connecting-ip"] == b"198.51.100.9"
    assert out[b"x-real-ip"] == b"198.51.100.9"  # the front proxy's value, the Gate adds none of its own
    assert b"true-client-ip" not in out and b"x-original-url" not in out
    assert "cf-connecting-ip" not in stripped_client_headers(SPOOF, keep)


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
