"""detect-web: unit tests for tokiwa.detect.web_common (decoding, normalisation, inspection targets)."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tokiwa.config import Settings, WebDetectionSettings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    BODY,
    BODY_RAW,
    COOKIE,
    FILENAME,
    HEADER,
    HEADER_OTHER,
    PATH,
    QUERY,
    build_view,
    clean_path,
    compile_user_regex,
    decode,
    get_view,
    normalize,
    path_key,
    snippet,
    strip_sql_comments,
    to_lower,
    web_settings,
)
from tokiwa.schemas.events import Event


@pytest.mark.parametrize(
    ("raw", "plus", "expected"),
    [
        ("%3Cscript%3E", False, "<script>"),
        ("%253Cscript%253E", False, "<script>"),  # double
        ("%25253C", False, "<"),  # triple
        ("%%32%65%%32%65%2f", False, "../"),  # nested hex digits
        ("%u003cscript%u003e", False, "<script>"),  # IIS %u
        ("%c0%ae%c0%ae%c0%af", False, "../"),  # overlong UTF-8
        ("%e0%80%ae", False, "."),
        ("&lt;svg&#x2F;onload&#61;1&gt;", False, "<svg/onload=1>"),
        ("%26lt%3Bb%26gt%3B", False, "<b>"),  # URL then HTML entity
        ("\\u003cimg\\x20src\\u003e", False, "<img src>"),  # JS escapes
        ("a+b", True, "a b"),
        ("a+b", False, "a+b"),  # paths keep '+'
        ("1%2B1", True, "1+1"),  # encoded plus survives the first round
        ("%zz%", False, "%zz%"),  # malformed stays put
    ],
)
def test_decode(raw: str, plus: bool, expected: str) -> None:
    assert decode(raw, plus=plus) == expected


def test_decode_is_bounded() -> None:
    deep = "<"
    for _ in range(10):
        deep = deep.replace("%", "%25").replace("<", "%3C")
    out = decode(deep)
    assert out != "<"  # only MAX_DECODE_ROUNDS rounds are undone (CPU guard)


def test_strip_sql_comments() -> None:
    assert strip_sql_comments("union/**/select") == "union select"
    assert strip_sql_comments("/*!50000union*/ /*!select*/") == " union   select "
    assert strip_sql_comments("a/* unterminated") == "a/* unterminated"
    assert strip_sql_comments("text/html,*/*;q=0.8") == "text/html,*/*;q=0.8"


def test_normalize_views() -> None:
    lower = to_lower("UnIoN\t/**/\n SeLeCt")
    assert normalize(lower) == "union select"
    assert to_lower("＜ＳＣＲＩＰＴ＞") == "<script>"  # NFKC full-width


def test_path_key_and_clean_path() -> None:
    assert path_key("/api/v1/users/12345/orders") == "/api/v1/users"
    assert path_key("/items/550e8400-e29b-41d4-a716-446655440000") == "/items/{id}"
    assert path_key("/static/../../etc/passwd") == "/static/{x}/etc"
    assert path_key("/") == "/"
    assert clean_path("//a\\.\\b/./c") == "/a/b/c"


def test_snippet_limits() -> None:
    text = "x" * 1000 + "PAYLOAD" + "y" * 1000
    frag = snippet(text, 1000, 1007)
    assert len(frag) <= 200 and "PAYLOAD" in frag
    assert snippet("a\x00b", 0, 3) == "a\\x00b"
    assert snippet("\ud800z", 0, 2) == "?z"


def test_build_view_targets(make_http_event: Callable[..., Event]) -> None:
    ev = make_http_event(
        "/a%2Fb",
        method="post",
        query="id=1&flag&q=a+b",
        body='{"user": {"name": "bob", "tags": ["x", "y"]}, "n": 3}',
        headers={
            "user-agent": "UA",
            "content-type": "application/json",
            "cookie": "theme=dark; sid=abc",
            "x-api-version": "1",
            "accept": "*/*",
            "authorization": "[REDACTED:authorization]",
        },
    )
    view = build_view(ev)
    assert view is not None
    assert view.method == "POST" and view.path == "/a/b" and view.host == "app.lab"
    by_loc: dict[str, list[tuple[str | None, str]]] = {}
    for t in view.targets:
        by_loc.setdefault(t.location, []).append((t.param, t.value))
    assert by_loc[PATH] == [(None, "/a/b")]
    assert by_loc[QUERY] == [("id", "1"), (None, "flag"), ("q", "a b")]
    assert by_loc[BODY] == [("user.name", "bob"), ("user.tags[0]", "x"), ("user.tags[1]", "y")]
    assert len(by_loc[BODY_RAW]) == 1
    assert by_loc[COOKIE] == [("theme", "dark"), ("sid", "abc")]
    assert (("user-agent", "ua")) in by_loc[HEADER] and ("x-api-version", "1") in by_loc[HEADER]
    assert ("accept", "*/*") in by_loc[HEADER_OTHER]
    assert all(p != "authorization" for p, _ in by_loc[HEADER] + by_loc[HEADER_OTHER])


def test_build_view_form_multipart_and_fallbacks(make_http_event: Callable[..., Event]) -> None:
    form = build_view(
        make_http_event(
            "/f",
            method="POST",
            body="a=1+2&b=%3Cx%3E",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
    )
    assert form is not None
    assert [(t.param, t.value) for t in form.targets if t.location == BODY] == [("a", "1 2"), ("b", "<x>")]

    body = '--B\r\nContent-Disposition: form-data; name="f"; filename="../x.php"\r\n\r\nDATA\r\n--B--\r\n'
    mp = build_view(
        make_http_event(
            "/u", method="POST", body=body, headers={"content-type": "multipart/form-data; boundary=B"}
        )
    )
    assert mp is not None
    assert [(t.location, t.param, t.value) for t in mp.targets if t.location in (BODY, FILENAME)] == [
        (FILENAME, "f", "../x.php"),
        (BODY, "f", "data"),
    ]

    truncated = build_view(
        make_http_event("/j", method="POST", body='{"a": "b', headers={"content-type": "application/json"})
    )
    assert truncated is not None
    assert [t.location for t in truncated.targets if t.location in (BODY, BODY_RAW)] == [
        BODY
    ]  # inspected whole

    split = build_view(make_http_event("/p?x=1"))  # nginx-style path with query
    assert split is not None and split.path == "/p"
    assert [(t.param, t.value) for t in split.targets if t.location == QUERY] == [("x", "1")]


def test_inspection_length_cap(make_http_event: Callable[..., Event]) -> None:
    view = build_view(make_http_event("/", query="q=" + "a" * 50_000), max_chars=1000)
    assert view is not None
    assert all(len(t.raw) <= 1300 for t in view.targets)


def test_get_view_caches_per_event(settings: Settings, make_http_event: Callable[..., Event]) -> None:
    ctx = DetectionContext(settings)
    a, b = make_http_event("/a"), make_http_event("/b")
    va = get_view(a, ctx)
    assert get_view(a, ctx) is va
    vb = get_view(b, ctx)
    assert vb is not va and vb is not None and vb.path == "/b"
    assert get_view(a, None) is not va  # no ctx -> fresh view


def test_settings_section(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(web_settings(settings), WebDetectionSettings)
    from tokiwa.config import reset_settings_cache

    monkeypatch.setenv("TOKIWA_DETECTION__WEB__FLOOD_MAX_RPS", "50")
    reset_settings_cache()
    assert web_settings(Settings()).flood_max_rps == 50


def test_compile_user_regex_falls_back() -> None:
    default = r"(?:^|/)login\b"
    assert compile_user_regex("(unclosed", default).pattern == default
    assert compile_user_regex("x" * 3000, default).pattern == default
    assert compile_user_regex(r"/signon", default).search("/SIGNON")
