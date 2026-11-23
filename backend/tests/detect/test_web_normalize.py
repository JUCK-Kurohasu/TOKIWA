"""detect-web: normalisation gaps from audit #89 (4x URL encoding, base64 parameters, UTF-16 bodies, %A0
whitespace, HTTP parameter pollution) and the HTML-entity case that turned out to be a matrix artifact.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from urllib.parse import quote

import pytest

from tokiwa.config import Settings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import DetectionEngine
from tokiwa.detect.web_common import BASE64_SUFFIX, JOINED_SUFFIX, decode, try_base64, utf16_text
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.events import Event

SQLI = "1' UNION SELECT username,password FROM users--"


async def _web_drafts(settings: Settings, ev: Event) -> dict[str, AlertDraft]:
    ctx = DetectionContext(settings)
    out: dict[str, AlertDraft] = {}
    for det in DetectionEngine(settings).all_detectors().values():
        if det.id.startswith("web.") and det.accepts(ev):
            for d in await det.process(ev, ctx):
                out[d.rule_id] = d
    return out


def _encode(s: str, times: int) -> str:
    for _ in range(times):
        s = quote(s, safe="")
    return s


def test_decode_undoes_up_to_eight_layers() -> None:
    assert decode(_encode("<script>", 4)) == "<script>"
    assert decode(_encode("<script>", 8)) == "<script>"
    assert decode(_encode("<script>", 9)) != "<script>"  # still bounded
    assert decode(_encode("<script>", 4), rounds=3) != "<script>"  # detection.web.max_decode_rounds


def test_lone_invalid_utf8_byte_becomes_latin1() -> None:
    assert decode("union%A0select") == "union\xa0select"  # was U+FFFD
    assert decode("caf%C3%A9") == "café"  # valid UTF-8 unchanged
    assert decode("caf%E9") == "café"


def test_html_numeric_reference_without_semicolon_is_greedy() -> None:
    # Python's html.unescape follows the HTML5 rule for numeric references: the semicolon is optional and hex
    # digits are consumed greedily. "&#x3dalert" is U+03DA + "lert", in a browser too (TODO(verify) in one), so
    # the audit matrix's misses for this technique were payloads a spec-compliant parser also breaks.
    assert decode("&#x3cscript&#x3e") == "<script>"
    assert decode("&#x3dalert") == "Ϛlert"


async def test_four_times_encoded_and_nbsp_sqli(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    ev = make_http_event("/search", query="q=" + _encode(SQLI, 4))
    assert "web.sqli" in await _web_drafts(settings, ev)
    nbsp = quote(SQLI, safe="").replace("%20", "%A0")
    assert "web.sqli" in await _web_drafts(settings, make_http_event("/search", query="q=" + nbsp))


@pytest.mark.parametrize("encoder", [base64.b64encode, base64.urlsafe_b64encode])
async def test_base64_parameter_is_decoded(
    encoder: Callable[[bytes], bytes], settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    value = quote(encoder(SQLI.encode()).decode(), safe="")
    drafts = await _web_drafts(settings, make_http_event("/search", query=f"filter={value}"))
    assert drafts["web.sqli"].details["param"] == "filter" + BASE64_SUFFIX
    body = json.dumps({"state": encoder(b"<script>alert(document.cookie)</script>").decode()})
    ev = make_http_event("/cb", method="POST", body=body, headers={"content-type": "application/json"})
    assert (await _web_drafts(settings, ev))["web.xss"].details["param"] == "state" + BASE64_SUFFIX


def test_try_base64_ignores_tokens_and_binaries() -> None:
    assert try_base64(base64.b64encode(b'{"returnTo":"/dashboard"}').decode()) == '{"returnTo":"/dashboard"}'
    assert try_base64("0b7c1e2a4f5d4b8e9a1c2d3e4f5a6b7c") is None  # hex id -> binary
    assert try_base64("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig") is None  # JWT ('.' is not base64)
    assert try_base64(base64.b64encode(bytes(range(256))).decode()) is None  # binary
    assert try_base64("short") is None
    assert try_base64("abc+def/ghi-jkl_mnop") is None  # mixed alphabets


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be", "utf-16"])
async def test_utf16_json_body(codec: str, settings: Settings, make_http_event: Callable[..., Event]) -> None:
    raw = json.dumps({"q": SQLI}).encode(codec)
    body = raw.decode("utf-8", "replace")  # what a sensor that assumes UTF-8 ships
    ev = make_http_event("/api", method="POST", body=body, headers={"content-type": "application/json"})
    drafts = await _web_drafts(settings, ev)
    assert drafts["web.sqli"].details["param"] == "q"


def test_utf16_text_needs_the_alternating_pattern() -> None:
    assert utf16_text("\x00" * 300) is None  # zero-filled binary
    assert utf16_text("abc\x00def\x00ghi\x00jkl") is None  # a few NULs
    assert utf16_text("{\x00}\x00a\x00b\x00c\x00d\x00") == "{}abcd"


async def test_parameter_pollution_is_joined(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    half = len(SQLI) // 2
    query = f"q={quote(SQLI[:half], safe='')}&q={quote(SQLI[half:], safe='')}"
    drafts = await _web_drafts(settings, make_http_event("/search", query=query))
    assert drafts["web.sqli"].details["param"] == "q" + JOINED_SUFFIX
    benign = make_http_event("/items", query="tag=red&tag=blue&ids=1&ids=2&sort=name&sort=-date")
    assert await _web_drafts(settings, benign) == {}
