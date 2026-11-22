"""Audit #41 (L01-06): the AI-canary snippet must not live only at the end of a page.

ARTEX (norma SDK) hands its LLM only the first 30,000 characters of a tool output; a canary right before
``</body>`` of a 40 KB page was never read. Positions are configurable (``deception.html_injection_positions``),
default: right after ``<body>`` and before ``</body>``.
"""

from __future__ import annotations

import pytest

from tokiwa.config import reset_settings_cache
from tokiwa.deception.render import SiteContext, html_injection
from tokiwa.gate.policy import CompiledPolicy
from tokiwa.gate.proxy import LEGACY_POSITIONS, inject_html
from tokiwa.respond.policy import build_gate_policy
from tokiwa.schemas.response import GatePolicy
from tokiwa.util import utcnow

SNIP = b'<!-- note dbg_x -->\n<div hidden aria-hidden="true">note dbg_x</div>'
BOTH = ("body_start", "body_end")


def test_default_is_start_and_end_legacy_is_end_only() -> None:
    page = b"<html><head><title>t</title></head><body class='home'><h1>x</h1></body></html>"
    both = inject_html(page, SNIP, BOTH)
    assert both == (
        b"<html><head><title>t</title></head><body class='home'>"
        + SNIP
        + b"<h1>x</h1>"
        + SNIP
        + b"</body></html>"
    )
    assert inject_html(page, SNIP, LEGACY_POSITIONS) == page.replace(b"</body>", SNIP + b"</body>")
    assert inject_html(page, SNIP) == inject_html(page, SNIP, ("body_end",))


def test_head_gets_the_comment_only() -> None:
    page = b"<!doctype html><html><HEAD lang=en><meta charset=utf-8></head><body>b</body></html>"
    out = inject_html(page, SNIP, ("head",))
    assert out == page.replace(b"<HEAD lang=en>", b"<HEAD lang=en>\n<!-- note dbg_x -->\n")
    assert b"<div" not in (out or b"").split(b"</head>")[0]  # a <div> would end <head> early
    assert inject_html(page, b"<div>no comment</div>", ("head",)) is None
    assert inject_html(b"<header>x</header><body>b</body>", SNIP, ("head",)) is None  # <header> is not <head>


REAL = b'<body id="real">'


@pytest.mark.parametrize(
    ("page", "tag"),
    [
        # "<body>" in a script string, a comment, a <title> or a <template> must not be taken for the tag
        (
            b'<html><head><script>var s = "<body class=x>";</script></head><body id="real">c</body></html>',
            REAL,
        ),
        (b'<html><head><!-- <body> --></head><body id="real">c</body></html>', REAL),
        (b'<html><head><title>&lt;body&gt; <body></title></head><body id="real">c</body></html>', REAL),
        (b'<html><head><template><body></template></head><body id="real">c</body></html>', REAL),
        # ">" inside a quoted attribute
        (
            b'<html><head></head><body id="real" data-x="a>b">c</body></html>',
            b'<body id="real" data-x="a>b">',
        ),
    ],
)
def test_body_start_skips_raw_text_and_quoted_attributes(page: bytes, tag: bytes) -> None:
    assert inject_html(page, SNIP, ("body_start",)) == page.replace(tag, tag + SNIP)


def test_missing_tags_and_unknown_positions() -> None:
    assert inject_html(b"<div>fragment</div>", SNIP, (*BOTH, "head")) is None
    no_close = b"<html><body><p>omitted end tag"
    assert inject_html(no_close, SNIP, BOTH) == no_close.replace(b"<body>", b"<body>" + SNIP)
    page = b"<body>x</body>"
    assert inject_html(page, SNIP, ("someday", "body_end")) == b"<body>x" + SNIP + b"</body>"
    assert inject_html(page, SNIP, ("someday",)) is None


def test_large_page_keeps_canary_within_the_first_30k_characters() -> None:
    filler = b"<p>" + b"lorem ipsum dolor sit amet " * 1600 + b"</p>"  # ~43 KB
    page = b"<html><head><title>shop</title></head><body>" + filler + b"</body></html>"
    assert len(page) > 40_000
    legacy = inject_html(page, SNIP, LEGACY_POSITIONS) or b""
    assert legacy.index(b"dbg_x") > 30_000  # the audit finding
    out = inject_html(page, SNIP, BOTH) or b""
    assert out.index(b"dbg_x") < 1_000 and out.count(b"dbg_x") == 4


def test_gate_compiles_positions_and_old_servers_mean_end_only() -> None:
    old = GatePolicy(version="a", generated_at=utcnow(), html_injection="<i>x</i>")
    assert CompiledPolicy.compile(old).html_injection_positions == LEGACY_POSITIONS
    new = GatePolicy(
        version="b", generated_at=utcnow(), html_injection="<i>x</i>", html_injection_positions=list(BOTH)
    )
    assert CompiledPolicy.compile(new).html_injection_positions == BOTH
    # an older gate parsing a newer policy ignores fields it does not know instead of rejecting it
    doc = new.model_dump(mode="json") | {"some_future_field": 1}
    assert GatePolicy.model_validate(doc).html_injection_positions == list(BOTH)


@pytest.mark.usefixtures("db")
async def test_server_sends_configured_positions(monkeypatch: pytest.MonkeyPatch, settings) -> None:  # type: ignore[no-untyped-def]
    from tokiwa.deception import service

    await service.seed_defaults()
    service.invalidate()
    p = await build_gate_policy()
    assert p.html_injection and p.html_injection_positions == ["body_start", "body_end"]
    monkeypatch.setenv("TOKIWA_DECEPTION__HTML_INJECTION_POSITIONS", '["head", "body_end"]')
    reset_settings_cache()
    service.invalidate()
    q = await build_gate_policy()
    assert q.html_injection_positions == ["head", "body_end"] and q.version != p.version
    monkeypatch.setenv("TOKIWA_DECEPTION__HTML_INJECTION", "false")
    reset_settings_cache()
    service.invalidate()
    off = await build_gate_policy()
    assert off.html_injection is None and off.html_injection_positions is None


def test_snippet_starts_with_a_comment_for_the_head_position(make_asset) -> None:  # type: ignore[no-untyped-def]
    from tokiwa.config import DeceptionSettings
    from tokiwa.schemas.response import DeceptionKind

    site = SiteContext(DeceptionSettings(), b"k", [make_asset(DeceptionKind.AI_CANARY)])
    snippet = html_injection(site)
    assert snippet is not None and snippet.startswith("<!--")
