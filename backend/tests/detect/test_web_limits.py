"""detect-web: inspection limits must not hide payloads silently (audit #51) and the evasion signal.

Before #51 the request view stopped at the 128th JSON leaf / 16th level / 32nd multipart part / 64th cookie or
header and never looked at JSON keys, so dummy elements in front of a payload (or a payload used as a key) hid it
from every ``web.*`` detector. Items past a limit are now folded into one overflow target; text past
``max_inspect_chars`` is still cut, but the alert says so, and padding in front of a limit raises a low alert.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from tokiwa.config import Settings, WebDetectionSettings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import DetectionEngine
from tokiwa.detect.web_common import (
    BODY,
    INSPECTION_TRUNCATED_TAG,
    JSON_KEYS_PARAM,
    OVERFLOW_PARAM,
    build_view,
    is_padding,
    is_padding_items,
)
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.events import Event

SQLI = "1' UNION SELECT username,password FROM users--"
JSON_CT = {"content-type": "application/json"}


async def _web_drafts(settings: Settings, ev: Event) -> dict[str, AlertDraft]:
    engine = DetectionEngine(settings)
    ctx = DetectionContext(settings)
    out: dict[str, AlertDraft] = {}
    for det in engine.all_detectors().values():
        if det.id.startswith("web.") and det.accepts(ev):
            for d in await det.process(ev, ctx):
                out[d.rule_id] = d
    return out


async def test_json_dummy_leaves_do_not_hide_payload(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    body = json.dumps({"x": [""] * 128, "q": SQLI})
    drafts = await _web_drafts(settings, make_http_event("/api", method="POST", body=body, headers=JSON_CT))
    sqli = drafts["web.sqli"]
    assert sqli.details["param"] == OVERFLOW_PARAM
    assert sqli.details["inspection_truncated"] == ["json_leaves"]
    assert INSPECTION_TRUNCATED_TAG in sqli.tags
    evasion = drafts["web.inspection_evasion"]
    assert evasion.severity == "low"
    assert evasion.details["indicators"] == ["padding:json_leaves"]


async def test_json_key_is_inspected(settings: Settings, make_http_event: Callable[..., Event]) -> None:
    body = json.dumps({"filter": {SQLI: "1"}})
    drafts = await _web_drafts(settings, make_http_event("/api", method="POST", body=body, headers=JSON_CT))
    assert drafts["web.sqli"].details["param"] == JSON_KEYS_PARAM
    assert "inspection_truncated" not in drafts["web.sqli"].details  # keys are not a truncation
    assert "web.inspection_evasion" not in drafts


async def test_deep_json_and_many_parts_cookies(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    deep: object = SQLI
    for _ in range(20):
        deep = {"a": deep}
    drafts = await _web_drafts(
        settings, make_http_event("/api", method="POST", body=json.dumps(deep), headers=JSON_CT)
    )
    assert drafts["web.sqli"].details["inspection_truncated"] == ["json_depth"]

    parts = "".join(f'--B\r\nContent-Disposition: form-data; name="f{i}"\r\n\r\nv{i}\r\n' for i in range(40))
    body = parts + f'--B\r\nContent-Disposition: form-data; name="q"\r\n\r\n{SQLI}\r\n--B--\r\n'
    ev = make_http_event(
        "/upload", method="POST", body=body, headers={"content-type": "multipart/form-data; boundary=B"}
    )
    drafts = await _web_drafts(settings, ev)
    assert drafts["web.sqli"].details["inspection_truncated"] == ["multipart_parts"]
    assert "web.inspection_evasion" not in drafts  # 40 distinct parts are not padding

    cookie = "; ".join(f"c{i}=v{i}" for i in range(80)) + "; last=" + SQLI.replace(";", "%3B")
    drafts = await _web_drafts(settings, make_http_event("/", headers={"cookie": cookie}))
    assert drafts["web.sqli"].details["inspection_truncated"] == ["cookies"]


async def test_limits_are_configurable(make_http_event: Callable[..., Event]) -> None:
    cfg = WebDetectionSettings(max_json_leaves=2)
    body = json.dumps({"a": "1", "b": "2", "c": "3", "d": "4"})
    view = build_view(make_http_event("/", method="POST", body=body, headers=JSON_CT), 8192, cfg)
    assert view is not None
    targets = [(t.param, t.value) for t in view.targets if t.location == BODY]
    assert targets == [
        ("a", "1"),
        ("b", "2"),
        (OVERFLOW_PARAM, "3\x004"),
        (JSON_KEYS_PARAM, "a\x00b\x00c\x00d"),
    ]
    assert view.truncated == ("json_leaves",)


async def test_padding_before_char_limit_raises_low_alert(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    body = json.dumps({"q": "A" * 9000 + " " + SQLI})
    drafts = await _web_drafts(settings, make_http_event("/api", method="POST", body=body, headers=JSON_CT))
    assert set(drafts) == {"web.inspection_evasion"}  # the payload itself is past the limit
    assert drafts["web.inspection_evasion"].details["indicators"] == ["padding:body"]
    assert drafts["web.inspection_evasion"].details["inspection_truncated"] == ["body_chars"]


async def test_large_benign_bodies_stay_quiet(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    records = json.dumps({"items": [{"name": f"item {i}", "sku": f"S{i:04d}"} for i in range(150)]})
    upload = (
        '--B\r\nContent-Disposition: form-data; name="f"; filename="a.bin"\r\n\r\n'
        + "\x00" * 9000
        + "\r\n--B--\r\n"
    )
    text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200
    for ev in (
        make_http_event("/api/bulk", method="POST", body=records, headers=JSON_CT),
        make_http_event(
            "/upload", method="POST", body=upload, headers={"content-type": "multipart/form-data; boundary=B"}
        ),
        make_http_event("/notes", method="POST", body=text, headers={"content-type": "text/plain"}),
    ):
        assert await _web_drafts(settings, ev) == {}


def test_padding_heuristics() -> None:
    assert is_padding("A" * 2000)
    assert is_padding("A" * 1900 + "B" * 100)
    assert not is_padding("A" * 1000 + "B" * 1000)
    assert not is_padding("\x00" * 5000)  # binary upload decoded with replacement
    assert not is_padding("A" * 100)  # too short to matter
    assert is_padding_items([""] * 128)
    assert is_padding_items(["x"] * 30 + ["y"])
    assert not is_padding_items([f"v{i}" for i in range(40)])
    assert not is_padding_items([""] * 5)
