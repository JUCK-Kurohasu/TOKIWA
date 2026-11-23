"""detect-web: multipart boundary parsing (audit #52).

The old prefix regex read ``boundary=`` inside ``xboundary=ZZ`` and missed ``BOUNDARY=``, so a harmless extra
parameter in front of the real one split the body wrongly and hid every part from the ``web.*`` detectors.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tokiwa.config import Settings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import DetectionEngine
from tokiwa.detect.web_common import BODY, build_view, content_type_params
from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.events import Event

SQLI = "1' UNION SELECT username,password FROM users--"


def _body(boundary: str) -> str:
    return f'--{boundary}\r\nContent-Disposition: form-data; name="q"\r\n\r\n{SQLI}\r\n--{boundary}--\r\n'


async def _web_drafts(settings: Settings, ev: Event) -> dict[str, AlertDraft]:
    ctx = DetectionContext(settings)
    out: dict[str, AlertDraft] = {}
    for det in DetectionEngine(settings).all_detectors().values():
        if det.id.startswith("web.") and det.accepts(ev):
            for d in await det.process(ev, ctx):
                out[d.rule_id] = d
    return out


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("multipart/form-data; boundary=BB", [("boundary", "BB")]),
        ("multipart/form-data; xboundary=ZZ; boundary=BB", [("xboundary", "ZZ"), ("boundary", "BB")]),
        ("multipart/form-data;BOUNDARY=Bb", [("boundary", "Bb")]),  # name case-insensitive, value kept
        (
            'multipart/form-data; boundary="a;b c"; charset=utf-8',
            [("boundary", "a;b c"), ("charset", "utf-8")],
        ),
        ('multipart/form-data; boundary="q\\"x"', [("boundary", 'q"x')]),
        ("multipart/form-data; flag; boundary = BB ", [("boundary", "BB")]),
        ("multipart/form-data", []),
    ],
)
def test_content_type_params(value: str, expected: list[tuple[str, str]]) -> None:
    assert content_type_params(value) == expected


@pytest.mark.parametrize(
    "content_type",
    [
        "multipart/form-data; xboundary=ZZ; boundary=BB",  # the audit's confusion case
        "multipart/form-data; BOUNDARY=BB",
        'multipart/form-data; boundary="BB"',
    ],
)
async def test_boundary_confusion_no_longer_hides_parts(
    content_type: str, settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    ev = make_http_event("/upload", method="POST", body=_body("BB"), headers={"content-type": content_type})
    drafts = await _web_drafts(settings, ev)
    assert drafts["web.sqli"].details["param"] == "q"
    assert "web.inspection_evasion" not in drafts


async def test_duplicate_boundaries_are_flagged_and_both_tried(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    for ct in (
        "multipart/form-data; boundary=ZZ; boundary=BB",
        "multipart/form-data; boundary=BB; boundary=ZZ",
    ):
        ev = make_http_event("/upload", method="POST", body=_body("BB"), headers={"content-type": ct})
        drafts = await _web_drafts(settings, ev)
        assert drafts["web.sqli"].details["param"] == "q"
        assert drafts["web.inspection_evasion"].details["indicators"] == ["multipart_boundary_ambiguous"]


def test_unsplittable_multipart_is_inspected_whole(make_http_event: Callable[..., Event]) -> None:
    ev = make_http_event(
        "/upload",
        method="POST",
        body=_body("BB"),
        headers={"content-type": "multipart/form-data; boundary=NOPE"},
    )
    view = build_view(ev)
    assert view is not None
    bodies = [t for t in view.targets if t.location == BODY]
    assert len(bodies) == 1 and bodies[0].param is None and "union select" in bodies[0].norm
