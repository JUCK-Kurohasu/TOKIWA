"""#57: oversized event fields are truncated (not rejected) and marked; the cap never narrows detection (#21)."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from tokiwa.aidetect.payloads import MAX_TEXT as AIDETECT_MAX_TEXT
from tokiwa.config import WebDetectionSettings
from tokiwa.detect.sigma.evaluator import MAX_MATCH_CHARS
from tokiwa.schemas.events import (
    EVENT_FIELD_MAX_CHARS,
    EVENT_RAW_MAX_BYTES,
    TRUNCATED_LABEL,
    TRUNCATED_TAG,
    Event,
    EventKind,
    HttpInfo,
    ListeningSocket,
    PortInfo,
    ProcessInfo,
)

BIG = EVENT_FIELD_MAX_CHARS + 10


def test_cap_is_not_narrower_than_any_detector_window() -> None:
    """Truncating below a detector's inspection window would hide the tail of a field from it (audit #21)."""
    assert EVENT_FIELD_MAX_CHARS >= MAX_MATCH_CHARS
    assert WebDetectionSettings().max_inspect_chars <= EVENT_FIELD_MAX_CHARS
    assert EVENT_FIELD_MAX_CHARS >= AIDETECT_MAX_TEXT


def test_small_event_is_untouched() -> None:
    ev = Event(kind=EventKind.HTTP, dataset="gate.http", message="GET / -> 200", raw={"a": 1})
    assert ev.tags == [] and ev.labels == {}
    assert ev.raw == {"a": 1}
    exact = Event(kind=EventKind.CUSTOM, dataset="x", message="m" * EVENT_FIELD_MAX_CHARS)
    assert exact.message is not None and len(exact.message) == EVENT_FIELD_MAX_CHARS
    assert TRUNCATED_TAG not in exact.tags


def test_oversized_strings_are_truncated_everywhere_and_marked() -> None:
    ev = Event(
        kind=EventKind.HTTP,
        dataset="gate.http",
        message="M" * 8_388_608,
        http=HttpInfo(user_agent="U" * 2_097_152, headers={"x-pad": "v" * BIG}, header_order=["h" * BIG]),
        port=PortInfo(
            listeners=[
                ListeningSocket(
                    protocol="tcp", bind_ip="0.0.0.0", port=1, process=ProcessInfo(cmdline="c" * BIG)
                )
            ]
        ),
        labels={"k": "L" * BIG},
        tags=["existing"],
    )
    assert ev.message == "M" * EVENT_FIELD_MAX_CHARS
    assert ev.http is not None
    assert ev.http.user_agent is not None and len(ev.http.user_agent) == EVENT_FIELD_MAX_CHARS
    assert len(ev.http.headers["x-pad"]) == EVENT_FIELD_MAX_CHARS
    assert len(ev.http.header_order[0]) == EVENT_FIELD_MAX_CHARS
    assert ev.port is not None and ev.port.listeners[0].process is not None
    assert len(ev.port.listeners[0].process.cmdline or "") == EVENT_FIELD_MAX_CHARS
    assert ev.tags == ["existing", TRUNCATED_TAG]
    mark = ev.labels[TRUNCATED_LABEL]
    for field in (
        "message:8388608",
        "http.user_agent:2097152",
        "http.headers{}",
        "http.header_order[]",
        "port.listeners[].process.cmdline",
        "labels{}",
    ):
        assert field in mark, (field, mark)


def test_raw_is_capped_in_the_adapter_shape_and_revalidation_is_stable() -> None:
    ev = Event(kind=EventKind.CUSTOM, dataset="x", raw={"t": 'r"' * EVENT_RAW_MAX_BYTES})
    assert ev.raw is not None and ev.raw["_truncated"] is True
    assert ev.raw["_bytes"] > EVENT_RAW_MAX_BYTES
    assert len(ev.raw["text"].encode()) <= EVENT_RAW_MAX_BYTES
    # Stored events are re-validated on every read: nothing is cut twice and the mark is kept.
    again = Event.model_validate(ev.model_dump(mode="json"))
    assert again.raw == ev.raw
    assert again.labels == ev.labels and again.tags == ev.tags


def test_forged_truncated_raw_cannot_smuggle_a_huge_text() -> None:
    ev = Event(
        kind=EventKind.CUSTOM, dataset="x", raw={"_truncated": True, "text": "z" * (EVENT_RAW_MAX_BYTES * 4)}
    )
    assert ev.raw is not None
    assert len(ev.raw["text"].encode()) <= EVENT_RAW_MAX_BYTES
    assert TRUNCATED_TAG in ev.tags


async def test_ingest_truncates_and_still_detects(
    client: httpx.AsyncClient,
    ingest_headers: dict[str, str],
    admin_headers: dict[str, str],
    make_http_event: Callable[..., Event],
) -> None:
    """Audit repro: an 8 MiB message + 2 MiB User-Agent was stored as is. Now it is cut, tagged and still analysed."""
    ev = make_http_event(
        "/items",
        ip="192.0.2.9",
        query="id=1%20UNION%20SELECT%20null,version()--&pad=" + "a" * 200_000,
        ua="U" * 2_097_152,
    ).model_dump(mode="json")
    ev["message"] = "M" * 8_388_608
    r = await client.post("/api/v1/ingest/events", json={"events": [ev]}, headers=ingest_headers)
    assert r.status_code == 200, r.text[:300]
    assert r.json()["alerts"] >= 1  # the payload at the start of the (truncated) query is still detected

    page = (
        await client.get("/api/v1/events", params={"source_ip": "192.0.2.9"}, headers=admin_headers)
    ).json()
    stored = page["items"][0]
    assert len(stored["message"]) == EVENT_FIELD_MAX_CHARS
    assert len(stored["http"]["user_agent"]) == EVENT_FIELD_MAX_CHARS
    assert len(stored["http"]["query"]) == EVENT_FIELD_MAX_CHARS
    assert TRUNCATED_TAG in stored["tags"]
    assert "message:8388608" in stored["labels"][TRUNCATED_LABEL]
