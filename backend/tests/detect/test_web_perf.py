"""detect-web: ReDoS safety of every registered regex and a coarse per-event performance budget.

Thresholds are deliberately loose (CI machines vary); the point is to catch catastrophic backtracking
(seconds) and accidental O(n^2) work, not to micro-benchmark. Measured on the dev container (2026-10):
worst single pattern ~10 ms on a 4 KiB adversarial string; ~0.2 ms/event for all web detectors.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from tokiwa.config import Settings
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.engine import DetectionEngine
from tokiwa.detect.web_common import registered_patterns
from tokiwa.schemas.events import Event

FIXTURES = Path(__file__).parent / "fixtures"
N = 4096
PER_PATTERN_BUDGET_S = 0.25
PER_EVENT_BUDGET_MS = 5.0  # requirement says ~1 ms; keep CI headroom


def _adversarial_inputs() -> list[str]:
    chars = " \t\n'\"<>(){}$%&|;:/\\.=@#*-_`0a"
    inputs = [c * N for c in chars]
    inputs += [("a" + c) * (N // 2) for c in " '\"<(.:/=%$"]
    inputs += [
        "${" * (N // 2),
        "{{" * (N // 2),
        "/*" * (N // 2),
        "../" * (N // 3),
        "%2e" * (N // 3),
        "$1:" * (N // 3),
        "<a " * (N // 3),
        "http://" + "a." * (N // 2),
        "union " * (N // 6),
        '"on' * (N // 3),
        "<!entity " * (N // 9),
        'o:1:"' * (N // 5),
    ]
    return inputs


def test_all_web_patterns_are_redos_safe(settings: Settings) -> None:
    DetectionEngine(settings).all_detectors()  # import every detector module -> registers its patterns
    patterns = registered_patterns()
    assert len(patterns) > 50
    inputs = _adversarial_inputs()
    slow = []
    for name, pattern in patterns:
        for text in inputs:
            t0 = time.perf_counter()
            pattern.search(text)
            elapsed = time.perf_counter() - t0
            if elapsed > PER_PATTERN_BUDGET_S:
                slow.append((name, text[:12], round(elapsed, 3)))
    assert not slow, slow


def _event(make_http_event: Callable[..., Event], case: dict[str, Any]) -> Event:
    headers = {"user-agent": "Mozilla/5.0 Chrome/130", **case.get("headers", {})}
    if "content_type" in case:
        headers["content-type"] = case["content_type"]
    return make_http_event(
        case.get("path", "/"),
        method=case.get("method", "GET"),
        query=case.get("query"),
        body=case.get("body"),
        status=case.get("status", 200),
        headers=headers,
    )


async def test_signature_detectors_per_event_budget(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    cases = []
    for name in ("web_attacks.json", "web_benign.json"):
        cases += json.loads((FIXTURES / name).read_text(encoding="utf-8"))["cases"]
    events = [_event(make_http_event, c) for c in cases] * 3
    detectors = [d for k, d in DetectionEngine(settings).all_detectors().items() if k.startswith("web.")]
    ctx = DetectionContext(settings)
    t0 = time.perf_counter()
    for ev in events:
        ctx.scratch.clear()
        for det in detectors:
            await det.process(ev, ctx)
    avg_ms = (time.perf_counter() - t0) / len(events) * 1000
    assert avg_ms < PER_EVENT_BUDGET_MS, f"{avg_ms:.3f} ms/event"


async def test_large_adversarial_body_stays_bounded(
    settings: Settings, make_http_event: Callable[..., Event]
) -> None:
    detectors = [d for k, d in DetectionEngine(settings).all_detectors().items() if k.startswith("web.")]
    body = "<a " * 20_000  # 60 KB, capped to detection.web.max_inspect_chars
    ev = make_http_event(
        "/x", method="POST", body=body, query="q=" + "%2e" * 3000, headers={"cookie": "a=" + "'" * 9000}
    )
    ctx = DetectionContext(settings)
    t0 = time.perf_counter()
    for det in detectors:
        await det.process(ev, ctx)
    assert time.perf_counter() - t0 < 2.0
