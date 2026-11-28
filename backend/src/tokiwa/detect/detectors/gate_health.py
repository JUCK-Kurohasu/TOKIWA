"""Gate health: the Gate says some of its telemetry never reached TOKIWA (audit #55).

The Gate queues events while the server is unreachable or slow and drops them when the queue is full. Before,
the drops showed only in the Gate's local ``/__tokiwa/health``: an attacker could follow the decisive request with
~10 000 cheap ones during a server restart, and the SOC would see nothing at all. The Gate now reports drops in a
``gate.health`` event with the next batch that gets through (:mod:`tokiwa.gate.shipper`).

No source IP is attached on purpose: the alert is about the sensor, and nothing should be proposed against an
address because of it. Drops of requests that were not plain page views raise the severity, since those are the
ones that may have carried the attack.
"""

from __future__ import annotations

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind
from tokiwa.util import short_hash


def _int(value: str | None) -> int:
    try:
        return max(0, int(value or 0))
    except ValueError:
        return 0


@register_detector
class GateEventsDroppedDetector(Detector):
    id = "sensor.events_dropped"
    name = "Gate dropped telemetry"
    description = "TOKIWA Gate had to drop queued events before they reached the server (audit #55)."
    category = AlertCategory.ANOMALY
    kinds = frozenset({EventKind.CUSTOM})
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        if event.dataset != "gate.health":
            return []
        dropped = _int(event.labels.get("health.dropped"))
        if dropped <= 0:
            return []
        sensor = (event.sensor_id or "unknown")[:128]
        notable_total = _int(event.labels.get("health.dropped_notable_total"))
        return [
            self.draft(
                event,
                title=f"Gate {sensor} dropped {dropped} event(s) before they reached TOKIWA",
                description=(
                    (event.message or "")
                    + " Requests in that window are missing from TOKIWA: check the Gate's /__tokiwa/health and "
                    "the upstream application's own logs for the period before this report. A flood of cheap "
                    "requests while the server was down is also how an attacker would hide a decisive request."
                ),
                severity=Severity.HIGH if notable_total > 0 else Severity.MEDIUM,
                confidence=0.9,
                entities={"sensor": sensor},
                tags=["sensor", "telemetry-loss"],
                fingerprint=f"{self.id}|{short_hash(sensor, 32)}",
                details={k: v for k, v in event.labels.items() if k.startswith("health.")},
            )
        ]
