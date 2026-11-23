"""Sensor health: the agent says part of its telemetry did not reach TOKIWA (audit #121 / #131).

* ``sensor.connections_truncated`` (PORT_SNAPSHOT label ``connections_truncated``): a host sensor cycle had more
  new connections than ``agent.max_connections_per_cycle``. The overflow is carried over to the next cycle, but
  a burst of loopback / half-open connections is also how an attacker on the host would try to hide a C2 channel,
  so the saturation itself is worth a look.
* ``sensor.log_parse_failures`` (``agent.health`` events): a log source had lines it could not parse or
  timestamps it could not interpret (wrong ``log_format`` / ``escape``, unknown time format). Silent loss of
  telemetry is a detection gap, and with a hand-written nginx format a client could provoke it on purpose.
  Offset-less timestamps alone (``health.naive_time``) do not alert: they are often correct UTC; the agent warns.

No source IP is attached on purpose: these alerts are about the sensor, and response proposals must not target
anything because of them.
"""

from __future__ import annotations

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind
from tokiwa.util import short_hash


def _host(event: Event) -> str:
    return event.host.name if event.host and event.host.name else (event.sensor_id or "unknown")


def _int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


@register_detector
class ConnectionsTruncatedDetector(Detector):
    id = "sensor.connections_truncated"
    name = "Host sensor connection limit reached"
    description = "More new connections in one host-sensor cycle than the agent may report (audit #121)."
    category = AlertCategory.ANOMALY
    kinds = frozenset({EventKind.PORT_SNAPSHOT})
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        truncated = _int(event.labels.get("connections_truncated"))
        if truncated <= 0:
            return []
        host = _host(event)
        total = _int(event.labels.get("connections_new"))
        return [
            self.draft(
                event,
                title=f"Host sensor on {host} saw {total} new connections in one cycle ({truncated} deferred)",
                description=(
                    f"The host sensor on {host} found {total} new TCP connections in one cycle; {truncated} exceeded "
                    "agent.max_connections_per_cycle and are reported in the following cycles (established "
                    "outbound connections first). A burst of loopback or half-open connections can be an attempt "
                    "to hide a command-and-control channel; check the connections reported around this time."
                ),
                confidence=0.5,
                entities={"host": host},
                tags=["sensor", "saturation"],
                fingerprint=f"{self.id}|{short_hash(host, 32)}",
                details={"connections_new": total, "connections_truncated": truncated},
            )
        ]


@register_detector
class LogParseFailuresDetector(Detector):
    id = "sensor.log_parse_failures"
    name = "Log lines the agent could not read"
    description = "A tailed log had unparseable lines or uninterpretable timestamps (audit #131)."
    category = AlertCategory.ANOMALY
    kinds = frozenset({EventKind.CUSTOM})
    default_severity = Severity.LOW

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        if event.dataset != "agent.health":
            return []
        unparsed = _int(event.labels.get("health.unparsed"))
        bad_time = _int(event.labels.get("health.bad_time"))
        if unparsed <= 0 and bad_time <= 0:
            return []
        host = _host(event)
        source = event.labels.get("health.source", "?")[:200]
        return [
            self.draft(
                event,
                title=f"Agent on {host} could not read {unparsed + bad_time} log record(s) from {source}",
                description=event.message or "",
                severity=Severity.MEDIUM if unparsed else Severity.LOW,
                confidence=0.6,
                entities={"host": host, "log_source": source},
                tags=["sensor", "log-format"],
                fingerprint=f"{self.id}|{short_hash(f'{host}|{source}', 32)}",
                details={k: v for k, v in event.labels.items() if k.startswith("health.")},
            )
        ]
