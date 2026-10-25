"""Port baseline deviation detectors (FR-02).

They consume the PORT_CHANGE events that ``enrich/ports.py`` derives from host snapshots. Baseline facts are
read from the event ``labels`` the enricher sets (detectors never touch the DB):

* ``port.unexpected_listener`` a listener opened that no baseline allows. Severity follows reachability:
  all interfaces (0.0.0.0 / ::) high, a specific address medium, loopback low; info for the first snapshot
  of a host (nothing has been baselined yet).
* ``port.public_exposure``     a baselined port with ``allow_public=false`` is bound to all interfaces.
* ``port.process_changed``     a known listener is now owned by a different process (high when the
  baseline names the expected process and the new one is not it).

Tuning: severities are in ``_listener_severity``; allow-listing is done with baselines (UI / API), not here.
"""

from __future__ import annotations

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind, ListeningSocket
from tokiwa.schemas.hosts import is_loopback_bind, is_wildcard_bind
from tokiwa.util import short_hash


def _fp(*parts: object) -> str:
    """Dedup key that fits ``alerts.fingerprint`` (String(128)) even for long host names."""
    key = "|".join(str(p) for p in parts)
    return key if len(key) <= 128 else f"{parts[0]}|{short_hash(key, 32)}"


def _ctx(event: Event) -> tuple[str, ListeningSocket] | None:
    if event.port is None or event.port.socket is None:
        return None
    host = event.host.name if event.host and event.host.name else (event.sensor_id or "unknown")
    return host, event.port.socket


def _entities(host: str, sock: ListeningSocket) -> dict[str, str]:
    ent = {"host": host, "port": str(sock.port), "protocol": sock.protocol, "bind_ip": sock.bind_ip}
    if sock.process and sock.process.name:
        ent["process"] = sock.process.name
    return ent


def _details(event: Event, sock: ListeningSocket) -> dict[str, object]:
    return {
        "change": event.port.change if event.port else None,
        "socket": sock.model_dump(mode="json", exclude_none=True),
        "labels": dict(event.labels),
    }


def _proc(sock: ListeningSocket) -> str:
    return sock.process.name if sock.process and sock.process.name else "unknown process"


def _listener_severity(sock: ListeningSocket, initial: bool) -> Severity:
    if initial:
        return Severity.INFO
    if is_wildcard_bind(sock.bind_ip):
        return Severity.HIGH
    if is_loopback_bind(sock.bind_ip):
        return Severity.LOW
    return Severity.MEDIUM


@register_detector
class UnexpectedListenerDetector(Detector):
    id = "port.unexpected_listener"
    name = "Unexpected listening port"
    description = "A new listener that is not covered by any port baseline (FR-02)."
    category = AlertCategory.PORT_DEVIATION
    kinds = frozenset({EventKind.PORT_CHANGE})
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        c = _ctx(event)
        if c is None or event.port is None or event.port.change != "opened":
            return []
        if event.labels.get("baseline") == "allowed":
            return []
        host, sock = c
        initial = event.labels.get("port.initial") == "true"
        severity = _listener_severity(sock, initial)
        desc = f"{_proc(sock)} listens on {sock.protocol} {sock.bind_ip}:{sock.port} on {host}; no baseline allows it."
        if event.labels.get("baseline.process_mismatch") == "true":
            desc += f" The port is baselined for '{event.labels.get('baseline.process')}' only."
            severity = Severity.max(severity, Severity.MEDIUM) if not initial else severity
        if initial:
            desc += " (first snapshot from this host: review and baseline the expected listeners)"
        tags = ["port", "listener"]
        if is_wildcard_bind(sock.bind_ip):
            tags.append("all-interfaces")
        if initial:
            tags.append("initial")
        return [
            self.draft(
                event,
                title=f"Unexpected listener {sock.protocol}/{sock.port} on {host} ({_proc(sock)})",
                description=desc,
                severity=severity,
                confidence=0.6 if initial else 0.8,
                entities=_entities(host, sock),
                tags=tags,
                fingerprint=_fp(self.id, host, sock.protocol, sock.bind_ip, sock.port),
                details=_details(event, sock),
            )
        ]


@register_detector
class PublicExposureDetector(Detector):
    id = "port.public_exposure"
    name = "Port exposed on all interfaces"
    description = "A baselined port with allow_public=false is bound to 0.0.0.0 / :: (FR-02)."
    category = AlertCategory.PORT_DEVIATION
    kinds = frozenset({EventKind.PORT_CHANGE})
    default_severity = Severity.HIGH

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        c = _ctx(event)
        if c is None or event.port is None or event.port.change != "opened":
            return []
        if event.labels.get("baseline") != "allowed" or event.labels.get("baseline.allow_public") != "false":
            return []
        host, sock = c
        if not is_wildcard_bind(sock.bind_ip):
            return []
        initial = event.labels.get("port.initial") == "true"
        return [
            self.draft(
                event,
                title=f"{sock.protocol}/{sock.port} on {host} is bound to all interfaces",
                description=(
                    f"{_proc(sock)} binds {sock.bind_ip}:{sock.port} on {host}, but its baseline does not allow "
                    "public exposure. Bind it to a specific / loopback address or allow it explicitly."
                ),
                severity=Severity.MEDIUM if initial else Severity.HIGH,
                confidence=0.85,
                entities=_entities(host, sock),
                tags=["port", "exposure", "all-interfaces"],
                fingerprint=_fp(self.id, host, sock.protocol, sock.port),
                details=_details(event, sock),
            )
        ]


@register_detector
class ProcessChangedDetector(Detector):
    id = "port.process_changed"
    name = "Listening port owner changed"
    description = "A known listener is now owned by a different process (FR-02)."
    category = AlertCategory.PORT_DEVIATION
    kinds = frozenset({EventKind.PORT_CHANGE})
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        c = _ctx(event)
        if c is None or event.port is None or event.port.change != "process_changed":
            return []
        host, sock = c
        previous = event.labels.get("port.previous_process", "?")
        mismatch = event.labels.get("baseline.process_mismatch") == "true"
        desc = f"{sock.protocol} {sock.bind_ip}:{sock.port} on {host} moved from '{previous}' to '{_proc(sock)}'."
        if mismatch:
            desc += f" The baseline expects '{event.labels.get('baseline.process')}'."
        return [
            self.draft(
                event,
                title=f"Port {sock.protocol}/{sock.port} on {host} now owned by {_proc(sock)} (was {previous})",
                description=desc,
                severity=Severity.HIGH if mismatch else Severity.MEDIUM,
                confidence=0.75,
                entities={**_entities(host, sock), "previous_process": previous},
                tags=["port", "process-change"],
                fingerprint=_fp(self.id, host, sock.protocol, sock.bind_ip, sock.port, _proc(sock)),
                details=_details(event, sock),
            )
        ]
