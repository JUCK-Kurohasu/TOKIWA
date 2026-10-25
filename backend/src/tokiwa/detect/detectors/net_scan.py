"""``net.port_scan`` (FR-03): one source touching many destination ports or hosts within a window.

Inputs are CONNECTION (host sensor, Zeek conn, Suricata flow), IDS_ALERT and HTTP events that carry a source
IP and a destination. Per source we keep a sliding window of (dest ip, dest port) and alert when

* distinct destination ports >= ``agent.scan_port_threshold`` (vertical scan), or
* distinct destination hosts >= ``agent.scan_host_threshold`` (horizontal sweep)

within ``agent.scan_window_seconds``. Severity is high at 5x the threshold.

Connections the monitored host itself initiated (``network.direction == "outbound"``) are ignored: a busy
server talks to many hosts on 443 and that is not a scan *by the remote side*. Outbound scanning from a
compromised host is therefore not covered here (TODO: separate detector with its own thresholds).
Limitation: the host sensor only sees connections to *open* ports; Zeek/Suricata see failed attempts too.
"""

from __future__ import annotations

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind

# Connection states that indicate a probe rather than a conversation (Zeek conn_state, TCP states).
_FAILED_STATES = frozenset({"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "SH", "SHR", "OTH", "SYN_RECV"})
_EVIDENCE_MAX = 25


@register_detector
class PortScanDetector(Detector):
    id = "net.port_scan"
    name = "Port scan / host sweep"
    description = "One source connects to many destination ports or hosts within a short window (FR-03)."
    category = AlertCategory.SCAN
    kinds = frozenset({EventKind.CONNECTION, EventKind.IDS_ALERT, EventKind.HTTP})
    mitre = ("T1046",)
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        src = event.source_ip
        dst = event.destination
        if not src or dst is None or (dst.port is None and not dst.ip):
            return []
        if event.network is not None and event.network.direction == "outbound":
            return []
        cfg = ctx.settings.agent
        window = ctx.window(self.id, src, seconds=cfg.scan_window_seconds, maxlen=5000)
        state = event.network.state if event.network else None
        window.add(event.timestamp, (dst.ip, dst.port, event.id, state in _FAILED_STATES))
        items = window.values()
        ports = {p for _, p, _, _ in items if p is not None}
        hosts = {ip for ip, _, _, _ in items if ip}
        vertical = len(ports) >= cfg.scan_port_threshold
        horizontal = len(hosts) >= cfg.scan_host_threshold
        if not (vertical or horizontal):
            return []
        # One draft per source per window (the engine would dedup anyway; this keeps the hot path cheap).
        if ctx.state.get(self.id, src):
            return []
        ctx.state.set(self.id, src, True, ttl=cfg.scan_window_seconds)
        big = len(ports) >= 5 * cfg.scan_port_threshold or len(hosts) >= 5 * cfg.scan_host_threshold
        kind = " and ".join(k for k, hit in (("vertical", vertical), ("horizontal", horizontal)) if hit)
        failed = sum(1 for *_, f in items if f)
        evidence = list(dict.fromkeys(eid for _, _, eid, _ in items))[-_EVIDENCE_MAX:]
        return [
            self.draft(
                event,
                title=f"Port scan from {src}: {len(ports)} ports / {len(hosts)} hosts in {int(cfg.scan_window_seconds)}s",
                description=(
                    f"{src} contacted {len(ports)} distinct destination ports on {len(hosts)} hosts within "
                    f"{int(cfg.scan_window_seconds)} seconds ({kind} scan; {failed} failed/probe connections)."
                ),
                severity=Severity.HIGH if big else Severity.MEDIUM,
                confidence=0.8 if failed else 0.65,
                evidence=evidence,
                entities={"source_ip": src},
                tags=["scan", *kind.split(" and ")],
                fingerprint=f"{self.id}|{src}",
                details={
                    "distinct_ports": len(ports),
                    "distinct_hosts": len(hosts),
                    "sample_ports": sorted(ports)[:50],
                    "sample_hosts": sorted(hosts)[:20],
                    "failed_connections": failed,
                    "window_seconds": cfg.scan_window_seconds,
                },
            )
        ]
