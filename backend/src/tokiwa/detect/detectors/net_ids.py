"""``net.ids_alert``: Suricata alerts and Zeek notices become TOKIWA alerts.

Severity mapping (tunable in the tables below):

* Suricata ``alert.severity`` 1 -> high, 2 -> medium, 3 -> low, other/unknown -> low (1 is the most severe
  in Suricata's classification.config convention).
* Zeek notices by ``note`` prefix (``_ZEEK_NOTES``); unknown notices -> medium.

``rule_id`` is ``<engine>:<signature id or note>`` so dashboards can rank individual signatures, while the
detector itself can still be toggled as one unit (``net.ids_alert``).
"""

from __future__ import annotations

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind, IdsInfo
from tokiwa.util import short_hash

_SURICATA_SEVERITY = {1: Severity.HIGH, 2: Severity.MEDIUM, 3: Severity.LOW}

# note prefix -> (severity, category, mitre)
_ZEEK_NOTES: list[tuple[str, Severity, AlertCategory, tuple[str, ...]]] = [
    ("Scan::", Severity.MEDIUM, AlertCategory.SCAN, ("T1046",)),
    ("SSH::Password_Guessing", Severity.HIGH, AlertCategory.CREDENTIAL_ATTACK, ("T1110",)),
    ("FTP::Bruteforcing", Severity.HIGH, AlertCategory.CREDENTIAL_ATTACK, ("T1110",)),
    ("HTTP::SQL_Injection", Severity.HIGH, AlertCategory.EXPLOIT_ATTEMPT, ("T1190",)),
    ("SSL::Invalid_Server_Cert", Severity.LOW, AlertCategory.IDS, ()),
    ("Weird::", Severity.LOW, AlertCategory.ANOMALY, ()),
    ("CaptureLoss::", Severity.INFO, AlertCategory.OTHER, ()),
    ("PacketFilter::", Severity.INFO, AlertCategory.OTHER, ()),
    ("Software::", Severity.INFO, AlertCategory.OTHER, ()),
]

# Suricata classtype text (alert.category) hints -> category
_SURICATA_CATEGORY_HINTS: list[tuple[str, AlertCategory]] = [
    ("scan", AlertCategory.SCAN),
    ("web application attack", AlertCategory.EXPLOIT_ATTEMPT),
    ("exploit", AlertCategory.EXPLOIT_ATTEMPT),
    ("privilege gain", AlertCategory.EXPLOIT_ATTEMPT),
    ("credential", AlertCategory.CREDENTIAL_ATTACK),
    ("brute", AlertCategory.CREDENTIAL_ATTACK),
]


def _fp(*parts: object) -> str:
    """Dedup key that fits ``alerts.fingerprint`` (String(128)) even for long host names."""
    key = "|".join(str(p) for p in parts)
    return key if len(key) <= 128 else f"{parts[0]}|{short_hash(key, 32)}"


def classify(ids: IdsInfo) -> tuple[Severity, AlertCategory, tuple[str, ...]]:
    engine = (ids.engine or "").lower()
    if engine == "zeek":
        note = ids.signature or ""
        for prefix, sev, cat, mitre in _ZEEK_NOTES:
            if note.startswith(prefix):
                return sev, cat, mitre
        return Severity.MEDIUM, AlertCategory.IDS, ()
    sev = _SURICATA_SEVERITY.get(ids.severity or 0, Severity.LOW if ids.severity else Severity.MEDIUM)
    text = (ids.category or "").lower()
    for hint, cat in _SURICATA_CATEGORY_HINTS:
        if hint in text:
            return sev, cat, ()
    return sev, AlertCategory.IDS, ()


@register_detector
class IdsAlertDetector(Detector):
    id = "net.ids_alert"
    name = "IDS signature alert"
    description = "Suricata alert / Zeek notice forwarded as a TOKIWA alert with a severity mapping."
    category = AlertCategory.IDS
    kinds = frozenset({EventKind.IDS_ALERT})
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        ids = event.ids
        if ids is None or not (ids.signature or ids.signature_id):
            return []
        engine = (ids.engine or "ids").lower()
        severity, category, mitre = classify(ids)
        ref = str(ids.signature_id) if ids.signature_id is not None else (ids.signature or "?")
        signature = ids.signature or f"signature {ref}"
        src = event.source_ip
        tags = ["ids", engine]
        if ids.action and ids.action.lower() in {"blocked", "drop", "dropped", "reject"}:
            tags.append("blocked")
        entities: dict[str, str] = {"signature": signature[:200]}
        if src:
            entities["source_ip"] = src
        if event.destination and event.destination.ip:
            entities["dest_ip"] = event.destination.ip
        if event.destination and event.destination.port is not None:
            entities["dest_port"] = str(event.destination.port)
        return [
            self.draft(
                event,
                title=f"{engine}: {signature}"[:300],
                description=(event.message or signature)[:2000],
                severity=severity,
                confidence=0.8,
                category=category,
                mitre=list(mitre),
                rule_id=f"{engine}:{ref}"[:128],
                entities=entities,
                tags=tags,
                fingerprint=_fp(self.id, engine, ref, src or "-"),
                details={
                    "engine": engine,
                    "signature": signature,
                    "signature_id": ids.signature_id,
                    "ids_category": ids.category,
                    "ids_severity": ids.severity,
                    "action": ids.action,
                },
            )
        ]
