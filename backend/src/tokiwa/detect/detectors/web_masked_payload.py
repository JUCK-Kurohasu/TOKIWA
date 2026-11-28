"""web.masked_payload: TOKIWA Gate says it hid an attack-shaped value from the server (ADR-0007 C).

The Gate masks secrets and cuts long values before events leave it, so the signature detectors never see a payload
put behind ``token:`` (audit #20), in a Cookie / X-Api-Key value (#31), or past the size limit (#21). The Gate
classifies what it hid and ships only the class (``gate.hidden_signals``, :mod:`tokiwa.payload_shapes`); this
detector turns that into an alert.

Trust: the label is written by the sender. An event of a Gate dataset sent with a token *without* the gate scope is
marked low-trust at ingest (``ingest.trust=low``), and this detector ignores it: otherwise an ingest-only token could
put the label on events "from" any address (the framing of audit #40). The alert stays **medium** so that rule
triage, which only proposes actions from high and above, never proposes anything on this evidence alone.
"""

from __future__ import annotations

from tokiwa import payload_shapes
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind
from tokiwa.util import short_hash

# tokiwa.api.routes.ingest.LABEL_TRUST / TRUST_LOW (not imported: detectors do not depend on the API layer; a test
# pins the values).
TRUST_LABEL = "ingest.trust"
TRUST_LOW = "low"


@register_detector
class MaskedPayloadDetector(Detector):
    id = "web.masked_payload"
    name = "Attack-shaped value hidden by masking or size limits"
    description = (
        "TOKIWA Gate masked or cut a request value that looked like an attack (SQLi, XSS, command injection, ...); "
        "the signature detectors could not see it (ADR-0007)."
    )
    category = AlertCategory.EXPLOIT_ATTEMPT
    mitre = ("T1190", "T1027")  # exploit public-facing application; obfuscation (hiding behind masking / padding)
    kinds = frozenset({EventKind.HTTP})
    default_severity = Severity.MEDIUM

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        signals = payload_shapes.parse_label(event.labels.get(payload_shapes.HIDDEN_SIGNALS_LABEL))
        if not signals or not event.dataset.startswith("gate."):
            return []
        if event.labels.get(TRUST_LABEL) == TRUST_LOW:
            return []  # sent with a token that lacks the gate scope: the label could be forged
        classes = sorted({c for c, _ in signals})
        places = sorted({w for _, w in signals})
        path = event.http.path if event.http and event.http.path else "/"
        return [
            self.draft(
                event,
                title=f"{', '.join(classes)} hidden from detection in {', '.join(places)[:120]}",
                description=(
                    "The Gate masked or cut part of this request before it reached TOKIWA, and the hidden part had "
                    f"the shape of: {', '.join(classes)} (in {', '.join(places)}). The value itself is not stored. "
                    "A payload placed behind a secret-looking key (token:, password=), in a Cookie / API-key header, "
                    "or padded past the capture limit evades the signature detectors this way."
                ),
                confidence=0.5,
                entities={"path": path[:200], "hidden_in": ",".join(places)[:200]},
                tags=["evasion", "masked", *classes],
                fingerprint=f"{self.id}|{event.source_ip or '-'}|{short_hash(path, 16)}",
                details={"hidden_signals": [f"{c}@{w}" for c, w in signals]},
            )
        ]
