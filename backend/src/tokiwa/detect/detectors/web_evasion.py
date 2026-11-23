"""web.inspection_evasion - requests shaped to push a payload past the inspection limits (audit #51 / #52).

Every inspector has limits (characters per field, JSON leaves, multipart parts, headers). Items past a structural
limit are still inspected by the signature detectors (folded into one overflow target), but text past
``detection.web.max_inspect_chars`` - or past the sensor's body capture - is not. Normal traffic reaches those
limits too (uploads, bulk APIs), so reaching a limit alone is only recorded on the alerts
(``details.inspection_truncated``). This detector fires when the request also *looks* like it was built to
reach the limit:

* padding: a field cut at the limit that is >= 90% one character (``"A" * 8200`` + payload), a body captured
  only in part whose prefix is padding, or a container past its limit whose items are mostly empty / identical
  (128 dummy JSON elements, 32 empty multipart parts);
* ambiguous multipart framing: several ``boundary`` parameters with different values (servers disagree on which
  one wins, so inspector and application may split the body differently).

Low severity: the signal says "something was hidden", not what. The ``web.*`` signature alert on the same
request (if any) carries the payload.
"""

from __future__ import annotations

from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import get_view
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind


@register_detector
class InspectionEvasionDetector(Detector):
    id = "web.inspection_evasion"
    name = "Inspection limit evasion"
    description = (
        "The request is shaped to push content past the inspection limits: padding in front of a cut-off "
        "(one repeated character, dummy JSON elements or empty multipart parts) or ambiguous multipart "
        "boundaries. Look at the end of the request body / the overflow items for the actual payload."
    )
    category = AlertCategory.EXPLOIT_ATTEMPT
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1190",)
    default_severity = Severity.LOW

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        view = get_view(event, ctx)
        if view is None or not view.evasion:
            return []
        reasons = list(view.evasion)
        return [
            self.draft(
                event,
                title=f"{self.name}: {', '.join(reasons)[:150]}",
                description=self.description,
                severity=Severity.LOW,
                confidence=round(min(0.6, 0.4 + 0.1 * (len(reasons) - 1)), 2),
                entities=view.entities(),
                tags=list(
                    dict.fromkeys(["web", "inspection_evasion", *(r.split(":", 1)[0] for r in reasons)])
                ),
                fingerprint=f"{self.id}|{event.source_ip or '-'}|{view.path_key}",
                details={
                    "indicators": reasons,
                    "inspection_truncated": list(view.truncated),
                    "method": view.method,
                    "status": view.status,
                },
            )
        ]
