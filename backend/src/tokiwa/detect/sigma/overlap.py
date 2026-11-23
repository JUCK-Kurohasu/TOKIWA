"""Bundled Sigma web rules vs. the native ``web.*`` detectors: one alert per finding (audit #76).

The 14 rules in ``rules/sigma/web`` look for the same things as the native detectors (SQLi, XSS, traversal ...)
with plain substring matching and a fixed ``level``. Before #76 one request raised two alerts with different
fingerprints, and the Sigma one skipped the native detectors' false-positive tuning: a single ``../`` that
``web.path_traversal`` deliberately rates medium was a high (= notified) Sigma alert.

Chosen behaviour (per event, after every detector ran):

* the native detector fired too -> the Sigma draft is dropped and recorded on the native alert
  (``details.corroborated_by``, tag ``sigma-corroborated``);
* the native detector is enabled but stayed silent -> the Sigma draft is kept as a **low** fallback
  (``details.native_detector`` / ``native_verdict="silent"``, tag ``native-silent``): either the native tuning
  judged the request benign, or the native detector missed it - visible, but neither triaged nor notified by
  default;
* the native detector is disabled -> the Sigma rule is the only coverage and keeps its own level.

Only the bundled rules are mapped (by Sigma ``id``); user / LLM rules are never merged or downgraded.
"""

from __future__ import annotations

from collections.abc import Collection

from tokiwa.schemas.alerts import AlertDraft
from tokiwa.schemas.common import Severity

# Bundled Sigma rule id -> native detector that covers the same class.
NATIVE_OVERLAP: dict[str, str] = {
    "758f38f5-68ce-4d10-ae2a-ef2c765d1f03": "web.cmd_injection",
    "6622a926-1e5b-4905-b8be-919682073137": "web.lfi_rfi",
    "7f1fa436-88ca-4da3-88a1-e44c8dba1779": "web.log4shell",
    "e9c1a34a-6610-4569-b5ae-1a23ce7790ad": "web.path_traversal",
    "6abbe658-5712-45ec-b908-05238670a5f0": "web.rare_method",
    "004869cf-0236-45b7-875f-9f40dab81dca": "web.scanner_ua",
    "8db5e4e5-c68f-4807-943a-3e79810ba1af": "web.sensitive_file_probe",
    "8702e466-1a81-4f21-83dc-0c5858a17114": "web.deserialization",
    "be88336f-ab43-4572-b22f-f67eaae301df": "web.sqli",
    "63ff1f08-4ee1-462c-a4e1-dff453231a96": "web.sqli",
    "d76230ce-dd7a-4d84-a073-d8de5d91b70b": "web.ssrf",
    "6d8d9e73-625b-4bdc-83f8-2444de57ff5c": "web.ssti",
    "0eb136e3-5f0d-4279-8a01-97911b7d7ba9": "web.xss",
    "bedfc4cb-c715-4f73-9fdc-2faf787dda75": "web.xxe",
}
FALLBACK_SEVERITY = Severity.LOW
CORROBORATED_TAG = "sigma-corroborated"
NATIVE_SILENT_TAG = "native-silent"
_SIGMA_PREFIX = "sigma:"


def native_for(draft: AlertDraft) -> str | None:
    """The native detector a bundled Sigma draft duplicates, if any."""
    if not draft.rule_id.startswith(_SIGMA_PREFIX):
        return None
    if draft.details.get("rule_origin") != "file":
        return None  # user / LLM rules from the rules table are never merged
    return NATIVE_OVERLAP.get(draft.rule_id[len(_SIGMA_PREFIX) :])


def merge_native_overlap(drafts: list[AlertDraft], enabled: Collection[str]) -> list[AlertDraft]:
    """Apply the rules above to the drafts of **one** event. Returns the drafts to keep (same order)."""
    if not drafts or not any(d.rule_id.startswith(_SIGMA_PREFIX) for d in drafts):
        return drafts
    native = {d.rule_id: d for d in drafts if not d.rule_id.startswith(_SIGMA_PREFIX)}
    out: list[AlertDraft] = []
    for d in drafts:
        target = native_for(d)
        if target is None:
            out.append(d)
            continue
        hit = native.get(target)
        if hit is not None:
            corroborated = hit.details.setdefault("corroborated_by", [])
            if isinstance(corroborated, list) and d.rule_id not in corroborated:
                corroborated.append(d.rule_id)
            if CORROBORATED_TAG not in hit.tags:
                hit.tags.append(CORROBORATED_TAG)
            continue
        if target in enabled:
            d.details["native_detector"] = target
            d.details["native_verdict"] = "silent"
            d.details["sigma_level_severity"] = str(d.severity)
            if Severity(d.severity).rank > FALLBACK_SEVERITY.rank:
                d.severity = FALLBACK_SEVERITY
            if NATIVE_SILENT_TAG not in d.tags:
                d.tags.append(NATIVE_SILENT_TAG)
        out.append(d)
    return out
