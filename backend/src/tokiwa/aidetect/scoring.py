"""Explainable AI-agent attribution: features -> signals (0..1) -> weighted logistic heads -> classification.

Why not ML: ADR-0006 (explainability, no model training in scope). Every number below is a *hand-set prior*
derived from the hypotheses in docs/detection/ai-attacks.md and the synthetic sessions in tests; it must be
re-tuned with the evaluation harness (``tokiwa eval run``) on real lab traffic. **All tunables live in this file.**

Three heads, each ``sigmoid(bias + sum(weight * signal))``:

- ``ai``       is the actor an autonomous LLM agent?        -> ``ActorSession.ai_score``
- ``scanner``  is it a conventional automated scanner?
- ``hostile``  is there attack intent at all (vs benign use)?

Classification (first rule that matches):
  canary followed -> ai_agent | too few requests -> unknown | ai >= threshold -> ai_agent |
  scanner >= SCANNER_THRESHOLD -> automated_scanner | hostile >= HOSTILE_THRESHOLD -> human |
  hostile < BENIGN_MAX_HOSTILE (and not automation-only) -> benign | otherwise unknown.

"human" therefore means *hostile activity not attributable to an AI agent or a scanner* (most likely hands-on).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from tokiwa.aidetect.fingerprints import AUTOMATION_FAMILIES, BROWSER_MISMATCH_ANOMALIES, ClientFamily
from tokiwa.schemas.common import ActorType

# ---------------------------------------------------------------------------------------------------------------
# Tunables (single place). Positive weight = evidence FOR the head, negative = evidence AGAINST.

AI_BIAS = -3.4
AI_WEIGHTS: dict[str, float] = {
    "burst_think_rhythm": 1.7,  # H1 tool-call bursts separated by LLM "thinking" gaps
    "regular_think_gaps": 0.6,  # H1' think gaps are comparatively regular (LLM latency), humans are heavy-tailed
    "adaptive_mutation": 2.4,  # H2 payload variants on the same endpoint right after error responses
    "discovery_then_use": 1.8,  # H3 spec / JS / robots fetched, then real (non-404) routes hit without Referer
    "spec_discovery": 0.6,  # H3 OpenAPI / GraphQL introspection fetched
    "ai_ecosystem_probe": 1.2,  # H3 /.well-known/ai-plugin.json, MCP, llms.txt, agent card
    "natural_language_payload": 1.6,  # H4 explanatory prose inside attack payloads
    "ai_declared_client": 1.4,  # H5 UA declares an AI agent / LLM framework (spoofable -> weak)
    "llm_sdk_headers": 1.0,  # H5 x-stainless-* / MCP headers
    "automation_client": 0.7,  # H5 HTTP library / CLI / headless / non-standard Mozilla UA
    "browser_claim_mismatch": 0.8,  # H5 browser UA with a library header set / missing browser headers
    "attack_payloads": 0.5,  # attack intent (does not discriminate AI vs human by itself)
    "multi_tool_source": 0.5,  # several non-browser tool fingerprints from one IP at once (agent + tools)
    "ai_canary_followed": 8.0,  # H6 followed a hidden instruction in a decoy -> near-deterministic
    # counter-evidence
    "sustained_high_rate": -2.6,  # constant high request rate without thinking gaps -> scanner
    "wordlist_enumeration": -2.0,  # mostly 404 over ever-new paths -> brute force wordlist
    "scanner_client": -2.2,  # known scanner UA
    "reflexive_fuzzing": -1.2,  # payload variants fired regardless of / faster than responses
    "browser_consistent": -2.0,  # complete, consistent browser behaviour (Referer chains, assets, headers)
    "sparse_irregular_pacing": -0.8,  # long heavy-tailed pauses, no bursts -> human pacing
}

SCANNER_BIAS = -2.6
SCANNER_WEIGHTS: dict[str, float] = {
    "sustained_high_rate": 3.2,
    "wordlist_enumeration": 2.6,
    "scanner_client": 3.4,
    "reflexive_fuzzing": 1.4,
    "automation_client": 0.4,
    "browser_consistent": -2.0,
    "burst_think_rhythm": -1.2,
    "adaptive_mutation": -1.0,
    "discovery_then_use": -0.8,
}

HOSTILE_BIAS = -2.2
HOSTILE_WEIGHTS: dict[str, float] = {
    "attack_payloads": 3.6,
    "error_pressure": 1.4,
    "adaptive_mutation": 1.2,
    "natural_language_payload": 0.8,
    "spec_discovery": 0.6,
    "ai_ecosystem_probe": 0.8,
    "discovery_then_use": 0.6,
    "wordlist_enumeration": 2.4,
    "sustained_high_rate": 1.2,
    "scanner_client": 2.6,
    "ai_canary_followed": 5.0,
    "decoy_touched": 4.0,
    "browser_consistent": -0.8,
}

SCANNER_THRESHOLD = 0.6
HOSTILE_THRESHOLD = 0.5
BENIGN_MAX_HOSTILE = 0.35
MIN_REQUESTS_FOR_VERDICT = 5
DEFAULT_AI_THRESHOLD = 0.7
CANARY_FLOOR = 0.99

# Human-readable indicator labels (ja / en). Keys match the signal names above.
INDICATOR_LABELS: dict[str, tuple[str, str]] = {
    "burst_think_rhythm": ("バースト→思考待ちのリズム", "Burst-then-think request rhythm"),
    "regular_think_gaps": ("思考待ち間隔の規則性", "Regular thinking gaps"),
    "adaptive_mutation": ("エラー応答後の適応的ペイロード変異", "Adaptive payload mutation after errors"),
    "discovery_then_use": (
        "仕様/JS 取得直後の実在 API 利用",
        "Discovered routes used right after spec/JS fetch",
    ),
    "spec_discovery": (
        "API 仕様・GraphQL イントロスペクション取得",
        "API spec / GraphQL introspection fetched",
    ),
    "ai_ecosystem_probe": (
        "AI エコシステム探索（MCP/ai-plugin/llms.txt）",
        "AI ecosystem probe (MCP/ai-plugin/llms.txt)",
    ),
    "natural_language_payload": (
        "攻撃ペイロード内の自然言語説明",
        "Natural-language prose inside attack payloads",
    ),
    "ai_declared_client": ("AI/LLM クライアントを名乗る UA", "Client declares an AI/LLM agent"),
    "llm_sdk_headers": ("LLM SDK / MCP 由来ヘッダ", "LLM SDK / MCP headers"),
    "automation_client": (
        "自動化クライアント（ライブラリ/CLI/ヘッドレス）",
        "Automation client (library/CLI/headless)",
    ),
    "browser_claim_mismatch": ("ブラウザ詐称（ヘッダ不整合）", "Browser UA with inconsistent headers"),
    "attack_payloads": ("攻撃ペイロード", "Attack payloads"),
    "multi_tool_source": ("同一送信元から複数ツール指紋", "Several tool fingerprints from one source"),
    "ai_canary_followed": ("AI カナリアの隠し指示に追従", "Followed an AI-canary hidden instruction"),
    "decoy_touched": ("デコイ/ハニートークンに接触", "Touched a decoy / honeytoken"),
    "sustained_high_rate": ("思考待ちのない一定高速レート", "Sustained high rate without thinking gaps"),
    "wordlist_enumeration": ("ワードリスト総当たり（404 多発）", "Wordlist enumeration (mostly 404)"),
    "scanner_client": ("既知スキャナの UA", "Known scanner user agent"),
    "reflexive_fuzzing": ("応答を待たない機械的ファジング", "Reflexive fuzzing (not response-driven)"),
    "browser_consistent": ("一貫したブラウザ挙動", "Consistent real-browser behaviour"),
    "sparse_irregular_pacing": ("不規則で長い間隔（人間的）", "Sparse, irregular (human-like) pacing"),
    "error_pressure": ("高いエラー率", "High error rate"),
}


def _clamp(x: float) -> float:
    return 0.0 if x <= 0 else 1.0 if x >= 1 else float(x)


def _suff(n: float, needed: float) -> float:
    """Data-sufficiency ramp: evidence from few samples counts proportionally less."""
    return _clamp(n / needed) if needed > 0 else 1.0


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def _f(feats: Mapping[str, Any], key: str, default: float = 0.0) -> float:
    v = feats.get(key, default)
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def signals(feats: Mapping[str, Any]) -> dict[str, float]:
    """Map raw features to bounded 0..1 signals. Kept next to the weights so tuning stays in one file."""
    family = str(feats.get("client_family") or ClientFamily.UNKNOWN)
    anomalies = set(feats.get("header_anomalies") or [])
    n = _f(feats, "n_requests")
    n_gaps = _f(feats, "n_gaps")
    burst, think = _f(feats, "burst_frac"), _f(feats, "think_frac")
    gap_cv = _f(feats, "gap_cv")
    mismatch = bool(anomalies & BROWSER_MISMATCH_ANOMALIES)
    automation = family in {str(f) for f in AUTOMATION_FAMILIES} or bool(
        anomalies & {"nonstandard_mozilla_ua", "empty_user_agent"}
    )
    s: dict[str, float] = {}
    s["burst_think_rhythm"] = _clamp(2.0 * min(burst, think)) * _suff(n_gaps, 8)
    n_think = _f(feats, "n_think_gaps")
    s["regular_think_gaps"] = (
        (1.0 - _clamp(_f(feats, "think_gap_cv") / 1.2)) * _suff(n_think, 4) if n_think >= 2 else 0.0
    ) * (1.0 if burst > 0.1 else 0.5)
    s["adaptive_mutation"] = _clamp(_f(feats, "adaptive_mutations") / 3.0)
    s["discovery_then_use"] = _clamp(_f(feats, "api_after_discovery_hits") / 4.0) * _f(
        feats, "discovered_hit_rate"
    )
    s["spec_discovery"] = _clamp(_f(feats, "spec_fetches") / 2.0)
    s["ai_ecosystem_probe"] = 1.0 if _f(feats, "ai_ecosystem_probes") >= 1 else 0.0
    s["natural_language_payload"] = _clamp(_f(feats, "nl_attack_payloads") / 2.0)
    s["ai_declared_client"] = (
        1.0 if family == ClientFamily.AI_AGENT else 0.5 if family == ClientFamily.AI_CRAWLER else 0.0
    )
    s["llm_sdk_headers"] = 1.0 if feats.get("llm_sdk_headers") else 0.0
    s["automation_client"] = 1.0 if automation else 0.0
    s["browser_claim_mismatch"] = 1.0 if mismatch else 0.0
    s["attack_payloads"] = _clamp(_f(feats, "attack_requests") / 3.0)
    s["multi_tool_source"] = _clamp((_f(feats, "ip_tool_fingerprints", 1) - 1) / 2.0)
    s["ai_canary_followed"] = 1.0 if _f(feats, "canary_hits") >= 1 else 0.0
    s["decoy_touched"] = 1.0 if _f(feats, "decoy_hits") >= 1 else 0.0
    s["sustained_high_rate"] = (
        _clamp((_f(feats, "rps") - 2.0) / 6.0) * (1.0 - _clamp(think * 4.0)) * _suff(n, 20)
    )
    s["wordlist_enumeration"] = (
        _clamp((_f(feats, "not_found_rate") - 0.4) / 0.4)
        * _clamp((_f(feats, "new_path_rate") - 0.5) / 0.4)
        * _suff(n, 20)
    )
    s["scanner_client"] = 1.0 if family == ClientFamily.SCANNER else 0.0
    s["reflexive_fuzzing"] = _clamp(_f(feats, "reflexive_mutations") / 6.0)
    if family == ClientFamily.BROWSER and not mismatch:
        s["browser_consistent"] = (
            0.5
            + 0.25 * _clamp(_f(feats, "referer_ratio") / 0.5)
            + 0.25 * _clamp(_f(feats, "static_ratio") / 0.3)
        )
    else:
        s["browser_consistent"] = 0.0
    s["sparse_irregular_pacing"] = (
        _clamp((gap_cv - 1.0) / 1.0) * (1.0 - _clamp(burst * 3.0)) * _suff(n_gaps, MIN_REQUESTS_FOR_VERDICT)
    )
    s["error_pressure"] = _clamp((_f(feats, "error_rate") - 0.2) / 0.4) * _suff(n, MIN_REQUESTS_FOR_VERDICT)
    return {k: round(v, 4) for k, v in s.items()}


def _head(
    bias: float, weights: Mapping[str, float], sig: Mapping[str, float]
) -> tuple[float, dict[str, float]]:
    contrib = {k: w * sig.get(k, 0.0) for k, w in weights.items()}
    return _sigmoid(bias + sum(contrib.values())), contrib


def _evidence_text(key: str, f: Mapping[str, Any]) -> str:
    """Short factual summary of the features behind an indicator (shown to analysts and the LLM)."""
    g = f.get
    match key:
        case "burst_think_rhythm" | "regular_think_gaps":
            return (
                f"bursts={g('bursts', 0)} burst_frac={g('burst_frac', 0)} think_frac={g('think_frac', 0)} "
                f"think_median_ms={g('think_gap_median_ms', 0)} think_cv={g('think_gap_cv', 0)}"
            )
        case "adaptive_mutation" | "reflexive_fuzzing":
            return (
                f"adaptive={g('adaptive_mutations', 0)} reflexive={g('reflexive_mutations', 0)} "
                f"chain_max={g('mutation_chain_max', 0)} think_gap_ms={g('mutation_think_gap_median_ms', 0)}"
            )
        case "discovery_then_use" | "spec_discovery" | "ai_ecosystem_probe":
            return (
                f"kinds={g('discovery_kinds', [])} api_after_discovery={g('api_after_discovery', 0)} "
                f"hits={g('api_after_discovery_hits', 0)}"
            )
        case "natural_language_payload":
            return f"nl_attack_payloads={g('nl_attack_payloads', 0)} nl_score_max={g('nl_score_max', 0)}"
        case "ai_declared_client" | "automation_client" | "llm_sdk_headers" | "scanner_client":
            return (
                f"family={g('client_family')} tool={g('client_tool')} sdk_headers={g('llm_sdk_headers', [])}"
            )
        case "browser_claim_mismatch" | "browser_consistent":
            return (
                f"anomalies={g('header_anomalies', [])} referer_ratio={g('referer_ratio', 0)} "
                f"static_ratio={g('static_ratio', 0)}"
            )
        case "attack_payloads":
            return f"attack_requests={g('attack_requests', 0)} families={g('attack_families', [])}"
        case "sustained_high_rate" | "sparse_irregular_pacing":
            return f"rps={g('rps', 0)} gap_median_ms={g('gap_median_ms', 0)} gap_cv={g('gap_cv', 0)}"
        case "wordlist_enumeration" | "error_pressure":
            return (
                f"error_rate={g('error_rate', 0)} not_found_rate={g('not_found_rate', 0)} "
                f"new_path_rate={g('new_path_rate', 0)}"
            )
        case "ai_canary_followed" | "decoy_touched":
            return f"canary_hits={g('canary_hits', 0)} decoy_hits={g('decoy_hits', 0)}"
        case "multi_tool_source":
            return f"tool_fingerprints_from_ip={g('ip_tool_fingerprints', 1)}"
    return ""


@dataclass(slots=True)
class ScoreResult:
    ai_score: float
    scanner_score: float
    hostile_score: float
    classification: ActorType
    indicators: list[dict[str, Any]] = field(default_factory=list)
    signals: dict[str, float] = field(default_factory=dict)

    def as_features(self) -> dict[str, Any]:
        """Fields merged into ``ActorSession.features``."""
        return {
            "scores": {
                "ai": round(self.ai_score, 4),
                "scanner": round(self.scanner_score, 4),
                "hostile": round(self.hostile_score, 4),
            },
            "indicators": self.indicators,
            "signals": {k: v for k, v in self.signals.items() if v > 0},
        }


def classify(
    n_requests: float,
    ai: float,
    scanner: float,
    hostile: float,
    sig: Mapping[str, float],
    *,
    threshold: float = DEFAULT_AI_THRESHOLD,
) -> ActorType:
    if sig.get("ai_canary_followed", 0.0) > 0:
        return ActorType.AI_AGENT
    if n_requests < MIN_REQUESTS_FOR_VERDICT:
        return ActorType.UNKNOWN
    if ai >= threshold:
        return ActorType.AI_AGENT
    if scanner >= SCANNER_THRESHOLD:
        return ActorType.AUTOMATED_SCANNER
    if hostile >= HOSTILE_THRESHOLD:
        return ActorType.HUMAN
    if hostile < BENIGN_MAX_HOSTILE and (
        sig.get("browser_consistent", 0.0) > 0 or sig.get("automation_client", 0.0) == 0
    ):
        return ActorType.BENIGN
    return ActorType.UNKNOWN


def score_features(
    feats: Mapping[str, Any], *, threshold: float = DEFAULT_AI_THRESHOLD, max_indicators: int = 10
) -> ScoreResult:
    sig = signals(feats)
    ai, ai_c = _head(AI_BIAS, AI_WEIGHTS, sig)
    scanner, _ = _head(SCANNER_BIAS, SCANNER_WEIGHTS, sig)
    hostile, _ = _head(HOSTILE_BIAS, HOSTILE_WEIGHTS, sig)
    if sig.get("ai_canary_followed", 0.0) > 0:
        ai = max(ai, CANARY_FLOOR)
    cls = classify(_f(feats, "n_requests"), ai, scanner, hostile, sig, threshold=threshold)
    ranked = sorted(
        ((k, c) for k, c in ai_c.items() if abs(c) >= 0.05), key=lambda kc: (-(kc[1] > 0), -abs(kc[1]))
    )
    indicators = []
    for k, c in ranked[:max_indicators]:
        ja, en = INDICATOR_LABELS.get(k, (k, k))
        indicators.append(
            {
                "key": k,
                "ja": ja,
                "en": en,
                "signal": sig.get(k, 0.0),
                "weight": AI_WEIGHTS[k],
                "contribution": round(c, 3),
                "direction": "for" if c > 0 else "against",
                "evidence": _evidence_text(k, feats),
            }
        )
    return ScoreResult(
        ai_score=round(ai, 4),
        scanner_score=round(scanner, 4),
        hostile_score=round(hostile, 4),
        classification=cls,
        indicators=indicators,
        signals=sig,
    )
