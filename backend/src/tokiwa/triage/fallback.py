"""Rule-based triage verdict (FR-07 fallback; ADR-0004 §5).

Used when the LLM is skipped (below ``min_severity_for_llm``, no evidence) or fails (budget exceeded, refusal,
invalid output, no valid evidence after the retry). Detection never stops because the LLM is unavailable.

The same logic is registered as the mock-provider responder for :class:`TriageResult`, so "no API key" mode and
tests exercise the full pipeline (escalation, evidence validation, action proposals) with meaningful output.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from tokiwa.config import get_settings
from tokiwa.correlate import killchain
from tokiwa.correlate.scoring import AlertFacts, infer_actor_type
from tokiwa.llm.mock import register_mock_responder
from tokiwa.schemas.alerts import AlertCategory
from tokiwa.schemas.common import ActorType, Severity
from tokiwa.schemas.triage import ActionType, RecommendedAction, TriageResult
from tokiwa.triage.evidence import TriageSubject, normalize_action_target

log = logging.getLogger(__name__)

RULES_PROMPT_VERSION = "triage.rules@1"
DEFAULT_ACTION_TTL_MINUTES = 60

_NEXT_STEPS: dict[str, dict[str, list[str]]] = {
    "ja": {
        "default": [
            "証拠イベントの送信元と時系列を確認する",
            "同一送信元の他のアラート・セッションを確認する",
        ],
        AlertCategory.EXPLOIT_ATTEMPT: [
            "対象エンドポイントの応答（ステータス・サイズ）から成功の有無を確認する",
            "該当アプリのログで同時刻のエラー・例外を確認する",
        ],
        AlertCategory.AI_AGENT: [
            "セッションのリクエスト間隔（バースト→思考待ち）とエラー後のペイロード変異を確認する",
            "デコイ/AI カナリアへのアクセス有無を確認する",
        ],
        AlertCategory.CREDENTIAL_ATTACK: [
            "対象アカウントのロックアウト・成功ログインの有無を確認する",
            "同一送信元からの認証試行のユーザー名多様性を確認する",
        ],
        AlertCategory.PORT_DEVIATION: [
            "新規リスナーのプロセス・実行ユーザー・起動時刻を確認する",
            "想定された変更か（デプロイ記録）を確認し、不明ならベースライン外として調査する",
        ],
        AlertCategory.PROMPT_INJECTION: [
            "LLM アプリの応答内容とツール呼び出しの有無を確認する",
            "システムプロンプトや秘密情報の漏えいがないか確認する",
        ],
        AlertCategory.DECEPTION: ["デコイ接触の前後のリクエストを確認し、攻撃者の目的を推定する"],
    },
    "en": {
        "default": [
            "Review the source and timeline of the evidence events",
            "Check other alerts and sessions from the same source",
        ],
        AlertCategory.EXPLOIT_ATTEMPT: [
            "Check the target endpoint's responses (status / size) for signs of success",
            "Look for errors / exceptions in the application logs at the same time",
        ],
        AlertCategory.AI_AGENT: [
            "Inspect the session's request rhythm (burst then thinking pause) and post-error payload mutation",
            "Check whether decoys / AI canaries were touched",
        ],
        AlertCategory.CREDENTIAL_ATTACK: [
            "Check for account lockouts or successful logins on the targeted accounts",
            "Check the username diversity of authentication attempts from the source",
        ],
        AlertCategory.PORT_DEVIATION: [
            "Identify the new listener's process, user and start time",
            "Confirm whether it was an expected change (deployment records); investigate otherwise",
        ],
        AlertCategory.PROMPT_INJECTION: [
            "Review the LLM application's responses and any tool calls",
            "Check for leakage of system prompts or secrets",
        ],
        AlertCategory.DECEPTION: [
            "Review requests around the decoy interaction to infer the attacker's goal"
        ],
    },
}


def _category_label(subject: TriageSubject, ai: bool) -> str:
    rid = subject.rule_ids[0] if len(subject.rule_ids) == 1 else ""
    family, _, suffix = rid.partition(".")
    if rid and not rid.startswith("sigma:") and suffix:
        base = f"ai_{suffix}" if family == "ai" else suffix
    else:
        base = str(subject.category)
    base = re.sub(r"[^a-z0-9_]+", "_", base.lower()).strip("_")[:48] or "other"
    if ai and not base.startswith("ai"):
        base = f"ai_agent_{base}"
    return base


def _facts(subject: TriageSubject) -> list[AlertFacts]:
    if subject.alerts:
        return [
            AlertFacts(
                rule_id=a.rule_id,
                category=a.category,
                severity=a.severity,
                ai_score=a.ai_score,
                tags=subject.tags,
                entities=subject.entities,
            )
            for a in subject.alerts
        ]
    return [
        AlertFacts(
            rule_id=subject.rule_ids[0] if subject.rule_ids else "",
            category=subject.category,
            severity=subject.severity,
            ai_score=subject.ai_score,
            tags=subject.tags,
            entities=subject.entities,
        )
    ]


def _is_canary(subject: TriageSubject) -> bool:
    return any("ai_canary" in t for t in subject.tags) or "ai_canary" in subject.entities.values()


def _recommend(
    subject: TriageSubject, actor: ActorType, evidence_source_ips: Sequence[str], lang: str
) -> list[RecommendedAction]:
    """Conservative proposals (always human-approved): only for high+ severity and an evidenced source IP."""
    sev = Severity(subject.severity)
    if not sev.at_least(Severity.HIGH):
        return []
    target = next(
        (ip for ip in (normalize_action_target(s, evidence_source_ips) for s in subject.source_ips) if ip),
        None,
    )
    if target is None:
        return []
    ja = lang == "ja"
    if sev == Severity.CRITICAL:
        action, reason = (
            ActionType.BLOCK_IP,
            "重大度 critical のルール判定に基づく一時遮断"
            if ja
            else "Temporary block based on a critical rule verdict",
        )
    elif actor == ActorType.AI_AGENT:
        action, reason = (
            ActionType.DECEIVE,
            "AI エージェントと推定: デコイ環境へ誘導して行動を観察・浪費させる"
            if ja
            else "Likely AI agent: route into Mirage decoys to observe it and waste its effort",
        )
    else:
        action, reason = (
            ActionType.RATE_LIMIT,
            "重大度 high のルール判定に基づくレート制限"
            if ja
            else "Rate limit based on a high-severity rule verdict",
        )
    return [
        RecommendedAction(
            action_type=action, target=target, reason=reason, ttl_minutes=DEFAULT_ACTION_TTL_MINUTES
        )
    ]


def rule_based_triage(
    subject: TriageSubject,
    evidence_ids: Sequence[str],
    evidence_source_ips: Sequence[str] = (),
    *,
    lang: str | None = None,
    ai_threshold: float | None = None,
) -> TriageResult:
    settings = get_settings()
    lang = lang or settings.llm.output_language
    threshold = settings.detection.ai_agent_threshold if ai_threshold is None else ai_threshold
    canary = _is_canary(subject)

    if subject.actor_type and subject.actor_type != ActorType.UNKNOWN:
        actor = ActorType(subject.actor_type)
    else:
        actor = infer_actor_type(_facts(subject), ai_score=subject.ai_score, ai_threshold=threshold)
    ai_likelihood = subject.ai_score if subject.ai_score is not None else 0.0
    if canary:
        ai_likelihood = max(ai_likelihood, 0.95)
    is_ai = actor == ActorType.AI_AGENT

    indicators: list[str] = []
    if subject.ai_score is not None:
        indicators.append(f"behavioural ai_score={subject.ai_score:.2f} (threshold {threshold:.2f})")
    if canary:
        indicators.append("ai_canary_followed")
    indicators.extend(f"detector:{r}" for r in subject.rule_ids if r.startswith(("ai.", "llm_app.")))

    tactics = subject.kill_chain or killchain.tactics_for_alert(subject.mitre, subject.category)
    confidence = subject.confidence
    if canary or subject.category == AlertCategory.DECEPTION:
        confidence = max(confidence, 0.95)

    ids = list(dict.fromkeys(evidence_ids))[:10]
    sev = Severity(subject.severity)
    label = _category_label(subject, is_ai)
    src = ", ".join(subject.source_ips[:3])
    noun = ("インシデント" if subject.kind == "incident" else "アラート") if lang == "ja" else subject.kind
    if lang == "ja":
        summary = (
            f"ルールベース判定: {noun}「{subject.title[:120]}」（重大度 {sev}、送信元 {src or '不明'}）。"
        )
        if is_ai:
            summary += " 振る舞いから AI エージェントによる活動の可能性が高い。"
        rationale = (
            f"LLM を使わない規則判定。検知器 {', '.join(subject.rule_ids[:5]) or '-'} の重大度・信頼度"
            f"（{subject.confidence:.2f}）と AI スコア（{subject.ai_score if subject.ai_score is not None else '-'}）に基づく。"
            f" 根拠イベント: {', '.join(ids) or 'なし'}"
        )
    else:
        summary = (
            f"Rule-based verdict: {noun} '{subject.title[:120]}' (severity {sev}, source {src or 'unknown'})."
        )
        if is_ai:
            summary += " Behaviour suggests an autonomous AI agent."
        rationale = (
            f"Deterministic rule verdict without an LLM, based on detector(s) {', '.join(subject.rule_ids[:5]) or '-'} "
            f"severity/confidence ({subject.confidence:.2f}) and AI score "
            f"({subject.ai_score if subject.ai_score is not None else '-'}). Evidence: {', '.join(ids) or 'none'}"
        )
    steps = _NEXT_STEPS.get(lang, _NEXT_STEPS["en"])
    next_steps = list(steps.get(str(subject.category), [])) + steps["default"]

    return TriageResult(
        severity=sev,
        category=label,
        confidence=min(1.0, max(0.0, confidence)),
        actor_type=actor,
        ai_agent_likelihood=min(1.0, max(0.0, ai_likelihood)),
        ai_agent_indicators=indicators[:10],
        attack_stage=killchain.most_advanced(tactics),
        mitre_techniques=list(dict.fromkeys(subject.mitre))[:10],
        summary=summary,
        rationale=rationale,
        evidence_ids=ids,
        next_steps=next_steps[:8],
        recommended_actions=_recommend(subject, actor, evidence_source_ips, lang),
    )


# ------------------------------------------------------------------------------------------- mock responder

_BLOCK_RE = re.compile(r'<untrusted_data name="([A-Za-z0-9_.-]+)">\n(.*?)\n</untrusted_data>', re.DOTALL)


def parse_untrusted_blocks(text: str) -> dict[str, Any]:
    """Decode the JSON payloads of ``untrusted_block()`` envelopes (``<``/``>`` are JSON ``\\u`` escapes)."""
    out: dict[str, Any] = {}
    for name, body in _BLOCK_RE.findall(text):
        try:
            out[name] = json.loads(body)
        except json.JSONDecodeError:
            out[name] = None
    return out


@register_mock_responder(TriageResult)
def mock_triage_responder(system: str, user: str) -> dict[str, Any]:
    """Mock-provider answer for triage prompts: the rule verdict computed from the prompt's own data blocks."""
    blocks = parse_untrusted_blocks(user)
    try:
        subject = TriageSubject.model_validate(blocks.get("subject") or {})
    except ValidationError:
        log.debug("mock triage: subject block missing or invalid; using a neutral subject")
        subject = TriageSubject(
            kind="alert", id="unknown", title="unknown", severity=Severity.MEDIUM, category="other"
        )
    raw_ids = blocks.get("evidence_ids")
    ids = [i for i in raw_ids if isinstance(i, str)] if isinstance(raw_ids, list) else []
    raw_events = blocks.get("evidence_events")
    src_ips: list[str] = []
    if isinstance(raw_events, list):
        for ev in raw_events:
            src = ev.get("src") if isinstance(ev, dict) else None
            if isinstance(src, dict) and isinstance(src.get("ip"), str):
                src_ips.append(src["ip"])
    lang = "ja" if "in Japanese" in system else "en"
    return rule_based_triage(subject, ids, src_ips, lang=lang).model_dump(mode="json")
