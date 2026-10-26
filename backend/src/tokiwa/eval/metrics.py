"""Metrics: compare what the pipeline produced (:class:`~tokiwa.eval.harness.RunResults`) with ground truth.

Attribution of an alert to labelled sessions: primarily through ``evidence_event_ids``; when an alert carries no
labelled evidence, through its ``source_ip`` (the simulator gives every session its own source address).

Definitions (requirements §7 評価指標):

* session detection rate — attack sessions with >= 1 attributed alert / attack sessions (also per profile);
* benign FPR — benign sessions with >= 1 attributed alert / benign sessions (any severity and >= medium);
* event recall — attack-labelled events that appear in some alert's evidence / attack events. Lower bound: windowed
  detectors cite a subset of the events, and evidence is capped per alert;
* alert precision — alerts attributed only to attack sessions / alerts attributed to anything;
* AI attribution — per session score = max(actor_session.ai_score, alert.ai_score, triage.ai_agent_likelihood);
  predicted AI when score >= ``detection.ai_agent_threshold`` or the sessionizer classified it ``ai_agent``.
  Precision / recall / F1 / ROC-AUC (Mann-Whitney) against ``actor == ai_agent``;
* LLM agreement — over triaged alerts/incidents: actor type, malicious verdict, AI verdict vs ground truth;
* cost — tokens and USD from ``llm_calls`` per alert / per triaged alert; latency — batch processing time
  (ingest -> alert) and alert -> triage.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

from tokiwa.eval.dataset import SessionTruth, Truth
from tokiwa.eval.harness import RunResults

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def ratio(num: float, den: float) -> float | None:
    return round(num / den, 4) if den else None


def percentile(values: Sequence[float], pct: float) -> float | None:
    if not values:
        return None
    data = sorted(values)
    k = (len(data) - 1) * pct / 100.0
    lo, hi = int(k), min(int(k) + 1, len(data) - 1)
    return round(data[lo] + (data[hi] - data[lo]) * (k - lo), 4)


def roc_auc(positives: Sequence[float], negatives: Sequence[float]) -> float | None:
    """Probability a random positive scores higher than a random negative (ties count half)."""
    if not positives or not negatives:
        return None
    wins = 0.0
    for p in positives:
        for n in negatives:
            wins += 1.0 if p > n else (0.5 if p == n else 0.0)
    return round(wins / (len(positives) * len(negatives)), 4)


def binary_scores(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1: float | None = None
    if precision is not None and recall is not None:
        f1 = round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1}


def _triage_result(record: Any) -> dict[str, Any] | None:
    if isinstance(record, dict):
        result = record.get("result")
        return result if isinstance(result, dict) else None
    return None


class _Attribution:
    def __init__(self, truth: Truth, res: RunResults) -> None:
        self.truth = truth
        self.res = res
        self.by_ip = truth.sessions_by_ip()
        self.alert_sessions: dict[str, set[str]] = {}
        self.session_alerts: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for a in res.alerts:
            names = self._sessions_for_alert(a)
            self.alert_sessions[a["id"]] = names
            for n in names:
                self.session_alerts[n].append(a)
        # pipeline session ids per labelled session (via the sessionizer's event.session_id)
        self.pipeline_sessions: dict[str, set[str]] = defaultdict(set)
        for ev in res.events:
            st = truth.session_of(ev["id"])
            if st is not None and ev.get("session_id"):
                self.pipeline_sessions[st.session].add(ev["session_id"])

    def _sessions_for_alert(self, alert: dict[str, Any]) -> set[str]:
        names: set[str] = set()
        for eid in alert.get("evidence_event_ids") or []:
            st = self.truth.session_of(eid)
            if st is not None:
                names.add(st.session)
        if not names and alert.get("source_ip"):
            names = {st.session for st in self.by_ip.get(alert["source_ip"], [])}
        return names

    def sessions_for_ips(self, ips: Iterable[str]) -> set[str]:
        return {st.session for ip in ips for st in self.by_ip.get(ip, [])}

    def truth_actor(self, names: set[str]) -> str | None:
        if not names:
            return None
        counts: Counter[str] = Counter()
        for n in names:
            st = self.truth.sessions[n]
            counts[st.actor] += len(st.event_ids)
        return counts.most_common(1)[0][0]


def _detection(truth: Truth, att: _Attribution) -> tuple[dict[str, Any], dict[str, Any]]:
    per_profile: dict[str, dict[str, Any]] = {}
    attack_total = attack_hit = benign_total = benign_hit = benign_hit_med = 0
    for st in truth.sessions.values():
        alerts = att.session_alerts.get(st.session, [])
        hit = bool(alerts)
        hit_med = any(_SEV_RANK.get(str(a.get("severity")), 0) >= 2 for a in alerts)
        row = per_profile.setdefault(
            st.profile,
            {"actor": st.actor, "sessions": 0, "detected": 0, "detected_medium_plus": 0, "alerts": 0},
        )
        row["sessions"] += 1
        row["detected"] += int(hit)
        row["detected_medium_plus"] += int(hit_med)
        row["alerts"] += len(alerts)
        if st.is_attack:
            attack_total += 1
            attack_hit += int(hit)
        else:
            benign_total += 1
            benign_hit += int(hit)
            benign_hit_med += int(hit_med)
    for row in per_profile.values():
        row["detection_rate"] = ratio(row["detected"], row["sessions"])
    evidence: set[str] = set()
    for a in att.res.alerts:
        evidence.update(a.get("evidence_event_ids") or [])
    attack_events = [
        eid for eid, lb in truth.by_event.items() if lb["actor"] != "benign" and lb["attack"] != "none"
    ]
    benign_events = [eid for eid, lb in truth.by_event.items() if lb["actor"] == "benign"]
    detection = {
        "attack_sessions": attack_total,
        "attack_sessions_detected": attack_hit,
        "attack_session_rate": ratio(attack_hit, attack_total),
        "benign_sessions": benign_total,
        "benign_sessions_alerted": benign_hit,
        "benign_session_fpr": ratio(benign_hit, benign_total),
        "benign_session_fpr_medium_plus": ratio(benign_hit_med, benign_total),
        "attack_events": len(attack_events),
        "event_recall": ratio(sum(1 for e in attack_events if e in evidence), len(attack_events)),
        "benign_events": len(benign_events),
        "event_fpr": ratio(sum(1 for e in benign_events if e in evidence), len(benign_events)),
    }
    return detection, dict(sorted(per_profile.items()))


def _alerts(truth: Truth, att: _Attribution) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    tp = fp = unattributed = 0
    per_rule: dict[str, dict[str, Any]] = {}
    for a in att.res.alerts:
        names = att.alert_sessions.get(a["id"], set())
        actors = {truth.sessions[n].actor for n in names}
        row = per_rule.setdefault(
            a["rule_id"],
            {
                "rule_id": a["rule_id"],
                "detector": a.get("detector"),
                "alerts": 0,
                "hits": 0,
                "tp": 0,
                "fp": 0,
                "unattributed": 0,
                "actors": Counter(),
            },
        )
        row["alerts"] += 1
        row["hits"] += int(a.get("count") or 1)
        if not names:
            unattributed += 1
            row["unattributed"] += 1
        elif actors <= {"benign"}:
            fp += 1
            row["fp"] += 1
        else:
            tp += 1
            row["tp"] += 1
        for actor in actors:
            row["actors"][actor] += 1
    rules = []
    for row in sorted(per_rule.values(), key=lambda r: (-r["alerts"], r["rule_id"])):
        row["precision"] = ratio(row["tp"], row["tp"] + row["fp"])
        row["actors"] = dict(sorted(row["actors"].items()))
        rules.append(row)
    by_sev = Counter(str(a.get("severity")) for a in att.res.alerts)
    by_cat = Counter(str(a.get("category")) for a in att.res.alerts)
    summary = {
        "total": len(att.res.alerts),
        "true_positive": tp,
        "false_positive": fp,
        "unattributed": unattributed,
        "precision": ratio(tp, tp + fp),
        "by_severity": dict(sorted(by_sev.items())),
        "by_category": dict(sorted(by_cat.items())),
        "incidents": len(att.res.incidents),
    }
    return summary, rules


def _session_scores(st: SessionTruth, att: _Attribution) -> dict[str, Any]:
    rows = [s for s in att.res.sessions if s.get("id") in att.pipeline_sessions.get(st.session, set())]
    behaviour = max((float(s.get("ai_score") or 0.0) for s in rows), default=None)
    classes = [
        str(s.get("classification")) for s in sorted(rows, key=lambda r: -(r.get("request_count") or 0))
    ]
    alerts = att.session_alerts.get(st.session, [])
    alert_score = max((float(a["ai_score"]) for a in alerts if a.get("ai_score") is not None), default=None)
    triage_scores = []
    incident_ids = {a.get("incident_id") for a in alerts if a.get("incident_id")}
    for rec in [a.get("triage") for a in alerts] + [
        i.get("triage") for i in att.res.incidents if i.get("id") in incident_ids
    ]:
        result = _triage_result(rec)
        if result and result.get("ai_agent_likelihood") is not None:
            triage_scores.append(float(result["ai_agent_likelihood"]))
    triage = max(triage_scores, default=None)
    available = [s for s in (behaviour, alert_score, triage) if s is not None]
    return {
        "behaviour": behaviour,
        "alert": alert_score,
        "triage": triage,
        "combined": max(available, default=0.0),
        "classification": classes[0] if classes else None,
        "classifications": sorted(set(classes)),
    }


def _ai_attribution(truth: Truth, att: _Attribution, threshold: float) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    scores: dict[str, dict[str, list[float]]] = {
        k: {"pos": [], "neg": []} for k in ("combined", "behaviour", "alert", "triage")
    }
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    per_session = []
    for st in sorted(truth.sessions.values(), key=lambda s: s.session):
        sc = _session_scores(st, att)
        predicted = sc["combined"] >= threshold or "ai_agent" in sc["classifications"]
        if st.is_ai:
            tp, fn = tp + int(predicted), fn + int(not predicted)
        else:
            fp, tn = fp + int(predicted), tn + int(not predicted)
        for key in scores:
            value = sc[key]
            if key == "combined" or value is not None:
                scores[key]["pos" if st.is_ai else "neg"].append(float(value or 0.0))
        pred_class = sc["classification"] or ("ai_agent" if predicted else "unknown")
        confusion[st.actor][pred_class] += 1
        per_session.append(
            {
                "session": st.session,
                "actor": st.actor,
                "predicted_ai": predicted,
                **{k: sc[k] for k in scores},
            }
        )
    out = binary_scores(tp, fp, fn, tn)
    out["threshold"] = threshold
    out["auc"] = roc_auc(scores["combined"]["pos"], scores["combined"]["neg"])
    out["auc_by_source"] = {k: roc_auc(v["pos"], v["neg"]) for k, v in scores.items() if k != "combined"}
    out["confusion"] = {actor: dict(sorted(c.items())) for actor, c in sorted(confusion.items())}
    out["sessions"] = per_session
    return out


def _llm(truth: Truth, att: _Attribution, threshold: float) -> dict[str, Any]:
    judged = actor_ok = verdict_ok = ai_ok = 0
    by_tier: Counter[str] = Counter()
    items: list[tuple[dict[str, Any] | None, set[str]]] = [
        (a.get("triage"), att.alert_sessions.get(a["id"], set())) for a in att.res.alerts
    ]
    items += [(i.get("triage"), att.sessions_for_ips(i.get("source_ips") or [])) for i in att.res.incidents]
    triaged = 0
    for record, names in items:
        result = _triage_result(record)
        if result is None:
            continue
        triaged += 1
        by_tier[str(record.get("tier") if isinstance(record, dict) else "?")] += 1
        actor = att.truth_actor(names)
        if actor is None:
            continue
        judged += 1
        actor_ok += int(result.get("actor_type") == actor)
        malicious = result.get("actor_type") != "benign" and float(result.get("confidence") or 0.0) >= 0.5
        verdict_ok += int(malicious == (actor != "benign"))
        ai_ok += int((float(result.get("ai_agent_likelihood") or 0.0) >= threshold) == (actor == "ai_agent"))
    return {
        "triaged": triaged,
        "judged_against_truth": judged,
        "by_tier": dict(sorted(by_tier.items())),
        "actor_agreement": ratio(actor_ok, judged),
        "verdict_agreement": ratio(verdict_ok, judged),
        "ai_agreement": ratio(ai_ok, judged),
    }


def _cost(res: RunResults, triaged: int) -> dict[str, Any]:
    calls = res.llm_calls
    cost = sum(float(c.get("cost_usd") or 0.0) for c in calls)
    tin = sum(int(c.get("input_tokens") or 0) for c in calls)
    tout = sum(int(c.get("output_tokens") or 0) for c in calls)
    n_alerts = len(res.alerts)
    return {
        "provider": res.llm_provider,
        "llm_calls": len(calls),
        "by_status": dict(sorted(Counter(str(c.get("status")) for c in calls).items())),
        "by_purpose": dict(sorted(Counter(str(c.get("purpose")) for c in calls).items())),
        "input_tokens": tin,
        "output_tokens": tout,
        "cost_usd": round(cost, 6),
        "cost_per_alert_usd": round(cost / n_alerts, 6) if n_alerts else None,
        "tokens_per_alert": round((tin + tout) / n_alerts, 1) if n_alerts else None,
        "cost_per_triaged_usd": round(cost / triaged, 6) if triaged else None,
    }


def _latency(res: RunResults) -> dict[str, Any]:
    events = sum(res.batch_sizes)
    per_event = [ms / n for ms, n in zip(res.batch_latencies_ms, res.batch_sizes, strict=True) if n]
    return {
        "batches": len(res.batch_sizes),
        "events": events,
        "replay_seconds": round(res.replay_seconds, 3),
        "throughput_eps": round(events / res.replay_seconds, 1) if res.replay_seconds else None,
        "batch_p50_ms": percentile(res.batch_latencies_ms, 50),
        "batch_p95_ms": percentile(res.batch_latencies_ms, 95),
        "batch_max_ms": round(max(res.batch_latencies_ms), 3) if res.batch_latencies_ms else None,
        "per_event_mean_ms": round(statistics.fmean(per_event), 4) if per_event else None,
        "triage_samples": len(res.triage_latencies_s),
        "triage_source": res.triage_latency_source,
        "triage_p50_s": percentile(res.triage_latencies_s, 50),
        "triage_p95_s": percentile(res.triage_latencies_s, 95),
        "triage_max_s": round(max(res.triage_latencies_s), 3) if res.triage_latencies_s else None,
        "drain_seconds": round(res.drain_seconds, 3),
    }


def compute_metrics(truth: Truth, res: RunResults, *, ai_threshold: float | None = None) -> dict[str, Any]:
    threshold = res.ai_agent_threshold if ai_threshold is None else ai_threshold
    att = _Attribution(truth, res)
    detection, per_profile = _detection(truth, att)
    alerts, per_rule = _alerts(truth, att)
    llm = _llm(truth, att, threshold)
    return {
        "detection": detection,
        "per_profile": per_profile,
        "alerts": alerts,
        "per_detector": per_rule,
        "ai_attribution": _ai_attribution(truth, att, threshold),
        "llm": llm,
        "cost": _cost(res, llm["triaged"]),
        "latency": _latency(res),
        "pipeline": {
            "detectors_registered": res.detectors_registered,
            "detectors_enabled": res.detectors_enabled,
            "enrichers": res.enrichers,
            "actor_sessions": len(res.sessions),
            "events_stored": len(res.events),
            "notes": res.notes,
        },
    }
