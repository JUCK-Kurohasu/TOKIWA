"""Behavioural features of an actor session (pure functions — easy to test and to re-run in evaluation).

Pipeline::

    Event --observe_http()--> RequestObs --annotate(prev_same_endpoint)--> RequestObs (+ mutation relation)
    [RequestObs ...] + FingerprintInfo + SessionExtras --compute_features()--> dict (JSON-safe)

``RequestObs`` is deliberately small (no raw payload) because the sessionizer keeps a bounded window of them
per live session in memory. The only payload-dependent comparison (successive requests to the same endpoint)
is computed once at observation time by :func:`annotate`, which keeps :func:`compute_features` O(n).

Timing thresholds below are hypotheses (see docs/detection/ai-attacks.md §3) and are expected to be tuned with
the evaluation harness; they are module constants so tuning touches one place.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from tokiwa.aidetect import payloads as pl
from tokiwa.aidetect.fingerprints import FingerprintInfo
from tokiwa.aidetect.recon import AI_ECOSYSTEM_KINDS, DISCOVERY_SOURCE_KINDS, SPEC_KINDS, discovery_kind
from tokiwa.schemas.events import Event

# --- timing bands (seconds)
BURST_GAP_S = 0.3  # requests closer than this belong to one burst (parallel tool calls / page assets)
THINK_MIN_S = 1.0  # "LLM is thinking" band lower bound
THINK_MAX_S = 60.0  # upper bound; longer pauses look like a human reading / leaving
# --- mutation analysis
MUTATION_WINDOW_S = 180.0  # follow-up to the same endpoint must arrive within this window
MUTATION_MIN_SIMILARITY = 0.15  # below: unrelated payload, not a variant
MUTATION_MAX_SIMILARITY = 0.97  # above: effectively identical (a retry, not a variant)
ADAPTIVE_MIN_GAP_S = 0.8  # variant after an error with at least this gap = "read the error, then adapted"
# --- discovery -> use
DISCOVERY_WINDOW_S = 300.0
# Minimum number of gaps before timing features are trusted.
MIN_GAPS_FOR_TIMING = 6


@dataclass(slots=True)
class RequestObs:
    t: float  # epoch seconds
    event_id: str
    method: str
    template: str
    status: int | None
    is_static: bool
    is_js: bool
    discovery: str | None
    has_referer: bool
    param_names: frozenset[str]
    payload_sig: str  # values signature (bounded) — used by annotate(), dropped from long-lived windows
    payload_hash: int
    has_payload: bool
    attack: frozenset[str]
    nl_score: float
    entropy: float
    semantic_tokens: int
    # --- relation to the previous request to the same endpoint (filled by annotate())
    prev_gap_s: float | None = None
    prev_status: int | None = None
    is_variant: bool = False
    variant_similarity: float | None = None

    @property
    def endpoint(self) -> str:
        return f"{self.method} {self.template}"

    @property
    def is_error(self) -> bool:
        return self.status is not None and self.status >= 400


def observe_http(event: Event) -> RequestObs | None:
    """Build a RequestObs from an HTTP event (None for non-HTTP events)."""
    h = event.http
    if h is None:
        return None
    path = h.path or "/"
    payload = pl.extract_payload(path, h.query, h.request_body, h.content_type)
    text = payload.values_text()
    custom = pl.custom_header_text(h.headers)
    norm = pl.normalize_text(f"{text} {custom}" if custom else text)
    nl = pl.natural_language_score(f"{text} {custom}" if custom else text) if (text or custom) else None
    sig = payload.signature()
    referer = h.referrer or (h.headers or {}).get("referer")
    return RequestObs(
        t=event.timestamp.timestamp(),
        event_id=event.id,
        method=(h.method or "GET").upper()[:10],
        template=pl.path_template(path),
        status=h.status,
        is_static=pl.is_static_asset(path),
        is_js=pl.is_js_asset(path),
        discovery=discovery_kind(path, h.query, h.request_body),
        has_referer=bool(referer),
        param_names=payload.names,
        payload_sig=sig,
        payload_hash=hash(sig) if sig else 0,
        has_payload=payload.present,
        attack=pl.attack_markers(norm, normalized=True),
        nl_score=nl.score if nl else 0.0,
        entropy=round(pl.shannon_entropy(text), 3) if text else 0.0,
        semantic_tokens=pl.semantic_test_tokens(text),
    )


def annotate(prev: RequestObs | None, cur: RequestObs) -> RequestObs:
    """Fill ``cur``'s relation to ``prev`` (the previous request to the *same endpoint*). Pure w.r.t. inputs."""
    if prev is None:
        return cur
    gap = cur.t - prev.t
    if gap < 0 or gap > MUTATION_WINDOW_S:
        return cur
    cur.prev_gap_s = gap
    cur.prev_status = prev.status
    if cur.has_payload and prev.has_payload and cur.payload_sig != prev.payload_sig:
        names_overlap = (
            pl.jaccard(cur.param_names, prev.param_names) if (cur.param_names or prev.param_names) else 1.0
        )
        sim = pl.payload_similarity(prev.payload_sig, cur.payload_sig)
        if names_overlap >= 0.5 and MUTATION_MIN_SIMILARITY <= sim < MUTATION_MAX_SIMILARITY:
            cur.is_variant = True
            cur.variant_similarity = round(sim, 3)
    return cur


def build_observations(events: Sequence[Event]) -> list[RequestObs]:
    """Observations for a full event list (time-ordered, annotated). Used by tests and offline evaluation."""
    out: list[RequestObs] = []
    last: dict[str, RequestObs] = {}
    for e in sorted(events, key=lambda ev: ev.timestamp):
        o = observe_http(e)
        if o is None:
            continue
        annotate(last.get(o.endpoint), o)
        last[o.endpoint] = o
        out.append(o)
    return out


@dataclass(slots=True)
class SessionExtras:
    """Signals from outside the HTTP request window."""

    canary_hits: int = 0  # DECEPTION events with asset_kind=ai_canary attributed to the session
    decoy_hits: int = 0  # other DECEPTION events (decoy path / honeytoken)
    llm_app_prompts: int = 0
    ip_tool_fingerprints: int = 1  # distinct non-browser client fingerprints from the same IP (concurrently)
    request_count_total: int = 0
    unique_paths_total: int = 0
    deception_kinds: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------------------------------------------
# small stats helpers


def _median(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    m = len(s) // 2
    return s[m] if len(s) % 2 else (s[m - 1] + s[m]) / 2


def _quantile(xs: Sequence[float], q: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    idx = min(len(s) - 1, max(0, round(q * (len(s) - 1))))
    return s[idx]


def _mean_std(xs: Sequence[float]) -> tuple[float, float]:
    if not xs:
        return 0.0, 0.0
    m = sum(xs) / len(xs)
    var = sum((x - m) ** 2 for x in xs) / len(xs)
    return m, math.sqrt(var)


def _cv(xs: Sequence[float]) -> float:
    m, sd = _mean_std(xs)
    return sd / m if m > 0 else 0.0


def bimodality_coefficient(xs: Sequence[float]) -> float:
    """Sarle's bimodality coefficient on the given sample (> 0.555 suggests bi/multi-modality)."""
    n = len(xs)
    if n < 4:
        return 0.0
    m, sd = _mean_std(xs)
    if sd == 0:
        return 0.0
    skew = sum(((x - m) / sd) ** 3 for x in xs) / n
    kurt = sum(((x - m) / sd) ** 4 for x in xs) / n - 3.0
    denom = kurt + (3.0 * (n - 1) ** 2) / ((n - 2) * (n - 3))
    return round((skew**2 + 1) / denom, 3) if denom > 0 else 0.0


def _r(x: float, nd: int = 3) -> float:
    return round(float(x), nd)


# ---------------------------------------------------------------------------------------------------------------


def timing_features(times: Sequence[float]) -> dict[str, Any]:
    ts = sorted(times)
    gaps = [b - a for a, b in pairwise(ts)]
    n = len(gaps)
    out: dict[str, Any] = {
        "n_gaps": n,
        "gap_median_ms": 0.0,
        "gap_p90_ms": 0.0,
        "gap_cv": 0.0,
        "burst_frac": 0.0,
        "think_frac": 0.0,
        "mid_frac": 0.0,
        "long_frac": 0.0,
        "bimodality_coef": 0.0,
        "bursts": 0,
        "mean_burst_size": 0.0,
        "think_gap_median_ms": 0.0,
        "think_gap_cv": 0.0,
        "n_think_gaps": 0,
        "rps": 0.0,
    }
    if n == 0:
        return out
    burst = [g for g in gaps if g < BURST_GAP_S]
    think = [g for g in gaps if THINK_MIN_S <= g <= THINK_MAX_S]
    mid = [g for g in gaps if BURST_GAP_S <= g < THINK_MIN_S]
    long_ = [g for g in gaps if g > THINK_MAX_S]
    # clusters (bursts) separated by gaps >= BURST_GAP_S
    sizes: list[int] = []
    cur = 1
    for g in gaps:
        if g < BURST_GAP_S:
            cur += 1
        else:
            sizes.append(cur)
            cur = 1
    sizes.append(cur)
    multi = [s for s in sizes if s >= 2]
    duration = ts[-1] - ts[0]
    out.update(
        gap_median_ms=_r(_median(gaps) * 1000, 1),
        gap_p90_ms=_r(_quantile(gaps, 0.9) * 1000, 1),
        gap_cv=_r(_cv(gaps)),
        burst_frac=_r(len(burst) / n),
        think_frac=_r(len(think) / n),
        mid_frac=_r(len(mid) / n),
        long_frac=_r(len(long_) / n),
        bimodality_coef=bimodality_coefficient([math.log10(max(g, 0.001)) for g in gaps]),
        bursts=len(multi),
        mean_burst_size=_r(sum(multi) / len(multi)) if multi else 0.0,
        think_gap_median_ms=_r(_median(think) * 1000, 1),
        think_gap_cv=_r(_cv(think)) if len(think) >= 2 else 0.0,
        n_think_gaps=len(think),
        rps=_r((n + 1) / duration) if duration > 0 else float(n + 1),
    )
    return out


def mutation_features(obs: Sequence[RequestObs]) -> dict[str, Any]:
    err_follow = ok_follow = post_err_var = post_ok_var = adaptive = reflexive = 0
    errors_with_payload = 0
    chain: dict[str, int] = {}
    chain_max = 0
    adaptive_gaps: list[float] = []
    sims: list[float] = []
    for o in obs:
        if o.is_error and o.has_payload:
            errors_with_payload += 1
        if o.prev_status is None or o.prev_gap_s is None:
            continue
        ep = o.endpoint
        if o.prev_status >= 400:
            err_follow += 1
            if o.is_variant:
                post_err_var += 1
                if o.variant_similarity is not None:
                    sims.append(o.variant_similarity)
                if o.prev_gap_s >= ADAPTIVE_MIN_GAP_S:
                    adaptive += 1
                    adaptive_gaps.append(o.prev_gap_s)
                else:
                    reflexive += 1
                chain[ep] = chain.get(ep, 0) + 1
                chain_max = max(chain_max, chain[ep])
            else:
                chain[ep] = 0
        else:
            ok_follow += 1
            if o.is_variant:
                post_ok_var += 1
                if o.prev_gap_s < ADAPTIVE_MIN_GAP_S:
                    reflexive += 1
            chain[ep] = 0
    p_err = post_err_var / err_follow if err_follow else 0.0
    p_ok = post_ok_var / ok_follow if ok_follow else 0.0
    return {
        "errors_with_payload": errors_with_payload,
        "followups_after_error": err_follow,
        "followups_after_success": ok_follow,
        "post_error_variants": post_err_var,
        "post_success_variants": post_ok_var,
        "adaptive_mutations": adaptive,
        "reflexive_mutations": reflexive,
        "post_error_mutation_rate": _r(p_err),
        "mutation_conditionality": _r(p_err - p_ok)
        if err_follow >= 2 and ok_follow >= 2
        else _r(p_err * 0.5),
        "mutation_chain_max": chain_max,
        "mutation_think_gap_median_ms": _r(_median(adaptive_gaps) * 1000, 1),
        "mutation_similarity_median": _r(_median(sims)),
    }


def discovery_features(obs: Sequence[RequestObs]) -> dict[str, Any]:
    seen: set[str] = set()
    last_disc: float | None = None
    after = after_hits = new_api = 0
    spec = js = eco = 0
    kinds: dict[str, int] = {}
    for o in obs:
        if o.discovery:
            kinds[o.discovery] = kinds.get(o.discovery, 0) + 1
            if o.discovery in SPEC_KINDS:
                spec += 1
            if o.discovery in AI_ECOSYSTEM_KINDS:
                eco += 1
            if o.is_js:
                js += 1
            # JS fetched *by a browser page* (with Referer) is normal page loading, not discovery by the client
            if o.discovery in DISCOVERY_SOURCE_KINDS and not (
                o.discovery in ("js", "source_map") and o.has_referer
            ):
                last_disc = o.t
            seen.add(o.template)
            continue
        if o.is_static:
            seen.add(o.template)
            continue
        if o.template not in seen:
            seen.add(o.template)
            new_api += 1
            if not o.has_referer and last_disc is not None and 0 <= o.t - last_disc <= DISCOVERY_WINDOW_S:
                after += 1
                if o.status is not None and o.status != 404:
                    after_hits += 1
    return {
        "spec_fetches": spec,
        "js_fetches": js,
        "ai_ecosystem_probes": eco,
        "discovery_kinds": sorted(kinds),
        "graphql_introspection": kinds.get("graphql_introspection", 0) > 0,
        "new_api_paths": new_api,
        "api_after_discovery": after,
        "api_after_discovery_hits": after_hits,
        "discovered_hit_rate": _r(after_hits / after) if after else 0.0,
    }


def compute_features(
    obs: Sequence[RequestObs],
    *,
    fp: FingerprintInfo | None = None,
    extras: SessionExtras | None = None,
) -> dict[str, Any]:
    """Session features from a time-ordered, annotated observation window. JSON-safe output."""
    ex = extras or SessionExtras()
    n = len(obs)
    feats: dict[str, Any] = {"n_requests": n}
    if n:
        active = [o.t for o in obs if not o.is_static]
        times = active if len(active) >= MIN_GAPS_FOR_TIMING else [o.t for o in obs]
        feats.update(timing_features(times))
        feats["timing_basis"] = "active" if times is active else "all"
        feats["duration_s"] = _r(max(o.t for o in obs) - min(o.t for o in obs), 1)
        statuses = [o.status for o in obs if o.status is not None]
        ns = len(statuses) or 1
        feats["error_rate"] = _r(sum(1 for s in statuses if s >= 400) / ns)
        feats["not_found_rate"] = _r(sum(1 for s in statuses if s == 404) / ns)
        feats["server_error_rate"] = _r(sum(1 for s in statuses if s >= 500) / ns)
        feats["blocked_rate"] = _r(sum(1 for s in statuses if s in (403, 406, 429)) / ns)
        templates = {o.template for o in obs}
        feats["path_diversity"] = _r(len(templates) / n)
        first_seen: set[str] = set()
        new = 0
        for o in obs:
            if o.template not in first_seen:
                first_seen.add(o.template)
                new += 1
        feats["new_path_rate"] = _r(new / n)
        feats["referer_ratio"] = _r(sum(1 for o in obs if o.has_referer) / n)
        feats["static_ratio"] = _r(sum(1 for o in obs if o.is_static) / n)
        with_payload = [o for o in obs if o.has_payload]
        npay = len(with_payload)
        feats["payload_ratio"] = _r(npay / n)
        attack = [o for o in obs if o.attack]
        fams: set[str] = set()
        for o in attack:
            fams |= o.attack
        feats["attack_requests"] = len(attack)
        feats["attack_ratio"] = _r(len(attack) / n)
        feats["attack_families"] = sorted(fams)
        feats["payload_uniqueness"] = _r(len({o.payload_hash for o in with_payload}) / npay) if npay else 0.0
        feats["payload_entropy_mean"] = _r(sum(o.entropy for o in with_payload) / npay) if npay else 0.0
        nl_attack = [o for o in attack if o.nl_score >= 0.55]
        feats["nl_attack_payloads"] = len(nl_attack)
        feats["nl_score_max"] = _r(max((o.nl_score for o in obs), default=0.0))
        feats["semantic_token_ratio"] = (
            _r(sum(1 for o in with_payload if o.semantic_tokens) / npay) if npay else 0.0
        )
        feats.update(mutation_features(obs))
        feats.update(discovery_features(obs))
    if fp is not None:
        feats["client_family"] = str(fp.family)
        feats["client_tool"] = fp.tool
        feats["ai_declared_client"] = fp.ai_declared
        feats["header_anomalies"] = list(fp.anomalies)
        feats["llm_sdk_headers"] = list(fp.llm_sdk_headers)
        feats["has_accept_language"] = "accept-language" in fp.header_names
    feats["canary_hits"] = ex.canary_hits
    feats["decoy_hits"] = ex.decoy_hits
    feats["llm_app_prompts"] = ex.llm_app_prompts
    feats["ip_tool_fingerprints"] = ex.ip_tool_fingerprints
    if ex.deception_kinds:
        feats["deception_kinds"] = sorted(set(ex.deception_kinds))
    return feats
