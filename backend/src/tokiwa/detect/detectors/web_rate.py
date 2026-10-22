"""Rate / behaviour detectors on HTTP events (per-source sliding windows via ``ctx.window``).

* ``web.error_burst``        - many 4xx with high error ratio and many distinct paths = directory brute force.
* ``web.credential_stuffing`` - repeated 401/403 on login-like paths; many distinct usernames = stuffing/spraying.
* ``web.request_flood``      - sustained requests/second above a threshold from one source.

Windows run on *event* time (``event.timestamp``) so replayed logs behave like live traffic. After an alert the
detector stays quiet for one window per source (cooldown keyed on event time); the engine's fingerprint dedup
then folds repeats into one alert with a growing ``count``. Thresholds live in ``detection.web``
(``TOKIWA_DETECTION__WEB__FLOOD_MAX_RPS=50`` ...). Known limitation: state is in-memory and per process, and
NAT/proxy egress IPs aggregate many users (raise thresholds or trust X-Forwarded-For at the Gate).
"""

from __future__ import annotations

from collections import Counter

from tokiwa.config import WebDetectionSettings
from tokiwa.detect.base import Detector, register_detector
from tokiwa.detect.context import DetectionContext
from tokiwa.detect.web_common import (
    BODY,
    QUERY,
    HttpView,
    clean_label,
    compile_user_regex,
    get_view,
    web_settings,
)
from tokiwa.schemas.alerts import AlertCategory, AlertDraft
from tokiwa.schemas.common import Severity
from tokiwa.schemas.events import Event, EventKind
from tokiwa.util import short_hash

_H, _M = Severity.HIGH, Severity.MEDIUM

_DEFAULT_LOGIN_RE = str(WebDetectionSettings.model_fields["login_path_regex"].default)
_USER_FIELDS = frozenset(
    [
        "username",
        "user",
        "user_name",
        "login",
        "email",
        "mail",
        "userid",
        "user_id",
        "account",
        "log",
        "uid",
        "j_username",
        "usr",
        "loginid",
        "login_id",
        "identifier",
    ]
)


def _in_cooldown(ctx: DetectionContext, ns: str, key: str, ts: float, seconds: float) -> bool:
    last = ctx.state.get(ns, f"alerted:{key}")
    return last is not None and abs(ts - float(last)) < seconds


def _mark_alerted(ctx: DetectionContext, ns: str, key: str, ts: float, seconds: float) -> None:
    ctx.state.set(ns, f"alerted:{key}", ts, ttl=max(seconds * 4, 60.0))


def _host_entities(view: HttpView | None) -> dict[str, str]:
    if view is None:
        return {}
    return {k: v for k, v in view.entities().items() if k == "host"}


@register_detector
class ErrorBurstDetector(Detector):
    id = "web.error_burst"
    name = "HTTP 4xx error burst"
    description = (
        "One source produced many 4xx responses across many distinct paths within the window "
        "(directory/file brute force, wordlist scanning, API endpoint guessing)."
    )
    category = AlertCategory.SCAN
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1595.003", "T1083")
    default_severity = _M

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        http, ip = event.http, event.source_ip
        if http is None or http.status is None or not ip:
            return []
        cfg = web_settings(ctx.settings)
        win = cfg.error_burst_window_seconds
        ts = event.timestamp.timestamp()
        total_w = ctx.window(self.id, f"all:{ip}", win, maxlen=20_000)
        total_w.add(event.timestamp, None)
        if not 400 <= http.status < 500:
            return []
        view = get_view(event, ctx)
        path = view.path_clean[:200] if view else ""
        err_w = ctx.window(self.id, f"err:{ip}", win, maxlen=20_000)
        err_w.add(event.timestamp, (path, event.id, http.status))
        errors, total = len(err_w), max(len(total_w), len(err_w))
        if errors < cfg.error_burst_min_errors or _in_cooldown(ctx, self.id, ip, ts, win):
            return []
        ratio = errors / total
        if ratio < cfg.error_burst_min_ratio:
            return []
        items = err_w.values()
        paths = list(dict.fromkeys(p for p, _, _ in items))
        if len(paths) < cfg.error_burst_min_unique_paths:
            return []
        _mark_alerted(ctx, self.id, ip, ts, win)
        statuses = Counter(str(s) for _, _, s in items)
        return [
            self.draft(
                event,
                title=f"{self.name}: {errors} errors / {total} requests, {len(paths)} paths in {win:g}s",
                description=self.description,
                severity=_M,
                confidence=round(min(0.9, 0.5 + 0.4 * ratio), 2),
                evidence=[eid for _, eid, _ in items[-20:]],
                entities=_host_entities(view),
                tags=["web", "error_burst", "content_discovery"],
                fingerprint=f"{self.id}|{ip}",
                details={
                    "window_seconds": win,
                    "errors": errors,
                    "requests": total,
                    "error_ratio": round(ratio, 3),
                    "unique_paths": len(paths),
                    "status_counts": dict(statuses.most_common(6)),
                    "sample_paths": [clean_label(p, 100) for p in paths[:10]],
                },
            )
        ]


def extract_username_hash(view: HttpView) -> str | None:
    """Short hash of the submitted username (never the plaintext). ``None`` when absent or redacted."""
    for t in view.targets:
        if t.location not in (BODY, QUERY) or not t.param:
            continue
        name = t.param.lower()
        if "[" in name:  # user[email] -> email
            name = name.rsplit("[", 1)[-1].rstrip("]")
        name = name.rsplit(".", 1)[-1]  # json path user.email -> email
        if name not in _USER_FIELDS:
            continue
        value = t.value.strip()
        if not value or value.startswith("[redacted"):
            return None
        return short_hash(value, 12)
    return None


@register_detector
class CredentialStuffingDetector(Detector):
    id = "web.credential_stuffing"
    name = "Credential attack on login endpoint"
    description = (
        "Repeated authentication failures (401/403 by default) on login-like paths from one source. Many distinct "
        "usernames indicate credential stuffing / password spraying; one username indicates password guessing."
    )
    category = AlertCategory.CREDENTIAL_ATTACK
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1110",)
    default_severity = _H

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        http, ip = event.http, event.source_ip
        if http is None or http.status is None or not ip:
            return []
        cfg = web_settings(ctx.settings)
        if http.status not in cfg.credential_fail_statuses:
            return []
        view = get_view(event, ctx)
        if view is None:
            return []
        login_re = compile_user_regex(cfg.login_path_regex, _DEFAULT_LOGIN_RE)
        if not login_re.search(view.path_clean[:2048]):
            return []
        win = cfg.credential_window_seconds
        ts = event.timestamp.timestamp()
        w = ctx.window(self.id, ip, win, maxlen=10_000)
        w.add(event.timestamp, (extract_username_hash(view), event.id, view.path_key))
        failures = len(w)
        if failures < cfg.credential_min_failures or _in_cooldown(ctx, self.id, ip, ts, win):
            return []
        _mark_alerted(ctx, self.id, ip, ts, win)
        items = w.values()
        users = {u for u, _, _ in items if u}
        unknown = sum(1 for u, _, _ in items if not u)
        stuffing = len(users) >= cfg.credential_min_unique_users
        if stuffing:
            title = (
                f"Credential stuffing / password spraying: {failures} failures across {len(users)} usernames"
            )
            severity, mitre, kind = _H, ["T1110", "T1110.003", "T1110.004"], "credential_stuffing"
        else:
            title = f"Login brute force: {failures} failed logins in {win:g}s"
            severity, mitre, kind = _M, ["T1110", "T1110.001"], "password_guessing"
        return [
            self.draft(
                event,
                title=title,
                description=self.description,
                severity=severity,
                confidence=0.8 if stuffing else 0.7,
                evidence=[eid for _, eid, _ in items[-20:]],
                entities={**view.entities(), "path": clean_label(view.path, 200)},
                tags=["web", "credential_attack", kind],
                fingerprint=f"{self.id}|{ip}|{view.path_key}",
                mitre=mitre,
                details={
                    "window_seconds": win,
                    "failures": failures,
                    "unique_usernames": len(users),
                    "username_unknown": unknown,
                    "statuses": dict(Counter(str(s) for s in [http.status])),
                    "classification": kind,
                },
            )
        ]


@register_detector
class RequestFloodDetector(Detector):
    id = "web.request_flood"
    name = "HTTP request flood"
    description = (
        "One source exceeded the configured sustained request rate (requests/second over the window): "
        "application-layer DoS, aggressive crawler or brute-force tooling."
    )
    category = AlertCategory.ANOMALY
    kinds = frozenset({EventKind.HTTP})
    mitre = ("T1499.002",)
    default_severity = _M

    async def process(self, event: Event, ctx: DetectionContext) -> list[AlertDraft]:
        ip = event.source_ip
        if event.http is None or not ip:
            return []
        cfg = web_settings(ctx.settings)
        win = cfg.flood_window_seconds
        threshold = max(2, int(cfg.flood_max_rps * win))
        ts = event.timestamp.timestamp()
        w = ctx.window(self.id, ip, win, maxlen=threshold + 1)
        w.add(event.timestamp, event.id)
        count = len(w)
        if count < threshold or _in_cooldown(ctx, self.id, ip, ts, win):
            return []
        _mark_alerted(ctx, self.id, ip, ts, win)
        stamps = w.timestamps()
        span = max(stamps[-1] - stamps[0], 0.0)
        avg_rps = count / win
        peak_rps = count / max(span, 1.0)
        severity = _H if avg_rps >= 5 * cfg.flood_max_rps else _M
        view = get_view(event, ctx)
        return [
            self.draft(
                event,
                title=f"{self.name}: {count} requests in {win:g}s (~{avg_rps:.0f} rps)",
                description=self.description,
                severity=severity,
                confidence=0.75,
                evidence=list(w.values())[-20:],
                entities=_host_entities(view),
                tags=["web", "request_flood"],
                fingerprint=f"{self.id}|{ip}",
                details={
                    "window_seconds": win,
                    "requests": count,
                    "threshold_rps": cfg.flood_max_rps,
                    "avg_rps": round(avg_rps, 1),
                    "observed_rps": round(peak_rps, 1),
                },
            )
        ]
