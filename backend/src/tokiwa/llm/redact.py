"""Masking of secrets / PII before storage or LLM submission (NFR: 秘匿).

Applied by: the Gate (before shipping events), ingest normalizers, and every prompt builder via
``tokiwa.llm.prompting``. Patterns err on the side of masking. Masked values keep a short type tag so the LLM
still knows *what* was there (e.g. ``[REDACTED:jwt]``), which matters for triage of credential attacks.
"""

from __future__ import annotations

import re
from typing import Any

from tokiwa.config import RedactionSettings, get_settings

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}")),
    ("basic_auth", re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{12,}")),
    (
        "secret_param",
        re.compile(
            r"(?i)((?:password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|auth|session(?:id)?)"
            r"[\"']?\s*[=:]\s*[\"']?)([^&\s\"',;}{]{3,})"
        ),
    ),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")),
]

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact_text(text: str | None, settings: RedactionSettings | None = None) -> str | None:
    if text is None:
        return None
    cfg = settings or get_settings().llm.redaction
    if not cfg.enabled:
        return text[: cfg.max_field_chars] if cfg.max_field_chars else text
    out = text
    for tag, pat in _PATTERNS:
        if tag == "secret_param":
            out = pat.sub(lambda m: f"{m.group(1)}[REDACTED:secret]", out)
        elif tag == "url_credentials":
            out = pat.sub(lambda m: f"{m.group(1)}[REDACTED:cred]@", out)
        else:
            out = pat.sub(f"[REDACTED:{tag}]", out)

    def _card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        return "[REDACTED:card]" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else m.group(0)

    out = _CARD.sub(_card, out)
    if cfg.mask_emails:
        out = _EMAIL.sub("[REDACTED:email]", out)
    if cfg.mask_ips:
        out = _IPV4.sub("[REDACTED:ip]", out)
    if cfg.max_field_chars and len(out) > cfg.max_field_chars:
        out = out[: cfg.max_field_chars] + f"...[truncated {len(out) - cfg.max_field_chars} chars]"
    return out


def redact_headers(headers: dict[str, str], settings: RedactionSettings | None = None) -> dict[str, str]:
    cfg = settings or get_settings().llm.redaction
    sensitive = {h.lower() for h in cfg.sensitive_headers}
    result: dict[str, str] = {}
    for k, v in headers.items():
        lk = k.lower()
        if cfg.enabled and lk in sensitive:
            result[lk] = f"[REDACTED:{lk}]"
        else:
            result[lk] = redact_text(v, cfg) or ""
    return result


def redact_obj(obj: Any, settings: RedactionSettings | None = None, _depth: int = 0) -> Any:
    """Recursively redact strings inside dict/list structures (e.g. ``Event.model_dump()``)."""
    cfg = settings or get_settings().llm.redaction
    if _depth > 12:
        return "[REDACTED:depth]"
    if isinstance(obj, str):
        return redact_text(obj, cfg)
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if k == "headers" and isinstance(v, dict):
                out[k] = redact_headers({str(a): str(b) for a, b in v.items()}, cfg)
            else:
                out[k] = redact_obj(v, cfg, _depth + 1)
        return out
    if isinstance(obj, list | tuple):
        return [redact_obj(v, cfg, _depth + 1) for v in obj]
    return obj
