"""Coarse attack-shape classes, shared by TOKIWA Gate and the ``web.masked_payload`` detector (ADR-0007 C).

The Gate masks secrets (``token=...``, ``Cookie``) and cuts long values *before* the server's detectors see them.
An attacker who puts ``token:`` in front of a payload, sends it in a Cookie, or pads it past the size limit hid it
from every signature detector (audit #20 #21 #31). The Gate cannot ship the hidden text (that is the point of
masking), so it ships only the *class* of what it hid: this module is the one definition of those classes, used by
both sides so the names cannot drift.

These are deliberately coarse, cheap regular expressions over a normalised view (lower-case, up to two rounds of
URL decoding). They are evidence that "something attack-shaped was hidden here", not a replacement for the
server's detectors; a determined attacker can avoid them, and the alert built on them is kept at medium.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

# Label the Gate puts on an HTTP event: comma-separated "<class>@<where>", where is path / query / body /
# body_beyond (after the captured prefix) / header:<name>. Classes only, never values.
HIDDEN_SIGNALS_LABEL = "gate.hidden_signals"
MAX_LABEL_CHARS = 512
# Scan at most this much of one value (and of a streamed body beyond the captured prefix), to bound Gate CPU.
MAX_SCAN_CHARS = 64 * 1024

SHAPES: dict[str, re.Pattern[str]] = {
    "sqli": re.compile(
        r"'\s*(?:or|and)\s+[\w'\"(]|\bunion\b[\s/*]+(?:all[\s/*]+)?select\b|;\s*(?:drop|insert|update|delete|select)\b"
        r"|\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b|'\s*(?:--|#|/\*)"
    ),
    "xss": re.compile(
        r"<\s*(?:script|svg|iframe|img|body)\b|javascript\s*:|\bon(?:error|load|mouseover|focus)\s*="
    ),
    "cmdi": re.compile(
        r"(?:;|\|\|?|&&|`|\$\()\s*(?:cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python\d?|perl|powershell)\b"
    ),
    "traversal": re.compile(r"(?:\.\./|\.\.\\){2,}|/etc/passwd\b|\bwin\.ini\b"),
    "template": re.compile(r"\$\{\s*jndi\s*:|\$\{[^}]{0,40}\$\{|\{\{.{0,80}\}\}|<%=|#\{.{0,80}\}|\$\{\{"),
    "deserialization": re.compile(r"ro0ab|aced0005|o:\d+:\"|aaeaaad/////|__reduce__|!!python/"),
    "ssrf": re.compile(r"\b(?:gopher|dict|file|ldap)://|169\.254\.169\.254|metadata\.google\.internal"),
}


def _views(text: str) -> list[str]:
    """Lower-cased text plus up to two rounds of URL decoding (each only when it changes something)."""
    low = text[:MAX_SCAN_CHARS].lower()
    views = [low]
    cur = low
    for _ in range(2):
        if "%" not in cur and "+" not in cur:
            break
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        views.append(nxt)
        cur = nxt
    return views


def classify(text: str | None) -> set[str]:
    """Attack-shape classes found in ``text`` (empty for None / clean text)."""
    if not text:
        return set()
    found: set[str] = set()
    for view in _views(text):
        for name, pattern in SHAPES.items():
            if name not in found and pattern.search(view):
                found.add(name)
    return found


def hidden_classes(raw: str | None, shown: str | None) -> set[str]:
    """Classes present in ``raw`` but not in what the server will see (``shown``: the masked / cut value).

    Only the difference is reported, so a payload the server can still read does not raise a second alert.
    Nothing is scanned when the value went through unchanged.
    """
    if not raw or raw == shown:
        return set()
    return classify(raw) - classify(shown)


def format_label(entries: dict[str, set[str]]) -> str | None:
    """``{"query": {"sqli"}}`` -> ``"sqli@query"`` (sorted, capped); None when empty."""
    parts = sorted(f"{cls}@{where}" for where, classes in entries.items() for cls in classes)
    if not parts:
        return None
    out = ",".join(parts)
    return out if len(out) <= MAX_LABEL_CHARS else out[: out.rfind(",", 0, MAX_LABEL_CHARS)]


def parse_label(value: str | None) -> list[tuple[str, str]]:
    """``"sqli@query,xss@header:cookie"`` -> ``[("sqli", "query"), ("xss", "header:cookie")]`` (known classes only)."""
    out: list[tuple[str, str]] = []
    for part in (value or "").split(","):
        cls, sep, where = part.strip().partition("@")
        if sep and cls in SHAPES and where:
            out.append((cls, where[:64]))
    return out
