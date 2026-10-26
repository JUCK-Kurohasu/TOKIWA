"""What the simulated AI agent "reads" in responses: API routes and hidden instructions (AI canaries).

These helpers make the ``ai_agent`` profile behave like ARTEX-style tooling: it pulls the JS bundle / OpenAPI /
robots.txt, extracts routes that are never linked from HTML, and then hits them. It also *follows* hidden
instructions aimed at AI agents (TOKIWA Mirage canaries, or the lab victim's own canary) — but only on the same
origin: :func:`tokiwa.eval.safety.same_origin_path` is applied by the caller.

The canary wording used by the deception module is not fixed yet, so parsing is deliberately tolerant
(TODO(verify): align with docs/deception.md once the canary templates are final).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_JS_ROUTE = re.compile(r"""["'`](/api/[A-Za-z0-9_\-./{}$?=&]*)""")
_TEMPLATE_VAR = re.compile(r"\$\{[^}]*\}")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_HIDDEN_ELEMENT = re.compile(
    r"<(?P<tag>[a-z]+)[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|aria-hidden=['\"]true|hidden)[^>]*>"
    r"(?P<body>.*?)</(?P=tag)>",
    re.S | re.I,
)
_AI_ADDRESSEE = re.compile(
    r"(?i)\b(?:ai|llm|assistants?|agents?|gpt|claude|autonomous|automated)\b|アシスタント|エージェント"
)
_HEADER_INSTRUCTION = re.compile(r"\b([Xx]-[A-Za-z0-9-]{2,40})\s*:\s*([A-Za-z0-9._~\-]{6,128})")
_PATH_IN_TEXT = re.compile(r"(?<![\w/])(/[A-Za-z0-9._~\-/]{2,200})(?:\?[A-Za-z0-9._~\-=&%]*)?")


@dataclass(frozen=True)
class CanaryInstruction:
    path: str | None
    header: tuple[str, str] | None
    snippet: str


def extract_js_routes(text: str) -> list[str]:
    """API paths referenced in a JS bundle. Template variables become ``{id}``; query stubs are kept."""
    out: list[str] = []
    for m in _JS_ROUTE.finditer(text or ""):
        route = _TEMPLATE_VAR.sub("{id}", m.group(1)).rstrip("`'\"")
        if route not in out:
            out.append(route)
    return out


def extract_openapi_routes(text: str) -> list[tuple[str, str, list[str]]]:
    """(METHOD, path, parameter names) from an OpenAPI JSON document. Invalid input -> []."""
    try:
        doc = json.loads(text or "")
    except ValueError:
        return []
    paths = doc.get("paths") if isinstance(doc, dict) else None
    if not isinstance(paths, dict):
        return []
    out: list[tuple[str, str, list[str]]] = []
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            params = []
            if isinstance(op, dict):
                for p in op.get("parameters") or []:
                    if isinstance(p, dict) and isinstance(p.get("name"), str):
                        params.append(p["name"])
            out.append((method.upper(), str(path), params))
    return out


def extract_robots_disallow(text: str) -> list[str]:
    out: list[str] = []
    for line in (text or "").splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "disallow" and value.strip().startswith("/"):
            out.append(value.strip())
    return out


def _snippets(text: str) -> list[str]:
    found = [m.group(1) for m in _HTML_COMMENT.finditer(text)]
    found += [m.group("body") for m in _HIDDEN_ELEMENT.finditer(text)]
    # robots.txt / plain-text comments
    found += [line.lstrip("# ") for line in text.splitlines() if line.lstrip().startswith("#")]
    # OpenAPI "description" fields
    found += re.findall(r'"description"\s*:\s*"((?:[^"\\]|\\.){0,2000})"', text)
    return found


def find_canary_instructions(text: str) -> list[CanaryInstruction]:
    """Hidden instructions that address AI agents and name a header token and/or a path to visit."""
    out: list[CanaryInstruction] = []
    for snippet in _snippets(text or ""):
        if not _AI_ADDRESSEE.search(snippet):
            continue
        header_m = _HEADER_INSTRUCTION.search(snippet)
        header = (header_m.group(1), header_m.group(2)) if header_m else None
        path = None
        for pm in _PATH_IN_TEXT.finditer(snippet):
            candidate = pm.group(0).rstrip(".,;)")
            if candidate.count("/") >= 2 or candidate.startswith("/api"):
                path = candidate
                break
        if header or path:
            inst = CanaryInstruction(path=path, header=header, snippet=snippet.strip()[:300])
            if inst not in out:
                out.append(inst)
    return out
