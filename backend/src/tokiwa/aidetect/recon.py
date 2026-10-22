"""Discovery-endpoint catalogue for semantic reconnaissance.

LLM agents (and their recon helpers) prefer *machine-readable descriptions* of a target over blind brute force:
API specs (OpenAPI/Swagger), GraphQL introspection, AI-ecosystem manifests (``/.well-known/ai-plugin.json``,
MCP endpoints, ``/llms.txt``, A2A agent cards) and hint files (robots.txt, sitemap.xml, JS bundles, source maps).
Fetching one of these and then hitting the *real* routes it describes is the "semantic recon" pattern.

Kinds:

- SPEC_KINDS     describe the API surface directly (strong discovery source)
- AI_ECOSYSTEM   only meaningful to AI agents / LLM tooling (probing them is itself an AI-ish signal)
- HINT_KINDS     weaker sources (robots, sitemap, JS bundles, source maps)

TODO(verify): the A2A agent-card path (``/.well-known/agent.json`` vs ``agent-card.json``) has changed across
spec drafts; both are listed.
"""

from __future__ import annotations

import re

SPEC_KINDS = frozenset({"openapi", "graphql_introspection", "wsdl"})
AI_ECOSYSTEM_KINDS = frozenset({"ai_plugin", "mcp", "llms_txt", "agent_card"})
HINT_KINDS = frozenset({"robots", "sitemap", "js", "source_map"})
DISCOVERY_SOURCE_KINDS = SPEC_KINDS | AI_ECOSYSTEM_KINDS | HINT_KINDS

_PATH_RULES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p, re.I), kind)
    for p, kind in (
        (r"/\.well-known/ai-plugin\.json$", "ai_plugin"),
        (r"/\.well-known/mcp(?:\.json)?$|/mcp(?:/sse|/messages)?/?$|/mcp\.json$", "mcp"),
        (r"/llms(?:-full)?\.txt$", "llms_txt"),
        (r"/\.well-known/agent(?:-card)?\.json$", "agent_card"),
        (
            r"/(?:openapi|swagger)(?:[-_.]?v?\d)?\.(?:json|ya?ml)$|/swagger(?:-ui)?(?:/|\.html|/index\.html)?$"
            r"|/(?:v\d/)?api-docs(?:/|\.json)?$|/swagger/v\d+/swagger\.json$|/redoc/?$|/openapi/?$",
            "openapi",
        ),
        (r"/robots\.txt$", "robots"),
        (r"/sitemap(?:_index)?\.xml$", "sitemap"),
        (r"\.(?:js|mjs)\.map$|\.css\.map$", "source_map"),
        (r"\.(?:js|mjs)$", "js"),
    )
)

_INTROSPECTION_RE = re.compile(r"__schema|IntrospectionQuery|__type\s*\(", re.I)
_WSDL_RE = re.compile(r"(?:^|&)wsdl(?:=|&|$)", re.I)


def discovery_kind(path: str | None, query: str | None = None, body: str | None = None) -> str | None:
    """Classify a request as a discovery fetch (``None`` when it is not one)."""
    p = (path or "").split("?", 1)[0][:512]
    if not p:
        return None
    if "graphql" in p.lower() and (
        _INTROSPECTION_RE.search((query or "")[:4096]) or _INTROSPECTION_RE.search((body or "")[:4096])
    ):
        return "graphql_introspection"
    if query and _WSDL_RE.search(query[:256]):
        return "wsdl"
    for pattern, kind in _PATH_RULES:
        if pattern.search(p):
            return kind
    return None


def is_strong_discovery(kind: str | None) -> bool:
    return kind in SPEC_KINDS or kind in AI_ECOSYSTEM_KINDS
