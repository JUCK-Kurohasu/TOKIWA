"""Render deception assets into what the Gate serves (``DecoyRoute``) and the HTML injection snippet.

Pure functions over (assets, settings, derive key). ``policy.build_gate_decoys`` and the preview API share them,
so the preview shows byte-for-byte what the Gate serves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tokiwa.config import DeceptionSettings
from tokiwa.deception import labyrinth
from tokiwa.deception import templates as t
from tokiwa.deception.matcher import normalize_path
from tokiwa.deception.tokens import Slot, honey_values, primary_slot
from tokiwa.schemas.deception import DeceptionPreview
from tokiwa.schemas.response import DeceptionAsset, DeceptionKind, DecoyRoute

_NO_STORE = {"Cache-Control": "no-store"}


@dataclass
class SiteContext:
    """Everything rendering needs: settings, the derive key and the currently enabled assets."""

    settings: DeceptionSettings
    key: bytes
    assets: list[DeceptionAsset] = field(default_factory=list)

    @property
    def canaries_on(self) -> bool:
        return self.settings.enabled and self.settings.ai_canaries

    def labyrinth_bases(self) -> list[str]:
        if not self.settings.labyrinth_enabled:
            return []
        return [
            labyrinth.normalize_base(a.path, self.settings.labyrinth_prefix)
            for a in self.assets
            if a.kind == DeceptionKind.LABYRINTH
        ]

    def plain_decoy_paths(self) -> list[str]:
        """Decoy paths that may be advertised (robots Disallow): no wildcards, no dot-files."""
        return [
            a.path
            for a in self.assets
            if a.kind == DeceptionKind.DECOY_PATH and a.path and "*" not in a.path and "/." not in a.path
        ]

    def openapi_canary_paths(self) -> list[str]:
        return [
            a.path
            for a in self.assets
            if a.kind == DeceptionKind.AI_CANARY and a.path and _is_openapi(a.path)
        ]


def _is_openapi(path: str) -> bool:
    p = path.lower()
    return p.endswith(".json") or "openapi" in p or "swagger" in p


def _tidy(body: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", body)


def canary_lines(value: str, site: SiteContext) -> list[str]:
    if not site.canaries_on:
        return []
    return t.canary_sentences(value, site.settings.canary_header, site.settings.canary_language)


def context_for(asset: DeceptionAsset, site: SiteContext) -> tuple[dict[str, str], list[str]]:
    """Template context (all placeholder values) and the canary sentences for this asset."""
    token = asset.token or ""
    values = honey_values(DeceptionKind(asset.kind), token, site.key)
    ctx = {slot.value: v for slot, v in values.items()}
    lines = canary_lines(values[Slot.CANARY], site)
    ctx.update(
        token=token,
        canary_header=site.settings.canary_header,
        canary_note=" ".join(lines),
        canary_html=t.hidden_html(lines),
        host=t.FAKE_HOST,
        db_host=t.FAKE_DB_HOST,
        git_host=t.FAKE_GIT_HOST,
        path=asset.path or "",
        date=asset.created_at.strftime("%Y-%m-%d %H:%M:%S"),
    )
    return ctx, lines


def _guess_type(path: str | None, body: str) -> str:
    p = (path or "").lower()
    head = body.lstrip()[:1]
    if p.endswith((".html", ".htm")) or head == "<":
        return t.TEXT_HTML
    if p.endswith(".json") or head in ("{", "["):
        return t.APP_JSON
    return t.TEXT_PLAIN


def decoy_body(asset: DeceptionAsset, site: SiteContext) -> tuple[str, str]:
    """(content_type, body) for a decoy_path asset."""
    ctx, lines = context_for(asset, site)
    if asset.content_template:
        body = t.fill(asset.content_template, ctx)
        return _guess_type(asset.path, body), body
    tpl = t.template_for_path(asset.path or "/")
    if isinstance(tpl, str):  # JSON_DEBUG
        return t.APP_JSON, t.json_debug_body(ctx, lines)
    note = t.comment(lines, tpl.style)
    return tpl.content_type, _tidy(t.fill(tpl.body, {**ctx, "canary_note": note}))


def honeytoken_body(asset: DeceptionAsset, site: SiteContext) -> tuple[str, str]:
    ctx, _lines = context_for(asset, site)
    if asset.content_template:
        body = t.fill(asset.content_template, ctx)
        return _guess_type(asset.path, body), body
    slot = primary_slot(DeceptionKind.HONEYTOKEN, asset.token or "")
    tpl = t.HONEY_AWS if slot == Slot.AWS_KEY_ID else t.HONEY_DB if slot == Slot.DB_USER else t.HONEY_API
    return t.TEXT_PLAIN, t.fill(tpl, ctx)


def canary_page_body(asset: DeceptionAsset, site: SiteContext) -> tuple[str, str]:
    """(content_type, body) for an ai_canary asset with a path."""
    ctx, _ = context_for(asset, site)
    lines = t.canary_sentences(asset.token or "", site.settings.canary_header, site.settings.canary_language)
    ctx.update(canary_note=" ".join(lines), canary_html=t.hidden_html(lines))
    if asset.content_template:
        body = t.fill(asset.content_template, ctx)
        return _guess_type(asset.path, body), body
    p = (asset.path or "").lower()
    if p.endswith("robots.txt"):
        disallow = [t.CANARY_PATH_PREFIX, *site.labyrinth_bases(), *site.plain_decoy_paths()]
        return t.TEXT_PLAIN, t.robots_body(lines, list(dict.fromkeys(disallow)))
    if _is_openapi(p):
        return t.APP_JSON, t.openapi_body(lines, site.settings.canary_header)
    if p.endswith(".md"):
        return "text/markdown; charset=utf-8", t.markdown_body(lines)
    if p.endswith(".txt"):
        return t.TEXT_PLAIN, t.markdown_body(lines)
    return t.TEXT_HTML, t.html_canary_page(lines)


def canary_snippet(asset: DeceptionAsset, site: SiteContext, links: list[tuple[str, str]]) -> str:
    """Hidden HTML for a path-less ai_canary (appended before </body> of upstream HTML by the Gate)."""
    ctx, _ = context_for(asset, site)
    lines = t.canary_sentences(asset.token or "", site.settings.canary_header, site.settings.canary_language)
    ctx.update(canary_note=" ".join(lines), canary_html=t.hidden_html(lines, links))
    if asset.content_template:
        return t.fill(asset.content_template, ctx)
    return t.hidden_html(lines, links)


def landing_route(asset: DeceptionAsset, value: str) -> DecoyRoute:
    """Prefix route that answers requests made by following the canary instruction (fake endpoint index)."""
    return DecoyRoute(
        asset_id=asset.id,
        kind=str(asset.kind),
        path=f"{t.CANARY_PATH_PREFIX}{value}*",
        content_type=t.APP_JSON,
        body=t.canary_landing_body(value),
        headers=dict(_NO_STORE),
    )


def _route(asset: DeceptionAsset, path: str, content_type: str, body: str) -> DecoyRoute:
    return DecoyRoute(
        asset_id=asset.id,
        kind=str(asset.kind),
        path=path,
        content_type=content_type,
        body=body,
        headers=dict(_NO_STORE),
    )


def labyrinth_routes(asset: DeceptionAsset, site: SiteContext) -> list[DecoyRoute]:
    s = site.settings
    base = labyrinth.normalize_base(asset.path, s.labyrinth_prefix)
    seed = asset.token or asset.id
    _, lines = context_for(asset, site)
    note = t.hidden_html(lines)
    out: list[DecoyRoute] = []
    for p in labyrinth.prerender_paths(base, seed, max_depth=s.labyrinth_max_depth):
        body = labyrinth.render_page(
            base, seed, p, max_depth=s.labyrinth_max_depth, language=s.canary_language, canary_html=note
        )
        out.append(_route(asset, p, t.TEXT_HTML, body))
    root = out[0].body
    out.append(_route(asset, base.rstrip("/") or "/", t.TEXT_HTML, root))
    out.append(_route(asset, base + "*", t.TEXT_HTML, root))  # everything deeper: endless, same page
    return out


def routes_for_asset(asset: DeceptionAsset, site: SiteContext) -> list[DecoyRoute]:
    kind = DeceptionKind(asset.kind)
    values = honey_values(kind, asset.token or "", site.key)
    out: list[DecoyRoute] = []
    if kind == DeceptionKind.DECOY_PATH and asset.path:
        ct, body = decoy_body(asset, site)
        out.append(_route(asset, asset.path, ct, body))
        if site.canaries_on:
            out.append(landing_route(asset, values[Slot.CANARY]))
    elif kind == DeceptionKind.HONEYTOKEN and asset.path:
        ct, body = honeytoken_body(asset, site)
        out.append(_route(asset, asset.path, ct, body))
    elif kind == DeceptionKind.AI_CANARY and site.canaries_on and asset.token:
        if asset.path:
            ct, body = canary_page_body(asset, site)
            out.append(_route(asset, asset.path, ct, body))
        out.append(landing_route(asset, asset.token))
    elif kind == DeceptionKind.LABYRINTH and site.settings.labyrinth_enabled:
        out.extend(labyrinth_routes(asset, site))
        if site.canaries_on:
            out.append(landing_route(asset, values[Slot.CANARY]))
    return out


def html_injection(site: SiteContext) -> str | None:
    if not site.canaries_on or not site.settings.html_injection:
        return None
    links = [(p, "Internal API reference") for p in site.openapi_canary_paths()]
    links += [(b, "Document archive") for b in site.labyrinth_bases()]
    parts: list[str] = []
    for a in site.assets:
        if a.kind == DeceptionKind.AI_CANARY and not a.path and a.token:
            parts.append(canary_snippet(a, site, links))
            links = []  # advertise the hidden links once
    return "\n".join(parts) or None


def render_site(site: SiteContext) -> tuple[list[DecoyRoute], str | None]:
    """All Gate decoys for the enabled assets (first asset wins on a duplicate path) + HTML injection."""
    if not site.settings.enabled:
        return [], None
    routes: list[DecoyRoute] = []
    seen: set[str] = set()
    for a in site.assets:
        if not a.enabled:
            continue
        for r in routes_for_asset(a, site):
            if r.path in seen:
                continue
            seen.add(r.path)
            routes.append(r)
    return routes, html_injection(site)


def preview(asset: DeceptionAsset, site: SiteContext, path: str | None = None) -> DeceptionPreview:
    """Render one asset as it would be served. Global toggles for the asset's own feature are forced on, and
    ``served`` tells whether the Gate actually serves it with the current settings."""
    kind = DeceptionKind(asset.kind)
    s = site.settings
    served = bool(
        s.enabled
        and asset.enabled
        and (kind != DeceptionKind.AI_CANARY or s.ai_canaries)
        and (kind != DeceptionKind.LABYRINTH or s.labyrinth_enabled)
        and (kind != DeceptionKind.HONEYTOKEN or asset.path)
        and (kind != DeceptionKind.AI_CANARY or asset.path or s.html_injection)
    )
    forced = s.model_copy(update={"enabled": True})
    if kind == DeceptionKind.AI_CANARY:
        forced = forced.model_copy(update={"ai_canaries": True})
    if kind == DeceptionKind.LABYRINTH:
        forced = forced.model_copy(update={"labyrinth_enabled": True})
    fsite = SiteContext(forced, site.key, [a for a in site.assets if a.id != asset.id] + [asset])

    if kind == DeceptionKind.AI_CANARY and not asset.path:
        links = [(p, "Internal API reference") for p in fsite.openapi_canary_paths()]
        links += [(b, "Document archive") for b in fsite.labyrinth_bases()]
        landing = landing_route(asset, asset.token or "")
        return DeceptionPreview(
            asset_id=asset.id,
            path=None,
            content_type=t.TEXT_HTML,
            body=canary_snippet(asset, fsite, links),
            served=served,
            extra_paths=[landing.path],
        )
    if kind == DeceptionKind.HONEYTOKEN and not asset.path:
        ct, body = honeytoken_body(asset, fsite)
        return DeceptionPreview(asset_id=asset.id, path=None, content_type=ct, body=body, served=False)
    if kind == DeceptionKind.LABYRINTH and path:
        base = labyrinth.normalize_base(asset.path, forced.labyrinth_prefix)
        norm = normalize_path(path)
        if labyrinth.rel_segments(base, norm) is not None:
            _, lines = context_for(asset, fsite)
            body = labyrinth.render_page(
                base,
                asset.token or asset.id,
                norm,
                max_depth=forced.labyrinth_max_depth,
                language=forced.canary_language,
                canary_html=t.hidden_html(lines),
            )
            return DeceptionPreview(
                asset_id=asset.id, path=norm, content_type=t.TEXT_HTML, body=body, served=served
            )
    routes = routes_for_asset(asset, fsite)
    if not routes:
        return DeceptionPreview(
            asset_id=asset.id, path=asset.path, content_type=t.TEXT_PLAIN, body="", served=False
        )
    main = routes[0]
    return DeceptionPreview(
        asset_id=asset.id,
        path=main.path,
        content_type=main.content_type,
        body=main.body,
        status_code=main.status_code,
        headers=main.headers,
        served=served,
        extra_paths=[r.path for r in routes[1:]],
    )
