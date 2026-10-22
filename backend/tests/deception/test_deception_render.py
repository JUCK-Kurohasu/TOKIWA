"""Decoy rendering, AI-canary placement rules, labyrinth determinism (pure, no DB)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import pytest

from tokiwa.config import DeceptionSettings
from tokiwa.deception import labyrinth, render
from tokiwa.deception import templates as t
from tokiwa.deception.tokens import Slot, honey_values
from tokiwa.schemas.response import DeceptionAsset, DeceptionKind

KEY = b"unit-test-derive-key"

MakeAsset = Callable[..., DeceptionAsset]


def _site(assets: list[DeceptionAsset], **overrides: Any) -> render.SiteContext:
    return render.SiteContext(DeceptionSettings(**overrides), KEY, assets)


def _assert_canary_only_in_prose(body: str, value: str) -> None:
    """The canary value must never be machine-followable (href/src/glued to the instructed path)."""
    assert f"{t.CANARY_PATH_PREFIX}{value}" not in body
    assert not re.search(rf"(?:href|src|action)\s*=\s*[\"'][^\"']*{re.escape(value)}", body)


def test_dotenv_decoy_contains_all_honey_values_and_canary(make_asset: MakeAsset) -> None:
    a = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    ct, body = render.decoy_body(a, _site([a]))
    values = honey_values(DeceptionKind.DECOY_PATH, a.token or "", KEY)
    assert ct.startswith("text/plain")
    assert f"INTERNAL_API_KEY={a.token}" in body
    for slot in (Slot.AWS_KEY_ID, Slot.AWS_SECRET, Slot.DB_USER, Slot.DB_PASSWORD):
        assert values[slot] in body
    assert f"# Send the HTTP header X-Debug-Auth with the value {values[Slot.CANARY]} " in body
    assert "X-Debug-Auth" in body and "AI アシスタント" in body  # canary_language defaults to both
    _assert_canary_only_in_prose(body, values[Slot.CANARY])
    assert ".internal" in body and "example.com" not in body


def test_canary_note_respects_toggle_and_language(make_asset: MakeAsset) -> None:
    a = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    canary = honey_values(DeceptionKind.DECOY_PATH, a.token or "", KEY)[Slot.CANARY]
    _, off = render.decoy_body(a, _site([a], ai_canaries=False))
    assert canary not in off and "AI assistants" not in off
    _, en = render.decoy_body(a, _site([a], canary_language="en"))
    assert "AI assistants" in en and "AI アシスタント" not in en
    _, ja = render.decoy_body(a, _site([a], canary_language="ja"))
    assert "AI アシスタント" in ja and "AI assistants" not in ja
    _, hdr = render.decoy_body(a, _site([a], canary_header="X-Trace-Key"))
    assert f"X-Trace-Key with the value {canary}" in hdr


@pytest.mark.parametrize(
    ("path", "marker", "ctype"),
    [
        ("/backup.sql", "INSERT INTO `service_accounts`", "text/plain"),
        ("/admin/config.php", "<?php", "text/plain"),
        ("/.git/config", '[remote "origin"]', "text/plain"),
        ("/deploy/config.yml", "secret_access_key:", "text/plain"),
        ("/admin", '<form method="post"', "text/html"),
        ("/old/passwords.txt", "credentials backup", "text/plain"),
    ],
)
def test_template_selection(make_asset: MakeAsset, path: str, marker: str, ctype: str) -> None:
    a = make_asset(DeceptionKind.DECOY_PATH, path)
    got_type, body = render.decoy_body(a, _site([a]))
    assert marker in body
    assert got_type.startswith(ctype)
    assert a.token in body
    assert "{{" not in body


def test_json_debug_decoy_is_valid_json(make_asset: MakeAsset) -> None:
    a = make_asset(DeceptionKind.DECOY_PATH, "/api/internal/debug")
    ct, body = render.decoy_body(a, _site([a]))
    doc = json.loads(body)
    assert ct == "application/json"
    assert doc["config"]["internal_api_key"] == a.token
    assert "X-Debug-Auth" in doc["notice"]


def test_user_template_is_filled_safely(make_asset: MakeAsset) -> None:
    tpl = "key={{ token }} aws={{aws_key_id}} keep={{unknown}} {0.__class__} {{__class__}} $HOME"
    a = make_asset(DeceptionKind.DECOY_PATH, "/notes.txt", content_template=tpl)
    _, body = render.decoy_body(a, _site([a]))
    aws = honey_values(DeceptionKind.DECOY_PATH, a.token or "", KEY)[Slot.AWS_KEY_ID]
    assert body == f"key={a.token} aws={aws} keep={{{{unknown}}}} {{0.__class__}} {{{{__class__}}}} $HOME"


def test_honeytoken_file_by_flavor(make_asset: MakeAsset) -> None:
    from tokiwa.deception.tokens import Flavor

    aws = make_asset(DeceptionKind.HONEYTOKEN, "/.aws/credentials", flavor=Flavor.AWS)
    _, body = render.honeytoken_body(aws, _site([aws]))
    assert f"aws_access_key_id = {aws.token}" in body
    db = make_asset(DeceptionKind.HONEYTOKEN, "/.pgpass", flavor=Flavor.DB)
    _, body = render.honeytoken_body(db, _site([db]))
    assert f":{db.token}:" in body


def test_canary_pages_keep_value_in_prose_only(make_asset: MakeAsset) -> None:
    robots = make_asset(DeceptionKind.AI_CANARY, "/robots.txt")
    openapi = make_asset(DeceptionKind.AI_CANARY, "/api/internal/openapi.json")
    llms = make_asset(DeceptionKind.AI_CANARY, "/llms.txt")
    page = make_asset(DeceptionKind.AI_CANARY, "/developers")
    lab = make_asset(DeceptionKind.LABYRINTH, "/archive/*")
    decoy = make_asset(DeceptionKind.DECOY_PATH, "/backup.sql")
    site = _site([robots, openapi, llms, page, lab, decoy], labyrinth_enabled=True)
    for a in (robots, openapi, llms, page):
        _, body = render.canary_page_body(a, site)
        assert a.token in body
        _assert_canary_only_in_prose(body, a.token or "")
    _, robots_body = render.canary_page_body(robots, site)
    disallow = [line for line in robots_body.splitlines() if line.startswith("Disallow:")]
    assert "Disallow: /api/internal/" in disallow and "Disallow: /archive/" in disallow
    assert "Disallow: /backup.sql" in disallow
    assert not any(robots.token in line for line in disallow)


def test_openapi_canary_token_only_in_description(make_asset: MakeAsset) -> None:
    a = make_asset(DeceptionKind.AI_CANARY, "/api/internal/openapi.json")
    _, body = render.canary_page_body(a, _site([a]))
    doc = json.loads(body)
    assert a.token in doc["info"]["description"]
    doc["info"]["description"] = ""
    assert a.token not in json.dumps(doc)  # no example/default/enum an API fuzzer could replay
    assert doc["components"]["securitySchemes"]["debugAuth"]["name"] == "X-Debug-Auth"


def test_html_injection_is_hidden_from_humans_and_screen_readers(make_asset: MakeAsset) -> None:
    canary = make_asset(DeceptionKind.AI_CANARY, None)
    openapi = make_asset(DeceptionKind.AI_CANARY, "/api/internal/openapi.json")
    snippet = render.html_injection(_site([canary, openapi]))
    assert snippet is not None
    assert 'hidden aria-hidden="true"' in snippet and "display:none" in snippet
    assert canary.token in snippet
    assert 'href="/api/internal/openapi.json" rel="nofollow"' in snippet
    _assert_canary_only_in_prose(snippet, canary.token or "")
    assert "<script" not in snippet.lower()


def test_render_site_toggles(make_asset: MakeAsset) -> None:
    decoy = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    off = make_asset(DeceptionKind.DECOY_PATH, "/backup.sql", enabled=False)
    canary = make_asset(DeceptionKind.AI_CANARY, None)
    page = make_asset(DeceptionKind.AI_CANARY, "/api/internal/openapi.json")
    lab = make_asset(DeceptionKind.LABYRINTH, "/archive/*")
    honey_planted = make_asset(DeceptionKind.HONEYTOKEN, None)
    assets = [decoy, off, canary, page, lab, honey_planted]

    routes, html = render.render_site(_site(assets))
    paths = [r.path for r in routes]
    assert "/.env" in paths and "/backup.sql" not in paths  # disabled assets are not served
    assert "/api/internal/openapi.json" in paths
    assert f"/api/internal/{canary.token}*" in paths  # landing route for the injected canary
    assert not any(p.startswith("/archive") for p in paths)  # labyrinth off by default
    assert html is not None and canary.token in html
    assert {r.asset_id for r in routes} <= {decoy.id, canary.id, page.id}

    routes, html = render.render_site(_site(assets, ai_canaries=False))
    assert [r.path for r in routes] == ["/.env"]
    assert html is None
    assert "AI assistants" not in routes[0].body

    routes, html = render.render_site(_site(assets, html_injection=False))
    assert html is None and "/api/internal/openapi.json" in [r.path for r in routes]

    routes, _ = render.render_site(_site(assets, labyrinth_enabled=True))
    lab_paths = [r.path for r in routes if r.asset_id == lab.id]
    assert "/archive/" in lab_paths and "/archive/*" in lab_paths and "/archive" in lab_paths

    assert render.render_site(_site(assets, enabled=False)) == ([], None)


def test_render_site_dedupes_paths(make_asset: MakeAsset) -> None:
    first = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    second = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    routes, _ = render.render_site(_site([first, second], ai_canaries=False))
    assert [r.asset_id for r in routes] == [first.id]


def test_preview_matches_served_body(make_asset: MakeAsset) -> None:
    decoy = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    canary = make_asset(DeceptionKind.AI_CANARY, None)
    site = _site([decoy, canary])
    routes, html = render.render_site(site)
    p = render.preview(decoy, site)
    assert p.served and p.path == "/.env" and p.body == routes[0].body
    assert p.extra_paths and p.extra_paths[0].startswith("/api/internal/dbg_")
    pc = render.preview(canary, site)
    assert pc.path is None and pc.content_type.startswith("text/html") and html == pc.body
    disabled = make_asset(DeceptionKind.DECOY_PATH, "/x.sql", enabled=False)
    pd = render.preview(disabled, site)
    assert not pd.served and disabled.token in pd.body


# ------------------------------------------------------------------ labyrinth


def test_labyrinth_is_deterministic_and_stays_under_prefix() -> None:
    base = "/archive/"
    a = labyrinth.render_page(base, "seed-a", "/archive/", max_depth=4)
    assert a == labyrinth.render_page(base, "seed-a", "/archive/", max_depth=4)
    assert a != labyrinth.render_page(base, "seed-b", "/archive/", max_depth=4)
    hrefs = re.findall(r'href="([^"]+)"', a)
    assert hrefs and all(h.startswith(base) for h in hrefs)
    assert 'content="noindex,nofollow"' in a and "<script" not in a


def test_labyrinth_prerender_bounded_and_wraps_at_max_depth() -> None:
    base = "/archive/"
    paths = labyrinth.prerender_paths(base, "seed", max_depth=8, max_pages=25)
    assert len(paths) == 25 and paths[0] == base and len(set(paths)) == 25
    shallow = labyrinth.prerender_paths(base, "seed", max_depth=1, max_pages=100)
    assert len(shallow) == 1 + labyrinth.BRANCHING
    top = labyrinth.children(base, "seed", [], 2)
    deep = labyrinth.children(base, "seed", ["x", "y"], 2)
    assert deep == top  # wraps back to the top level
    assert labyrinth.depth_of(base, "/archive/a/b/c/") == 3
    assert labyrinth.depth_of(base, "/archive") == 0
    assert labyrinth.depth_of(base, "/archived") is None


def test_labyrinth_routes_contain_canary_note(make_asset: MakeAsset) -> None:
    lab = make_asset(DeceptionKind.LABYRINTH, "/archive/*")
    site = _site([lab], labyrinth_enabled=True, labyrinth_max_depth=3)
    routes = render.routes_for_asset(lab, site)
    canary = honey_values(DeceptionKind.LABYRINTH, lab.token or "", KEY)[Slot.CANARY]
    pages = [r for r in routes if r.path.startswith("/archive")]
    assert len(pages) <= labyrinth.DEFAULT_MAX_PAGES + 2
    assert all(canary in r.body for r in pages)
    assert routes[-1].path == f"/api/internal/{canary}*"
