"""Audit #65 (L09-06): a decoy / deploy_canary path must not take over the protected site.

The Gate answers decoys for every visitor and never forwards them. ``/.`` passed the old literal ``== "/"``
check but the Gate normalizes it to ``/`` - the whole site became a decoy; ``/a*`` took ``/about``, ``/api/...``.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tokiwa.config import DeceptionSettings
from tokiwa.deception import service
from tokiwa.deception.render import SiteContext, render_site, shadows_site
from tokiwa.gate.policy import DecoyMatcher
from tokiwa.schemas.deception import DeceptionAssetUpdate
from tokiwa.schemas.response import DeceptionAsset, DeceptionAssetIn, DeceptionKind

MakeAsset = Callable[..., DeceptionAsset]

SITE_ROOTS = ["/.", "/./", "//", "///", "/a/..", "/a/../", "/%2e", "/%2E/", "/%252e", "/.*", "//*", "/a/../*"]


@pytest.mark.usefixtures("db")
@pytest.mark.parametrize("path", SITE_ROOTS)
@pytest.mark.parametrize(
    "kind", [DeceptionKind.DECOY_PATH, DeceptionKind.AI_CANARY, DeceptionKind.HONEYTOKEN]
)
async def test_paths_that_mean_the_site_root_are_refused(kind: DeceptionKind, path: str) -> None:
    with pytest.raises(service.DeceptionError, match="shadow the whole protected site") as exc:
        await service.create_asset(DeceptionAssetIn(kind=kind, name="x", path=path))
    assert exc.value.status_code == 422


@pytest.mark.usefixtures("db")
@pytest.mark.parametrize("path", ["/a*", "/admin*", "/.e*", "/api/../a*"])
async def test_prefix_routes_need_a_complete_segment(path: str) -> None:
    with pytest.raises(service.DeceptionError, match="complete segment"):
        await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.DECOY_PATH, name="x", path=path))


@pytest.mark.usefixtures("db")
async def test_paths_are_stored_gate_normalized_and_duplicates_conflict() -> None:
    ok = {
        "/admin/*": "/admin/*",
        "/api/internal/dbg*": "/api/internal/dbg*",
        "/static/../backup2.sql": "/backup2.sql",
        "//old//site.zip": "/old/site.zip",
        "/admin/./x/": "/admin/x/",
    }
    for raw, stored in ok.items():
        a = await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.DECOY_PATH, name=raw, path=raw))
        assert a.path == stored
    with pytest.raises(service.DeceptionConflict):
        await service.create_asset(
            DeceptionAssetIn(kind=DeceptionKind.DECOY_PATH, name="d", path="/backup2.sql")
        )
    lab = await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.LABYRINTH, name="lab"))
    assert lab.path == "/archive/*"  # the labyrinth default still passes
    with pytest.raises(service.DeceptionError):
        await service.create_asset(DeceptionAssetIn(kind=DeceptionKind.LABYRINTH, name="lab2", path="/."))
    # an update cannot sneak the root in either (deploy_canary goes through create_asset too)
    with pytest.raises(service.DeceptionError):
        await service.update_asset(lab.id, DeceptionAssetUpdate(path="/x/.."))


def test_old_rows_with_a_root_path_are_not_served(make_asset: MakeAsset) -> None:
    """Assets created before the validation may still say "/."; the Gate must not get them."""
    bad = make_asset(DeceptionKind.DECOY_PATH, "/.")
    good = make_asset(DeceptionKind.DECOY_PATH, "/.env")
    routes, _ = render_site(SiteContext(DeceptionSettings(), b"k", [bad, good]))
    assert "/." not in {r.path for r in routes} and "/.env" in {r.path for r in routes}
    matcher, _ = DecoyMatcher.build(routes)
    assert matcher.match("/") is None and matcher.match("/.env") is not None
    assert all(shadows_site(p) for p in SITE_ROOTS)
    assert not any(shadows_site(p) for p in ["/.env", "/admin/*", "/a*", "/.well-known/x"])
