"""Decoy matching against path variants a lenient upstream resolves to the same file (audit #54)."""

from __future__ import annotations

from urllib.parse import unquote

import pytest
from gate_helpers import FakeServer, GateFactory, Upstream, asgi_call, events_of, http_scope

from tokiwa.gate.policy import DecoyMatcher, match_key, normalize_path, path_anomalies
from tokiwa.schemas.response import DecoyRoute

ROUTES = [
    DecoyRoute(asset_id="env", kind="decoy_path", path="/.env", body="e"),
    DecoyRoute(asset_id="git", kind="decoy_path", path="/.git/config", body="g"),
    DecoyRoute(asset_id="php", kind="decoy_path", path="/admin/config.php", body="p"),
    DecoyRoute(asset_id="dbg", kind="decoy_path", path="/api/internal/debug", body="d"),
    DecoyRoute(asset_id="bak", kind="decoy_path", path="/backup/*", body="b"),
]


def _scope_path(raw_target: str) -> str:
    """What the ASGI server puts in scope['path'] for this raw request target (one percent-decoding)."""
    return unquote(raw_target)


# The repro of L06-03 (raw request targets that used to reach the upstream) + the asset each must hit.
VARIANTS = [
    ("/.ENV", "env"),
    ("/.env;x", "env"),
    ("/.env.", "env"),
    ("/.env%20", "env"),
    ("/.env%00", "env"),
    ("/.env/", "env"),
    ("/%5c.env", "env"),
    ("/x\\..\\.env", "env"),
    ("/x/..;/.env", "env"),
    ("/.env%2f", "env"),
    ("/%252eenv", "env"),
    ("/.git/config;", "git"),
    ("/.GIT/Config", "git"),
    ("/API/internal/debug", "dbg"),
    ("/api/internal/debug/", "dbg"),
    ("/admin/config.php%3b.css", "php"),
    ("/admin/config.php::$DATA", "php"),
    ("/BACKUP/db.sql", "bak"),
    ("/backup", "bak"),
    ("/backup;x/db.sql", "bak"),
]


@pytest.mark.parametrize(("target", "asset"), VARIANTS)
def test_variants_hit_the_decoy(target: str, asset: str) -> None:
    matcher, rejected = DecoyMatcher.build(ROUTES)
    assert rejected == []
    hit = matcher.match(_scope_path(target))
    assert hit is not None and hit.asset_id == asset, target


@pytest.mark.parametrize(
    "target", ["/.env.bak", "/.envx", "/admin/config.php.bak", "/backups/x", "/", "/x.env"]
)
def test_other_paths_do_not(target: str) -> None:
    matcher, _ = DecoyMatcher.build(ROUTES)
    assert matcher.match(_scope_path(target)) is None


def test_routes_that_reduce_to_the_root_are_rejected() -> None:
    """A route the server let through (normalize_path keeps "/;x") must not take over the home page here."""
    routes = [
        DecoyRoute(asset_id=p, kind="decoy_path", path=p, body="x") for p in ("/;x", "/%2e", "/ ", "/.env")
    ]
    matcher, rejected = DecoyMatcher.build(routes)
    assert rejected == ["/;x", "/%2e", "/ "]
    assert matcher.match("/") is None and matcher.match("/.env") is not None


def test_normalize_path_itself_is_unchanged() -> None:
    """The server validates and stores decoy paths with normalize_path (deception #65): keep it case-preserving."""
    assert normalize_path("/Admin/../.ENV") == "/.ENV"
    assert normalize_path("/a;x/") == "/a;x/"
    assert match_key("/Admin/../.ENV") == "/.env"


def test_path_anomalies() -> None:
    assert path_anomalies("/.env") == []
    assert path_anomalies("/a/..;/.env") == ["semicolon"]
    assert path_anomalies("/%2eenv") == ["double_encoding"]
    assert path_anomalies("/x\\y") == ["backslash"]
    assert path_anomalies("/.env\x00") == ["nul"]
    assert path_anomalies("/.env.") == ["trailing_dot_or_space"]
    assert path_anomalies("/��env") == ["invalid_utf8"]
    assert path_anomalies("/a/./b/../c") == []


async def test_gate_serves_the_decoy_for_a_variant(
    make_gate: GateFactory, upstream: Upstream, fake_server: FakeServer
) -> None:
    fake_server.set_policy("v1", decoys=ROUTES)
    app, gate = await make_gate()
    sent = await asgi_call(app, http_scope("/.env;x", b"/.env;x"))
    assert sent[0]["status"] == 200 and sent[1]["body"] == b"e"
    assert upstream.requests == []
    http_event, trip = await events_of(gate, fake_server)
    assert trip["deception"]["asset_id"] == "env"
    assert http_event["http"]["path"] == "/.env;x"  # recorded as sent
    assert "gate:path_anomaly" in http_event["tags"]
    assert http_event["labels"]["gate.path_anomaly"] == "semicolon"
