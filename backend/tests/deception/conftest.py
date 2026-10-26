"""Helpers for deception tests."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime

import pytest

from tokiwa.deception import service
from tokiwa.deception.tokens import Flavor, generate_token
from tokiwa.schemas.response import DeceptionAsset, DeceptionKind
from tokiwa.util import new_id

KEY = b"unit-test-derive-key"

_FLAVOR = {
    DeceptionKind.DECOY_PATH: Flavor.API_KEY,
    DeceptionKind.HONEYTOKEN: Flavor.API_KEY,
    DeceptionKind.AI_CANARY: Flavor.CANARY,
    DeceptionKind.LABYRINTH: Flavor.SEED,
}


@pytest.fixture(autouse=True)
def _fresh_deception_cache() -> Iterator[None]:
    service.invalidate()
    yield
    service.invalidate()


@pytest.fixture
def make_asset() -> Callable[..., DeceptionAsset]:
    """In-memory DeceptionAsset (no DB) for pure render/matcher tests."""

    def _make(
        kind: DeceptionKind,
        path: str | None = None,
        *,
        token: str | None = None,
        name: str | None = None,
        enabled: bool = True,
        content_template: str | None = None,
        flavor: Flavor | None = None,
    ) -> DeceptionAsset:
        return DeceptionAsset(
            id=new_id(),
            kind=kind,
            name=name or f"{kind.value} {path or ''}".strip(),
            path=path,
            token=token or generate_token(flavor or _FLAVOR[kind]),
            content_template=content_template,
            description=None,
            enabled=enabled,
            created_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
            trip_count=0,
            last_tripped=None,
        )

    return _make
