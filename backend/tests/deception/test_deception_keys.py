"""Audit #68 (L11-03): derived decoy values must survive a JWT key rotation (key ring in data_dir/deception.key)."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import stat

import pytest

from tokiwa.auth import security
from tokiwa.config import reset_settings_cache
from tokiwa.deception import keys, service
from tokiwa.deception.tokens import Slot, derive_key, derive_keys, honey_values
from tokiwa.schemas.response import DeceptionAssetIn, DeceptionKind


def _rotate_jwt_key(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("TOKIWA_SERVER__SECRET_KEY", value)
    reset_settings_cache()
    security.reset_secret_cache()


def test_first_use_seeds_the_ring_with_the_old_derivation(settings) -> None:  # type: ignore[no-untyped-def]
    old = hmac.new(security.secret_key().encode(), b"tokiwa.deception.derive.v1", hashlib.sha256).digest()
    path = keys.key_file()
    assert not path.exists()
    assert derive_key() == old  # rendered values stay byte-identical for existing deployments
    assert path.exists() and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert keys.parse_keyring(path.read_text()) == [old]
    assert derive_keys() == [old]  # idempotent: the file is not rewritten


def test_jwt_rotation_no_longer_changes_derived_values(settings, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    before = derive_key()
    _rotate_jwt_key(monkeypatch, "rotated-after-a-suspected-leak-0123456789abcdef")
    assert keys.legacy_key() != before  # what the old code would have used from now on
    assert derive_key() == before


def test_rotation_keeps_old_values_matching(settings, caplog: pytest.LogCaptureFixture) -> None:  # type: ignore[no-untyped-def]
    old = derive_key()
    new = bytes(range(32))
    path = keys.key_file()
    path.write_text(f"# rotated\n{new.hex()}\n{path.read_text()}")
    assert derive_keys() == [new, old] and derive_key() == new
    # malformed / empty rings never stop detection: fall back to the legacy derivation, loudly
    path.write_text("not-hex\n")
    with caplog.at_level(logging.ERROR, logger="tokiwa.deception.keys"):
        assert derive_keys() == [keys.legacy_key()]
    assert "malformed" in caplog.text
    path.write_text("# only comments\n")
    assert derive_keys() == [keys.legacy_key()]
    with pytest.raises(ValueError, match="line 1"):
        keys.parse_keyring("abcd\n")  # too short


@pytest.mark.usefixtures("db")
async def test_index_matches_values_of_every_key_in_the_ring(monkeypatch: pytest.MonkeyPatch) -> None:
    env = await service.create_asset(
        DeceptionAssetIn(kind=DeceptionKind.DECOY_PATH, name="env", path="/.env")
    )
    assert env.token is not None
    handed_out = honey_values(DeceptionKind.DECOY_PATH, env.token, derive_key())  # what the attacker copied
    # the JWT key is rotated (leak suspected) ...
    _rotate_jwt_key(monkeypatch, "another-signing-key-after-rotation-0123456789")
    service.invalidate()
    index = await service.get_index()
    assert all(v in index.tokens for v in handed_out.values())
    # ... and later the deception key itself: new decoys render new values, the old ones still trip
    path = keys.key_file()
    path.write_text(f"{bytes(range(1, 33)).hex()}\n{path.read_text()}")
    service.invalidate()
    index = await service.get_index()
    assert handed_out[Slot.CANARY] in index.tokens and handed_out[Slot.AWS_SECRET] in index.tokens
    rendered = honey_values(DeceptionKind.DECOY_PATH, env.token, derive_key())
    assert rendered[Slot.CANARY] != handed_out[Slot.CANARY] and rendered[Slot.CANARY] in index.tokens
