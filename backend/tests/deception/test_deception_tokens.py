"""Token formats: never masked by tokiwa.llm.redact, never an exact real-world credential format."""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from tokiwa.config import RedactionSettings
from tokiwa.deception.tokens import (
    Flavor,
    Slot,
    derive,
    flavor_for,
    flavor_of_token,
    generate_token,
    honey_values,
    primary_slot,
    survives_redaction,
    validate_token,
)
from tokiwa.llm.redact import _PATTERNS, redact_headers, redact_text
from tokiwa.schemas.response import DeceptionKind

STRICT = RedactionSettings(mask_emails=True, mask_ips=True)

# Real formats the fakes may *resemble* but must never be (exact, full match).
REAL_FORMATS = {
    "aws_access_key_id": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
    "aws_secret_access_key": r"[A-Za-z0-9/+]{40}",
    "openai": r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}",
    "anthropic": r"sk-ant-[A-Za-z0-9_-]{16,}",
    "stripe_secret": r"[sr]k_live_[0-9a-zA-Z]{24,}",
    "github": r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}",
    "slack": r"xox[abprs]-[A-Za-z0-9-]{10,}",
    "google_api_key": r"AIza[0-9A-Za-z_-]{35}",
    "jwt": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
}


def _values(per_flavor: int = 40) -> Iterator[str]:
    key = b"k"
    for flavor in Flavor:
        for _ in range(per_flavor):
            token = generate_token(flavor)
            yield token
            for kind in DeceptionKind:
                yield from honey_values(kind, token, key).values()


def test_generated_values_survive_redaction_in_observable_positions() -> None:
    for v in _values():
        for text in (
            v,
            f"GET /api/internal/{v}/users",
            f"page=2&ref={v}",
            f'{{"key": "{v}", "note": "x"}}',
            f"username={v}&password=hunter2",
            f"https://app.lab/api/internal/{v}/",
        ):
            assert v in (redact_text(text, STRICT) or ""), (v, text)
        headers = redact_headers({"X-Debug-Auth": v, "Referer": f"https://app.lab/api/internal/{v}/"}, STRICT)
        assert headers["x-debug-auth"] == v
        assert v in headers["referer"]


def test_no_redaction_pattern_matches_any_generated_value() -> None:
    for v in _values():
        for tag, pattern in _PATTERNS:
            assert not pattern.search(v), (tag, v)


def test_values_are_not_exact_real_formats() -> None:
    for v in _values():
        for name, pattern in REAL_FORMATS.items():
            assert not re.fullmatch(pattern, v), (name, v)


def test_fake_aws_key_resembles_but_is_never_a_valid_key_id() -> None:
    v = generate_token(Flavor.AWS)
    assert v.startswith("AKIA")
    assert len(v) == 24  # real access key ids are exactly 20 characters
    assert redact_text(f"aws_access_key_id {v}", STRICT) == f"aws_access_key_id {v}"


def test_tokens_are_unique() -> None:
    for flavor in Flavor:
        values = {generate_token(flavor) for _ in range(2000)}
        assert len(values) == 2000


def test_derive_is_deterministic_and_keyed() -> None:
    token = generate_token(Flavor.API_KEY)
    a = derive(b"key-1", token, Slot.AWS_SECRET)
    assert a == derive(b"key-1", token, Slot.AWS_SECRET)
    assert a != derive(b"key-2", token, Slot.AWS_SECRET)
    assert len(a) == 42  # deliberately not the real 40
    assert derive(b"key-1", token, Slot.CANARY).startswith("dbg_")


def test_honey_values_place_token_in_primary_slot() -> None:
    key = b"k"
    aws = generate_token(Flavor.AWS)
    values = honey_values(DeceptionKind.HONEYTOKEN, aws, key)
    assert values[Slot.AWS_KEY_ID] == aws
    assert values[Slot.AWS_SECRET] != aws
    canary = generate_token(Flavor.CANARY)
    assert honey_values(DeceptionKind.AI_CANARY, canary, key)[Slot.CANARY] == canary
    seed = generate_token(Flavor.SEED)
    assert seed not in honey_values(DeceptionKind.LABYRINTH, seed, key).values()  # seeds are never rendered
    assert len(set(honey_values(DeceptionKind.DECOY_PATH, generate_token(Flavor.API_KEY), key).values())) == 6


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("aws backup key", Flavor.AWS),
        ("S3 uploader", Flavor.AWS),
        ("prod database", Flavor.DB),
        ("postgres replica", Flavor.DB),
        ("payments api", Flavor.API_KEY),
    ],
)
def test_flavor_for_honeytoken_names(name: str, expected: Flavor) -> None:
    assert flavor_for(DeceptionKind.HONEYTOKEN, name) == expected


def test_flavor_for_other_kinds() -> None:
    assert flavor_for(DeceptionKind.AI_CANARY, "aws") == Flavor.CANARY
    assert flavor_for(DeceptionKind.LABYRINTH) == Flavor.SEED
    assert flavor_for(DeceptionKind.DECOY_PATH, "database") == Flavor.API_KEY
    assert flavor_of_token("my_custom_value_123") == Flavor.API_KEY
    assert primary_slot(DeceptionKind.HONEYTOKEN, generate_token(Flavor.DB)) == Slot.DB_USER
    assert primary_slot(DeceptionKind.LABYRINTH, "mz_x") is None


@pytest.mark.parametrize(
    "bad",
    [
        "short",
        "contains whitespace inside",
        "AKIAABCDEFGHIJKLMNOP",  # exact AWS key id format -> masked
        "sk-ant-abcdefghijklmnopqrstuvwx",
        "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4",
        "someone@example.com",
        "10.20.30.40.canary",
        "x" * 200,
    ],
)
def test_validate_token_rejects_unusable_values(bad: str) -> None:
    assert validate_token(bad, STRICT) is not None


def test_validate_token_accepts_custom_values() -> None:
    assert validate_token("corp_canary_7f3a9c1e2b", STRICT) is None
    assert survives_redaction("corp_canary_7f3a9c1e2b", STRICT, canary_header="X-Debug-Auth")
    # a header listed as sensitive masks the value -> not usable for the canary
    assert not survives_redaction("corp_canary_7f3a9c1e2b", STRICT, canary_header="Authorization")
