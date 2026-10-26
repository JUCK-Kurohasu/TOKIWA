"""Honeytoken / AI-canary value generation.

Why the formats look the way they do
------------------------------------
Events reach the server *after* masking (``tokiwa.llm.redact``: Gate, adapters). Detection therefore only sees
what survives redaction, so every value generated here is built to never match a redact pattern:

* only ``[A-Za-z0-9_]`` - no ``-``/``.``/``@``/``:``/``=``/whitespace, so the JWT, ``sk-``, URL-credential,
  e-mail, IPv4, card (needs a word boundary before 13+ digits) and ``key=value`` patterns cannot fire;
* fixed prefixes that differ from the vendor prefixes redact knows (``sk-``, ``ghp_``, ``xox?-``, ``AIza`` ...);
* the fake AWS key id is ``AKIA`` + 20 chars = 24 chars. Real key ids are exactly 20 chars, so it can never be a
  valid key id, and redact's ``\\bAKIA[0-9A-Z]{16}\\b`` cannot match (no word boundary after 16 chars). The fake
  secret is 42 chars (real: exactly 40).

Values look like credentials but are not verifiable against any real service. Each asset stores one random
``token``; companion values (AWS secret, DB password, canary ...) are derived from it with a keyed HMAC so the
rendered decoy and the detector always agree without extra storage, and an attacker cannot tell that two values
in one decoy are related (the key is derived from the server secret and never leaves the server).

Where a token is still invisible (by design of redaction): values of sensitive headers (Authorization, Cookie,
X-API-Key ...), values after ``token=``/``password=``/``api_key=``/``auth=`` ..., URL user:pass. See
docs/deception.md "観測可能性".
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string
from collections.abc import Mapping
from enum import StrEnum

from tokiwa.config import RedactionSettings, get_settings
from tokiwa.llm.redact import redact_headers, redact_text
from tokiwa.schemas.response import DeceptionKind

ALNUM = string.ascii_letters + string.digits
UPPER_ALNUM = string.ascii_uppercase + string.digits
LOWER_ALNUM = string.ascii_lowercase + string.digits

MIN_TOKEN_LEN = 12
MAX_TOKEN_LEN = 128

_TOKEN_CHARS = re.compile(r"^[\x21-\x7e]+$")  # printable ASCII, no whitespace


class Slot(StrEnum):
    """Named credential slots a decoy can contain. The asset token occupies one, the rest are derived."""

    API_KEY = "api_key"
    AWS_KEY_ID = "aws_key_id"
    AWS_SECRET = "aws_secret"
    DB_USER = "db_user"
    DB_PASSWORD = "db_password"
    CANARY = "canary"


class Flavor(StrEnum):
    """Shape of a generated token."""

    API_KEY = "api_key"
    AWS = "aws"
    DB = "db"
    CANARY = "canary"
    SEED = "seed"  # labyrinth seed (never rendered)


# flavor -> (prefix, alphabet, random body length)
_FORMATS: dict[Flavor, tuple[str, str, int]] = {
    Flavor.API_KEY: ("svc_live_", ALNUM, 32),
    Flavor.AWS: ("AKIA", UPPER_ALNUM, 20),  # 24 chars total; a real key id has 20
    Flavor.DB: ("app_rw_", LOWER_ALNUM, 12),
    Flavor.CANARY: ("dbg_", ALNUM, 24),
    Flavor.SEED: ("mz_", ALNUM, 24),
}

# slot -> (prefix, alphabet, body length) for derived values
_SLOT_FORMATS: dict[Slot, tuple[str, str, int]] = {
    Slot.API_KEY: _FORMATS[Flavor.API_KEY],
    Slot.AWS_KEY_ID: _FORMATS[Flavor.AWS],
    Slot.AWS_SECRET: ("", ALNUM, 42),  # real secrets are exactly 40 chars
    Slot.DB_USER: _FORMATS[Flavor.DB],
    Slot.DB_PASSWORD: ("", ALNUM, 24),
    Slot.CANARY: _FORMATS[Flavor.CANARY],
}

_FLAVOR_SLOT = {
    Flavor.API_KEY: Slot.API_KEY,
    Flavor.AWS: Slot.AWS_KEY_ID,
    Flavor.DB: Slot.DB_USER,
    Flavor.CANARY: Slot.CANARY,
}

_AWS_WORDS = re.compile(r"(?i)aws|amazon|\bs3\b|iam")
_DB_WORDS = re.compile(r"(?i)\bdb\b|database|postgres|mysql|maria|mongo|redis|sql|pgpass")


def generate_token(flavor: Flavor) -> str:
    prefix, alphabet, length = _FORMATS[flavor]
    return prefix + "".join(secrets.choice(alphabet) for _ in range(length))


def flavor_for(kind: DeceptionKind, name: str = "", description: str | None = None) -> Flavor:
    """Token shape for a new asset. Honeytokens pick a credential type from their name/description."""
    if kind == DeceptionKind.AI_CANARY:
        return Flavor.CANARY
    if kind == DeceptionKind.LABYRINTH:
        return Flavor.SEED
    if kind == DeceptionKind.HONEYTOKEN:
        text = f"{name} {description or ''}"
        if _AWS_WORDS.search(text):
            return Flavor.AWS
        if _DB_WORDS.search(text):
            return Flavor.DB
    return Flavor.API_KEY


def flavor_of_token(token: str) -> Flavor:
    for flavor in (Flavor.AWS, Flavor.DB, Flavor.CANARY, Flavor.SEED, Flavor.API_KEY):
        prefix = _FORMATS[flavor][0]
        if token.startswith(prefix):
            return flavor
    return Flavor.API_KEY  # custom (user supplied) tokens are treated as an opaque API key


def primary_slot(kind: DeceptionKind, token: str) -> Slot | None:
    """Which slot the stored token occupies when rendered (None = token is never rendered, e.g. a seed)."""
    if kind == DeceptionKind.AI_CANARY:
        return Slot.CANARY
    if kind == DeceptionKind.LABYRINTH:
        return None
    if kind == DeceptionKind.DECOY_PATH:
        return Slot.API_KEY
    flavor = flavor_of_token(token)
    return _FLAVOR_SLOT.get(flavor, Slot.API_KEY)


def _encode(digest: bytes, alphabet: str, length: int) -> str:
    n = int.from_bytes(digest, "big")
    base = len(alphabet)
    out = []
    for _ in range(length):
        n, r = divmod(n, base)
        out.append(alphabet[r])
    return "".join(out)


def derive(key: bytes, token: str, slot: Slot) -> str:
    """Deterministic companion value for ``slot`` (keyed: unrelated-looking without the server key)."""
    prefix, alphabet, length = _SLOT_FORMATS[slot]
    digest = hmac.new(key, f"{slot.value}:{token}".encode(), hashlib.sha512).digest()
    return prefix + _encode(digest, alphabet, length)


def honey_values(kind: DeceptionKind, token: str, key: bytes) -> dict[Slot, str]:
    """All credential values a decoy built from this asset can contain (slot -> value)."""
    primary = primary_slot(kind, token)
    return {slot: (token if slot == primary else derive(key, token, slot)) for slot in Slot}


def derive_key() -> bytes:
    """Sub-key for :func:`derive`, bound to this deployment's server secret (domain separated)."""
    from tokiwa.auth.security import secret_key

    return hmac.new(secret_key().encode(), b"tokiwa.deception.derive.v1", hashlib.sha256).digest()


def _strict_redaction(cfg: RedactionSettings | None) -> RedactionSettings:
    base = cfg or get_settings().llm.redaction
    return base.model_copy(update={"enabled": True, "mask_emails": True, "mask_ips": True})


def survives_redaction(
    value: str,
    cfg: RedactionSettings | None = None,
    *,
    canary_header: str | None = None,
) -> bool:
    """True when ``value`` is still visible after masking in the places detection looks at."""
    strict = _strict_redaction(cfg)
    samples = [value, f"see {value} here", f"/api/internal/{value}/", f"ref={value}"]
    if any(redact_text(s, strict) != s for s in samples):
        return False
    if canary_header:
        headers: Mapping[str, str] = {canary_header: value}
        if redact_headers(dict(headers), strict).get(canary_header.lower()) != value:
            return False
    return True


def validate_token(token: str, cfg: RedactionSettings | None = None) -> str | None:
    """Return an error message for an unusable (user supplied) token, else None."""
    if not MIN_TOKEN_LEN <= len(token) <= MAX_TOKEN_LEN:
        return f"token length must be {MIN_TOKEN_LEN}..{MAX_TOKEN_LEN} characters"
    if not _TOKEN_CHARS.match(token):
        return "token must be printable ASCII without whitespace"
    if not survives_redaction(token, cfg):
        return (
            "token matches a redaction pattern (tokiwa.llm.redact) and would be masked before detection; "
            "use the generated format or letters/digits/underscore only without a known vendor prefix"
        )
    return None
