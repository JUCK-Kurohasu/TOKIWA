"""Password hashing (scrypt), JWT access tokens and API (ingest) tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

import jwt

from tokiwa.config import get_settings
from tokiwa.util import sha256_hex, utcnow

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
API_TOKEN_PREFIX = "tkw_"

_secret_cache: str | None = None


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = encoded.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


def secret_key() -> str:
    """JWT secret: config value, else persisted random key in data_dir/secret.key."""
    global _secret_cache
    settings = get_settings()
    if settings.server.secret_key is not None:
        return settings.server.secret_key.get_secret_value()
    if _secret_cache:
        return _secret_cache
    path = Path(settings.server.data_dir) / "secret.key"
    if path.is_file():
        _secret_cache = path.read_text().strip()
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        _secret_cache = secrets.token_urlsafe(48)
        path.write_text(_secret_cache)
        path.chmod(0o600)
    return _secret_cache


def reset_secret_cache() -> None:
    global _secret_cache
    _secret_cache = None


def create_access_token(user_id: str, username: str, role: str) -> tuple[str, int]:
    ttl = get_settings().server.token_ttl_minutes * 60
    now = utcnow()
    payload: dict[str, Any] = {
        "sub": user_id,
        "name": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "typ": "access",
    }
    return jwt.encode(payload, secret_key(), algorithm="HS256"), ttl


def decode_access_token(token: str) -> dict[str, Any]:
    data: dict[str, Any] = jwt.decode(token, secret_key(), algorithms=["HS256"])
    if data.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return data


def generate_api_token() -> tuple[str, str, str]:
    """Returns (plaintext token, sha256 hash, display prefix)."""
    token = API_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, sha256_hex(token), token[:10]


def hash_api_token(token: str) -> str:
    return sha256_hex(token)
