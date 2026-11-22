"""Password hashing (scrypt), JWT access tokens and API (ingest) tokens."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import logging
import os
import secrets
import weakref
from datetime import timedelta
from pathlib import Path
from typing import Any

import jwt

from tokiwa.auth.files import create_private_file, read_private_file
from tokiwa.config import MIN_SECRET_KEY_LENGTH, get_settings
from tokiwa.util import sha256_hex, utcnow

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
API_TOKEN_PREFIX = "tkw_"

log = logging.getLogger(__name__)

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


_hash_slots: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = (
    weakref.WeakKeyDictionary()
)
# Hash of a random, discarded password with the current parameters: verifying against it costs the same as
# verifying a real user's password, and nothing matches it.
_DUMMY_HASH = "scrypt$16384$8$1$XN7DDZh7K2OvW8bQXo2/iA==$Mbt4a1zxgfLbQDTknAEN4pgWsD49UtI/lzl6PyDyJ1g="


def _slots() -> asyncio.Semaphore:
    """Per-event-loop semaphore (an asyncio.Semaphore must not be shared across loops, e.g. between tests)."""
    loop = asyncio.get_running_loop()
    sem = _hash_slots.get(loop)
    if sem is None:
        sem = _hash_slots[loop] = asyncio.Semaphore(get_settings().auth.password_hash_concurrency)
    return sem


async def hash_password_async(password: str) -> str:
    """:func:`hash_password` off the event loop (scrypt blocks for tens of ms), bounded by a semaphore."""
    async with _slots():
        return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, encoded: str | None) -> bool:
    """:func:`verify_password` off the event loop. ``encoded=None`` (unknown user) still runs one scrypt against
    a dummy hash, so the response time does not reveal whether the user name exists (#56)."""
    async with _slots():
        ok = await asyncio.to_thread(verify_password, password, encoded or _DUMMY_HASH)
    return ok and encoded is not None


def secret_key() -> str:
    """JWT secret: config value, else persisted random key in data_dir/secret.key.

    The file is created with mode 0600 from the start (no umask window, #102) and atomically, so several workers
    starting at once agree on one key. An empty ``server.secret_key`` counts as unset (see config.py).
    """
    global _secret_cache
    settings = get_settings()
    if settings.server.secret_key is not None:
        return settings.server.secret_key.get_secret_value()
    if _secret_cache:
        return _secret_cache
    path = Path(settings.server.data_dir) / "secret.key"
    key = read_private_file(path)
    if key is None and not path.exists():
        create_private_file(path, secrets.token_urlsafe(48) + "\n")
        key = read_private_file(path)  # ours, or the one a concurrent process created first
    if key is None:
        raise RuntimeError(
            f"{path} is empty; delete it to generate a new JWT signing key (logs everyone out)"
        )
    if len(key) < MIN_SECRET_KEY_LENGTH:
        raise RuntimeError(
            f"{path} holds a key shorter than {MIN_SECRET_KEY_LENGTH} characters; replace or delete it"
        )
    with contextlib.suppress(OSError):
        if path.stat().st_mode & 0o077:
            log.warning("%s is readable by other users; restrict it with: chmod 600 %s", path, path)
    _secret_cache = key
    return _secret_cache


def reset_secret_cache() -> None:
    global _secret_cache
    _secret_cache = None


def create_access_token(user_id: str, username: str, role: str, token_version: int = 0) -> tuple[str, int]:
    """``token_version`` is the user's ``users.token_version``; the API rejects the JWT once it has changed.

    Why: a JWT is self-contained, so without a server-side counter a stolen token stayed valid for the whole TTL
    even after a password change or logout (#34).
    """
    ttl = get_settings().server.token_ttl_minutes * 60
    now = utcnow()
    payload: dict[str, Any] = {
        "sub": user_id,
        "name": username,
        "role": role,
        "ver": int(token_version or 0),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "typ": "access",
    }
    return jwt.encode(payload, secret_key(), algorithm="HS256"), ttl


def token_version_matches(claims: dict[str, Any], current: int | None) -> bool:
    """JWTs issued before versioning have no ``ver`` and count as version 0 (the column's default)."""
    ver = claims.get("ver", 0)
    if not isinstance(ver, int) or isinstance(ver, bool):
        return False
    return ver == int(current or 0)


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
