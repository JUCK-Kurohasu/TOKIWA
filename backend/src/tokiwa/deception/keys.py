"""Deception key ring: the HMAC keys behind derived decoy values, independent of the JWT signing key (audit #68).

Companion values in a decoy (fake AWS secret, DB password, the canary inside ``/.env`` ...) are
``HMAC(key, slot:token)`` (:func:`tokiwa.deception.tokens.derive`). The key used to be derived from the JWT
signing key (``server.secret_key`` / ``data_dir/secret.key``) on every start, so rotating the JWT key after a
suspected leak - or losing ``secret.key`` - silently changed every derived value: credentials and canaries an
attacker had already taken from a decoy no longer matched, and nobody noticed.

Now the keys live in their own file, ``data_dir/deception.key`` (0600, created atomically like ``secret.key``):

* one hex key per line, ``#`` comments allowed; the **first** key is active (renders decoys), **all** keys are
  matched, so values handed out under an older key keep tripping after a rotation;
* on first use the file is seeded with the key the old code derived from the JWT key, so rendered values stay
  byte-identical for existing deployments; from then on the JWT key can rotate freely;
* rotate: put a new random key (``python -c "import secrets; print(secrets.token_hex(32))"``) on the first line
  and keep the old lines. How long to keep old keys is an operator decision (docs/deception.md §3).

Back the file up with the database (docs/deploy.md §7): losing it re-seeds from the *current* JWT key.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import re
from pathlib import Path

from tokiwa.config import get_settings

log = logging.getLogger(__name__)

KEY_FILE_NAME = "deception.key"
LEGACY_LABEL = b"tokiwa.deception.derive.v1"
MIN_KEY_BYTES = 16
_HEX = re.compile(r"^[0-9a-fA-F]+$")

_HEADER = (
    "# TOKIWA deception key ring (docs/deception.md section 3). One hex key per line.\n"
    "# First line = active key (renders decoy values); every key is still matched (keep old keys after a rotation).\n"
    "# Back this file up with the database: losing it changes every derived decoy value.\n"
)


def legacy_key() -> bytes:
    """The sub-key releases before audit #68 derived from the JWT signing key (domain separated)."""
    from tokiwa.auth.security import secret_key

    return hmac.new(secret_key().encode(), LEGACY_LABEL, hashlib.sha256).digest()


def key_file() -> Path:
    return Path(get_settings().server.data_dir) / KEY_FILE_NAME


def parse_keyring(text: str) -> list[bytes]:
    """Keys in file order. Raises ValueError on a malformed line (a typo must not silently drop a key)."""
    keys: list[bytes] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not _HEX.match(line) or len(line) % 2 or len(line) < 2 * MIN_KEY_BYTES:
            raise ValueError(f"line {n}: expected a hex key of at least {MIN_KEY_BYTES} bytes")
        key = bytes.fromhex(line)
        if key not in keys:
            keys.append(key)
    return keys


def keyring() -> list[bytes]:
    """Active key first. Creates ``data_dir/deception.key`` (seeded with :func:`legacy_key`) when missing.

    A missing / empty / malformed file never stops detection: it falls back to the legacy key with an error log.
    """
    from tokiwa.auth.files import create_private_file

    path = key_file()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        try:
            if create_private_file(path, _HEADER + legacy_key().hex() + "\n"):
                log.info("deception: created %s (seeded with the key derived from the JWT signing key)", path)
            text = path.read_text(encoding="utf-8")  # ours, or the one a concurrent process created first
        except OSError:  # read-only data dir (secret key from the environment): keep the old behaviour
            log.exception("deception: cannot create %s; using the key derived from the JWT signing key", path)
            return [legacy_key()]
    except OSError:
        log.exception("deception: cannot read %s; using the key derived from the JWT signing key", path)
        return [legacy_key()]
    try:
        keys = parse_keyring(text)
    except ValueError as exc:
        log.error(
            "deception: %s is malformed (%s); using the key derived from the JWT signing key", path, exc
        )
        return [legacy_key()]
    if not keys:
        log.error("deception: %s holds no key; using the key derived from the JWT signing key", path)
        return [legacy_key()]
    with contextlib.suppress(OSError):
        if path.stat().st_mode & 0o077:
            log.warning("%s is readable by other users; restrict it with: chmod 600 %s", path, path)
    return keys
