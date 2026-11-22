"""One-time setup code for ``POST /auth/setup`` (#95).

Why: the first admin is created through an unauthenticated endpoint and the server listens on 0.0.0.0 by
default, so whoever reaches a fresh installation first could become its admin (a scanner, an AI agent on the
lab network ...). Like Jupyter's token, the server prints a random code to its own log and to
``data_dir/setup-code`` (mode 0600). Only someone who can read the server's log or data directory can finish the
setup. The code is deleted once setup succeeds.

The file is the source of truth so that every worker process and a restarted server use the same code; an
in-memory copy is used only when the data directory is not writable.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from pathlib import Path

from tokiwa.auth.files import create_private_file, read_private_file
from tokiwa.config import get_settings

log = logging.getLogger(__name__)

FILE_NAME = "setup-code"
# Upper-case letters and digits without look-alikes (0/O, 1/I): easy to read from a log and to type.
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_GROUPS, _GROUP_LEN = 4, 4  # 16 symbols x 5 bits = 80 bits

_memory_code: str | None = None


def _path() -> Path:
    return Path(get_settings().server.data_dir) / FILE_NAME


def _generate() -> str:
    groups = ("".join(secrets.choice(_ALPHABET) for _ in range(_GROUP_LEN)) for _ in range(_GROUPS))
    return "-".join(groups)


def _normalize(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def current_setup_code() -> str | None:
    """The pending code, without creating one."""
    return read_private_file(_path()) or _memory_code


def ensure_setup_code() -> str:
    """Return the pending code, creating (and announcing) one if there is none yet."""
    global _memory_code
    existing = current_setup_code()
    if existing:
        return existing
    code = _generate()
    path = _path()
    try:
        if not create_private_file(path, code + "\n"):
            # Another process created it between our read and our write: use theirs.
            return read_private_file(path) or code
    except OSError as exc:
        log.warning("cannot write %s (%s); the setup code is only in this log", path, exc)
        _memory_code = code
    announce_setup_code(code)
    return code


def announce_setup_code(code: str | None = None) -> None:
    """Log where to finish the first-run setup. Logged at WARNING so it shows with the default log level."""
    code = code or current_setup_code()
    if not code:
        return
    settings = get_settings()
    base = settings.server.base_url.rstrip("/")
    log.warning(
        "TOKIWA is not set up yet. Create the first admin at %s/setup#code=%s "
        "(or enter the setup code %s on the setup page; it is also in %s). "
        "Alternatively, on the server: tokiwa user create <name> --role admin",
        base,
        code,
        code,
        _path(),
    )


def check_setup_code(candidate: str | None) -> bool:
    """Constant-time comparison, ignoring case, spaces and dashes."""
    expected = current_setup_code()
    if not expected or not candidate:
        return False
    return hmac.compare_digest(_normalize(candidate).encode(), _normalize(expected).encode())


def consume_setup_code() -> None:
    """Forget the code after a successful setup (it must not be reusable)."""
    global _memory_code
    _memory_code = None
    try:
        _path().unlink(missing_ok=True)
    except OSError:
        log.exception("could not delete %s", _path())


def reset_memory_code() -> None:
    """For tests."""
    global _memory_code
    _memory_code = None
