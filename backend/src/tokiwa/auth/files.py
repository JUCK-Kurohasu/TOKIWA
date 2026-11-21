"""Private files in ``server.data_dir`` (JWT signing key, one-time setup code).

Why not ``path.write_text()`` + ``chmod``: the file exists with umask permissions (usually 0644) between the two
calls, so another local user can read it (#102). Files here are created with mode 0600 from the start, and
"create unless it exists" is atomic so two processes starting at once (several workers, server + CLI) end up
with the same content instead of overwriting each other.
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
from pathlib import Path

log = logging.getLogger(__name__)


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (and parents) with mode 0700 if missing. Existing directories are left as they are.

    Existing ones are not chmod-ed: a Docker volume or bind mount may deliberately use other modes/owners.
    """
    if path.is_dir():
        return
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def create_private_file(path: Path, content: str) -> bool:
    """Atomically create ``path`` with ``content`` and mode 0600. Returns False if it already exists.

    The content is written to a private temp file first and then hard-linked into place, so a concurrent reader
    never sees a half-written file. Filesystems without hard links fall back to ``O_CREAT | O_EXCL``.
    """
    ensure_private_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        try:
            os.link(tmp, path)
            return True
        except FileExistsError:
            return False
        except OSError:  # no hard links (some network / FUSE filesystems)
            log.debug("hard link unsupported for %s; using O_EXCL", path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return True


def read_private_file(path: Path) -> str | None:
    """Stripped content, or None if the file is missing or empty."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return text or None
