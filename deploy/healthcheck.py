#!/usr/bin/env python3
"""Docker HEALTHCHECK probe for the TOKIWA image.

Standard library only: the slim runtime image has no curl/wget, and the probe must not depend on the
application's virtualenv being importable.

Target selection:
- default: ``http://127.0.0.1:${TOKIWA_SERVER__PORT:-8788}/api/v1/health`` (``tokiwa serve``)
- ``TOKIWA_HEALTHCHECK_URL=<url>``: another role's endpoint, e.g. the gate's
  ``http://127.0.0.1:8080/__tokiwa/health``
- ``TOKIWA_HEALTHCHECK_URL=none``: always healthy (roles without an HTTP endpoint: agent, sim, one-shot CLI)
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

_DISABLED = {"none", "off", "disabled", "false", "0"}


def _target() -> str | None:
    url = os.environ.get("TOKIWA_HEALTHCHECK_URL", "").strip()
    if url.lower() in _DISABLED:
        return None
    if url:
        return url
    port = os.environ.get("TOKIWA_SERVER__PORT", "8788").strip() or "8788"
    return f"http://127.0.0.1:{port}/api/v1/health"


def main() -> int:
    url = _target()
    if url is None:
        return 0
    if not url.startswith(("http://", "https://")):
        print(f"healthcheck: unsupported URL scheme: {url!r}", file=sys.stderr)
        return 1
    timeout = float(os.environ.get("TOKIWA_HEALTHCHECK_TIMEOUT", "4"))
    # Never route the probe through HTTP(S)_PROXY that may be set for outbound LLM / intel traffic.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as resp:
            status = resp.status
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"healthcheck: {url}: {exc}", file=sys.stderr)
        return 1
    if not 200 <= status < 300:
        print(f"healthcheck: {url}: HTTP {status}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
