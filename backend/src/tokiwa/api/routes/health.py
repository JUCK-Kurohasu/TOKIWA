from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Header

from tokiwa import __version__
from tokiwa.api.deps import _bearer, user_from_token
from tokiwa.db.session import session_scope

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get("/health")
async def health(authorization: Annotated[str | None, Header()] = None) -> dict[str, str]:
    """Liveness probe for Docker / load balancers: no authentication, never fails, no DB access without a token.

    The version is returned only to a signed-in user (the UI sidebar shows it). Unauthenticated callers do not
    get it, because a version string lets a scanner match known vulnerabilities (audit #93). Note that the
    OpenAPI document (``server.expose_docs``) and ``/auth/status`` also carry the version.
    """
    out = {"status": "ok"}
    token = _bearer(authorization)
    if token:
        try:
            async with session_scope() as session:
                await user_from_token(session, token)
        except Exception:  # invalid / expired token, DB trouble: still healthy, just no version
            log.debug("health: version withheld (token not accepted)", exc_info=True)
        else:
            out["version"] = __version__
    return out
