from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Header

from tokiwa import __version__
from tokiwa.api.deps import _bearer, user_from_token
from tokiwa.db.session import session_scope
from tokiwa.schemas.system import Role

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["system"])


def system_checks(*, admin: bool) -> dict[str, dict[str, Any]]:
    """Component checks for signed-in users (#177): in-memory state only, never raises.

    ``sigma``: a missing rule directory or a directory without valid rules leaves Sigma detecting nothing while
    the process is otherwise healthy (the old CWD-relative default did this silently). Directory paths are
    shown to admins only.
    """
    try:
        from tokiwa.detect.engine import get_detection_engine
        from tokiwa.detect.sigma.loader import SIGMA_DETECTOR_ID, get_rule_store

        engine = get_detection_engine()  # honours detection.disabled_detectors and PATCH /detectors overrides
        det = engine.all_detectors().get(SIGMA_DETECTOR_ID)
        enabled = det is not None and engine.is_enabled(det)
        sigma = get_rule_store().health(detector_enabled=enabled, include_paths=admin)
    except Exception:
        log.exception("health: sigma check failed")
        sigma = {"status": "unknown"}
    return {"sigma": sigma}


@router.get("/health")
async def health(authorization: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    """Liveness probe for Docker / load balancers: no authentication, never fails, no DB access without a token.

    Unauthenticated callers always get ``{"status": "ok"}`` with HTTP 200: a version string lets a scanner match
    known vulnerabilities (audit #93), "Sigma is off" tells an attacker what goes unseen, and a 503 for a
    degraded component would make Docker / the load balancer restart or drain an instance whose problem a
    restart cannot fix (taking every other detector down with it). A signed-in user (the UI) also gets the
    version and ``checks``; ``status`` is then ``degraded`` when a check is (audit #177). Note that the OpenAPI
    document (``server.expose_docs``) and ``/auth/status`` also carry the version.
    """
    out: dict[str, Any] = {"status": "ok"}
    token = _bearer(authorization)
    if token:
        try:
            async with session_scope() as session:
                user = await user_from_token(session, token)
        except Exception:  # invalid / expired token, DB trouble: still healthy, just no version
            log.debug("health: version withheld (token not accepted)", exc_info=True)
        else:
            out["version"] = __version__
            checks = system_checks(admin=user.role == Role.ADMIN)
            out["checks"] = checks
            if any(c.get("status") == "degraded" for c in checks.values()):
                out["status"] = "degraded"
    return out
