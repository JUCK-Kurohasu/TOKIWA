"""Gate policy pulled by TOKIWA Gate (API token with scope "gate").

Supports ``If-None-Match`` with the policy ``version`` (sent back as a quoted ``ETag``) so polling Gates can
skip unchanged bodies with a 304.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Header, Response

from tokiwa.api.deps import GateToken
from tokiwa.respond.policy import build_gate_policy
from tokiwa.schemas.response import GatePolicy

router = APIRouter(prefix="/api/v1/gate", tags=["gate"])


@router.get("/policy", response_model=GatePolicy, responses={304: {"description": "Not modified"}})
async def gate_policy(
    token: GateToken,
    response: Response,
    if_none_match: Annotated[str | None, Header()] = None,
) -> GatePolicy | Response:
    policy = await build_gate_policy()
    etag = f'"{policy.version}"'
    if if_none_match is not None:
        candidates = {c.strip() for c in if_none_match.split(",")}
        if etag in candidates or policy.version in candidates or f"W/{etag}" in candidates:
            return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"
    return policy
