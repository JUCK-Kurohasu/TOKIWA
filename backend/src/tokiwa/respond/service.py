"""Response action service. OWNER: respond module.

Public API used by other modules (keep signatures stable):

- ``propose_action(proposal) -> ResponseAction | None``  create a proposal (deduplicated); may auto-approve
  only when policy allows (``response.auto_approve_enabled`` + type allow-list). Returns None if rejected by
  validation (e.g. protected CIDR, invalid target).
"""

from __future__ import annotations

from tokiwa.schemas.response import ActionProposal, ResponseAction


async def propose_action(proposal: ActionProposal) -> ResponseAction | None:  # pragma: no cover - stub
    raise NotImplementedError("implemented by the respond module")
