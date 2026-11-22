"""Interface used by the gate-policy endpoint (respond module) to obtain decoys.

OWNER: deception module.

``build_gate_decoys()`` returns the decoy routes of all *enabled* assets (pre-rendered bodies; exact paths and
``*`` prefix routes) and the hidden AI-canary snippet the Gate inserts into upstream HTML
(``None`` when ``deception.ai_canaries`` / ``deception.html_injection`` is off or no path-less canary exists).
``html_injection_positions()`` says where (``GatePolicy.html_injection_positions``).

Gate expectations (docs/deception.md "Gate との約束"): exact routes win over prefix routes, longest prefix wins;
decoy responses are recorded as ONE event with ``deception.asset_id`` set.
"""

from __future__ import annotations

from tokiwa.config import get_settings
from tokiwa.schemas.response import DecoyRoute


def html_injection_positions() -> list[str]:
    """Where the Gate inserts the snippet (``deception.html_injection_positions``, audit #41), de-duplicated."""
    return list(dict.fromkeys(get_settings().deception.html_injection_positions))


async def build_gate_decoys() -> tuple[list[DecoyRoute], str | None]:
    """Return (decoy routes served by the gate, optional HTML snippet injected into upstream HTML)."""
    if not get_settings().deception.enabled:
        return [], None
    from tokiwa.deception.service import gate_decoys

    return await gate_decoys()
