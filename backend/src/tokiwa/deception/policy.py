"""Interface used by the gate-policy endpoint (respond module) to obtain decoys.

OWNER: deception module. The skeleton returns nothing; the deception module implements real rendering.
"""

from __future__ import annotations

from tokiwa.schemas.response import DecoyRoute


async def build_gate_decoys() -> tuple[list[DecoyRoute], str | None]:
    """Return (decoy routes served by the gate, optional HTML snippet injected into upstream HTML)."""
    return [], None
