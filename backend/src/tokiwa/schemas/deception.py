"""Deception (Mirage) API models that are not part of the shared response contract.

``DeceptionAsset`` / ``DeceptionAssetIn`` / ``DecoyRoute`` live in :mod:`tokiwa.schemas.response`.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class DeceptionAssetUpdate(BaseModel):
    """PATCH /deception/assets/{id}. Omitted fields are unchanged; ``kind`` is immutable."""

    name: str | None = None
    path: str | None = None
    token: str | None = None
    content_template: str | None = None
    description: str | None = None
    enabled: bool | None = None


class DeceptionPreview(BaseModel):
    """GET /deception/preview/{id}: exactly what the Gate serves for the asset (or injects, path=None)."""

    asset_id: str
    path: str | None
    content_type: str
    body: str
    status_code: int = 200
    headers: dict[str, str] = Field(default_factory=dict)
    # False when the Gate does not serve it with the current settings (asset disabled, feature switched off,
    # honeytoken without path = planted elsewhere by the operator).
    served: bool = True
    # Other routes produced by the same asset (e.g. the AI-canary landing prefix, labyrinth pages)
    extra_paths: list[str] = Field(default_factory=list)
