"""Runtime-editable settings stored in ``settings_kv`` (key -> JSON object).

Keys are namespaced by owner module, e.g. ``llm.config``, ``detection.overrides``, ``response.policy``.
"""

from __future__ import annotations

from typing import Any

from tokiwa.db.models.core import SettingRow
from tokiwa.db.session import session_scope
from tokiwa.util import utcnow


async def get_setting(key: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
    async with session_scope() as session:
        row = await session.get(SettingRow, key)
        if row is None:
            return dict(default or {})
        return dict(row.value or {})


async def set_setting(key: str, value: dict[str, Any]) -> None:
    async with session_scope() as session:
        row = await session.get(SettingRow, key)
        if row is None:
            session.add(SettingRow(key=key, value=value, updated_at=utcnow()))
        else:
            row.value = value
            row.updated_at = utcnow()
