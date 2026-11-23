"""``agent.log_timezone``: how to read log timestamps that carry no UTC offset (audit #131).

Stdlib only (``tokiwa.config`` validates the setting with it without import cycles).
"""

from __future__ import annotations

import re
from datetime import UTC, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def resolve_timezone(name: str | None) -> tzinfo | None:
    """``None`` -> None (offset-less timestamps are read as UTC and counted); ``UTC`` / ``Z``; a fixed offset
    such as ``+09:00`` / ``-0530``; or an IANA zone such as ``Asia/Tokyo`` (needs the OS tz database or the
    ``tzdata`` package). Raises ``ValueError`` for anything else so a typo is not silently UTC."""
    if name is None:
        return None
    s = name.strip()
    if not s:
        return None
    if s.upper() in {"UTC", "Z", "GMT"}:
        return UTC
    m = _OFFSET.match(s)
    if m:
        hours, minutes = int(m.group(2)), int(m.group(3))
        if hours > 23 or minutes > 59:
            raise ValueError(f"invalid UTC offset: {name!r}")
        delta = timedelta(hours=hours, minutes=minutes)
        return timezone(-delta if m.group(1) == "-" else delta)
    try:
        return ZoneInfo(s)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"unknown time zone {name!r}: use an IANA name (Asia/Tokyo), a fixed offset (+09:00) or UTC"
        ) from exc
