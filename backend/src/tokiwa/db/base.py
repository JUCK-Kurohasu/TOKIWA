"""SQLAlchemy declarative base and portable column types (SQLite <-> PostgreSQL)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from tokiwa.util import ensure_utc, new_id, utcnow


class UTCDateTime(TypeDecorator[datetime]):
    """Always store/return timezone-aware UTC datetimes (SQLite would otherwise return naive values)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return ensure_utc(value)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return ensure_utc(value)


class Base(DeclarativeBase):
    type_annotation_map = {  # noqa: RUF012
        datetime: UTCDateTime(),
        dict[str, Any]: JSON(),
        list[str]: JSON(),
        list[dict[str, Any]]: JSON(),
        dict[str, str]: JSON(),
    }


class IdMixin:
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_id)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)
