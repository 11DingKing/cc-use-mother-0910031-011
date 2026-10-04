"""时间工具：统一 UTC、与 SQLite 中 strftime('%Y-%m-%dT%H:%M:%fZ','now') 同形。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_str() -> str:
    return ts_str(now())


def ts_str(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def parse(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def plus_hours(value: datetime, hours: int) -> str:
    return ts_str(value + timedelta(hours=hours))


def plus_seconds(value: datetime, seconds: int) -> str:
    return ts_str(value + timedelta(seconds=seconds))
