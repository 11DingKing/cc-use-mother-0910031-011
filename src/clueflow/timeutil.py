"""时间工具：统一使用 UTC ISO8601。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def now_iso() -> str:
    return iso(utcnow())


def parse(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def add_seconds(value: str, seconds: float) -> str:
    return iso(parse(value) + timedelta(seconds=seconds))


def add_days(value: str, days: int) -> str:
    return iso(parse(value) + timedelta(days=days))
