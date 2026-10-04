"""核心数据模型。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Actor:
    """已认证操作者。角色与所属机构以服务端登记为准，不接受客户端自报。"""

    id: str
    name: str
    role: str
    org_id: str | None = None
