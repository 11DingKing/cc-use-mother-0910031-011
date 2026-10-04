"""按角色裁剪证据与敏感字段（domain 契约“敏感证据裁剪”）。

裁剪规则：
- 证据级别 ≤ 角色密级：完整可见；
- 证据级别 = 角色密级 + 1：仅见元数据，内容打码（redacted=True）；
- 证据级别更高：从列表中隐藏，仅返回隐藏数量；
- 主体标识、反映人姓名对低密级角色打码；联系方式一律只存哈希、不出接口。
"""
from __future__ import annotations

from .constants import CLEARANCE, SENSITIVITY_NAMES


def _mask(text: str | None, keep: int = 0) -> str:
    text = text or ""
    if keep and len(text) > keep:
        return "▓" * (len(text) - keep) + text[-keep:]
    return "▓" * min(len(text), 12) if text else ""


def clearance_for(role: str) -> int:
    return CLEARANCE.get(role, 0)


def evidence_view(role: str, ev: dict) -> dict | None:
    """生成单条证据的角色视图；返回 None 表示对该角色隐藏。"""
    clearance = clearance_for(role)
    level = int(ev["sensitivity"])
    base = {
        "id": ev["id"],
        "case_id": ev["case_id"],
        "kind": ev["kind"],
        "filename": ev["filename"],
        "sensitivity": level,
        "sensitivity_name": SENSITIVITY_NAMES.get(level, str(level)),
        "sha256": ev["sha256"],
        "uploaded_by": ev["uploaded_by"],
        "created_at": ev["created_at"],
    }
    if level <= clearance:
        return {**base, "content": ev["content"], "redacted": False}
    if level == clearance + 1:
        return {**base, "content": _mask(ev["content"]), "redacted": True}
    return None


def redact_evidence_list(role: str, items: list[dict]) -> tuple[list[dict], int]:
    """返回 (可见视图列表, 隐藏条数)。"""
    views: list[dict] = []
    hidden = 0
    for ev in items:
        view = evidence_view(role, ev)
        if view is None:
            hidden += 1
        else:
            views.append(view)
    return views, hidden


def subject_view(role: str, subj: dict) -> dict:
    """主体视图：监管人员与复核专家可见完整标识，其余角色打码。"""
    clearance = clearance_for(role)
    identifier = subj["identifier"] if clearance >= 3 else _mask(subj["identifier"], keep=2)
    return {
        "id": subj["id"],
        "type": subj["type"],
        "name": subj["name"],
        "identifier": identifier,
        "org_id": subj["org_id"],
    }


def reporter_view(role: str, clue: dict) -> dict:
    """反映人视图：低密级角色不可见姓名；联系方式永不返回（仅存哈希）。"""
    clearance = clearance_for(role)
    anonymous = bool(clue["anonymous"])
    if anonymous or clearance < 3:
        name = "匿名" if anonymous else (_mask(clue["reporter_name"]) if clue["reporter_name"] else None)
    else:
        name = clue["reporter_name"]
    return {
        "anonymous": anonymous,
        "name": name,
        "contact_registered": bool(clue["reporter_contact_hash"]),
    }
