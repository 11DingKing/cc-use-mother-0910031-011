"""运行期配置：角色、证据敏感度、租约与风险规则版本。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# 与 domain/contract.json 的 actors 对齐，并补充系统侧分流管理员。
ROLE_DISPATCH_ADMIN = "分流管理员"

ROLES: tuple[str, ...] = (
    "机构合规员",
    "执业人员",
    "监管人员",
    "复核专家",
    ROLE_DISPATCH_ADMIN,
)

# 证据敏感度分级（由低到高）。
SENSITIVITY_LEVELS: tuple[str, ...] = ("普通", "内部", "敏感", "机密")

# 各角色可见的最高证据敏感度（含本级）。
#   机构合规员/执业人员：仅普通
#   监管人员：敏感及以下
#   复核专家/分流管理员：全部
ROLE_MAX_SENSITIVITY: dict[str, str] = {
    "机构合规员": "普通",
    "执业人员": "普通",
    "监管人员": "敏感",
    "复核专家": "机密",
    ROLE_DISPATCH_ADMIN: "机密",
}

# 动作所需角色（动作名与 api 层、audit action 保持一致）。
PERMISSIONS: dict[str, frozenset[str]] = {
    "clue.create": frozenset({"机构合规员", "监管人员"}),
    "clue.list": frozenset(ROLES),
    "clue.read": frozenset(ROLES),
    "clue.accept": frozenset({"复核专家", "监管人员"}),
    "clue.register_receipt": frozenset({"机构合规员", "监管人员", "复核专家"}),
    "rules.publish": frozenset({"分流管理员", "监管人员"}),
    "merge.suggest": frozenset({"分流管理员", "监管人员", "复核专家"}),
    "merge.confirm": frozenset({"分流管理员", "监管人员"}),
    "merge.reject": frozenset({"分流管理员", "监管人员"}),
    "priority.suggest": frozenset({"分流管理员", "监管人员", "复核专家"}),
    "priority.confirm": frozenset({"分流管理员", "监管人员"}),
    "clue.assign": frozenset({"分流管理员", "监管人员"}),
    "clue.transfer": frozenset({"分流管理员", "监管人员"}),
    "clue.claim": frozenset({"监管人员", "复核专家", "分流管理员"}),
    "clue.release": frozenset({"监管人员", "复核专家", "分流管理员"}),
    "clue.start": frozenset({"监管人员", "复核专家", "分流管理员"}),
    "clue.verify": frozenset({"复核专家", "监管人员"}),
    "clue.split": frozenset({"分流管理员", "监管人员", "复核专家"}),
    "measure.create": frozenset({"监管人员", "分流管理员", "复核专家"}),
    "measure.lift": frozenset({"监管人员", "分流管理员"}),
    "extension.request": frozenset({"监管人员", "复核专家", "分流管理员"}),
    "extension.approve": frozenset({"分流管理员", "监管人员"}),
    "clue.close": frozenset({"监管人员", "分流管理员", "复核专家"}),
    "clue.reopen": frozenset({"分流管理员", "监管人员"}),
    "clue.audit": frozenset(ROLES),
}

# 合同要求的五个顶层状态（contract.json states）。
STATE_REGISTERED = "登记"
STATE_PENDING_VERIFY = "待核验"
STATE_PROCESSING = "处置中"
STATE_DECIDED = "已决定"
STATE_ARCHIVED = "已归档"

# 办理时限（小时）：优先级 -> 默认时限。
DEFAULT_DEADLINE_HOURS: dict[str, int] = {
    "特急": 24,
    "紧急": 48,
    "高": 72,
    "中": 120,
    "低": 240,
}

PRIORITIES: tuple[str, ...] = ("低", "中", "高", "紧急", "特急")
PRIORITY_RANK = {name: i for i, name in enumerate(PRIORITIES)}


@dataclass(frozen=True)
class Settings:
    db_path: str = field(default_factory=lambda: os.environ.get("TRIAGE_DB", "triage.db"))
    lease_seconds: int = field(default_factory=lambda: int(os.environ.get("TRIAGE_LEASE_SECONDS", "1800")))
    host: str = field(default_factory=lambda: os.environ.get("TRIAGE_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("TRIAGE_PORT", "8080")))
