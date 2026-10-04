"""领域常量：角色、状态、渠道、优先级与权限矩阵。"""
from __future__ import annotations

# 与 domain/contract.json 对齐
ROLES = ("机构合规员", "执业人员", "监管人员", "复核专家")
STATES = ("登记", "待核验", "处置中", "已决定", "已归档")
ACTIVE_STATES = ("登记", "待核验", "处置中")

CHANNELS = ("投诉", "巡查", "机构自报")

PRIORITIES = ("低", "中", "高", "紧急")
PRIORITY_RANK = {name: i for i, name in enumerate(PRIORITIES)}
# 办理时限（日历天）：自当前办理周期起算
PRIORITY_SLA_DAYS = {"低": 30, "中": 15, "高": 7, "紧急": 3}

DECISIONS = ("立案查处", "不予立案", "移送其他部门")

MEASURE_TYPES = ("责令整改", "暂停执业", "封存证据", "限制经营")

EVIDENCE_KINDS = ("书证", "物证", "视听资料", "电子数据", "证人证言", "其他")

SUBJECT_TYPES = ("机构", "执业人员")

# 证据敏感级别：数值越大越敏感
SENSITIVITY_NAMES = {1: "公开", 2: "内部", 3: "敏感", 4: "机密"}
# 角色密级：可完整查看的证据级别上限；高一级仅见元数据（打码）；更高则不可见
CLEARANCE = {"执业人员": 1, "机构合规员": 2, "监管人员": 3, "复核专家": 4}

# 租约
LEASE_TTL_DEFAULT_SECONDS = 1800
LEASE_TTL_MAX_SECONDS = 7200

# 延期约束
MAX_EXTENSIONS_PER_CYCLE = 2
MAX_EXTENSION_DAYS = 30

# 合并建议相似度阈值（精确指纹命中不受阈值限制）
MERGE_SCORE_THRESHOLD = 0.45

# 状态机：动作 -> 约束（来源状态、目标状态、允许角色、是否要求持有租约）
TRANSITIONS = {
    "triage": {"from": {"登记"}, "to": "待核验", "roles": {"监管人员", "复核专家"}, "lease": False},
    "return": {"from": {"待核验"}, "to": "登记", "roles": {"监管人员", "复核专家"}, "lease": False},
    "verify": {"from": {"待核验"}, "to": "处置中", "roles": {"监管人员", "复核专家"}, "lease": True},
    "decide": {"from": {"处置中"}, "to": "已决定", "roles": {"监管人员"}, "lease": True},
    "archive": {"from": {"已决定"}, "to": "已归档", "roles": {"监管人员", "复核专家"}, "lease": False},
    "reopen": {"from": {"已决定", "已归档"}, "to": "处置中", "roles": {"复核专家"}, "lease": False},
}
