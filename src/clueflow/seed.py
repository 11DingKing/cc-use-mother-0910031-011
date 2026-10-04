"""基础种子数据：演示账号与默认风险规则集（幂等）。"""
from __future__ import annotations

from .store import Store, dumps
from .timeutil import now_iso

# 演示账号：id / 姓名 / 角色 / 所属机构
BASE_ACTORS = [
    ("u-heliang", "何亮", "机构合规员", "org-hospital-1"),
    ("ZY-3301", "林一凡", "执业人员", None),
    ("u-jian-guan-1", "陈监管", "监管人员", None),
    ("u-jian-guan-2", "王监管", "监管人员", None),
    ("u-expert-1", "赵复核", "复核专家", None),
]

# 默认风险规则集（版本 1）
DEFAULT_RULES = [
    ("关键词命中-重大违法", "keyword", {"words": ["非法集资", "传销", "致人死亡", "群体性", "暴力抗法", "伪劣药品"]}, 40),
    ("关键词命中-一般违法", "keyword", {"words": ["超范围经营", "虚假宣传", "无证", "逾期", "未备案"]}, 20),
    ("渠道权重-巡查发现", "channel", {"channel": "巡查"}, 10),
    ("渠道权重-群众投诉", "channel", {"channel": "投诉"}, 5),
    ("主体有既往违规", "recidivism", {}, 20),
    ("含敏感级证据", "sensitive_evidence", {"min_level": 3}, 15),
    ("多渠道重复反映", "multi_source", {"min_clues": 2}, 15),
]


def seed_base(store: Store) -> None:
    """写入演示账号与默认规则集；已存在则跳过。"""
    with store.tx():
        for actor_id, name, role, org_id in BASE_ACTORS:
            store.execute(
                "INSERT OR IGNORE INTO actors(id, name, role, org_id) VALUES (?, ?, ?, ?)",
                (actor_id, name, role, org_id),
            )
        if store.get_meta("risk_rule_version") is None:
            for i, (name, kind, params, points) in enumerate(DEFAULT_RULES, start=1):
                store.execute(
                    "INSERT INTO risk_rules(id, version, name, kind, params, points, enabled) "
                    "VALUES (?, 1, ?, ?, ?, ?, 1)",
                    (f"RUL-{i:06d}", name, kind, dumps(params), points),
                )
            store.set_meta("risk_rule_version", "1")
            store.set_meta("seeded_at", now_iso())
