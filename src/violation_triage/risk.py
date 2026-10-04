"""风险规则：版本化存储 + 确定性条件求值。

规则条件为受限 JSON 结构：

    {"field": "source_channel", "op": "==", "value": "巡查"}
    {"field": "title_desc", "op": "contains_any", "value": ["中毒", "死亡"]}
    {"field": "risk_score", "op": ">=", "value": 60}
    {"all": [<条件>, ...]} / {"any": [...]} / {"not": <条件>}

求值只读取预先构造的事实字典，不执行任何外部代码。
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from .config import PRIORITY_RANK

COMPARISONS = {"==", "!=", ">", ">=", "<", "<=", "in", "not_in", "contains_any"}


def evaluate(condition: dict[str, Any], facts: dict[str, Any]) -> bool:
    """对事实字典求值一条条件。"""
    if "all" in condition:
        return all(evaluate(item, facts) for item in condition["all"])
    if "any" in condition:
        return any(evaluate(item, facts) for item in condition["any"])
    if "not" in condition:
        return not evaluate(condition["not"], facts)

    field = condition.get("field")
    op = condition.get("op")
    if field is None or op not in COMPARISONS:
        raise ValueError(f"非法条件：{condition!r}")
    expected = condition.get("value")
    actual = facts.get(field)

    if op == "==":
        return actual == expected
    if op == "!=":
        return actual != expected
    if op == "in":
        return actual in expected
    if op == "not_in":
        return actual not in expected
    if op == "contains_any":
        if not isinstance(actual, str):
            return False
        haystack = actual.lower()
        return any(str(keyword).lower() in haystack for keyword in expected)
    # 数值比较
    try:
        if op == ">":
            return actual is not None and actual > expected
        if op == ">=":
            return actual is not None and actual >= expected
        if op == "<":
            return actual is not None and actual < expected
        if op == "<=":
            return actual is not None and actual <= expected
    except TypeError:
        return False
    return False


def score_band(score: int) -> str:
    """无规则直接建议优先级时，按分值落档。"""
    if score >= 80:
        return "特急"
    if score >= 60:
        return "紧急"
    if score >= 40:
        return "高"
    if score >= 20:
        return "中"
    return "低"


def evaluate_rules(rules: list[sqlite3.Row], facts: dict[str, Any]) -> dict:
    """返回评分结果：score、suggested_priority、hits、rule_version 由调用方补。"""
    total = 0
    suggested_rank = -1
    suggested: str | None = None
    hits: list[dict] = []
    for rule in rules:
        condition = json.loads(rule["condition"])
        try:
            matched = evaluate(condition, facts)
        except ValueError:
            matched = False
        if not matched:
            continue
        total += rule["add_score"]
        hits.append(
            {
                "rule_key": rule["rule_key"],
                "title": rule["title"],
                "add_score": rule["add_score"],
                "suggest_priority": rule["suggest_priority"],
            }
        )
        if rule["suggest_priority"]:
            rank = PRIORITY_RANK.get(rule["suggest_priority"], -1)
            if rank > suggested_rank:
                suggested_rank = rank
                suggested = rule["suggest_priority"]
    if suggested is None:
        suggested = score_band(total)
    return {"risk_score": total, "suggested_priority": suggested, "risk_hits": hits}


# 首次发布时内置的默认规则。
DEFAULT_RULES: list[dict] = [
    {
        "rule_key": "channel-patrol",
        "title": "巡查渠道线索",
        "condition": {"field": "source_channel", "op": "==", "value": "巡查"},
        "add_score": 10,
        "suggest_priority": None,
    },
    {
        "rule_key": "channel-self-report",
        "title": "机构主动自报",
        "condition": {"field": "source_channel", "op": "==", "value": "机构自报"},
        "add_score": 5,
        "suggest_priority": None,
    },
    {
        "rule_key": "sensitive-evidence",
        "title": "附敏感或机密证据",
        "condition": {"field": "has_sensitive_evidence", "op": "==", "value": True},
        "add_score": 30,
        "suggest_priority": "高",
    },
    {
        "rule_key": "major-harm-keyword",
        "title": "重大危害关键词",
        "condition": {
            "field": "title_desc",
            "op": "contains_any",
            "value": ["死亡", "重伤", "中毒", "群体性", "重大事故"],
        },
        "add_score": 50,
        "suggest_priority": "特急",
    },
    {
        "rule_key": "fraud-keyword",
        "title": "欺诈伪造关键词",
        "condition": {
            "field": "title_desc",
            "op": "contains_any",
            "value": ["诈骗", "伪造", "虚报", "套取", "骗取"],
        },
        "add_score": 35,
        "suggest_priority": "紧急",
    },
]
