"""风险规则引擎：版本化规则集 + 评分定级。

规则集整体版本化（domain 契约“风险优先级版本”）：每次评估记录所用版本与
命中明细，规则变更后历史评估仍可追溯，重评产生新的待确认建议。
"""
from __future__ import annotations

from dataclasses import dataclass, field

LEVEL_THRESHOLDS = ((70, "紧急"), (45, "高"), (25, "中"), (0, "低"))

RULE_KINDS = ("keyword", "channel", "recidivism", "sensitive_evidence", "multi_source")


def level_for_score(score: int) -> str:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "低"


@dataclass
class RuleHit:
    rule_id: str
    name: str
    points: int
    detail: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "points": self.points,
            "detail": self.detail,
        }


@dataclass
class AssessmentContext:
    """评估上下文：案件当前聚合的事实。"""

    channels: set[str] = field(default_factory=set)
    contents: list[str] = field(default_factory=list)
    clue_count: int = 0
    max_sensitivity: int = 0
    recidivist_subjects: list[str] = field(default_factory=list)


def evaluate(rules: list[dict], ctx: AssessmentContext) -> tuple[int, list[RuleHit]]:
    """对启用规则逐条求值，返回 (总分, 命中明细)。"""
    hits: list[RuleHit] = []
    for rule in rules:
        if not rule.get("enabled", 1):
            continue
        kind = rule["kind"]
        params = rule["params"]
        detail: str | None = None
        if kind == "keyword":
            words = [w for w in params.get("words", []) if any(w in c for c in ctx.contents)]
            if words:
                detail = "命中关键词：" + "、".join(words)
        elif kind == "channel":
            if params.get("channel") in ctx.channels:
                detail = f"来源渠道：{params['channel']}"
        elif kind == "recidivism":
            if ctx.recidivist_subjects:
                detail = "既往违规主体：" + "、".join(ctx.recidivist_subjects)
        elif kind == "sensitive_evidence":
            if ctx.max_sensitivity >= int(params.get("min_level", 3)):
                detail = f"含敏感级别≥{params.get('min_level', 3)}的证据"
        elif kind == "multi_source":
            if ctx.clue_count >= int(params.get("min_clues", 2)):
                detail = f"同一案件汇聚 {ctx.clue_count} 条线索"
        else:  # pragma: no cover - 规则种类在写入时已校验
            continue
        if detail:
            hits.append(RuleHit(rule["id"], rule["name"], int(rule["points"]), detail))
    score = min(100, sum(h.points for h in hits))
    return score, hits
