"""测试公共工具：内存库服务与常用流程。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from clueflow.services import ClueflowService  # noqa: E402
from clueflow.store import Store  # noqa: E402


def make_service() -> ClueflowService:
    return ClueflowService(Store(":memory:"))


def actor(service: ClueflowService, actor_id: str):
    return service.authenticate(actor_id)


def clue_payload(**overrides) -> dict:
    data = {
        "channel": "投诉",
        "title": "仁爱医院涉嫌违规执业",
        "content": "群众反映仁爱医院存在超范围经营问题",
        "event_date": "2026-09-28",
        "location": "城东街道",
        "reporter": {"name": "张三", "contact": "13800000000"},
        "subjects": [
            {"type": "机构", "name": "仁爱医院", "identifier": "USCC-100", "org_id": "org-hospital-1"}
        ],
    }
    data.update(overrides)
    return data


def register(service: ClueflowService, actor_id: str = "u-jian-guan-1", **overrides) -> dict:
    return service.register_clue(actor(service, actor_id), clue_payload(**overrides))


def to_pending(service: ClueflowService, case_id: str, actor_id: str = "u-jian-guan-1") -> None:
    """登记 → 待核验。"""
    service.transition(actor(service, actor_id), case_id, {"action": "triage", "reason": "分流至监管队列"})


def to_active(service: ClueflowService, case_id: str, actor_id: str = "u-jian-guan-1") -> str:
    """登记 → 待核验 → 处置中，返回租约令牌。"""
    a = actor(service, actor_id)
    to_pending(service, case_id, actor_id)
    lease = service.claim_case(a, case_id, {})
    service.transition(
        a, case_id,
        {"action": "verify", "reason": "核验属实，转入处置", "lease_token": lease["lease_token"]},
    )
    return lease["lease_token"]
