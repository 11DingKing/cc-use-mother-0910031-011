"""状态机与流转约束测试（服务层）。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from clueflow.errors import DomainViolation, Forbidden, LeaseRequired, StateConflict, ValidationError
from support import actor, make_service, register, to_active, to_pending


class StateMachineTest(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        self.reg = actor(self.service, "u-jian-guan-1")
        self.expert = actor(self.service, "u-expert-1")

    def _new_case(self) -> str:
        return register(self.service)["case"]["id"]

    def test_happy_path_full_lifecycle(self):
        case_id = self._new_case()
        to_pending(self.service, case_id)
        lease = self.service.claim_case(self.reg, case_id, {})
        token = lease["lease_token"]
        view = self.service.transition(self.reg, case_id, {
            "action": "verify", "reason": "核验属实", "lease_token": token})
        self.assertEqual(view["state"], "处置中")
        view = self.service.transition(self.reg, case_id, {
            "action": "decide", "reason": "事实清楚", "decision": "立案查处", "lease_token": token})
        self.assertEqual(view["state"], "已决定")
        self.assertEqual(view["decision"], "立案查处")
        view = self.service.transition(self.reg, case_id, {"action": "archive", "reason": "办结归档"})
        self.assertEqual(view["state"], "已归档")

    def test_illegal_direct_jump(self):
        case_id = self._new_case()
        with self.assertRaises(StateConflict):
            self.service.transition(self.reg, case_id, {"action": "verify", "reason": "跳态"})
        with self.assertRaises(StateConflict):
            self.service.transition(self.reg, case_id, {"action": "archive", "reason": "跳态"})

    def test_reason_is_mandatory(self):
        case_id = self._new_case()
        with self.assertRaises(ValidationError):
            self.service.transition(self.reg, case_id, {"action": "triage", "reason": "  "})

    def test_verify_requires_lease(self):
        case_id = self._new_case()
        to_pending(self.service, case_id)
        with self.assertRaises(LeaseRequired):
            self.service.transition(self.reg, case_id, {"action": "verify", "reason": "无租约核验"})

    def test_decide_requires_decision_value(self):
        case_id = self._new_case()
        token = to_active(self.service, case_id)
        with self.assertRaises(ValidationError):
            self.service.transition(self.reg, case_id, {
                "action": "decide", "reason": "缺决定", "lease_token": token})

    def test_return_to_registration(self):
        case_id = self._new_case()
        to_pending(self.service, case_id)
        view = self.service.transition(self.reg, case_id, {"action": "return", "reason": "材料不全退回补正"})
        self.assertEqual(view["state"], "登记")

    def test_archive_blocked_by_active_measure(self):
        case_id = self._new_case()
        token = to_active(self.service, case_id)
        self.service.impose_measure(self.reg, case_id, {
            "type": "封存证据", "reason": "防止证据灭失", "lease_token": token})
        self.service.transition(self.reg, case_id, {
            "action": "decide", "reason": "事实清楚", "decision": "立案查处", "lease_token": token})
        with self.assertRaises(DomainViolation):
            self.service.transition(self.reg, case_id, {"action": "archive", "reason": "归档"})
        # 解除措施后可归档
        measure = self.service.get_case(self.reg, case_id)["measures"][0]
        self.service.lift_measure(self.reg, case_id, measure["id"], {
            "reason": "证据已固定", "lease_token": token})
        view = self.service.transition(self.reg, case_id, {"action": "archive", "reason": "办结归档"})
        self.assertEqual(view["state"], "已归档")

    def test_reopen_only_by_expert_and_resets_cycle(self):
        case_id = self._new_case()
        token = to_active(self.service, case_id)
        self.service.transition(self.reg, case_id, {
            "action": "decide", "reason": "事实清楚", "decision": "不予立案", "lease_token": token})
        self.service.transition(self.reg, case_id, {"action": "archive", "reason": "归档"})
        with self.assertRaises(Forbidden):
            self.service.transition(self.reg, case_id, {"action": "reopen", "reason": "监管试图复开"})
        view = self.service.transition(self.expert, case_id, {"action": "reopen", "reason": "发现新证据，复开核查"})
        self.assertEqual(view["state"], "处置中")
        self.assertEqual(view["reopened_count"], 1)
        self.assertIsNone(view["decision"])
        self.assertIsNone(view["archived_at"])
        # 复开后重新初评，回到待确认
        self.assertEqual(view["priority_status"], "待确认")

    def test_reopen_from_decided_without_archive(self):
        case_id = self._new_case()
        token = to_active(self.service, case_id)
        self.service.transition(self.reg, case_id, {
            "action": "decide", "reason": "事实清楚", "decision": "移送其他部门", "lease_token": token})
        view = self.service.transition(self.expert, case_id, {"action": "reopen", "reason": "移送被退回"})
        self.assertEqual(view["state"], "处置中")

    def test_audit_trail_records_reasons(self):
        case_id = self._new_case()
        to_pending(self.service, case_id)
        trail = self.service.list_audit(self.reg, case_id)
        actions = [e["action"] for e in trail]
        self.assertIn("登记线索", actions)
        self.assertIn("风险初评", actions)
        self.assertIn("状态流转:triage", actions)
        triage = next(e for e in trail if e["action"] == "状态流转:triage")
        self.assertEqual(triage["reason"], "分流至监管队列")
        self.assertEqual(triage["from_state"], "登记")
        self.assertEqual(triage["to_state"], "待核验")


if __name__ == "__main__":
    unittest.main()
