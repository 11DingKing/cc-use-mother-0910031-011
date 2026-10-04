"""合并建议、优先级确认、延期、拆分、转派与可见性测试（服务层）。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from clueflow.errors import DomainViolation, Forbidden, LeaseConflict, StateConflict, ValidationError
from clueflow.timeutil import parse
from support import actor, make_service, register, to_active, to_pending


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        self.reg = actor(self.service, "u-jian-guan-1")
        self.expert = actor(self.service, "u-expert-1")
        self.compliance = actor(self.service, "u-heliang")

    def _register_pair(self):
        """登记两条疑似重复线索，返回 (案件A, 案件B, 建议id)。"""
        first = register(self.service)
        second = register(
            self.service,
            channel="巡查",
            title="仁爱医院超范围经营巡查发现",
            content="巡查发现仁爱医院存在超范围经营问题，群众反映属实",
        )
        suggestions = second["merge_suggestions"]
        self.assertEqual(len(suggestions), 1, "应生成一条合并建议")
        return first["case"]["id"], second["case"]["id"], suggestions[0]["id"]

    def test_suggestion_carries_reason_signals(self):
        _, _, sid = self._register_pair()
        sug = next(s for s in self.service.list_merge_suggestions(self.reg, {}) if s["id"] == sid)
        self.assertEqual(sug["status"], "待确认")
        self.assertGreater(sug["score"], 0)
        self.assertIn("USCC-100", sug["signals"]["shared_subjects"])
        self.assertGreater(sug["signals"]["content_similarity"], 0)

    def test_confirm_merge_moves_everything_to_target(self):
        case_a, case_b, sid = self._register_pair()
        result = self.service.confirm_merge(self.expert, sid, {"reason": "同一事件多渠道重复登记，并案处理"})
        source = result["source_case"]
        target = result["target_case"]
        self.assertEqual(source["id"], case_b)  # 后登记的并入先登记的
        self.assertEqual(source["state"], "已归档")
        self.assertIn(case_a, source["decision"])
        self.assertEqual(target["state"], "登记")
        self.assertEqual(len(target["clues"]), 2)
        # 多渠道汇聚后重新初评且命中“多渠道重复反映”
        hits = [h["name"] for h in target["latest_assessment"]["hits"]]
        self.assertIn("多渠道重复反映", hits)
        # 建议状态与审计
        sug = next(s for s in self.service.list_merge_suggestions(self.reg, {}) if s["id"] == sid)
        self.assertEqual(sug["status"], "已确认")
        actions = [e["action"] for e in self.service.list_audit(self.reg, case_b)]
        self.assertIn("合并关闭", actions)

    def test_confirm_merge_requires_authorized_role(self):
        _, _, sid = self._register_pair()
        with self.assertRaises(Forbidden):
            self.service.confirm_merge(self.compliance, sid, {"reason": "越权确认"})

    def test_reject_merge(self):
        case_a, case_b, sid = self._register_pair()
        self.service.reject_merge(self.reg, sid, {"reason": "经核实并非同一事件"})
        sug = next(s for s in self.service.list_merge_suggestions(self.reg, {}) if s["id"] == sid)
        self.assertEqual(sug["status"], "已拒绝")
        self.assertEqual(self.service.get_case(self.reg, case_b)["state"], "登记")
        with self.assertRaises(StateConflict):
            self.service.confirm_merge(self.reg, sid, {"reason": "重复处理"})

    def test_no_suggestion_for_unrelated_clue(self):
        register(self.service)
        other = register(
            self.service,
            title="完全不同的事件",
            content="另一家药店未按规定登记台账",
            subjects=[{"type": "机构", "name": "康泰药店", "identifier": "USCC-999", "org_id": "org-pharmacy-1"}],
        )
        self.assertEqual(other["merge_suggestions"], [])


class PriorityTest(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        self.reg = actor(self.service, "u-jian-guan-1")
        self.expert = actor(self.service, "u-expert-1")

    def test_auto_assessment_pending_then_confirm(self):
        result = register(self.service)
        case = result["case"]
        assessment = result["priority_assessment"]
        self.assertEqual(assessment["status"], "待确认")
        self.assertEqual(assessment["suggested_level"], "中")  # 关键词20 + 投诉5
        self.assertEqual(case["priority_status"], "待确认")
        view = self.service.confirm_priority(self.reg, case["id"], {"accept": True, "reason": "同意系统建议"})
        self.assertEqual(view["priority"], "中")
        self.assertEqual(view["priority_status"], "已确认")

    def test_adjust_priority_changes_deadline(self):
        result = register(self.service)
        case = result["case"]
        before = parse(case["due_at"])
        view = self.service.confirm_priority(
            self.expert, case["id"],
            {"accept": False, "level": "紧急", "reason": "涉及用药安全，提级办理"},
        )
        self.assertEqual(view["priority"], "紧急")
        after = parse(view["due_at"])
        self.assertLess(after, before)  # 时限随级别收紧
        self.assertEqual(view["latest_assessment"]["status"], "已调整")

    def test_double_confirm_rejected(self):
        result = register(self.service)
        case_id = result["case"]["id"]
        self.service.confirm_priority(self.reg, case_id, {"accept": True, "reason": "确认"})
        with self.assertRaises(StateConflict):
            self.service.confirm_priority(self.reg, case_id, {"accept": True, "reason": "再次确认"})

    def test_severe_clue_gets_urgent_suggestion(self):
        result = register(
            self.service,
            title="某诊所涉嫌非法集资",
            content="该诊所以会员制名义非法集资，涉及众多老年人",
        )
        # 重大关键词 40 + 投诉渠道 5 = 45 → 高
        self.assertEqual(result["priority_assessment"]["suggested_level"], "高")

    def test_rule_set_versioning(self):
        before = self.service.list_rules(self.reg)
        self.assertEqual(before["version"], 1)
        with self.assertRaises(Forbidden):
            self.service.replace_rules(self.reg, {"rules": [{"name": "x", "kind": "channel", "params": {"channel": "投诉"}, "points": 5}]})
        new = self.service.replace_rules(self.expert, {"rules": [
            {"name": "投诉即高分", "kind": "channel", "params": {"channel": "投诉"}, "points": 80},
        ]})
        self.assertEqual(new["version"], 2)
        result = register(self.service)
        self.assertEqual(result["priority_assessment"]["rule_version"], 2)
        self.assertEqual(result["priority_assessment"]["suggested_level"], "紧急")


class ExtensionTest(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        self.reg = actor(self.service, "u-jian-guan-1")
        self.expert = actor(self.service, "u-expert-1")
        self.case_id = register(self.service)["case"]["id"]
        self.token = to_active(self.service, self.case_id)

    def test_approved_extension_moves_deadline(self):
        before = parse(self.service.get_case(self.reg, self.case_id)["due_at"])
        ext = self.service.request_extension(self.reg, self.case_id, {
            "days": 5, "reason": "涉案人员在外地，需延伸调查", "lease_token": self.token})
        self.assertEqual(ext["status"], "待审批")
        decided = self.service.decide_extension(self.expert, self.case_id, ext["id"], {
            "approve": True, "reason": "情况属实，同意延期"})
        self.assertEqual(decided["status"], "已批准")
        after = parse(self.service.get_case(self.reg, self.case_id)["due_at"])
        self.assertEqual((after - before).days, 5)

    def test_only_expert_approves(self):
        ext = self.service.request_extension(self.reg, self.case_id, {
            "days": 3, "reason": "需延期", "lease_token": self.token})
        with self.assertRaises(Forbidden):
            self.service.decide_extension(self.reg, self.case_id, ext["id"], {
                "approve": True, "reason": "自审自批"})

    def test_max_two_extensions_per_cycle(self):
        for _ in range(2):
            ext = self.service.request_extension(self.reg, self.case_id, {
                "days": 2, "reason": "延期", "lease_token": self.token})
            self.service.decide_extension(self.expert, self.case_id, ext["id"], {
                "approve": True, "reason": "同意"})
        with self.assertRaises(DomainViolation):
            self.service.request_extension(self.reg, self.case_id, {
                "days": 1, "reason": "第三次延期", "lease_token": self.token})

    def test_extension_requires_lease_and_active_state(self):
        done = register(self.service)["case"]["id"]
        with self.assertRaises(StateConflict):
            self.service.request_extension(self.reg, done, {"days": 1, "reason": "登记态延期"})


class SplitTransferTest(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        self.reg1 = actor(self.service, "u-jian-guan-1")
        self.reg2 = actor(self.service, "u-jian-guan-2")
        self.expert = actor(self.service, "u-expert-1")

    def _merged_case(self):
        first = register(self.service)
        second = register(
            self.service,
            channel="巡查",
            title="仁爱医院巡查线索",
            content="巡查发现仁爱医院存在超范围经营问题",
        )
        sid = second["merge_suggestions"][0]["id"]
        self.service.confirm_merge(self.expert, sid, {"reason": "并案"})
        return first["case"]["id"], second["clue"]["id"]

    def test_split_moves_clue_to_child_case(self):
        case_id, clue_b = self._merged_case()
        result = self.service.split_case(self.reg1, case_id, {
            "title": "仁爱医院巡查部分", "clue_ids": [clue_b], "reason": "线索涉及不同违法行为，拆分核查"})
        parent, child = result["parent"], result["child"]
        self.assertEqual(len(parent["clues"]), 1)
        self.assertEqual(len(child["clues"]), 1)
        self.assertEqual(child["parent_id"], case_id)
        self.assertIn(child["id"], parent["children"])
        self.assertEqual(child["state"], "登记")

    def test_split_must_keep_one_clue_in_parent(self):
        case_id = register(self.service)["case"]["id"]
        clue_id = self.service.get_case(self.reg1, case_id)["clues"][0]["id"]
        with self.assertRaises(ValidationError):
            self.service.split_case(self.reg1, case_id, {
                "title": "全搬走", "clue_ids": [clue_id], "reason": "非法拆分"})

    def test_split_in_active_state_requires_lease(self):
        case_id, clue_b = self._merged_case()
        token = to_active(self.service, case_id)
        with self.assertRaises(ValidationError):
            self.service.split_case(self.reg1, case_id, {
                "title": "不存在的线索", "clue_ids": ["CLU-999999"], "reason": "校验归属",
                "lease_token": token})
        result = self.service.split_case(self.reg1, case_id, {
            "title": "合法拆分", "clue_ids": [clue_b], "reason": "拆分", "lease_token": token})
        self.assertEqual(result["child"]["state"], "登记")

    def test_transfer_releases_lease_and_changes_assignee(self):
        case_id = register(self.service)["case"]["id"]
        to_pending(self.service, case_id)
        lease = self.service.claim_case(self.reg1, case_id, {})
        view = self.service.transfer(self.reg1, case_id, {
            "to_actor_id": "u-jian-guan-2", "reason": "属地管辖调整",
            "lease_token": lease["lease_token"]})
        self.assertEqual(view["assignee_id"], "u-jian-guan-2")
        self.assertIsNone(view["lease"])
        # 原持约人令牌失效，新承办人可认领
        with self.assertRaises(LeaseConflict):
            self.service.transition(self.reg1, case_id, {
                "action": "verify", "reason": "旧承办人操作", "lease_token": lease["lease_token"]})
        new_lease = self.service.claim_case(self.reg2, case_id, {})
        view = self.service.transition(self.reg2, case_id, {
            "action": "verify", "reason": "新承办人核验", "lease_token": new_lease["lease_token"]})
        self.assertEqual(view["state"], "处置中")

    def test_transfer_to_practitioner_rejected(self):
        case_id = register(self.service)["case"]["id"]
        to_pending(self.service, case_id)
        with self.assertRaises(ValidationError):
            self.service.transfer(self.reg1, case_id, {
                "to_actor_id": "ZY-3301", "reason": "非法接收人"})


class VisibilityTest(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        self.reg = actor(self.service, "u-jian-guan-1")
        self.compliance = actor(self.service, "u-heliang")  # org-hospital-1
        self.practitioner = actor(self.service, "ZY-3301")

    def test_compliance_officer_scoped_to_own_org(self):
        own = register(self.service)["case"]["id"]  # 主体 org-hospital-1
        other = register(
            self.service,
            subjects=[{"type": "机构", "name": "康泰药店", "identifier": "USCC-999", "org_id": "org-pharmacy-1"}],
        )["case"]["id"]
        self.assertEqual(self.service.get_case(self.compliance, own)["id"], own)
        with self.assertRaises(Forbidden):
            self.service.get_case(self.compliance, other)
        listed = {c["id"] for c in self.service.list_cases(self.compliance, {})["items"]}
        self.assertIn(own, listed)
        self.assertNotIn(other, listed)

    def test_practitioner_scoped_to_self(self):
        involved = register(
            self.service,
            subjects=[
                {"type": "机构", "name": "仁爱医院", "identifier": "USCC-100", "org_id": "org-hospital-1"},
                {"type": "执业人员", "name": "林一凡", "identifier": "ZY-3301"},
            ],
        )["case"]["id"]
        unrelated = register(self.service)["case"]["id"]
        self.assertEqual(self.service.get_case(self.practitioner, involved)["id"], involved)
        with self.assertRaises(Forbidden):
            self.service.get_case(self.practitioner, unrelated)

    def test_evidence_redaction_by_role_via_service(self):
        case_id = register(
            self.service,
            subjects=[
                {"type": "机构", "name": "仁爱医院", "identifier": "USCC-100", "org_id": "org-hospital-1"},
                {"type": "执业人员", "name": "林一凡", "identifier": "ZY-3301"},
            ],
        )["case"]["id"]
        for level in (1, 2, 3, 4):
            self.service.add_evidence(self.reg, case_id, {
                "kind": "书证", "content": f"级别{level}证据内容", "sensitivity": level})
        expert_view = self.service.list_evidence(actor(self.service, "u-expert-1"), case_id)
        self.assertEqual(expert_view["hidden_count"], 0)
        self.assertEqual(len(expert_view["items"]), 4)
        reg_view = self.service.list_evidence(self.reg, case_id)
        masked = [i for i in reg_view["items"] if i["redacted"]]
        self.assertEqual(len(masked), 1)
        self.assertNotIn("级别4证据内容", masked[0]["content"])
        com_view = self.service.list_evidence(self.compliance, case_id)
        self.assertEqual(com_view["hidden_count"], 1)
        pra_view = self.service.list_evidence(self.practitioner, case_id)
        self.assertEqual(pra_view["hidden_count"], 2)

    def test_compliance_officer_cannot_upload_secret_evidence(self):
        case_id = register(self.service, actor_id="u-heliang", channel="机构自报")["case"]["id"]
        with self.assertRaises(ValidationError):
            self.service.add_evidence(self.compliance, case_id, {
                "kind": "书证", "content": "自报材料", "sensitivity": 4})


if __name__ == "__main__":
    unittest.main()
