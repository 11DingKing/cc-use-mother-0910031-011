"""领域服务测试：指纹去重、合并/优先级人工确认、租约、状态机、裁剪、审计。"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from violation_triage.errors import (
    AuthError,
    ConflictError,
    NotFoundError,
    PermissionError,
    ValidationError,
)
from violation_triage.risk import DEFAULT_RULES
from violation_triage.service import TriageService


class ServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.svc = TriageService(self.tmp.name, lease_seconds=3600)
        self.svc.create_user("admin", "p", "分流管理员", "分流管理员")
        self.svc.create_user("li", "p", "李监管", "监管人员")
        self.svc.create_user("wang", "p", "王复核", "复核专家")
        self.svc.create_user("zhou", "p", "周合规", "机构合规员")
        self.svc.create_user("wu", "p", "吴执业", "执业人员")
        self.admin = self._user("admin")
        self.li = self._user("li")
        self.wang = self._user("wang")
        self.zhou = self._user("zhou")
        self.wu = self._user("wu")
        self.svc.publish_rules(self.admin, DEFAULT_RULES, "v1")

    def tearDown(self) -> None:
        Path(self.tmp.name).unlink(missing_ok=True)

    def _user(self, username: str):
        return self.svc.conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def base_clue(self, **overrides) -> dict:
        payload = {
            "source_channel": "投诉",
            "source_ref": "TS-100",
            "title": "某机构涉嫌伪造材料骗取资金",
            "description": "存在伪造和虚报行为",
            "occurrence_at": "2026-10-01T09:00:00Z",
            "region": "城东区",
            "subject_type": "机构",
            "subject_name": "测试机构",
            "subject_identifier": "91330100ma0000009x",
            "evidences": [],
        }
        payload.update(overrides)
        return payload

    def register(self, actor=None, **overrides) -> dict:
        return self.svc.register_clue(actor or self.li, self.base_clue(**overrides))


class FingerprintTest(ServiceTestBase):
    def test_identical_fingerprint_is_idempotent(self) -> None:
        first = self.register()
        again = self.register()
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["clue_id"], first["clue_id"])

    def test_different_channel_same_event_creates_merge_suggestion(self) -> None:
        first = self.register(source_ref="TS-100", title="某机构涉嫌伪造材料骗取资金")
        second = self.register(
            source_channel="机构自报", source_ref="SR-2",
            title="测试机构伪造材料骗取资金自查上报",
        )
        self.assertFalse(second["duplicate"])
        self.assertEqual(len(second["merge_suggestions"]), 1)
        cand = second["merge_suggestions"][0]
        self.assertEqual(cand["primary_id"], first["clue_id"])
        self.assertGreaterEqual(cand["score"], 0.45)

    def test_unrelated_subject_no_suggestion(self) -> None:
        self.register()
        other = self.register(source_ref="TS-200", subject_name="另一机构",
                              subject_identifier="91330100ma0000008y",
                              title="完全不相关的广告投诉")
        self.assertEqual(other["merge_suggestions"], [])


class RiskAndPriorityTest(ServiceTestBase):
    def test_default_rules_score_and_suggest(self) -> None:
        result = self.register()
        # fraud-keyword = 35
        self.assertEqual(result["risk_score"], 35)
        self.assertEqual(result["suggested_priority"], "紧急")

    def test_major_harm_implies_top_priority(self) -> None:
        result = self.register(title="发生群体性食物中毒，出现死亡病例", description="")
        self.assertEqual(result["suggested_priority"], "特急")
        self.assertGreaterEqual(result["risk_score"], 50)

    def test_priority_requires_confirmation(self) -> None:
        reg = self.register()
        detail = self.svc.get_clue_detail(self.li, reg["clue_id"])
        self.assertIsNone(detail["priority"])
        self.assertIsNone(detail["due_at"])
        out = self.svc.confirm_priority(self.admin, reg["clue_id"], "特急", "重大风险")
        self.assertEqual(out["state"], "待核验")
        self.assertIsNotNone(out["due_at"])

    def test_institution_role_cannot_confirm_priority(self) -> None:
        reg = self.register()
        with self.assertRaises(PermissionError):
            self.svc.confirm_priority(self.zhou, reg["clue_id"], "高", "")

    def test_rule_versioning_and_rescore(self) -> None:
        reg = self.register()
        self.svc.publish_rules(
            self.admin,
            [{"rule_key": "r1", "title": "任意投诉",
              "condition": {"field": "source_channel", "op": "==", "value": "投诉"},
              "add_score": 5, "suggest_priority": "低"}],
            "v2",
        )
        out = self.svc.rescale_risk(self.li, reg["clue_id"])
        self.assertEqual(out["rule_version"], 2)
        self.assertEqual(out["risk_score"], 5)
        # 历史版本仍可读取
        v1 = self.svc.get_rules(1)
        self.assertEqual(v1["version"], 1)
        self.assertTrue(v1["rules"])

    def test_priority_only_in_early_states(self) -> None:
        reg = self.register()
        self.svc.confirm_priority(self.admin, reg["clue_id"], "紧急", "")
        self.svc.claim(self.li, reg["clue_id"])
        self.svc.verify_clue(self.li, reg["clue_id"])
        with self.assertRaises(ConflictError):
            self.svc.confirm_priority(self.admin, reg["clue_id"], "特急", "")


class MergeWorkflowTest(ServiceTestBase):
    def _pair(self):
        first = self.register()
        second = self.register(source_channel="机构自报", source_ref="SR-2",
                               title="测试机构伪造材料骗取资金自查上报")
        return first, second

    def test_suggestion_must_be_confirmed(self) -> None:
        first, second = self._pair()
        sugs = self.svc.list_merge_suggestions(self.admin)
        self.assertTrue(all(s["status"] == "待确认" for s in sugs))
        second_detail = self.svc.get_clue_detail(self.li, second["clue_id"])
        self.assertIsNone(second_detail["merged_into"])

    def test_confirm_merge_archives_duplicate(self) -> None:
        first, second = self._pair()
        sug = self.svc.list_merge_suggestions(self.admin)[0]
        result = self.svc.confirm_merge(self.admin, sug["id"], "同事件多渠道")
        self.assertEqual(result["merged_clue_id"], second["clue_id"])
        detail = self.svc.get_clue_detail(self.li, second["clue_id"])
        self.assertEqual(detail["state"], "已归档")
        self.assertIsNotNone(detail["merged_into"])
        self.assertEqual(detail["merged_into"]["clue_id"], first["clue_id"])

    def test_merge_double_confirm_conflicts(self) -> None:
        self._pair()
        sug = self.svc.list_merge_suggestions(self.admin)[0]
        self.svc.confirm_merge(self.admin, sug["id"])
        with self.assertRaises(ConflictError):
            self.svc.confirm_merge(self.admin, sug["id"])

    def test_merged_clue_cannot_reopen(self) -> None:
        self._pair()
        sug = self.svc.list_merge_suggestions(self.admin)[0]
        merged = self.svc.confirm_merge(self.admin, sug["id"])
        with self.assertRaises(ConflictError):
            self.svc.reopen_clue(self.admin, merged["merged_clue_id"], "试一下")

    def test_reject_keeps_both_open(self) -> None:
        first, second = self._pair()
        sug = self.svc.list_merge_suggestions(self.admin)[0]
        self.svc.reject_merge(self.admin, sug["id"], "不是同一事件")
        detail = self.svc.get_clue_detail(self.li, second["clue_id"])
        self.assertEqual(detail["state"], "登记")

    def test_officer_cannot_confirm_merge(self) -> None:
        self._pair()
        sug = self.svc.list_merge_suggestions(self.admin)[0]
        with self.assertRaises(PermissionError):
            self.svc.confirm_merge(self.zhou, sug["id"])


class LeaseTest(ServiceTestBase):
    def _ready(self):
        reg = self.register()
        self.svc.confirm_priority(self.admin, reg["clue_id"], "紧急", "")
        return reg["clue_id"]

    def test_second_claim_conflicts(self) -> None:
        cid = self._ready()
        self.svc.claim(self.li, cid)
        with self.assertRaises(ConflictError):
            self.svc.claim(self.wang, cid)

    def test_release_allows_reclaim(self) -> None:
        cid = self._ready()
        self.svc.claim(self.li, cid)
        self.svc.release_clue(self.li, cid, "换班")
        claim = self.svc.claim(self.wang, cid)
        self.assertEqual(claim["holder"], "王复核")

    def test_transfer_requires_reason_and_moves_lease(self) -> None:
        cid = self._ready()
        self.svc.claim(self.li, cid)
        with self.assertRaises(ValidationError):
            self.svc.assign(self.admin, cid, self.wang["id"], "")
        out = self.svc.assign(self.admin, cid, self.wang["id"], "需要专家")
        self.assertEqual(out["action"], "transfer")
        detail = self.svc.get_clue_detail(self.admin, cid)
        self.assertEqual(detail["lease"]["holder"], "王复核")
        self.assertTrue(detail["lease"]["mine"] is False)

    def test_verify_requires_lease_holder(self) -> None:
        cid = self._ready()
        self.svc.claim(self.li, cid)
        with self.assertRaises(ConflictError):
            self.svc.verify_clue(self.wang, cid)

    def test_expired_lease_is_reclaimable(self) -> None:
        svc = TriageService(self.tmp.name, lease_seconds=0)
        cid = self._ready()
        svc.claim(self.li, cid)
        # lease_seconds=0 → 立即过期（过期时间与当前时间同刻，<= 判断成立）
        claim = svc.claim(self.wang, cid)
        self.assertEqual(claim["holder"], "王复核")


class StateMachineTest(ServiceTestBase):
    def _full_lifecycle(self):
        reg = self.register()
        cid = reg["clue_id"]
        self.svc.confirm_priority(self.admin, cid, "紧急", "")
        self.svc.claim(self.li, cid)
        self.svc.verify_clue(self.li, cid)
        return cid

    def test_illegal_jump_registered_to_closed(self) -> None:
        reg = self.register()
        with self.assertRaises(ConflictError):
            self.svc.close_clue(self.li, reg["clue_id"], "驳回投诉", "摘要")

    def test_close_requires_summary(self) -> None:
        cid = self._full_lifecycle()
        with self.assertRaises(ValidationError):
            self.svc.close_clue(self.li, cid, "属实立案", "")

    def test_active_measure_blocks_close(self) -> None:
        cid = self._full_lifecycle()
        m = self.svc.create_measure(self.li, cid, "暂停结算", "止损")
        with self.assertRaises(ConflictError):
            self.svc.close_clue(self.li, cid, "责令整改", "摘要")
        self.svc.lift_measure(self.admin, m["measure_id"], "风险解除")
        out = self.svc.close_clue(self.li, cid, "责令整改", "摘要")
        self.assertEqual(out["state"], "已决定")

    def test_measure_lift_is_once_only(self) -> None:
        cid = self._full_lifecycle()
        m = self.svc.create_measure(self.li, cid, "暂停结算", "")
        self.svc.lift_measure(self.admin, m["measure_id"], "解除")
        with self.assertRaises(ConflictError):
            self.svc.lift_measure(self.admin, m["measure_id"], "再次解除")

    def test_archive_then_reopen(self) -> None:
        cid = self._full_lifecycle()
        self.svc.close_clue(self.li, cid, "属实立案", "摘要")
        self.svc.archive_clue(self.admin, cid)
        with self.assertRaises(ValidationError):
            self.svc.reopen_clue(self.admin, cid, "")
        out = self.svc.reopen_clue(self.admin, cid, "出现新证据")
        self.assertEqual(out["state"], "处置中")
        detail = self.svc.get_clue_detail(self.admin, cid)
        self.assertIsNotNone(detail["lease"])

    def test_decided_cannot_be_reopened_directly(self) -> None:
        cid = self._full_lifecycle()
        self.svc.close_clue(self.li, cid, "属实立案", "摘要")
        with self.assertRaises(ConflictError):
            self.svc.reopen_clue(self.admin, cid, "跳过归档")

    def test_extension_approval_extends_due(self) -> None:
        cid = self._full_lifecycle()
        detail_before = self.svc.get_clue_detail(self.li, cid)
        req = self.svc.request_extension(self.li, cid, 48, "等待鉴定")
        out = self.svc.decide_extension(self.admin, req["extension_id"], True, "同意")
        self.assertGreater(out["due_at"], detail_before["due_at"])
        detail_after = self.svc.get_clue_detail(self.li, cid)
        self.assertEqual(len(detail_after["deadline_extensions"]), 1)
        # 已处理后可以再次申请
        req2 = self.svc.request_extension(self.li, cid, 12, "再次需要时间")
        self.assertEqual(req2["status"], "待审批")

    def test_pending_extension_blocks_close(self) -> None:
        cid = self._full_lifecycle()
        self.svc.request_extension(self.li, cid, 24, "材料补充中")
        with self.assertRaises(ConflictError):
            self.svc.close_clue(self.li, cid, "属实立案", "摘要")

    def test_split_creates_children_and_copies_evidence(self) -> None:
        cid = self._full_lifecycle()
        self.svc.add_evidence(self.li, str(cid),
                              {"label": "关键合同", "content_ref": "oss://x/9", "sensitivity": "内部"})
        out = self.svc.split_clue(self.admin, str(cid), [
            {"title": "资金问题", "evidence_ids": []},
            {"title": "人员问题"},
        ])
        self.assertEqual(len(out["children"]), 2)
        parent = self.svc.get_clue_detail(self.admin, cid)
        self.assertEqual(len(parent["children"]), 2)
        child = self.svc.get_clue_detail(self.admin, out["children"][0]["clue_id"])
        self.assertEqual(child["parent"]["clue_id"], parent["clue_id"])
        self.assertEqual(child["state"], "待核验")


class EvidenceRedactionTest(ServiceTestBase):
    def _clue_with_evidence(self):
        reg = self.register(evidences=[
            {"label": "公开回执", "content_ref": "oss://a", "sensitivity": "普通"},
            {"label": "内部通报", "content_ref": "oss://b", "sensitivity": "内部"},
            {"label": "举报人材料", "content_ref": "oss://c", "sensitivity": "敏感"},
            {"label": "密钥级证据", "content_ref": "oss://d", "sensitivity": "机密"},
        ])
        return reg["clue_id"]

    def test_institution_sees_only_general(self) -> None:
        cid = self._clue_with_evidence()
        detail = self.svc.get_clue_detail(self.zhou, cid)
        levels = {(e["sensitivity"], e["redacted"]) for e in detail["evidences"]}
        self.assertIn(("普通", False), levels)
        self.assertNotIn(("内部", False), levels)
        self.assertIn(("机密", True), levels)
        # 被裁剪证据不得出现内容指针与名称
        for e in detail["evidences"]:
            if e["redacted"]:
                self.assertNotIn("content_ref", e)
                self.assertNotIn("label", e)
        self.assertEqual(detail["evidence_visibility"]["visible"], 1)

    def test_regulator_sees_through_sensitive(self) -> None:
        cid = self._clue_with_evidence()
        detail = self.svc.get_clue_detail(self.li, cid)
        visible = {e["sensitivity"] for e in detail["evidences"] if not e["redacted"]}
        self.assertEqual(visible, {"普通", "内部", "敏感"})

    def test_expert_sees_all(self) -> None:
        cid = self._clue_with_evidence()
        detail = self.svc.get_clue_detail(self.wang, cid)
        self.assertTrue(all(not e["redacted"] for e in detail["evidences"]))

    def test_institution_cannot_file_sensitive_evidence(self) -> None:
        reg = self.register()
        with self.assertRaises(PermissionError):
            self.svc.add_evidence(self.zhou, reg["clue_id"],
                                  {"label": "密件", "content_ref": "oss://z", "sensitivity": "机密"})

    def test_reporter_contact_masked_for_institution(self) -> None:
        reg = self.register()
        self.svc.add_evidence(self.li, str(reg["clue_id"]),
                              {"label": "x", "content_ref": "oss://1", "sensitivity": "敏感"})
        # reporter_contact 默认空；补一条带联系方式的登记
        reg2 = self.register(source_ref="TS-101", reporter_contact="13800001234")
        detail = self.svc.get_clue_detail(self.zhou, reg2["clue_id"])
        self.assertIn("*", detail["reporter_contact"])
        detail_li = self.svc.get_clue_detail(self.li, reg2["clue_id"])
        self.assertEqual(detail_li["reporter_contact"], "13800001234")


class AuthAndAuditTest(ServiceTestBase):
    def test_login_and_token_lifecycle(self) -> None:
        session = self.svc.login("li", "p")
        self.assertEqual(session["user"]["role"], "监管人员")
        user = self.svc.authenticate(session["token"])
        self.assertEqual(user["id"], self.li["id"])
        self.svc.logout(session["token"])
        with self.assertRaises(AuthError):
            self.svc.authenticate(session["token"])

    def test_bad_password(self) -> None:
        with self.assertRaises(AuthError):
            self.svc.login("li", "wrong")

    def test_missing_token(self) -> None:
        with self.assertRaises(AuthError):
            self.svc.authenticate(None)

    def test_audit_trail_records_every_triage_reason(self) -> None:
        reg = self.register()
        cid = reg["clue_id"]
        self.svc.confirm_priority(self.admin, cid, "紧急", "人工提级理由")
        self.svc.claim(self.li, cid)
        self.svc.verify_clue(self.li, cid, "核验理由")
        measure = self.svc.create_measure(self.li, cid, "暂停结算", "止损理由")
        self.svc.lift_measure(self.admin, measure["measure_id"], "结案前解除")
        self.svc.close_clue(self.li, cid, "责令整改", "结案摘要")
        logs = self.svc.list_audit(self.li, cid)
        actions = [a["action"] for a in logs]
        for expected in ("clue.register", "priority.confirm", "clue.claim", "clue.verify",
                         "measure.create", "measure.lift", "clue.close"):
            self.assertIn(expected, actions)
        # 每条记录都有操作人、角色、理由
        for item in logs:
            self.assertTrue(item["actor"])
            self.assertTrue(item["actor_role"])
            self.assertIn("reason", item)
        priority_log = next(a for a in logs if a["action"] == "priority.confirm")
        self.assertEqual(priority_log["reason"], "人工提级理由")
        self.assertEqual(priority_log["detail"]["priority"], "紧急")


class QueryTest(ServiceTestBase):
    def test_overdue_filter_and_mine(self) -> None:
        reg = self.register()
        cid = reg["clue_id"]
        # 特急 24h，手工把时限改到过去
        self.svc.confirm_priority(self.admin, cid, "特急", "")
        with self.svc._tx() as conn:
            conn.execute("UPDATE clues SET due_at = '2000-01-01T00:00:00.000Z' WHERE id = ?", (cid,))
        overdue = self.svc.list_clues(self.li, {"overdue": "1"})
        self.assertEqual(overdue["total"], 1)
        self.assertTrue(overdue["items"][0]["overdue"])
        self.svc.claim(self.li, cid)
        mine = self.svc.list_clues(self.li, {"mine": "1"})
        self.assertEqual(mine["total"], 1)

    def test_list_excludes_merged_by_default(self) -> None:
        first = self.register()
        second = self.register(source_channel="机构自报", source_ref="SR-2",
                               title="测试机构伪造材料骗取资金自查上报")
        sug = self.svc.list_merge_suggestions(self.admin)[0]
        self.svc.confirm_merge(self.admin, sug["id"])
        default_list = self.svc.list_clues(self.li, {})
        self.assertEqual(default_list["total"], 1)
        with_merged = self.svc.list_clues(self.li, {"include_merged": "1"})
        self.assertEqual(with_merged["total"], 2)


if __name__ == "__main__":
    unittest.main()
