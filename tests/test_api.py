"""端到端 API 测试：真实 HTTP 服务 + 完整业务流。"""
from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from clueflow.api import create_server
from clueflow.services import ClueflowService
from clueflow.store import Store

REG1 = "u-jian-guan-1"
REG2 = "u-jian-guan-2"
EXPERT = "u-expert-1"
COMPLIANCE = "u-heliang"


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = ClueflowService(Store(":memory:"))
        cls.server = create_server(cls.service, "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def call(self, method, path, actor=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if actor:
            headers["X-Actor-Id"] = actor
        conn.request(method, path, body=json.dumps(body or {}, ensure_ascii=False).encode("utf-8"),
                     headers=headers)
        resp = conn.getresponse()
        payload = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return resp.status, payload

    def _register(self, actor=REG1, **overrides):
        data = {
            "channel": "投诉",
            "title": "仁爱医院涉嫌违规执业",
            "content": "群众反映仁爱医院存在超范围经营问题",
            "event_date": "2026-09-28",
            "subjects": [
                {"type": "机构", "name": "仁爱医院", "identifier": "USCC-100", "org_id": "org-hospital-1"}
            ],
        }
        data.update(overrides)
        return self.call("POST", "/clues", actor, data)

    # ---------- 基础 ----------
    def test_public_endpoints(self):
        status, body = self.call("GET", "/health")
        self.assertEqual(status, 200)
        status, body = self.call("GET", "/meta")
        self.assertEqual(status, 200)
        self.assertIn("处置中", body["states"])
        status, body = self.call("GET", "/actors")
        self.assertEqual(status, 200)
        self.assertTrue(any(a["id"] == REG1 for a in body["items"]))

    def test_auth_required(self):
        status, body = self.call("GET", "/cases")
        self.assertEqual(status, 401)
        status, body = self.call("GET", "/cases", actor="no-such-user")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "UNAUTHORIZED")

    def test_unknown_route_404(self):
        status, _ = self.call("GET", "/nope", actor=REG1)
        self.assertEqual(status, 404)

    def test_role_channel_restriction(self):
        status, body = self._register(actor=COMPLIANCE, channel="投诉")
        self.assertEqual(status, 403)
        status, body = self._register(actor=COMPLIANCE, channel="机构自报")
        self.assertEqual(status, 201)
        self.assertEqual(body["clue"]["channel"], "机构自报")

    # ---------- 全流程 ----------
    def test_full_workflow(self):
        # 1. 多渠道登记同一事件 → 自动合并建议
        status, first = self._register()
        self.assertEqual(status, 201)
        case_a = first["case"]["id"]
        self.assertEqual(first["case"]["state"], "登记")
        self.assertEqual(first["priority_assessment"]["status"], "待确认")

        status, second = self._register(
            channel="巡查",
            title="仁爱医院超范围经营巡查发现",
            content="巡查发现仁爱医院存在超范围经营问题，群众反映属实",
        )
        self.assertEqual(status, 201)
        case_b = second["case"]["id"]
        self.assertEqual(len(second["merge_suggestions"]), 1)
        sid = second["merge_suggestions"][0]["id"]

        # 2. 未授权角色不能确认合并
        status, _ = self.call("POST", f"/merge-suggestions/{sid}/confirm", COMPLIANCE, {"reason": "越权"})
        self.assertEqual(status, 403)
        # 3. 复核专家确认合并
        status, merged = self.call("POST", f"/merge-suggestions/{sid}/confirm", EXPERT,
                                   {"reason": "同一事件多渠道重复登记"})
        self.assertEqual(status, 200)
        self.assertEqual(merged["source_case"]["state"], "已归档")
        self.assertEqual(len(merged["target_case"]["clues"]), 2)

        # 4. 确认优先级（提级）
        status, view = self.call("POST", f"/cases/{case_a}/priority/confirm", EXPERT,
                                 {"accept": False, "level": "高", "reason": "涉及诊疗安全"})
        self.assertEqual(status, 200)
        self.assertEqual(view["priority"], "高")
        self.assertEqual(view["priority_status"], "已确认")

        # 5. 分流 → 认领 → 核验
        status, view = self.call("POST", f"/cases/{case_a}/transitions", REG1,
                                 {"action": "triage", "reason": "分流至执法一队", "assignee_id": REG1})
        self.assertEqual(status, 200)
        self.assertEqual(view["state"], "待核验")
        status, lease = self.call("POST", f"/cases/{case_a}/claim", REG1, {"ttl_seconds": 1800})
        self.assertEqual(status, 200)
        token = lease["lease_token"]
        # 租约互斥
        status, conflict = self.call("POST", f"/cases/{case_a}/claim", REG2, {})
        self.assertEqual(status, 409)
        self.assertEqual(conflict["error"]["code"], "LEASE_CONFLICT")
        # 无租约不能核验
        status, nolease = self.call("POST", f"/cases/{case_a}/transitions", REG1,
                                    {"action": "verify", "reason": "无租约"})
        self.assertEqual(status, 409)
        self.assertEqual(nolease["error"]["code"], "LEASE_REQUIRED")
        status, view = self.call("POST", f"/cases/{case_a}/transitions", REG1,
                                 {"action": "verify", "reason": "核验属实", "lease_token": token})
        self.assertEqual(view["state"], "处置中")

        # 6. 临时措施阻止归档
        status, measure = self.call("POST", f"/cases/{case_a}/measures", REG1,
                                    {"type": "封存证据", "reason": "防止灭失", "lease_token": token})
        self.assertEqual(status, 201)
        status, view = self.call("POST", f"/cases/{case_a}/transitions", REG1,
                                 {"action": "decide", "reason": "事实清楚", "decision": "立案查处",
                                  "lease_token": token})
        self.assertEqual(view["state"], "已决定")
        status, blocked = self.call("POST", f"/cases/{case_a}/transitions", REG1,
                                    {"action": "archive", "reason": "归档"})
        self.assertEqual(status, 422)
        status, _ = self.call("POST", f"/cases/{case_a}/measures/{measure['id']}/lift", REG1,
                              {"reason": "证据已固定", "lease_token": token})
        self.assertEqual(status, 200)
        status, view = self.call("POST", f"/cases/{case_a}/transitions", REG1,
                                 {"action": "archive", "reason": "办结归档"})
        self.assertEqual(view["state"], "已归档")

        # 7. 结案复开：监管无权，复核专家可复开
        status, _ = self.call("POST", f"/cases/{case_a}/transitions", REG1,
                              {"action": "reopen", "reason": "监管复开"})
        self.assertEqual(status, 403)
        status, view = self.call("POST", f"/cases/{case_a}/transitions", EXPERT,
                                 {"action": "reopen", "reason": "出现新证据"})
        self.assertEqual(status, 200)
        self.assertEqual(view["state"], "处置中")
        self.assertEqual(view["reopened_count"], 1)

        # 8. 复开后重新认领并申请延期
        status, lease = self.call("POST", f"/cases/{case_a}/claim", REG1, {})
        token = lease["lease_token"]
        status, ext = self.call("POST", f"/cases/{case_a}/extensions", REG1,
                                {"days": 5, "reason": "延伸调查", "lease_token": token})
        self.assertEqual(status, 201)
        due_before = self.call("GET", f"/cases/{case_a}", REG1)[1]["due_at"]
        status, decided = self.call("POST", f"/cases/{case_a}/extensions/{ext['id']}/decide", EXPERT,
                                    {"approve": True, "reason": "同意"})
        self.assertEqual(status, 200)
        due_after = self.call("GET", f"/cases/{case_a}", REG1)[1]["due_at"]
        self.assertGreater(due_after, due_before)

        # 9. 证据按角色裁剪
        status, _ = self.call("POST", f"/cases/{case_a}/evidence", REG1,
                              {"kind": "书证", "content": "机密账本原文", "sensitivity": 4,
                               "lease_token": token})
        self.assertEqual(status, 201)
        _, expert_ev = self.call("GET", f"/cases/{case_a}/evidence", EXPERT)
        self.assertTrue(any(i["content"] == "机密账本原文" for i in expert_ev["items"]))
        _, reg_ev = self.call("GET", f"/cases/{case_a}/evidence", REG1)
        secret = next(i for i in reg_ev["items"] if i["sensitivity"] == 4)
        self.assertTrue(secret["redacted"])
        self.assertNotIn("机密账本原文", secret["content"])
        _, com_ev = self.call("GET", f"/cases/{case_a}/evidence", COMPLIANCE)
        self.assertEqual(com_ev["hidden_count"], 1)
        self.assertFalse(any(i["sensitivity"] == 4 for i in com_ev["items"]))

        # 10. 审计轨迹完整且含分流理由
        status, audit = self.call("GET", f"/cases/{case_a}/audit", REG1)
        self.assertEqual(status, 200)
        actions = [e["action"] for e in audit["items"]]
        for expected in ("登记线索", "风险初评", "并入线索", "确认优先级", "状态流转:triage",
                         "认领案件", "状态流转:verify", "采取临时措施", "解除临时措施",
                         "状态流转:decide", "状态流转:archive", "状态流转:reopen", "审批延期"):
            self.assertIn(expected, actions)
        triage = next(e for e in audit["items"] if e["action"] == "状态流转:triage")
        self.assertEqual(triage["reason"], "分流至执法一队")

        # 11. 来源案件（已并入）也有完整轨迹
        _, audit_b = self.call("GET", f"/cases/{case_b}/audit", REG1)
        self.assertIn("合并关闭", [e["action"] for e in audit_b["items"]])

    def test_list_cases_filters(self):
        self._register(title="过滤测试专用案件-甲")
        query = urllib.parse.urlencode({"state": "登记", "q": "过滤测试专用案件"})
        status, body = self.call("GET", f"/cases?{query}", REG1)
        self.assertEqual(status, 200)
        self.assertTrue(any("过滤测试专用案件" in i["title"] for i in body["items"]))
        query = urllib.parse.urlencode({"state": "已归档", "q": "过滤测试专用案件"})
        status, body = self.call("GET", f"/cases?{query}", REG1)
        self.assertEqual(body["total"], 0)

    def test_invalid_json_body(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/clues", body="{not json", headers={
            "Content-Type": "application/json", "X-Actor-Id": REG1})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        conn.close()


if __name__ == "__main__":
    unittest.main()
