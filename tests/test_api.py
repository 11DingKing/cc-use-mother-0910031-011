"""HTTP 接口与并发租约测试（真实 ThreadingHTTPServer）。"""
from __future__ import annotations

import concurrent.futures
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from violation_triage.api import make_server
from violation_triage.app import seed
from violation_triage.config import Settings
from violation_triage.risk import DEFAULT_RULES
from violation_triage.service import TriageService


class ApiTestBase(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["TRIAGE_QUIET"] = "1"
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        settings = Settings(db_path=self.tmp.name, host="127.0.0.1", port=0, lease_seconds=3600)
        service = TriageService(settings.db_path, lease_seconds=settings.lease_seconds)
        seed(service)
        self.httpd = make_server(settings, service)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.tokens = {
            name: self.login(name, pwd)
            for name, pwd in {
                "admin": "admin123", "inspector": "inspect123", "expert": "expert123",
                "officer": "officer123", "practitioner": "pract123",
            }.items()
        }

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        Path(self.tmp.name).unlink(missing_ok=True)

    def call(self, method: str, path: str, role: str | None = None, body: dict | None = None):
        if "?" in path:
            from urllib.parse import parse_qsl, urlencode, urlsplit

            parts = urlsplit(path)
            path = parts.path + "?" + urlencode(parse_qsl(parts.query))
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if role:
            headers["Authorization"] = f"Bearer {self.tokens[role]}"
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8")
        conn.close()
        return resp.status, json.loads(raw) if raw else {}

    def login(self, username: str, password: str) -> str:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/auth/login",
                     body=json.dumps({"username": username, "password": password}).encode(),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        return data["token"]

    def register_clue(self, role: str = "inspector", **overrides) -> dict:
        body = {
            "source_channel": "巡查",
            "title": "某机构涉嫌伪造材料套取资金",
            "description": "疑似伪造虚报",
            "occurrence_at": "2026-10-02T09:00:00Z",
            "region": "城北区",
            "subject_type": "机构",
            "subject_name": "测试机构",
            "subject_identifier": "91330100ma0000077x",
            "evidences": [{"label": "现场笔录", "content_ref": "oss://e/1", "sensitivity": "敏感"}],
        }
        body.update(overrides)
        status, data = self.call("POST", "/api/clues", role, body)
        assert status in (200, 201), data
        return data


class HttpAuthTest(ApiTestBase):
    def test_health_and_roles(self) -> None:
        status, data = self.call("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(data["product"], "违规线索分流处置")
        status, data = self.call("GET", "/api/roles", "admin")
        self.assertEqual(status, 200)
        self.assertEqual(data["role_max_sensitivity"]["机构合规员"], "普通")

    def test_missing_and_bad_token(self) -> None:
        self.assertEqual(self.call("GET", "/api/clues")[0], 401)
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/api/clues", headers={"Authorization": "Bearer nonsense"})
        self.assertEqual(conn.getresponse().status, 401)

    def test_unknown_route(self) -> None:
        self.assertEqual(self.call("GET", "/api/nope", "admin")[0], 404)

    def test_bad_json(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("POST", "/api/auth/login", body=b"{not json", headers={"Content-Type": "application/json"})
        self.assertEqual(conn.getresponse().status, 400)


class HttpTriageFlowTest(ApiTestBase):
    def _triage_ready(self):
        clue = self.register_clue()
        cid = clue["clue_id"]
        status, _ = self.call("POST", f"/api/clues/{cid}/priority", "admin",
                              {"priority": "紧急", "reason": "欺诈风险高"})
        self.assertEqual(status, 200)
        return cid

    def test_register_scores_and_suggests(self) -> None:
        clue = self.register_clue()
        self.assertEqual(clue["suggested_priority"], "紧急")
        self.assertGreater(clue["risk_score"], 0)

    def test_evidence_redacted_by_role_over_http(self) -> None:
        cid = self.register_clue()["clue_id"]
        status, officer = self.call("GET", f"/api/clues/{cid}", "officer")
        self.assertTrue(officer["evidences"][0]["redacted"])
        self.assertNotIn("content_ref", officer["evidences"][0])
        status, inspector = self.call("GET", f"/api/clues/{cid}", "inspector")
        self.assertFalse(inspector["evidences"][0]["redacted"])

    def test_rbac_enforced_over_http(self) -> None:
        cid = self.register_clue()["clue_id"]
        self.assertEqual(self.call("POST", f"/api/clues/{cid}/priority", "officer", {"priority": "高"})[0], 403)
        self.assertEqual(self.call("POST", f"/api/clues/{cid}/claim", "practitioner")[0], 403)

    def test_full_lifecycle_with_audit(self) -> None:
        cid = self._triage_ready()
        self.assertEqual(self.call("POST", f"/api/clues/{cid}/claim", "inspector")[0], 200)
        self.assertEqual(self.call("POST", f"/api/clues/{cid}/verify", "inspector", {"note": "核验通过"})[0], 200)
        m = self.call("POST", f"/api/clues/{cid}/measures", "inspector",
                      {"measure_type": "暂停结算", "detail": "止损"})
        measure_id = m[1]["measure_id"]
        # 生效措施阻止结案
        self.assertEqual(
            self.call("POST", f"/api/clues/{cid}/close", "admin",
                      {"decision": "责令整改", "summary": "完成"})[0], 409)
        self.assertEqual(self.call("POST", f"/api/measures/{measure_id}/lift", "admin",
                                   {"reason": "风险解除"})[0], 200)
        self.assertEqual(self.call("POST", f"/api/clues/{cid}/close", "admin",
                                   {"decision": "责令整改", "summary": "完成"})[0], 200)
        self.assertEqual(self.call("POST", f"/api/clues/{cid}/archive", "admin")[0], 200)
        status, reopened = self.call("POST", f"/api/clues/{cid}/reopen", "admin", {"reason": "新投诉"})
        self.assertEqual(status, 200)
        self.assertEqual(reopened["state"], "处置中")

        status, audits = self.call("GET", f"/api/audit?clue={cid}", "inspector")
        actions = [a["action"] for a in audits["items"]]
        self.assertIn("clue.register", actions)
        self.assertIn("clue.close", actions)
        self.assertIn("clue.reopen", actions)
        # 审计条目展示分流理由
        close_log = next(a for a in audits["items"] if a["action"] == "clue.close")
        self.assertIn("完成", close_log["reason"])

    def test_merge_confirm_over_http(self) -> None:
        first = self.register_clue(source_ref="X-1", title="某机构涉嫌伪造材料套取资金")
        second = self.register_clue(
            source_channel="机构自报", source_ref="X-2",
            title="测试机构伪造材料套取资金自查报告")
        status, pending = self.call("GET", "/api/merge-suggestions?status=待确认", "admin")
        self.assertEqual(status, 200)
        sug = next(s for s in pending["items"]
                   if s["duplicate_clue_id"] == second["clue_id"] and s["primary_clue_id"] == first["clue_id"])
        # 建议先于确认存在
        self.assertEqual(sug["status"], "待确认")
        self.assertEqual(
            self.call("POST", f"/api/merge-suggestions/{sug['id']}/confirm", "officer",
                      {"reason": "同事件"})[0], 403)
        status, _ = self.call("POST", f"/api/merge-suggestions/{sug['id']}/confirm", "admin",
                              {"reason": "确属同一事件多渠道登记"})
        self.assertEqual(status, 200)
        status, dup = self.call("GET", f"/api/clues/{second['clue_id']}", "inspector")
        self.assertEqual(dup["state"], "已归档")
        self.assertEqual(dup["merged_into"]["clue_id"], first["clue_id"])

    def test_extension_workflow(self) -> None:
        cid = self._triage_ready()
        self.call("POST", f"/api/clues/{cid}/claim", "inspector")
        self.call("POST", f"/api/clues/{cid}/verify", "inspector")
        status, req = self.call("POST", f"/api/clues/{cid}/extensions", "inspector",
                                {"hours": 48, "reason": "等待检验报告"})
        self.assertEqual(status, 201)
        status, decision = self.call("POST", f"/api/extensions/{req['extension_id']}/decision",
                                     "admin", {"approve": True, "comment": "同意"})
        self.assertEqual(status, 200)
        self.assertEqual(decision["status"], "已批准")

    def test_split_over_http(self) -> None:
        cid = self._triage_ready()
        self.call("POST", f"/api/clues/{cid}/claim", "inspector")
        self.call("POST", f"/api/clues/{cid}/verify", "inspector")
        status, out = self.call("POST", f"/api/clues/{cid}/split", "admin",
                                {"children": [{"title": "子线索A"}, {"title": "子线索B"}]})
        self.assertEqual(status, 201)
        self.assertEqual(len(out["children"]), 2)
        status, parent = self.call("GET", f"/api/clues/{cid}", "admin")
        self.assertEqual(len(parent["children"]), 2)


class ConcurrentClaimTest(ApiTestBase):
    def test_only_one_claim_wins(self) -> None:
        clue = self.register_clue()
        cid = clue["clue_id"]
        self.call("POST", f"/api/clues/{cid}/priority", "admin", {"priority": "特急", "reason": "重大"})

        roles = ["inspector", "expert", "admin"] * 4  # 12 个并发认领

        def claim(role: str):
            return self.call("POST", f"/api/clues/{cid}/claim", role)

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(claim, roles))

        successes = [r for r in results if r[0] == 200]
        conflicts = [r for r in results if r[0] == 409]
        self.assertEqual(len(successes), 1, results)
        self.assertEqual(len(conflicts), 11)

        status, detail = self.call("GET", f"/api/clues/{cid}", "admin")
        self.assertIsNotNone(detail["lease"])

    def test_concurrent_registration_same_fingerprint_is_idempotent(self) -> None:
        body = {
            "source_channel": "投诉", "source_ref": "DUP-1",
            "title": "并发重复登记事件", "description": "",
            "occurrence_at": "2026-10-02T10:00:00Z", "region": "城东区",
            "subject_type": "机构", "subject_name": "并发机构",
            "subject_identifier": "91330100ma0000066z", "evidences": [],
        }

        def register(_):
            return self.call("POST", "/api/clues", "inspector", body)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(register, range(8)))
        ids = {r[1]["clue_id"] for r in results if r[0] in (200, 201)}
        self.assertEqual(len(ids), 1, results)


if __name__ == "__main__":
    unittest.main()
