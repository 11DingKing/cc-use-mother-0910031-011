"""按角色裁剪证据与敏感字段测试。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from clueflow import redaction


def ev(level):
    return {
        "id": f"EVD-{level}",
        "case_id": "CAS-1",
        "kind": "书证",
        "filename": None,
        "content": "敏感内容原文",
        "sensitivity": level,
        "sha256": "x" * 64,
        "uploaded_by": "u-jian-guan-1",
        "created_at": "2026-10-01T00:00:00+00:00",
    }


class RedactionTest(unittest.TestCase):
    def test_expert_sees_everything(self):
        views, hidden = redaction.redact_evidence_list("复核专家", [ev(1), ev(2), ev(3), ev(4)])
        self.assertEqual(hidden, 0)
        self.assertEqual(len(views), 4)
        self.assertTrue(all(not v["redacted"] for v in views))

    def test_regulator_level4_masked(self):
        view = redaction.evidence_view("监管人员", ev(4))
        self.assertIsNotNone(view)
        self.assertTrue(view["redacted"])
        self.assertNotIn("敏感内容原文", view["content"])
        view3 = redaction.evidence_view("监管人员", ev(3))
        self.assertFalse(view3["redacted"])

    def test_compliance_officer_level4_hidden(self):
        views, hidden = redaction.redact_evidence_list("机构合规员", [ev(1), ev(2), ev(3), ev(4)])
        self.assertEqual(hidden, 1)
        by_level = {v["sensitivity"]: v for v in views}
        self.assertFalse(by_level[2]["redacted"])
        self.assertTrue(by_level[3]["redacted"])

    def test_practitioner_only_public_full(self):
        views, hidden = redaction.redact_evidence_list("执业人员", [ev(1), ev(2), ev(3), ev(4)])
        self.assertEqual(hidden, 2)
        by_level = {v["sensitivity"]: v for v in views}
        self.assertFalse(by_level[1]["redacted"])
        self.assertTrue(by_level[2]["redacted"])

    def test_subject_identifier_masked_for_low_clearance(self):
        subj = {"id": "SUB-1", "type": "机构", "name": "仁爱医院", "identifier": "USCC-91330100", "org_id": "o1"}
        full = redaction.subject_view("监管人员", subj)
        self.assertEqual(full["identifier"], "USCC-91330100")
        masked = redaction.subject_view("执业人员", subj)
        self.assertNotEqual(masked["identifier"], "USCC-91330100")
        self.assertTrue(masked["identifier"].endswith("00"))
        self.assertIn("▓", masked["identifier"])

    def test_reporter_privacy(self):
        clue = {"reporter_name": "张三", "reporter_contact_hash": "abc", "anonymous": 0}
        self.assertEqual(redaction.reporter_view("复核专家", clue)["name"], "张三")
        self.assertNotEqual(redaction.reporter_view("执业人员", clue)["name"], "张三")
        anon = {**clue, "anonymous": 1}
        self.assertEqual(redaction.reporter_view("复核专家", anon)["name"], "匿名")
        # 联系方式不出接口
        self.assertNotIn("contact", redaction.reporter_view("复核专家", clue))


if __name__ == "__main__":
    unittest.main()
