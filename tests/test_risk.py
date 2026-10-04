"""风险规则引擎测试。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from clueflow import risk


def rule(rid, kind, params, points, enabled=1):
    return {"id": rid, "name": rid, "kind": kind, "params": params, "points": points, "enabled": enabled}


class RiskTest(unittest.TestCase):
    def test_level_thresholds(self):
        self.assertEqual(risk.level_for_score(0), "低")
        self.assertEqual(risk.level_for_score(24), "低")
        self.assertEqual(risk.level_for_score(25), "中")
        self.assertEqual(risk.level_for_score(45), "高")
        self.assertEqual(risk.level_for_score(70), "紧急")
        self.assertEqual(risk.level_for_score(100), "紧急")

    def test_keyword_rule(self):
        rules = [rule("R1", "keyword", {"words": ["非法集资", "传销"]}, 40)]
        ctx = risk.AssessmentContext(contents=["该机构涉嫌非法集资活动"])
        score, hits = risk.evaluate(rules, ctx)
        self.assertEqual(score, 40)
        self.assertEqual(len(hits), 1)
        self.assertIn("非法集资", hits[0].detail)

    def test_channel_and_multi_source(self):
        rules = [
            rule("R1", "channel", {"channel": "巡查"}, 10),
            rule("R2", "multi_source", {"min_clues": 2}, 15),
        ]
        ctx = risk.AssessmentContext(channels={"巡查", "投诉"}, clue_count=3)
        score, hits = risk.evaluate(rules, ctx)
        self.assertEqual(score, 25)
        self.assertEqual(len(hits), 2)

    def test_sensitive_evidence_and_recidivism(self):
        rules = [
            rule("R1", "sensitive_evidence", {"min_level": 3}, 15),
            rule("R2", "recidivism", {}, 20),
        ]
        ctx = risk.AssessmentContext(max_sensitivity=4, recidivist_subjects=["仁爱医院"])
        score, hits = risk.evaluate(rules, ctx)
        self.assertEqual(score, 35)
        self.assertIn("仁爱医院", hits[1].detail)

    def test_disabled_rule_ignored_and_score_capped(self):
        rules = [
            rule("R1", "keyword", {"words": ["无证"]}, 90, enabled=0),
            rule("R2", "keyword", {"words": ["无证"]}, 90),
            rule("R3", "channel", {"channel": "投诉"}, 50),
        ]
        ctx = risk.AssessmentContext(channels={"投诉"}, contents=["无证行医"])
        score, hits = risk.evaluate(rules, ctx)
        self.assertEqual(score, 100)  # 90+50 封顶 100，且停用规则不计
        self.assertEqual(len(hits), 2)


if __name__ == "__main__":
    unittest.main()
