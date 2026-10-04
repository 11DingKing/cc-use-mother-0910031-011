"""风险规则引擎单元测试。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from violation_triage.risk import evaluate, score_band


class RiskEngineTest(unittest.TestCase):
    def test_comparisons(self) -> None:
        facts = {"channel": "巡查", "score": 65, "text": "涉嫌伪造病历骗取医保"}
        self.assertTrue(evaluate({"field": "channel", "op": "==", "value": "巡查"}, facts))
        self.assertTrue(evaluate({"field": "channel", "op": "in", "value": ["巡查", "投诉"]}, facts))
        self.assertFalse(evaluate({"field": "channel", "op": "not_in", "value": ["巡查"]}, facts))
        self.assertTrue(evaluate({"field": "score", "op": ">=", "value": 60}, facts))
        self.assertFalse(evaluate({"field": "score", "op": "<", "value": 60}, facts))
        self.assertTrue(evaluate({"field": "text", "op": "contains_any", "value": ["伪造", "中毒"]}, facts))
        self.assertFalse(evaluate({"field": "text", "op": "contains_any", "value": ["中毒"]}, facts))

    def test_boolean_combinators(self) -> None:
        facts = {"a": 1, "b": 2}
        cond = {"all": [{"field": "a", "op": "==", "value": 1}, {"field": "b", "op": "==", "value": 2}]}
        self.assertTrue(evaluate(cond, facts))
        self.assertTrue(evaluate({"any": [{"field": "a", "op": "==", "value": 9}, {"field": "b", "op": "==", "value": 2}]}, facts))
        self.assertTrue(evaluate({"not": {"field": "a", "op": "==", "value": 9}}, facts))

    def test_missing_field_is_not_equal(self) -> None:
        self.assertFalse(evaluate({"field": "nope", "op": "==", "value": 1}, {}))

    def test_bad_operator_raises(self) -> None:
        with self.assertRaises(ValueError):
            evaluate({"field": "a", "op": "exec", "value": "1"}, {"a": 1})

    def test_score_band(self) -> None:
        self.assertEqual(score_band(85), "特急")
        self.assertEqual(score_band(65), "紧急")
        self.assertEqual(score_band(45), "高")
        self.assertEqual(score_band(25), "中")
        self.assertEqual(score_band(5), "低")


if __name__ == "__main__":
    unittest.main()
