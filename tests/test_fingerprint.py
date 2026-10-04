"""来源指纹与相似度计算测试。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from clueflow import fingerprint


class FingerprintTest(unittest.TestCase):
    def test_normalize_strips_punctuation_and_case(self):
        self.assertEqual(fingerprint.normalize_text(" 仁爱医院, ABC-123！ "), "仁爱医院abc123")
        self.assertEqual(fingerprint.normalize_text(None), "")

    def test_content_tokens_cjk_bigrams(self):
        tokens = fingerprint.content_tokens("超范围经营")
        self.assertIn("超范", tokens)
        self.assertIn("经营", tokens)
        self.assertNotIn("超范围经", tokens)

    def test_content_tokens_latin_words(self):
        tokens = fingerprint.content_tokens("clinic AB 2026")
        self.assertIn("clinic", tokens)
        self.assertIn("ab", tokens)
        self.assertIn("2026", tokens)

    def test_jaccard(self):
        self.assertEqual(fingerprint.jaccard(set(), {"a"}), 0.0)
        self.assertAlmostEqual(fingerprint.jaccard({"a", "b"}, {"b", "c"}), 1 / 3)

    def test_source_fingerprint_stable_for_same_event(self):
        fp1 = fingerprint.source_fingerprint("投诉", ["USCC-1"], "某机构违规！", "2026-09-28")
        fp2 = fingerprint.source_fingerprint("投诉", ["USCC-1"], "某机构违规", "2026-09-28")
        self.assertEqual(fp1, fp2)  # 标点差异不影响指纹

    def test_source_fingerprint_differs_by_channel_or_subject(self):
        base = fingerprint.source_fingerprint("投诉", ["USCC-1"], "内容", "2026-09-28")
        self.assertNotEqual(base, fingerprint.source_fingerprint("巡查", ["USCC-1"], "内容", "2026-09-28"))
        self.assertNotEqual(base, fingerprint.source_fingerprint("投诉", ["USCC-2"], "内容", "2026-09-28"))

    def test_contact_hash_not_plaintext(self):
        h = fingerprint.contact_hash("138-0000-0000")
        self.assertIsNotNone(h)
        self.assertNotIn("138", h)
        self.assertEqual(h, fingerprint.contact_hash("13800000000"))
        self.assertIsNone(fingerprint.contact_hash(""))

    def test_merge_score_exact_match(self):
        self.assertEqual(fingerprint.merge_score(True, 0.0, 0, 2), 1.0)

    def test_merge_score_weighted(self):
        score = fingerprint.merge_score(False, 0.5, 1, 2)
        self.assertAlmostEqual(score, 0.6 * 0.5 + 0.4 * 0.5, places=3)


if __name__ == "__main__":
    unittest.main()
