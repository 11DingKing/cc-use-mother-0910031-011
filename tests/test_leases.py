"""租约式认领并发控制测试。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from clueflow.errors import LeaseConflict, StateConflict
from support import actor, make_service, register, to_pending


class LeaseTest(unittest.TestCase):
    def setUp(self):
        self.service = make_service()
        self.reg1 = actor(self.service, "u-jian-guan-1")
        self.reg2 = actor(self.service, "u-jian-guan-2")
        result = register(self.service)
        self.case_id = result["case"]["id"]
        to_pending(self.service, self.case_id)

    def test_exclusive_claim(self):
        self.service.claim_case(self.reg1, self.case_id, {})
        with self.assertRaises(LeaseConflict):
            self.service.claim_case(self.reg2, self.case_id, {})

    def test_expired_lease_can_be_reclaimed(self):
        first = self.service.claim_case(self.reg1, self.case_id, {"ttl_seconds": 0})
        self.assertEqual(first["holder_id"], self.reg1.id)
        second = self.service.claim_case(self.reg2, self.case_id, {})
        self.assertEqual(second["holder_id"], self.reg2.id)
        self.assertGreater(second["fencing"], first["fencing"])

    def test_stale_token_rejected_after_reclaim(self):
        first = self.service.claim_case(self.reg1, self.case_id, {"ttl_seconds": 0})
        self.service.claim_case(self.reg2, self.case_id, {})
        with self.assertRaises(LeaseConflict):
            self.service.transition(self.reg1, self.case_id, {
                "action": "verify", "reason": "旧持约人尝试处置",
                "lease_token": first["lease_token"]})

    def test_renew_and_release(self):
        lease = self.service.claim_case(self.reg1, self.case_id, {})
        renewed = self.service.renew_lease(self.reg1, self.case_id, {
            "lease_token": lease["lease_token"], "ttl_seconds": 3600})
        self.assertGreater(renewed["expires_at"], lease["expires_at"])
        self.service.release_lease(self.reg1, self.case_id, {"lease_token": lease["lease_token"]})
        # 释放后他人可认领
        other = self.service.claim_case(self.reg2, self.case_id, {})
        self.assertEqual(other["holder_id"], self.reg2.id)

    def test_claim_not_allowed_in_wrong_state(self):
        result = register(self.service)  # 登记态
        with self.assertRaises(StateConflict):
            self.service.claim_case(self.reg1, result["case"]["id"], {})

    def test_same_holder_reclaim_renews(self):
        first = self.service.claim_case(self.reg1, self.case_id, {})
        second = self.service.claim_case(self.reg1, self.case_id, {"ttl_seconds": 3000})
        self.assertEqual(second["holder_id"], self.reg1.id)
        self.assertGreater(second["fencing"], first["fencing"])


if __name__ == "__main__":
    unittest.main()
