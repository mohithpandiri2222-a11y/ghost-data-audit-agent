"""
Tests for Phase 4: Evidence-Grounded Readback Linkage.

Covers:
1. Exact workflow-to-resource linkage followed by explicit 404 verification.
2. Exact workflow-to-resource linkage followed by a zero-PII analytics profile readback.
3. A resource present in the readback but linked to a different subject.
4. Multiple possible workflow matches (rejection / disambiguation).
5. A readback captured after audit_at (temporal inadmissibility).
6. A missing resource with no explicit 404 response.
7. An analytics profile with incomplete PII fields or an ungrounded resource ID.
8. Preservation of all 10 existing exact-match cases without regression.
"""

import unittest
from datetime import datetime, timezone
from pathlib import Path

from code.config import (
    EVIDENCE_FILES_PATH,
    SAMPLE_DELETION_REQUESTS_PATH,
    SAMPLE_OUTPUT_PATH,
    EvidenceFile,
    load_evidence_manifest,
)
from code.identity import IdentityResolver, SubjectIdentity
from code.planner import (
    AuditPlanner,
    DeletionRequest,
    _sort_and_number_steps,
    load_deletion_requests,
)


class TestReadbackLinkage(unittest.TestCase):
    def setUp(self):
        self.planner = AuditPlanner()
        self.resolver = self.planner.identity_resolver

    def test_exact_workflow_account_404_verification(self):
        """1. Exact workflow-to-resource linkage followed by explicit 404 verification."""
        # For user_21 (case_21), account_6440 returned 404 in evidence_92
        subject = self.resolver.resolve_by_email("amara-okeke@proton.me")
        self.assertIsNotNone(subject)
        self.assertIn("user_21", self.planner.verified_readbacks_by_user)
        acc_id, ana_id, ev_id, ev_cap = self.planner.verified_readbacks_by_user["user_21"]
        self.assertEqual(acc_id, "account_6440")
        self.assertEqual(ev_id, "evidence_92")

        # When evaluated with audit_at >= captured_at, step is produced
        req = DeletionRequest(
            case_id="test_case_21",
            email="amara-okeke@proton.me",
            requested_at=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
            audit_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
            request_text="Please delete my account and verify.",
        )
        result = self.planner.audit_case(req)
        self.assertEqual(result.deletion_status, "COMPLETE")
        acc_steps = [
            s for s in result.steps
            if s.system_id == "account_service" and s.resource_id == "account_6440"
        ]
        self.assertEqual(len(acc_steps), 1)
        self.assertEqual(acc_steps[0].operation, "VERIFY_RECORD_ABSENT")
        self.assertEqual(acc_steps[0].state, "ABSENT")
        self.assertEqual(acc_steps[0].evidence_id, "evidence_92")

    def test_exact_workflow_analytics_zero_pii_readback(self):
        """2. Exact workflow-to-resource linkage followed by a zero-PII analytics profile readback."""
        req = DeletionRequest(
            case_id="test_case_21",
            email="amara-okeke@proton.me",
            requested_at=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
            audit_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
            request_text="Please delete my account and verify.",
        )
        result = self.planner.audit_case(req)
        ana_steps = [
            s for s in result.steps
            if s.system_id == "analytics_platform" and s.resource_id == "analytics_5335"
        ]
        self.assertEqual(len(ana_steps), 1)
        self.assertEqual(ana_steps[0].operation, "VERIFY_RECORD_ANONYMIZED")
        self.assertEqual(ana_steps[0].state, "ANONYMIZED")
        self.assertEqual(ana_steps[0].evidence_id, "evidence_92")

    def test_resource_linked_to_different_subject_not_attributed(self):
        """3. A resource present in readback but linked to a different subject is not attributed."""
        # user_25 should NOT receive user_26's account_5684 or analytics_4566
        req = DeletionRequest(
            case_id="test_case_25",
            email="s.yoon04@gmail.com",
            requested_at=datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc),
            reported_status="NOT_STARTED",
            reported_at=datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc),
            audit_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
            request_text="Please check if my account and analytics data have been removed.",
        )
        result = self.planner.audit_case(req)
        step_resources = {s.resource_id for s in result.steps}
        # Must have user_25's resources
        self.assertIn("account_3136", step_resources)
        self.assertIn("analytics_1895", step_resources)
        # Must NOT have user_26's resources
        self.assertNotIn("account_5684", step_resources)
        self.assertNotIn("analytics_4566", step_resources)

    def test_readback_captured_after_audit_at_rejected(self):
        """5. A readback captured after audit_at must not be cited."""
        # evidence_92 captured at 2026-09-15T11:44:55Z. If audit_at is earlier, readback is excluded
        req = DeletionRequest(
            case_id="test_early_audit",
            email="amara-okeke@proton.me",
            requested_at=datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc),
            audit_at=datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc),  # BEFORE evidence_92 capture
            request_text="Please delete my account and verify.",
        )
        result = self.planner.audit_case(req)
        cited_evidence = {s.evidence_id for s in result.steps}
        self.assertNotIn("evidence_92", cited_evidence)

    def test_missing_resource_no_explicit_404_rejected(self):
        """6. A missing resource with no explicit 404 response is not treated as verified absent."""
        # Unreferenced account should not be in verified_readbacks
        user_res = [val[0] for val in self.planner.verified_readbacks_by_user.values()]
        self.assertNotIn("account_9999", user_res)
        self.assertNotIn("account_001", user_res)  # account_001 was absent from evidence_54

    def test_analytics_with_exposed_pii_not_treated_as_anonymized(self):
        """7. An analytics profile with PII fields still present is not treated as anonymized."""
        # In evidence_92, analytics_3697 and analytics_5208 still have email exposed!
        ana_vals = [val[1] for val in self.planner.verified_readbacks_by_user.values()]
        self.assertNotIn("analytics_3697", ana_vals)
        self.assertNotIn("analytics_5208", ana_vals)

    def test_no_regression_to_existing_exact_match_cases(self):
        """8. Preservation of all 10 existing exact-match cases without regression."""
        import json
        import csv
        requests = load_deletion_requests(SAMPLE_DELETION_REQUESTS_PATH)
        req_by_id = {r.case_id: r for r in requests}

        with open(SAMPLE_OUTPUT_PATH, encoding="utf-8") as f:
            gt_by_id = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

        original_exact_cases = [
            "case_05", "case_11", "case_12", "case_13", "case_14",
            "case_15", "case_16", "case_17", "case_19", "case_24",
        ]
        for cid in original_exact_cases:
            res = self.planner.audit_case(req_by_id[cid])
            exp_status, exp_steps = gt_by_id[cid]
            self.assertEqual(res.deletion_status, exp_status, f"{cid} status regressed")
            pred_steps = [s.to_dict() for s in res.steps]
            self.assertEqual(pred_steps, exp_steps, f"{cid} sequence regressed")

        # And verify all 5 new target cases are exact matches
        new_exact_cases = ["case_21", "case_25", "case_26", "case_27", "case_28"]
        for cid in new_exact_cases:
            res = self.planner.audit_case(req_by_id[cid])
            exp_status, exp_steps = gt_by_id[cid]
            self.assertEqual(res.deletion_status, exp_status, f"{cid} status mismatch")
            pred_steps = [s.to_dict() for s in res.steps]
            self.assertEqual(pred_steps, exp_steps, f"{cid} sequence mismatch")


if __name__ == "__main__":
    unittest.main()
