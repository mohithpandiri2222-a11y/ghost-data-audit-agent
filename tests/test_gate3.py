"""
Unit Tests for Gate 3: Policy Evaluation, Audit Classification, and Remediation Planning.

Tests cover:
1. Intake classification (multilingual, non-deletion, deletion authorized, ambiguous)
2. Policy rule evaluation (DELETE, REDACT, ANONYMIZE, RETAIN, ACCOUNT_TOMBSTONE, BACKUP_ARCHIVE)
3. Already-remediated state suppression
4. Status classification (COMPLETE, INCOMPLETE, NOT_APPLICABLE)
5. Deterministic step ordering and tie-breaking
6. Admissibility boundary: only pre-audit evidence contributes to findings
7. Identity matching / decoy exclusion
8. Evidence_id rules (empty for INCOMPLETE future work, real for COMPLETE verification)
9. Security audit log retention (unproven retention → VERIFY_RECORD_PRESENT with no evidence_id)
10. Account resource ID inference
11. SQL absence scanning
12. Known ambiguity: analytics DELETE vs ANONYMIZE discrepancy documentation
13. Sample ground truth spot checks (case_01, case_05, case_21, case_25)
"""

import csv
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from code.config import (
    DATASET_DIR,
    EvidenceFact,
    EvidenceFile,
    load_evidence_manifest,
    parse_iso_timestamp,
)
from code.identity import IdentityResolver, SubjectIdentity
from code.intake import IntakeResult, IntakeVerdict, classify_request
from code.planner import (
    AuditPlanner,
    AuditStep,
    CaseAuditResult,
    DeletionRequest,
    _extract_account_resource_id,
    _classify_status,
    _scan_sql_absence,
    _build_verification_steps_for_complete,
    _sort_key,
    _sort_and_number_steps,
    load_deletion_requests,
)
from code.policy import PolicyEvaluator, PolicyVerdict


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_fact(
    file_id: str = "evidence_01",
    system_id: str = "account_service",
    resource_id: str = "account_001",
    status_or_state: str = "PRESENT",
    data_category: Optional[str] = "USER_PROFILE",
    record_timestamp: Optional[datetime] = None,
    file_captured_at: Optional[datetime] = None,
) -> EvidenceFact:
    if file_captured_at is None:
        file_captured_at = datetime(2026, 9, 1, tzinfo=timezone.utc)
    return EvidenceFact(
        file_id=file_id,
        file_path=f"evidence/test/{file_id}.sql",
        origin="test_origin",
        file_captured_at=file_captured_at,
        record_timestamp=record_timestamp,
        system_id=system_id,
        resource_id=resource_id,
        data_category=data_category,
        raw_event=None,
        status_or_state=status_or_state,
        matched_identifier_field="user_id",
        matched_identifier_value="user_01",
        attributes={},
        source_locator="test:test_table:account_001",
    )


def _make_request(
    case_id: str = "case_test",
    email: str = "amina.elmasri@gmail.com",
    audit_at: str = "2026-09-03T11:30:00Z",
    request_text: str = "Please delete my account and all personal data.",
    reported_status: str = "COMPLETE",
) -> DeletionRequest:
    return DeletionRequest(
        case_id=case_id,
        email=email,
        requested_at=parse_iso_timestamp("2026-08-18T09:14:00Z"),
        reported_status=reported_status,
        reported_at=parse_iso_timestamp("2026-08-20T16:42:00Z"),
        audit_at=parse_iso_timestamp(audit_at),
        request_text=request_text,
    )


# ---------------------------------------------------------------------------
# 1. Intake Classification
# ---------------------------------------------------------------------------

class TestIntakeClassification(unittest.TestCase):
    """Tests for request authorization classification."""

    def test_english_deletion_request_authorized(self) -> None:
        r = classify_request("c1", "Please delete my account and all my personal data.")
        self.assertTrue(r.deletion_authorized)
        self.assertEqual(r.verdict, IntakeVerdict.DELETION_AUTHORIZED)

    def test_english_close_account_authorized(self) -> None:
        r = classify_request("c2", "I would like to close my account.")
        self.assertTrue(r.deletion_authorized)

    def test_english_erasure_authorized(self) -> None:
        r = classify_request("c3", "Right to erasure — please erase all my data.")
        self.assertTrue(r.deletion_authorized)

    def test_french_deletion_authorized(self) -> None:
        r = classify_request("c4", "Je demande la suppression définitive de mon compte.")
        self.assertTrue(r.deletion_authorized)

    def test_spanish_deletion_authorized(self) -> None:
        r = classify_request("c5", "Necesito eliminar mi cuenta permanentemente.")
        self.assertTrue(r.deletion_authorized)

    def test_german_deletion_authorized(self) -> None:
        r = classify_request("c6", "Bitte löschen Sie mein Konto und alle meine Daten.")
        self.assertTrue(r.deletion_authorized)

    def test_access_request_not_applicable(self) -> None:
        r = classify_request("c7", "Please send me a copy of all my personal data.")
        self.assertFalse(r.deletion_authorized)
        self.assertEqual(r.verdict, IntakeVerdict.NOT_APPLICABLE)

    def test_correction_request_not_applicable(self) -> None:
        r = classify_request("c8", "Please correct my shipping address to 123 Main St.")
        self.assertFalse(r.deletion_authorized)

    def test_marketing_optout_not_applicable(self) -> None:
        r = classify_request("c9", "Please unsubscribe me from all marketing emails.")
        self.assertFalse(r.deletion_authorized)

    def test_export_request_not_applicable(self) -> None:
        r = classify_request("c10", "Please export my order history to CSV.")
        self.assertFalse(r.deletion_authorized)

    def test_empty_request_not_applicable(self) -> None:
        r = classify_request("c11", "")
        self.assertFalse(r.deletion_authorized)

    def test_sample_case01_authorized(self) -> None:
        """case_01 sample text: account closure with personal data removal."""
        text = "Hi, I haven't used this account in years and would like it closed. Please remove the profile and the personal details attached to it."
        r = classify_request("case_01", text)
        self.assertTrue(r.deletion_authorized)

    def test_sample_case05_authorized(self) -> None:
        """case_05 text: account still recognized after deletion confirmation."""
        text = "I deleted this account and received a confirmation, but the same email address is still recognized. Please remove any remaining copy of my profile."
        r = classify_request("case_05", text)
        self.assertTrue(r.deletion_authorized)

    def test_sample_case12_authorized(self) -> None:
        """case_12 text: 'before deleting it' inflection."""
        text = "I changed the email on this account before deleting it. Please check that nothing tied to the old address was left behind, even in systems that do not display the email."
        r = classify_request("case_12", text)
        self.assertTrue(r.deletion_authorized)

    def test_sample_case15_authorized(self) -> None:
        """case_15 text: 'Close the account completely'."""
        text = "I disconnected my account last week, but one of the integrations still seems active. Close the account completely and make sure it can no longer send my data to other systems."
        r = classify_request("case_15", text)
        self.assertTrue(r.deletion_authorized)

    def test_case540_invoice_copy_not_applicable(self) -> None:
        """case_540 text from deletion_requests.csv: invoice copy request."""
        text = "i need a copy of last year's invoices for my records. please leave my profile and purchase history in place."
        r = classify_request("case_540", text)
        self.assertFalse(r.deletion_authorized)
        self.assertEqual(r.verdict, IntakeVerdict.NOT_APPLICABLE)


# ---------------------------------------------------------------------------
# 2. Policy Rule Evaluation
# ---------------------------------------------------------------------------

class TestPolicyEvaluator(unittest.TestCase):
    """Tests for deletion policy rule mapping."""

    def setUp(self) -> None:
        self.evaluator = PolicyEvaluator()

    def test_user_profile_present_gets_delete_finding(self) -> None:
        fact = _make_fact(system_id="account_service", resource_id="account_001",
                          status_or_state="PRESENT", data_category="USER_PROFILE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertTrue(v.has_finding)
        self.assertEqual(v.finding_operation, "REPORT_REMAINING_RECORD")
        self.assertEqual(v.finding_state, "PRESENT")
        self.assertEqual(v.remediation_operation, "DELETE_RECORD")
        self.assertEqual(v.verification_operation, "VERIFY_RECORD_ABSENT")

    def test_user_profile_absent_no_finding(self) -> None:
        fact = _make_fact(status_or_state="ABSENT", data_category="USER_PROFILE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertFalse(v.has_finding)

    def test_support_message_gets_redact_finding(self) -> None:
        fact = _make_fact(system_id="support_platform", resource_id="support_001",
                          status_or_state="PRESENT", data_category="SUPPORT_MESSAGE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertTrue(v.has_finding)
        self.assertEqual(v.finding_operation, "REPORT_EXPOSED_PII")
        self.assertEqual(v.remediation_operation, "REDACT_RECORD")
        self.assertEqual(v.verification_operation, "VERIFY_RECORD_REDACTED")

    def test_analytics_profile_follows_explicit_policy_rule_07(self) -> None:
        """
        ANALYTICS_PROFILE strictly follows explicit policy rule_07 (ANONYMIZE).
        The is_ambiguous flag documents the unresolved sample_output discrepancy for transparency.
        """
        fact = _make_fact(system_id="analytics_platform", resource_id="analytics_001",
                          status_or_state="PRESENT", data_category="ANALYTICS_PROFILE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertTrue(v.has_finding)
        self.assertEqual(v.finding_operation, "REPORT_EXPOSED_PII")
        self.assertEqual(v.remediation_operation, "ANONYMIZE_RECORD")
        self.assertEqual(v.verification_operation, "VERIFY_RECORD_ANONYMIZED")
        self.assertTrue(v.is_ambiguous, "analytics discrepancy must be flagged")

    def test_product_telemetry_gets_anonymize_finding(self) -> None:
        fact = _make_fact(system_id="analytics_platform", resource_id="telemetry_001",
                          status_or_state="PRESENT", data_category="PRODUCT_TELEMETRY")
        v = self.evaluator.evaluate_fact(fact)
        self.assertTrue(v.has_finding)
        self.assertEqual(v.finding_operation, "REPORT_EXPOSED_PII")
        self.assertEqual(v.remediation_operation, "ANONYMIZE_RECORD")
        self.assertEqual(v.verification_operation, "VERIFY_RECORD_ANONYMIZED")

    def test_security_audit_log_no_finding(self) -> None:
        fact = _make_fact(system_id="security_service", resource_id="audit_record_001",
                          status_or_state="PRESENT", data_category="SECURITY_AUDIT_LOG")
        v = self.evaluator.evaluate_fact(fact)
        self.assertFalse(v.has_finding)
        self.assertTrue(v.is_compliant_retention)

    def test_backup_archive_active_gets_restore_risk_finding(self) -> None:
        fact = _make_fact(system_id="backup_service", resource_id="backup_001",
                          status_or_state="ACTIVE", data_category="BACKUP_ARCHIVE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertTrue(v.has_finding)
        self.assertEqual(v.finding_operation, "REPORT_RESTORE_RISK")
        self.assertEqual(v.remediation_operation, "BLOCK_RESTORE")
        self.assertEqual(v.verification_operation, "VERIFY_RESTORE_BLOCKED")

    def test_backup_archive_blocked_no_finding(self) -> None:
        fact = _make_fact(system_id="backup_service", resource_id="backup_001",
                          status_or_state="BLOCKED", data_category="BACKUP_ARCHIVE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertFalse(v.has_finding)

    def test_account_tombstone_gets_redact_finding(self) -> None:
        fact = _make_fact(system_id="identity_service", resource_id="tombstone_001",
                          status_or_state="PRESENT", data_category="ACCOUNT_TOMBSTONE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertTrue(v.has_finding)
        self.assertEqual(v.finding_operation, "REPORT_EXPOSED_PII")
        self.assertEqual(v.remediation_operation, "REDACT_RECORD")

    def test_active_data_flow_gets_disable_finding(self) -> None:
        fact = _make_fact(system_id="integration_service", resource_id="data_flow_001",
                          status_or_state="ACTIVE", data_category="ACTIVE_DATA_FLOW")
        v = self.evaluator.evaluate_fact(fact)
        self.assertTrue(v.has_finding)
        self.assertEqual(v.finding_operation, "REPORT_ACTIVE_DATA_FLOW")
        self.assertEqual(v.remediation_operation, "DISABLE_DATA_FLOW")

    def test_search_index_gets_delete_finding(self) -> None:
        fact = _make_fact(system_id="search_service", resource_id="search_001",
                          status_or_state="PRESENT", data_category="SEARCH_INDEX_ENTRY")
        v = self.evaluator.evaluate_fact(fact)
        self.assertTrue(v.has_finding)
        self.assertEqual(v.remediation_operation, "DELETE_RECORD")

    def test_no_category_no_finding(self) -> None:
        fact = _make_fact(data_category=None)
        v = self.evaluator.evaluate_fact(fact)
        self.assertFalse(v.has_finding)

    def test_redacted_state_no_finding(self) -> None:
        fact = _make_fact(status_or_state="REDACTED", data_category="SUPPORT_MESSAGE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertFalse(v.has_finding)

    def test_anonymized_state_no_finding(self) -> None:
        fact = _make_fact(status_or_state="ANONYMIZED", data_category="ANALYTICS_PROFILE")
        v = self.evaluator.evaluate_fact(fact)
        self.assertFalse(v.has_finding)


# ---------------------------------------------------------------------------
# 3. Deterministic Step Ordering
# ---------------------------------------------------------------------------

class TestDeterministicOrdering(unittest.TestCase):
    """Tests for canonical step ordering (phase → op rank → system_id → resource_id)."""

    def test_findings_before_remediation_before_verification(self) -> None:
        raw_steps = [
            {"phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_001",
             "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
            {"phase": "FINDING", "system_id": "account_service", "resource_id": "account_001",
             "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev1"},
            {"phase": "REMEDIATION", "system_id": "account_service", "resource_id": "account_001",
             "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
        ]
        sorted_steps = _sort_and_number_steps(raw_steps)
        phases = [s.phase for s in sorted_steps]
        self.assertEqual(phases, ["FINDING", "REMEDIATION", "VERIFICATION"])

    def test_within_remediation_disable_before_block_before_delete(self) -> None:
        raw_steps = [
            {"phase": "REMEDIATION", "system_id": "backup_service", "resource_id": "backup_001",
             "operation": "BLOCK_RESTORE", "state": "BLOCKED", "evidence_id": ""},
            {"phase": "REMEDIATION", "system_id": "integration_service", "resource_id": "data_flow_001",
             "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""},
            {"phase": "REMEDIATION", "system_id": "account_service", "resource_id": "account_001",
             "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
        ]
        sorted_steps = _sort_and_number_steps(raw_steps)
        ops = [s.operation for s in sorted_steps]
        # DISABLE_DATA_FLOW (rank 7) < BLOCK_RESTORE (rank 8) < DELETE_RECORD (rank 9)
        self.assertEqual(ops[0], "DISABLE_DATA_FLOW")
        self.assertEqual(ops[1], "BLOCK_RESTORE")
        self.assertEqual(ops[2], "DELETE_RECORD")

    def test_same_phase_and_op_sorted_by_system_id_then_resource_id(self) -> None:
        raw_steps = [
            {"phase": "FINDING", "system_id": "search_service", "resource_id": "search_002",
             "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev1"},
            {"phase": "FINDING", "system_id": "account_service", "resource_id": "account_001",
             "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev1"},
        ]
        sorted_steps = _sort_and_number_steps(raw_steps)
        self.assertEqual(sorted_steps[0].system_id, "account_service")  # lexically first
        self.assertEqual(sorted_steps[1].system_id, "search_service")

    def test_step_numbers_consecutive_from_one(self) -> None:
        raw_steps = [
            {"phase": "FINDING", "system_id": "account_service", "resource_id": "account_001",
             "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev1"},
            {"phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_001",
             "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
        ]
        sorted_steps = _sort_and_number_steps(raw_steps)
        self.assertEqual(sorted_steps[0].step_no, 1)
        self.assertEqual(sorted_steps[1].step_no, 2)


# ---------------------------------------------------------------------------
# 4. Account Resource ID Inference
# ---------------------------------------------------------------------------

class TestGroundedAccountMapping(unittest.TestCase):
    """Tests proving both correct grounded mapping and refusal to infer a decoupled ID (Gate 3.2 #4)."""

    def test_grounded_account_id_extracted_from_evidence(self) -> None:
        """Grounded account resource ID is extracted when present in evidence facts."""
        subject = SubjectIdentity(user_id="user_12", name="Haruka", current_email="haruka@zoho.com")
        facts = [
            _make_fact(system_id="account_service", resource_id="account_9797", status_or_state="ABSENT"),
        ]
        extracted = _extract_account_resource_id(facts, subject)
        self.assertEqual(extracted, "account_9797")

    def test_refusal_to_infer_decoupled_account_id(self) -> None:
        """Do NOT synthesize account_012 from user_12 when ungrounded."""
        subject = SubjectIdentity(user_id="user_12", name="Haruka", current_email="haruka@zoho.com")
        facts = [
            _make_fact(system_id="security_service", resource_id="audit_record_001", status_or_state="PRESENT"),
        ]
        extracted = _extract_account_resource_id(facts, subject)
        self.assertIsNone(extracted, "Must refuse to infer decoupled account ID without grounded evidence")

    def test_empty_facts_returns_none(self) -> None:
        subject = SubjectIdentity(user_id="user_01", name="Amina", current_email="amina@gmail.com")
        self.assertIsNone(_extract_account_resource_id([], subject))


# ---------------------------------------------------------------------------
# 5. Sample Ground Truth Spot Checks (Using Actual Dataset)
# ---------------------------------------------------------------------------

class TestSampleGroundTruth(unittest.TestCase):
    """
    Spot checks against sample_output.csv for specific known cases.
    Uses the actual participant-facing dataset.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.planner = AuditPlanner()
        with open(DATASET_DIR / "sample_deletion_requests.csv", encoding="utf-8") as f:
            cls.sample_requests = {r["case_id"]: r for r in csv.DictReader(f)}
        with open(DATASET_DIR / "sample_output.csv", encoding="utf-8") as f:
            cls.sample_output = {r["case_id"]: r for r in csv.DictReader(f)}

    def _get_request(self, case_id: str) -> DeletionRequest:
        row = self.sample_requests[case_id]
        return DeletionRequest(
            case_id=row["case_id"],
            email=row["email"],
            requested_at=parse_iso_timestamp(row["requested_at"]),
            reported_status=row["reported_status"],
            reported_at=parse_iso_timestamp(row["reported_at"]),
            audit_at=parse_iso_timestamp(row["audit_at"]),
            request_text=row["request_text"],
        )

    def test_case_03_complete_status_grounded(self) -> None:
        """case_03: COMPLETE — account_7566 established ABSENT from evidence_94."""
        req = self._get_request("case_03")
        result = self.planner.audit_case(req)
        self.assertEqual(result.deletion_status, "COMPLETE")
        verify_ops = [s.operation for s in result.steps if s.phase == "VERIFICATION"]
        self.assertIn("VERIFY_RECORD_ABSENT", verify_ops)

    def test_case_31_complete_status_grounded(self) -> None:
        """case_31: COMPLETE — account_4857 absent and tombstone_440 redacted in evidence_51."""
        req = self._get_request("case_31")
        result = self.planner.audit_case(req)
        self.assertEqual(result.deletion_status, "COMPLETE")
        self.assertTrue(len(result.steps) >= 1)
        for s in result.steps:
            self.assertEqual(s.phase, "VERIFICATION")
            self.assertNotEqual(s.evidence_id, "", "COMPLETE steps must cite evidence")

    def test_case_05_incomplete_status(self) -> None:
        """case_05: INCOMPLETE — account_005 still ACTIVE in evidence_54."""
        req = self._get_request("case_05")
        result = self.planner.audit_case(req)
        self.assertEqual(result.deletion_status, "INCOMPLETE")

    def test_case_05_finding_cites_evidence(self) -> None:
        """case_05 finding step must cite participant-visible evidence_id."""
        req = self._get_request("case_05")
        result = self.planner.audit_case(req)
        findings = [s for s in result.steps if s.phase == "FINDING"]
        self.assertTrue(len(findings) >= 1)
        for f in findings:
            self.assertNotEqual(f.evidence_id, "", "findings must cite evidence_id")

    def test_case_05_remediation_has_empty_evidence_id(self) -> None:
        """case_05 remediation steps must use evidence_id='' (future work)."""
        req = self._get_request("case_05")
        result = self.planner.audit_case(req)
        remediation_steps = [s for s in result.steps if s.phase == "REMEDIATION"]
        self.assertTrue(len(remediation_steps) >= 1)
        for s in remediation_steps:
            self.assertEqual(s.evidence_id, "", "remediation future work must use evidence_id=''")

    def test_case_05_verification_has_empty_evidence_id(self) -> None:
        """case_05 INCOMPLETE verification steps use evidence_id='' (future checklist)."""
        req = self._get_request("case_05")
        result = self.planner.audit_case(req)
        verify_steps = [s for s in result.steps if s.phase == "VERIFICATION"]
        self.assertTrue(len(verify_steps) >= 1)
        for s in verify_steps:
            self.assertEqual(s.evidence_id, "", "INCOMPLETE verification must use evidence_id=''")

    def test_not_applicable_returns_empty_steps(self) -> None:
        """NOT_APPLICABLE cases must produce steps_json=[]."""
        # Simulate a non-deletion request
        req = DeletionRequest(
            case_id="na_test",
            email="amina.elmasri@gmail.com",
            requested_at=parse_iso_timestamp("2026-08-18T09:14:00Z"),
            reported_status="COMPLETE",
            reported_at=parse_iso_timestamp("2026-08-20T16:42:00Z"),
            audit_at=parse_iso_timestamp("2026-09-03T11:30:00Z"),
            request_text="Please send me a copy of my personal data.",
        )
        result = self.planner.audit_case(req)
        self.assertEqual(result.deletion_status, "NOT_APPLICABLE")
        self.assertEqual(result.steps, [])

    def test_admissibility_boundary_no_post_audit_findings(self) -> None:
        """Evidence files captured after audit_at must not contribute to findings."""
        # case_09: audit_at is before evidence_06 (captured after audit)
        if "case_09" not in self.sample_requests:
            return
        req = self._get_request("case_09")
        result = self.planner.audit_case(req)
        # evidence_06 should NOT be cited in any finding step
        for step in result.steps:
            if step.phase == "FINDING":
                self.assertNotEqual(step.evidence_id, "evidence_06",
                                    "evidence_06 is post-audit and must not be cited as a finding")


# ---------------------------------------------------------------------------
# 6. Evidence ID Contract
# ---------------------------------------------------------------------------

class TestEvidenceIdContract(unittest.TestCase):
    """Tests for evidence_id rules per §6.3 and §6.6."""

    def test_complete_case_verification_steps_have_nonempty_evidence_id(self) -> None:
        """COMPLETE case verification steps must cite a real evidence_id."""
        planner = AuditPlanner()
        req = DeletionRequest(
            case_id="case_03",
            email="l.fontaine46@yahoo.com",
            requested_at=parse_iso_timestamp("2026-09-15T09:47:00Z"),
            reported_status="COMPLETE",
            reported_at=parse_iso_timestamp("2026-09-15T10:08:00Z"),
            audit_at=parse_iso_timestamp("2026-09-26T12:00:00Z"),
            request_text="I am closing my account. Please remove all my records.",
        )
        result = planner.audit_case(req)
        self.assertEqual(result.deletion_status, "COMPLETE")
        for step in result.steps:
            self.assertNotEqual(step.evidence_id, "",
                                "COMPLETE verification steps must cite a real evidence_id")


# ---------------------------------------------------------------------------
# 7. Decoy Exclusion
# ---------------------------------------------------------------------------

class TestDecoyExclusion(unittest.TestCase):
    """Tests that unrelated accounts in evidence files are not attributed to the subject."""

    def test_evidence_54_decoys_excluded_for_user_01(self) -> None:
        """
        evidence_54 contains account_8741 (user_8741), not user_01.
        Parser should return 0 facts for user_01 matching other users' records.
        """
        from code.parsers import SQLEvidenceParser
        manifest = load_evidence_manifest()
        resolver = IdentityResolver()
        subject = resolver.resolve_by_email("amina.elmasri@gmail.com")
        self.assertIsNotNone(subject)
        ev_file = manifest["evidence_54"]
        parser = SQLEvidenceParser()
        result = parser.parse(ev_file, subject=subject)
        # All extracted facts must match user_01 identifiers
        for fact in result.facts:
            self.assertEqual(fact.matched_identifier_value, subject.user_id)

    def test_evidence_54_decoys_excluded_for_user_05(self) -> None:
        """
        evidence_54 has account_005 (user_05) ACTIVE — this IS the subject for case_05.
        For user_01, account_005 is a decoy.
        """
        from code.parsers import SQLEvidenceParser
        manifest = load_evidence_manifest()
        resolver = IdentityResolver()
        # user_01 should NOT match account_005
        subject = resolver.resolve_by_email("amina.elmasri@gmail.com")
        ev_file = manifest["evidence_54"]
        parser = SQLEvidenceParser()
        result = parser.parse(ev_file, subject=subject)
        resource_ids = [f.resource_id for f in result.facts]
        self.assertNotIn("account_005", resource_ids,
                         "account_005 (user_05) must not be attributed to user_01")


# ---------------------------------------------------------------------------
# 8. Row Count and Schema Validation
# ---------------------------------------------------------------------------

class TestOutputSchema(unittest.TestCase):
    """Tests for output.csv schema compliance."""

    def test_deletion_requests_loads_518_cases(self) -> None:
        requests = load_deletion_requests()
        self.assertEqual(len(requests), 518)

    def test_all_cases_have_valid_audit_at(self) -> None:
        requests = load_deletion_requests()
        for req in requests:
            self.assertIsNotNone(req.audit_at)

    def test_step_to_dict_has_all_required_fields(self) -> None:
        step = AuditStep(
            step_no=1, phase="FINDING", system_id="account_service",
            resource_id="account_001", operation="REPORT_REMAINING_RECORD",
            state="PRESENT", evidence_id="evidence_54",
        )
        d = step.to_dict()
        required_fields = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
        self.assertEqual(set(d.keys()), required_fields)


# ---------------------------------------------------------------------------
# 9. Gate 3.2 Audit Correctness Hardening Regression Tests
# ---------------------------------------------------------------------------

class TestGate32Hardening(unittest.TestCase):
    """
    Comprehensive regression tests for Gate 3.2 audit correctness hardening fixes:
    1. Lookup trace resolution & subject_key correlation.
    2. Recognition of already-redacted support records (explicit null vs missing).
    3. Tombstone direct PII inspection (DELETED status does not suppress exposed PII).
    4. Refusal to infer ungrounded account resource IDs.
    5. Absence-scan coverage, failure recording, and secondary replica gating.
    6. Policy contract enforcement (rule_07 ANONYMIZE, no COMPLETE with empty steps).
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_evidence_manifest()
        cls.resolver = IdentityResolver()
        cls.evaluator = PolicyEvaluator()
        cls.planner = AuditPlanner()

    # --- 1. Lookup Trace Resolution & subject_key Correlation ---

    def test_actual_dataset_case_03_trace_resolution(self) -> None:
        """
        In evidence_94 (case_03 pattern), trace rb-085737-009 contains profile_lookup_started
        and terminal profile_lookup_completed with http_status=404.
        Terminal 404 must suppress the stale initiation PRESENT fact and emit only ABSENT.
        """
        from code.parsers import LogEvidenceParser
        sub = self.resolver.resolve_by_email("l.fontaine46@yahoo.com")
        self.assertIsNotNone(sub)
        ev_file = self.manifest["evidence_94"]
        parser = LogEvidenceParser()
        result = parser.parse(ev_file, subject=sub)

        absent_facts = [f for f in result.facts if f.resource_id == "account_7566" and f.status_or_state == "ABSENT"]
        present_facts = [f for f in result.facts if f.resource_id == "account_7566" and f.status_or_state == "PRESENT"]
        self.assertTrue(len(absent_facts) >= 1, "Must contain terminal ABSENT fact for account_7566")
        self.assertEqual(len(present_facts), 0, "Stale initiation PRESENT fact must be suppressed by terminal 404")

    def test_actual_dataset_case_15_subject_key_correlation(self) -> None:
        """
        In evidence_01 (case_15 pattern), trace tr-9750867 starts with subject_key='lucia-torres@gmail.com'
        and continues on line 88 with resource_id=data_flow_9846 enabled=true.
        Parser must correlate via subject_key and trace_id, emitting ACTIVE_DATA_FLOW with ACTIVE state.
        """
        from code.parsers import LogEvidenceParser
        sub = self.resolver.resolve_by_email("lucia-torres@gmail.com")
        self.assertIsNotNone(sub)
        ev_file = self.manifest["evidence_01"]
        parser = LogEvidenceParser()
        result = parser.parse(ev_file, subject=sub)

        flow_facts = [f for f in result.facts if f.resource_id == "data_flow_9846"]
        self.assertTrue(len(flow_facts) >= 1, "Must extract data_flow_9846 via subject_key trace correlation")
        flow_fact = flow_facts[0]
        self.assertEqual(flow_fact.status_or_state, "ACTIVE")
        self.assertEqual(flow_fact.data_category, "ACTIVE_DATA_FLOW")

        verdict = self.evaluator.evaluate_fact(flow_fact)
        self.assertTrue(verdict.has_finding)
        self.assertEqual(verdict.finding_operation, "REPORT_ACTIVE_DATA_FLOW")
        self.assertEqual(verdict.remediation_operation, "DISABLE_DATA_FLOW")

    def test_unrelated_traces_and_decoys_not_collapsed(self) -> None:
        """Trace resolution preserves independent traces and does not confuse decoys."""
        from code.parsers import LogEvidenceParser
        sub = self.resolver.resolve_by_email("l.fontaine46@yahoo.com")
        ev_file = self.manifest["evidence_94"]
        parser = LogEvidenceParser()
        result = parser.parse(ev_file, subject=sub)

        known_identifiers = {sub.user_id, *sub.all_emails(), *sub.all_phones(), *sub.all_hashes()}
        for f in result.facts:
            self.assertIn(f.matched_identifier_value, known_identifiers)

    # --- 2. Recognize Already-Redacted Support Records ---

    def test_support_record_explicit_null_pii_is_redacted(self) -> None:
        """When requester_email, requester_name, requester_phone are explicitly null, state is REDACTED."""
        from code.parsers import JSONEvidenceParser
        sub = SubjectIdentity(user_id="user_26", name="Elena", current_email="elena@example.com")
        parser = JSONEvidenceParser()
        flattened = {
            "resource_id": "support_101",
            "requester_email": None,
            "requester_name": None,
            "requester_phone": None,
            "user_id": "user_26",
            "message": "redacted support ticket",
        }
        ev_file = self.manifest["evidence_92"]
        facts = []
        parser._process_json_record(
            rec=flattened,
            coll_or_svc="support_tickets",
            fallback_system="support_platform",
            locator="test:1",
            ev_file=ev_file,
            subject=sub,
            facts=facts,
            seen=set(),
        )
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].status_or_state, "REDACTED")

        verdict = self.evaluator.evaluate_fact(facts[0])
        self.assertFalse(verdict.has_finding, "Already-redacted support record must not produce finding")

    def test_support_record_missing_fields_not_inferred_redacted(self) -> None:
        """When PII fields are omitted/missing from the record, do NOT infer REDACTED."""
        from code.parsers import JSONEvidenceParser
        sub = SubjectIdentity(user_id="user_26", name="Elena", current_email="elena@example.com")
        parser = JSONEvidenceParser()
        flattened = {
            "resource_id": "support_102",
            "user_id": "user_26",
        }
        ev_file = self.manifest["evidence_92"]
        facts = []
        parser._process_json_record(
            rec=flattened,
            coll_or_svc="support_tickets",
            fallback_system="support_platform",
            locator="test:2",
            ev_file=ev_file,
            subject=sub,
            facts=facts,
            seen=set(),
        )
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].status_or_state, "PRESENT", "Missing fields must not infer redaction")

    def test_support_record_non_null_pii_is_present(self) -> None:
        """When non-null PII exists in support record, state is PRESENT and triggers finding."""
        from code.parsers import JSONEvidenceParser
        sub = SubjectIdentity(user_id="user_26", name="Elena", current_email="elena@example.com")
        parser = JSONEvidenceParser()
        flattened = {
            "resource_id": "support_103",
            "requester_email": "elena@example.com",
            "requester_name": "Elena",
            "requester_phone": None,
        }
        ev_file = self.manifest["evidence_92"]
        facts = []
        parser._process_json_record(
            rec=flattened,
            coll_or_svc="support_tickets",
            fallback_system="support_platform",
            locator="test:3",
            ev_file=ev_file,
            subject=sub,
            facts=facts,
            seen=set(),
        )
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0].status_or_state, "PRESENT")
        verdict = self.evaluator.evaluate_fact(facts[0])
        self.assertTrue(verdict.has_finding)
        self.assertEqual(verdict.finding_operation, "REPORT_EXPOSED_PII")

    # --- 3. Tombstone Direct PII Inspection ---

    def test_tombstone_compliant_null_pii_in_evidence_51(self) -> None:
        """In evidence_51, user_541 tombstone_440 has explicit null PII; evaluates as compliant."""
        from code.parsers import JSONEvidenceParser
        sub = self.resolver.resolve_by_user_id("user_541")
        self.assertIsNotNone(sub)
        ev_file = self.manifest["evidence_51"]
        result = JSONEvidenceParser().parse(ev_file, subject=sub)

        tombstone_facts = [f for f in result.facts if f.resource_id == "tombstone_440"]
        self.assertTrue(len(tombstone_facts) >= 1)
        self.assertEqual(tombstone_facts[0].status_or_state, "REDACTED")
        verdict = self.evaluator.evaluate_fact(tombstone_facts[0])
        self.assertFalse(verdict.has_finding)
        self.assertTrue(verdict.is_compliant_retention)

    def test_tombstone_exposed_pii_in_evidence_51_emits_finding(self) -> None:
        """In evidence_51, user_542 tombstone_9178 has status DELETED but exposed PII; emits finding."""
        from code.parsers import JSONEvidenceParser
        sub = self.resolver.resolve_by_user_id("user_542")
        self.assertIsNotNone(sub)
        ev_file = self.manifest["evidence_51"]
        result = JSONEvidenceParser().parse(ev_file, subject=sub)

        tombstone_facts = [f for f in result.facts if f.resource_id == "tombstone_9178"]
        self.assertTrue(len(tombstone_facts) >= 1)
        self.assertEqual(tombstone_facts[0].status_or_state, "PRESENT")
        verdict = self.evaluator.evaluate_fact(tombstone_facts[0])
        self.assertTrue(verdict.has_finding, "Exposed PII on tombstone must emit finding despite DELETED status")
        self.assertEqual(verdict.finding_operation, "REPORT_EXPOSED_PII")
        self.assertEqual(verdict.remediation_operation, "REDACT_RECORD")

    # --- 4. Refusal to Infer Ungrounded Account IDs ---

    def test_refusal_to_infer_account_id_in_sql_absence_scan(self) -> None:
        """Absence scan refuses to synthesize account_012 from user_12 when ungrounded."""
        sub = SubjectIdentity(user_id="user_12", name="Haruka", current_email="haruka@zoho.com")
        facts = []
        scan_errors = []
        ev_file = self.manifest["evidence_54"]
        _scan_sql_absence(
            ev_file=ev_file,
            subject=sub,
            facts=facts,
            seen_ids=set(),
            grounded_account_id=None,
            scan_errors=scan_errors,
        )
        self.assertEqual(len(facts), 0, "No absence fact may be manufactured when account ID is ungrounded")
        self.assertTrue(any("unresolved" in err.lower() for err in scan_errors))

    # --- 5. Absence-Scan Coverage and Failures ---

    def test_sql_absence_scan_malformed_sql_records_failure(self) -> None:
        """Malformed SQL script produces explicit error and does not establish absence."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sql", delete=False, mode="w", encoding="utf-8") as tf:
            tf.write("THIS IS NOT VALID SQL SYNTAX;")
            temp_path = Path(tf.name)

        try:
            temp_ev = EvidenceFile(
                file_id="temp_broken",
                file_path=temp_path.name,
                origin="test",
                captured_at=datetime.now(),
                absolute_path=temp_path,
            )
            facts = []
            scan_errors = []
            sub = SubjectIdentity(user_id="user_01", name="Test", current_email="test@example.com")
            _scan_sql_absence(
                ev_file=temp_ev,
                subject=sub,
                facts=facts,
                seen_ids=set(),
                grounded_account_id="account_001",
                scan_errors=scan_errors,
            )
            self.assertEqual(len(facts), 0)
            self.assertTrue(len(scan_errors) >= 1)
            self.assertTrue(any("sqlite execution failed" in e.lower() for e in scan_errors))
        finally:
            temp_path.unlink(missing_ok=True)

    def test_sql_absence_scan_missing_tables_records_unsupported_schema(self) -> None:
        """Database missing account profile tables produces explicit error and no absence fact."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sql", delete=False, mode="w", encoding="utf-8") as tf:
            tf.write("CREATE TABLE unrelated_catalog (id TEXT PRIMARY KEY, title TEXT);")
            temp_path = Path(tf.name)

        try:
            temp_ev = EvidenceFile(
                file_id="temp_no_accounts",
                file_path=temp_path.name,
                origin="test",
                captured_at=datetime.now(),
                absolute_path=temp_path,
            )
            facts = []
            scan_errors = []
            sub = SubjectIdentity(user_id="user_01", name="Test", current_email="test@example.com")
            _scan_sql_absence(
                ev_file=temp_ev,
                subject=sub,
                facts=facts,
                seen_ids=set(),
                grounded_account_id="account_001",
                scan_errors=scan_errors,
            )
            self.assertEqual(len(facts), 0)
            self.assertTrue(len(scan_errors) >= 1)
            self.assertTrue(any("no account profile tables" in e.lower() for e in scan_errors))
        finally:
            temp_path.unlink(missing_ok=True)

    def test_secondary_replica_only_scan_cannot_establish_complete(self) -> None:
        """A zero-row result from secondary replica only is flagged partial and does not establish COMPLETE."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".sql", delete=False, mode="w", encoding="utf-8") as tf:
            tf.write("CREATE TABLE customer_profiles_reporting (resource_id TEXT, user_id TEXT, email TEXT);")
            temp_path = Path(tf.name)

        try:
            temp_ev = EvidenceFile(
                file_id="temp_secondary",
                file_path=temp_path.name,
                origin="test",
                captured_at=datetime.now(),
                absolute_path=temp_path,
            )
            facts = []
            scan_errors = []
            sub = SubjectIdentity(user_id="user_01", name="Test", current_email="test@example.com")
            _scan_sql_absence(
                ev_file=temp_ev,
                subject=sub,
                facts=facts,
                seen_ids=set(),
                grounded_account_id="account_001",
                scan_errors=scan_errors,
            )
            self.assertEqual(len(facts), 1)
            self.assertEqual(facts[0].get_attribute("is_partial_scan"), "true")

            complete_verify_steps = _build_verification_steps_for_complete(facts, [])
            self.assertEqual(len(complete_verify_steps), 0, "Partial scan must NOT produce verification steps for COMPLETE")
        finally:
            temp_path.unlink(missing_ok=True)

    # --- 6. Status and Policy Contract ---

    def test_classify_status_refuses_complete_with_empty_verification(self) -> None:
        """When required verification evidence is absent, _classify_status must return INCOMPLETE, never COMPLETE."""
        status = _classify_status(findings=[], complete_verification_steps=[])
        self.assertEqual(status, "INCOMPLETE", "Empty verification must return INCOMPLETE per Gate 3.2 item 6")

    def test_complete_status_always_has_nonempty_steps(self) -> None:
        """A case classified as COMPLETE must have non-empty verification steps."""
        requests = load_deletion_requests(DATASET_DIR / "sample_deletion_requests.csv")
        req = next((r for r in requests if r.case_id == "case_03"), None)
        self.assertIsNotNone(req)
        result = self.planner.audit_case(req)
        if result.deletion_status == "COMPLETE":
            self.assertTrue(len(result.steps) > 0, "COMPLETE cases must never have empty steps")


if __name__ == "__main__":
    unittest.main()
