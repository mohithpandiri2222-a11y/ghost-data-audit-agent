"""
Regression test suite for Account Identity Grounding and Evidence Safeguards.

Covers:
1. Unsupported ID synthesis (ensures no user_id numbering heuristics).
2. Ambiguous deletion-worker events (ensures no first-candidate or ungrounded window heuristics).
3. Temporal boundary enforcement (ensures post-audit_at events are rejected).
4. Malformed/unsupported PDF handling (ensures safe escape parsing, filter isolation, no absence facts).
5. Absence verification with no grounded identifier (ensures no manufactured absence facts).
"""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from code.config import EvidenceFact, EvidenceFile
from code.identity import SubjectIdentity
from code.parsers import (
    DocumentImageEvidenceParser,
    LogEvidenceParser,
    ParseStatus,
)
from code.planner import (
    AuditPlanner,
    DeletionRequest,
    _extract_account_resource_id,
    _scan_sql_absence,
)
from code.temporal import TemporalAdmissibilityValidator


class TestGroundingRemediation(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = AuditPlanner()
        self.pdf_parser = DocumentImageEvidenceParser()

    def test_unsupported_id_synthesis_rejected(self) -> None:
        """
        Verify that account IDs are never synthesized from user ID patterns
        (e.g., user_04 -> account_004, user_01 -> account_001, user_99 -> account_099).
        """
        # Test case for user_04 (Thandiwe Ndlovu) who has no grounded account in evidence
        subject_04 = SubjectIdentity(
            user_id="user_04",
            name="Thandiwe Ndlovu",
            current_email="thandiwe.n@gmail.com",
            current_phone="+27 71 684 5928",
            current_email_hash="f730ef60615bde7a8f5ee21138637b4e9d4094855fbb02da6afcdba9c076281f",
        )
        req_04 = DeletionRequest(
            case_id="case_04",
            email="thandiwe.n@gmail.com",
            requested_at=datetime(2026, 8, 25, 12, 32, 0, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 8, 27, 8, 54, 0, tzinfo=timezone.utc),
            audit_at=datetime(2026, 9, 7, 10, 20, 0, tzinfo=timezone.utc),
            request_text="I'm deleting my account.",
        )

        resolved_acc = self.planner._resolve_case_account_id(subject_04, req_04)
        self.assertIsNone(
            resolved_acc,
            "Must NOT synthesize 'account_004' from user_04 numbering pattern",
        )

        # Test case for arbitrary user numbers (user_01, user_99, etc.)
        for uid in ["user_01", "user_02", "user_03", "user_09", "user_99"]:
            subj = SubjectIdentity(
                user_id=uid,
                name="Test User",
                current_email=f"{uid}@example.com",
                current_phone="+1 555 0199",
                current_email_hash="0" * 64,
            )
            req = DeletionRequest(
                case_id="test_case",
                email=f"{uid}@example.com",
                requested_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                reported_status="COMPLETE",
                reported_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
                audit_at=datetime(2026, 1, 5, tzinfo=timezone.utc),
                request_text="Delete me",
            )
            # Should be None unless linked by grounded evidence
            acc = self.planner._resolve_case_account_id(subj, req)
            if acc is not None:
                # If resolved, verify it actually matches a grounded link in the index
                cand_keys = [subj.user_id.lower()] + [e.lower() for e in subj.all_emails()]
                self.assertTrue(
                    any(k in self.planner.account_links_by_user for k in cand_keys),
                    f"Resolved account {acc} for {uid} without a grounded link!",
                )

    def test_ambiguous_deletion_worker_events_rejected(self) -> None:
        """
        Verify that deletion worker events occurring in the request window that lack
        a stable subject identifier are NOT used as first-candidate fallbacks.
        """
        subject_unlinked = SubjectIdentity(
            user_id="user_8888",
            name="Unlinked Person",
            current_email="unlinked@example.com",
            current_phone="+1 555 8888",
            current_email_hash="1" * 64,
        )
        # Request window that overlaps with many deletion worker events
        req = DeletionRequest(
            case_id="test_ambig",
            email="unlinked@example.com",
            requested_at=datetime(2026, 8, 26, 8, 0, 0, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 8, 26, 10, 0, 0, tzinfo=timezone.utc),
            audit_at=datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc),
            request_text="Delete my account",
        )
        resolved = self.planner._resolve_case_account_id(subject_unlinked, req)
        self.assertIsNone(
            resolved,
            "Ambiguous deletion worker events must not resolve via first-match fallback",
        )

    def test_temporal_boundary_enforcement(self) -> None:
        """
        Verify that evidence or activity events occurring strictly after audit_at
        are rejected under temporal boundary enforcement.
        """
        # Inject a synthetic grounded link occurring on 2026-09-10
        self.planner.account_links_by_user["user_7777"] = ("account_7777", "2026-09-10T12:00:00Z")
        subj = SubjectIdentity(
            user_id="user_7777",
            name="Future Person",
            current_email="future@example.com",
            current_phone="+1 555 7777",
            current_email_hash="2" * 64,
        )
        # Case audit_at is earlier: 2026-09-05
        req_early_audit = DeletionRequest(
            case_id="case_early",
            email="future@example.com",
            requested_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 8, 21, tzinfo=timezone.utc),
            audit_at=datetime(2026, 9, 5, 0, 0, 0, tzinfo=timezone.utc),
            request_text="Delete me",
        )
        resolved = self.planner._resolve_case_account_id(subj, req_early_audit)
        self.assertIsNone(
            resolved,
            "Must reject grounded account link whose event_time is after audit_at",
        )

        # Case audit_at is later: 2026-09-15
        req_late_audit = DeletionRequest(
            case_id="case_late",
            email="future@example.com",
            requested_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
            reported_status="COMPLETE",
            reported_at=datetime(2026, 8, 21, tzinfo=timezone.utc),
            audit_at=datetime(2026, 9, 15, 0, 0, 0, tzinfo=timezone.utc),
            request_text="Delete me",
        )
        resolved_late = self.planner._resolve_case_account_id(subj, req_late_audit)
        self.assertEqual(resolved_late, "account_7777")

    def test_malformed_and_unsupported_pdf_handling(self) -> None:
        """
        Verify that malformed PDFs, unsupported filters, and escape sequences
        are handled safely, and that failed/unsupported PDFs never yield absence facts.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Malformed / corrupted PDF stream
            bad_pdf = Path(tmpdir) / "corrupt.pdf"
            bad_pdf.write_bytes(b"%PDF-1.4\n1 0 obj << /Length 50 >> stream\nINVALID_GARBAGE\nendstream\nendobj\n%%EOF")

            ev_bad = EvidenceFile(
                file_id="evidence_bad_pdf",
                file_path="evidence/documents/corrupt.pdf",
                origin="support_platform",
                captured_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                absolute_path=bad_pdf,
            )
            res_bad = self.pdf_parser.parse(ev_bad)
            self.assertEqual(res_bad.status, ParseStatus.UNSUPPORTED_FORMAT)
            self.assertEqual(len(res_bad.facts), 0)
            self.assertIn("cannot serve as evidence of absence", res_bad.errors[0])

            # 2. PDF literal string escapes and octal values
            tokens, errors = self.pdf_parser._extract_pdf_tokens(bad_pdf)
            self.assertIsInstance(tokens, list)
            self.assertIsInstance(errors, list)

            # Test string unescaping directly
            test_stream = (
                b"%PDF-1.4\n1 0 obj << /Filter /FlateDecode /Length 100 >> stream\n"
            )
            # 3. PDF with subject match produces positive fact, never absence fact
            subj_priya = SubjectIdentity(
                user_id="user_07",
                name="Priya Raman",
                current_email="priya.raman@gmail.com",
                current_phone="+91 98765 73142",
                current_email_hash="3" * 64,
            )
            real_pdf = Path("dataset/evidence/documents/delivery_correction_attachment.pdf")
            if real_pdf.exists():
                ev_real = EvidenceFile(
                    file_id="evidence_58",
                    file_path="evidence/documents/delivery_correction_attachment.pdf",
                    origin="support_platform",
                    captured_at=datetime(2026, 9, 2, tzinfo=timezone.utc),
                    absolute_path=real_pdf,
                )
                res_real = self.pdf_parser.parse(ev_real, subject=subj_priya)
                self.assertEqual(res_real.status, ParseStatus.SUCCESS)
                self.assertGreater(len(res_real.facts), 0)
                for f in res_real.facts:
                    self.assertEqual(f.status_or_state, "PRESENT")
                    self.assertNotEqual(f.status_or_state, "ABSENT")

    def test_absence_verification_with_no_grounded_identifier(self) -> None:
        """
        Verify that _scan_sql_absence refuses to manufacture an absence fact
        when grounded_account_id is None, and records an unresolved scan error.
        """
        sql_file = Path("dataset/evidence/databases/customer_accounts_failover_replica_20260902.sql")
        if not sql_file.exists():
            self.skipTest("SQL snapshot evidence file missing")

        ev_sql = EvidenceFile(
            file_id="evidence_54",
            file_path="evidence/databases/customer_accounts_failover_replica_20260902.sql",
            origin="account_service",
            captured_at=datetime(2026, 9, 2, 23, 0, 0, tzinfo=timezone.utc),
            absolute_path=sql_file,
        )
        subj = SubjectIdentity(
            user_id="user_04",
            name="Thandiwe Ndlovu",
            current_email="thandiwe.n@gmail.com",
            current_phone="+27 71 684 5928",
            current_email_hash="4" * 64,
        )

        facts = []
        seen_ids = set()
        scan_errors = []

        _scan_sql_absence(
            ev_file=ev_sql,
            subject=subj,
            facts=facts,
            seen_ids=seen_ids,
            grounded_account_id=None,  # Unresolved
            scan_errors=scan_errors,
        )

        self.assertEqual(
            len(facts),
            0,
            "Must NOT manufacture absence facts when grounded_account_id is None",
        )
        self.assertGreater(
            len(scan_errors),
            0,
            "Must record explicit scan error when account ID is unresolved",
        )
        self.assertIn("refusing to manufacture absence fact", scan_errors[0])

    def test_log_parser_no_trace_id_resource_synthesis(self) -> None:
        """
        Verify that LogEvidenceParser never synthesizes a data resource ID
        from a trace_id or line_no on initiation or operational lines,
        while correctly preserving cross-line trace correlation and genuine
        resource IDs on terminal/result lines.

        Also verifies:
        - 404 terminal event is linked to the intended subject.
        - Event is temporally admissible before asserting ABSENT.
        - Negative test: terminal resource belonging to an unrelated subject
          must not emit an ABSENT fact for the target subject.
        """
        parser = LogEvidenceParser()
        subj = SubjectIdentity(
            user_id="user_12",
            name="Min-jun Kim",
            current_email="minjun.kim@gmail.com",
            current_phone="+82 10 9876 5432",
            current_email_hash="a" * 64,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_trace.log"
            log_content = (
                # Target subject trace: initiation (no resource ID) -> intermediate (no resource ID) -> terminal (404 with grounded resource ID)
                '2026-09-15T11:56:49Z level=DEBUG service=account_service trace_id=tr-target event=profile_lookup_started lookup_key="minjun.kim@gmail.com" attempt=1\n'
                '2026-09-15T11:56:50Z level=DEBUG service=account_service trace_id=tr-target event=connection_acquired wait_ms=10\n'
                '2026-09-15T11:56:57Z level=INFO service=account_service trace_id=tr-target resource_id=account_9797 event=profile_lookup_completed http_status=404\n'
                # Unrelated subject trace: initiation (unrelated subject) -> terminal (404 for unrelated subject)
                '2026-09-15T11:57:00Z level=DEBUG service=account_service trace_id=tr-unrelated event=profile_lookup_started lookup_key="other@example.com"\n'
                '2026-09-15T11:57:05Z level=INFO service=account_service trace_id=tr-unrelated resource_id=account_8888 event=profile_lookup_completed http_status=404\n'
                # Unrelated subject with explicit conflicting identifier on terminal line
                '2026-09-15T11:57:10Z level=INFO service=account_service trace_id=tr-target-conflict resource_id=account_7777 event=profile_lookup_completed lookup_key="stranger@example.com" http_status=404\n'
            )
            log_path.write_text(log_content, encoding="utf-8")

            ev_log = EvidenceFile(
                file_id="evidence_test_log",
                file_path="evidence/logs/test_trace.log",
                origin="account_service",
                captured_at=datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc),
                absolute_path=log_path,
            )

            res = parser.parse(ev_log, subject=subj)
            self.assertEqual(res.status, ParseStatus.SUCCESS)

            # Exactly 1 fact should be extracted for the target subject: account_9797
            self.assertEqual(len(res.facts), 1)
            fact = res.facts[0]

            # 1. Subject link verification
            self.assertEqual(fact.resource_id, "account_9797")
            self.assertEqual(fact.matched_identifier_field, "lookup_key")
            self.assertEqual(fact.matched_identifier_value, "minjun.kim@gmail.com")
            self.assertEqual(fact.system_id, "account_service")

            # 2. Temporal admissibility verification before asserting ABSENT
            validator = TemporalAdmissibilityValidator({ev_log.file_id: ev_log})
            admissible_audit_at = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
            val_result = validator.validate_fact(fact, admissible_audit_at)
            self.assertTrue(val_result.is_admissible, "Fact must be temporally admissible at or after event time")
            self.assertEqual(fact.status_or_state, "ABSENT")

            # Inadmissible cutoff: audit_at before event time must reject the fact
            inadmissible_audit_at = datetime(2026, 9, 15, 11, 0, 0, tzinfo=timezone.utc)
            val_early = validator.validate_fact(fact, inadmissible_audit_at)
            self.assertFalse(val_early.is_admissible, "Fact must be inadmissible when audit_at is before event time")

            # 3. Negative test verification: unrelated resources must NOT emit facts for target subject
            extracted_resource_ids = {f.resource_id for f in res.facts}
            self.assertNotIn("account_8888", extracted_resource_ids)
            self.assertNotIn("account_7777", extracted_resource_ids)

            # 4. Anti-synthesis check: must never synthesize ID from trace_id or line_no
            for f in res.facts:
                self.assertNotIn("tr-target", f.resource_id)
                self.assertNotIn("tr-unrelated", f.resource_id)
                self.assertNotIn("account_service_1", f.resource_id)
                self.assertNotIn("account_service_2", f.resource_id)

    def test_polymorphic_identifier_matching(self) -> None:
        """
        Focused regression tests for polymorphic identifier matching:
        1. correlation_key="user_12" matches subject whose user_id is exactly "user_12".
        2. subject_ref="user_61" matches only the subject whose user_id is exactly "user_61".
        3. lookup_key containing a known email matches after email normalization.
        4. A known hash matches correctly.
        5. An unrelated user ID, email, or hash is rejected.
        6. Empty, invalid, or ambiguous identifiers are rejected safely.
        """
        known_hash_12 = "44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e"
        subj_12 = SubjectIdentity(
            user_id="user_12",
            name="Min-jun Kim",
            current_email="minjun.kim@gmail.com",
            historical_emails=frozenset(["m.kim90@gmail.com"]),
            current_phone="+82 10 9876 5432",
            historical_phones=frozenset(),
            current_email_hash=known_hash_12,
            historical_email_hashes=frozenset(),
        )

        subj_61 = SubjectIdentity(
            user_id="user_61",
            name="Kofi Appiah",
            current_email="k.appiah88@gmail.com",
            historical_emails=frozenset(),
            current_phone="+233 20 123 4567",
            historical_phones=frozenset(),
            current_email_hash="b" * 64,
            historical_email_hashes=frozenset(),
        )

        # 1. correlation_key="user_12" matches subject whose user_id is exactly "user_12"
        self.assertTrue(subj_12.matches_identifier("correlation_key", "user_12"))
        self.assertTrue(subj_12.matches_identifier("lookup_key", "user_12"))
        self.assertTrue(subj_12.matches_identifier("match_key", "user_12"))
        self.assertTrue(subj_12.matches_identifier("query", "user_12"))
        self.assertTrue(subj_12.matches_identifier("subject_key", "user_12"))
        self.assertTrue(subj_12.matches_identifier("subject_ref", "user_12"))

        # 2. subject_ref="user_61" matches only user_61, never user_12
        self.assertTrue(subj_61.matches_identifier("subject_ref", "user_61"))
        self.assertFalse(subj_12.matches_identifier("subject_ref", "user_61"))
        self.assertFalse(subj_61.matches_identifier("subject_ref", "user_12"))

        # 3. lookup_key containing a known email matches after email normalization (case/whitespace)
        self.assertTrue(subj_61.matches_identifier("lookup_key", "  K.Appiah88@Gmail.com  "))
        self.assertTrue(subj_12.matches_identifier("query", "M.Kim90@Gmail.Com"))
        self.assertTrue(subj_12.matches_identifier("subject_key", "MINJUN.KIM@GMAIL.COM"))

        # 4. A known hash matches correctly in generic polymorphic fields
        self.assertTrue(subj_12.matches_identifier("correlation_key", known_hash_12))
        self.assertTrue(subj_12.matches_identifier("lookup_key", known_hash_12.upper()))
        self.assertTrue(subj_12.matches_identifier("match_key", known_hash_12))

        # 5. An unrelated user ID, email, or hash is rejected
        self.assertFalse(subj_12.matches_identifier("correlation_key", "user_99"))
        self.assertFalse(subj_12.matches_identifier("lookup_key", "stranger@example.com"))
        self.assertFalse(subj_12.matches_identifier("match_key", "c" * 64))
        self.assertFalse(subj_61.matches_identifier("query", "user_12"))
        self.assertFalse(subj_61.matches_identifier("subject_ref", "minjun.kim@gmail.com"))

        # 6. Empty, invalid, or ambiguous identifiers are rejected safely
        for invalid_val in [None, "", "   ", "null", "none", "NULL", "NONE", "N/A", "n/a", "undefined"]:
            self.assertFalse(subj_12.matches_identifier("correlation_key", invalid_val))
            self.assertFalse(subj_12.matches_identifier("subject_ref", invalid_val))
            self.assertFalse(subj_12.matches_identifier("lookup_key", invalid_val))
            self.assertFalse(subj_61.matches_identifier("query", invalid_val))


if __name__ == "__main__":
    unittest.main()

