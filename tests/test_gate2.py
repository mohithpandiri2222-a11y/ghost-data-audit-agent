"""
Automated Unit Tests for Gate 2: Strict Temporal Admissibility Validator & Evidence Parsers.

Validates:
1. File captured before audit_at is admissible.
2. File captured exactly at audit_at is admissible.
3. File captured after audit_at is inadmissible.
4. Record timestamp before, exactly at, and after audit_at.
5. Missing, malformed, and invalid record timestamps remain unknown/unproven.
6. A timely internal timestamp cannot rescue a file captured after audit_at.
7. A timely file timestamp cannot rescue a record with a late internal timestamp.
8. Provenance retention across all supported parsers (SQL, JSON, Log, Text).
9. Representative records from multiple actual participant-facing dataset formats.
10. Malformed input and unsupported formats (.pdf, .png) produce explicit outcomes without silent discard.
11. Duplicate records are not emitted twice by a single traversal.
12. Existing Gate 1.1 identity and manifest tests continue to pass.
"""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from code.config import (
    DATASET_DIR,
    EvidenceFact,
    EvidenceFile,
    load_evidence_manifest,
    parse_iso_timestamp,
)
from code.identity import IdentityResolver
from code.parsers import (
    DocumentImageEvidenceParser,
    EvidenceParseResult,
    JSONEvidenceParser,
    LogEvidenceParser,
    ParseStatus,
    SQLEvidenceParser,
    TextEvidenceParser,
    UnifiedEvidenceParser,
)
from code.temporal import (
    TemporalAdmissibilityValidator,
    TemporalValidationResult,
)


class TestGate2TemporalAdmissibilityValidator(unittest.TestCase):
    """Test suite for strict temporal admissibility validator (Gate 2)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_evidence_manifest()
        cls.validator = TemporalAdmissibilityValidator(cls.manifest)

    # -----------------------------------------------------------------------
    # 1. File-Level Temporal Gating Tests
    # -----------------------------------------------------------------------

    def test_file_captured_before_audit_at_is_admissible(self) -> None:
        """File captured strictly before audit_at satisfies file-level admissibility."""
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")
        self.assertIsNotNone(audit_at)

        # evidence_92 captured at 2026-09-15T11:44:55Z (< audit_at)
        self.assertTrue(self.validator.validate_file("evidence_92", audit_at))

        fact = EvidenceFact(
            file_id="evidence_92",
            file_path="evidence/records/service_resource_export_20260915_114455.json",
            origin="service_resource_export",
            file_captured_at=parse_iso_timestamp("2026-09-15T11:44:55Z"),
            record_timestamp=None,
            system_id="account_service",
            resource_id="account_3136",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="ABSENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_25",
        )
        verdict = self.validator.validate_fact(fact, audit_at)
        self.assertTrue(verdict.is_admissible)
        self.assertTrue(verdict.is_file_admissible)
        self.assertFalse(verdict.is_record_event_proven)
        self.assertIsNone(verdict.is_record_event_admissible)
        self.assertIsNone(verdict.rejection_reason)

    def test_file_captured_exactly_at_audit_at_is_admissible(self) -> None:
        """File captured exactly at audit_at satisfies file-level admissibility (<=)."""
        exact_time = parse_iso_timestamp("2026-10-01T12:00:00Z")
        self.assertIsNotNone(exact_time)

        # evidence_03 captured at 2026-10-01T12:00:00Z (== audit_at)
        self.assertTrue(self.validator.validate_file("evidence_03", exact_time))

        fact = EvidenceFact(
            file_id="evidence_03",
            file_path="evidence/records/customer_account_handover_20261001.txt",
            origin="customer_account_service",
            file_captured_at=exact_time,
            record_timestamp=exact_time,
            system_id="account_service",
            resource_id="account_146",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="ABSENT",
            matched_identifier_field="email",
            matched_identifier_value="e.lindberg18@yahoo.com",
        )
        verdict = self.validator.validate_fact(fact, exact_time)
        self.assertTrue(verdict.is_admissible)
        self.assertTrue(verdict.is_file_admissible)
        self.assertTrue(verdict.is_record_event_proven)
        self.assertTrue(verdict.is_record_event_admissible)

    def test_file_captured_after_audit_at_is_inadmissible(self) -> None:
        """File captured after audit_at must be rejected."""
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")

        # evidence_06 captured at 2026-09-18T10:14:22Z (> audit_at)
        self.assertFalse(self.validator.validate_file("evidence_06", audit_at))

        fact = EvidenceFact(
            file_id="evidence_06",
            file_path="evidence/logs/service_events_eu_west_20260918.log",
            origin="service_readback_logs",
            file_captured_at=parse_iso_timestamp("2026-09-18T10:14:22Z"),
            record_timestamp=None,
            system_id="account_service",
            resource_id="account_001",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_01",
        )
        verdict = self.validator.validate_fact(fact, audit_at)
        self.assertFalse(verdict.is_admissible)
        self.assertFalse(verdict.is_file_admissible)
        self.assertEqual(verdict.rejection_reason, "FILE_CAPTURED_AFTER_AUDIT_AT")

    # -----------------------------------------------------------------------
    # 2. Strict Cross-Gating Non-Rescue Rules
    # -----------------------------------------------------------------------

    def test_timely_record_cannot_rescue_late_file(self) -> None:
        """
        CRITICAL RULE (Prompt §3.5):
        An internal record timestamp from before audit_at CANNOT rescue
        a file captured after audit_at.
        """
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")

        # Record occurred on 2026-09-10 (5 days before audit_at),
        # but the container file was captured on 2026-09-18 (3 days after audit_at).
        fact = EvidenceFact(
            file_id="evidence_06",
            file_path="evidence/logs/late.log",
            origin="service_readback_logs",
            file_captured_at=parse_iso_timestamp("2026-09-18T10:14:22Z"),
            record_timestamp=parse_iso_timestamp("2026-09-10T08:00:00Z"),
            system_id="account_service",
            resource_id="account_001",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_01",
        )
        verdict = self.validator.validate_fact(fact, audit_at)
        self.assertFalse(
            verdict.is_admissible,
            "Timely internal timestamp must NEVER rescue a late evidence file",
        )
        self.assertFalse(verdict.is_file_admissible)
        self.assertTrue(verdict.is_record_event_proven)
        self.assertTrue(verdict.is_record_event_admissible)
        self.assertEqual(verdict.rejection_reason, "FILE_CAPTURED_AFTER_AUDIT_AT")

    def test_timely_file_cannot_rescue_late_record(self) -> None:
        """
        CRITICAL RULE (Prompt §3.7):
        A file captured before audit_at CANNOT rescue a record whose internal
        timestamp is after audit_at.
        """
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")

        # Container file captured at 11:59:39Z (before audit_at),
        # but an internal log event occurred at 12:05:00Z (post-audit mutation).
        fact = EvidenceFact(
            file_id="evidence_01",
            file_path="evidence/logs/audit.log",
            origin="central_observability_export",
            file_captured_at=parse_iso_timestamp("2026-09-15T11:59:39Z"),
            record_timestamp=parse_iso_timestamp("2026-09-15T12:05:00Z"),
            system_id="account_service",
            resource_id="account_001",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_01",
        )
        verdict = self.validator.validate_fact(fact, audit_at)
        self.assertFalse(
            verdict.is_admissible,
            "Timely file capture must NEVER rescue a post-audit record timestamp",
        )
        self.assertTrue(verdict.is_file_admissible)
        self.assertTrue(verdict.is_record_event_proven)
        self.assertFalse(verdict.is_record_event_admissible)
        self.assertEqual(verdict.rejection_reason, "RECORD_TIMESTAMP_AFTER_AUDIT_AT")

    # -----------------------------------------------------------------------
    # 3. Explicit Unknown Record Timestamp Semantics
    # -----------------------------------------------------------------------

    def test_missing_and_unknown_record_timestamps_remain_unproven(self) -> None:
        """
        CRITICAL RULE (Prompt §3.4):
        Missing record timestamps must remain unknown/unproven and must NEVER
        be replaced by file capture timestamps.
        """
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")
        capture_time = self.manifest["evidence_54"].captured_at

        fact = EvidenceFact(
            file_id="evidence_54",
            file_path="evidence/databases/customer_accounts_primary_20260902.sql",
            origin="customer_data_inventory_capture",
            file_captured_at=capture_time,
            record_timestamp=None,  # Missing/unknown internal timestamp
            system_id="account_service",
            resource_id="account_005",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_05",
        )
        verdict = self.validator.validate_fact(fact, audit_at)
        self.assertTrue(verdict.is_admissible)
        self.assertTrue(verdict.is_file_admissible)
        self.assertFalse(verdict.is_record_event_proven)
        self.assertIsNone(verdict.is_record_event_admissible)
        self.assertIsNone(verdict.record_timestamp)
        self.assertEqual(verdict.file_captured_at, capture_time)

    def test_unmanifested_file_is_inadmissible(self) -> None:
        """Rule 1: Source file not listed in validated manifest is inadmissible."""
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")
        fact = EvidenceFact(
            file_id="evidence_ghost_999",  # Not in evidence_files.csv
            file_path="evidence/unknown.sql",
            origin="unknown",
            file_captured_at=parse_iso_timestamp("2026-09-15T10:00:00Z"),
            record_timestamp=None,
            system_id="account_service",
            resource_id="account_999",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_99",
        )
        verdict = self.validator.validate_fact(fact, audit_at)
        self.assertFalse(verdict.is_admissible)
        self.assertEqual(verdict.rejection_reason, "UNMANIFESTED_FILE")

    def test_temporal_validator_uses_authoritative_manifest_capture_time(self) -> None:
        """
        CRITICAL RULE (Prompt §5):
        Validator must obtain authoritative capture timestamp from manifest entry
        and reject a fact whose manifest file was captured after audit_at, even if
        the fact object carries a forged pre-audit timestamp.
        """
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")
        manifest_cap = self.manifest["evidence_06"].captured_at

        # Fact carrying forged/tampered pre-audit file_captured_at
        fact = EvidenceFact(
            file_id="evidence_06",
            file_path="evidence/logs/service_events_eu_west_20260918.log",
            origin="service_readback_logs",
            file_captured_at=parse_iso_timestamp("2026-09-01T00:00:00Z"),
            record_timestamp=parse_iso_timestamp("2026-09-10T08:00:00Z"),
            system_id="account_service",
            resource_id="account_001",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_01",
        )
        verdict = self.validator.validate_fact(fact, audit_at)
        self.assertFalse(verdict.is_admissible)
        self.assertFalse(verdict.is_file_admissible)
        self.assertEqual(verdict.rejection_reason, "FILE_CAPTURED_AFTER_AUDIT_AT")
        self.assertEqual(verdict.file_captured_at, manifest_cap)


class TestGate2EvidenceParsers(unittest.TestCase):
    """Test suite for provenance-preserving evidence parsers (Gate 2)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_evidence_manifest()
        cls.resolver = IdentityResolver()
        cls.unified = UnifiedEvidenceParser(cls.manifest)
        cls.sql_parser = SQLEvidenceParser()
        cls.json_parser = JSONEvidenceParser()
        cls.log_parser = LogEvidenceParser()
        cls.txt_parser = TextEvidenceParser()
        cls.doc_parser = DocumentImageEvidenceParser()

    # -----------------------------------------------------------------------
    # 4. SQL Evidence Parser on Actual Dataset
    # -----------------------------------------------------------------------

    def test_sql_parser_actual_dataset_evidence_54_user_05(self) -> None:
        """
        Verify SQL parser extracts customer_profiles_failover_replica for user_05
        from actual dataset evidence_54.
        """
        u05 = self.resolver.resolve_by_user_id("user_05")
        self.assertIsNotNone(u05)

        res = self.unified.parse_file("evidence_54", u05)
        self.assertEqual(res.status, ParseStatus.SUCCESS)
        self.assertGreater(len(res.facts), 0, "evidence_54 must extract facts for user_05")

        fact = res.facts[0]
        self.assertEqual(fact.file_id, "evidence_54")
        self.assertEqual(fact.resource_id, "account_005")
        self.assertEqual(fact.status_or_state, "ACTIVE")
        self.assertEqual(fact.matched_identifier_field, "user_id")
        self.assertEqual(fact.matched_identifier_value, "user_05")
        self.assertIn("customer_profiles_failover_replica", fact.source_locator)
        self.assertTrue(fact.has_record_timestamp)
        self.assertEqual(
            fact.record_timestamp,
            parse_iso_timestamp("2026-09-02T22:45:00Z"),
        )

    # -----------------------------------------------------------------------
    # 5. JSON Evidence Parser on Actual Dataset
    # -----------------------------------------------------------------------

    def test_json_parser_actual_dataset_evidence_92_user_25(self) -> None:
        """
        Verify JSON parser extracts security audit record for user_25 from
        actual dataset evidence_92 (service resource export).
        """
        u25 = self.resolver.resolve_by_user_id("user_25")
        self.assertIsNotNone(u25)

        res = self.unified.parse_file("evidence_92", u25)
        self.assertEqual(res.status, ParseStatus.SUCCESS)

        # Should match audit_record_451
        audit_facts = [f for f in res.facts if f.resource_id == "audit_record_451"]
        self.assertEqual(len(audit_facts), 1)

        fact = audit_facts[0]
        self.assertEqual(fact.file_id, "evidence_92")
        self.assertEqual(fact.system_id, "security_service")
        self.assertEqual(fact.resource_id, "audit_record_451")
        self.assertEqual(fact.status_or_state, "PRESENT")
        self.assertEqual(fact.matched_identifier_field, "subject_reference")
        self.assertEqual(fact.matched_identifier_value, "user_25")
        self.assertIn("audit_records", fact.source_locator)
        self.assertEqual(
            fact.record_timestamp,
            parse_iso_timestamp("2026-09-15T10:07:33Z"),
        )

    # -----------------------------------------------------------------------
    # 6. Log Evidence Parser on Actual Dataset
    # -----------------------------------------------------------------------

    def test_log_parser_actual_dataset_evidence_01_user_12(self) -> None:
        """
        Verify Log parser extracts line 92 matching user_12's pre-recorded historical
        SHA-256 hash in actual dataset evidence_01.
        """
        u12 = self.resolver.resolve_by_user_id("user_12")
        self.assertIsNotNone(u12)

        res = self.unified.parse_file("evidence_01", u12)
        self.assertEqual(res.status, ParseStatus.SUCCESS)

        # Matches analytics_9914 via correlation_key
        analytics_facts = [f for f in res.facts if f.resource_id == "analytics_9914"]
        self.assertEqual(len(analytics_facts), 1)

        fact = analytics_facts[0]
        self.assertEqual(fact.file_id, "evidence_01")
        self.assertEqual(fact.system_id, "analytics_platform")
        self.assertEqual(fact.resource_id, "analytics_9914")
        self.assertEqual(fact.matched_identifier_field, "correlation_key")
        self.assertEqual(
            fact.matched_identifier_value,
            "44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e",
        )
        self.assertIn(":92", fact.source_locator)
        self.assertEqual(
            fact.record_timestamp,
            parse_iso_timestamp("2026-09-15T11:58:26Z"),
        )

    # -----------------------------------------------------------------------
    # 7. Text Evidence Parser on Actual Dataset
    # -----------------------------------------------------------------------

    def test_text_parser_actual_dataset_evidence_03(self) -> None:
        """
        Verify Text parser extracts shift handover records from actual dataset evidence_03
        for user_31 (Erik Lindberg) and user_32 (Tomasz Novak).
        """
        u31 = self.resolver.resolve_by_user_id("user_31")
        self.assertIsNotNone(u31)

        res31 = self.unified.parse_file("evidence_03", u31)
        self.assertEqual(res31.status, ParseStatus.SUCCESS)
        self.assertGreater(len(res31.facts), 0)

        fact = res31.facts[0]
        self.assertEqual(fact.file_id, "evidence_03")
        self.assertEqual(fact.system_id, "account_service")
        self.assertEqual(fact.resource_id, "account_146")
        self.assertEqual(fact.status_or_state, "ABSENT")  # NOT_FOUND -> ABSENT
        self.assertEqual(fact.matched_identifier_field, "email")
        self.assertEqual(fact.matched_identifier_value, "e.lindberg18@yahoo.com")
        self.assertTrue(fact.has_record_timestamp)
        self.assertEqual(fact.record_timestamp, parse_iso_timestamp("2026-10-01T12:00:00Z"))

        # Also verify user_32 matches all 6 shift checks across 6 services
        u32 = self.resolver.resolve_by_user_id("user_32")
        res32 = self.unified.parse_file("evidence_03", u32)
        self.assertEqual(res32.status, ParseStatus.SUCCESS)
        self.assertEqual(len(res32.facts), 6)
        r_ids = {f.resource_id for f in res32.facts}
        self.assertEqual(
            r_ids,
            {"account_4248", "analytics_2034", "data_flow_9522", "search_052", "audit_record_9394", "support_864"},
        )

    # -----------------------------------------------------------------------
    # 8. Unsupported Format Handling (.pdf and .png)
    # -----------------------------------------------------------------------

    def test_unsupported_formats_produce_explicit_outcome(self) -> None:
        """
        CRITICAL RULE (Prompt §4):
        PDF and image files without dependencies produce ParseStatus.UNSUPPORTED_FORMAT
        with explicit errors and NEVER produce fake absence facts.
        """
        # PDF evidence file (evidence_18)
        res_pdf = self.unified.parse_file("evidence_18")
        self.assertEqual(res_pdf.status, ParseStatus.UNSUPPORTED_FORMAT)
        self.assertEqual(len(res_pdf.facts), 0)
        self.assertGreater(len(res_pdf.errors), 0)
        self.assertIn("cannot serve as evidence of absence", res_pdf.errors[0])

        # PNG image evidence file (evidence_04)
        res_png = self.unified.parse_file("evidence_04")
        self.assertEqual(res_png.status, ParseStatus.UNSUPPORTED_FORMAT)
        self.assertEqual(len(res_png.facts), 0)
        self.assertGreater(len(res_png.errors), 0)
        self.assertIn("cannot serve as evidence of absence", res_png.errors[0])

    # -----------------------------------------------------------------------
    # 9. Malformed Input Handling Without File Discard
    # -----------------------------------------------------------------------

    def test_malformed_input_produces_explicit_errors_without_file_discard(self) -> None:
        """
        CRITICAL RULE (Prompt §4):
        Handle malformed records safely and report parse errors without silently
        discarding the entire file.
        """
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write("2026-09-15T10:00:00Z level=INFO service=account_service user_id=user_99 resource_id=account_99 event=profile_lookup\n")
            f.write("MALFORMED_HEADER_WITHOUT_TIMESTAMP level=DEBUG user_id=user_99\n")
            f.write("2026-09-15T10:05:00Z level=INFO service=account_service user_id=user_99 resource_id=account_100 event=profile_lookup\n")
            temp_path = Path(f.name)

        try:
            ev_dummy = EvidenceFile(
                file_id="evidence_dummy_log",
                file_path=temp_path.name,
                origin="test_logs",
                captured_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
                absolute_path=temp_path,
            )
            res = self.log_parser.parse(ev_dummy)
            self.assertEqual(res.status, ParseStatus.PARTIAL_SUCCESS)
            # The 2 valid lines were extracted as facts
            self.assertEqual(len(res.facts), 2)
            # The 1 malformed line was reported in errors
            self.assertGreater(len(res.errors), 0)
            self.assertIn("Line 2", res.errors[0])
        finally:
            if temp_path.exists():
                temp_path.unlink()

    # -----------------------------------------------------------------------
    # 10. Traversal Deduplication
    # -----------------------------------------------------------------------

    def test_duplicate_records_not_emitted_twice_by_single_traversal(self) -> None:
        """
        CRITICAL RULE (Prompt §4):
        Avoid duplicate facts when the same record is encountered through
        a parser's traversal.
        """
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            # Identical log entry repeated
            f.write("2026-09-15T10:00:00Z level=INFO service=search_service user_id=user_77 resource_id=search_77 event=query\n")
            f.write("2026-09-15T10:00:00Z level=INFO service=search_service user_id=user_77 resource_id=search_77 event=query\n")
            temp_path = Path(f.name)

        try:
            ev_dummy = EvidenceFile(
                file_id="evidence_dummy_dup",
                file_path=temp_path.name,
                origin="test_logs",
                captured_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
                absolute_path=temp_path,
            )
            res = self.log_parser.parse(ev_dummy)
            self.assertEqual(res.records_read, 2)
            # Deduplicated: only 1 fact emitted
            self.assertEqual(len(res.facts), 1)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    # -----------------------------------------------------------------------
    # 11. Provenance Retention Across Parsers
    # -----------------------------------------------------------------------

    def test_provenance_retention_across_parsers(self) -> None:
        """
        Verify source provenance is preserved: file_id, file_path, origin, and source_locator.
        """
        u12 = self.resolver.resolve_by_user_id("user_12")
        facts = self.unified.parse_all_for_subject(u12)
        self.assertGreater(len(facts), 0)

        for fact in facts:
            self.assertTrue(fact.file_id, "file_id must not be empty")
            self.assertTrue(fact.file_path, "file_path must not be empty")
            self.assertTrue(fact.origin, "origin must not be empty")
            self.assertTrue(fact.source_locator, "source_locator must not be empty")
            self.assertIn(":", fact.source_locator, "source_locator must contain separator")

    # -----------------------------------------------------------------------
    # 12. Gate 2.1 Regression Tests: Hardened Parsers & Deduplication
    # -----------------------------------------------------------------------

    def test_log_parser_actual_dataset_json_lines_evidence_06_and_34(self) -> None:
        """
        Gate 2.1 Fix 1: LogEvidenceParser must parse timestamp-prefixed JSON objects.
        Validates actual dataset evidence_06 and evidence_34 without silent drops.
        """
        u_collins = self.resolver.resolve_by_email("collins.grace@icloud.com")
        self.assertIsNotNone(u_collins)

        res06 = self.unified.parse_file("evidence_06", u_collins)
        self.assertEqual(res06.status, ParseStatus.SUCCESS)
        self.assertGreater(len(res06.facts), 0, "evidence_06 must extract facts for collins.grace")

        # Find profile facts for account_6633
        acct_facts = [f for f in res06.facts if f.resource_id == "account_6633"]
        self.assertGreater(len(acct_facts), 0)
        f_acct = acct_facts[0]
        self.assertEqual(f_acct.system_id, "account_service")
        self.assertEqual(f_acct.file_id, "evidence_06")
        self.assertIn(":4", f_acct.source_locator)
        self.assertTrue(f_acct.has_record_timestamp)

        # Also test evidence_34
        u_dubois = self.resolver.resolve_by_email("dubois.ines94@icloud.com")
        self.assertIsNotNone(u_dubois)
        res34 = self.unified.parse_file("evidence_34", u_dubois)
        self.assertEqual(res34.status, ParseStatus.SUCCESS)
        self.assertGreater(len(res34.facts), 0, "evidence_34 must extract facts for dubois.ines94")

    def test_log_parser_malformed_json_lines_recorded_in_errors(self) -> None:
        """
        Gate 2.1 Fix 1: Malformed JSON lines in logs must be recorded in errors
        without discarding the entire file.
        """
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write('2026-09-15T10:00:00Z {"service":"account_service","user_id":"user_99","resource_id":"account_99","event":"profile_lookup"}\n')
            f.write('2026-09-15T10:02:00Z {malformed json line without closing\n')
            f.write('2026-09-15T10:05:00Z level=INFO service=account_service user_id=user_99 resource_id=account_100 event=profile_lookup\n')
            temp_path = Path(f.name)

        try:
            ev_dummy = EvidenceFile(
                file_id="evidence_dummy_json_log",
                file_path=temp_path.name,
                origin="test_logs",
                captured_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
                absolute_path=temp_path,
            )
            res = self.log_parser.parse(ev_dummy)
            self.assertEqual(res.status, ParseStatus.PARTIAL_SUCCESS)
            self.assertEqual(len(res.facts), 2)
            self.assertGreater(len(res.errors), 0)
            self.assertIn("Line 2", res.errors[0])
            self.assertIn("malformed JSON", res.errors[0])
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_json_parser_missing_internal_timestamp_remains_unproven_despite_container_export_ts(self) -> None:
        """
        Gate 2.1 Fix 2: JSONEvidenceParser must NEVER substitute container export/capture
        timestamps for missing internal record timestamps.
        """
        import json as json_mod
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json_mod.dump({
                "collection": "customer_snapshots",
                "exported_at": "2026-09-15T12:00:00Z",
                "captured_at": "2026-09-15T12:00:00Z",
                "records": [
                    {"user_id": "user_99", "resource_id": "account_99", "status": "ACTIVE"},
                    {"user_id": "user_99", "resource_id": "account_100", "status": "ACTIVE", "updated_at": "2026-09-10T08:00:00Z"},
                ]
            }, f)
            temp_path = Path(f.name)

        try:
            ev = EvidenceFile(
                file_id="evidence_dummy_container_ts",
                file_path=temp_path.name,
                origin="test_json",
                captured_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
                absolute_path=temp_path,
            )
            res = self.json_parser.parse(ev)
            self.assertEqual(len(res.facts), 2)

            f_no_ts = next(f for f in res.facts if f.resource_id == "account_99")
            self.assertIsNone(f_no_ts.record_timestamp, "Missing internal timestamp must remain None")
            self.assertFalse(f_no_ts.is_event_time_proven, "is_event_time_proven must be False")
            self.assertIn("2026-09-15T12:00:00+00:00", dict(f_no_ts.attributes).get("container_timestamp", ""))

            f_with_ts = next(f for f in res.facts if f.resource_id == "account_100")
            self.assertIsNotNone(f_with_ts.record_timestamp)
            self.assertTrue(f_with_ts.is_event_time_proven)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_sql_parser_canonical_system_mapping_and_replica_preservation(self) -> None:
        """
        Gate 2.1 Fix 3 & 4: SQLEvidenceParser must use canonical system IDs
        (not manifest origin capture strings) and preserve distinct tables
        (primary vs failover replica).
        """
        u05 = self.resolver.resolve_by_user_id("user_05")
        res54_u05 = self.unified.parse_file("evidence_54", u05)
        self.assertEqual(res54_u05.status, ParseStatus.SUCCESS)
        fact_u05 = res54_u05.facts[0]
        self.assertEqual(fact_u05.system_id, "account_service", "Must resolve to account_service, not manifest origin")

        # Full parse of evidence_54 must preserve all 7 records across primary and replica
        res54_all = self.sql_parser.parse(self.manifest["evidence_54"], None)
        self.assertEqual(res54_all.records_read, 7)
        self.assertEqual(res54_all.facts_extracted, 7, "Both primary and replica tables must be preserved")

        # account_7204 exists in both primary and failover replica
        acct_7204_facts = [f for f in res54_all.facts if f.resource_id == "account_7204"]
        self.assertEqual(len(acct_7204_facts), 2, "account_7204 must exist in both tables")
        tables = {dict(f.attributes).get("table") for f in acct_7204_facts}
        self.assertEqual(tables, {"customer_profiles_primary", "customer_profiles_failover_replica"})

    def test_deduplication_different_events_same_timestamp_survive(self) -> None:
        """
        Gate 2.1 Fix 4: Different events for the same resource at the same timestamp
        must both survive without being collapsed.
        """
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write("2026-09-15T10:00:00Z level=INFO service=account_service user_id=user_88 resource_id=account_88 event=profile_lookup_started\n")
            f.write("2026-09-15T10:00:00Z level=INFO service=account_service user_id=user_88 resource_id=account_88 event=profile_lookup_completed status=200\n")
            temp_path = Path(f.name)

        try:
            ev_dummy = EvidenceFile(
                file_id="evidence_dummy_diff_events",
                file_path=temp_path.name,
                origin="test_logs",
                captured_at=datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc),
                absolute_path=temp_path,
            )
            res = self.log_parser.parse(ev_dummy)
            self.assertEqual(res.records_read, 2)
            self.assertEqual(len(res.facts), 2, "Distinct events at same timestamp must both survive")
            events = {dict(f.attributes).get("event") for f in res.facts}
            self.assertEqual(events, {"profile_lookup_started", "profile_lookup_completed"})
        finally:
            if temp_path.exists():
                temp_path.unlink()


if __name__ == "__main__":
    unittest.main()
