"""
Unit tests for Gate 1: Evidence Ingestion Foundation and Identity Resolution.

Validates:
1. Repository-relative configuration and dataset paths.
2. Manifest-driven evidence inventory (dataset/evidence_files.csv).
3. Temporal admissibility gating (captured_at <= audit_at).
4. Immutable EvidenceFact structure and separation of file_captured_at from record_timestamp.
5. Identity resolution using dataset/user_identities.csv and dataset/user_audit_log.csv.
6. Direct historical email-hash recovery for user_12 and user_30 without dynamic hashing.
7. Rejection of null, empty, sentinel, and decoy identifiers.
"""

import tempfile
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

from code.config import (
    DATASET_DIR,
    DELETION_REQUESTS_PATH,
    DELETION_RULES_PATH,
    EVIDENCE_FILES_PATH,
    EvidenceFact,
    EvidenceFile,
    REPO_ROOT,
    SYSTEM_ACTIVITY_PATH,
    USER_AUDIT_LOG_PATH,
    USER_IDENTITIES_PATH,
    load_evidence_manifest,
    parse_iso_timestamp,
)
from code.identity import IdentityResolver, SubjectIdentity


class TestGate1EvidenceAndIdentity(unittest.TestCase):
    """Test suite for Gate 1 foundation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_evidence_manifest()
        cls.resolver = IdentityResolver()

    # -----------------------------------------------------------------------
    # 1. Path & Manifest Loading Tests
    # -----------------------------------------------------------------------

    def test_repository_paths_exist(self) -> None:
        """Verify that all core participant-facing dataset files exist at resolved paths."""
        self.assertTrue(REPO_ROOT.is_dir(), f"Repo root does not exist: {REPO_ROOT}")
        self.assertTrue(DATASET_DIR.is_dir(), f"Dataset dir does not exist: {DATASET_DIR}")
        self.assertTrue(DELETION_REQUESTS_PATH.is_file(), "deletion_requests.csv missing")
        self.assertTrue(USER_IDENTITIES_PATH.is_file(), "user_identities.csv missing")
        self.assertTrue(USER_AUDIT_LOG_PATH.is_file(), "user_audit_log.csv missing")
        self.assertTrue(SYSTEM_ACTIVITY_PATH.is_file(), "system_activity.csv missing")
        self.assertTrue(DELETION_RULES_PATH.is_file(), "deletion_rules.csv missing")
        self.assertTrue(EVIDENCE_FILES_PATH.is_file(), "evidence_files.csv missing")

    def test_evidence_manifest_inventory(self) -> None:
        """Verify that evidence_files.csv loads all 94 files with valid metadata."""
        self.assertEqual(len(self.manifest), 94, "Manifest must contain exactly 94 evidence files")

        ev01 = self.manifest.get("evidence_01")
        self.assertIsNotNone(ev01)
        self.assertEqual(ev01.file_id, "evidence_01")
        self.assertEqual(ev01.origin, "central_observability_export")
        self.assertEqual(
            ev01.captured_at,
            datetime(2026, 9, 15, 11, 59, 39, tzinfo=timezone.utc),
        )
        self.assertTrue(ev01.absolute_path.is_file(), f"Physical file missing: {ev01.absolute_path}")

    def test_manifest_rejects_duplicate_file_id(self) -> None:
        """F-01: Manifest loader must reject duplicate file_id entries."""
        real_file_path = self.manifest["evidence_01"].file_path
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("file_id,file_path,origin,captured_at\n")
            f.write(f"evidence_01,{real_file_path},central_observability_export,2026-09-15T10:00:00Z\n")
            f.write(f"evidence_01,{real_file_path},central_observability_export,2026-09-15T11:00:00Z\n")
            temp_path = Path(f.name)

        try:
            with self.assertRaises(ValueError) as ctx:
                load_evidence_manifest(temp_path)
            self.assertIn("Duplicate file_id", str(ctx.exception))
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_manifest_rejects_path_traversal(self) -> None:
        """F-01: Manifest loader must prevent evidence paths from escaping DATASET_DIR."""
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("file_id,file_path,origin,captured_at\n")
            f.write("evidence_escape,../../escaped_secret.txt,attacker,2026-09-15T10:00:00Z\n")
            temp_path = Path(f.name)

        try:
            with self.assertRaises(ValueError) as ctx:
                load_evidence_manifest(temp_path)
            self.assertIn("escapes dataset directory", str(ctx.exception))
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_manifest_rejects_missing_or_non_regular_file(self) -> None:
        """F-03: Manifest loader must validate that each referenced file exists and is a file."""
        # Non-existent file
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("file_id,file_path,origin,captured_at\n")
            f.write("evidence_missing,evidence/databases/non_existent_file_9999.sql,db,2026-09-15T10:00:00Z\n")
            temp_path = Path(f.name)

        try:
            with self.assertRaises(FileNotFoundError) as ctx:
                load_evidence_manifest(temp_path)
            self.assertIn("Evidence file missing on disk", str(ctx.exception))
        finally:
            if temp_path.exists():
                temp_path.unlink()

        # Directory instead of a regular file
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as f:
            f.write("file_id,file_path,origin,captured_at\n")
            f.write("evidence_dir,evidence/databases,db,2026-09-15T10:00:00Z\n")
            temp_dir_ref = Path(f.name)

        try:
            with self.assertRaises(FileNotFoundError) as ctx:
                load_evidence_manifest(temp_dir_ref)
            self.assertIn("not a regular file", str(ctx.exception))
        finally:
            if temp_dir_ref.exists():
                temp_dir_ref.unlink()

    def test_manifest_all_files_exist_and_are_regular_files(self) -> None:
        """F-03: Verify that all 94 evidence files in evidence_files.csv exist as regular files on disk."""
        self.assertEqual(len(self.manifest), 94)
        for file_id, ev_file in self.manifest.items():
            self.assertTrue(ev_file.absolute_path.exists(), f"File missing on disk: {ev_file.absolute_path}")
            self.assertTrue(ev_file.absolute_path.is_file(), f"Path is not a regular file: {ev_file.absolute_path}")

    # -----------------------------------------------------------------------
    # 2. Strict Temporal Admissibility Gating Tests
    # -----------------------------------------------------------------------

    def test_manifest_temporal_gating_case_09(self) -> None:
        """
        Verify case_09 temporal admissibility (audit_at: 2026-09-16T12:00:00Z):
        - evidence_93 (captured 2026-09-14) is admissible.
        - evidence_06 (captured 2026-09-18T10:14:22Z) is post-audit and MUST be rejected.
        """
        case_09_audit_at = parse_iso_timestamp("2026-09-16T12:00:00Z")
        self.assertIsNotNone(case_09_audit_at)

        ev93 = self.manifest["evidence_93"]
        self.assertTrue(
            ev93.is_admissible_for_case(case_09_audit_at),
            "evidence_93 captured before audit_at must be admissible",
        )

        ev06 = self.manifest["evidence_06"]
        self.assertFalse(
            ev06.is_admissible_for_case(case_09_audit_at),
            "evidence_06 captured after audit_at must be rejected as inadmissible",
        )

    def test_manifest_temporal_gating_case_30(self) -> None:
        """
        Verify case_30 temporal admissibility (audit_at: 2026-09-15T12:00:00Z):
        - evidence_92 (captured 2026-09-15T11:45:00Z) is admissible.
        - evidence_02 (captured 2026-09-17T09:12:44Z) is post-audit and MUST be rejected.
        """
        case_30_audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")
        self.assertIsNotNone(case_30_audit_at)

        ev92 = self.manifest["evidence_92"]
        self.assertTrue(
            ev92.is_admissible_for_case(case_30_audit_at),
            "evidence_92 captured before audit_at must be admissible",
        )

        ev02 = self.manifest["evidence_02"]
        self.assertFalse(
            ev02.is_admissible_for_case(case_30_audit_at),
            "evidence_02 captured after audit_at must be rejected as inadmissible",
        )

    # -----------------------------------------------------------------------
    # 3. EvidenceFact Immutability & Timestamp Separation Tests
    # -----------------------------------------------------------------------

    def test_evidence_fact_immutability(self) -> None:
        """Verify that EvidenceFact is frozen and rejects mutation."""
        captured_time = parse_iso_timestamp("2026-09-15T10:00:00Z")
        fact = EvidenceFact(
            file_id="evidence_54",
            file_path="evidence/databases/customer_accounts_primary_20260902.sql",
            origin="database_snapshot",
            file_captured_at=captured_time,
            record_timestamp=None,
            system_id="account_service",
            resource_id="account_005",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_05",
        )

        with self.assertRaises(FrozenInstanceError):
            fact.status_or_state = "ABSENT"  # type: ignore

    def test_evidence_fact_does_not_conflate_file_captured_at_with_record_timestamp(self) -> None:
        """
        CRITICAL RULE:
        Verify that missing record_timestamp remains None and is never
        populated with file_captured_at.
        """
        captured_time = parse_iso_timestamp("2026-09-15T10:00:00Z")
        fact = EvidenceFact(
            file_id="evidence_54",
            file_path="evidence/databases/customer_accounts_primary_20260902.sql",
            origin="database_snapshot",
            file_captured_at=captured_time,
            record_timestamp=None,  # Record has no internal timestamp
            system_id="account_service",
            resource_id="account_005",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_05",
        )

        self.assertIsNone(fact.record_timestamp)
        self.assertFalse(fact.has_record_timestamp)
        self.assertEqual(fact.file_captured_at, captured_time)

    def test_evidence_fact_temporal_admissibility(self) -> None:
        """Verify dual timestamp gating logic on individual facts."""
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")

        # 1. File captured before audit, no record timestamp -> Admissible
        fact_valid = EvidenceFact(
            file_id="evidence_54",
            file_path="evidence/databases/snapshot.sql",
            origin="db_snapshot",
            file_captured_at=parse_iso_timestamp("2026-09-15T10:00:00Z"),
            record_timestamp=None,
            system_id="account_service",
            resource_id="account_001",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_01",
        )
        self.assertTrue(fact_valid.is_temporally_admissible(audit_at))

        # 2. File captured after audit -> Inadmissible
        fact_late_file = EvidenceFact(
            file_id="evidence_06",
            file_path="evidence/databases/late.sql",
            origin="db_snapshot",
            file_captured_at=parse_iso_timestamp("2026-09-18T10:00:00Z"),
            record_timestamp=parse_iso_timestamp("2026-09-10T10:00:00Z"),  # Old record in late file
            system_id="account_service",
            resource_id="account_001",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_01",
        )
        self.assertFalse(fact_late_file.is_temporally_admissible(audit_at))

        # 3. File captured before audit, but internal record event timestamp is after audit -> Inadmissible
        fact_late_record = EvidenceFact(
            file_id="evidence_54",
            file_path="evidence/databases/snapshot.sql",
            origin="db_snapshot",
            file_captured_at=parse_iso_timestamp("2026-09-15T11:00:00Z"),
            record_timestamp=parse_iso_timestamp("2026-09-15T13:00:00Z"),  # Post-audit event
            system_id="account_service",
            resource_id="account_001",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_01",
        )
        self.assertFalse(fact_late_record.is_temporally_admissible(audit_at))

    def test_evidence_fact_explicit_admissibility_and_event_time_distinction(self) -> None:
        """
        F-02: Explicitly distinguish file-level admissibility from whether an individual
        record's event time is proven. Missing record timestamps must remain unknown
        and must never be replaced by file capture timestamps.
        """
        audit_at = parse_iso_timestamp("2026-09-15T12:00:00Z")
        self.assertIsNotNone(audit_at)

        # Scenario 1: Snapshot fact with no record event timestamp (e.g. SQL table row)
        fact_unproven = EvidenceFact(
            file_id="evidence_54",
            file_path="evidence/databases/customer_accounts_primary_20260902.sql",
            origin="database_snapshot",
            file_captured_at=parse_iso_timestamp("2026-09-15T10:00:00Z"),
            record_timestamp=None,
            system_id="account_service",
            resource_id="account_005",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_05",
        )
        # Event time is unproven
        self.assertFalse(fact_unproven.is_event_time_proven)
        self.assertIsNone(fact_unproven.record_timestamp)
        # Record-level event admissibility is None (unknown - NEVER substituted with file_captured_at)
        self.assertIsNone(fact_unproven.is_record_event_admissible(audit_at))
        # File-level admissibility is True
        self.assertTrue(fact_unproven.is_file_admissible(audit_at))
        # Overall temporal admissibility under dual gate is True (snapshot container bounded pre-audit)
        self.assertTrue(fact_unproven.is_temporally_admissible(audit_at))

        # Scenario 2: Log record with proven pre-audit event timestamp
        fact_proven_pre = EvidenceFact(
            file_id="evidence_01",
            file_path="evidence/logs/audit.log",
            origin="central_observability_export",
            file_captured_at=parse_iso_timestamp("2026-09-15T11:59:39Z"),
            record_timestamp=parse_iso_timestamp("2026-09-15T11:30:00Z"),
            system_id="account_service",
            resource_id="account_005",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_05",
        )
        self.assertTrue(fact_proven_pre.is_event_time_proven)
        self.assertTrue(fact_proven_pre.is_record_event_admissible(audit_at))
        self.assertTrue(fact_proven_pre.is_file_admissible(audit_at))
        self.assertTrue(fact_proven_pre.is_temporally_admissible(audit_at))

        # Scenario 3: Container file captured post-audit with older internal record timestamp
        # File is late -> wholly inadmissible, even though internal record timestamp is old
        fact_late_file = EvidenceFact(
            file_id="evidence_06",
            file_path="evidence/databases/replica.sql",
            origin="database_snapshot",
            file_captured_at=parse_iso_timestamp("2026-09-18T10:14:22Z"),
            record_timestamp=parse_iso_timestamp("2026-09-10T10:00:00Z"),
            system_id="account_service",
            resource_id="account_005",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_05",
        )
        self.assertTrue(fact_late_file.is_event_time_proven)
        self.assertTrue(fact_late_file.is_record_event_admissible(audit_at))
        self.assertFalse(fact_late_file.is_file_admissible(audit_at))
        self.assertFalse(fact_late_file.is_temporally_admissible(audit_at))

        # Scenario 4: Container file captured pre-audit, but internal event occurred post-audit
        # Record is late -> inadmissible
        fact_late_record = EvidenceFact(
            file_id="evidence_01",
            file_path="evidence/logs/audit.log",
            origin="central_observability_export",
            file_captured_at=parse_iso_timestamp("2026-09-15T11:59:39Z"),
            record_timestamp=parse_iso_timestamp("2026-09-15T12:01:00Z"),
            system_id="account_service",
            resource_id="account_005",
            data_category="USER_PROFILE",
            raw_event=None,
            status_or_state="PRESENT",
            matched_identifier_field="user_id",
            matched_identifier_value="user_05",
        )
        self.assertTrue(fact_late_record.is_event_time_proven)
        self.assertFalse(fact_late_record.is_record_event_admissible(audit_at))
        self.assertTrue(fact_late_record.is_file_admissible(audit_at))
        self.assertFalse(fact_late_record.is_temporally_admissible(audit_at))

    # -----------------------------------------------------------------------
    # 4. Identity Resolution Tests for user_12 (Direct Historical Hash Recovery)
    # -----------------------------------------------------------------------

    def test_identity_resolution_user_12(self) -> None:
        """
        Verify user_12 identity graph and direct historical hash recovery:
        - Current Email: minjun.kim@gmail.com
        - Historical Email (audit_282): minjun.kim90@gmail.com
        - Current Hash: 6e34ae5737be5401d915eb47a87a17264110c5a4e61c06f20b6a121f1520b9d2
        - Historical Hash (audit_283): 44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e
        """
        subject = self.resolver.resolve_by_user_id("user_12")
        self.assertIsNotNone(subject)
        self.assertEqual(subject.user_id, "user_12")
        self.assertEqual(subject.name, "Min-jun Kim")
        self.assertEqual(subject.current_email, "minjun.kim@gmail.com")
        self.assertEqual(subject.current_phone, "+82 10 2466 4678")

        # Verify historical email recovered directly from user_audit_log.csv
        self.assertIn("minjun.kim90@gmail.com", subject.historical_emails)
        self.assertIn("minjun.kim@gmail.com", subject.all_emails())
        self.assertIn("minjun.kim90@gmail.com", subject.all_emails())

        # Verify pre-recorded historical hash recovered directly
        expected_hist_hash = "44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e"
        expected_curr_hash = "6e34ae5737be5401d915eb47a87a17264110c5a4e61c06f20b6a121f1520b9d2"
        self.assertIn(expected_hist_hash, subject.historical_email_hashes)
        self.assertIn(expected_hist_hash, subject.all_hashes())
        self.assertIn(expected_curr_hash, subject.all_hashes())

        # Verify resolution by current email
        res_curr_email = self.resolver.resolve_by_email("minjun.kim@gmail.com")
        self.assertIsNotNone(res_curr_email)
        self.assertEqual(res_curr_email.user_id, "user_12")

        # Verify resolution by historical email
        res_hist_email = self.resolver.resolve_by_email("minjun.kim90@gmail.com")
        self.assertIsNotNone(res_hist_email)
        self.assertEqual(res_hist_email.user_id, "user_12")

        # Verify resolution by historical hash (direct match)
        res_hist_hash = self.resolver.resolve_by_hash(expected_hist_hash)
        self.assertIsNotNone(res_hist_hash)
        self.assertEqual(res_hist_hash.user_id, "user_12")

        # Verify resolution by current hash
        res_curr_hash = self.resolver.resolve_by_hash(expected_curr_hash)
        self.assertIsNotNone(res_curr_hash)
        self.assertEqual(res_curr_hash.user_id, "user_12")

        # Verify polymorphic identifier matching
        self.assertTrue(subject.matches_identifier("email", "minjun.kim90@gmail.com"))
        self.assertTrue(subject.matches_identifier("user_email", "minjun.kim@gmail.com"))
        self.assertTrue(subject.matches_identifier("correlation_key", expected_hist_hash))
        self.assertTrue(subject.matches_identifier("email_hash", expected_curr_hash))
        self.assertTrue(subject.matches_identifier("user_id", "user_12"))
        self.assertTrue(subject.matches_identifier("phone", "+821024664678"))

    # -----------------------------------------------------------------------
    # 5. Identity Resolution Tests for user_30 (Direct Historical Hash Recovery)
    # -----------------------------------------------------------------------

    def test_identity_resolution_user_30(self) -> None:
        """
        Verify user_30 identity graph and direct historical hash recovery:
        - Current Email: camille.bernard@outlook.com
        - Historical Email (audit_280): camille.bernard86@outlook.com (used in case_30 request)
        - Current Hash: 81310fd2f1e102930bc5f18c2d42a74786e74ce9e603fadcefe9caf8065081bc
        - Historical Hash (audit_281): b891c158feafa1949f0b023518725836228066adc1500488528cae6d799b3bef
        """
        subject = self.resolver.resolve_by_user_id("user_30")
        self.assertIsNotNone(subject)
        self.assertEqual(subject.user_id, "user_30")
        self.assertEqual(subject.name, "Camille Bernard")
        self.assertEqual(subject.current_email, "camille.bernard@outlook.com")

        # Verify historical email recovered directly
        self.assertIn("camille.bernard86@outlook.com", subject.historical_emails)
        self.assertIn("camille.bernard86@outlook.com", subject.all_emails())

        # Verify historical hash recovered directly
        expected_hist_hash = "b891c158feafa1949f0b023518725836228066adc1500488528cae6d799b3bef"
        expected_curr_hash = "81310fd2f1e102930bc5f18c2d42a74786e74ce9e603fadcefe9caf8065081bc"
        self.assertIn(expected_hist_hash, subject.historical_email_hashes)
        self.assertIn(expected_hist_hash, subject.all_hashes())
        self.assertIn(expected_curr_hash, subject.all_hashes())

        # Verify resolution by request email (case_30 submitted historical email!)
        res_req_email = self.resolver.resolve_by_email("camille.bernard86@outlook.com")
        self.assertIsNotNone(res_req_email)
        self.assertEqual(res_req_email.user_id, "user_30")

        # Verify resolution by historical hash
        res_hist_hash = self.resolver.resolve_by_hash(expected_hist_hash)
        self.assertIsNotNone(res_hist_hash)
        self.assertEqual(res_hist_hash.user_id, "user_30")

    # -----------------------------------------------------------------------
    # 6. Null & Sentinel Identifier Rejection Tests
    # -----------------------------------------------------------------------

    def test_null_and_empty_identifiers_rejected(self) -> None:
        """
        Validation requirement: Ensure null identifiers cannot create identity matches.
        """
        subject_12 = self.resolver.resolve_by_user_id("user_12")
        self.assertIsNotNone(subject_12)

        # Resolver lookup rejection
        self.assertIsNone(self.resolver.resolve_by_email(None))
        self.assertIsNone(self.resolver.resolve_by_email(""))
        self.assertIsNone(self.resolver.resolve_by_email("   "))
        self.assertIsNone(self.resolver.resolve_by_email("null"))
        self.assertIsNone(self.resolver.resolve_by_hash(None))
        self.assertIsNone(self.resolver.resolve_by_hash(""))
        self.assertIsNone(self.resolver.resolve_by_hash("undefined"))
        self.assertIsNone(self.resolver.resolve_by_user_id(None))
        self.assertIsNone(self.resolver.resolve_by_user_id(""))
        self.assertIsNone(self.resolver.resolve_by_identifier("email", None))
        self.assertIsNone(self.resolver.resolve_by_identifier("email", ""))
        self.assertIsNone(self.resolver.resolve_by_identifier("email", "null"))

        # Subject matching rejection
        self.assertFalse(subject_12.matches_identifier("email", None))
        self.assertFalse(subject_12.matches_identifier("email", ""))
        self.assertFalse(subject_12.matches_identifier("email", "   "))
        self.assertFalse(subject_12.matches_identifier("email", "null"))
        self.assertFalse(subject_12.matches_identifier("email", "none"))
        self.assertFalse(subject_12.matches_identifier("email", "N/A"))
        self.assertFalse(subject_12.matches_identifier("correlation_key", None))
        self.assertFalse(subject_12.matches_identifier("correlation_key", ""))
        self.assertFalse(subject_12.matches_identifier("user_id", None))
        self.assertFalse(subject_12.matches_identifier("user_id", ""))

    # -----------------------------------------------------------------------
    # 7. Unrelated Decoy Rejection Tests
    # -----------------------------------------------------------------------

    def test_unrelated_and_decoy_identifiers_rejected(self) -> None:
        """
        Validation requirement: Ensure unrelated users and decoys cannot match.
        """
        subject_12 = self.resolver.resolve_by_user_id("user_12")
        self.assertIsNotNone(subject_12)

        # Unrelated user_id
        self.assertFalse(subject_12.matches_identifier("user_id", "user_30"))
        self.assertFalse(subject_12.matches_identifier("user_id", "user_9999"))

        # Unrelated decoy accounts from evidence files
        self.assertFalse(subject_12.matches_identifier("account_id", "account_8741"))
        self.assertFalse(subject_12.matches_identifier("customer_reference", "backup_3933"))

        # Unrelated email and phone
        self.assertFalse(subject_12.matches_identifier("email", "camille.bernard@outlook.com"))
        self.assertFalse(subject_12.matches_identifier("email", "random.stranger@domain.com"))
        self.assertFalse(subject_12.matches_identifier("phone", "+1 555 019 2834"))

        # Resolver does not match non-existent users
        self.assertIsNone(self.resolver.resolve_by_email("nonexistent.user@fake.com"))
        self.assertIsNone(self.resolver.resolve_by_user_id("user_fake_000"))
        self.assertIsNone(self.resolver.resolve_by_hash("0000000000000000000000000000000000000000000000000000000000000000"))

    # -----------------------------------------------------------------------
    # 8. Multi-Hop Historical Identifier Recovery Tests (user_10)
    # -----------------------------------------------------------------------

    def test_multi_hop_historical_identity_user_10(self) -> None:
        """
        F-04: Verify multi-hop historical identifier changes using actual dataset
        records for user_10. Do not hardcode a fabricated identity mapping.

        Actual dataset records:
        user_identities.csv:
          user_10,Nadia Petrescu,n.petrescu@yahoo.com,+40 723 481 638,6385b5b5e70720c197abedd379f714bb84330a9c7bc86bbb4bfbc4405bdba326,2026-04-12T14:38:26Z
        user_audit_log.csv:
          audit_121,user_10,2025-12-13T08:17:43Z,email,nadia.ionescu@yahoo.com,nadia.petrescu@yahoo.com
          audit_122,user_10,2025-12-13T08:17:43Z,email_hash,708ef5640eec7c7aa89a6dc39793c5df6f9bca6968397f46a8f44ff1bdde75f5,e407f542e6f638d23b7efa7c74bacfb3ee6c3991ca6625ad36c8dcb7dffa144a
          audit_238,user_10,2026-04-12T14:38:26Z,email,nadia.petrescu@yahoo.com,n.petrescu@yahoo.com
          audit_239,user_10,2026-04-12T14:38:26Z,email_hash,e407f542e6f638d23b7efa7c74bacfb3ee6c3991ca6625ad36c8dcb7dffa144a,6385b5b5e70720c197abedd379f714bb84330a9c7bc86bbb4bfbc4405bdba326
        """
        subject = self.resolver.resolve_by_user_id("user_10")
        self.assertIsNotNone(subject, "user_10 must resolve from actual dataset records")
        self.assertEqual(subject.user_id, "user_10")
        self.assertEqual(subject.name, "Nadia Petrescu")
        self.assertEqual(subject.current_email, "n.petrescu@yahoo.com")
        self.assertEqual(subject.current_phone, "+40 723 481 638")

        # Hop 1 (earliest recorded): nadia.ionescu@yahoo.com
        # Hop 2 (intermediate): nadia.petrescu@yahoo.com
        # Current: n.petrescu@yahoo.com
        self.assertIn("nadia.ionescu@yahoo.com", subject.historical_emails)
        self.assertIn("nadia.petrescu@yahoo.com", subject.historical_emails)
        self.assertEqual(
            subject.all_emails(),
            frozenset({"nadia.ionescu@yahoo.com", "nadia.petrescu@yahoo.com", "n.petrescu@yahoo.com"}),
        )

        # Multi-hop pre-recorded historical hashes:
        hash_hop1 = "708ef5640eec7c7aa89a6dc39793c5df6f9bca6968397f46a8f44ff1bdde75f5"
        hash_hop2 = "e407f542e6f638d23b7efa7c74bacfb3ee6c3991ca6625ad36c8dcb7dffa144a"
        hash_curr = "6385b5b5e70720c197abedd379f714bb84330a9c7bc86bbb4bfbc4405bdba326"

        self.assertIn(hash_hop1, subject.historical_email_hashes)
        self.assertIn(hash_hop2, subject.historical_email_hashes)
        self.assertEqual(
            subject.all_hashes(),
            frozenset({hash_hop1, hash_hop2, hash_curr}),
        )

        # Multi-index resolution across all hops
        # Resolving via hop 1 email
        res_hop1 = self.resolver.resolve_by_email("nadia.ionescu@yahoo.com")
        self.assertIsNotNone(res_hop1)
        self.assertEqual(res_hop1.user_id, "user_10")

        # Resolving via hop 2 (intermediate) email
        res_hop2 = self.resolver.resolve_by_email("nadia.petrescu@yahoo.com")
        self.assertIsNotNone(res_hop2)
        self.assertEqual(res_hop2.user_id, "user_10")

        # Resolving via current email
        res_curr = self.resolver.resolve_by_email("n.petrescu@yahoo.com")
        self.assertIsNotNone(res_curr)
        self.assertEqual(res_curr.user_id, "user_10")

        # Resolving via hop 1 historical hash
        res_hash1 = self.resolver.resolve_by_hash(hash_hop1)
        self.assertIsNotNone(res_hash1)
        self.assertEqual(res_hash1.user_id, "user_10")

        # Resolving via hop 2 historical hash
        res_hash2 = self.resolver.resolve_by_hash(hash_hop2)
        self.assertIsNotNone(res_hash2)
        self.assertEqual(res_hash2.user_id, "user_10")

        # Resolving via current hash
        res_hash_curr = self.resolver.resolve_by_hash(hash_curr)
        self.assertIsNotNone(res_hash_curr)
        self.assertEqual(res_hash_curr.user_id, "user_10")

        # Polymorphic identifier matching on all historical and current values
        self.assertTrue(subject.matches_identifier("email", "nadia.ionescu@yahoo.com"))
        self.assertTrue(subject.matches_identifier("email", "nadia.petrescu@yahoo.com"))
        self.assertTrue(subject.matches_identifier("user_email", "n.petrescu@yahoo.com"))
        self.assertTrue(subject.matches_identifier("correlation_key", hash_hop1))
        self.assertTrue(subject.matches_identifier("email_hash", hash_hop2))
        self.assertTrue(subject.matches_identifier("lookup_key", hash_curr))
        self.assertTrue(subject.matches_identifier("phone", "+40723481638"))


if __name__ == "__main__":
    unittest.main()
