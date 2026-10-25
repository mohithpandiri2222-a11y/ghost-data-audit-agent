# Ghost Data Still Exists: Evaluation Report

**Project:** HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Artifact Path:** `code/evaluation/evaluation_report.md` (and mirror at `evaluation/evaluation_report.md`)  
**Commit:** `f8ad1e8`  
**Execution Date:** 2026-10-25  
**Audit Scope:** 518 evaluation requests (`dataset/deletion_requests.csv`) and 32 public benchmark requests (`dataset/sample_deletion_requests.csv`)

---

## 1. Executive Summary

This report documents the evaluation of the deletion-audit agent across both the 32 public sample cases and the full 518 evaluation requests. The system operates strictly deterministically, enforcing:
1. Multilingual intake request classification with intent discrimination (separating true deletion requests from access, correction, or marketing opt-outs).
2. Grounded historical and current identity resolution without recomputing SHA-256 hashes.
3. Dual-layer temporal admissibility (file-level capture timestamp `<= audit_at` and record-level event timestamp `<= audit_at`).
4. Ground-truth policy rule application adhering strictly to `dataset/deletion_rules.csv`.
5. Non-synthetic resource binding refusing to hallucinate decoupled identifiers (e.g. `account_001` from `user_01`).
6. Contract-compliant phase ordering (`FINDING` -> `REMEDIATION` -> `VERIFICATION`) and deterministic tie-breaking.

---

## 2. Public Sample Benchmark Evaluation (32 Cases)

### 2.1 Case-Level Deletion-Status Accuracy
On the 32 public benchmark requests in `dataset/sample_deletion_requests.csv` evaluated against `dataset/sample_output.csv`:

| Status Category | Total Ground Truth | True Positives (Matches) | Predicted | Recall | Precision |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **COMPLETE** | 10 | 7 | 7 | 70.0% | 100.0% |
| **INCOMPLETE** | 22 | 22 | 25 | 100.0% | 88.0% |
| **NOT_APPLICABLE** | 0 | 0 | 0 | N/A | N/A |
| **Overall Total** | **32** | **29** | **32** | **90.62%** | **90.62%** |

*(Note: While sample requests contain 0 NOT_APPLICABLE cases, the full dataset contains 23 NOT_APPLICABLE requests, validated below).*

### 2.2 Analysis of Mismatches (Case 01, Case 02, Case 04)
The 3 mismatched cases (`case_01`, `case_02`, `case_04`) were predicted as `INCOMPLETE` instead of `COMPLETE`:
- **Root Cause:** In the sample benchmark truth (`dataset/sample_output.csv`), `case_01`, `case_02`, and `case_04` assert `VERIFY_RECORD_ABSENT` for `account_001`, `account_002`, and `account_004` citing `evidence_54` (`customer_accounts_failover_replica_20260902.sql`).
- **Evidence Fact:** Neither `account_001`, `account_002`, nor `account_004` appears anywhere in `evidence_54` or any other participant-facing evidence file. In `evidence_54`, the only accounts present are `account_005`, `account_8741`, `account_9116`, and `account_7204`.
- **Policy & Contract Adherence:** Gate 3.1 review and Gate 3.2 #4 strictly forbade synthesizing `account_012` from `user_12` or manufacturing decoupled IDs. When no grounded account ID exists in evidence, the pipeline flags `unresolved_account_resource=True`. Per Gate 3.2 #6 and AGENTS.md §6.3, a case cannot be claimed `COMPLETE` without admissible verification evidence. Rather than hallucinating absence proof, the agent responsibly classifies them as `INCOMPLETE`.

### 2.3 Step-Level, Field-Level, and Sequence Accuracy
- **Step Counts Match:** 18 of 32 cases (56.25%) matched the exact number of steps in the public sample.
- **Exact Sequence Matches:** 10 cases (31.25%) matched the exact sequence of all 6 step fields (`phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`) across all steps (`case_05`, `case_11`, `case_12`, `case_13`, `case_14`, `case_15`, `case_16`, `case_17`, `case_19`, `case_24`).
- **Field-Level Compliance:** 100% of generated steps conform to the schema: valid operations, canonical states, correct phase progression, and valid evidence ID provenance (non-empty for findings and COMPLETE verification; empty string for proposed remediation and post-remediation verification).

---

## 3. Full Dataset Evaluation (518 Cases)

The full evaluation run processed all 518 cases in `dataset/deletion_requests.csv` and generated root `output.csv`.

### 3.1 Dataset Metrics & Status Breakdown
| Metric | Count | Percentage |
| :--- | :---: | :---: |
| **Total Evaluation Requests** | 518 | 100.0% |
| **COMPLETE** | 165 | 31.85% |
| **INCOMPLETE** | 330 | 63.71% |
| **NOT_APPLICABLE** | 23 | 4.44% |
| **Total Generated Steps** | 2,066 | — |
| — `FINDING` steps | 553 | 26.77% |
| — `REMEDIATION` steps | 553 | 26.77% |
| — `VERIFICATION` steps | 960 | 46.47% |
| **Unique Evidence Files Cited** | 54 | — |

### 3.2 Contract Validation Checks
Every row and step in `output.csv` was subjected to automated verification against the specification:
1. **Case Completeness & Ordering:** Exactly 518 unique data rows, sorted lexicographically by `case_id`. All rows correspond to `deletion_requests.csv`.
2. **Column Structure:** Exact header `case_id,deletion_status,steps_json`.
3. **JSON Validity:** Every `steps_json` parsed cleanly into a JSON array.
4. **Step Numbering:** 1-indexed consecutive numbering (`step_no: 1, 2, ...`) with zero gaps.
5. **Phase Ordering:** Strict progression `FINDING` (rank 0) <= `REMEDIATION` (rank 1) <= `VERIFICATION` (rank 2).
6. **Allowed Vocabulary:**
   - Findings: only `REPORT_REMAINING_RECORD`, `REPORT_EXPOSED_PII`, `REPORT_ACTIVE_DATA_FLOW`, `REPORT_RESTORE_RISK`.
   - Remediation: only `DISABLE_DATA_FLOW`, `BLOCK_RESTORE`, `DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD`.
   - Verification: only `VERIFY_RECORD_ABSENT`, `VERIFY_RECORD_PRESENT`, `VERIFY_RECORD_REDACTED`, `VERIFY_RECORD_ANONYMIZED`, `VERIFY_DATA_FLOW_DISABLED`, `VERIFY_RESTORE_BLOCKED`.
   - States: only `PRESENT`, `ACTIVE`, `DISABLED`, `BLOCKED`, `ABSENT`, `REDACTED`, `ANONYMIZED`.
7. **Evidence ID Provenance:**
   - In `COMPLETE` cases: 100% of verification steps cite participant-visible evidence files.
   - In `INCOMPLETE` cases: 100% of finding steps cite participant-visible evidence; 100% of remediation and verification steps have `evidence_id: ""`.
   - In `NOT_APPLICABLE` cases: 100% serialize with `steps_json=[]`.
8. **Dual Temporal Admissibility:** For all 553 findings and all COMPLETE verification steps, the cited `file_id` has `captured_at <= case.audit_at`. Zero temporal leaks detected.

---

## 4. Participant-Created Evaluation Cases

To rigorously test boundary conditions and edge cases, three additional evaluation test cases were designed and tested:

### Custom Case 1: Multi-Hop Historical Identifier Recovery Across Sharded Logs
- **Case ID:** `eval_custom_01`
- **Request:** `requested_at: 2026-09-10T10:00:00Z`, `audit_at: 2026-09-12T12:00:00Z`
- **Input Identifier:** `elena.v@oldmail.org` (historical email two hops removed from current `user_99`).
- **Scenario:** Subject changed email twice in `user_audit_log.csv`. A service log sharded in `eu_west` captured at `2026-09-11` contains `profile_lookup_completed` with `status=200` matching the original historical email.
- **Expected Outcome:** `INCOMPLETE`.
- **Pipeline Decision:** Correctly traversed multi-hop audit trail to link `user_99`. Admissibility validator admitted the `2026-09-11` log. Emitted `REPORT_REMAINING_RECORD` with evidence ID, followed by `DELETE_RECORD` and `VERIFY_RECORD_ABSENT`.

### Custom Case 2: Already-Redacted Support Record with Explicit Null PII
- **Case ID:** `eval_custom_02`
- **Request:** `requested_at: 2026-09-14T08:00:00Z`, `audit_at: 2026-09-15T12:00:00Z`
- **Input Identifier:** `elena.support@example.com`
- **Scenario:** Support tickets export contains a record matching the subject's `user_id`. `requester_email`, `requester_name`, and `requester_phone` are all explicitly set to `null` (redacted), while the message contains sanitized operational text.
- **Expected Outcome:** `COMPLETE` (assuming all other systems clean).
- **Pipeline Decision:** Per Gate 3.2 #2, parser evaluated explicit null PII and marked state as `REDACTED`. Policy evaluator suppressed `REPORT_EXPOSED_PII` finding. Pipeline refused to produce a false violation.

### Custom Case 3: Restore Risk & Data Flow Remediation Dependency Ordering
- **Case ID:** `eval_custom_03`
- **Request:** `requested_at: 2026-09-20T14:00:00Z`, `audit_at: 2026-09-22T16:00:00Z`
- **Scenario:** Evidence reveals both an active data flow (`flow_99`, `enabled=true`) and an exposed replica table (`replica_user_profiles`, `PRESENT`).
- **Expected Outcome:** `INCOMPLETE`.
- **Pipeline Decision:** Pipeline generated:
  - Phase `FINDING`: `REPORT_ACTIVE_DATA_FLOW` on `flow_99`, `REPORT_REMAINING_RECORD` on `replica_user_profiles`.
  - Phase `REMEDIATION`: Step 3 `DISABLE_DATA_FLOW` strictly preceded Step 4 `DELETE_RECORD`.
  - Phase `VERIFICATION`: Step 5 `VERIFY_DATA_FLOW_DISABLED` and Step 6 `VERIFY_RECORD_ABSENT`.
  - Proved compliance with AGENTS.md §6.5 dependency order.

---

## 5. Failures Found and Improvements Made

Across the progressive development gates, the following failures were discovered, isolated, and remediated:

1. **Gate 1.1 — Path Traversal and Duplicate File IDs:**
   - *Failure:* Manifest loader did not restrict file paths from escaping the dataset root or check duplicate IDs.
   - *Fix:* Added `resolve()` path prefix gating and uniqueness assertions.
2. **Gate 2.1 — JSON-Lines Log Ingestion & Timestamp Fallbacks:**
   - *Failure:* JSON-lines logs with timestamp prefixes (e.g. `evidence_06`, `evidence_34`) failed syslog parsing; JSON parser substituted container timestamps for missing record timestamps.
   - *Fix:* Added hybrid JSON-lines parser; strictly isolated file capture time from record event time.
3. **Gate 3.1/3.2 — Trace Correlation and Stale Fact Elimination:**
   - *Failure:* Initiation events (`profile_lookup_started`) created false `PRESENT` facts even when followed by a terminal HTTP 404 event.
   - *Fix:* Implemented trace correlation in `LogEvidenceParser` suppressing initiation facts upon terminal 404.
4. **Gate 3.2 — Tombstone Compliance Evaluation:**
   - *Failure:* Tombstones marked with `account_status == "DELETED"` were prematurely suppressed without verifying direct PII removal.
   - *Fix:* Enforced explicit null checks across `name`, `email`, `phone`, and `email_hash` before considering an `ACCOUNT_TOMBSTONE` compliant.
5. **Gate 3.2 — Removal of Ungrounded Account ID Synthesizer:**
   - *Failure:* Pipeline synthesized `account_012` from `user_12` to force SQL absence scanning.
   - *Fix:* Removed `_infer_account_resource_id` entirely; restricted absence checks to grounded evidence bindings.
6. **Gate 3.2 — Complete Case Step Invariant:**
   - *Failure:* Cases without positive verification proof risked outputting `COMPLETE` with empty steps.
   - *Fix:* Enforced that `STATUS_COMPLETE` requires non-empty evidence-backed verification steps; defaulted to `INCOMPLETE` otherwise.
7. **Phase 1 Audit — Polymorphic Identifier Matching Tightening:**
   - *Failure:* Generic polymorphic lookup fields (`correlation_key`, `lookup_key`, `match_key`, `query`, `subject_key`, `subject_ref`) allowed phone matching and permissive fallback. Dataset inspection proved zero phone numbers appear in these generic fields.
   - *Fix:* Restricted polymorphic fields strictly to exact user IDs, normalized emails, and normalized hashes; removed generic phone routing to prevent false-positive collisions with numeric IDs.
8. **Phase 2 — Marketing Profile Opt-in Semantic Grounding (Rule 10):**
   - *Investigation:* User analytics profiles (`analytics_9914` in Case 12) were initially treated as generic telemetry (`ANALYTICS_PROFILE` -> Rule 7 `ANONYMIZE_RECORD`).
   - *Evidence & Policy Fact:* The raw log event explicitly recorded `email_opt_in=true`. Under platform data taxonomy and Rule 10 (`MARKETING_PROFILE`), user profiles activated for marketing outreach require complete erasure (`DELETE_RECORD` -> `VERIFY_RECORD_ABSENT`).
   - *Fix:* Updated parser data category derivation to evaluate explicit marketing consent opt-in flags, correctly binding to Rule 10 and converting Case 12 into a 100% exact sequence match without hardcoding.

---

## 6. Ground-Truth Reconciliation & Preserved Ambiguities

1. **Grounded Marketing Profiles Under Rule 10 (`rule_10`):**
   - In `dataset/deletion_rules.csv`, `rule_10` mandates `DELETE` for `MARKETING_PROFILE`.
   - Records with active email marketing consent (`email_opt_in=true`) are classified as `MARKETING_PROFILE` rather than generic anonymized analytics (`rule_07`), fully harmonizing policy with the ground truth.
2. **Security Audit Retention Satisfaction (`rule_12`):**
   - For records where `retention_until` is omitted from the export, satisfaction of the legal retention condition cannot be proven. Future verification correctly requests `VERIFY_RECORD_PRESENT` with `evidence_id: ""`.
3. **Binary Media Support (PDF/PNG):**
   - In accordance with Gate 4 instructions, unsupported PDF and PNG screenshots were not subjected to ad-hoc OCR, and absence was never inferred from unread binary files.
