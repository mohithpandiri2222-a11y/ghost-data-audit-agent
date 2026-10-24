# Step 2 Final Reconciliation Report: Ground-Truth Evidence Audit (Corrected)

**Project:** HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Artifact Path:** `code/evaluation/reconciliation_report.md`  
**Revision:** 2.1 (Scope & Evidence Precision Correction)  
**Location Rationale:** Conforming to README.md lines 91–99 and AGENTS.md §6.8, all audit and evaluation reports are located in `code/evaluation/` to ensure inclusion in `code.zip` while preserving the clean repository layout.  
**Audit Scope:** Deep-dive ground-truth verification of sample cases (`case_12`, `case_05`, `case_09`, `case_20`, `case_30`, `case_25`, `case_11`), cross-referenced against `dataset/deletion_rules.csv`, `dataset/evidence_files.csv`, `dataset/system_activity.csv`, `dataset/user_identities.csv`, `dataset/user_audit_log.csv`, and participant-facing evidence files.

---

## Change Note & Revision History (v2.1)

This revision implements targeted corrections to ensure strict adherence to ground truth and the project specification:
1. **Strict Dual Temporal Admissibility Enforced (§A.1, §B.3, §C):** Enforced that an evidence file is admissible only if `captured_at <= audit_at` and individual records/events are `<= audit_at`. An event from a file captured after `audit_at` cannot be used as admissible evidence merely because the event timestamp is older. Consequently, for `case_09`, `evidence_06` (captured 2026-09-18) is inadmissible at `audit_at` (`2026-09-16T09:00:00Z`), leaving verification states for `account_3960` and `audit_record_4902` unproven from admissible evidence. For `case_30`, `evidence_02` (captured 2026-09-17) is likewise inadmissible at `audit_at` (`2026-09-15T12:00:00Z`), leaving `audit_record_1707` unproven from admissible evidence.
2. **Case 12 Analytics Policy Conflict Strictly Unresolved (§B.2, §D.1, §E.3):** Removed any proposed override or rule converting `email_opt_in=true` or attempted `DELETE_RECORD` into a deterministic `MARKETING_PROFILE` classification. Activity logs prove only what the workflow attempted, not policy correctness. The conflict between `rule_07` (`ANALYTICS_PROFILE -> ANONYMIZE`) and `sample_output.csv:13` (`DELETE_RECORD`) remains explicitly unresolved.
3. **Security Audit Retention Condition Separated (§B.1, §D.2):** Separated proof that an audit record exists and links to the subject from proof that its retention condition is satisfied. Removed any statement treating missing `retention_until` as an assumed policy default. Where `retention_until` is absent, satisfaction of `rule_12`'s retention condition is strictly unproven.
4. **Case 25 Evidence vs. Global Absence Distinction (§B.4, §C):** Distinguished the 3 verification steps observed directly in `evidence_92` (`account_3136` 404, `analytics_1895` null identifiers, `audit_record_451` retention until 2031) from global absence across the entire system. Documented the search across 79 text/SQL/log/JSON files and 4 decompressed PDFs; explicitly stated that because the 11 PNG screenshots were not subjected to full OCR/visual inspection in this turn, absolute global absence across all binary representations remains unproven.
5. **Terminology Precision:** Audited all uses of "confirmed", "verified", and "unproven" to ensure that only claims with direct, admissible, participant-facing evidence are labeled confirmed.

---

## Executive Summary

1. **System State Over Workflow Claims:** Deletion workflows report `COMPLETE` while secondary replicas (`case_05`), restore paths (`case_09`), search indexes (`case_20`, `case_30`), support tickets (`case_30`), or analytics records (`case_12`, `case_30`) retain personal data. Conversely, a workflow reporting failure or `NOT_STARTED` can have its required deletion state established on admissible evidence at `audit_at` (`case_25`).
2. **Pre-Grounded Identity Resolution:** Historical emails and historical SHA-256 hashes are pre-recorded in `dataset/user_audit_log.csv`. The audit agent must trace audit log chains directly rather than attempting dynamic hash re-computation or guessing.
3. **Strict Dual Temporal Rule:** An evidence file is admissible *only* if its manifest `captured_at <= audit_at`. Within an admissible file, each record/event timestamp must also be `<= audit_at`. Evidence files captured after `audit_at` are wholly inadmissible.
4. **Evidence ID Provenance:**
   - In `COMPLETE` cases (`case_25`), verification steps cite participant-visible evidence IDs (`evidence_id: "evidence_92"`) proving compliance at `audit_at`.
   - In `INCOMPLETE` cases, finding steps cite participant-visible evidence IDs, while remediation and post-remediation verification steps **must** use `evidence_id: ""` because they describe future corrective work.
5. **Preserved Ambiguities:**
   - `analytics_9914` in `case_12` uses `DELETE_RECORD`, conflicting with `rule_07` (`ANONYMIZE`). The policy justification remains unresolved; activity logs establish what was attempted, not what policy dictates.
   - For `audit_record_4902` (`case_09`), `audit_record_5569` (`case_20`), `audit_record_1707` (`case_30`), and `audit_record_9394` (`case_11`), `retention_until` is absent from `dataset/`, leaving compliance with `rule_12`'s retention condition unproven.

---

## Section A. Confirmed Corrections

The following principles are confirmed by raw evidence and the project specification:

### A.1. Strict Dual Temporal Admissibility Contract
* **Specification Mandate:**
  - AGENTS.md §6.2: "Use only information available at or before audit_at when deciding the case. Evidence created later must not change the answer for that case."
  - AGENTS.md §6.6: "Never cite organizer-only truth or an evidence item captured after the case's audit_at."
* **Dual Timestamp Requirement:**
  1. **File-Level:** An evidence file is admissible only if `evidence_files.csv` records `captured_at <= audit_at`.
  2. **Record-Level:** An individual entry inside an admissible file is admissible only if `observed_at <= audit_at` or `event_time <= audit_at`.
  3. **Strict Inadmissibility:** A file captured after `audit_at` cannot be used to prove findings or verification states for that case, regardless of whether internal event timestamps precede `audit_at`.
* **Admissibility Status Across Audited Sample Cases:**
  - `case_05` (`audit_at: 2026-09-08T13:40:00Z`): `evidence_54` captured `2026-09-02T23:00:00Z` <= `audit_at`. [**ADMISSIBLE**]
  - `case_09` (`audit_at: 2026-09-16T09:00:00Z`):
    - `evidence_93` (`customer_data_inventory_20260916.sql`) captured `2026-09-16T08:37:39Z` <= `audit_at`. [**ADMISSIBLE**]
    - `evidence_06` (`structured_service_events_eu_west_20260918.log`) captured `2026-09-18T11:55:24Z` > `audit_at`. [**INADMISSIBLE**]
  - `case_12` (`audit_at: 2026-09-15T12:00:00Z`): `evidence_01` captured `2026-09-15T11:59:39Z` <= `audit_at`. [**ADMISSIBLE**]
  - `case_20` (`audit_at: 2026-09-26T11:00:00Z`): `evidence_94` captured `2026-09-26T10:38:56Z` <= `audit_at`. [**ADMISSIBLE**]
  - `case_25` (`audit_at: 2026-09-15T12:00:00Z`): `evidence_92` captured `2026-09-15T11:44:55Z` <= `audit_at`. [**ADMISSIBLE**]
  - `case_30` (`audit_at: 2026-09-15T12:00:00Z`):
    - `evidence_92` (`service_resource_export_20260915_114455.json`) captured `2026-09-15T11:44:55Z` <= `audit_at`. [**ADMISSIBLE**]
    - `evidence_02` (`customer_data_snapshot_bundle_20260917.json`) captured `2026-09-17T12:00:00Z` > `audit_at`. [**INADMISSIBLE**]
  - `case_11` (`audit_at: 2026-10-01T12:00:00Z`): `evidence_03` captured `2026-10-01T12:00:00Z` <= `audit_at`. [**ADMISSIBLE**]

### A.2. Identity Resolution & Historical Hash Recovery
* **Specification Mandate:** AGENTS.md §6.1, §6.5: Resolve current and historical identifiers. The request email may match a past email.
* **Ground-Truth Confirmations:**
  - `case_12`: Request email `valerie.lemoine@outlook.com` links to current `user_12` via `dataset/user_audit_log.csv:283` (`audit_282`). Line 284 (`audit_283`) explicitly provides the old SHA-256 hash `44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e`. This matches `correlation_key` in `service_events_ap_south_20260915.log:92`.
  - `case_30`: Request email `camille.bernard86@outlook.com` links to current `user_30` via `user_audit_log.csv:281` (`audit_280`). This historical email matches remnants across search, analytics, support, and integration services in `evidence_92`.
  - **Correction:** Historical email hashes are pre-computed and stored in `user_audit_log.csv`. No client-side hashing algorithms or normalization routines need to be guessed.

### A.3. Evidence ID Provenance Contract
* **Specification Mandate:** AGENTS.md §6.3, §6.6:
  - Findings cite participant-visible evidence IDs.
  - Proposed remediation and future verification steps in `INCOMPLETE` cases use `evidence_id: ""` because they describe future work.
  - Verification steps in `COMPLETE` cases cite evidence proving the state at `audit_at`.
* **Ground-Truth Confirmations:**
  - In `case_05`, `case_09`, `case_12`, `case_20`, `case_30`, `case_11`: finding steps cite valid `file_id` values; remediation and verification steps strictly use `evidence_id: ""`.
  - In `case_25` (`COMPLETE`): all 3 verification steps cite `evidence_92` (`account_3136` 404, `audit_record_451` PRESENT, `analytics_1895` ANONYMIZED).

### A.4. Remediation Precedence Order
* **Specification Mandate:** AGENTS.md §6.5: "Within remediation, disable data flows and block unsafe restores before changing dependent records."
* **Ground-Truth Confirmations:**
  - In `case_20`: `DISABLE_DATA_FLOW` (Step 3) precedes `DELETE_RECORD` (Step 4).
  - In `case_30`: `DISABLE_DATA_FLOW` (Step 5) precedes `DELETE_RECORD`, `REDACT_RECORD`, and `ANONYMIZE_RECORD` (Steps 6–8).
  - In `case_11`: `DISABLE_DATA_FLOW` (Step 5) precedes `DELETE_RECORD`, `REDACT_RECORD`, and `ANONYMIZE_RECORD` (Steps 6–8).
  - In `case_09`: `BLOCK_RESTORE` (Step 2) is the primary remediation action.

### A.5. Decoy Discrimination Mechanics
* **Specification Mandate:** AGENTS.md §6.1, §6.6: Connect evidence through contents and grounded links, not manifest names or resource prefixes.
* **Ground-Truth Confirmations:**
  - Confirmed rejection of decoys sharing schemas or files: `account_8741` (`user_8741`) in `customer_accounts_failover_replica_20260902.sql:14`, `backup_3933` (`user_62`) in `customer_data_inventory_20260916.sql:23`, `search_4324` in `resource_lookup_trace_20260926_103856.log:37`, and 40 unrelated shift handover items in `customer_account_handover_20261001.txt`. Decoys are excluded by subject mismatch.

---

## Section B. Findings Still Unproven

The following claims and hypotheses lack complete ground-truth support in participant-facing files:

### B.1. Satisfaction of Retention Condition for Security Audit Records
* **Observed Facts:**
  - `case_25`: `service_resource_export_20260915_114455.json:303` (`evidence_92`) contains `"retention_until": "2031-12-31T23:59:59Z"`. Because `2026-09-15` < `2031-12-31`, the retention condition in `rule_12` is proven satisfied.
  - `case_11`: `customer_account_handover_20261001.txt:40` (`evidence_03`) proves `audit_record_9394` exists and links to `user_32`.
* **Unproven Facts:**
  - For `audit_record_4902` (`case_09`), `audit_record_5569` (`case_20`), `audit_record_1707` (`case_30`), and `audit_record_9394` (`case_11`), **no `retention_until` timestamp exists in `dataset/`**.
  - `rule_12` states: `SECURITY_AUDIT_LOG | Record is within the supplied retention period | RETAIN`.
  - **Distinction:** Evidence proves the record exists and links to the user (except in case_20 where `audit_record_5569` is completely absent). However, evidence proving that the record is *within the supplied retention period* is **UNPROVEN**.

### B.2. Policy Rationale for `analytics_9914` `DELETE_RECORD`
* **Observed Facts:**
  - In `service_events_ap_south_20260915.log:92`, `analytics_9914` was logged under `service=analytics_platform` with `event=contact_lookup_completed rows=1 email_opt_in=true`.
  - In `system_activity.csv:3436`, `deletion_worker` submitted `DELETE_RECORD` for `analytics_9914` (which returned `FAILED`).
* **Unproven Facts:**
  - `deletion_rules.csv:8` mandates: `rule_07 | ANALYTICS_PROFILE | Record is still attributable to a user | ANONYMIZE`.
  - The dataset contains no rule defining `contact_lookup` or `email_opt_in=true` as a `MARKETING_PROFILE` (`rule_10` -> `DELETE`) or creating an exception to `rule_07`.
  - The hypothesis that `analytics_9914` was deleted because it was deemed marketing data is **INFERRED**.
  - The policy-correct treatment under participant-facing rules remains **UNPROVEN / UNRESOLVED**.

### B.3. Inadmissibility of Later-Captured Evidence Files
* **Observed Facts:**
  - In `case_09` (`audit_at: 2026-09-16T09:00:00Z`), the only evidence file referencing `account_3960` (profile 404) and `audit_record_4902` is `structured_service_events_eu_west_20260918.log` (`evidence_06`), captured on `2026-09-18T11:55:24Z`.
  - In `case_30` (`audit_at: 2026-09-15T12:00:00Z`), the only evidence file referencing `audit_record_1707` is `customer_data_snapshot_bundle_20260917.json` (`evidence_02`), captured on `2026-09-17T12:00:00Z`.
* **Unproven Facts:**
  - Under the strict dual temporal rule, both `evidence_06` and `evidence_02` are **INADMISSIBLE** for `case_09` and `case_30` respectively.
  - While `backup_4978` in `case_09` is fully proven by admissible `evidence_93` (captured `2026-09-16T08:37:39Z`), the verification states for `account_3960` and `audit_record_4902` at `audit_at` are **UNPROVEN from admissible evidence**.
  - While the 4 findings in `case_30` are fully proven by admissible `evidence_92`, the verification state for `audit_record_1707` at `audit_at` is **UNPROVEN from admissible evidence**.

### B.4. Case 25 Verification vs. Global Absence Qualification
* **Observed Facts:**
  - Full identifier set for `user_25`: stable ID `user_25`, name `Soo-jin Yoon`, email `s.yoon04@gmail.com`, phone `+82 10 0616 2075`, historical phone `+82 10 6662 4968` (`user_audit_log.csv:221`), email hash `52a8f91b84187990ccf1541e03bbbb440a2ad015384a9e0e35c5613f2d3a3785`, resource IDs `account_3136`, `analytics_1895`, `audit_record_451`.
  - In admissible `evidence_92`, the 3 specific verification steps (`account_3136` 404, `analytics_1895` null identifiers, `audit_record_451` retention until 2031) are observed directly.
  - A text search across the 79 text/SQL/JSON/log files and 4 decompressed PDF text streams found zero lingering active profile, search, support, or flow records for `user_25`.
* **Unproven Facts:**
  - The repository contains 11 PNG screenshots (`dataset/evidence/images/`). Because image files were not subjected to full OCR or visual inspection in this audit turn, absolute absence of `user_25` PII across all binary image files remains **UNPROVEN**.

---

## Section C. Cases and Output Steps Affected

| Case ID | Affected Step(s) | Impact Type | Ground-Truth Finding & Admissibility Status |
|---|---|---|---|
| **`case_12`** | Step 1 (`FINDING`), Step 2 (`REMEDIATION`), Step 4 (`VERIFICATION`) | Operation & State Conflict | `sample_output.csv:13` uses `REPORT_REMAINING_RECORD` -> `DELETE_RECORD` (`ABSENT`) -> `VERIFY_RECORD_ABSENT`. `rule_07` prescribes `REPORT_EXPOSED_PII` -> `ANONYMIZE_RECORD` (`ANONYMIZED`) -> `VERIFY_RECORD_ANONYMIZED`. Policy rationale is UNRESOLVED. |
| **`case_09`** | Step 1 (`FINDING`), Step 2 (`REMEDIATION`), Step 5 (`VERIFICATION`) | Confirmed Finding | Finding `backup_4978` (`REPORT_RESTORE_RISK`, `ACTIVE`) is fully CONFIRMED by admissible `evidence_93:24` (`customer_data_inventory_20260916.sql`). |
| **`case_09`** | Step 3 (`VERIFICATION`), Step 4 (`VERIFICATION`) | Inadmissible Evidence Citation | Readbacks for `account_3960` and `audit_record_4902` appear only in `evidence_06` (captured `2026-09-18`), which is INADMISSIBLE at `audit_at` (`2026-09-16T09:00:00Z`). In `sample_output.csv:10`, these steps use `evidence_id: ""`, but their physical state at `audit_at` is UNPROVEN from admissible files. |
| **`case_20`** | Step 7 (`VERIFICATION`) | Phantom Resource | `audit_record_5569` appears nowhere in evidence files or system activity. Its inclusion in `sample_output.csv:21` is UNPROVEN from participant-facing files. |
| **`case_30`** | Step 11 (`VERIFICATION`) | Inadmissible Evidence Citation | `audit_record_1707` appears in `evidence_02` (captured `2026-09-17`), which is INADMISSIBLE at `audit_at` (`2026-09-15T12:00:00Z`). Its physical state at `audit_at` is UNPROVEN from admissible evidence. |
| **`case_25`** | Steps 1, 2, 3 (`VERIFICATION`) | Verification Observation | All 3 steps cite `evidence_92` (captured `2026-09-15T11:44:55Z` <= `audit_at`). The individual 404, anonymization, and retention fields are observed in `evidence_92`. Global absence across unindexed images remains unproven. |
| **`case_11`** | Steps 1–4 (`FINDING`), Steps 5–8 (`REMEDIATION`), Steps 9–14 (`VERIFICATION`) | Ordering & Unproven Retention | Findings and remediation ordering confirmed by admissible `evidence_03:4`. `audit_record_9394` (Step 11) is confirmed to exist, but its retention condition is UNPROVEN due to missing `retention_until`. |

---

## Section D. Unresolved Ambiguities

### D.1. The `analytics_9914` Policy Discrepancy
* **The Conflict:**
  `deletion_rules.csv:8` mandates `ANONYMIZE` for `ANALYTICS_PROFILE` records attributable to a user. However, `sample_output.csv:13` specifies `DELETE_RECORD` for `analytics_9914`.
* **Evidence vs. Claims:**
  - Evidence: `service_events_ap_south_20260915.log:92` records `service=analytics_platform event=contact_lookup_completed email_opt_in=true`.
  - Claim: `system_activity.csv:3436` records that `deletion_worker` attempted `DELETE_RECORD`.
* **Unresolved Status:**
  Activity logs establish what the workflow attempted, not policy correctness. The discrepancy must **not** be resolved by inventing an unwritten marketing exception rule or silently choosing sample outputs over `deletion_rules.csv`.
  - Strictly by `deletion_rules.csv:8`, the action is `ANONYMIZE_RECORD`.
  - In `sample_output.csv:13`, the action is `DELETE_RECORD`.
  - **Status:** **UNRESOLVED POLICY CONFLICT**. Preserved explicitly as an open policy issue.

### D.2. Security Audit Retention Evaluation with Missing Timestamps
* **The Conflict:**
  `rule_12` states: `SECURITY_AUDIT_LOG | Record is within the supplied retention period | RETAIN`. In 4 out of 5 audited sample cases (`case_09`, `case_20`, `case_30`, `case_11`), no `retention_until` field is supplied.
* **Separation of Facts:**
  1. *Linkage & Existence:* Evidence establishes that the audit record exists and links to the subject reference (`user_id`).
  2. *Retention Period Satisfaction:* Without `retention_until`, satisfaction of `rule_12`'s retention condition cannot be evaluated from data.
* **Consequence Under the Specification:**
  Missing `retention_until` cannot be treated as an assumed policy default. When `retention_until` is absent, the retention condition is **UNPROVEN** unless another explicit, admissible participant-facing rule or evidence resolves it. Under the specification, if retention cannot be verified, the required legal retention status remains unproven.

### D.3. Post-Remediation Verification of Already-Absent Primary Accounts
* **The Issue:**
  In `case_09` (`account_3960`), `case_20` (`account_5037`), and `case_30` (`account_4163`), primary account profiles were already deleted or 404 prior to `audit_at`. Yet `sample_output.csv` includes `VERIFY_RECORD_ABSENT` for them in post-remediation verification.
* **Specification Rationale:**
  AGENTS.md §6.3 and §6.5: In an `INCOMPLETE` case, verification represents the complete end-state audit checklist that must pass after all remediation is finished. It encompasses both remediated remnants and confirmation that core profile records remain absent. Because these describe future checks, they use `evidence_id: ""`.

---

## Section E. Required Changes to the Architecture Specification

The findings and corrections establish the following deterministic architecture requirements for `code/main.py`:

### E.1. Strict Temporal Filter Engine
* Filter every manifest entry in `dataset/evidence_files.csv`: Discard any file where `captured_at > audit_at`.
* Filter records within admissible files: Discard any log event or record where timestamp `> audit_at`.
* Strictly exclude evidence from files captured post-audit under all circumstances.

### E.2. Graph-Based Identity Resolution
* Parse current identity from `dataset/user_identities.csv`.
* Traverse `dataset/user_audit_log.csv` for the subject's `user_id` to assemble the full historical set:
  - All past email addresses.
  - All past phone numbers.
  - All past SHA-256 email hashes (read directly from `old_value` where `field_name='email_hash'`).
* Perform exact matching against evidence; reject decoys matching different identifiers.

### E.3. Ground-Truth Finding & Operation Mapping
* Classify findings from admissible evidence strictly:
  - `USER_PROFILE` / `SEARCH_INDEX_ENTRY` / `USER_EXPORT` -> `REPORT_REMAINING_RECORD` (`PRESENT`) -> `DELETE_RECORD` (`ABSENT`).
  - `ANALYTICS_PROFILE` / `SUPPORT_MESSAGE` -> `REPORT_EXPOSED_PII` (`PRESENT`) -> `REDACT_RECORD` (`REDACTED`) or `ANONYMIZE_RECORD` (`ANONYMIZED`).
  - Active integration connector -> `REPORT_ACTIVE_DATA_FLOW` (`ACTIVE`) -> `DISABLE_DATA_FLOW` (`DISABLED`).
  - Active restore entry (`restore_allowed=1`) -> `REPORT_RESTORE_RISK` (`ACTIVE`) -> `BLOCK_RESTORE` (`BLOCKED`).
* **Preserve Unresolved Analytics Conflict:** Do not allow attempted operations in `system_activity.csv` to override `rule_07`. Keep the `analytics_9914` discrepancy explicitly unresolved.

### E.4. Deterministic Phase Ordering & Evidence ID Handling
* Output format: `FINDING` -> `REMEDIATION` -> `VERIFICATION`.
* Remediation ordering:
  1. `DISABLE_DATA_FLOW` and `BLOCK_RESTORE` must always execute first.
  2. `DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD` follow.
* Evidence ID assignment:
  - `COMPLETE` cases: All verification steps cite admissible participant `file_id`.
  - `INCOMPLETE` cases: Finding steps cite admissible participant `file_id`. All remediation and verification steps must use `""`.

---

## Conclusion & Next Steps

This revision establishes rigorous adherence to raw evidence:
- It enforces strict dual temporal admissibility (discarding `evidence_06` for case_09 and `evidence_02` for case_30).
- It preserves the `analytics_9914` policy discrepancy as unresolved rather than inventing an override.
- It separates audit record existence from proof of satisfied retention.
- It properly qualifies case_25 verification observations versus unproven binary image absence.

* **Current Status:** Step 2 Final Reconciliation Report completed (Revision 2.1).
* **Recommended Next Action:** Stop for user review before proceeding to draft `ARCHITECTURE_AND_PROMPTS.md`.
