# Architecture and Prompts Specification

**Challenge:** HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Artifact:** `ARCHITECTURE_AND_PROMPTS.md`  
**Status:** Approved Architecture Specification  
**Reference Ground Truth:** `code/evaluation/reconciliation_report.md` (Revision 2.1), `AGENTS.md`, `problem_statement.md`, `README.md`, `dataset/deletion_rules.csv`

---

## 1. Inputs and Output Contract

### 1.1. Input Datasets
The audit agent operates exclusively on participant-facing data inside `dataset/`:
1. `dataset/deletion_requests.csv`: 518 evaluation requests requiring predictions.
   - Schema: `case_id,email,requested_at,reported_status,reported_at,audit_at,request_text`
2. `dataset/sample_deletion_requests.csv`: 32 reference requests with public ground truth in `dataset/sample_output.csv`.
3. `dataset/user_identities.csv`: Current identity snapshots (`user_id,name,email,phone,email_hash,updated_at`).
4. `dataset/user_audit_log.csv`: Historical identity mutations (`audit_id,user_id,event_time,field_name,old_value,new_value`).
5. `dataset/system_activity.csv`: Global stream of deletion, synchronization, export, backup, restore, indexing, and audit events (`activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details`).
6. `dataset/deletion_rules.csv`: Policy rules mapping data categories and conditions to required actions (`rule_id,data_category,condition,required_action`).
7. `dataset/evidence_files.csv`: Evidence manifest mapping files to metadata (`file_id,file_path,origin,captured_at`).
8. `dataset/evidence/`: 94 evidence artifacts across databases, logs, records, documents, and images.

*Constraint (AGENTS.md §6.1, §6.7):* Organizer-only truth, golden answers, generator internals, and hidden review files must never be accessed or used for predictions.

### 1.2. Output Contract
The solution must write the final completed predictions to `output.csv` at the repository root.
* **Exact CSV Header:**
  ```text
  case_id,deletion_status,steps_json
  ```
* **Row Count & Ordering:** Exactly 518 data rows plus the header row, strictly ordered by `case_id` ascending.
* **Status Domain:** `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
* **Serialization for `NOT_APPLICABLE`:** Must output `steps_json` as an empty JSON array: `[]`.
* **Serialization for `COMPLETE` and `INCOMPLETE`:** Must output `steps_json` as a valid JSON array of step objects.

### 1.3. Step Schema and Domain Restrictions
Each step in `steps_json` contains exactly seven fields:
```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_54"
}
```

* **Step Numbering:** Consecutively numbered starting at `1` (`step_no: 1, 2, 3, ...`).
* **Phase Hierarchy:** Strictly ordered by phase: `FINDING` -> `REMEDIATION` -> `VERIFICATION`.
* **Allowed Operations & States (AGENTS.md §6.4):**
  - **Findings:**
    | Operation | State | Meaning |
    |---|---|---|
    | `REPORT_REMAINING_RECORD` | `PRESENT` | A record that should have been deleted still exists. |
    | `REPORT_EXPOSED_PII` | `PRESENT` | A record may remain, but identifiers requiring redaction/anonymization are exposed. |
    | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | An active process can copy or recreate personal data. |
    | `REPORT_RESTORE_RISK` | `ACTIVE` | A backup or restore path can restore deleted data. |
  - **Remediation:**
    | Operation | State | Meaning |
    |---|---|---|
    | `DISABLE_DATA_FLOW` | `DISABLED` | Stop a process that copies or recreates data. |
    | `BLOCK_RESTORE` | `BLOCKED` | Prevent affected backup from restoring subject data. |
    | `DELETE_RECORD` | `ABSENT` | Remove the record entirely. |
    | `REDACT_RECORD` | `REDACTED` | Retain record but remove identifying fields. |
    | `ANONYMIZE_RECORD` | `ANONYMIZED` | Irreversibly unlink record from the user. |
  - **Verification:**
    | Operation | State | Meaning |
    |---|---|---|
    | `VERIFY_RECORD_ABSENT` | `ABSENT` | Confirm record no longer exists. |
    | `VERIFY_RECORD_PRESENT` | `PRESENT` | Confirm policy-required retained record still exists. |
    | `VERIFY_RECORD_REDACTED` | `REDACTED` | Confirm required identifying fields were removed. |
    | `VERIFY_RECORD_ANONYMIZED` | `ANONYMIZED` | Confirm record can no longer link to the user. |
    | `VERIFY_DATA_FLOW_DISABLED` | `DISABLED` | Confirm relevant data flow is inactive. |
    | `VERIFY_RESTORE_BLOCKED` | `BLOCKED` | Confirm affected data cannot be restored. |
  *Constraint:* No other phases, operations, or states may be emitted.

### 1.4. Evidence ID Provenance Contract
* **Incomplete Cases:**
  - `FINDING` steps cite the participant-visible `evidence_id` (`file_id`, `activity_id`, or `audit_id`) that proves the remnant or risk.
  - Proposed `REMEDIATION` and post-remediation `VERIFICATION` steps represent future work and **must use `evidence_id: ""`** (AGENTS.md §6.3, §6.6).
* **Complete Cases:**
  - Include *only* `VERIFICATION` steps.
  - Every verification step **must cite a valid participant-visible `evidence_id`** proving the actual compliant state at `audit_at` (e.g. `evidence_92`).

---

## 2. Evidence Ingestion Architecture

### 2.1. Manifest-Driven Inventory
The ingestion engine reads `dataset/evidence_files.csv` as the authoritative catalog of files under `dataset/evidence/`. For each file, the ingestion engine indexes:
- `file_id`: Unique manifest identifier (e.g. `evidence_54`, `evidence_92`).
- `file_path`: Relative path under `dataset/`.
- `origin`: Source subsystem tag.
- `captured_at`: Upper temporal bound for file admissibility.

### 2.2. Specialized Parsers by Evidence Format
The engine implements format-specific parsers to extract candidate entities with full provenance tracking:
1. **SQL Database Snapshots (`dataset/evidence/databases/*.sql`):**
   - Readable text files containing SQLite DDL and DML.
   - *Dynamic Schema Extraction:* Inspect `CREATE TABLE` statements dynamically rather than assuming fixed schemas. Table schemas differ between primary stores, failover replicas, read replicas, and regional replicas (e.g. `customer_profiles_failover_replica` vs `customer_data_primary`).
   - Parse `INSERT INTO` statements into structured row tuples with table name, column definitions, and primary keys.
2. **JSON Records & Snapshots (`dataset/evidence/records/*.json`):**
   - Recursive object traversal down to leaf collections (`profile_lookups`, `profiles`, `tickets`, `security_audit_records`, `connector_subscriptions`, `index_queries`).
   - Extract record-level timestamps (`observed_at`, `exported_at`, `captured_at`) and exact field mappings.
3. **Structured & Syslog Logs (`dataset/evidence/logs/*.log`):**
   - Support both JSON-lines format (`{"severity":"DEBUG", ...}`) and key-value syslog format (`timestamp level=DEBUG service=... key="value"`).
   - Parse trace correlation keys (`trace_id`, `correlation_key`, `lookup_key`, `subject_ref`).
4. **Shift Handover Text Files (`dataset/evidence/records/*.txt`):**
   - Pipe-delimited structured rows: `timestamp | service | resource_id | category | status | identifier`.
5. **PDF Documents (`dataset/evidence/documents/*.pdf`):**
   - Extract plain text by parsing decompressed streams (using standard library `zlib` stream inspection) to extract tabular records, customer account summaries, and legal register entries.
6. **PNG Image Screenshots (`dataset/evidence/images/*.png`):**
   - Parse administrative UI screenshots using OCR text extraction when available, caching extracted text blocks alongside visual coordinates.

### 2.3. Evidence Fact Provenance Model
Every fact ingested by the engine is stored as an immutable `EvidenceFact`:
```python
@dataclass(frozen=True)
class EvidenceFact:
    file_id: str
    file_path: str
    origin: str
    file_captured_at: datetime
    record_timestamp: Optional[datetime]
    system_id: str
    resource_id: str
    data_category: Optional[str]
    raw_event: Optional[str]
    status_or_state: str  # e.g., "PRESENT", "ACTIVE", "404", "ANONYMIZED"
    matched_identifier_field: str
    matched_identifier_value: str
    attributes: Dict[str, Any]
    source_locator: str  # e.g. "customer_accounts_failover_replica_20260902.sql:13"
```

---

## 3. Identity Resolution

### 3.1. Unified Subject Identity Graph
An audit cannot rely on the request email alone. The identity engine constructs an identity graph for each subject:
```
Request Email (Current OR Historical)
      │
      ▼
user_audit_log.csv (Resolve historical changes)
      │
      ▼
user_id (Stable Anchor) ◄──► user_identities.csv (Current Snapshot)
      │
      ├─ Current Email & Historical Emails
      ├─ Current Phone & Historical Phones
      ├─ Current Hash & Pre-recorded Historical Hashes (SHA-256)
      └─ Full Name
```

### 3.2. Historical Hash Recovery (Zero Guessing)
* **Established Ground Truth:** Historical email hashes are pre-computed and recorded directly in `dataset/user_audit_log.csv` under `field_name='email_hash'`.
* **Rule:** The engine must read `old_value` directly from `user_audit_log.csv` (e.g. `audit_283` for `user_12`). Dynamic hashing or trial-and-error normalization is strictly forbidden.

### 3.3. Grounded Decoy Exclusion
* The evidence corpus contains decoys that share schemas, files, or timestamps (e.g. `account_8741` in `evidence_54`, `backup_3933` in `evidence_93`, 40 shift records in `evidence_03`).
* **Exclusion Standard:** An evidence record is associated with the subject **only if** it matches at least one resolved identifier from the subject identity graph:
  - Exact match on `user_id` / `customer_reference` / `subject_reference`
  - Exact match on current or historical email (case-insensitive)
  - Exact match on current or historical phone (normalized whitespace)
  - Exact match on current or historical email hash (`correlation_key`, `email_hash`)
* Any record that matches an unrelated user identifier or contains unlinked null identifiers without subject correlation is rejected as a decoy.

---

## 4. Temporal Admissibility Engine

### 4.1. The Strict Dual Timestamp Rule
Per AGENTS.md §6.2, §6.6 and `code/evaluation/reconciliation_report.md` §A.1, temporal admissibility requires both file-level and record-level gating:
1. **File Gating:** An evidence file is admissible for a case if and only if:
   $$\text{file.captured\_at} \le \text{case.audit\_at}$$
   If `file.captured_at > case.audit_at`, the file is discarded for that case.
2. **Record Gating:** For an admissible file, an individual record or event inside that file is admissible if and only if:
   $$\text{record.timestamp} \le \text{case.audit\_at}$$
   (where `record.timestamp` is `observed_at`, `event_time`, or `updated_at`).
3. **No Retroactive Admission:** An event from a file captured after `audit_at` can **never** be admitted on the grounds that the event timestamp is older than `audit_at`.

### 4.2. Timestamp Normalization
All timestamps are parsed into timezone-aware UTC `datetime` objects. Timestamps terminating in `Z` are compared directly using standard chronological ordering.

### 4.3. Missing Record Timestamps and Strict Temporal State
* **No Specification Authorization for Fallback Timestamps:** A comprehensive review of participant-facing documentation (`problem_statement.md`, `AGENTS.md` §6.2, §6.6) confirms that **no rule authorizes substituting a file's `captured_at` as the event timestamp of an individual record**.
* **Container vs. Event Temporal State:**
  - If an evidence file satisfies `file.captured_at <= case.audit_at`, the file itself is admissible as a container that existed on or before `audit_at`.
  - However, for an un-timestamped row, log entry, or event within that file, `captured_at` proves only when the container was captured, not when the internal event or mutation actually occurred.
* **Preserving UNPROVEN Temporal State (Zero Timestamp Invention):**
  - When the timing of a record relative to an audit event (e.g. relative to `requested_at`, `reported_at`, or retention windows) is necessary to determine policy compliance, that record's temporal state must remain **UNPROVEN**.
  - The engine must **never invent, assume, or fabricate timestamps** for records that lack them.
  - Where temporal admissibility cannot be verified to pre-date `audit_at`, the candidate fact cannot serve as positive proof of pre-audit deletion compliance.

---

## 5. Findings, Remediation, and Verification

### 5.1. Policy Mapping via `deletion_rules.csv`
Every admitted fact is mapped to its deletion rule:
| Data Category | Condition | Required Action | Finding Operation | Remediation Operation |
|---|---|---|---|---|
| `USER_PROFILE` | Always | `DELETE` | `REPORT_REMAINING_RECORD` | `DELETE_RECORD` |
| `SECONDARY_IDENTIFIER` | Always | `DELETE` | `REPORT_REMAINING_RECORD` | `DELETE_RECORD` |
| `SEARCH_INDEX_ENTRY` | Always | `DELETE` | `REPORT_REMAINING_RECORD` | `DELETE_RECORD` |
| `CACHE_ENTRY` | Always | `DELETE` | `REPORT_REMAINING_RECORD` | `DELETE_RECORD` |
| `SUPPORT_MESSAGE` | Context retained | `REDACT` | `REPORT_EXPOSED_PII` | `REDACT_RECORD` |
| `SUPPORT_ATTACHMENT` | Belongs only to subject | `DELETE` | `REPORT_REMAINING_RECORD` | `DELETE_RECORD` |
| `ANALYTICS_PROFILE` | Attributable to user | `ANONYMIZE` | `REPORT_EXPOSED_PII` | `ANONYMIZE_RECORD` |
| `PRODUCT_TELEMETRY` | Attributable to user | `ANONYMIZE` | `REPORT_EXPOSED_PII` | `ANONYMIZE_RECORD` |
| `USER_EXPORT` | Always | `DELETE` | `REPORT_REMAINING_RECORD` | `DELETE_RECORD` |
| `MARKETING_PROFILE` | Always | `DELETE` | `REPORT_REMAINING_RECORD` | `DELETE_RECORD` |
| `EMAIL_DELIVERY_LOG` | Contains email | `REDACT` | `REPORT_EXPOSED_PII` | `REDACT_RECORD` |
| `SECURITY_AUDIT_LOG` | Within retention period | `RETAIN` | N/A (Compliant) | N/A |
| `BACKUP_ARCHIVE` | Restore can be blocked | `RETAIN` | `REPORT_RESTORE_RISK` | `BLOCK_RESTORE` |
| Active Flow | Connector active | Stop | `REPORT_ACTIVE_DATA_FLOW` | `DISABLE_DATA_FLOW` |

### 5.2. Observed Workflow Claims vs. Policy Correctness
* Records in `dataset/system_activity.csv` record what the automated workflow attempted (e.g. `DELETE_RECORD`, `ANONYMIZE_RECORD`).
* An attempted action in `system_activity.csv` is a claim, not proof of policy correctness. Policy actions must derive strictly from `deletion_rules.csv` applied to ground-truth evidence.

### 5.3. Deterministic Step and Operation Ordering

Emitted steps in `steps_json` must follow a deterministic execution order. A rigorous reconciliation of `problem_statement.md` and `AGENTS.md` establishes the exact ordering strategy while isolating specification tensions:

#### 5.3.1. Fully Aligned Hierarchy Across Documents
Both `problem_statement.md` (lines 101–126) and `AGENTS.md` (§6.3, §6.4, §6.5) establish identical primary and secondary ordering:
1. **Phase Ordering (Primary Key):**
   Steps are strictly partitioned and ordered by phase:
   $$\text{FINDING} \longrightarrow \text{REMEDIATION} \longrightarrow \text{VERIFICATION}$$

2. **Operation Ordering Within Phase (Secondary Key):**
   Within each phase, operations follow the exact sequence defined in the Allowed Operations table (`problem_statement.md:103-120`, `AGENTS.md §6.4`):
   - **Phase 1 (`FINDING`):**
     1. `REPORT_REMAINING_RECORD` (State: `PRESENT`)
     2. `REPORT_EXPOSED_PII` (State: `PRESENT`)
     3. `REPORT_ACTIVE_DATA_FLOW` (State: `ACTIVE`)
     4. `REPORT_RESTORE_RISK` (State: `ACTIVE`)
   - **Phase 2 (`REMEDIATION`):**
     1. `DISABLE_DATA_FLOW` (State: `DISABLED`)
     2. `BLOCK_RESTORE` (State: `BLOCKED`)
     3. `DELETE_RECORD` (State: `ABSENT`)
     4. `REDACT_RECORD` (State: `REDACTED`)
     5. `ANONYMIZE_RECORD` (State: `ANONYMIZED`)
   - **Phase 3 (`VERIFICATION`):**
     1. `VERIFY_RECORD_ABSENT` (State: `ABSENT`)
     2. `VERIFY_RECORD_PRESENT` (State: `PRESENT`)
     3. `VERIFY_RECORD_REDACTED` (State: `REDACTED`)
     4. `VERIFY_RECORD_ANONYMIZED` (State: `ANONYMIZED`)
     5. `VERIFY_DATA_FLOW_DISABLED` (State: `DISABLED`)
     6. `VERIFY_RESTORE_BLOCKED` (State: `BLOCKED`)

   *(Precedence Alignment Note: This canonical table order directly enforces the foundational requirement of AGENTS.md §6.5: active data flows must be disabled and unsafe restores blocked before executing record-level mutations.)*

#### 5.3.2. Downstream Dependency Ordering vs. Lexicographical Tie-Breaking
A critical tension exists between the general dependency requirement in `AGENTS.md` and the literal sorting formula in `problem_statement.md`:
* **The Dependency Requirement (`AGENTS.md §6.5`):**
  *"Within remediation, disable data flows and block unsafe restores before changing dependent records. Process downstream copies before their source records when the dependency requires it."*
* **The Literal Sorting Rule (`problem_statement.md:126`):**
  *"Within each phase, follow the operation order in the table above, followed by `system_id` and `resource_id` in ascending order."*
* **The Conflict:**
  Alphabetical tie-breaking on `system_id` does **not** guarantee downstream-before-source ordering. For example, if the primary source is `account_service` and a downstream replica or search index is `search_service`, lexicographical sorting places `account_service` (`"a"`) before `search_service` (`"s"`), muting the source before the downstream copy.
* **Grounded Resolution via Public Sample Output:**
  Inspection of the public ground truth in `dataset/sample_output.csv` demonstrates that the evaluator literally applies the formula from `problem_statement.md:126`:
  - In `case_16` (`sample_output.csv:17`), remediation steps are:
    1. Step 3: `account_service`, `account_994`, `DELETE_RECORD`
    2. Step 4: `search_service`, `search_1007`, `DELETE_RECORD`
  - In `case_24` (`sample_output.csv:25`), remediation steps are:
    1. Step 3: `account_service`, `account_5334`, `DELETE_RECORD`
    2. Step 4: `search_service`, `search_5577`, `DELETE_RECORD`
  In both public evaluation cases, `account_service` precedes `search_service` strictly due to alphabetical tie-breaking on `system_id`.
* **Explicit Deterministic Strategy:**
  1. Primary key: `phase` (`FINDING` -> `REMEDIATION` -> `VERIFICATION`).
  2. Secondary key: Canonical operation order from the Allowed Operations table (`problem_statement.md:103-120`).
  3. Tertiary key: `system_id` ascending lexicographical order (`problem_statement.md:126`).
  4. Quaternary key: `resource_id` ascending lexicographical order (`problem_statement.md:126`).
  5. The tension with AGENTS.md §6.5's downstream-copy clause is explicitly documented as an unresolved specification conflict, preventing arbitrary prioritization or invented sort keys.

### 5.4. Post-Remediation Verification Checklist (INCOMPLETE Cases)
In `INCOMPLETE` cases, post-remediation verification specifies the complete checklist of system states that must pass once remediation concludes:
- Verify remediated flows are disabled (`VERIFY_DATA_FLOW_DISABLED`).
- Verify remediated backups are blocked (`VERIFY_RESTORE_BLOCKED`).
- Verify remediated records are absent (`VERIFY_RECORD_ABSENT`).
- Verify redacted messages are redacted (`VERIFY_RECORD_REDACTED`).
- Verify anonymized profiles are anonymized (`VERIFY_RECORD_ANONYMIZED`).
- Verify primary account profile is absent (`VERIFY_RECORD_ABSENT`).
- Verify required security audit logs remain present (`VERIFY_RECORD_PRESENT`).
*All future verification steps in `INCOMPLETE` cases use `evidence_id: ""`.*

---

## 6. Status Classification Engine

### 6.1. Intake Authorization Gate (`NOT_APPLICABLE`)
Before evaluating evidence, `request_text` must be inspected for valid deletion intent.
* **Positive Deletion Intent:** The user explicitly requests account deletion, erasure, removal, profile purging, or "right to be forgotten."
* **Non-Deletion Actions (`NOT_APPLICABLE`):**
  - Data access request (e.g. "Send me a copy of my data", "What personal data do you hold?")
  - Data rectification / correction request (e.g. "Please update my shipping address", "Correct my phone number")
  - Marketing opt-out (e.g. "Unsubscribe me from marketing emails", "Opt me out of promotional SMS")
  - Export request (e.g. "Export my order history to CSV")
* **Multilingual Classification:** Supports intake requests in English, French, Spanish, German, Polish, Korean, Japanese, and Arabic.
* **Contract:** When `request_text` does not authorize deletion:
  - `deletion_status = "NOT_APPLICABLE"`
  - `steps_json = []`
  - Evidence search is bypassed.

### 6.2. Status Determination Logic (`COMPLETE` vs `INCOMPLETE`)
For an authorized deletion request:

#### 6.2.1. The `COMPLETE` Specification Contract
Under `problem_statement.md:24–29, 89` and `AGENTS.md §6.3, §6.5`, a deletion is classified as `COMPLETE` when:
1. Every relevant copy has received the required treatment under `deletion_rules.csv` (e.g. primary account profile deleted, support message redacted, telemetry anonymized).
2. No active sync, import, or restore path can recreate the user's data.
3. Retained records contain only the identifiers permitted by policy.
4. Records required to be retained remain available.
5. **Positive Verification Requirement:** The compliant state at `audit_at` is established from participant-visible evidence.
6. **Output Representation:** Emitted `steps_json` contains *only* verification steps (`phase: "VERIFICATION"`), where each step cites the exact admissible `evidence_id` (`file_id`, `activity_id`, or `audit_id`) proving that compliant state at `audit_at` (e.g. HTTP 404 readback in `evidence_92` for `case_25`).

#### 6.2.2. The `INCOMPLETE` Specification Contract
Under `problem_statement.md:91, 105–108` and `AGENTS.md §6.3, §6.5`, a case is classified as `INCOMPLETE` when admissible evidence establishes an ongoing policy violation or recreation risk:
1. **Evidence-Grounded Findings:** Admissible evidence proves at least one concrete remnant or recreation risk:
   - Remaining record that should have been deleted (`REPORT_REMAINING_RECORD`, State: `PRESENT`).
   - Exposed PII that should have been redacted or anonymized (`REPORT_EXPOSED_PII`, State: `PRESENT`).
   - Active sync or import process capable of recreating data (`REPORT_ACTIVE_DATA_FLOW`, State: `ACTIVE`).
   - Unblocked backup or restore path capable of recreating data (`REPORT_RESTORE_RISK`, State: `ACTIVE`).
2. **Output Representation:**
   - Admissible `FINDING` steps citing participant-visible evidence (`file_id`, `activity_id`, or `audit_id`).
   - Proposed `REMEDIATION` steps describing future required actions, strictly using `evidence_id: ""` (never claiming future remediation has succeeded).
   - Future `VERIFICATION` checks that must pass after remediation concludes, strictly using `evidence_id: ""` (never asserting that pre-audit proof already exists).

#### 6.2.3. Unresolved Ambiguity: Insufficient Verification Evidence Without Discovered Findings
A structural tension arises when:
- No admissible evidence establishes any remaining record, exposed PII, active data flow, or restore risk (zero evidentiary findings).
- BUT ALSO no admissible pre-audit evidence exists positively proving that required deletion treatments were accomplished by `audit_at` (e.g. readback verification logs are missing, or exist only in files captured after `audit_at`, such as `evidence_06` in `case_09` and `evidence_02` in `case_30`).

**Specification Audit of this Edge Scenario:**
1. **The Contract Dilemma:**
   - *If classified as `INCOMPLETE`:* `AGENTS.md §6.3` and `problem_statement.md:91` require an `INCOMPLETE` case to contain `FINDING` steps citing participant-visible evidence. However, claiming a violation without admissible evidence directly violates AGENTS.md §6.1 and §6.6 ("Determine resource state from the available evidence rather than trusting workflow or operation results alone"). Citing zero findings in an `INCOMPLETE` case or inventing an ad-hoc finding operation/state (e.g. `REPORT_UNPROVEN_DELETION`) is strictly forbidden by §6.4.
   - *If classified as `COMPLETE`:* `problem_statement.md:24–29` states that deletion is complete only when every copy has received required treatment. Relying purely on the absence of discovered remnants to assert completeness risks negative inference.
   - *Strict 3-Status Domain:* The specification restricts `deletion_status` strictly to `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE` (`problem_statement.md:68`, `AGENTS.md §6.3`). No fourth status (such as `UNVERIFIED` or `UNKNOWN`) may be invented.
2. **Public Ground-Truth Evidence Pattern:**
   In all 32 public reference cases (`dataset/sample_output.csv`), this edge condition does not occur:
   - Every single `INCOMPLETE` case (22 cases) contains at least one concrete, participant-visible finding fact grounded in admissible evidence.
   - Every single `COMPLETE` case (10 cases) contains concrete verification evidence proving compliant state at `audit_at`.
3. **Explicit Isolation for Implementation Review:**
   Because the participant-facing specification does not provide an explicit rule for this edge condition, the architecture will **not silently invent an ungrounded classification heuristic**:
   - The engine isolates this decision boundary into an explicit review gate in `code/planner.py`.
   - Admissible findings will **never** be fabricated, and post-audit files will **never** be cited.
   - If evaluation requests exhibit this condition, the case is isolated for transparent inspection against the official ground truth rather than masked by artificial labels.

### 6.3. LLM Integration Architecture (Groq API)
Where natural language ambiguity arises in request authorization classification:
* **Optional Model Usage:** The LLM is strictly optional and invoked only when deterministic keyword/regex classification of `request_text` is genuinely ambiguous (e.g. complex non-English phrasing with dual intent). For all clear deletion requests and clear non-deletion requests (access, rectification, marketing opt-out, export), fast deterministic parsing is used with zero external API calls.
* **Client Model:** Groq API (`llama-3.3-70b-versatile` or `llama-3.1-8b-instant`).
* **Strict Environment-Only Credential Isolation:** `GROQ_API_KEY` must be loaded exclusively from environment variables (`os.environ.get("GROQ_API_KEY")`). Loading credentials from `.env` files, config files, or code is strictly prohibited (AGENTS.md §4.4, §6.7; `problem_statement.md:160`). If `GROQ_API_KEY` is unset in the environment, the LLM module is disabled and deterministic classification is enforced.
* **Safe Deterministic Disk Cache (`code/cache/intake/`):** All prompt inputs and model outputs are hashed (SHA-256) and cached locally to disk. Cached responses eliminate redundant network latency, guarantee reproducible evaluation runs, and protect against unnecessary token spend.
* **Actual Telemetry Tracking (Zero Fabrication):** Token counts and costs must never be simulated, estimated, or fabricated. The wrapper extracts actual telemetry directly from API response objects:
  - `prompt_tokens = response.usage.prompt_tokens`
  - `completion_tokens = response.usage.completion_tokens`
  - `total_tokens = response.usage.total_tokens`
  The exact recorded counts and calculated pricing are aggregated and written directly to `code/evaluation/usage_report.md`. If no LLM calls are made during a run, the report records exactly 0 calls, 0 tokens, and $0.00 cost.

---

## 7. Unresolved Policy Issues

The engine architecture explicitly isolates the following unresolved policy discrepancies:

### 7.1. The `analytics_9914` Policy Action Discrepancy
* **The Conflict:**
  - **Policy Rule (`deletion_rules.csv:8`):** `rule_07 | ANALYTICS_PROFILE | Record is still attributable to a user | ANONYMIZE`. Under this official policy rule, the required remediation is `ANONYMIZE_RECORD` (resulting state `ANONYMIZED`), and post-remediation verification is `VERIFY_RECORD_ANONYMIZED` (state `ANONYMIZED`).
  - **Public Sample Output (`sample_output.csv:13`):** For Case 12, the public sample emits `REPORT_REMAINING_RECORD` -> `DELETE_RECORD` (state `ABSENT`) -> `VERIFY_RECORD_ABSENT` (state `ABSENT`) for `analytics_9914`.
* **Evidence vs. Attempted Workflow Claims:**
  - `service_events_ap_south_20260915.log:92` records `service=analytics_platform event=contact_lookup_completed email_opt_in=true`.
  - `system_activity.csv:3436` records that an automated worker attempted `DELETE_RECORD` on `analytics_9914` with `reported_result=FAILED`.
  - Per AGENTS.md §6.1, §6.5, §6.6 and `problem_statement.md:57, 124`: Activity logs and workflow events record what an automated process attempted, not what policy requires. An attempted deletion by a background worker is a claim and does not override `deletion_rules.csv`.
* **Architecture Treatment:**
  - **Derive Policy Actions Strictly from Rules and Evidence:** Policy operations derive strictly from `deletion_rules.csv` applied to ground-truth evidence.
  - **No Unsupported Overrides or Config Toggles:** The architecture rejects configurable override switches (e.g. `POLICY_ANALYTICS_ACTION`). Code must not encode an ad-hoc exception or treat `email_opt_in=true` as an unwritten marketing exception.
  - **Explicitly Unresolved Discrepancy:** This divergence between `deletion_rules.csv` and `sample_output.csv:13` is documented as an unresolved specification issue. During sample benchmark evaluation, the resulting step mismatch will be reported and explained in `code/evaluation/evaluation_report.md` rather than masked by a hardcoded shortcut.

### 7.2. Missing `retention_until` in Security Audit Records
* **The Conflict:** `rule_12` mandates retention only if the record is "within the supplied retention period." In `case_09`, `case_20`, `case_30`, and `case_11`, `retention_until` is absent from all participant-facing files.
* **Architecture Treatment:**
  - The engine separates proof of record existence from proof that the retention condition is satisfied.
  - Where `retention_until` is missing, the retention condition is flagged as **UNPROVEN**.
  - In post-remediation verification planning for `INCOMPLETE` cases, the engine emits `VERIFY_RECORD_PRESENT` (`evidence_id: ""`) to maintain compatibility with the required end-state checklist, while logging the unproven retention attribute in evaluation notes.

### 7.3. Inadmissible Later-Captured Verification Evidence
* **The Conflict:** In `case_09` and `case_30`, the evidence files containing readback verification records (`evidence_06` and `evidence_02`) were captured after `audit_at`.
* **Architecture Treatment:**
  - Under the strict dual temporal rule, these files are completely excluded from finding generation.
  - For post-remediation verification in `INCOMPLETE` cases, the checklist is emitted with `evidence_id: ""`, as permitted by §6.3, without asserting that pre-audit physical proof exists.

### 7.4. Unverifiable Absence vs. Zero Discovered Findings Ambiguity
* **The Conflict:**
  - An authorized deletion request yields no findings of remaining records, exposed PII, active flows, or restore risks in participant-facing evidence, but also lacks admissible pre-audit readback evidence positively verifying complete deletion.
  - Classifying as `INCOMPLETE` requires emitting `FINDING` steps citing evidence (§6.3), which would require claiming an unproven violation.
  - Classifying as `COMPLETE` requires evidence-backed verification steps proving the compliant state at `audit_at` (§6.3, §6.5), which cannot be fabricated.
* **Architecture Treatment:**
  - The specification does not supply an explicit rule for this edge condition, and no fourth status exists.
  - The architecture refuses to invent artificial findings, cite post-audit evidence, or fake completion proofs.
  - This decision boundary is isolated into a dedicated review gate in `code/planner.py`, documented transparently for evaluation review.

---

## 8. Evaluation and Deliverables

### 8.1. Benchmark Evaluation on Public Samples
* The engine will evaluate all 32 public requests in `dataset/sample_deletion_requests.csv` against `dataset/sample_output.csv`.
* Evaluation metrics:
  - **Status Accuracy:** Case-level deletion status match rate.
  - **Step-Level Precision & Recall:** Exact match on `(system_id, resource_id, operation, state, evidence_id)`.
  - **Sequence Accuracy:** Strict array order match.
  - **Field-Level Accuracy:** Per-field correctness across all emitted steps.

### 8.2. Required Deliverables
1. `code/evaluation/evaluation_report.md`:
   - Full accuracy breakdown across all 32 sample cases.
   - Analysis of exact matches and mismatches.
   - At least three additional custom evaluation test cases created by the participant (e.g. multi-identifier edge cases, tombstone redactions, language edge cases).
   - Documented failure modes and improvements made.
2. `code/evaluation/usage_report.md`:
   - Full accounting of model providers, model names, call counts, input/output tokens, total/average tokens per request, and total estimated cost.
3. `output.csv` (Repository Root):
   - Exactly 518 evaluation rows, formatted and sorted.
4. `code.zip`:
   - Packaged from root containing `code/`, `README.md`, `ARCHITECTURE_AND_PROMPTS.md`.
   - Excludes `dataset/`, virtual environments, caches, and nested archives.
5. `log.txt` (Repository Root):
   - Continuous append-only transcript of the entire session for upload as `chat_transcript`.

---

## 9. Modular Implementation Plan

The solution in `code/main.py` will be structured into decoupled, independently testable modules:

```
code/
├── main.py                     # Entry point & CLI runner
├── config.py                   # Paths, constants, schemas, operation tables
├── intake.py                   # Stage 1: Request authorization & classification
├── identity.py                 # Stage 2: Graph resolution & historical hash recovery
├── temporal.py                 # Stage 3: Strict dual timestamp validator
├── parsers/                    # Stage 4: Format-specific evidence ingestion
│   ├── sql_parser.py           # SQLite dynamic schema & insert extractor
│   ├── json_parser.py          # JSON records & snapshot bundle extractor
│   ├── log_parser.py           # Syslog and JSON structured log parser
│   ├── text_parser.py          # Handover pipe-delimited parser
│   └── doc_parser.py           # PDF stream decompressor & image text reader
├── policy.py                   # Stage 5: Deletion rules mapper & decoy discriminator
├── planner.py                  # Stage 6 & 7: Status decider, remediation sorter, verifier
├── serializer.py               # Stage 8: CSV & JSON formatter and schema validator
└── evaluation/
    ├── main.py                 # Evaluator harness against sample_output.csv
    ├── reconciliation_report.md# Step 2 Ground-truth reconciliation
    ├── evaluation_report.md    # Final evaluation metrics & custom test cases
    └── usage_report.md         # Token usage & cost summary
```

### Staged Implementation Sequence & Quality Gates:
1. **Gate 1 (Ingestion & Identity):** Unit tests verifying historical email hash recovery for `user_12` and `user_30` without hashing.
2. **Gate 2 (Temporal Gating):** Unit tests verifying that `evidence_06` is rejected for `case_09` and `evidence_02` is rejected for `case_30`.
3. **Gate 3 (Decoy Rejection):** Unit tests confirming that unrelated accounts in `evidence_54`, `evidence_93`, `evidence_94`, and `evidence_03` are excluded.
4. **Gate 4 (Public Sample Benchmark):** Run `code/evaluation/main.py` against all 32 sample requests, confirming high fidelity against `sample_output.csv`.
5. **Gate 5 (Full Dataset Prediction):** Generate predictions for all 518 cases in `dataset/deletion_requests.csv` to root `output.csv`.
6. **Gate 6 (Packaging & Validation):** Run validation scripts ensuring `output.csv` conforms to row counts, column order, and JSON syntax.

---

## 10. Source Traceability

| Requirement | Supporting Source Section | Status |
|---|---|---|
| Input & Output Columns, Status Domain | `problem_statement.md:53-74`; `AGENTS.md §6.1, §6.2, §6.3`; `README.md:66-77` | Confirmed Spec |
| Exact Step Operations & States | `problem_statement.md:103-120`; `AGENTS.md §6.4` | Confirmed Spec |
| Deterministic Step and Operation Ordering | `problem_statement.md:126` (table order + system_id + resource_id); `AGENTS.md §6.3, §6.4, §6.5` | Confirmed Spec |
| Pre-Recorded Historical Email Hashes | `dataset/user_audit_log.csv` (rows 281, 284); `reconciliation_report.md` §A.2 | Confirmed Data |
| Strict Dual Timestamp Admissibility | `problem_statement.md:57, 124`; `AGENTS.md §6.2, §6.6`; `reconciliation_report.md` §A.1 | Confirmed Spec |
| Status Determination & Complete Proof Standards | `problem_statement.md:24-29, 68`; `AGENTS.md §6.3, §6.5, §6.6` | Confirmed Spec |
| Evidence ID Rules (`""` in Incomplete) | `problem_statement.md:127`; `AGENTS.md §6.3, §6.6`; `sample_output.csv` | Confirmed Spec |
| Complete Case Evidence Proving | `problem_statement.md:127`; `AGENTS.md §6.3`; `sample_output.csv:26` (`case_25`) | Confirmed Spec |
| Non-Deletion Intake Actions (`NOT_APPLICABLE`) | `problem_statement.md:19, 91-97`; `AGENTS.md §6.3, §6.5`; `sample_output.csv:1-4` | Confirmed Spec |
| Environment-Only Credentials (`GROQ_API_KEY`) | `problem_statement.md:160`; `AGENTS.md §4.4, §6.7, §6.8` | Confirmed Spec |
| Analytics Policy Discrepancy Isolation | `dataset/deletion_rules.csv:8` (`rule_07`); `sample_output.csv:13`; `reconciliation_report.md` §B.2, §D.1 | Unresolved Discrepancy |
| Security Audit Log Retention Condition | `dataset/deletion_rules.csv:13` (`rule_12`); `reconciliation_report.md` §B.1, §D.2 | Unresolved Retention Data |
| Later-Captured Evidence Inadmissibility | `problem_statement.md:124`; `AGENTS.md §6.6`; `reconciliation_report.md` §B.3, §D.3 | Confirmed Spec Rule |
| Missing Record Timestamp Handling | `problem_statement.md:124`; `AGENTS.md §6.2, §6.6`; no fallback timestamp authorized | Confirmed Spec Rule |
| Downstream Dependency vs. Table Order Tension | `problem_statement.md:126`; `AGENTS.md §6.5`; `sample_output.csv:17, 25` (lexicographical applied) | Unresolved Tension |
| Unverifiable Absence vs. Zero Findings | `problem_statement.md:24-29, 91`; `AGENTS.md §6.3, §6.5`; no rule for unverifiable absence | Unresolved Ambiguity |
| Submission Packaging & Directory Rules | `problem_statement.md:143-160`; `AGENTS.md §6.8, §6.9`; `README.md:89-158` | Confirmed Contract |
