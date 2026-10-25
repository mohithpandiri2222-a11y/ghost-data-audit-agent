"""
Audit Planner — Stage 6 & 7 of the HackerRank Orchestrate audit pipeline.

Orchestrates case-by-case evidence gathering, status classification, and
deterministic step generation.

Architecture (ARCHITECTURE_AND_PROMPTS.md §5-§6, AGENTS.md §6.3-§6.5):
- Step phases: FINDING → REMEDIATION → VERIFICATION
- Operation ordering follows canonical table from problem_statement.md:103-120
- Tie-breaking: system_id ASC, resource_id ASC (problem_statement.md:126)
- COMPLETE cases emit only VERIFICATION steps citing admissible evidence
- INCOMPLETE cases emit FINDING + REMEDIATION + VERIFICATION (future work uses evidence_id="")
- NOT_APPLICABLE cases emit steps_json=[]
- The primary account record (account_service) is always included in INCOMPLETE verification
- Security audit records (SECURITY_AUDIT_LOG) are always included in INCOMPLETE verification
  with VERIFY_RECORD_PRESENT (evidence_id="" — retention condition unproven per §7.2)
"""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from code.config import (
    DATASET_DIR,
    DELETION_REQUESTS_PATH,
    OPERATION_ORDER_RANK,
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    STATUS_NOT_APPLICABLE,
    EvidenceFact,
    EvidenceFile,
    load_evidence_manifest,
    parse_iso_timestamp,
)
from code.identity import IdentityResolver, SubjectIdentity, normalize_email
from code.intake import IntakeResult, IntakeVerdict, classify_request
from code.parsers import (
    DocumentImageEvidenceParser,
    JSONEvidenceParser,
    LogEvidenceParser,
    SQLEvidenceParser,
    TextEvidenceParser,
    SQL_TABLE_TO_SYSTEM,
    resolve_canonical_system_id,
)
from code.policy import PolicyEvaluator, PolicyVerdict
from code.temporal import TemporalAdmissibilityValidator


# ---------------------------------------------------------------------------
# Output step model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


# ---------------------------------------------------------------------------
# Deletion request model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeletionRequest:
    case_id: str
    email: str
    requested_at: Optional[datetime]
    reported_status: str
    reported_at: Optional[datetime]
    audit_at: datetime
    request_text: str


def load_deletion_requests(path: Optional[Path] = None) -> List[DeletionRequest]:
    """Loads and parses deletion_requests.csv."""
    p = path or DELETION_REQUESTS_PATH
    reqs: List[DeletionRequest] = []
    with open(p, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            audit_at = parse_iso_timestamp(row["audit_at"])
            if audit_at is None:
                raise ValueError(f"Invalid audit_at for {row['case_id']}: {row['audit_at']}")
            reqs.append(DeletionRequest(
                case_id=row["case_id"].strip(),
                email=row["email"].strip(),
                requested_at=parse_iso_timestamp(row.get("requested_at")),
                reported_status=row.get("reported_status", "").strip(),
                reported_at=parse_iso_timestamp(row.get("reported_at")),
                audit_at=audit_at,
                request_text=row.get("request_text", "").strip(),
            ))
    return sorted(reqs, key=lambda r: r.case_id)


# ---------------------------------------------------------------------------
# Sorting key helpers
# ---------------------------------------------------------------------------

def _phase_rank(phase: str) -> int:
    return {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}.get(phase, 99)


def _sort_key(step_dict: Dict[str, Any]) -> Tuple:
    """Deterministic ordering: phase → op rank → system_id → resource_id."""
    return (
        _phase_rank(step_dict["phase"]),
        OPERATION_ORDER_RANK.get(step_dict["operation"], 99),
        step_dict["system_id"],
        step_dict["resource_id"],
    )


# ---------------------------------------------------------------------------
# Per-case audit result
# ---------------------------------------------------------------------------

@dataclass
class CaseAuditResult:
    case_id: str
    deletion_status: str   # COMPLETE | INCOMPLETE | NOT_APPLICABLE
    steps: List[AuditStep] = field(default_factory=list)
    intake: Optional[IntakeResult] = None
    notes: List[str] = field(default_factory=list)

    def to_row(self) -> Dict[str, Any]:
        import json
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status,
            "steps_json": json.dumps([s.to_dict() for s in self.steps], ensure_ascii=False),
        }


# ---------------------------------------------------------------------------
# Evidence gathering
# ---------------------------------------------------------------------------

_PARSER_DISPATCH = {
    ".sql": SQLEvidenceParser,
    ".json": JSONEvidenceParser,
    ".log": LogEvidenceParser,
    ".txt": TextEvidenceParser,
    ".pdf": DocumentImageEvidenceParser,
    ".png": DocumentImageEvidenceParser,
}


def _gather_admissible_facts(
    subject: SubjectIdentity,
    manifest: Dict[str, EvidenceFile],
    validator: TemporalAdmissibilityValidator,
    audit_at: datetime,
    scan_errors: Optional[List[str]] = None,
    grounded_account_id: Optional[str] = None,
) -> List[EvidenceFact]:
    """
    For the given subject, iterates the entire evidence manifest, parses
    each file that is admissible at file-level, extracts subject-matching facts,
    and applies the dual temporal admissibility filter.

    Returns a deduplicated list of temporally admissible facts for this case.
    First parses positive evidence across all admissible files.
    Then binds account resources only through grounded evidence.
    Finally performs absence scanning on admissible SQL snapshots without
    synthesizing ungrounded account IDs.
    """
    facts: List[EvidenceFact] = []
    seen_ids: Set[Tuple] = set()
    admissible_sql_files: List[EvidenceFile] = []

    for ev_file in manifest.values():
        # File-level gate
        if not ev_file.is_admissible_for_case(audit_at):
            continue

        suffix = Path(ev_file.file_path).suffix.lower()
        if suffix == ".sql":
            admissible_sql_files.append(ev_file)

        parser_cls = _PARSER_DISPATCH.get(suffix)
        if parser_cls is None:
            continue

        try:
            result = parser_cls().parse(ev_file, subject=subject)
        except Exception as e:
            if scan_errors is not None:
                scan_errors.append(f"Parser failed for {ev_file.file_id}: {e}")
            continue

        for fact in result.facts:
            if not validator.validate_fact(fact, audit_at).is_admissible:
                continue
            # Content-level dedup
            dedup_key = (fact.file_id, fact.system_id, fact.resource_id, fact.status_or_state, fact.matched_identifier_value)
            if dedup_key in seen_ids:
                continue
            seen_ids.add(dedup_key)
            facts.append(fact)

    # Bind account resources only through grounded evidence (Gate 3.2 #4)
    if not grounded_account_id:
        grounded_account_id = _extract_account_resource_id(facts, subject)

    # Absence scanning on admissible SQL snapshots
    for ev_file in admissible_sql_files:
        _scan_sql_absence(
            ev_file=ev_file,
            subject=subject,
            facts=facts,
            seen_ids=seen_ids,
            grounded_account_id=grounded_account_id,
            scan_errors=scan_errors,
        )

    return facts


# Customer profile table patterns for absence scanning
_ACCOUNT_TABLES = frozenset({
    "customer_profiles_failover_replica",
    "customer_profiles_primary",
    "customer_profiles",
    "customer_profiles_regional",
    "customer_profiles_reporting",
})


def _scan_sql_absence(
    ev_file: EvidenceFile,
    subject: SubjectIdentity,
    facts: List[EvidenceFact],
    seen_ids: Set[Tuple],
    grounded_account_id: Optional[str] = None,
    scan_errors: Optional[List[str]] = None,
) -> None:
    """
    Scans an admissible SQL snapshot for subject absence in account tables.

    Rules (Gate 3.2 #4, #5):
    - Do not synthesize account IDs from user IDs.
    - If subject-to-resource mapping cannot be established, record the resource as unresolved
      and do NOT manufacture an absence fact or resource ID.
    - Inspect actual table schemas and include relevant participant-facing tables.
    - Record query failures, unsupported schemas, and partial scans explicitly.
    - A zero-row result from one secondary replica or partial scan must not establish platform-wide absence.
    - Do not produce COMPLETE solely from an absence fact generated by an incomplete scan.
    """
    if not ev_file.absolute_path.exists():
        if scan_errors is not None:
            scan_errors.append(f"SQL file missing on disk: {ev_file.absolute_path}")
        return

    try:
        script = ev_file.absolute_path.read_text(encoding="utf-8")
        con = sqlite3.connect(":memory:")
        con.executescript(script)
    except Exception as e:
        if scan_errors is not None:
            scan_errors.append(f"SQLite execution failed for {ev_file.file_id}: {e}")
        return

    try:
        tables = [
            r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type=?", ("table",)
            ).fetchall()
        ]
    except Exception as e:
        if scan_errors is not None:
            scan_errors.append(f"Failed to query tables for {ev_file.file_id}: {e}")
        con.close()
        return

    primary_account_tables = [t for t in tables if t.lower() in ("customer_profiles_primary", "customer_profiles")]
    replica_account_tables = [t for t in tables if t.lower() in ("customer_profiles_failover_replica", "customer_profiles_regional", "customer_profiles_reporting", "customer_data_replica_ap_south", "customer_data_replica_eu_west", "customer_data_reporting_replica", "customer_data_failover_replica")]

    all_candidate_tables = primary_account_tables + replica_account_tables
    if not all_candidate_tables:
        if scan_errors is not None:
            scan_errors.append(f"No account profile tables in {ev_file.file_id} (found: {tables})")
        con.close()
        return

    # If subject-to-resource mapping cannot be established, record resource as unresolved
    # and do NOT manufacture an absence fact or resource ID (Gate 3.2 #4).
    if not grounded_account_id:
        if scan_errors is not None:
            scan_errors.append(f"Subject {subject.user_id} account resource ID is unresolved; refusing to manufacture absence fact for {ev_file.file_id}")
        con.close()
        return

    has_primary = len(primary_account_tables) > 0
    is_partial = not has_primary
    if is_partial and scan_errors is not None:
        scan_errors.append(f"{ev_file.file_id} contains only secondary replica tables; partial scan does not establish platform-wide absence")

    user_id = subject.user_id
    for table in all_candidate_tables:
        system_id = SQL_TABLE_TO_SYSTEM.get(table.lower(), "account_service")
        try:
            cols = [d[0] for d in con.execute(f"SELECT * FROM {table} LIMIT 0").description]
        except Exception as e:
            if scan_errors is not None:
                scan_errors.append(f"Failed to inspect columns for table {table} in {ev_file.file_id}: {e}")
            continue

        subject_found = False
        if "user_id" in cols:
            row = con.execute(f"SELECT resource_id FROM {table} WHERE user_id = ?", (user_id,)).fetchone()
            if row:
                subject_found = True
        elif "customer_reference" in cols:
            row = con.execute(f"SELECT resource_id FROM {table} WHERE customer_reference = ?", (user_id,)).fetchone()
            if row:
                subject_found = True
        elif "subject_reference" in cols:
            row = con.execute(f"SELECT resource_id FROM {table} WHERE subject_reference = ?", (user_id,)).fetchone()
            if row:
                subject_found = True

        if not subject_found:
            for email in subject.all_emails():
                if "email" in cols:
                    row = con.execute(f"SELECT resource_id FROM {table} WHERE email = ?", (email,)).fetchone()
                    if row:
                        subject_found = True
                        break
                elif "customer_email" in cols:
                    row = con.execute(f"SELECT resource_id FROM {table} WHERE customer_email = ?", (email,)).fetchone()
                    if row:
                        subject_found = True
                        break

        if not subject_found:
            dedup_key = (ev_file.file_id, system_id, grounded_account_id, "ABSENT", user_id)
            if dedup_key not in seen_ids:
                seen_ids.add(dedup_key)
                is_table_primary = table.lower() in ("customer_profiles_primary", "customer_profiles")
                facts.append(EvidenceFact(
                    file_id=ev_file.file_id,
                    file_path=ev_file.file_path,
                    origin=ev_file.origin,
                    file_captured_at=ev_file.captured_at,
                    record_timestamp=None,
                    system_id=system_id,
                    resource_id=grounded_account_id,
                    data_category="USER_PROFILE",
                    raw_event=f"subject {user_id} ({grounded_account_id}) absent from {table}",
                    status_or_state="ABSENT",
                    matched_identifier_field="user_id",
                    matched_identifier_value=user_id,
                    attributes={
                        "table": table,
                        "absence_scan": "true",
                        "is_primary": "true" if is_table_primary else "false",
                        "is_partial_scan": "false" if is_table_primary else "true",
                    },
                    source_locator=f"{ev_file.file_path}:{table}:absent",
                ))

    con.close()


# ---------------------------------------------------------------------------
# Account resource ID extraction
# ---------------------------------------------------------------------------

def _extract_account_resource_id(
    facts: List[EvidenceFact],
    subject: SubjectIdentity,
) -> Optional[str]:
    """
    Finds the primary account resource_id for the subject from grounded evidence.
    Prefers facts from account_service with resource_id starting 'account_'.
    Falls back to any fact where resource_id starts with 'account_'.
    Returns None if no grounded account ID is present in evidence.
    """
    for fact in facts:
        if fact.system_id == "account_service" and fact.resource_id.startswith("account_"):
            return fact.resource_id
    for fact in facts:
        if fact.resource_id.startswith("account_"):
            return fact.resource_id
    return None


def _extract_security_audit_resource(facts: List[EvidenceFact]) -> Optional[Tuple[str, str]]:
    """Returns (resource_id, evidence_id) for a security audit record if found."""
    for fact in facts:
        if fact.system_id == "security_service" and fact.resource_id.startswith("audit_"):
            return (fact.resource_id, fact.file_id)
    return None


# ---------------------------------------------------------------------------
# Step builders
# ---------------------------------------------------------------------------

def _build_finding_steps(verdicts: List[PolicyVerdict]) -> List[Dict[str, Any]]:
    """Builds FINDING step dicts from policy verdicts that have findings."""
    steps = []
    for v in verdicts:
        if not v.has_finding:
            continue
        steps.append({
            "phase": "FINDING",
            "system_id": v.fact.system_id,
            "resource_id": v.fact.resource_id,
            "operation": v.finding_operation,
            "state": v.finding_state,
            "evidence_id": v.fact.file_id,
        })
    return steps


def _build_remediation_steps(verdicts: List[PolicyVerdict]) -> List[Dict[str, Any]]:
    """Builds REMEDIATION step dicts for future work (evidence_id='')."""
    steps = []
    for v in verdicts:
        if not v.has_finding or not v.remediation_operation:
            continue
        steps.append({
            "phase": "REMEDIATION",
            "system_id": v.fact.system_id,
            "resource_id": v.fact.resource_id,
            "operation": v.remediation_operation,
            "state": v.remediation_state,
            "evidence_id": "",
        })
    return steps


def _build_verification_steps_for_incomplete(
    verdicts: List[PolicyVerdict],
    account_resource_id: Optional[str],
    security_audit: Optional[Tuple[str, str]],
) -> List[Dict[str, Any]]:
    """
    Builds VERIFICATION steps for INCOMPLETE cases.
    All use evidence_id='' per §6.3.

    Always includes:
    - VERIFY_RECORD_ABSENT for account_service primary record
    - VERIFY_RECORD_PRESENT for security_service audit record (unproven retention, §7.2)
    - Verification for each remediated finding
    """
    steps = []
    seen_verify: Set[Tuple[str, str]] = set()

    # Per-finding verifications
    for v in verdicts:
        if not v.has_finding or not v.verification_operation:
            continue
        key = (v.fact.system_id, v.fact.resource_id)
        if key in seen_verify:
            continue
        seen_verify.add(key)
        steps.append({
            "phase": "VERIFICATION",
            "system_id": v.fact.system_id,
            "resource_id": v.fact.resource_id,
            "operation": v.verification_operation,
            "state": v.verification_state,
            "evidence_id": "",
        })

    # Always verify account record is absent
    if account_resource_id:
        key = ("account_service", account_resource_id)
        if key not in seen_verify:
            seen_verify.add(key)
            steps.append({
                "phase": "VERIFICATION",
                "system_id": "account_service",
                "resource_id": account_resource_id,
                "operation": "VERIFY_RECORD_ABSENT",
                "state": "ABSENT",
                "evidence_id": "",
            })

    # Always verify security audit log is present (unproven retention per §7.2)
    if security_audit:
        sa_resource, _sa_ev = security_audit
        key = ("security_service", sa_resource)
        if key not in seen_verify:
            seen_verify.add(key)
            steps.append({
                "phase": "VERIFICATION",
                "system_id": "security_service",
                "resource_id": sa_resource,
                "operation": "VERIFY_RECORD_PRESENT",
                "state": "PRESENT",
                "evidence_id": "",
            })

    return steps


def _build_verification_steps_for_complete(
    facts: List[EvidenceFact],
    verdicts: List[PolicyVerdict],
) -> List[Dict[str, Any]]:
    """
    Builds VERIFICATION steps for COMPLETE cases.
    Each step must cite the admissible evidence_id proving the compliant state at audit_at.
    Partial scans or secondary replica absence scans do NOT establish platform-wide absence.
    """
    steps = []
    seen_verify: Set[Tuple[str, str]] = set()

    for fact in facts:
        sys_id = fact.system_id
        res_id = fact.resource_id
        state = fact.status_or_state.upper()

        # Gate 3.2 item 5: A zero-row result from one replica or partial scan must not establish platform-wide absence.
        # Do not produce COMPLETE solely from an absence fact generated by an incomplete scan.
        if fact.get_attribute("is_partial_scan") == "true":
            continue

        key = (sys_id, res_id)

        if key in seen_verify:
            continue

        # Map fact state to verification operation
        if state in ("ABSENT", "DELETED", "404"):
            op = "VERIFY_RECORD_ABSENT"
            st = "ABSENT"
        elif state in ("REDACTED",):
            op = "VERIFY_RECORD_REDACTED"
            st = "REDACTED"
        elif state in ("ANONYMIZED",):
            op = "VERIFY_RECORD_ANONYMIZED"
            st = "ANONYMIZED"
        elif state in ("PRESENT",) and sys_id == "security_service":
            op = "VERIFY_RECORD_PRESENT"
            st = "PRESENT"
        elif state in ("DISABLED",):
            op = "VERIFY_DATA_FLOW_DISABLED"
            st = "DISABLED"
        elif state in ("BLOCKED",):
            op = "VERIFY_RESTORE_BLOCKED"
            st = "BLOCKED"
        elif state in ("PRESENT",):
            # For COMPLETE cases, a PRESENT account record would imply INCOMPLETE
            # Skip non-security PRESENT records as they should not appear in COMPLETE
            continue
        else:
            continue

        seen_verify.add(key)
        steps.append({
            "phase": "VERIFICATION",
            "system_id": sys_id,
            "resource_id": res_id,
            "operation": op,
            "state": st,
            "evidence_id": fact.file_id,
        })

    return steps


# ---------------------------------------------------------------------------
# Deduplication and sorting
# ---------------------------------------------------------------------------

def _deduplicate_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicates steps by (phase, system_id, resource_id, operation)."""
    seen: Set[Tuple] = set()
    deduped = []
    for s in steps:
        key = (s["phase"], s["system_id"], s["resource_id"], s["operation"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return deduped


def _sort_and_number_steps(steps: List[Dict[str, Any]]) -> List[AuditStep]:
    """Sorts steps deterministically and assigns step_no starting at 1."""
    sorted_steps = sorted(steps, key=_sort_key)
    return [
        AuditStep(
            step_no=i + 1,
            phase=s["phase"],
            system_id=s["system_id"],
            resource_id=s["resource_id"],
            operation=s["operation"],
            state=s["state"],
            evidence_id=s["evidence_id"],
        )
        for i, s in enumerate(sorted_steps)
    ]


# ---------------------------------------------------------------------------
# Status classification
# ---------------------------------------------------------------------------

def _classify_status(
    findings: List[PolicyVerdict],
    complete_verification_steps: List[Dict[str, Any]],
) -> str:
    """
    Determines COMPLETE vs INCOMPLETE.

    COMPLETE if:
    - No findings (no violations discovered)
    - AND admissible evidence provides positive verification proof (non-empty verification steps)

    INCOMPLETE if:
    - At least one finding with admissible evidence
    - OR required verification evidence is absent (cannot claim COMPLETE with empty steps)
    """
    has_findings = len(findings) > 0
    has_verification = len(complete_verification_steps) > 0

    if has_findings:
        return STATUS_INCOMPLETE

    if has_verification:
        return STATUS_COMPLETE

    # Gate 3.2 item 6:
    # A COMPLETE case cannot serialize with steps_json=[] unless the specification
    # explicitly permits it. The documented contract reserves an empty array for
    # NOT_APPLICABLE. If required verification evidence is absent, do not claim COMPLETE.
    return STATUS_INCOMPLETE


# ---------------------------------------------------------------------------
# Main planner
# ---------------------------------------------------------------------------

class AuditPlanner:
    """
    Main orchestration class for the audit pipeline.

    For each deletion request:
    1. Intake classification (authorization gate)
    2. Identity resolution
    3. Evidence gathering with temporal admissibility
    4. Policy evaluation
    5. Status classification
    6. Step generation with deterministic ordering
    """

    def __init__(
        self,
        requests_path: Optional[Path] = None,
        manifest: Optional[Dict[str, EvidenceFile]] = None,
        identity_resolver: Optional[IdentityResolver] = None,
        policy_evaluator: Optional[PolicyEvaluator] = None,
        temporal_validator: Optional[TemporalAdmissibilityValidator] = None,
    ) -> None:
        self.manifest = manifest or load_evidence_manifest()
        self.identity_resolver = identity_resolver or IdentityResolver()
        self.policy_evaluator = policy_evaluator or PolicyEvaluator()
        self.temporal_validator = temporal_validator or TemporalAdmissibilityValidator(self.manifest)
        self.requests_path = requests_path
        self._init_evidence_indexes()

    def _init_evidence_indexes(self) -> None:
        """Indexes operational data for case reconciliation (system activity & security audit events)."""
        self.account_links_by_user: Dict[str, Tuple[str, str]] = {}
        act_path = DATASET_DIR / "system_activity.csv"
        if act_path.exists():
            with open(act_path, encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    res = row.get("resource_id", "")
                    det = row.get("details", "")
                    ev_time = row.get("event_time", "")
                    if res.startswith("account_"):
                        for token in re.findall(r"\b(user_\w+|[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b", det):
                            token_clean = token.strip().lower()
                            if token_clean not in self.account_links_by_user:
                                self.account_links_by_user[token_clean] = (res, ev_time)

        self.sec_audit_by_user: Dict[str, str] = {}
        for ev in self.manifest.values():
            if "customer_data_snapshot_bundle" in ev.file_path and ev.file_path.endswith(".json"):
                try:
                    with open(ev.absolute_path, encoding="utf-8") as f:
                        d = json.load(f)
                        for s in d.get("snapshots", []):
                            if s.get("collection") == "security_audit_events":
                                for r in s.get("records", []):
                                    u = r.get("subject_reference")
                                    if u and u not in self.sec_audit_by_user:
                                        self.sec_audit_by_user[u] = r.get("resource_id")
                except Exception:
                    pass

    def _resolve_case_account_id(self, subject: SubjectIdentity, request: DeletionRequest) -> Optional[str]:
        """
        Resolves an account resource ID for the subject only when supported by
        an explicit, grounded evidence link (stable identifier) that respects
        temporal admissibility (event_time <= audit_at).
        Never synthesizes IDs from user patterns or numbering assumptions.
        """
        audit_at_str = request.audit_at.isoformat() if request.audit_at else None

        candidates = [subject.user_id.lower()] + [e.lower() for e in subject.all_emails()]
        for cand in candidates:
            if cand in self.account_links_by_user:
                res_id, ev_time = self.account_links_by_user[cand]
                if audit_at_str is None or ev_time <= audit_at_str:
                    return res_id

        return None

    def _resolve_security_audit(self, subject: SubjectIdentity) -> Optional[Tuple[str, str]]:
        if subject.user_id in self.sec_audit_by_user:
            return (self.sec_audit_by_user[subject.user_id], "")
        return None

    def audit_case(self, request: DeletionRequest) -> CaseAuditResult:
        """Runs the full audit pipeline for a single deletion request."""
        notes: List[str] = []

        # Stage 1: Intake authorization
        intake = classify_request(request.case_id, request.request_text)
        if not intake.deletion_authorized:
            return CaseAuditResult(
                case_id=request.case_id,
                deletion_status=STATUS_NOT_APPLICABLE,
                steps=[],
                intake=intake,
                notes=[f"NOT_APPLICABLE: {intake.reason}"],
            )

        # Stage 2: Identity resolution
        subject = self.identity_resolver.resolve_by_email(request.email)
        if subject is None:
            # Request email may be historical — try hash lookup (unlikely to help here but safe)
            notes.append(f"Could not resolve identity for email: {request.email}")
            # If identity is unresolvable, verification evidence cannot be gathered.
            # Do NOT claim COMPLETE with empty steps (§6.3, Gate 3.2 item 6).
            return CaseAuditResult(
                case_id=request.case_id,
                deletion_status=STATUS_INCOMPLETE,
                steps=[],
                intake=intake,
                notes=notes + ["Identity unresolvable; no evidence gathered; defaulting INCOMPLETE"],
            )

        # Stage 3: Evidence gathering
        scan_errors: List[str] = []
        grounded_acc = self._resolve_case_account_id(subject, request)
        facts = _gather_admissible_facts(
            subject=subject,
            manifest=self.manifest,
            validator=self.temporal_validator,
            audit_at=request.audit_at,
            scan_errors=scan_errors,
            grounded_account_id=grounded_acc,
        )
        if scan_errors:
            notes.extend(scan_errors)

        # Stage 4: Policy evaluation
        all_verdicts = self.policy_evaluator.evaluate_facts(facts)
        findings = [v for v in all_verdicts if v.has_finding]

        # Separate account and security audit resources
        account_resource_id = _extract_account_resource_id(facts, subject) or grounded_acc
        security_audit = _extract_security_audit_resource(facts) or self._resolve_security_audit(subject)

        # Stage 5: Status classification
        # For COMPLETE check: what verification evidence do we have?
        complete_verify_steps = _build_verification_steps_for_complete(facts, all_verdicts)
        status = _classify_status(findings, complete_verify_steps)

        # Stage 6: Step generation
        if status == STATUS_INCOMPLETE:
            raw_steps = (
                _build_finding_steps(findings)
                + _build_remediation_steps(findings)
                + _build_verification_steps_for_incomplete(
                    findings, account_resource_id, security_audit
                )
            )
        elif status == STATUS_COMPLETE:
            raw_steps = complete_verify_steps
        else:
            raw_steps = []

        raw_steps = _deduplicate_steps(raw_steps)
        final_steps = _sort_and_number_steps(raw_steps)

        # Safety check: COMPLETE can never have empty steps (§6.3, Gate 3.2 item 6)
        if status == STATUS_COMPLETE and not final_steps:
            status = STATUS_INCOMPLETE

        return CaseAuditResult(
            case_id=request.case_id,
            deletion_status=status,
            steps=final_steps,
            intake=intake,
            notes=notes,
        )

    def audit_all(self, requests: Optional[List[DeletionRequest]] = None) -> List[CaseAuditResult]:
        """Runs the full audit for all deletion requests. Returns results sorted by case_id."""
        if requests is None:
            requests = load_deletion_requests(self.requests_path)
        results = [self.audit_case(req) for req in requests]
        return sorted(results, key=lambda r: r.case_id)
