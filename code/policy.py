"""
Policy Rule Evaluation — Stage 5 of the HackerRank Orchestrate audit pipeline.

Maps admissible EvidenceFacts to deletion policy rules from deletion_rules.csv
and determines the required remediation action.

Rules (AGENTS.md §6.5, ARCHITECTURE_AND_PROMPTS.md §5.1):
- Policy derives strictly from deletion_rules.csv.
- System_activity.csv events are claims, not proof.
- Retain/tombstone records are not findings; they are compliant.
- Exposed PII in REDACT/ANONYMIZE records is a finding.
- Data category must match the evidence fact's derived category.
- Unknown categories default to no finding (safe under-reporting).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from code.config import (
    DELETION_RULES_PATH,
    EvidenceFact,
    PHASE_FINDING,
    PHASE_REMEDIATION,
    PHASE_VERIFICATION,
)


# ---------------------------------------------------------------------------
# Deletion rule model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str   # DELETE, REDACT, ANONYMIZE, RETAIN


def load_deletion_rules(path: Optional[Path] = None) -> Dict[str, DeletionRule]:
    """Loads deletion_rules.csv indexed by data_category."""
    p = path or DELETION_RULES_PATH
    rules: Dict[str, DeletionRule] = {}
    with open(p, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cat = row["data_category"].strip()
            rules[cat] = DeletionRule(
                rule_id=row["rule_id"].strip(),
                data_category=cat,
                condition=row["condition"].strip(),
                required_action=row["required_action"].strip(),
            )
    return rules


# ---------------------------------------------------------------------------
# Policy evaluation result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyVerdict:
    """
    The policy assessment of a single EvidenceFact.

    - finding_operation / finding_state: populated when a violation is detected.
    - remediation_operation / remediation_state: the required remediation action.
    - verification_operation / verification_state: the verification check.
    - is_compliant_retention: True when policy requires RETAIN (no finding emitted).
    - is_ambiguous: True for the analytics DELETE vs ANONYMIZE discrepancy.
    """
    fact: EvidenceFact
    rule: Optional[DeletionRule]

    # Finding
    finding_operation: Optional[str] = None
    finding_state: Optional[str] = None

    # Remediation
    remediation_operation: Optional[str] = None
    remediation_state: Optional[str] = None

    # Verification
    verification_operation: Optional[str] = None
    verification_state: Optional[str] = None

    # Metadata
    is_compliant_retention: bool = False
    is_ambiguous: bool = False
    notes: str = ""

    @property
    def has_finding(self) -> bool:
        return self.finding_operation is not None

    @property
    def is_data_flow_finding(self) -> bool:
        return self.finding_operation in ("REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK")


# ---------------------------------------------------------------------------
# State-aware finding suppression
# ---------------------------------------------------------------------------

_ALREADY_COMPLIANT_STATES = frozenset({
    "ABSENT", "DELETED", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED",
    "404",
})


def _is_already_remediated(state: str) -> bool:
    """Returns True if the evidence fact's state_or_status shows the record is already handled."""
    return state.upper() in _ALREADY_COMPLIANT_STATES


# ---------------------------------------------------------------------------
# Core policy evaluator
# ---------------------------------------------------------------------------

class PolicyEvaluator:
    """
    Maps EvidenceFacts to policy findings based on deletion_rules.csv.

    Usage:
        evaluator = PolicyEvaluator()
        verdicts = evaluator.evaluate_facts(admissible_facts)
    """

    def __init__(self, rules_path: Optional[Path] = None) -> None:
        self.rules: Dict[str, DeletionRule] = load_deletion_rules(rules_path)

    def evaluate_fact(self, fact: EvidenceFact) -> PolicyVerdict:
        """Evaluates a single EvidenceFact against policy rules."""
        category = fact.data_category
        if not category:
            # Cannot categorize — no finding, no remediation
            return PolicyVerdict(fact=fact, rule=None, notes="Uncategorized fact; no policy finding")

        state = fact.status_or_state or "PRESENT"

        # ACCOUNT_TOMBSTONE: direct PII must be verified redacted before treating as compliant.
        # account_status == "DELETED" does not establish tombstone compliance if PII remains.
        if category == "ACCOUNT_TOMBSTONE":
            rule = self.rules.get(category)
            if state.upper() == "REDACTED":
                return PolicyVerdict(
                    fact=fact,
                    rule=rule,
                    is_compliant_retention=True,
                    notes="ACCOUNT_TOMBSTONE direct PII verified redacted",
                )
            return PolicyVerdict(
                fact=fact,
                rule=rule,
                finding_operation="REPORT_EXPOSED_PII",
                finding_state="PRESENT",
                remediation_operation="REDACT_RECORD",
                remediation_state="REDACTED",
                verification_operation="VERIFY_RECORD_REDACTED",
                verification_state="REDACTED",
                notes="ACCOUNT_TOMBSTONE retains exposed direct PII or unproven redaction",
            )

        # If already in a compliant end-state, suppress finding
        if _is_already_remediated(state):
            rule = self.rules.get(category)
            return PolicyVerdict(
                fact=fact,
                rule=rule,
                is_compliant_retention=(rule.required_action == "RETAIN") if rule else False,
                notes=f"Record already in compliant state: {state}",
            )

        # Active data flow connector — DISABLE (governed by AGENTS.md §6.4, not in deletion_rules.csv)
        if category == "ACTIVE_DATA_FLOW":
            if state.upper() in ("ACTIVE", "ENABLED", "1", "TRUE"):
                return PolicyVerdict(
                    fact=fact,
                    rule=None,
                    finding_operation="REPORT_ACTIVE_DATA_FLOW",
                    finding_state="ACTIVE",
                    remediation_operation="DISABLE_DATA_FLOW",
                    remediation_state="DISABLED",
                    verification_operation="VERIFY_DATA_FLOW_DISABLED",
                    verification_state="DISABLED",
                )
            return PolicyVerdict(fact=fact, rule=None, is_compliant_retention=False)

        rule = self.rules.get(category)
        if rule is None:
            return PolicyVerdict(fact=fact, rule=None, notes=f"No rule for category: {category}")

        action = rule.required_action

        # RETAIN / LEGAL_HOLD / BACKUP_ARCHIVE rules → no deletion finding
        if action == "RETAIN":
            if category == "BACKUP_ARCHIVE":
                # Backup archives should have restore blocked; if restore_allowed/ACTIVE → finding
                if state.upper() in ("ACTIVE", "PRESENT", "1", "TRUE"):
                    return PolicyVerdict(
                        fact=fact,
                        rule=rule,
                        finding_operation="REPORT_RESTORE_RISK",
                        finding_state="ACTIVE",
                        remediation_operation="BLOCK_RESTORE",
                        remediation_state="BLOCKED",
                        verification_operation="VERIFY_RESTORE_BLOCKED",
                        verification_state="BLOCKED",
                    )
                else:
                    # Backup is already blocked — compliant
                    return PolicyVerdict(fact=fact, rule=rule, is_compliant_retention=True)
            elif category == "SECURITY_AUDIT_LOG":
                # Security audit logs are retained — compliant (no finding)
                # Architecture §7.2: retention condition may be unproven but we don't fabricate violations
                return PolicyVerdict(
                    fact=fact,
                    rule=rule,
                    is_compliant_retention=True,
                    notes="SECURITY_AUDIT_LOG retained per rule_12; retention period unproven but no finding fabricated",
                )
            elif category == "LEGAL_HOLD_RECORD":
                return PolicyVerdict(fact=fact, rule=rule, is_compliant_retention=True)
            else:
                # Generic RETAIN
                return PolicyVerdict(fact=fact, rule=rule, is_compliant_retention=True)

        # DELETE action
        if action == "DELETE":
            return PolicyVerdict(
                fact=fact,
                rule=rule,
                finding_operation="REPORT_REMAINING_RECORD",
                finding_state="PRESENT",
                remediation_operation="DELETE_RECORD",
                remediation_state="ABSENT",
                verification_operation="VERIFY_RECORD_ABSENT",
                verification_state="ABSENT",
            )

        # REDACT action (SUPPORT_MESSAGE, EMAIL_DELIVERY_LOG)
        if action == "REDACT":
            return PolicyVerdict(
                fact=fact,
                rule=rule,
                finding_operation="REPORT_EXPOSED_PII",
                finding_state="PRESENT",
                remediation_operation="REDACT_RECORD",
                remediation_state="REDACTED",
                verification_operation="VERIFY_RECORD_REDACTED",
                verification_state="REDACTED",
            )

        # ANONYMIZE action (PRODUCT_TELEMETRY, ANALYTICS_PROFILE per explicit policy rule_07)
        if action == "ANONYMIZE":
            is_ambiguous = (category == "ANALYTICS_PROFILE")
            notes = (
                "ANALYTICS_PROFILE: evaluated as ANONYMIZE per explicit policy rule_07; "
                "sample_output case_12 showed DELETE_RECORD (unresolved policy discrepancy)."
                if is_ambiguous else ""
            )
            return PolicyVerdict(
                fact=fact,
                rule=rule,
                finding_operation="REPORT_EXPOSED_PII",
                finding_state="PRESENT",
                remediation_operation="ANONYMIZE_RECORD",
                remediation_state="ANONYMIZED",
                verification_operation="VERIFY_RECORD_ANONYMIZED",
                verification_state="ANONYMIZED",
                is_ambiguous=is_ambiguous,
                notes=notes,
            )

        # Unknown action — no finding
        return PolicyVerdict(
            fact=fact,
            rule=rule,
            notes=f"Unrecognized required_action: {action}",
        )

    def evaluate_facts(self, facts: List[EvidenceFact]) -> List[PolicyVerdict]:
        """Evaluates all facts and returns all verdicts."""
        return [self.evaluate_fact(f) for f in facts]

    def get_findings(self, facts: List[EvidenceFact]) -> List[PolicyVerdict]:
        """Returns only verdicts that have a non-None finding operation."""
        return [v for v in self.evaluate_facts(facts) if v.has_finding]
