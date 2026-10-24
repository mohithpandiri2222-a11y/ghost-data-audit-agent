"""
Configuration, path resolution, constants, and foundational data structures
for the HackerRank Orchestrate (October 2026) deletion-audit agent.

Reference: AGENTS.md, problem_statement.md, ARCHITECTURE_AND_PROMPTS.md.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Repository-Relative Path Resolution
# ---------------------------------------------------------------------------

# Resolve repository root dynamically relative to this file
REPO_ROOT: Path = Path(__file__).resolve().parent.parent

# Core participant-facing dataset directory
DATASET_DIR: Path = REPO_ROOT / "dataset"
EVIDENCE_DIR: Path = DATASET_DIR / "evidence"

# Dataset file paths
DELETION_REQUESTS_PATH: Path = DATASET_DIR / "deletion_requests.csv"
SAMPLE_DELETION_REQUESTS_PATH: Path = DATASET_DIR / "sample_deletion_requests.csv"
USER_IDENTITIES_PATH: Path = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_PATH: Path = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_PATH: Path = DATASET_DIR / "system_activity.csv"
DELETION_RULES_PATH: Path = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_PATH: Path = DATASET_DIR / "evidence_files.csv"
SAMPLE_OUTPUT_PATH: Path = DATASET_DIR / "sample_output.csv"

# Root prediction and log files
OUTPUT_PATH: Path = REPO_ROOT / "output.csv"
LOG_PATH: Path = REPO_ROOT / "log.txt"


# ---------------------------------------------------------------------------
# Specification Domains & Allowed Operations
# (Strictly matching problem_statement.md:103-120 and AGENTS.md §6.3, §6.4)
# ---------------------------------------------------------------------------

STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
VALID_STATUSES = frozenset({STATUS_COMPLETE, STATUS_INCOMPLETE, STATUS_NOT_APPLICABLE})

PHASE_FINDING = "FINDING"
PHASE_REMEDIATION = "REMEDIATION"
PHASE_VERIFICATION = "VERIFICATION"
VALID_PHASES = (PHASE_FINDING, PHASE_REMEDIATION, PHASE_VERIFICATION)

# Canonical Allowed Operations per Phase (Order is significant per problem_statement.md:126)
FINDING_OPERATIONS = (
    ("REPORT_REMAINING_RECORD", "PRESENT"),
    ("REPORT_EXPOSED_PII", "PRESENT"),
    ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("REPORT_RESTORE_RISK", "ACTIVE"),
)

REMEDIATION_OPERATIONS = (
    ("DISABLE_DATA_FLOW", "DISABLED"),
    ("BLOCK_RESTORE", "BLOCKED"),
    ("DELETE_RECORD", "ABSENT"),
    ("REDACT_RECORD", "REDACTED"),
    ("ANONYMIZE_RECORD", "ANONYMIZED"),
)

VERIFICATION_OPERATIONS = (
    ("VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
)

# Mapping of valid operations to allowed states
ALLOWED_OPERATION_STATES: Mapping[str, str] = dict(
    FINDING_OPERATIONS + REMEDIATION_OPERATIONS + VERIFICATION_OPERATIONS
)

# Canonical ordering rank within each phase
OPERATION_ORDER_RANK: Mapping[str, int] = {
    op: idx for idx, (op, _) in enumerate(
        FINDING_OPERATIONS + REMEDIATION_OPERATIONS + VERIFICATION_OPERATIONS
    )
}


# ---------------------------------------------------------------------------
# Timestamp Utilities
# ---------------------------------------------------------------------------

def parse_iso_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """
    Parses ISO-8601 timestamps terminating in 'Z' or offset into UTC datetime.
    Returns None if timestamp string is empty or invalid.
    """
    if not ts or not ts.strip():
        return None
    cleaned = ts.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Evidence File Manifest Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceFile:
    """
    Represents an evidence file cataloged in dataset/evidence_files.csv.
    """
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime
    absolute_path: Path

    def is_admissible_for_case(self, audit_at: datetime) -> bool:
        """
        Dual temporal rule - file gating:
        A file is admissible for a case if and only if file.captured_at <= case.audit_at.
        Files captured after audit_at are wholly inadmissible.
        """
        return self.captured_at <= audit_at


def load_evidence_manifest(manifest_path: Optional[Path] = None) -> Dict[str, EvidenceFile]:
    """
    Loads evidence_files.csv and indexes all evidence files by file_id.
    Validates file existence and parses UTC capture times.
    """
    path = manifest_path or EVIDENCE_FILES_PATH
    if not path.exists():
        raise FileNotFoundError(f"Evidence manifest not found at: {path}")

    manifest: Dict[str, EvidenceFile] = {}
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            file_id = row["file_id"].strip()
            file_path = row["file_path"].strip()
            origin = row["origin"].strip()
            captured_at = parse_iso_timestamp(row["captured_at"])
            if captured_at is None:
                raise ValueError(f"Invalid captured_at in manifest for {file_id}: {row['captured_at']}")

            abs_path = DATASET_DIR / file_path
            manifest[file_id] = EvidenceFile(
                file_id=file_id,
                file_path=file_path,
                origin=origin,
                captured_at=captured_at,
                absolute_path=abs_path,
            )

    return manifest


# ---------------------------------------------------------------------------
# Immutable Evidence Fact Model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceFact:
    """
    Immutable representation of a concrete fact extracted from evidence.

    CRITICAL RULE (ARCHITECTURE_AND_PROMPTS.md §4.3):
    file_captured_at is the upper bound of container capture.
    record_timestamp is the explicit timestamp of the internal event/record.
    If record_timestamp is absent, it MUST remain None.
    file_captured_at is NEVER substituted as a missing record's event timestamp.
    """
    file_id: str
    file_path: str
    origin: str
    file_captured_at: datetime
    record_timestamp: Optional[datetime]
    system_id: str
    resource_id: str
    data_category: Optional[str]
    raw_event: Optional[str]
    status_or_state: str
    matched_identifier_field: str
    matched_identifier_value: str
    attributes: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)
    source_locator: str = ""

    def __post_init__(self) -> None:
        if not self.file_id:
            raise ValueError("EvidenceFact must specify a non-empty file_id")
        if not self.system_id:
            raise ValueError("EvidenceFact must specify a non-empty system_id")
        if not self.resource_id:
            raise ValueError("EvidenceFact must specify a non-empty resource_id")
        if self.file_captured_at is None:
            raise ValueError("EvidenceFact must specify file_captured_at")

    @property
    def has_record_timestamp(self) -> bool:
        """Returns True if the internal record has an explicit event timestamp."""
        return self.record_timestamp is not None

    def is_temporally_admissible(self, audit_at: datetime) -> bool:
        """
        Evaluates dual temporal rule:
        1. File Gating: file_captured_at <= audit_at
        2. Record Gating: if record_timestamp is present, record_timestamp <= audit_at.
        If file was captured after audit_at, returns False.
        """
        if self.file_captured_at > audit_at:
            return False
        if self.record_timestamp is not None and self.record_timestamp > audit_at:
            return False
        return True
