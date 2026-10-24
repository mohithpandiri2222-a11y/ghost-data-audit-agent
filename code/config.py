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

    Validations (Gate 1.1 F-01 & F-03):
    1. Rejects duplicate manifest file_id entries.
    2. Prevents resolved evidence paths from escaping DATASET_DIR.
    3. Validates that each manifest-referenced file exists on disk and is a regular file.
    4. Validates captured_at ISO-8601 timestamps.
    """
    path = manifest_path or EVIDENCE_FILES_PATH
    if not path.exists():
        raise FileNotFoundError(f"Evidence manifest not found at: {path}")

    dataset_root = DATASET_DIR.resolve()
    manifest: Dict[str, EvidenceFile] = {}
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            file_id = row["file_id"].strip()
            if not file_id:
                raise ValueError("Manifest row missing file_id")

            # F-01: Reject duplicate manifest file IDs
            if file_id in manifest:
                raise ValueError(f"Duplicate file_id in evidence manifest: {file_id}")

            file_path = row["file_path"].strip()
            origin = row["origin"].strip()
            captured_at = parse_iso_timestamp(row["captured_at"])
            if captured_at is None:
                raise ValueError(f"Invalid captured_at in manifest for {file_id}: {row['captured_at']}")

            # F-01: Prevent resolved evidence paths from escaping dataset directory
            abs_path = (DATASET_DIR / file_path).resolve()
            try:
                if not abs_path.is_relative_to(dataset_root):
                    raise ValueError(f"Evidence file path escapes dataset directory: {file_path}")
            except AttributeError:
                try:
                    abs_path.relative_to(dataset_root)
                except ValueError:
                    raise ValueError(f"Evidence file path escapes dataset directory: {file_path}")

            # F-03: Validate that each manifest-referenced file exists and is a regular file
            if not abs_path.exists():
                raise FileNotFoundError(f"Evidence file missing on disk: {abs_path} (file_id: {file_id})")
            if not abs_path.is_file():
                raise FileNotFoundError(f"Evidence path is not a regular file: {abs_path} (file_id: {file_id})")

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

    CRITICAL RULES (ARCHITECTURE_AND_PROMPTS.md §4.3, Gate 1.1 F-02):
    1. file_captured_at is the upper bound of container capture.
    2. record_timestamp is the explicit timestamp of the internal event/record.
       If record_timestamp is absent, it MUST remain None (unknown).
       file_captured_at is NEVER substituted as a missing record's event timestamp.
    3. File-level admissibility is explicitly distinguished from whether an
       individual record's event time is proven.
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
        if isinstance(self.attributes, dict):
            object.__setattr__(
                self,
                "attributes",
                tuple(sorted((str(k), str(v)) for k, v in self.attributes.items())),
            )
        elif not isinstance(self.attributes, tuple):
            object.__setattr__(self, "attributes", tuple(self.attributes))

    @property
    def attributes_dict(self) -> Dict[str, str]:
        """Returns attributes as a dictionary."""
        return dict(self.attributes)

    def get_attribute(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves an attribute by key."""
        return dict(self.attributes).get(key, default)

    @property
    def has_record_timestamp(self) -> bool:
        """Returns True if the internal record has an explicit event timestamp."""
        return self.record_timestamp is not None

    @property
    def is_event_time_proven(self) -> bool:
        """
        F-02: Explicitly reports whether the individual record's event time is proven.
        When record_timestamp is None, the event time is unproven/unknown.
        Missing record timestamps must remain unknown and must never be replaced
        by file capture timestamps.
        """
        return self.record_timestamp is not None

    def is_file_admissible(self, audit_at: datetime) -> bool:
        """
        F-02: Evaluates file-level admissibility.
        Returns True if the containing evidence file was captured on or before audit_at.
        """
        return self.file_captured_at <= audit_at

    def is_record_event_admissible(self, audit_at: datetime) -> Optional[bool]:
        """
        F-02: Evaluates record-level event admissibility against audit_at cutoff.
        - Returns True if record_timestamp is proven and <= audit_at.
        - Returns False if record_timestamp is proven and > audit_at.
        - Returns None if record_timestamp is unproven (None). Missing record timestamps
          remain unknown and are never replaced by file capture timestamps.
        """
        if self.record_timestamp is None:
            return None
        return self.record_timestamp <= audit_at

    def is_temporally_admissible(self, audit_at: datetime) -> bool:
        """
        Dual temporal rule evaluation for pre-audit evidence admissibility:
        1. File Gating: file_captured_at <= audit_at (is_file_admissible).
        2. Record Gating: if record_timestamp is proven, record_timestamp <= audit_at.
           If record_timestamp is unproven (None), the event time remains unknown, but the
           fact as observed in the snapshot/file captured at or before audit_at is admissible.
        """
        if not self.is_file_admissible(audit_at):
            return False
        if self.record_timestamp is not None and self.record_timestamp > audit_at:
            return False
        return True
