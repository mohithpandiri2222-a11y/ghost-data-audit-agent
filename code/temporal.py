"""
Temporal Admissibility Validation Engine for HackerRank Orchestrate (October 2026).

Implements strict, non-negotiable temporal admissibility rules:
1. The source file must be listed in the validated evidence manifest.
2. The file's captured_at must be at or before the case's audit_at (file_captured_at <= audit_at).
3. If an evidence record has its own internal event/record timestamp, that timestamp
   must also be at or before audit_at (record_timestamp <= audit_at).
4. If the internal timestamp is missing, invalid, or unparseable, represent it explicitly
   as unknown/unproven (record_timestamp=None, is_record_event_proven=False).
   NEVER substitute the file's captured_at for the record timestamp.
5. Evidence captured after audit_at is INADMISSIBLE, even if an internal timestamp appears earlier.
6. Evidence captured exactly at audit_at is admissible for that time gate (<= audit_at).
7. Keep file-level admissibility and record-level temporal proof as separate concepts.
   A file passing its time gate does not automatically prove its records are timely.
8. Invalid timestamps must not silently become admissible.

Reference: AGENTS.md §6.2, §6.6, ARCHITECTURE_AND_PROMPTS.md §4.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Union

from code.config import (
    EvidenceFact,
    EvidenceFile,
    load_evidence_manifest,
    parse_iso_timestamp,
)


@dataclass(frozen=True)
class TemporalValidationResult:
    """
    Structured temporal validation verdict for an individual EvidenceFact.

    Guarantees strict separation between file-level container gating and
    record-level event timing proof.
    """
    is_admissible: bool
    is_file_admissible: bool
    is_record_event_proven: bool
    is_record_event_admissible: Optional[bool]
    file_captured_at: datetime
    record_timestamp: Optional[datetime]
    audit_at: datetime
    rejection_reason: Optional[str] = None
    file_id: str = ""

    @property
    def is_rejected(self) -> bool:
        """Returns True if the fact fails pre-audit temporal admissibility."""
        return not self.is_admissible


class TemporalAdmissibilityValidator:
    """
    Strict temporal admissibility validator enforcing dual-timestamp gating.
    """

    def __init__(self, manifest: Optional[Dict[str, EvidenceFile]] = None) -> None:
        self.manifest: Dict[str, EvidenceFile] = (
            manifest if manifest is not None else load_evidence_manifest()
        )

    def _normalize_audit_at(self, audit_at: Union[datetime, str]) -> datetime:
        """Parses and validates ISO-8601 audit_at timestamp."""
        if isinstance(audit_at, datetime):
            return audit_at
        parsed = parse_iso_timestamp(audit_at)
        if parsed is None:
            raise ValueError(f"Invalid or unparseable audit_at timestamp: {audit_at}")
        return parsed

    def validate_file(self, file_id: str, audit_at: Union[datetime, str]) -> bool:
        """
        Validates file-level container admissibility.
        Returns True if and only if:
        1. file_id exists in the evidence manifest.
        2. file.captured_at <= audit_at.
        """
        cutoff = self._normalize_audit_at(audit_at)
        ev_file = self.manifest.get(file_id)
        if ev_file is None:
            return False
        return ev_file.captured_at <= cutoff

    def validate_fact(
        self,
        fact: EvidenceFact,
        audit_at: Union[datetime, str],
    ) -> TemporalValidationResult:
        """
        Evaluates full dual-temporal admissibility of an EvidenceFact.

        Rules:
        - Rule 1: Manifest Check. Fact's file_id must exist in manifest.
        - Rule 2: File Gating. file_captured_at <= audit_at.
        - Rule 3: Record Gating. If record_timestamp is proven, record_timestamp <= audit_at.
        - Rule 4: Explicit Unknown. Missing/unparseable record_timestamp remains None.
        - Rule 5: No Retroactive Rescues. Timely record cannot rescue late file.
        - Rule 6: Timely file cannot rescue late internal record.
        - Rule 7: Exact cutoff matching (<=) is admissible.
        """
        cutoff = self._normalize_audit_at(audit_at)

        # 1. Manifest Membership
        if fact.file_id not in self.manifest:
            return TemporalValidationResult(
                is_admissible=False,
                is_file_admissible=False,
                is_record_event_proven=fact.is_event_time_proven,
                is_record_event_admissible=fact.is_record_event_admissible(cutoff),
                file_captured_at=fact.file_captured_at,
                record_timestamp=fact.record_timestamp,
                audit_at=cutoff,
                rejection_reason="UNMANIFESTED_FILE",
                file_id=fact.file_id,
            )

        # 2. File-Level Admissibility Gate (File captured_at <= audit_at)
        is_file_ok = fact.file_captured_at <= cutoff
        if not is_file_ok:
            return TemporalValidationResult(
                is_admissible=False,
                is_file_admissible=False,
                is_record_event_proven=fact.is_event_time_proven,
                is_record_event_admissible=fact.is_record_event_admissible(cutoff),
                file_captured_at=fact.file_captured_at,
                record_timestamp=fact.record_timestamp,
                audit_at=cutoff,
                rejection_reason="FILE_CAPTURED_AFTER_AUDIT_AT",
                file_id=fact.file_id,
            )

        # 3. Record-Level Event Timing Gate
        is_proven = fact.is_event_time_proven
        is_rec_ok = fact.is_record_event_admissible(cutoff)

        if is_proven and not is_rec_ok:
            # File is timely, but the specific record/event occurred AFTER audit_at
            return TemporalValidationResult(
                is_admissible=False,
                is_file_admissible=True,
                is_record_event_proven=True,
                is_record_event_admissible=False,
                file_captured_at=fact.file_captured_at,
                record_timestamp=fact.record_timestamp,
                audit_at=cutoff,
                rejection_reason="RECORD_TIMESTAMP_AFTER_AUDIT_AT",
                file_id=fact.file_id,
            )

        # Admissible under dual temporal rule:
        # File is bounded on or before audit_at, and record is either proven timely
        # or represents a snapshot record with unknown internal event time.
        return TemporalValidationResult(
            is_admissible=True,
            is_file_admissible=True,
            is_record_event_proven=is_proven,
            is_record_event_admissible=is_rec_ok,
            file_captured_at=fact.file_captured_at,
            record_timestamp=fact.record_timestamp,
            audit_at=cutoff,
            rejection_reason=None,
            file_id=fact.file_id,
        )

    def filter_admissible_facts(
        self,
        facts: Iterable[EvidenceFact],
        audit_at: Union[datetime, str],
    ) -> List[EvidenceFact]:
        """Filters an iterable of EvidenceFact to only those admissible for audit_at."""
        cutoff = self._normalize_audit_at(audit_at)
        return [f for f in facts if self.validate_fact(f, cutoff).is_admissible]
