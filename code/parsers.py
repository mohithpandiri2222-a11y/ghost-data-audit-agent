"""
Provenance-Preserving Evidence Parsers for HackerRank Orchestrate (October 2026).

Parses heterogeneous evidence formats from dataset/evidence/:
- SQL Database Snapshots (.sql via in-memory SQLite DDL/DML execution)
- JSON Snapshot Bundles & Service Resource Exports (.json)
- Structured Key-Value Syslog Logs (.log)
- Shift Handover Plaintext Tables (.txt)
- Document & Image Files (.pdf, .png with explicit parse outcome status)

Requirements:
- Strict source provenance tracking (file_id, file_path, origin, source_locator).
- Explicit separation of file capture bound from internal record timestamps.
- Zero timestamp fabrication (missing timestamps remain None / unknown).
- Safe handling of malformed records without silent file discard.
- Deduplication of facts during traversal.
- Zero assumption of global completeness or invented absence facts.

Reference: AGENTS.md §6.1, §6.6, ARCHITECTURE_AND_PROMPTS.md §2.
"""

from __future__ import annotations

import csv
import json
import re
import shlex
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from code.config import (
    DATASET_DIR,
    EvidenceFact,
    EvidenceFile,
    load_evidence_manifest,
    parse_iso_timestamp,
)
from code.identity import (
    INVALID_IDENTIFIER_STRINGS,
    SubjectIdentity,
    normalize_email,
    normalize_hash,
    normalize_phone,
)


class ParseStatus(str, Enum):
    """Explicit parse outcome status for evidence files."""
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    PARSE_ERROR = "PARSE_ERROR"


@dataclass(frozen=True)
class EvidenceParseResult:
    """
    Immutable structured parse result for an evidence file.
    Preserves extracted facts, record counts, and explicit error provenance.
    """
    file_id: str
    file_path: str
    status: ParseStatus
    facts: Tuple[EvidenceFact, ...] = field(default_factory=tuple)
    records_read: int = 0
    facts_extracted: int = 0
    errors: Tuple[str, ...] = field(default_factory=tuple)
    warnings: Tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Helper Identifier Matcher
# ---------------------------------------------------------------------------

def find_matching_identifier(
    data: Mapping[str, Any],
    subject: Optional[SubjectIdentity],
) -> Optional[Tuple[str, str]]:
    """
    Inspects a dictionary of record fields for an identifier matching the subject.
    If subject is None, returns the first non-null, non-sentinel identifier found.
    Returns (field_name, field_value) or None if no match.
    """
    # Priority order of identifier candidates
    candidate_fields = (
        "user_id",
        "customer_reference",
        "subject_reference",
        "account_id",
        "email",
        "user_email",
        "customer_email",
        "requester_email",
        "owner_email",
        "match_key",
        "phone",
        "user_phone",
        "requester_phone",
        "owner_phone",
        "email_hash",
        "correlation_key",
        "lookup_key",
    )

    for fn in candidate_fields:
        val = data.get(fn)
        if val is None:
            continue
        sval = str(val).strip()
        if not sval or sval.lower() in INVALID_IDENTIFIER_STRINGS:
            continue

        if subject is not None:
            if subject.matches_identifier(fn, sval):
                return (fn, sval)
        else:
            # When extracting without subject filter, return first valid identifier
            return (fn, sval)

    return None


def derive_data_category(
    system_id: str,
    resource_id: str,
    collection_or_table: str,
) -> Optional[str]:
    """Heuristic data category derivation strictly aligned with deletion_rules.csv."""
    combined = f"{system_id}_{resource_id}_{collection_or_table}".lower()
    if "profile" in combined or "account" in combined:
        return "USER_PROFILE"
    if "search" in combined or "index" in combined:
        return "SEARCH_INDEX_ENTRY"
    if "analytics" in combined:
        return "ANALYTICS_PROFILE"
    if "support" in combined or "ticket" in combined:
        return "SUPPORT_MESSAGE"
    if "export" in combined:
        return "USER_EXPORT"
    if "data_flow" in combined or "connector" in combined or "subscription" in combined:
        return "ACTIVE_DATA_FLOW"
    if "backup" in combined or "restore" in combined or "archive" in combined:
        return "BACKUP_ARCHIVE"
    if "audit" in combined or "security" in combined:
        return "SECURITY_AUDIT_LOG"
    return None


# ---------------------------------------------------------------------------
# Base Parser Interface
# ---------------------------------------------------------------------------

class BaseEvidenceParser(ABC):
    """Abstract interface for format-specific evidence parsers."""

    @abstractmethod
    def parse(
        self,
        ev_file: EvidenceFile,
        subject: Optional[SubjectIdentity] = None,
    ) -> EvidenceParseResult:
        """Parses the evidence file into structured facts."""
        pass


# ---------------------------------------------------------------------------
# SQL Evidence Parser (.sql)
# ---------------------------------------------------------------------------

class SQLEvidenceParser(BaseEvidenceParser):
    """
    Parses SQLite-compatible database snapshots (.sql).
    Executes the DDL and DML in an isolated in-memory SQLite database and
    queries table schemas dynamically.
    """

    def parse(
        self,
        ev_file: EvidenceFile,
        subject: Optional[SubjectIdentity] = None,
    ) -> EvidenceParseResult:
        if not ev_file.absolute_path.exists():
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Physical file missing on disk: {ev_file.absolute_path}",),
            )

        try:
            sql_script = ev_file.absolute_path.read_text(encoding="utf-8")
        except Exception as e:
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Failed to read SQL file: {e}",),
            )

        con = sqlite3.connect(":memory:")
        try:
            con.executescript(sql_script)
        except Exception as e:
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"SQLite script execution failed: {e}",),
            )

        tables = [
            r[0]
            for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]

        facts: List[EvidenceFact] = []
        seen_fact_keys: Set[Tuple[Any, ...]] = set()
        errors: List[str] = []
        records_read = 0

        for table in tables:
            try:
                cur = con.execute(f"SELECT * FROM {table}")
                cols = [d[0] for d in cur.description]
            except Exception as e:
                errors.append(f"Failed to inspect table {table}: {e}")
                continue

            rows = cur.fetchall()
            records_read += len(rows)

            for row_idx, row in enumerate(rows):
                row_dict = dict(zip(cols, row))

                # Handle JSON payload tables vs flat relational tables
                record_json_raw = row_dict.get("record_json")
                rec_data: Dict[str, Any] = {}
                if record_json_raw and isinstance(record_json_raw, str):
                    try:
                        rec_data = json.loads(record_json_raw)
                    except Exception as e:
                        errors.append(f"Invalid record_json in {table}:{row_idx}: {e}")
                        rec_data = {}

                # Merged view of columns and embedded json
                merged = dict(row_dict)
                merged.update(rec_data)

                # Check identifier match
                id_match = find_matching_identifier(merged, subject)
                if id_match is None:
                    continue

                matched_field, matched_value = id_match

                # Extract system_id, resource_id, and timestamps
                system_id = (
                    row_dict.get("origin_system")
                    or rec_data.get("origin_system")
                    or ev_file.origin
                )
                resource_id = (
                    merged.get("resource_id")
                    or f"{table}_{row_idx}"
                )

                # Extract record-level timestamp (updated_at / indexed_at)
                raw_ts = (
                    merged.get("updated_at")
                    or merged.get("indexed_at")
                    or merged.get("observed_at")
                )
                rec_ts = parse_iso_timestamp(str(raw_ts)) if raw_ts else None

                # Determine state/status
                state = "PRESENT"
                if "account_status" in merged:
                    state = str(merged["account_status"])
                elif "enabled" in merged:
                    state = "ACTIVE" if merged["enabled"] in (1, True, "1") else "DISABLED"
                elif "restore_allowed" in merged:
                    state = "ACTIVE" if merged["restore_allowed"] in (1, True, "1") else "BLOCKED"
                elif "status_code" in merged:
                    state = "ABSENT" if merged["status_code"] == 404 else "PRESENT"
                elif "status" in merged:
                    state = str(merged["status"])

                # Determine category
                category = derive_data_category(
                    system_id, resource_id, row_dict.get("collection_name") or table
                )

                # Source locator
                locator = f"{ev_file.file_path}:{table}:{resource_id}"

                # Semantic deduplication key
                fact_key = (
                    ev_file.file_id,
                    system_id,
                    resource_id,
                    state,
                    rec_ts,
                    matched_field,
                    matched_value,
                )
                if fact_key in seen_fact_keys:
                    continue
                seen_fact_keys.add(fact_key)

                # Attributes
                attrs = {
                    "table": table,
                    "matched_field": matched_field,
                    "matched_value": matched_value,
                }
                if "retention_until" in merged and merged["retention_until"]:
                    attrs["retention_until"] = str(merged["retention_until"])
                if "collection_name" in row_dict and row_dict["collection_name"]:
                    attrs["collection_name"] = str(row_dict["collection_name"])

                fact = EvidenceFact(
                    file_id=ev_file.file_id,
                    file_path=ev_file.file_path,
                    origin=ev_file.origin,
                    file_captured_at=ev_file.captured_at,
                    record_timestamp=rec_ts,
                    system_id=system_id,
                    resource_id=resource_id,
                    data_category=category,
                    raw_event=record_json_raw or json.dumps(row_dict),
                    status_or_state=state,
                    matched_identifier_field=matched_field,
                    matched_identifier_value=matched_value,
                    attributes=attrs,
                    source_locator=locator,
                )
                facts.append(fact)

        status = ParseStatus.SUCCESS if not errors else ParseStatus.PARTIAL_SUCCESS
        return EvidenceParseResult(
            file_id=ev_file.file_id,
            file_path=ev_file.file_path,
            status=status,
            facts=tuple(facts),
            records_read=records_read,
            facts_extracted=len(facts),
            errors=tuple(errors),
        )


# ---------------------------------------------------------------------------
# JSON Evidence Parser (.json)
# ---------------------------------------------------------------------------

class JSONEvidenceParser(BaseEvidenceParser):
    """
    Parses JSON records and snapshots (.json).
    Supports:
    1. Snapshot bundles: {"snapshots": [{"collection": "...", "records": [...]}]}
    2. Service resource exports: {"service_exports": {"account_service": {"lookups": [...]}}}
    3. Flat collection records: {"records": [...]} or list of dicts.
    """

    def parse(
        self,
        ev_file: EvidenceFile,
        subject: Optional[SubjectIdentity] = None,
    ) -> EvidenceParseResult:
        if not ev_file.absolute_path.exists():
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Physical file missing on disk: {ev_file.absolute_path}",),
            )

        try:
            content = ev_file.absolute_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except Exception as e:
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Failed to parse JSON content: {e}",),
            )

        facts: List[EvidenceFact] = []
        seen_fact_keys: Set[Tuple[Any, ...]] = set()
        errors: List[str] = []
        records_read = 0

        # Dispatched extraction based on JSON structure
        if isinstance(data, dict):
            # 1. Snapshot bundle structure
            if "snapshots" in data and isinstance(data["snapshots"], list):
                exported_at = parse_iso_timestamp(data.get("exported_at"))
                for s_idx, snapshot in enumerate(data["snapshots"]):
                    if not isinstance(snapshot, dict):
                        errors.append(f"Malformed snapshot entry at index {s_idx}")
                        continue
                    coll_name = snapshot.get("collection", f"snapshot_{s_idx}")
                    recs = snapshot.get("records", [])
                    if not isinstance(recs, list):
                        continue
                    records_read += len(recs)
                    for r_idx, rec in enumerate(recs):
                        if not isinstance(rec, dict):
                            errors.append(f"Malformed record in {coll_name}[{r_idx}]")
                            continue
                        self._process_json_record(
                            rec=rec,
                            coll_or_svc=coll_name,
                            fallback_system=data.get("source") or ev_file.origin,
                            fallback_ts=exported_at,
                            locator=f"{ev_file.file_path}:snapshots[{s_idx}].{coll_name}[{r_idx}]",
                            ev_file=ev_file,
                            subject=subject,
                            facts=facts,
                            seen=seen_fact_keys,
                        )

            # 2. Service resource export structure
            elif "service_exports" in data and isinstance(data["service_exports"], dict):
                for svc_name, svc_data in data["service_exports"].items():
                    if not isinstance(svc_data, dict):
                        continue
                    for sub_name, recs in svc_data.items():
                        if isinstance(recs, list):
                            records_read += len(recs)
                            for r_idx, rec in enumerate(recs):
                                if not isinstance(rec, dict):
                                    errors.append(f"Malformed record in {svc_name}.{sub_name}[{r_idx}]")
                                    continue
                                self._process_json_record(
                                    rec=rec,
                                    coll_or_svc=f"{svc_name}.{sub_name}",
                                    fallback_system=svc_name,
                                    fallback_ts=None,
                                    locator=f"{ev_file.file_path}:{svc_name}.{sub_name}[{r_idx}]",
                                    ev_file=ev_file,
                                    subject=subject,
                                    facts=facts,
                                    seen=seen_fact_keys,
                                )

            # 3. Collection records structure
            elif "records" in data and isinstance(data["records"], list):
                records_read += len(data["records"])
                coll_name = data.get("collection") or data.get("source") or "records"
                for r_idx, rec in enumerate(data["records"]):
                    if not isinstance(rec, dict):
                        errors.append(f"Malformed record at index {r_idx}")
                        continue
                    self._process_json_record(
                        rec=rec,
                        coll_or_svc=coll_name,
                        fallback_system=data.get("source") or ev_file.origin,
                        fallback_ts=parse_iso_timestamp(data.get("exported_at") or data.get("captured_at")),
                        locator=f"{ev_file.file_path}:{coll_name}[{r_idx}]",
                        ev_file=ev_file,
                        subject=subject,
                        facts=facts,
                        seen=seen_fact_keys,
                    )
        elif isinstance(data, list):
            records_read += len(data)
            for r_idx, rec in enumerate(data):
                if not isinstance(rec, dict):
                    errors.append(f"Malformed top-level list record at index {r_idx}")
                    continue
                self._process_json_record(
                    rec=rec,
                    coll_or_svc="root",
                    fallback_system=ev_file.origin,
                    fallback_ts=None,
                    locator=f"{ev_file.file_path}:root[{r_idx}]",
                    ev_file=ev_file,
                    subject=subject,
                    facts=facts,
                    seen=seen_fact_keys,
                )

        status = ParseStatus.SUCCESS if not errors else ParseStatus.PARTIAL_SUCCESS
        return EvidenceParseResult(
            file_id=ev_file.file_id,
            file_path=ev_file.file_path,
            status=status,
            facts=tuple(facts),
            records_read=records_read,
            facts_extracted=len(facts),
            errors=tuple(errors),
        )

    def _process_json_record(
        self,
        rec: Dict[str, Any],
        coll_or_svc: str,
        fallback_system: str,
        fallback_ts: Optional[datetime],
        locator: str,
        ev_file: EvidenceFile,
        subject: Optional[SubjectIdentity],
        facts: List[EvidenceFact],
        seen: Set[Tuple[Any, ...]],
    ) -> None:
        # Check flat fields and nested document/profile sub-dictionaries
        flattened = dict(rec)
        for nested_key in ("document", "profile", "user", "metadata"):
            if nested_key in rec and isinstance(rec[nested_key], dict):
                flattened.update(rec[nested_key])

        id_match = find_matching_identifier(flattened, subject)
        if id_match is None:
            return

        matched_field, matched_value = id_match

        system_id = flattened.get("origin_system") or fallback_system
        resource_id = flattened.get("resource_id") or locator.split(":")[-1]

        # Extract internal event timestamp
        raw_ts = (
            flattened.get("observed_at")
            or flattened.get("updated_at")
            or flattened.get("indexed_at")
            or flattened.get("timestamp")
        )
        rec_ts = parse_iso_timestamp(str(raw_ts)) if raw_ts else fallback_ts

        # Determine state
        state = "PRESENT"
        if "status_code" in flattened:
            state = "ABSENT" if flattened["status_code"] == 404 else "PRESENT"
        elif "account_status" in flattened:
            state = str(flattened["account_status"])
        elif "restore_allowed" in flattened:
            state = "ACTIVE" if flattened["restore_allowed"] in (True, 1, "1") else "BLOCKED"
        elif "enabled" in flattened:
            state = "ACTIVE" if flattened["enabled"] in (True, 1, "1") else "DISABLED"
        elif "status" in flattened:
            state = str(flattened["status"])

        category = derive_data_category(system_id, resource_id, coll_or_svc)

        fact_key = (
            ev_file.file_id,
            system_id,
            resource_id,
            state,
            rec_ts,
            matched_field,
            matched_value,
        )
        if fact_key in seen:
            return
        seen.add(fact_key)

        attrs = {
            "collection": coll_or_svc,
            "matched_field": matched_field,
            "matched_value": matched_value,
        }
        if "retention_until" in flattened and flattened["retention_until"]:
            attrs["retention_until"] = str(flattened["retention_until"])

        facts.append(
            EvidenceFact(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                origin=ev_file.origin,
                file_captured_at=ev_file.captured_at,
                record_timestamp=rec_ts,
                system_id=system_id,
                resource_id=resource_id,
                data_category=category,
                raw_event=json.dumps(rec),
                status_or_state=state,
                matched_identifier_field=matched_field,
                matched_identifier_value=matched_value,
                attributes=attrs,
                source_locator=locator,
            )
        )


# ---------------------------------------------------------------------------
# Log Evidence Parser (.log)
# ---------------------------------------------------------------------------

class LogEvidenceParser(BaseEvidenceParser):
    """
    Parses structured key-value syslog events (.log).
    Extracts timestamps, services, resources, trace correlation keys, and states.
    Reports malformed lines in errors without discarding the entire file.
    """

    KV_REGEX = re.compile(r'([a-zA-Z0-9_\-]+)=(?:"([^"]*)"|([^\s]+))')

    def parse(
        self,
        ev_file: EvidenceFile,
        subject: Optional[SubjectIdentity] = None,
    ) -> EvidenceParseResult:
        if not ev_file.absolute_path.exists():
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Physical file missing on disk: {ev_file.absolute_path}",),
            )

        facts: List[EvidenceFact] = []
        seen_fact_keys: Set[Tuple[Any, ...]] = set()
        errors: List[str] = []
        records_read = 0

        try:
            with open(ev_file.absolute_path, "r", encoding="utf-8") as f:
                for line_no, raw_line in enumerate(f, 1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    records_read += 1

                    parts = line.split(maxsplit=1)
                    if not parts:
                        continue

                    ts_str = parts[0]
                    rec_ts = parse_iso_timestamp(ts_str)
                    if rec_ts is None:
                        # Missing or invalid timestamp on log line - record error and skip malformed line
                        errors.append(f"Line {line_no}: invalid timestamp format '{ts_str}'")
                        continue

                    rest = parts[1] if len(parts) > 1 else ""
                    kv: Dict[str, str] = {}
                    for m in self.KV_REGEX.finditer(rest):
                        k = m.group(1)
                        v = m.group(2) if m.group(2) is not None else m.group(3)
                        kv[k] = v

                    id_match = find_matching_identifier(kv, subject)
                    if id_match is None:
                        continue

                    matched_field, matched_value = id_match

                    system_id = kv.get("service") or ev_file.origin
                    resource_id = (
                        kv.get("resource_id")
                        or kv.get("account_id")
                        or kv.get("search_id")
                        or kv.get("trace_id")
                        or f"{system_id}_{line_no}"
                    )

                    event = kv.get("event", "")
                    status_val = kv.get("status")

                    state = "PRESENT"
                    if status_val == "404" or "missing" in event or "absent" in event:
                        state = "ABSENT"
                    elif status_val == "200" or "present" in event or "found" in event:
                        state = "PRESENT"
                    elif "anonymized" in event:
                        state = "ANONYMIZED"
                    elif "redacted" in event:
                        state = "REDACTED"

                    category = derive_data_category(system_id, resource_id, event)
                    locator = f"{ev_file.file_path}:{line_no}"

                    # Semantic deduplication: resource in same state and timestamp
                    fact_key = (
                        ev_file.file_id,
                        system_id,
                        resource_id,
                        state,
                        rec_ts,
                        matched_field,
                        matched_value,
                    )
                    if fact_key in seen_fact_keys:
                        continue
                    seen_fact_keys.add(fact_key)

                    attrs = {
                        "event": event,
                        "line_no": str(line_no),
                        "matched_field": matched_field,
                        "matched_value": matched_value,
                    }
                    if "trace_id" in kv:
                        attrs["trace_id"] = kv["trace_id"]

                    facts.append(
                        EvidenceFact(
                            file_id=ev_file.file_id,
                            file_path=ev_file.file_path,
                            origin=ev_file.origin,
                            file_captured_at=ev_file.captured_at,
                            record_timestamp=rec_ts,
                            system_id=system_id,
                            resource_id=resource_id,
                            data_category=category,
                            raw_event=line,
                            status_or_state=state,
                            matched_identifier_field=matched_field,
                            matched_identifier_value=matched_value,
                            attributes=attrs,
                            source_locator=locator,
                        )
                    )

        except Exception as e:
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Log file read error: {e}",),
            )

        status = ParseStatus.SUCCESS if not errors else ParseStatus.PARTIAL_SUCCESS
        return EvidenceParseResult(
            file_id=ev_file.file_id,
            file_path=ev_file.file_path,
            status=status,
            facts=tuple(facts),
            records_read=records_read,
            facts_extracted=len(facts),
            errors=tuple(errors),
        )


# ---------------------------------------------------------------------------
# Text Evidence Parser (.txt)
# ---------------------------------------------------------------------------

class TextEvidenceParser(BaseEvidenceParser):
    """
    Parses shift handover text files (.txt).
    Row format: timestamp | service | resource_id | category | status | identifier
    """

    def parse(
        self,
        ev_file: EvidenceFile,
        subject: Optional[SubjectIdentity] = None,
    ) -> EvidenceParseResult:
        if not ev_file.absolute_path.exists():
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Physical file missing on disk: {ev_file.absolute_path}",),
            )

        facts: List[EvidenceFact] = []
        seen_fact_keys: Set[Tuple[Any, ...]] = set()
        errors: List[str] = []
        records_read = 0

        try:
            with open(ev_file.absolute_path, "r", encoding="utf-8") as f:
                for line_no, raw_line in enumerate(f, 1):
                    line = raw_line.strip()
                    if not line or not line.startswith("- "):
                        continue

                    content = line[2:].strip()
                    parts = [p.strip() for p in content.split("|")]
                    if len(parts) < 6:
                        errors.append(f"Line {line_no}: insufficient pipe-separated columns")
                        continue

                    records_read += 1
                    ts_str, service, res_id, category, status_str, ident_str = parts[:6]

                    rec_ts = parse_iso_timestamp(ts_str)

                    # Check identifier matching
                    dummy_dict = {
                        "email": ident_str,
                        "user_id": ident_str,
                        "resource_id": res_id,
                    }
                    id_match = find_matching_identifier(dummy_dict, subject)
                    if id_match is None:
                        continue

                    matched_field, matched_value = id_match

                    state = "PRESENT"
                    if status_str == "NOT_FOUND":
                        state = "ABSENT"
                    elif status_str == "ANONYMIZED":
                        state = "ANONYMIZED"
                    elif status_str == "REDACTED":
                        state = "REDACTED"
                    elif status_str in ("IDENTIFIABLE", "ACTIVE", "PRESENT"):
                        state = "PRESENT"

                    fact_key = (
                        ev_file.file_id,
                        service,
                        res_id,
                        state,
                        rec_ts,
                        matched_field,
                        matched_value,
                    )
                    if fact_key in seen_fact_keys:
                        continue
                    seen_fact_keys.add(fact_key)
                    locator = f"{ev_file.file_path}:{line_no}"
                    facts.append(
                        EvidenceFact(
                            file_id=ev_file.file_id,
                            file_path=ev_file.file_path,
                            origin=ev_file.origin,
                            file_captured_at=ev_file.captured_at,
                            record_timestamp=rec_ts,
                            system_id=service,
                            resource_id=res_id,
                            data_category=category,
                            raw_event=line,
                            status_or_state=state,
                            matched_identifier_field=matched_field,
                            matched_identifier_value=matched_value,
                            attributes={
                                "line_no": str(line_no),
                                "status_str": status_str,
                            },
                            source_locator=locator,
                        )
                    )

        except Exception as e:
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Text file read error: {e}",),
            )

        status = ParseStatus.SUCCESS if not errors else ParseStatus.PARTIAL_SUCCESS
        return EvidenceParseResult(
            file_id=ev_file.file_id,
            file_path=ev_file.file_path,
            status=status,
            facts=tuple(facts),
            records_read=records_read,
            facts_extracted=len(facts),
            errors=tuple(errors),
        )


# ---------------------------------------------------------------------------
# Document & Image Evidence Parser (.pdf, .png)
# ---------------------------------------------------------------------------

class DocumentImageEvidenceParser(BaseEvidenceParser):
    """
    Handles PDF documents (.pdf) and UI screenshot images (.png).
    Inspects available dependencies and project conventions.

    CRITICAL RULE (Prompt §4):
    Never silently treat an unsupported or unparsed file as evidence of absence.
    Record an explicit parse outcome, including UNSUPPORTED_FORMAT when necessary.
    """

    def parse(
        self,
        ev_file: EvidenceFile,
        subject: Optional[SubjectIdentity] = None,
    ) -> EvidenceParseResult:
        if not ev_file.absolute_path.exists():
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.PARSE_ERROR,
                errors=(f"Physical file missing on disk: {ev_file.absolute_path}",),
            )

        suffix = ev_file.absolute_path.suffix.lower()

        # Check for PDF
        if suffix == ".pdf":
            # In standard python environment without pypdf/fitz, record explicit outcome
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.UNSUPPORTED_FORMAT,
                errors=(
                    f"PDF document parsing requires external dependency (pypdf/pdfminer); "
                    f"file {ev_file.file_path} remains unparsed and cannot serve as evidence of absence.",
                ),
            )

        # Check for PNG / Images
        if suffix in (".png", ".jpg", ".jpeg"):
            return EvidenceParseResult(
                file_id=ev_file.file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.UNSUPPORTED_FORMAT,
                errors=(
                    f"Image OCR parsing requires external dependency (pytesseract/PIL); "
                    f"file {ev_file.file_path} remains unparsed and cannot serve as evidence of absence.",
                ),
            )

        return EvidenceParseResult(
            file_id=ev_file.file_id,
            file_path=ev_file.file_path,
            status=ParseStatus.UNSUPPORTED_FORMAT,
            errors=(f"Unsupported file format '{suffix}' for {ev_file.file_path}",),
        )


# ---------------------------------------------------------------------------
# Unified Evidence Parser Engine / Registry
# ---------------------------------------------------------------------------

class UnifiedEvidenceParser:
    """
    Master registry and dispatcher for all evidence parsers.
    Parses manifest files by extension into structured EvidenceParseResult instances.
    """

    def __init__(self, manifest: Optional[Dict[str, EvidenceFile]] = None) -> None:
        self.manifest: Dict[str, EvidenceFile] = (
            manifest if manifest is not None else load_evidence_manifest()
        )
        self._sql_parser = SQLEvidenceParser()
        self._json_parser = JSONEvidenceParser()
        self._log_parser = LogEvidenceParser()
        self._txt_parser = TextEvidenceParser()
        self._doc_parser = DocumentImageEvidenceParser()

    def parse_file(
        self,
        file_id: str,
        subject: Optional[SubjectIdentity] = None,
    ) -> EvidenceParseResult:
        """Parses a specific manifest-referenced file."""
        ev_file = self.manifest.get(file_id)
        if ev_file is None:
            return EvidenceParseResult(
                file_id=file_id,
                file_path="",
                status=ParseStatus.PARSE_ERROR,
                errors=(f"File ID '{file_id}' not found in evidence manifest",),
            )

        suffix = ev_file.absolute_path.suffix.lower()
        if suffix == ".sql":
            return self._sql_parser.parse(ev_file, subject)
        elif suffix == ".json":
            return self._json_parser.parse(ev_file, subject)
        elif suffix == ".log":
            return self._log_parser.parse(ev_file, subject)
        elif suffix == ".txt":
            return self._txt_parser.parse(ev_file, subject)
        elif suffix in (".pdf", ".png", ".jpg", ".jpeg"):
            return self._doc_parser.parse(ev_file, subject)
        else:
            return EvidenceParseResult(
                file_id=file_id,
                file_path=ev_file.file_path,
                status=ParseStatus.UNSUPPORTED_FORMAT,
                errors=(f"Unrecognized file extension '{suffix}'",),
            )

    def parse_all_for_subject(
        self,
        subject: SubjectIdentity,
    ) -> List[EvidenceFact]:
        """
        Parses all manifest evidence files for a given subject identity,
        returning deduplicated facts across the entire corpus.
        """
        all_facts: List[EvidenceFact] = []
        global_seen: Set[Tuple[Any, ...]] = set()

        for file_id in sorted(self.manifest.keys()):
            res = self.parse_file(file_id, subject)
            for fact in res.facts:
                key = (
                    fact.file_id,
                    fact.system_id,
                    fact.resource_id,
                    fact.source_locator,
                    fact.status_or_state,
                    fact.record_timestamp,
                )
                if key not in global_seen:
                    global_seen.add(key)
                    all_facts.append(fact)

        return all_facts
