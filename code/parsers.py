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

import base64
import csv
import json
import re
import shlex
import sqlite3
import zlib
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
        "subject_key",
        "subject_ref",
        "query",
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
    if "tombstone" in combined:
        return "ACCOUNT_TOMBSTONE"
    if "marketing" in combined:
        return "MARKETING_PROFILE"
    if "attachment" in combined:
        return "SUPPORT_ATTACHMENT"
    if "analytics" in combined or "telemetry" in combined:
        return "ANALYTICS_PROFILE"
    if "search" in combined or "index" in combined:
        return "SEARCH_INDEX_ENTRY"
    if "support" in combined or "ticket" in combined:
        return "SUPPORT_MESSAGE"
    if "profile" in combined or "account" in combined:
        return "USER_PROFILE"
    if "export" in combined:
        return "USER_EXPORT"
    if "cache" in combined:
        return "CACHE_ENTRY"
    if "email" in combined and "delivery" in combined:
        return "EMAIL_DELIVERY_LOG"
    if "data_flow" in combined or "connector" in combined or "subscription" in combined:
        return "ACTIVE_DATA_FLOW"
    if "backup" in combined or "restore" in combined or "archive" in combined:
        return "BACKUP_ARCHIVE"
    if "audit" in combined or "security" in combined:
        return "SECURITY_AUDIT_LOG"
    if "legal" in combined or "hold" in combined:
        return "LEGAL_HOLD_RECORD"
    return None


# ---------------------------------------------------------------------------
# Canonical Platform System Mapping for Database Tables & Resources
# ---------------------------------------------------------------------------

SQL_TABLE_TO_SYSTEM: Dict[str, str] = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_profiles_regional": "account_service",
    "customer_profiles_reporting": "account_service",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_search_documents_regional": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "customer_analytics_profiles_regional": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
    "legal_retention_records": "legal_service",
}


def resolve_canonical_system_id(
    explicit_origin: Optional[str],
    table_name: Optional[str],
    resource_id: Optional[str],
) -> str:
    """
    Schema-aware canonical system ID resolution.
    Prioritizes resource prefix, followed by table name, followed by origin matching.
    """
    if resource_id:
        r_low = resource_id.lower()
        if r_low.startswith("account_"):
            return "account_service"
        if r_low.startswith("search_"):
            return "search_service"
        if r_low.startswith("analytics_"):
            return "analytics_platform"
        if r_low.startswith("support_"):
            return "support_platform"
        if r_low.startswith("export_"):
            return "export_service"
        if r_low.startswith("data_flow_") or r_low.startswith("connector_"):
            return "integration_service"
        if r_low.startswith("backup_"):
            return "backup_service"
        if r_low.startswith("audit_"):
            return "security_service"
        if r_low.startswith("tombstone_") or r_low.startswith("identity_"):
            return "identity_service"
        if r_low.startswith("legal_"):
            return "legal_service"

    if table_name and table_name.lower() in SQL_TABLE_TO_SYSTEM:
        return SQL_TABLE_TO_SYSTEM[table_name.lower()]

    if explicit_origin:
        cleaned = str(explicit_origin).strip().lower()
        if cleaned in {
            "account_service",
            "search_service",
            "analytics_platform",
            "support_platform",
            "export_service",
            "integration_service",
            "backup_service",
            "security_service",
            "identity_service",
            "legal_service",
        }:
            return cleaned
        if "account" in cleaned:
            return "account_service"
        if "search" in cleaned:
            return "search_service"
        if "analytics" in cleaned or "telemetry" in cleaned:
            return "analytics_platform"
        if "support" in cleaned:
            return "support_platform"
        if "export" in cleaned:
            return "export_service"
        if "data_flow" in cleaned or "connector" in cleaned or "integration" in cleaned:
            return "integration_service"
        if "backup" in cleaned or "restore" in cleaned:
            return "backup_service"
        if "audit" in cleaned or "security" in cleaned:
            return "security_service"
        if "identity" in cleaned or "tombstone" in cleaned:
            return "identity_service"
        if "legal" in cleaned:
            return "legal_service"

    return "unresolved_system"


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
                if isinstance(rec_data.get("document"), dict):
                    merged.update(rec_data["document"])

                # Check identifier match
                id_match = find_matching_identifier(merged, subject)
                if id_match is None:
                    continue

                matched_field, matched_value = id_match

                # Extract system_id, resource_id, and timestamps
                raw_origin = row_dict.get("origin_system") or rec_data.get("origin_system")
                resource_id = (
                    merged.get("resource_id")
                    or f"{table}_{row_idx}"
                )
                system_id = resolve_canonical_system_id(raw_origin, table, resource_id)

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

                # Semantic deduplication key: preserves distinct tables (e.g. primary vs failover replica)
                fact_key = (
                    ev_file.file_id,
                    table,
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
                            fallback_system=snapshot.get("data_store") or data.get("source") or ev_file.origin,
                            locator=f"{ev_file.file_path}:snapshots[{s_idx}].{coll_name}[{r_idx}]",
                            ev_file=ev_file,
                            subject=subject,
                            facts=facts,
                            seen=seen_fact_keys,
                            container_ts=exported_at,
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
                                    locator=f"{ev_file.file_path}:{svc_name}.{sub_name}[{r_idx}]",
                                    ev_file=ev_file,
                                    subject=subject,
                                    facts=facts,
                                    seen=seen_fact_keys,
                                    container_ts=None,
                                )

            # 3. Collection records structure
            elif "records" in data and isinstance(data["records"], list):
                records_read += len(data["records"])
                coll_name = data.get("collection") or data.get("source") or "records"
                container_exp_ts = parse_iso_timestamp(data.get("exported_at") or data.get("captured_at"))
                for r_idx, rec in enumerate(data["records"]):
                    if not isinstance(rec, dict):
                        errors.append(f"Malformed record at index {r_idx}")
                        continue
                    self._process_json_record(
                        rec=rec,
                        coll_or_svc=coll_name,
                        fallback_system=data.get("source") or ev_file.origin,
                        locator=f"{ev_file.file_path}:{coll_name}[{r_idx}]",
                        ev_file=ev_file,
                        subject=subject,
                        facts=facts,
                        seen=seen_fact_keys,
                        container_ts=container_exp_ts,
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
                    locator=f"{ev_file.file_path}:root[{r_idx}]",
                    ev_file=ev_file,
                    subject=subject,
                    facts=facts,
                    seen=seen_fact_keys,
                    container_ts=None,
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
        locator: str,
        ev_file: EvidenceFile,
        subject: Optional[SubjectIdentity],
        facts: List[EvidenceFact],
        seen: Set[Tuple[Any, ...]],
        container_ts: Optional[datetime] = None,
    ) -> None:
        # Check flat fields and nested document/profile sub-dictionaries
        flattened = dict(rec)
        for nested_key in ("document", "profile", "user", "metadata"):
            if nested_key in rec and isinstance(rec[nested_key], dict):
                flattened.update(rec[nested_key])
        if "hits" in rec and isinstance(rec["hits"], dict):
            hits_obj = rec["hits"]
            if "documents" in hits_obj and isinstance(hits_obj["documents"], list):
                for doc in hits_obj["documents"]:
                    if isinstance(doc, dict):
                        if subject is not None:
                            if find_matching_identifier(doc, subject):
                                flattened.update({k: v for k, v in doc.items() if v is not None})
                                break
                        else:
                            flattened.update({k: v for k, v in doc.items() if v is not None})
                            break

        id_match = find_matching_identifier(flattened, subject)
        if id_match is None:
            return

        matched_field, matched_value = id_match

        resource_id = flattened.get("resource_id") or locator.split(":")[-1]
        system_id = resolve_canonical_system_id(flattened.get("origin_system") or fallback_system, coll_or_svc, resource_id)

        # Extract internal event timestamp strictly without container timestamp fallback
        raw_ts = (
            flattened.get("observed_at")
            or flattened.get("updated_at")
            or flattened.get("indexed_at")
            or flattened.get("timestamp")
        )
        rec_ts = parse_iso_timestamp(str(raw_ts)) if raw_ts else None

        category = derive_data_category(system_id, resource_id, coll_or_svc)
        if category == "ANALYTICS_PROFILE" or "analytics" in system_id:
            if str(flattened.get("email_opt_in", "")).lower() in ("true", "1", "yes"):
                category = "MARKETING_PROFILE"

        # Determine state
        state = "PRESENT"

        is_support = (
            category == "SUPPORT_MESSAGE"
            or "support" in coll_or_svc.lower()
            or resource_id.startswith("support_")
        )
        is_tombstone = (
            category == "ACCOUNT_TOMBSTONE"
            or "tombstone" in coll_or_svc.lower()
            or resource_id.startswith("tombstone_")
        )

        if is_support:
            support_pii_keys = ("requester_email", "requester_name", "requester_phone")
            all_pii_keys_present = all(k in flattened for k in support_pii_keys)
            all_pii_explicitly_null = all_pii_keys_present and all(flattened.get(k) is None for k in support_pii_keys)
            any_pii_present = any(flattened.get(k) is not None for k in support_pii_keys)

            if all_pii_explicitly_null:
                state = "REDACTED"
            elif any_pii_present:
                state = "PRESENT"
            else:
                # Fields missing from record or export — do NOT infer redaction
                state = "PRESENT"

        elif is_tombstone:
            tombstone_pii_keys = ("name", "email", "phone", "email_hash")
            all_tombstone_keys_present = all(k in flattened for k in tombstone_pii_keys)
            all_tombstone_explicitly_null = all_tombstone_keys_present and all(flattened.get(k) is None for k in tombstone_pii_keys)
            any_tombstone_pii_present = any(flattened.get(k) is not None for k in tombstone_pii_keys)

            if all_tombstone_explicitly_null:
                state = "REDACTED"
            elif any_tombstone_pii_present:
                # Prohibited direct PII remains exposed; do NOT treat as DELETED or compliant
                state = "PRESENT"
            else:
                # Keys missing from record — do not infer compliance
                state = "PRESENT"

        elif "status_code" in flattened:
            state = "ABSENT" if flattened["status_code"] == 404 else "PRESENT"
        elif "account_status" in flattened:
            state = str(flattened["account_status"])
        elif "restore_allowed" in flattened:
            state = "ACTIVE" if flattened["restore_allowed"] in (True, 1, "1") else "BLOCKED"
        elif "enabled" in flattened:
            state = "ACTIVE" if flattened["enabled"] in (True, 1, "1") else "DISABLED"
        elif "status" in flattened:
            state = str(flattened["status"])

        # Semantic deduplication key preserves collection and resource
        fact_key = (
            ev_file.file_id,
            coll_or_svc,
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
        if container_ts:
            attrs["container_timestamp"] = container_ts.isoformat()
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
        trace_context: Dict[str, Tuple[str, str]] = {}
        trace_resources: Dict[str, str] = {}
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
                    rest_stripped = rest.strip()
                    if rest_stripped.startswith("{"):
                        try:
                            json_obj = json.loads(rest_stripped)
                            if isinstance(json_obj, dict):
                                for k, v in json_obj.items():
                                    if v is not None:
                                        kv[str(k)] = str(v)
                            else:
                                errors.append(f"Line {line_no}: JSON payload is not an object")
                                continue
                        except Exception as e:
                            errors.append(f"Line {line_no}: malformed JSON payload: {e}")
                            continue
                    else:
                        for m in self.KV_REGEX.finditer(rest):
                            k = m.group(1)
                            v = m.group(2) if m.group(2) is not None else m.group(3)
                            kv[k] = v

                    trace_id = kv.get("trace_id")
                    id_match = find_matching_identifier(kv, subject)
                    if id_match is not None:
                        matched_field, matched_value = id_match
                        if trace_id:
                            trace_context[trace_id] = id_match
                    elif trace_id and trace_id in trace_context:
                        # Safeguard: Do not inherit trace context if this line has an explicit conflicting identifier
                        if any(
                            fn in kv and str(kv[fn]).strip() and str(kv[fn]).lower() not in INVALID_IDENTIFIER_STRINGS
                            for fn in (
                                "user_id",
                                "email",
                                "user_email",
                                "customer_email",
                                "requester_email",
                                "owner_email",
                                "phone",
                                "lookup_key",
                                "subject_key",
                                "subject_ref",
                            )
                        ):
                            continue
                        matched_field, matched_value = trace_context[trace_id]
                    else:
                        continue

                    raw_res = (
                        kv.get("resource_id")
                        or kv.get("account_id")
                        or kv.get("search_id")
                    )
                    if raw_res and trace_id:
                        trace_resources[trace_id] = raw_res
                    elif not raw_res and trace_id and trace_id in trace_resources:
                        raw_res = trace_resources[trace_id]

                    # Never synthesize a data resource ID from a trace ID or line number.
                    # Skip operational lines (initiation, retry, connection) that lack an actual resource ID.
                    if not raw_res:
                        continue

                    raw_system = kv.get("service") or ev_file.origin
                    resource_id = raw_res
                    system_id = resolve_canonical_system_id(raw_system, None, resource_id)

                    event = kv.get("event", "")
                    status_val = str(kv.get("http_status") or kv.get("status") or "")

                    state = "PRESENT"
                    if "enabled" in kv:
                        state = "ACTIVE" if str(kv.get("enabled")).lower() in ("true", "1") else "DISABLED"
                    elif "restore_allowed" in kv:
                        state = "ACTIVE" if str(kv.get("restore_allowed")).lower() in ("true", "1") else "BLOCKED"
                    elif status_val == "404" or "missing" in event or "absent" in event or "deleted" in event or status_val == "ABSENT":
                        state = "ABSENT"
                    elif status_val == "200" or "present" in event or "found" in event or status_val == "PRESENT" or status_val == "ACTIVE":
                        state = "PRESENT"
                    elif "anonymized" in event:
                        state = "ANONYMIZED"
                    elif "redacted" in event:
                        state = "REDACTED"

                    category = derive_data_category(system_id, resource_id, event)
                    # Marketing profile: analytics or contact event with marketing email consent / opt-in
                    # Governed by deletion_rules.csv Rule 10: MARKETING_PROFILE, Always, DELETE
                    if category == "ANALYTICS_PROFILE" or "analytics" in system_id:
                        if kv.get("email_opt_in", "").lower() in ("true", "1", "yes"):
                            category = "MARKETING_PROFILE"
                    locator = f"{ev_file.file_path}:{line_no}"

                    # Semantic deduplication: resource in same event, state, and timestamp
                    fact_key = (
                        ev_file.file_id,
                        system_id,
                        resource_id,
                        event,
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
                    if trace_id:
                        attrs["trace_id"] = trace_id
                    if status_val:
                        attrs["status_val"] = status_val

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

        # Trace resolution:
        # Correlate profile_lookup_started and profile_lookup_completed events by trace/request identity.
        # When a valid terminal event establishes HTTP 404 / ABSENT, do not leave a stale initiation-only
        # PRESENT fact that triggers a false remaining-record finding.
        # Genuinely independent events and traces are preserved.
        # Do not infer a terminal result when no terminal event exists.
        terminal_absent_traces: Set[Tuple[str, str]] = set()
        terminal_traces: Set[Tuple[str, str]] = set()

        for f in facts:
            tid = f.get_attribute("trace_id")
            ev = f.get_attribute("event") or ""
            if tid and (ev.endswith("_completed") or "completed" in ev):
                terminal_traces.add((tid, f.resource_id))
                if f.status_or_state == "ABSENT" or f.get_attribute("status_val") == "404":
                    terminal_absent_traces.add((tid, f.resource_id))

        resolved_facts: List[EvidenceFact] = []
        for f in facts:
            tid = f.get_attribute("trace_id")
            ev = f.get_attribute("event") or ""
            if tid and (ev.endswith("_started") or "started" in ev):
                key = (tid, f.resource_id)
                if key in terminal_absent_traces:
                    # Terminal event established ABSENT (e.g. 404); drop stale initiation fact
                    continue
                if key in terminal_traces and f.status_or_state == "PRESENT":
                    # Terminal event completed; drop duplicate initiation fact
                    continue
            resolved_facts.append(f)

        status = ParseStatus.SUCCESS if not errors else ParseStatus.PARTIAL_SUCCESS
        return EvidenceParseResult(
            file_id=ev_file.file_id,
            file_path=ev_file.file_path,
            status=status,
            facts=tuple(resolved_facts),
            records_read=records_read,
            facts_extracted=len(resolved_facts),
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
                    elif status_str in ("ACTIVE", "ENABLED"):
                        state = "ACTIVE"
                    elif status_str in ("DISABLED", "BLOCKED"):
                        state = "DISABLED"
                    elif status_str in ("IDENTIFIABLE", "PRESENT", "FOUND"):
                        state = "PRESENT"

                    norm_category = category
                    if category == "DATA_FLOW" or res_id.startswith("data_flow_") or res_id.startswith("connector_"):
                        norm_category = "ACTIVE_DATA_FLOW"

                    fact_key = (
                        ev_file.file_id,
                        service,
                        res_id,
                        norm_category,
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
                            data_category=norm_category,
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

    def _extract_pdf_tokens(self, pdf_path: Path) -> Tuple[List[str], List[str]]:
        """
        Pure-Python standard-library stream decompressor for PDF documents.
        Handles FlateDecode, ASCII85Decode, string literal escapes, octal escapes,
        and hex strings, while skipping binary font programs.
        Returns (tokens, errors).
        """
        try:
            data = pdf_path.read_bytes()
        except Exception as e:
            return [], [f"Failed to read file on disk: {e}"]

        tokens: List[str] = []
        errors: List[str] = []

        pattern = re.compile(rb"<<\s*([^>]*?)\s*>>\s*stream[\r\n]+(.*?)[\r\n]*endstream", re.DOTALL)
        for m in pattern.finditer(data):
            dict_part = m.group(1).decode("latin-1", errors="ignore")
            raw_stream = m.group(2)

            # Skip embedded fonts or non-content binary assets
            if "/Length1" in dict_part or "/Type /Font" in dict_part or "CIDFont" in dict_part:
                continue

            decomp: Optional[bytes] = None
            if "ASCII85Decode" in dict_part and "FlateDecode" in dict_part:
                try:
                    s = raw_stream.strip()
                    if not s.startswith(b"<~"):
                        s = b"<~" + s
                    if not s.endswith(b"~>"):
                        s = s + b"~>"
                    dec = base64.a85decode(s, adobe=True)
                    decomp = zlib.decompress(dec)
                except Exception as e:
                    errors.append(f"ASCII85+Flate decompression error: {e}")
            elif "FlateDecode" in dict_part:
                try:
                    decomp = zlib.decompress(raw_stream.strip())
                except Exception as e:
                    errors.append(f"Flate decompression error: {e}")
            elif "ASCII85Decode" in dict_part:
                try:
                    s = raw_stream.strip()
                    if not s.startswith(b"<~"):
                        s = b"<~" + s
                    if not s.endswith(b"~>"):
                        s = s + b"~>"
                    decomp = base64.a85decode(s, adobe=True)
                except Exception as e:
                    errors.append(f"ASCII85 decompression error: {e}")
            elif "/Filter" in dict_part:
                errors.append(f"Unsupported stream filter in {dict_part[:60]}")
            else:
                decomp = raw_stream

            if decomp:
                i = 0
                n = len(decomp)
                while i < n:
                    c = decomp[i:i + 1]
                    # Parse literal string: (...)
                    if c == b"(":
                        i += 1
                        buf = []
                        depth = 1
                        while i < n and depth > 0:
                            ch = decomp[i:i + 1]
                            if ch == b"\\":
                                i += 1
                                if i < n:
                                    esc = decomp[i:i + 1]
                                    if esc == b"n":
                                        buf.append(b"\n")
                                    elif esc == b"r":
                                        buf.append(b"\r")
                                    elif esc == b"t":
                                        buf.append(b"\t")
                                    elif esc == b"b":
                                        buf.append(b"\b")
                                    elif esc == b"f":
                                        buf.append(b"\f")
                                    elif esc in (b"(", b")", b"\\"):
                                        buf.append(esc)
                                    elif esc.isdigit():
                                        oct_digits = esc
                                        while i + 1 < n and decomp[i + 1:i + 2].isdigit() and len(oct_digits) < 3:
                                            i += 1
                                            oct_digits += decomp[i:i + 1]
                                        try:
                                            buf.append(bytes([int(oct_digits, 8)]))
                                        except Exception:
                                            buf.append(oct_digits)
                                    else:
                                        buf.append(esc)
                            elif ch == b"(":
                                depth += 1
                                buf.append(ch)
                            elif ch == b")":
                                depth -= 1
                                if depth > 0:
                                    buf.append(ch)
                            else:
                                buf.append(ch)
                            i += 1
                        s_val = b"".join(buf).decode("latin-1", errors="ignore").strip()
                        if s_val:
                            tokens.append(s_val)
                    # Parse hex string: <...>
                    elif c == b"<" and i + 1 < n and decomp[i + 1:i + 2] != b"<":
                        end_hex = decomp.find(b">", i + 1)
                        if end_hex != -1:
                            hex_str = decomp[i + 1:end_hex].strip()
                            if len(hex_str) % 2 == 1:
                                hex_str += b"0"
                            try:
                                s_val = bytes.fromhex(hex_str.decode("latin-1")).decode("latin-1", errors="ignore").strip()
                                if s_val:
                                    tokens.append(s_val)
                            except Exception:
                                pass
                            i = end_hex + 1
                        else:
                            i += 1
                    else:
                        i += 1

        return tokens, errors

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
            try:
                tokens, parse_errors = self._extract_pdf_tokens(ev_file.absolute_path)
                facts: List[EvidenceFact] = []
                if tokens and subject is not None:
                    full_text = " ".join(tokens)
                    matched_id: Optional[Tuple[str, str]] = None
                    for email in subject.all_emails():
                        if email.lower() in full_text.lower():
                            matched_id = ("email", email)
                            break
                    if not matched_id:
                        for phone in subject.all_phones():
                            if phone in full_text:
                                matched_id = ("phone", phone)
                                break
                    if not matched_id and subject.name and subject.name.lower() in full_text.lower():
                        matched_id = ("name", subject.name)
                    if not matched_id and subject.user_id in full_text:
                        matched_id = ("user_id", subject.user_id)

                    if matched_id:
                        matched_field, matched_value = matched_id
                        res_matches = re.findall(r"\b(support_\w+|account_\w+|export_\w+|search_\w+|audit_\w+)\b", full_text)
                        primary_res = res_matches[0] if res_matches else f"doc_{ev_file.file_id}"
                        system_id = resolve_canonical_system_id(ev_file.origin, ev_file.file_path, primary_res)
                        category = derive_data_category(system_id, primary_res, ev_file.file_path)

                        facts.append(
                            EvidenceFact(
                                file_id=ev_file.file_id,
                                file_path=ev_file.file_path,
                                origin=ev_file.origin,
                                file_captured_at=ev_file.captured_at,
                                record_timestamp=None,
                                system_id=system_id,
                                resource_id=primary_res,
                                data_category=category,
                                raw_event=full_text[:500],
                                status_or_state="PRESENT",
                                matched_identifier_field=matched_field,
                                matched_identifier_value=matched_value,
                                attributes={"document_type": "pdf_attachment"},
                                source_locator=f"{ev_file.file_path}:stream",
                            )
                        )

                if facts:
                    return EvidenceParseResult(
                        file_id=ev_file.file_id,
                        file_path=ev_file.file_path,
                        status=ParseStatus.SUCCESS,
                        facts=tuple(facts),
                        records_read=len(tokens),
                        facts_extracted=len(facts),
                        errors=tuple(parse_errors),
                    )
                else:
                    return EvidenceParseResult(
                        file_id=ev_file.file_id,
                        file_path=ev_file.file_path,
                        status=ParseStatus.UNSUPPORTED_FORMAT,
                        facts=(),
                        records_read=len(tokens),
                        facts_extracted=0,
                        errors=(
                            f"PDF document parsing requires external dependency (pypdf/pdfminer); "
                            f"file {ev_file.file_path} remains unparsed and cannot serve as evidence of absence.",
                        ),
                    )
            except Exception as e:
                return EvidenceParseResult(
                    file_id=ev_file.file_id,
                    file_path=ev_file.file_path,
                    status=ParseStatus.PARSE_ERROR,
                    errors=(f"PDF extraction error: {e}",),
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
