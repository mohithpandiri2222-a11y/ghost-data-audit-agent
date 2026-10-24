"""
Identity Resolution and Subject Graph Construction for the Deletion-Audit Agent.

Loads current identity snapshots and historical audit mutations to establish
complete subject graphs anchored to stable internal user_id.

CRITICAL RULES (ARCHITECTURE_AND_PROMPTS.md §3):
1. Historical email hashes are extracted DIRECTLY from user_audit_log.csv (field_name='email_hash', old_value).
   Never recompute, hash dynamically, or guess historical hashes.
2. Null identifiers, empty strings, and unrelated decoys MUST NEVER create identity matches.
3. Matching supports current and historical emails, phones, and email hashes.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Set

from code.config import (
    USER_AUDIT_LOG_PATH,
    USER_IDENTITIES_PATH,
    parse_iso_timestamp,
)


def normalize_phone(phone: Optional[str]) -> str:
    """Removes whitespace, dashes, and parentheses from a phone number."""
    if not phone:
        return ""
    return re.sub(r"[\s\-\(\)\.]+", "", phone.strip())


def normalize_email(email: Optional[str]) -> str:
    """Normalizes email to lowercased trimmed string."""
    if not email:
        return ""
    return email.strip().lower()


def normalize_hash(h: Optional[str]) -> str:
    """Normalizes hex hash string to lowercased trimmed string."""
    if not h:
        return ""
    return h.strip().lower()


INVALID_IDENTIFIER_STRINGS = frozenset({
    "", "null", "none", "undefined", "n/a", "na", "unknown", "nil", "{}"
})


@dataclass(frozen=True)
class SubjectIdentity:
    """
    Immutable subject identity graph representing all known current and
    historical identifiers for a single user, anchored to stable user_id.
    """
    user_id: str
    name: str
    current_email: str
    historical_emails: FrozenSet[str] = field(default_factory=frozenset)
    current_phone: str = ""
    historical_phones: FrozenSet[str] = field(default_factory=frozenset)
    current_email_hash: str = ""
    historical_email_hashes: FrozenSet[str] = field(default_factory=frozenset)
    updated_at: Optional[datetime] = None

    def all_emails(self) -> FrozenSet[str]:
        """Returns union of current and historical emails in normalized lowercase."""
        emails: Set[str] = set(self.historical_emails)
        if self.current_email:
            emails.add(normalize_email(self.current_email))
        return frozenset(emails)

    def all_phones(self) -> FrozenSet[str]:
        """Returns union of current and historical phones in normalized form."""
        phones: Set[str] = set(self.historical_phones)
        if self.current_phone:
            phones.add(normalize_phone(self.current_phone))
        return frozenset(phones)

    def all_hashes(self) -> FrozenSet[str]:
        """Returns union of current and pre-recorded historical SHA-256 email hashes."""
        hashes: Set[str] = set(self.historical_email_hashes)
        if self.current_email_hash:
            hashes.add(normalize_hash(self.current_email_hash))
        return frozenset(hashes)

    def matches_identifier(self, field_name: str, value: Optional[str]) -> bool:
        """
        Determines whether a candidate identifier value matches this subject.

        Safety guarantees:
        - None, empty string, or sentinel null strings return False.
        - Exact matching on stable user_id.
        - Case-insensitive matching on emails and hashes.
        - Whitespace-normalized matching on phone numbers.
        """
        if value is None:
            return False
        cleaned = value.strip()
        if not cleaned or cleaned.lower() in INVALID_IDENTIFIER_STRINGS:
            return False

        fn = field_name.strip().lower()

        # Match user_id / subject references
        if fn in {"user_id", "subject_id", "customer_reference", "subject_reference", "account_id", "user_reference"}:
            return cleaned == self.user_id

        # Match emails
        if fn in {"email", "user_email", "customer_email", "recipient_email", "historical_email", "subject_key"}:
            return normalize_email(cleaned) in self.all_emails()

        # Match phone numbers
        if fn in {"phone", "phone_number", "mobile", "user_phone"}:
            return normalize_phone(cleaned) in self.all_phones()

        # Match email hashes and correlation keys
        if fn in {"email_hash", "correlation_key", "lookup_key", "hash", "subject_hash"}:
            norm_hash = normalize_hash(cleaned)
            if norm_hash and norm_hash in self.all_hashes():
                return True

        # Fallback heuristic: check if value matches any known identifier format
        norm_email = normalize_email(cleaned)
        if norm_email in self.all_emails():
            return True

        norm_hash = normalize_hash(cleaned)
        if norm_hash in self.all_hashes():
            return True

        norm_phone = normalize_phone(cleaned)
        if norm_phone and norm_phone in self.all_phones():
            return True

        return False


class IdentityResolver:
    """
    In-memory identity resolution engine.
    Constructs subject identity graphs from participant-facing CSV snapshots
    and audit logs.
    """

    def __init__(
        self,
        identities_path: Optional[Path] = None,
        audit_log_path: Optional[Path] = None,
    ) -> None:
        self.identities_path = identities_path or USER_IDENTITIES_PATH
        self.audit_log_path = audit_log_path or USER_AUDIT_LOG_PATH

        self._by_user_id: Dict[str, SubjectIdentity] = {}
        self._by_email: Dict[str, str] = {}  # normalized email -> user_id
        self._by_phone: Dict[str, str] = {}  # normalized phone -> user_id
        self._by_hash: Dict[str, str] = {}   # normalized hash -> user_id

        self._load()

    def _load(self) -> None:
        if not self.identities_path.exists():
            raise FileNotFoundError(f"Identities file not found: {self.identities_path}")
        if not self.audit_log_path.exists():
            raise FileNotFoundError(f"Audit log file not found: {self.audit_log_path}")

        # 1. Parse current identity snapshots
        raw_snapshots: Dict[str, Dict[str, Any]] = {}
        with open(self.identities_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                raw_snapshots[uid] = {
                    "user_id": uid,
                    "name": row.get("name", "").strip(),
                    "email": row.get("email", "").strip(),
                    "phone": row.get("phone", "").strip(),
                    "email_hash": row.get("email_hash", "").strip(),
                    "updated_at": parse_iso_timestamp(row.get("updated_at")),
                    "historical_emails": set(),
                    "historical_phones": set(),
                    "historical_hashes": set(),
                }

        # 2. Reconstruct historical identifiers from user_audit_log.csv
        # Direct extraction: read recorded old_value without recomputation.
        with open(self.audit_log_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                if uid not in raw_snapshots:
                    continue

                field_name = row.get("field_name", "").strip().lower()
                old_val = row.get("old_value", "").strip()
                if not old_val or old_val.lower() in INVALID_IDENTIFIER_STRINGS:
                    continue

                if field_name == "email":
                    raw_snapshots[uid]["historical_emails"].add(normalize_email(old_val))
                elif field_name == "phone":
                    raw_snapshots[uid]["historical_phones"].add(normalize_phone(old_val))
                elif field_name == "email_hash":
                    # Direct extraction of recorded historical email hash
                    raw_snapshots[uid]["historical_hashes"].add(normalize_hash(old_val))

        # 3. Build immutable SubjectIdentity instances and multi-indexes
        for uid, data in raw_snapshots.items():
            subject = SubjectIdentity(
                user_id=uid,
                name=data["name"],
                current_email=data["email"],
                historical_emails=frozenset(data["historical_emails"]),
                current_phone=data["phone"],
                historical_phones=frozenset(data["historical_phones"]),
                current_email_hash=data["email_hash"],
                historical_email_hashes=frozenset(data["historical_hashes"]),
                updated_at=data["updated_at"],
            )
            self._by_user_id[uid] = subject

            # Index all associated emails
            for email in subject.all_emails():
                self._by_email[email] = uid

            # Index all associated phones
            for phone in subject.all_phones():
                self._by_phone[phone] = uid

            # Index all associated hashes
            for h in subject.all_hashes():
                self._by_hash[h] = uid

    def resolve_by_user_id(self, user_id: Optional[str]) -> Optional[SubjectIdentity]:
        """Resolves subject by stable user_id."""
        if not user_id:
            return None
        cleaned = user_id.strip()
        if not cleaned or cleaned.lower() in INVALID_IDENTIFIER_STRINGS:
            return None
        return self._by_user_id.get(cleaned)

    def resolve_by_email(self, email: Optional[str]) -> Optional[SubjectIdentity]:
        """
        Resolves subject by email address.
        Matches against both current snapshot and historical emails.
        """
        if not email:
            return None
        cleaned = normalize_email(email)
        if not cleaned or cleaned in INVALID_IDENTIFIER_STRINGS:
            return None

        uid = self._by_email.get(cleaned)
        if uid:
            return self._by_user_id.get(uid)
        return None

    def resolve_by_hash(self, email_hash: Optional[str]) -> Optional[SubjectIdentity]:
        """
        Resolves subject by SHA-256 email hash.
        Matches against both current hash and pre-recorded historical hashes.
        """
        if not email_hash:
            return None
        cleaned = normalize_hash(email_hash)
        if not cleaned or cleaned in INVALID_IDENTIFIER_STRINGS:
            return None

        uid = self._by_hash.get(cleaned)
        if uid:
            return self._by_user_id.get(uid)
        return None

    def resolve_by_phone(self, phone: Optional[str]) -> Optional[SubjectIdentity]:
        """
        Resolves subject by phone number.
        Matches against both current and historical phones.
        """
        if not phone:
            return None
        cleaned = normalize_phone(phone)
        if not cleaned or cleaned in INVALID_IDENTIFIER_STRINGS:
            return None

        uid = self._by_phone.get(cleaned)
        if uid:
            return self._by_user_id.get(uid)
        return None

    def resolve_by_identifier(self, field_name: str, value: Optional[str]) -> Optional[SubjectIdentity]:
        """
        Polymorphic resolution by field name and value.
        Rejects null, empty, or unlinked sentinel identifiers.
        """
        if not value:
            return None
        cleaned = value.strip()
        if not cleaned or cleaned.lower() in INVALID_IDENTIFIER_STRINGS:
            return None

        fn = field_name.strip().lower()
        if fn in {"user_id", "subject_id", "customer_reference", "subject_reference", "account_id"}:
            return self.resolve_by_user_id(cleaned)
        if fn in {"email", "user_email", "customer_email", "recipient_email", "subject_key"}:
            return self.resolve_by_email(cleaned)
        if fn in {"email_hash", "correlation_key", "lookup_key", "hash"}:
            res = self.resolve_by_hash(cleaned)
            if res:
                return res
        if fn in {"phone", "phone_number", "mobile"}:
            return self.resolve_by_phone(cleaned)

        # Fallback inspection by value format
        if "@" in cleaned:
            return self.resolve_by_email(cleaned)
        if len(cleaned) == 64 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
            return self.resolve_by_hash(cleaned)

        return self.resolve_by_user_id(cleaned)

    def is_subject_match(self, user_id: str, field_name: str, value: Optional[str]) -> bool:
        """
        Verifies whether an evidence record attribute belongs to the target user_id.
        Rejects unrelated users and unlinked null identifiers.
        """
        subject = self.resolve_by_user_id(user_id)
        if not subject:
            return False
        return subject.matches_identifier(field_name, value)
