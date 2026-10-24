"""
Intake Authorization Gate — Stage 1 of the HackerRank Orchestrate audit pipeline.

Inspects request_text to determine whether the request authorizes deletion.

Rules (AGENTS.md §6.5, ARCHITECTURE_AND_PROMPTS.md §6.1):
- A request is NOT_APPLICABLE when it does not express explicit deletion intent.
- Examples of non-deletion requests: access, correction, export, marketing opt-out.
- Multilingual classification supported (EN, FR, ES, DE, PL, KO, JA, AR).
- LLM (Groq API) is optional and invoked only for genuine ambiguity when
  GROQ_API_KEY is available in the environment.
- All deterministic keyword matches bypass the LLM entirely.
- Disk cache under code/cache/intake/ ensures deterministic re-runs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

from code.config import REPO_ROOT


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------

class IntakeVerdict(str, Enum):
    DELETION_AUTHORIZED = "DELETION_AUTHORIZED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    AMBIGUOUS = "AMBIGUOUS"   # resolved to NOT_APPLICABLE for safety


@dataclass(frozen=True)
class IntakeResult:
    case_id: str
    verdict: IntakeVerdict
    deletion_authorized: bool
    method: str          # "KEYWORD", "NEGATION", "LLM", "FALLBACK"
    confidence: str      # "HIGH", "MEDIUM", "LOW"
    reason: str


# ---------------------------------------------------------------------------
# Deterministic keyword sets
# ---------------------------------------------------------------------------

# Strong positive deletion signals (any language)
_DELETION_KEYWORDS_POSITIVE = (
    # English
    r"\bdelet(?:e|es|ed|ing|ion|ions)?\b",
    r"\beras(?:e|es|ed|ing|ure|ures)?\b",
    r"\bremov(?:e|es|ed|ing|al|als)?\b",
    r"\bpurg(?:e|es|ed|ing)?\b",
    r"\bclos(?:e|es|ed|ing)\s+(?:the\s+|this\s+|my\s+|our\s+)?account\b",
    r"\bclos(?:e|es|ed|ing)\s+(?:the\s+|this\s+|my\s+|our\s+)?profile\b",
    r"\bclos(?:e|es|ed|ing)\b",
    r"\bright\s+to\s+be\s+forgotten\b",
    r"\bforget\s+me\b",
    r"\bterminat(?:e|es|ed|ing|ion)\s+(?:the\s+|this\s+|my\s+)?account\b",
    r"\bwip(?:e|es|ed|ing)\s+(?:the\s+|this\s+|my\s+)?data\b",
    r"\bdeactivat(?:e|es|ed|ing|ion)\s+(?:and\s+)?delet(?:e|es|ed|ing|ion)?\b",
    r"\bprofile\s+(?:is|has\s+been)\s+gone\b",
    r"\bleft\s+behind\b",
    # French
    r"\bsuppression\b", r"\bsupprimer\b", r"\bsupprimé[e]?\b", r"\beffacement\b", r"\beffacer\b",
    r"\bdroit\s+à\s+l.oubli\b",
    # Spanish
    r"\beliminar\b", r"\beliminad[oa]\b", r"\beliminación\b", r"\belimination\b",
    r"\bborrar\b", r"\bborrad[oa]\b", r"\bbaja\b",
    r"\bsuprimir\b", r"\bsupresión\b", r"\bderecho\s+al\s+olvido\b",
    # German
    r"\blöschen\b", r"\blöschung\b", r"\bgelöscht\b", r"\bkonto\s+löschen\b",
    r"\brecht\s+auf\s+vergessenwerden\b", r"\bdatenlöschung\b",
    # Polish
    r"\busunięcie\b", r"\busunąć\b", r"\busunięto\b", r"\bwymazanie\b",
    # Korean / Japanese (transliterated patterns)
    r"계정\s*삭제", r"삭제", r"アカウント削除", r"削除",
    # Arabic
    r"حذف", r"مسح",
)

# Strong NON-deletion signals (clearly NOT_APPLICABLE)
_NON_DELETION_KEYWORDS = (
    # Access / copy requests
    r"\bsend\s+me\s+(?:a\s+)?copy\b", r"\bexport\s+(?:my|the)\b",
    r"\bprovide\s+(?:me\s+)?(?:a\s+)?copy\b",
    r"\bwhat\s+(?:personal\s+)?data\s+(?:do\s+you|you)\b",
    r"\baccess\s+(?:my|the)\b", r"\bdata\s+access\b", r"\bdata\s+subject\s+access\b",
    r"\brequest\s+(?:a\s+)?copy\b",
    # Correction / rectification
    r"\bcorrect\s+(?:my\b|the\b)", r"\bupdate\s+my\s+(?:address|phone|email|name|number)\b",
    r"\bchange\s+my\s+(?:address|phone|email|name|number)\b",
    r"\brectif(?:y|ication)\b", r"\bfix\s+my\b",
    # Marketing opt-out
    r"\bunsubscri(?:be|ption)\b", r"\bopt.out\b", r"\bopt\s+out\b",
    r"\bstop\s+(?:sending|receiving)\b",
    r"\bno\s+more\s+(?:emails|marketing|promotional)\b",
    r"\bremove\s+(?:me\s+)?from\s+(?:your\s+)?(?:mailing|email)\s+list\b",
    r"\bmarketing\s+(?:emails?|messages?|sms)\b",
    r"\bpromotional\b",
    # Export / download
    r"\bdownload\s+(?:my|the)\b",
)

# Negation patterns that can downgrade a deletion keyword signal
_NEGATION_PREFIXES = (
    r"not\s+", r"don.t\s+", r"do\s+not\s+", r"please\s+don.t\s+",
    r"never\s+", r"without\s+",
)


# ---------------------------------------------------------------------------
# Compiled regex cache
# ---------------------------------------------------------------------------

_RE_POSITIVE = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in _DELETION_KEYWORDS_POSITIVE]
_RE_NEGATIVE = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in _NON_DELETION_KEYWORDS]
_RE_NEGATION = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in _NEGATION_PREFIXES]


def _has_positive_signal(text: str) -> Tuple[bool, List[str]]:
    matches = []
    for pat in _RE_POSITIVE:
        m = pat.search(text)
        if m:
            matches.append(m.group(0))
    return (len(matches) > 0, matches)


def _has_non_deletion_signal(text: str) -> Tuple[bool, List[str]]:
    matches = []
    for pat in _RE_NEGATIVE:
        m = pat.search(text)
        if m:
            matches.append(m.group(0))
    return (len(matches) > 0, matches)


def _is_negated(text: str, match_start: int) -> bool:
    """Checks if a keyword match at position match_start is preceded by a negation."""
    prefix = text[max(0, match_start - 30):match_start]
    return any(neg.search(prefix) for neg in _RE_NEGATION)


# ---------------------------------------------------------------------------
# Disk cache
# ---------------------------------------------------------------------------

_CACHE_DIR = REPO_ROOT / "code" / "cache" / "intake"


def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_cache(text: str) -> Optional[dict]:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _CACHE_DIR / f"{_cache_key(text)}.json"
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _save_cache(text: str, result: dict) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _CACHE_DIR / f"{_cache_key(text)}.json"
    cache_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# LLM classification (optional, Groq API)
# ---------------------------------------------------------------------------

def _llm_classify(text: str) -> Optional[str]:
    """
    Calls Groq API for ambiguous cases. Returns "DELETION_AUTHORIZED", "NOT_APPLICABLE",
    or None if unavailable/failed.

    GROQ_API_KEY must be set in environment only (AGENTS.md §4.4, problem_statement.md:160).
    Never read from files or code.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None

    # Check disk cache first
    cached = _load_cache(text)
    if cached and "verdict" in cached:
        return cached["verdict"]

    try:
        import groq  # type: ignore
        client = groq.Groq(api_key=api_key)
        prompt = (
            "You are an assistant that determines whether a request authorizes account or data deletion.\n\n"
            "Return exactly one of these two labels (no explanation, just the label):\n"
            "- DELETION_AUTHORIZED: if the request explicitly asks for account deletion, data erasure, "
            "  right to be forgotten, or permanent removal of personal data.\n"
            "- NOT_APPLICABLE: if the request is for data access, data export, data correction, "
            "  marketing opt-out, or any other non-deletion purpose.\n\n"
            f"Request: {text[:1000]}\n\nLabel:"
        )
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=10,
            temperature=0.0,
        )
        label = response.choices[0].message.content.strip().upper()
        if label not in {"DELETION_AUTHORIZED", "NOT_APPLICABLE"}:
            return None
        _save_cache(text, {"verdict": label})
        return label
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

def classify_request(case_id: str, request_text: str) -> IntakeResult:
    """
    Classifies a deletion request as DELETION_AUTHORIZED or NOT_APPLICABLE.

    Decision flow:
    1. Strong non-deletion keywords → NOT_APPLICABLE (HIGH confidence).
    2. Strong deletion keywords without negation → DELETION_AUTHORIZED (HIGH confidence).
    3. Ambiguous → try LLM if available, else fall back to NOT_APPLICABLE for safety.
    """
    text = request_text.strip() if request_text else ""

    if not text:
        return IntakeResult(
            case_id=case_id,
            verdict=IntakeVerdict.NOT_APPLICABLE,
            deletion_authorized=False,
            method="KEYWORD",
            confidence="HIGH",
            reason="Empty request text",
        )

    # Step 1: Non-deletion signals take priority
    has_non_del, non_del_matches = _has_non_deletion_signal(text)
    has_del, del_matches = _has_positive_signal(text)

    # If non-deletion keywords dominate and no deletion keywords → NOT_APPLICABLE
    if has_non_del and not has_del:
        return IntakeResult(
            case_id=case_id,
            verdict=IntakeVerdict.NOT_APPLICABLE,
            deletion_authorized=False,
            method="KEYWORD",
            confidence="HIGH",
            reason=f"Non-deletion keywords found: {non_del_matches[:3]}",
        )

    # Step 2: Clear deletion signal
    if has_del:
        # Check if the deletion matches are negated
        all_negated = True
        for pat in _RE_POSITIVE:
            m = pat.search(text)
            if m and not _is_negated(text, m.start()):
                all_negated = False
                break

        if not all_negated:
            return IntakeResult(
                case_id=case_id,
                verdict=IntakeVerdict.DELETION_AUTHORIZED,
                deletion_authorized=True,
                method="KEYWORD",
                confidence="HIGH",
                reason=f"Deletion keywords: {del_matches[:3]}",
            )

    # Step 3: Ambiguous — try LLM
    llm_verdict = _llm_classify(text)
    if llm_verdict == "DELETION_AUTHORIZED":
        return IntakeResult(
            case_id=case_id,
            verdict=IntakeVerdict.DELETION_AUTHORIZED,
            deletion_authorized=True,
            method="LLM",
            confidence="MEDIUM",
            reason="LLM classified as deletion",
        )
    if llm_verdict == "NOT_APPLICABLE":
        return IntakeResult(
            case_id=case_id,
            verdict=IntakeVerdict.NOT_APPLICABLE,
            deletion_authorized=False,
            method="LLM",
            confidence="MEDIUM",
            reason="LLM classified as not applicable",
        )

    # Step 4: Safe fallback
    return IntakeResult(
        case_id=case_id,
        verdict=IntakeVerdict.NOT_APPLICABLE,
        deletion_authorized=False,
        method="FALLBACK",
        confidence="LOW",
        reason="Ambiguous request text; defaulting to NOT_APPLICABLE for safety",
    )
