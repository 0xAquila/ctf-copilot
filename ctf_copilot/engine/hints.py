"""
Hint storage and deduplication layer.

Hints are persisted to the DB so we can:
  - Never repeat the same insight in a session
  - Show hint history with `ctf hints`
  - Feed prior hints back into the AI prompt ("don't repeat these")

Deduplication uses Jaccard similarity on word sets — fast, zero-dependency,
and effective for the short sentences that make up hints.
"""

from __future__ import annotations

import re
from typing import Optional

from ctf_copilot.core.database import get_connection, init_db


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_hint(
    session_id: int,
    hint_text: str,
    source: str = "ai",
    confidence: float = 0.8,
    command_id: Optional[int] = None,
    rule_name: Optional[str] = None,
) -> int:
    """
    Persist a hint to the DB and return its row ID.
    Safe to call even if the hint turns out to be a duplicate — the caller
    should always call is_duplicate() first.
    """
    init_db()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO hints
                (session_id, command_id, hint_text, source, confidence, rule_name)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, command_id, hint_text, source, confidence, rule_name),
        )
        return cur.lastrowid


def get_recent_hints(session_id: int, limit: int = 20) -> list[dict]:
    """Return the most recent hints for a session, newest first."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT h.*, c.command as trigger_command
            FROM hints h
            LEFT JOIN commands c ON h.command_id = c.id
            WHERE h.session_id = ?
            ORDER BY h.timestamp DESC, h.id DESC
            LIMIT ?
            """,
            (session_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_hints_for_prompt(session_id: int, limit: int = 8) -> list[str]:
    """
    Return recent hint texts formatted for injection into the AI prompt.
    Oldest-first so the AI sees them chronologically.
    """
    hints = get_recent_hints(session_id, limit=limit)
    return [h["hint_text"] for h in reversed(hints)]


# ---------------------------------------------------------------------------
# Deduplication — Jaccard similarity
# ---------------------------------------------------------------------------

def _tokenise(text: str) -> set[str]:
    """
    Normalise a hint string into a set of lowercase word tokens.

    Version numbers like '2.3.4' and CVE IDs like 'CVE-2011-2523' are
    preserved as single tokens so they contribute correctly to similarity.
    """
    text = text.lower()
    # Preserve version numbers: 2.3.4 -> 2_3_4 (apply iteratively for chained dots)
    prev = None
    while prev != text:
        prev = text
        text = re.sub(r"(\d)\.(\d)", r"\1_\2", text)
    # Preserve CVE IDs: CVE-2011-2523 -> cve_2011_2523
    text = re.sub(r"(cve)-(\d)", r"\1_\2", text, flags=re.IGNORECASE)
    text = re.sub(r"[^\w\s]", " ", text)           # remove remaining punctuation
    tokens = {t for t in text.split() if len(t) > 2}  # drop tiny stop words
    return tokens


def _jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity between two token sets. Returns 0.0-1.0."""
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def is_duplicate(
    session_id: int,
    candidate: str,
    threshold: float = 0.45,
) -> bool:
    """
    Return True if the candidate hint is too similar to any previous hint
    in this session (Jaccard similarity >= threshold).

    A threshold of 0.55 catches paraphrases and minor rewording while
    allowing genuinely different insights through.
    """
    previous = get_recent_hints(session_id, limit=30)
    if not previous:
        return False

    candidate_tokens = _tokenise(candidate)
    for prev in previous:
        prev_tokens = _tokenise(prev["hint_text"])
        if _jaccard(candidate_tokens, prev_tokens) >= threshold:
            return True
    return False
