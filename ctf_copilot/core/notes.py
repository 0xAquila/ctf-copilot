"""
CTF Copilot — Session Notes.

Freeform tactical notes tied to an individual CTF session.
Use these to record hypotheses, dead-ends, observations, and ideas so the
AI copilot can factor them into its hints.

CLI:
  ctf note "Tried anon FTP — denied, might need creds"
  ctf note --pin "SQLi error on ' character at /login"
  ctf note --tag web,sqli "Found /admin panel, default creds failed"
  ctf notes                   # list all notes
  ctf note --delete 3         # delete note #3
"""

from __future__ import annotations

from typing import Optional

from ctf_copilot.core.database import get_connection


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def add_note(
    session_id: int,
    text: str,
    tags: str = "",
    pinned: bool = False,
) -> int:
    """
    Add a note to a session.  Returns the new note ID.

    Args:
        session_id: The CTF session this note belongs to.
        text:       The note content.
        tags:       Comma-separated tag string (e.g. "web,sqli").
        pinned:     If True, the note is displayed at the top of the list.
    """
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO session_notes (session_id, text, tags, pinned) "
            "VALUES (?, ?, ?, ?)",
            (session_id, text.strip(), tags.strip(), 1 if pinned else 0),
        )
        return cur.lastrowid  # type: ignore[return-value]


def get_notes(session_id: int) -> list[dict]:
    """
    Return all notes for a session, pinned first then chronological.
    Each row is a plain dict.
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, text, tags, pinned, created_at "
            "FROM session_notes "
            "WHERE session_id = ? "
            "ORDER BY pinned DESC, created_at ASC",
            (session_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_note(session_id: int, note_id: int) -> bool:
    """
    Delete a note by its ID.  Returns True if a row was deleted.
    Verifies session ownership to prevent cross-session deletion.
    """
    with get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM session_notes WHERE id = ? AND session_id = ?",
            (note_id, session_id),
        )
        return cur.rowcount > 0


def pin_note(session_id: int, note_id: int) -> bool:
    """
    Toggle the pinned state of a note.  Returns the new pinned value.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT pinned FROM session_notes WHERE id = ? AND session_id = ?",
            (note_id, session_id),
        ).fetchone()
        if not row:
            return False
        new_pin = 0 if row["pinned"] else 1
        conn.execute(
            "UPDATE session_notes SET pinned = ? WHERE id = ? AND session_id = ?",
            (new_pin, note_id, session_id),
        )
        return bool(new_pin)


def get_notes_for_ai(session_id: int, limit: int = 6) -> list[str]:
    """
    Return the most recent note texts for injection into AI prompts.
    Pinned notes are always included first.
    """
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT text FROM session_notes "
            "WHERE session_id = ? "
            "ORDER BY pinned DESC, created_at DESC "
            "LIMIT ?",
            (session_id, limit),
        ).fetchall()
    return [r["text"] for r in rows]


def note_count(session_id: int) -> int:
    """Return the total number of notes for a session."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM session_notes WHERE session_id = ?",
            (session_id,),
        ).fetchone()
    return row["cnt"] if row else 0
