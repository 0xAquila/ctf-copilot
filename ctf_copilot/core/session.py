"""
Session management — create, retrieve, pause, resume, and complete CTF sessions.

Each session maps to one machine / challenge and owns all findings within it.
A "current session" is tracked via a small state file at ~/.ctf_copilot/current_session.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from ctf_copilot.core.database import get_connection, get_db_path, init_db

_STATE_FILE = Path.home() / ".ctf_copilot" / "current_session"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Session:
    id: int
    name: str
    target_ip: Optional[str]
    target_host: Optional[str]
    os_guess: Optional[str]
    platform: Optional[str]
    difficulty: Optional[str]
    status: str          # active | paused | completed
    started_at: str
    stopped_at: Optional[str]
    notes: Optional[str]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _row_to_session(row) -> Session:
    return Session(
        id=row["id"],
        name=row["name"],
        target_ip=row["target_ip"],
        target_host=row["target_host"],
        os_guess=row["os_guess"],
        platform=row["platform"],
        difficulty=row["difficulty"],
        status=row["status"],
        started_at=row["started_at"],
        stopped_at=row["stopped_at"],
        notes=row["notes"],
    )


def _save_current(session_id: int) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(str(session_id))


def _clear_current() -> None:
    if _STATE_FILE.exists():
        _STATE_FILE.unlink()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_session(
    name: str,
    target_ip: str = "",
    target_host: str = "",
    platform: str = "",
    difficulty: str = "",
) -> Session:
    """
    Create a new session and mark it as the current active session.
    Raises ValueError if a session with that name already exists.
    """
    init_db()
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT id FROM sessions WHERE name = ?", (name,)
        ).fetchone()
        if existing:
            raise ValueError(
                f"Session '{name}' already exists. "
                f"Use `ctf resume {name}` to continue it."
            )
        cur = conn.execute(
            """
            INSERT INTO sessions (name, target_ip, target_host, platform, difficulty)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, target_ip or None, target_host or None, platform or None, difficulty or None),
        )
        session_id = cur.lastrowid
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        session = _row_to_session(row)

    _save_current(session.id)
    return session


def resume_session(name: str) -> Session:
    """
    Resume a paused or previously active session by name.
    Raises ValueError if not found.
    """
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE name = ?", (name,)
        ).fetchone()
        if not row:
            raise ValueError(f"No session named '{name}'. Use `ctf start {name}` to create it.")
        conn.execute(
            "UPDATE sessions SET status = 'active', stopped_at = NULL WHERE id = ?",
            (row["id"],),
        )
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (row["id"],)
        ).fetchone()
        session = _row_to_session(row)

    _save_current(session.id)
    return session


def pause_session() -> Optional[Session]:
    """Pause the current active session. Returns None if no session is active."""
    session = get_current_session()
    if not session:
        return None
    with get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET status = 'paused', stopped_at = datetime('now') WHERE id = ?",
            (session.id,),
        )
    _clear_current()
    return session


def complete_session() -> Optional[Session]:
    """Mark the current session as completed."""
    session = get_current_session()
    if not session:
        return None
    with get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET status = 'completed', stopped_at = datetime('now') WHERE id = ?",
            (session.id,),
        )
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session.id,)
        ).fetchone()
        session = _row_to_session(row)
    _clear_current()
    return session


def get_current_session() -> Optional[Session]:
    """Return the currently active session, or None."""
    if not _STATE_FILE.exists():
        return None
    try:
        session_id = int(_STATE_FILE.read_text().strip())
    except (ValueError, OSError):
        return None
    return get_session_by_id(session_id)


def get_session_by_id(session_id: int) -> Optional[Session]:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
    return _row_to_session(row) if row else None


def get_session_by_name(name: str) -> Optional[Session]:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE name = ?", (name,)
        ).fetchone()
    return _row_to_session(row) if row else None


def list_sessions() -> list[Session]:
    """Return all sessions, newest first."""
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC"
        ).fetchall()
    return [_row_to_session(r) for r in rows]


def update_session(session_id: int, **kwargs) -> None:
    """
    Update arbitrary session fields.
    Valid keys: target_ip, target_host, os_guess, platform, difficulty, notes.
    """
    allowed = {"target_ip", "target_host", "os_guess", "platform", "difficulty", "notes"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [session_id]
    with get_connection() as conn:
        conn.execute(
            f"UPDATE sessions SET {set_clause} WHERE id = ?", values
        )
