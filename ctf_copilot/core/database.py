"""
SQLite database layer — schema definition and connection management.

All persistent state (sessions, commands, services, findings, hints) lives here.
Tables are created automatically on first run via `init_db()`.
"""

import sqlite3
from pathlib import Path
from contextlib import contextmanager

# Default DB location: ~/.ctf_copilot/copilot.db
_DEFAULT_DB_DIR = Path.home() / ".ctf_copilot"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "copilot.db"


def get_db_path() -> Path:
    """Return the active DB path, creating parent dirs if needed."""
    _DEFAULT_DB_DIR.mkdir(parents=True, exist_ok=True)
    return _DEFAULT_DB_PATH


@contextmanager
def get_connection(db_path: Path | None = None):
    """
    Context manager that yields a SQLite connection with row_factory set.
    Commits on clean exit, rolls back on exception.
    """
    path = db_path or get_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row          # rows accessible as dicts
    conn.execute("PRAGMA journal_mode=WAL")  # concurrent reads during writes
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
-- Named CTF sessions (one per machine / challenge)
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    target_ip   TEXT,
    target_host TEXT,
    os_guess    TEXT,
    platform    TEXT,          -- e.g. HackTheBox, TryHackMe, CTF
    difficulty  TEXT,
    status      TEXT    NOT NULL DEFAULT 'active',  -- active | paused | completed
    started_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    stopped_at  TEXT,
    notes       TEXT
);

-- Every command run during a session (captured by shell hook)
CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    command     TEXT    NOT NULL,
    output      TEXT,
    exit_code   INTEGER,
    cwd         TEXT,
    tool        TEXT,          -- detected tool name (nmap, gobuster, …)
    parsed      INTEGER NOT NULL DEFAULT 0,  -- 0=raw, 1=parsed into findings
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Discovered services / open ports
CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    command_id  INTEGER REFERENCES commands(id),
    port        INTEGER NOT NULL,
    protocol    TEXT    NOT NULL DEFAULT 'tcp',
    service     TEXT,
    version     TEXT,
    banner      TEXT,
    extra       TEXT,          -- JSON blob for any extra parser data
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (session_id, port, protocol)
);

-- Web endpoints discovered (gobuster, ffuf, nikto, …)
CREATE TABLE IF NOT EXISTS web_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    command_id  INTEGER REFERENCES commands(id),
    endpoint    TEXT    NOT NULL,
    status_code INTEGER,
    method      TEXT    DEFAULT 'GET',
    content_type TEXT,
    parameters  TEXT,          -- JSON array of param names
    technology  TEXT,
    notes       TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (session_id, endpoint, method)
);

-- Credentials found or attempted
CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    username    TEXT,
    password    TEXT,
    hash        TEXT,
    hash_type   TEXT,
    source      TEXT,          -- where it came from (e.g. /etc/passwd, login form)
    valid       INTEGER,       -- NULL=unknown, 1=valid, 0=invalid
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Flags captured
CREATE TABLE IF NOT EXISTS flags (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    flag_type   TEXT    NOT NULL DEFAULT 'user',  -- user | root | other
    flag_value  TEXT    NOT NULL,
    found_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- CVE cache — shared across sessions, keyed by service+version+cve_id
-- Populated by NVD API queries; TTL = 7 days (checked at query time)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    service     TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    cve_id      TEXT    NOT NULL,
    cvss_score  REAL,
    description TEXT,
    source      TEXT    NOT NULL DEFAULT 'nvd',
    cached_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (service, version, cve_id)
);

-- AI and pattern-engine hints delivered to the user
CREATE TABLE IF NOT EXISTS hints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    command_id  INTEGER REFERENCES commands(id),
    hint_text   TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'ai',  -- ai | pattern
    confidence  REAL,          -- 0.0 – 1.0
    rule_name   TEXT,          -- populated when source='pattern'
    shown       INTEGER NOT NULL DEFAULT 1,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


def init_db(db_path: Path | None = None) -> None:
    """Create all tables if they don't exist. Safe to call on every startup."""
    with get_connection(db_path) as conn:
        conn.executescript(_SCHEMA)
