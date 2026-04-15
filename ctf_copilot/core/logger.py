"""
Command Logger — core business logic.

Responsibilities:
  - Detect which security tool a command invokes
  - Save command records to the DB
  - Retrieve recent commands for context building
  - Mark commands as parsed once a parser has processed their output

Called by:
  - ctf-log  (lightweight shell hook path — command text + exit code only)
  - ctf-wrap (rich path — full stdout/stderr output captured)
"""

from __future__ import annotations

import os
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ctf_copilot.core.database import get_connection, init_db
from ctf_copilot.core.session import get_current_session

# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

# Maps first token of a command → canonical tool name stored in DB.
# This covers direct calls AND common aliases/paths (e.g. /usr/bin/nmap).
_TOOL_NAMES: dict[str, str] = {
    # Recon
    "nmap":            "nmap",
    "masscan":         "masscan",
    "rustscan":        "rustscan",
    # Web fuzzing / directory busting
    "gobuster":        "gobuster",
    "ffuf":            "ffuf",
    "feroxbuster":     "feroxbuster",
    "dirb":            "dirb",
    "dirsearch":       "dirsearch",
    "wfuzz":           "wfuzz",
    # Vulnerability scanning
    "nikto":           "nikto",
    "sqlmap":          "sqlmap",
    # Brute force
    "hydra":           "hydra",
    "medusa":          "medusa",
    "crackmapexec":    "crackmapexec",
    "cme":             "crackmapexec",
    # SMB / AD
    "smbclient":       "smbclient",
    "smbmap":          "smbmap",
    "enum4linux":      "enum4linux",
    "enum4linux-ng":   "enum4linux",
    "rpcclient":       "rpcclient",
    "ldapsearch":      "ldapsearch",
    # Post-exploitation / shells
    "evil-winrm":      "evil-winrm",
    "nc":              "netcat",
    "netcat":          "netcat",
    "ncat":            "netcat",
    # HTTP clients
    "curl":            "curl",
    "wget":            "wget",
    # Password cracking
    "hashcat":         "hashcat",
    "john":            "john",
    # Script interpreters (track when user runs custom scripts)
    "python":          "python",
    "python3":         "python",
    "ruby":            "ruby",
    "perl":            "perl",
    # Exploit framework
    "msfconsole":      "metasploit",
    "msfvenom":        "metasploit",
    "searchsploit":    "searchsploit",
    # CMS scanners
    "wpscan":          "wpscan",
    "droopescan":      "droopescan",
    # Misc
    "ncrack":          "ncrack",
    "onesixtyone":     "onesixtyone",
    "snmpwalk":        "snmpwalk",
    "showmount":       "showmount",
    "dig":             "dig",
    "host":            "host",
}


def detect_tool(command: str) -> Optional[str]:
    """
    Return the canonical tool name for a command string, or None if unknown.

    Handles:
      - Full paths:  /usr/bin/nmap → nmap
      - Sudo prefix: sudo nmap      → nmap
      - ctf-wrap:    skips (internal)
    """
    if not command or not command.strip():
        return None

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    if not tokens:
        return None

    # Strip leading sudo / env / time prefixes and KEY=VALUE env assignments
    skip_prefixes = {"sudo", "env", "time", "nice", "ionice", "strace", "ltrace"}
    _kv_re = re.compile(r"^\w+=\S*$")  # matches VAR=value env assignments
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if tok in skip_prefixes or _kv_re.match(tok):
            idx += 1
        else:
            break

    if idx >= len(tokens):
        return None

    token = tokens[idx]
    # Strip path component (e.g. /usr/bin/nmap → nmap)
    binary = Path(token).name
    # Strip version suffixes (e.g. python3.11 → python3)
    binary = re.sub(r"\.\d+$", "", binary)

    return _TOOL_NAMES.get(binary)


# ---------------------------------------------------------------------------
# Save / retrieve commands
# ---------------------------------------------------------------------------

def save_command(
    command: str,
    exit_code: int = 0,
    cwd: str = "",
    timestamp: str = "",
    output: str = "",
    session_id: Optional[int] = None,
) -> Optional[int]:
    """
    Persist a command record to the DB.

    Returns the new command row ID, or None if no active session exists.
    Silently swallows all errors — this must never crash the user's shell.
    """
    try:
        init_db()

        if session_id is None:
            session = get_current_session()
            if not session:
                return None
            session_id = session.id

        ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tool = detect_tool(command)

        with get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO commands
                    (session_id, command, output, exit_code, cwd, tool, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, command, output or None, exit_code, cwd or None, tool, ts),
            )
            return cur.lastrowid

    except Exception:
        return None


def mark_parsed(command_id: int) -> None:
    """Mark a command record as parsed (findings have been extracted)."""
    try:
        with get_connection() as conn:
            conn.execute(
                "UPDATE commands SET parsed = 1 WHERE id = ?", (command_id,)
            )
    except Exception:
        pass


def get_recent_commands(
    session_id: int,
    limit: int = 20,
    tool: Optional[str] = None,
    unparsed_only: bool = False,
) -> list[dict]:
    """
    Return recent commands for a session as plain dicts.

    Args:
        session_id:    Filter to this session.
        limit:         Max rows to return.
        tool:          If set, filter to commands from this tool.
        unparsed_only: If True, only return commands not yet parsed.
    """
    try:
        init_db()
        query = "SELECT * FROM commands WHERE session_id = ?"
        params: list = [session_id]

        if tool:
            query += " AND tool = ?"
            params.append(tool)
        if unparsed_only:
            query += " AND parsed = 0 AND output IS NOT NULL"

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    except Exception:
        return []


def get_command_by_id(command_id: int) -> Optional[dict]:
    """Fetch a single command row by ID."""
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM commands WHERE id = ?", (command_id,)
            ).fetchone()
        return dict(row) if row else None
    except Exception:
        return None


def get_session_summary(session_id: int) -> dict:
    """
    Return a high-level summary of what has been run in a session.
    Used to build AI context prompts.
    """
    try:
        with get_connection() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM commands WHERE session_id = ?", (session_id,)
            ).fetchone()[0]

            tools_used = conn.execute(
                """
                SELECT tool, COUNT(*) as cnt
                FROM commands
                WHERE session_id = ? AND tool IS NOT NULL
                GROUP BY tool
                ORDER BY cnt DESC
                """,
                (session_id,),
            ).fetchall()

            last_5 = conn.execute(
                """
                SELECT command, tool, exit_code, timestamp
                FROM commands
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT 5
                """,
                (session_id,),
            ).fetchall()

        return {
            "total_commands": total,
            "tools_used":     [dict(r) for r in tools_used],
            "recent":         [dict(r) for r in last_5],
        }
    except Exception:
        return {"total_commands": 0, "tools_used": [], "recent": []}
