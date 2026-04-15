"""
Shared pytest fixtures for CTF Copilot tests.

Strategy:
  - Each test that needs a DB gets a fresh temp file via `tmp_db`.
  - Parsers are tested in isolation — no DB needed, just string input → result.
  - Pattern engine tests use a handcrafted SessionContext built without a DB.
  - The real DB path is patched so tests never touch ~/.ctf_copilot/copilot.db.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import pytest

from ctf_copilot.core.database import _SCHEMA, get_connection, init_db
from ctf_copilot.core.context import Observation, SessionContext


# ---------------------------------------------------------------------------
# Temp database fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    """
    Provide a fresh, isolated SQLite database for each test.

    Patches `get_db_path` so all DB calls in the test use the temp file.
    Returns the Path to the DB file.
    """
    db_file = tmp_path / "test_copilot.db"

    # Patch at the module level so every import of get_db_path sees the override
    monkeypatch.setattr(
        "ctf_copilot.core.database.get_db_path",
        lambda: db_file,
    )

    # Also patch imports already resolved in other modules
    for module in [
        "ctf_copilot.core.session",
        "ctf_copilot.core.logger",
        "ctf_copilot.core.context",
        "ctf_copilot.engine.hints",
        "ctf_copilot.engine.pattern",
        "ctf_copilot.engine.writeup",
    ]:
        try:
            monkeypatch.setattr(f"{module}.get_db_path", lambda: db_file)
        except AttributeError:
            pass  # Module doesn't re-import get_db_path directly

    init_db(db_file)
    return db_file


@pytest.fixture()
def tmp_conn(tmp_db):
    """Yield a live connection to the temp DB (auto-commits, auto-closes)."""
    with get_connection(tmp_db) as conn:
        yield conn


# ---------------------------------------------------------------------------
# Session fixture — creates a real session row in the temp DB
# ---------------------------------------------------------------------------

@pytest.fixture()
def test_session(tmp_db):
    """Insert a test session and return its row dict."""
    with get_connection(tmp_db) as conn:
        conn.execute(
            """INSERT INTO sessions (name, target_ip, platform, difficulty, status)
               VALUES ('test-lame', '10.10.10.3', 'HackTheBox', 'Easy', 'active')"""
        )
        row = conn.execute(
            "SELECT * FROM sessions WHERE name = 'test-lame'"
        ).fetchone()
    return dict(row)


# ---------------------------------------------------------------------------
# Mock SessionContext factory
# ---------------------------------------------------------------------------

@dataclass
class _MockSession:
    id:          int   = 1
    name:        str   = "test-session"
    target_ip:   str   = "10.10.10.3"
    target_host: str   = ""
    os_guess:    Optional[str] = None
    platform:    Optional[str] = "HackTheBox"
    difficulty:  Optional[str] = "Easy"
    status:      str   = "active"
    started_at:  str   = "2026-01-01T00:00:00"
    stopped_at:  Optional[str] = None
    notes:       Optional[str] = None


def make_context(
    services:     list[dict] | None = None,
    web_findings: list[dict] | None = None,
    credentials:  list[dict] | None = None,
    flags:        list[dict] | None = None,
    tools_used:   set[str]   | None = None,
    observations: list[Observation] | None = None,
) -> SessionContext:
    """
    Build a SessionContext without touching the database.
    Use this in pattern engine and observation tests.
    """
    svcs = services or []
    return SessionContext(
        session        = _MockSession(),
        services       = svcs,
        web_findings   = web_findings   or [],
        credentials    = credentials    or [],
        flags          = flags          or [],
        command_summary= {"total": 1, "tools_used": [], "recent": []},
        observations   = observations   or [],
        services_by_port = {s["port"]: s for s in svcs},
        tools_used     = tools_used     or set(),
    )


# ---------------------------------------------------------------------------
# Sample raw tool outputs (fixtures reused across parser tests)
# ---------------------------------------------------------------------------

NMAP_TEXT = """\
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.10.3
Host is up (0.053s latency).
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""

NMAP_GREPABLE = """\
# Nmap 7.94 scan initiated
Host: 10.10.10.3 ()	Status: Up
Host: 10.10.10.3 ()	Ports: 21/open/tcp//ftp//vsftpd 2.3.4/, 22/open/tcp//ssh//OpenSSH 4.7p1/, 80/open/tcp//http//Apache httpd 2.2.8/, 3306/open/tcp//mysql//MySQL 5.0.51a/
# Nmap done
"""

NMAP_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.3" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="2.3.4"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

GOBUSTER_DIR_NEW = """\
===============================================================
Gobuster v3.6
===============================================================
/login.php            (Status: 200) [Size: 1234]
/admin                (Status: 301) [Size: 0] [--> /admin/]
/.git                 (Status: 403) [Size: 277]
/backup               (Status: 200) [Size: 5678]
===============================================================
"""

GOBUSTER_DIR_OLD = """\
/login.php (Status: 200)
/admin (Status: 301)
/.git (Status: 403)
"""

GOBUSTER_DNS = """\
Found: api.example.com
Found: mail.example.com
Found: dev.example.com
"""

FFUF_JSON = (
    '{"commandline":"ffuf -u http://10.10.10.3/FUZZ -w wordlist.txt",'
    '"time":"2026-01-01T00:00:00Z",'
    '"results":['
    '{"url":"http://10.10.10.3/login.php","status":200,"length":1234,"words":100},'
    '{"url":"http://10.10.10.3/admin","status":301,"length":0,"words":0},'
    '{"url":"http://10.10.10.3/phpmyadmin","status":200,"length":4567,"words":200}'
    ']}'
)

FFUF_TEXT = """\
login.php               [Status: 200, Size: 1234, Words: 100]
admin                   [Status: 301, Size: 0, Words: 0]
phpmyadmin              [Status: 200, Size: 4567, Words: 200]
"""
