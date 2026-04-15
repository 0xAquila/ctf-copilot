"""
Searchsploit parser — parses `searchsploit --json <query>` output.

Searchsploit ships with Kali Linux and Parrot OS as part of exploitdb.
It searches the local ExploitDB copy for known exploits.

Usage (auto-fired by ctf-wrap after nmap parse):
    searchsploit --json vsftpd 2.3.4

JSON output format:
    {
      "RESULTS_EXPLOIT": [
        {
          "Title": "vsftpd 2.3.4 - Backdoor Command Execution",
          "EDB-ID": "49757",
          "Date": "2021-03-17",
          "Author": "1F98D",
          "Type": "remote",
          "Platform": "Unix",
          "Path": "/usr/share/exploitdb/exploits/unix/remote/49757.py"
        }
      ],
      "RESULTS_SHELLCODE": []
    }

This parser is also used manually via: ctf searchsploit <query>
"""

from __future__ import annotations

import json
import subprocess
import shutil
from typing import Optional

from ctf_copilot.parsers.base import BaseParser, ParseResult, WebFinding


class SearchsploitParser(BaseParser):
    tool_name = "searchsploit"

    def can_parse(self, output: str) -> bool:
        """Detect searchsploit --json output."""
        stripped = output.strip()
        if not stripped:
            return False
        # JSON output starts with { and contains RESULTS_EXPLOIT
        return stripped.startswith("{") and "RESULTS_EXPLOIT" in stripped

    def parse(self, output: str, command: str) -> ParseResult:
        """
        Parse searchsploit --json output into structured notes.

        Each exploit result becomes a note in the ParseResult.
        These notes are surfaced as hints by wrap_cmd.
        """
        notes: list[str] = []

        try:
            data = json.loads(output.strip())
        except (json.JSONDecodeError, ValueError):
            return self._make_result()

        exploits = data.get("RESULTS_EXPLOIT", [])
        shellcodes = data.get("RESULTS_SHELLCODE", [])

        all_results = exploits + shellcodes

        for item in all_results[:5]:  # cap at 5 results
            title    = item.get("Title", "Unknown").strip()
            edb_id   = item.get("EDB-ID", "").strip()
            exp_type = item.get("Type", "").strip()
            platform = item.get("Platform", "").strip()

            parts = [f"EDB-{edb_id}:" if edb_id else "ExploitDB:"]
            parts.append(title)
            if exp_type:
                parts.append(f"[{exp_type}]")
            if platform:
                parts.append(f"({platform})")

            notes.append(" ".join(parts))

        return self._make_result(notes=notes)


# ---------------------------------------------------------------------------
# Standalone query function (used by wrap_cmd and ctf searchsploit CLI)
# ---------------------------------------------------------------------------

def is_searchsploit_available() -> bool:
    """Return True if searchsploit is installed and reachable."""
    return shutil.which("searchsploit") is not None


def run_searchsploit(query: str, timeout: int = 15) -> list[str]:
    """
    Run `searchsploit --json <query>` and return a list of formatted result strings.

    Returns empty list if searchsploit is not installed or returns no results.
    Silently swallows all errors — must never crash the caller.

    Args:
        query:   Search query (e.g. "vsftpd 2.3.4")
        timeout: Subprocess timeout in seconds
    """
    if not query or not is_searchsploit_available():
        return []

    try:
        proc = subprocess.run(
            ["searchsploit", "--json"] + query.split(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = proc.stdout.strip()
        if not output:
            return []

        parser = SearchsploitParser()
        if not parser.can_parse(output):
            return []

        result = parser.parse(output, f"searchsploit --json {query}")
        return result.notes

    except (subprocess.TimeoutExpired, FileNotFoundError,
            PermissionError, OSError):
        return []
    except Exception:
        return []
