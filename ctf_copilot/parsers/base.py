"""
Base parser contract and shared data structures.

Every tool parser must:
  1. Inherit from BaseParser
  2. Set `tool_name` to match the canonical name in logger._TOOL_NAMES
  3. Implement `can_parse(output)` — quick pre-check
  4. Implement `parse(output, command, session_id)` — return a ParseResult

ParseResult carries structured findings ready to be written to the DB.
The registry calls `persist(result, conn)` which handles all DB writes.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Finding data classes (DB-ready)
# ---------------------------------------------------------------------------

@dataclass
class ServiceFinding:
    port:      int
    protocol:  str = "tcp"
    service:   str = ""
    version:   str = ""
    banner:    str = ""
    extra:     dict = field(default_factory=dict)   # arbitrary parser data


@dataclass
class WebFinding:
    endpoint:     str
    status_code:  Optional[int] = None
    method:       str = "GET"
    content_type: str = ""
    parameters:   list[str] = field(default_factory=list)
    technology:   str = ""
    notes:        str = ""


@dataclass
class CredentialFinding:
    username:  str = ""
    password:  str = ""
    hash:      str = ""
    hash_type: str = ""
    source:    str = ""


@dataclass
class ParseResult:
    """Aggregated output of one parser run."""
    tool:        str
    services:    list[ServiceFinding]    = field(default_factory=list)
    web_findings: list[WebFinding]       = field(default_factory=list)
    credentials: list[CredentialFinding] = field(default_factory=list)
    flags:       list[str]               = field(default_factory=list)
    notes:       list[str]               = field(default_factory=list)
    confidence:  float                   = 1.0   # parser's confidence in its own output

    @property
    def is_empty(self) -> bool:
        return not (
            self.services or self.web_findings
            or self.credentials or self.flags or self.notes
        )

    def summary(self) -> str:
        parts = []
        if self.services:     parts.append(f"{len(self.services)} service(s)")
        if self.web_findings: parts.append(f"{len(self.web_findings)} web finding(s)")
        if self.credentials:  parts.append(f"{len(self.credentials)} credential(s)")
        if self.flags:        parts.append(f"{len(self.flags)} flag(s)")
        if self.notes:        parts.append(f"{len(self.notes)} note(s)")
        return ", ".join(parts) if parts else "no findings"


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BaseParser(ABC):
    """
    All tool parsers inherit from this class.

    The registry discovers parsers automatically — just place a file named
    `<tool>_parser.py` in ctf_copilot/parsers/ and define a class that
    inherits from BaseParser with `tool_name` set correctly.
    """

    tool_name: str = ""   # must match logger._TOOL_NAMES canonical name

    @abstractmethod
    def can_parse(self, output: str) -> bool:
        """
        Quick sanity check — return True if this output looks parseable.
        Called before `parse()` to avoid wasted effort on empty/unrelated output.
        """

    @abstractmethod
    def parse(self, output: str, command: str) -> ParseResult:
        """
        Parse raw tool output and return structured findings.

        Args:
            output:  The captured stdout (and merged stderr) of the tool run.
            command: The full command string (may contain flags useful for parsing).

        Returns:
            A ParseResult with all discovered findings.
        """

    # ------------------------------------------------------------------
    # Shared helpers available to all parsers
    # ------------------------------------------------------------------

    def _make_result(self, **kwargs) -> ParseResult:
        return ParseResult(tool=self.tool_name, **kwargs)

    @staticmethod
    def _clean(text: str) -> str:
        """Strip ANSI escape codes and extra whitespace."""
        import re
        ansi = re.compile(r"\x1b\[[0-9;]*m")
        return ansi.sub("", text).strip()
