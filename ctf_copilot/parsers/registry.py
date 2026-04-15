"""
Parser Registry — auto-discovers and manages all tool parsers.

Discovery works by scanning the parsers package for files matching
`*_parser.py` and importing any class that inherits from BaseParser.

Usage:
    from ctf_copilot.parsers.registry import get_parser, run_parser

    parser = get_parser("nmap")
    if parser:
        result = parser.parse(output, command)

    # Or the high-level one-shot helper:
    result = run_parser(tool_name, output, command, session_id, command_id)
"""

from __future__ import annotations

import importlib
import inspect
import json
from pathlib import Path
from typing import Optional

from ctf_copilot.parsers.base import BaseParser, ParseResult
from ctf_copilot.core.database import get_connection
from ctf_copilot.core.logger import mark_parsed

# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------

_registry: dict[str, BaseParser] = {}
_discovered = False


def _discover() -> None:
    """Scan parsers directory and register all BaseParser subclasses."""
    global _discovered
    if _discovered:
        return
    _discovered = True

    parsers_dir = Path(__file__).parent
    for path in sorted(parsers_dir.glob("*_parser.py")):
        module_name = f"ctf_copilot.parsers.{path.stem}"
        try:
            module = importlib.import_module(module_name)
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseParser)
                    and obj is not BaseParser
                    and obj.tool_name
                ):
                    instance = obj()
                    _registry[obj.tool_name] = instance
        except Exception as exc:
            # Bad parser file — log but don't crash the copilot
            import sys
            print(f"[parser registry] Failed to load {path.name}: {exc}", file=sys.stderr)


def get_parser(tool_name: str) -> Optional[BaseParser]:
    """Return the parser for a tool name, or None if not registered."""
    _discover()
    return _registry.get(tool_name)


def list_parsers() -> list[str]:
    """Return all registered tool names."""
    _discover()
    return sorted(_registry.keys())


# ---------------------------------------------------------------------------
# Persistence — write ParseResult to DB
# ---------------------------------------------------------------------------

def _persist(result: ParseResult, session_id: int, command_id: Optional[int]) -> None:
    """Write all findings from a ParseResult into the database."""
    if result.is_empty:
        return

    with get_connection() as conn:
        # Services
        for svc in result.services:
            extra_json = json.dumps(svc.extra) if svc.extra else None
            conn.execute(
                """
                INSERT INTO services
                    (session_id, command_id, port, protocol, service, version, banner, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, port, protocol) DO UPDATE SET
                    service  = COALESCE(excluded.service,  service),
                    version  = COALESCE(excluded.version,  version),
                    banner   = COALESCE(excluded.banner,   banner),
                    extra    = COALESCE(excluded.extra,    extra)
                """,
                (
                    session_id,
                    command_id,
                    svc.port,
                    svc.protocol,
                    svc.service or None,
                    svc.version or None,
                    svc.banner or None,
                    extra_json,
                ),
            )

        # Web findings
        for wf in result.web_findings:
            params_json = json.dumps(wf.parameters) if wf.parameters else None
            conn.execute(
                """
                INSERT INTO web_findings
                    (session_id, command_id, endpoint, status_code, method,
                     content_type, parameters, technology, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, endpoint, method) DO UPDATE SET
                    status_code  = COALESCE(excluded.status_code,  status_code),
                    content_type = COALESCE(excluded.content_type, content_type),
                    technology   = COALESCE(excluded.technology,   technology)
                """,
                (
                    session_id,
                    command_id,
                    wf.endpoint,
                    wf.status_code,
                    wf.method,
                    wf.content_type or None,
                    params_json,
                    wf.technology or None,
                    wf.notes or None,
                ),
            )

        # Credentials
        for cred in result.credentials:
            conn.execute(
                """
                INSERT INTO credentials
                    (session_id, username, password, hash, hash_type, source)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    cred.username or None,
                    cred.password or None,
                    cred.hash or None,
                    cred.hash_type or None,
                    cred.source or None,
                ),
            )

        # Flags
        for flag_value in result.flags:
            conn.execute(
                """
                INSERT OR IGNORE INTO flags (session_id, flag_value)
                VALUES (?, ?)
                """,
                (session_id, flag_value),
            )


# ---------------------------------------------------------------------------
# High-level entry point
# ---------------------------------------------------------------------------

def run_parser(
    tool_name: str,
    output: str,
    command: str,
    session_id: int,
    command_id: Optional[int] = None,
) -> Optional[ParseResult]:
    """
    Look up the right parser, parse the output, persist findings, and mark
    the command as parsed.

    Returns the ParseResult if parsing happened, or None if no parser exists
    or the output was not recognisable.
    """
    parser = get_parser(tool_name)
    if not parser:
        return None

    if not output or not parser.can_parse(output):
        return None

    try:
        result = parser.parse(output, command)
        _persist(result, session_id, command_id)
        if command_id:
            mark_parsed(command_id)
        return result
    except Exception as exc:
        import sys
        print(f"[parser:{tool_name}] Error during parse: {exc}", file=sys.stderr)
        return None
