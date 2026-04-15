"""
ctf-wrap — transparent tool wrapper with full output capture.

Activated by shell aliases in ctf-init.sh. When the user types:

    nmap -sV 10.10.10.1

The alias transparently runs:

    ctf-wrap --tool nmap -- -sV 10.10.10.1

ctf-wrap:
  1. Runs the real tool with the original arguments
  2. Streams all output to the terminal in real time (identical UX)
  3. Captures the full output (stdout + stderr merged)
  4. Saves the command + captured output to the active session DB
  5. Triggers any registered parsers for the tool (Phase 4)
  6. Exits with the tool's original exit code

This gives us rich, structured data while preserving the user's workflow.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from typing import Optional

import click

from ctf_copilot.core.logger import save_command, detect_tool
from ctf_copilot.core.session import get_current_session
from ctf_copilot.parsers.registry import run_parser
from ctf_copilot.engine.ai import generate_hint
from ctf_copilot.engine.pattern import run_pattern_engine
from ctf_copilot.engine.hints import save_hint, is_duplicate
from ctf_copilot.core.context import build_context
from ctf_copilot.core.config import config as _cfg
from ctf_copilot.interface.display import show_hint, show_skip_reason, show_parse_result, show_flag_alert, show_generating

# Flag detection regex patterns — alert immediately on capture
import re

FLAG_PATTERNS = [
    re.compile(r"HTB\{[^}]+\}", re.IGNORECASE),
    re.compile(r"THM\{[^}]+\}", re.IGNORECASE),
    re.compile(r"FLAG\{[^}]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"DUCTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"picoCTF\{[^}]+\}", re.IGNORECASE),
    # Generic: 32-char hex (common MD5-style flags)
    re.compile(r"\b[a-f0-9]{32}\b"),
]


def _check_for_flags(text: str) -> list[str]:
    """Return any flag-like strings found in the tool output."""
    found = []
    for pattern in FLAG_PATTERNS:
        found.extend(pattern.findall(text))
    return list(set(found))



def _run_tool_capture(args: list[str]) -> tuple[int, str]:
    """
    Run a subprocess, stream its combined stdout+stderr to the terminal
    in real time, and return (exit_code, full_output_string).

    Merges stderr into stdout so the terminal sees a single interleaved
    stream — matching how most CTF tools behave naturally.
    """
    output_lines: list[str] = []
    lock = threading.Lock()

    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr → stdout
            bufsize=1,                  # line-buffered
            universal_newlines=True,
            env=os.environ.copy(),
        )

        # Stream lines as they arrive
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            with lock:
                output_lines.append(line)

        process.wait()
        return process.returncode, "".join(output_lines)

    except FileNotFoundError:
        msg = f"ctf-wrap: command not found: {args[0]}\n"
        sys.stderr.write(msg)
        return 127, msg
    except PermissionError:
        msg = f"ctf-wrap: permission denied: {args[0]}\n"
        sys.stderr.write(msg)
        return 126, msg
    except Exception as exc:
        msg = f"ctf-wrap: unexpected error running {args[0]}: {exc}\n"
        sys.stderr.write(msg)
        return 1, msg


def _run_cve_enrichment(session, cmd_id: Optional[int]) -> None:
    """
    Query NVD for each newly-discovered versioned service and surface
    high-severity CVEs as hints.  Silently swallows all errors.
    """
    try:
        from ctf_copilot.engine.cve import enrich_session_services, format_cve_hint
        enriched = enrich_session_services(session.id)
        for _version, cves in enriched:
            for cve in cves[:2]:   # cap at 2 CVEs per service
                if cve.cvss_score is None or cve.cvss_score < 7.0:
                    continue       # only surface high/critical CVEs proactively
                hint_text = format_cve_hint(cve)
                if is_duplicate(session.id, hint_text):
                    continue
                save_hint(
                    session_id=session.id,
                    hint_text=hint_text,
                    source="nvd",
                    confidence=0.90,
                    command_id=cmd_id,
                )
                show_hint(
                    hint_text=hint_text,
                    source="nvd",
                    confidence=0.90,
                    tool="nmap",
                    rule_name=cve.cve_id,
                )
    except Exception:
        pass


def _run_searchsploit_auto(session, cmd_id: Optional[int]) -> None:
    """
    For each versioned service discovered by nmap, run searchsploit and
    surface matching ExploitDB entries as hints.  Silently swallows all errors.
    """
    try:
        from ctf_copilot.parsers.searchsploit_parser import (
            run_searchsploit, is_searchsploit_available,
        )
        if not is_searchsploit_available():
            return

        from ctf_copilot.core.database import get_connection
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT service, version FROM services
                WHERE session_id = ? AND version IS NOT NULL AND version != ''
                ORDER BY port
                """,
                (session.id,),
            ).fetchall()

        for row in rows:
            svc     = row["service"] or ""
            version = row["version"] or ""
            if not version:
                continue

            # Build a clean search query: prefer "service version" but strip
            # extra parenthetical info that confuses searchsploit
            import re as _re
            version_clean = _re.sub(r"\([^)]*\)", "", version).strip()
            query = f"{svc} {version_clean}".strip() if svc else version_clean

            results = run_searchsploit(query)
            for note in results[:3]:   # cap at 3 per service
                hint_text = f"[ExploitDB] {note}"
                if is_duplicate(session.id, hint_text):
                    continue
                save_hint(
                    session_id=session.id,
                    hint_text=hint_text,
                    source="searchsploit",
                    confidence=0.85,
                    command_id=cmd_id,
                )
                show_hint(
                    hint_text=hint_text,
                    source="searchsploit",
                    confidence=0.85,
                    tool="nmap",
                    rule_name="exploitdb",
                )
    except Exception:
        pass


@click.command(
    "ctf-wrap",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.option("--tool", "-t", required=True, help="Canonical tool name (set by alias)")
@click.argument("tool_args", nargs=-1, type=click.UNPROCESSED)
def wrap_cmd(tool, tool_args):
    """
    Transparently wrap a tool invocation, capturing its output for analysis.

    This command is called automatically by shell aliases — you do not
    need to run it manually.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Reconstruct the full command as it would appear in history
    full_command = " ".join([tool] + list(tool_args))
    cwd = os.getcwd()

    # Run the actual tool, streaming + capturing output
    exit_code, output = _run_tool_capture([tool] + list(tool_args))

    # Save to DB and auto-parse (silent on failure)
    cmd_id = None
    session = None
    try:
        session = get_current_session()
        cmd_id = save_command(
            command=full_command,
            exit_code=exit_code,
            cwd=cwd,
            timestamp=timestamp,
            output=output,
            session_id=session.id if session else None,
        )
    except Exception:
        pass

    # Auto-parse the captured output into structured findings
    parsed_ok = False
    canonical_tool = detect_tool(full_command) or tool
    if session and cmd_id and output:
        try:
            result = run_parser(
                tool_name=canonical_tool,
                output=output,
                command=full_command,
                session_id=session.id,
                command_id=cmd_id,
            )
            if result and not result.is_empty:
                show_parse_result(canonical_tool, result.summary())
                parsed_ok = True
        except Exception:
            pass

    # Flag detection — runs regardless of session state
    flags = _check_for_flags(output)
    for flag in flags:
        show_flag_alert(flag)

    # CVE enrichment (NVD) + Searchsploit auto-query — fire after nmap parse.
    # Both are silent on error and don't block the main flow.
    if parsed_ok and session and cmd_id and canonical_tool == "nmap":
        _run_cve_enrichment(session, cmd_id)
        _run_searchsploit_auto(session, cmd_id)

    # Pattern engine — runs first (offline, zero latency, zero cost).
    # High-confidence matches suppress the AI call to save API credits.
    high_confidence_pattern_fired = False
    _target_ip = (session.target_ip or session.target_host or "") if session else ""
    if session and output:
        try:
            ctx = build_context(session.id)
            if ctx:
                pattern_matches = run_pattern_engine(
                    ctx=ctx,
                    trigger_command=full_command,
                    max_results=3,
                )
                for match in pattern_matches:
                    # Substitute <target> placeholder with actual target IP/host
                    hint_text = match.hint
                    if _target_ip:
                        hint_text = hint_text.replace("<target>", _target_ip)

                    # Dedup: skip if we've shown a near-identical hint before
                    if is_duplicate(session.id, hint_text):
                        continue
                    save_hint(
                        session_id=session.id,
                        hint_text=hint_text,
                        source="pattern",
                        confidence=match.confidence,
                        command_id=cmd_id,
                        rule_name=match.rule_id,
                    )
                    show_hint(
                        hint_text=hint_text,
                        source="pattern",
                        confidence=match.confidence,
                        tool=canonical_tool,
                        rule_name=match.rule_name,
                    )
                    if match.confidence >= 0.90:
                        high_confidence_pattern_fired = True
        except Exception:
            pass

    # AI hint generation — skipped when a high-confidence pattern already fired.
    # This preserves API credits for cases where offline rules are sufficient.
    if session and output and not high_confidence_pattern_fired:
        try:
            show_generating(backend=_cfg.ai_backend)
            hint = generate_hint(
                session_id=session.id,
                trigger_command=full_command,
                command_id=cmd_id,
            )
            if not hint.skipped:
                show_hint(
                    hint_text=hint.text,
                    source=hint.source,
                    confidence=hint.confidence,
                    tool=canonical_tool,
                )
            else:
                show_skip_reason(hint.skip_reason, verbose=False)
        except Exception:
            pass

    sys.exit(exit_code)


def main():
    wrap_cmd()


if __name__ == "__main__":
    main()
