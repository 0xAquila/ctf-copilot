"""
Session Writeup Auto-Generator.

Converts a completed (or in-progress) CTF session into a structured
Markdown writeup suitable for publishing or personal reference.

Structure generated:
  1.  Title + metadata block
  2.  Target Information table
  3.  Enumeration -- port scan table + web findings table
  4.  Vulnerabilities Identified (from pattern-engine hints)
  5.  Attack Path (AI-generated narrative, optional)
  6.  Credentials Found
  7.  Flags Captured
  8.  Tools Used
  9.  Command Log (chronological, code-fenced)
  10. Hints Timeline (all hints from the session)
  11. Footer

Usage:
    result = generate_writeup(session_id=3)
    result = generate_writeup(session_id=3, use_ai=False)  # offline
    print(result.markdown)
    result.save()  # writes to ~/ctf_writeups/<name>_writeup.md
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ctf_copilot.core.database import get_connection, init_db
from ctf_copilot.core.config import config


# ---------------------------------------------------------------------------
# Output model
# ---------------------------------------------------------------------------

@dataclass
class WriteupResult:
    session_name: str
    markdown:     str
    ai_enhanced:  bool = False
    filename:     str  = ""        # set after save()

    def save(self, output_path: Optional[str] = None) -> Path:
        """
        Write the Markdown content to disk.

        Default location: ~/ctf_writeups/<session_name>_writeup.md
        """
        if output_path:
            dest = Path(output_path).expanduser()
        else:
            writeups_dir = Path.home() / "ctf_writeups"
            writeups_dir.mkdir(parents=True, exist_ok=True)
            safe_name = "".join(
                c if c.isalnum() or c in "-_" else "_"
                for c in self.session_name
            )
            dest = writeups_dir / f"{safe_name}_writeup.md"

        dest.write_text(self.markdown, encoding="utf-8")
        self.filename = str(dest)
        return dest


# ---------------------------------------------------------------------------
# Data fetcher
# ---------------------------------------------------------------------------

def _fetch_session_data(session_id: int) -> dict:
    """Pull all relevant data for a session from the DB in one pass."""
    init_db()
    with get_connection() as conn:
        session = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()

        services = conn.execute(
            "SELECT * FROM services WHERE session_id = ? ORDER BY port",
            (session_id,),
        ).fetchall()

        web_findings = conn.execute(
            "SELECT * FROM web_findings WHERE session_id = ? ORDER BY status_code, endpoint",
            (session_id,),
        ).fetchall()

        credentials = conn.execute(
            "SELECT * FROM credentials WHERE session_id = ? ORDER BY username",
            (session_id,),
        ).fetchall()

        flags = conn.execute(
            "SELECT * FROM flags WHERE session_id = ? ORDER BY found_at",
            (session_id,),
        ).fetchall()

        commands = conn.execute(
            """SELECT command, tool, exit_code, timestamp, cwd
               FROM commands
               WHERE session_id = ?
               ORDER BY timestamp ASC""",
            (session_id,),
        ).fetchall()

        hints = conn.execute(
            """SELECT hint_text, source, confidence, rule_name, timestamp
               FROM hints
               WHERE session_id = ?
               ORDER BY timestamp ASC""",
            (session_id,),
        ).fetchall()

    return {
        "session":      dict(session) if session else {},
        "services":     [dict(r) for r in services],
        "web_findings": [dict(r) for r in web_findings],
        "credentials":  [dict(r) for r in credentials],
        "flags":        [dict(r) for r in flags],
        "commands":     [dict(r) for r in commands],
        "hints":        [dict(r) for r in hints],
    }


# ---------------------------------------------------------------------------
# Markdown section builders
# ---------------------------------------------------------------------------

def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Build a GitHub-flavoured Markdown table."""
    header_row = "| " + " | ".join(headers) + " |"
    sep_row    = "| " + " | ".join("---" for _ in headers) + " |"
    body_rows  = [
        "| " + " | ".join(str(c).replace("|", "\\|") for c in row) + " |"
        for row in rows
    ]
    return "\n".join([header_row, sep_row] + body_rows)


def _section(title: str, content: str, level: int = 2) -> str:
    heading = "#" * level
    return f"{heading} {title}\n\n{content.strip()}\n"


def _build_header(data: dict) -> str:
    s = data["session"]
    name       = s.get("name", "Unknown")
    platform   = s.get("platform") or "Unknown"
    difficulty = s.get("difficulty") or "Unknown"
    started    = (s.get("started_at") or "")[:10]
    target_ip  = s.get("target_ip") or ""
    target_host = s.get("target_host") or ""
    os_guess   = s.get("os_guess") or "Unknown"
    flags      = data["flags"]

    target_display = target_ip or target_host or "Unknown"

    rooted_line = ""
    if flags:
        flag_types = ", ".join(f.get("flag_type", "flag") for f in flags)
        rooted_line = f"  **Flags:** {flag_types}\n"

    lines = [
        f"# CTF Writeup: {name}",
        "",
        f"> **Platform:** {platform}  |  "
        f"**Difficulty:** {difficulty}  |  "
        f"**Date:** {started}  |  "
        f"**OS:** {os_guess}",
        "",
    ]
    if rooted_line:
        lines.append(rooted_line)
    lines.append("")
    return "\n".join(lines)


def _build_target_info(data: dict) -> str:
    s = data["session"]
    rows = []
    if s.get("target_ip"):
        rows.append(["IP Address", s["target_ip"]])
    if s.get("target_host"):
        rows.append(["Hostname", s["target_host"]])
    rows.append(["Platform", s.get("platform") or "-"])
    rows.append(["Difficulty", s.get("difficulty") or "-"])
    if s.get("os_guess"):
        rows.append(["OS", s["os_guess"]])
    if s.get("notes"):
        rows.append(["Notes", s["notes"]])

    if not rows:
        return _section("Target Information", "_No target information recorded._")

    table = _md_table(["Field", "Value"], rows)
    return _section("Target Information", table)


def _build_enumeration(data: dict) -> str:
    parts = []

    # Port scan
    if data["services"]:
        rows = []
        for svc in data["services"]:
            rows.append([
                str(svc.get("port", "")),
                svc.get("protocol", "tcp"),
                svc.get("service") or "-",
                (svc.get("version") or "-")[:60],
                (svc.get("banner") or "-")[:40],
            ])
        table = _md_table(["Port", "Proto", "Service", "Version", "Banner"], rows)
        parts.append(f"### Port Scan Results\n\n{table}")
    else:
        parts.append("### Port Scan Results\n\n_No port scan data recorded._")

    # Web findings
    if data["web_findings"]:
        rows = []
        for wf in data["web_findings"]:
            code = wf.get("status_code") or "-"
            rows.append([
                str(code),
                wf.get("method") or "GET",
                wf.get("endpoint", ""),
                (wf.get("notes") or "-")[:60],
            ])
        table = _md_table(["Status", "Method", "Endpoint", "Notes"], rows)
        parts.append(f"### Web Enumeration\n\n{table}")

    return _section("Enumeration", "\n\n".join(parts))


def _build_vulnerabilities(data: dict) -> str:
    """Extract high-confidence pattern-rule hints as a vuln list."""
    pattern_hints = [
        h for h in data["hints"]
        if h.get("source") == "pattern"
    ]

    if not pattern_hints:
        return _section(
            "Vulnerabilities Identified",
            "_No vulnerabilities automatically identified. See hints timeline for AI findings._",
        )

    # Sort by confidence descending
    pattern_hints.sort(key=lambda h: -(h.get("confidence") or 0.0))

    lines = []
    for h in pattern_hints:
        rule = h.get("rule_name") or "Unknown rule"
        conf = h.get("confidence") or 0.0
        # First sentence of hint as brief description
        hint_text = (h.get("hint_text") or "").strip()
        brief = hint_text.split("\n")[0][:120] if hint_text else ""
        lines.append(f"- **{rule}** — Confidence: {conf:.0%}")
        if brief:
            lines.append(f"  {brief}")

    return _section("Vulnerabilities Identified", "\n".join(lines))


def _build_attack_path(narrative: str) -> str:
    if narrative and narrative.strip():
        return _section("Attack Path", narrative.strip())
    return _section(
        "Attack Path",
        "_Attack path narrative not generated. "
        "Re-run with AI enabled or fill in manually._",
    )


def _build_credentials(data: dict) -> str:
    if not data["credentials"]:
        return _section("Credentials Found", "_No credentials captured._")
    rows = [
        [
            c.get("username") or "-",
            c.get("password") or "-",
            (c.get("hash") or "-")[:32],
            c.get("source") or "-",
        ]
        for c in data["credentials"]
    ]
    table = _md_table(["Username", "Password", "Hash", "Source"], rows)
    return _section("Credentials Found", table)


def _build_flags(data: dict) -> str:
    if not data["flags"]:
        return _section("Flags Captured", "_No flags captured yet._")
    rows = [
        [
            f.get("flag_type") or "flag",
            f"``{f.get('flag_value', '')}``",
            (f.get("found_at") or "")[:19].replace("T", " "),
        ]
        for f in data["flags"]
    ]
    table = _md_table(["Type", "Value", "Captured At"], rows)
    return _section("Flags Captured", table)


def _build_tools_used(data: dict) -> str:
    tools = sorted({
        cmd.get("tool") for cmd in data["commands"]
        if cmd.get("tool")
    })
    if not tools:
        return _section("Tools Used", "_No tools recorded._")
    lines = "\n".join(f"- `{t}`" for t in tools)
    return _section("Tools Used", lines)


def _build_command_log(data: dict) -> str:
    if not data["commands"]:
        return _section("Command Log", "_No commands logged._")

    blocks = []
    for cmd in data["commands"]:
        ts      = (cmd.get("timestamp") or "")[:19].replace("T", " ")
        command = cmd.get("command", "").strip()
        exit_c  = cmd.get("exit_code")
        note    = f" # exit {exit_c}" if exit_c not in (None, 0) else ""
        blocks.append(f"# {ts}{note}\n{command}")

    code_block = "```bash\n" + "\n\n".join(blocks) + "\n```"
    return _section("Command Log", code_block)


def _build_hints_timeline(data: dict) -> str:
    if not data["hints"]:
        return _section("Hints Timeline", "_No hints recorded._")

    lines = []
    for i, h in enumerate(data["hints"], 1):
        source = h.get("source", "ai").upper()
        ts     = (h.get("timestamp") or "")[:16].replace("T", " ")
        conf   = h.get("confidence") or 0.0
        rule   = h.get("rule_name") or ""
        hint   = (h.get("hint_text") or "").strip()

        label  = f"[{source}]"
        if rule:
            label += f" {rule}"

        lines.append(f"**{i}. {label}** — {ts} — {conf:.0%}")
        # Indent the hint text
        indented = textwrap.indent(hint, "  ")
        lines.append(indented)
        lines.append("")

    return _section("Hints Timeline", "\n".join(lines))


def _build_footer() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"\n---\n\n*Generated by [CTF Copilot](https://github.com) on {now}*\n"


# ---------------------------------------------------------------------------
# AI narrative generator
# ---------------------------------------------------------------------------

_WRITEUP_SYSTEM = (
    "You are a professional CTF writeup author. "
    "Given structured session data from a penetration testing session, "
    "write a concise 'Attack Path' narrative (4-8 sentences) in past tense. "
    "Cover: initial enumeration findings, the key vulnerability exploited, "
    "how access was gained, and privilege escalation if applicable. "
    "Be specific about tool names and vulnerability names. "
    "Do not use bullet points -- write flowing prose. "
    "Do not repeat information that will appear in other sections. "
    "Output only the narrative text, no headings or markdown formatting."
)


def _generate_ai_narrative(data: dict) -> str:
    """Call Claude to write a 4-8 sentence attack path narrative."""
    if not config.api_key or config.offline_mode:
        return ""

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=config.api_key)

        s          = data["session"]
        services   = data["services"]
        flags      = data["flags"]
        hints      = data["hints"]
        commands   = data["commands"]

        # Summarise the session for the AI
        svc_lines  = [
            f"  port {sv['port']}/{sv.get('protocol','tcp')} {sv.get('service','')} {sv.get('version','')}"
            for sv in services
        ]
        web_lines  = [
            f"  {wf.get('status_code','')} {wf.get('endpoint','')}"
            for wf in data["web_findings"][:10]
        ]
        flag_lines = [
            f"  {f.get('flag_type','flag')}: {f.get('flag_value','')}"
            for f in flags
        ]
        # Only pattern-engine and high-confidence AI hints
        hint_lines = [
            f"  [{h.get('source','')}] {h.get('rule_name') or ''}: {(h.get('hint_text') or '')[:100]}"
            for h in hints[:8]
        ]
        tool_names = sorted({c.get("tool") for c in commands if c.get("tool")})

        context_block = "\n".join([
            f"TARGET: {s.get('target_ip') or s.get('target_host') or 'unknown'}",
            f"PLATFORM: {s.get('platform') or 'CTF'}",
            f"DIFFICULTY: {s.get('difficulty') or 'unknown'}",
            "OPEN PORTS:",
            *svc_lines,
            "WEB FINDINGS:",
            *(web_lines or ["  none"]),
            "FLAGS CAPTURED:",
            *(flag_lines or ["  none yet"]),
            "KEY FINDINGS / HINTS:",
            *(hint_lines or ["  none"]),
            f"TOOLS USED: {', '.join(tool_names) or 'none'}",
        ])

        response = client.messages.create(
            model=config.ai_model,
            max_tokens=400,
            system=[{
                "type": "text",
                "text": _WRITEUP_SYSTEM,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{
                "role": "user",
                "content": (
                    "Write the Attack Path section for this CTF session:\n\n"
                    + context_block
                ),
            }],
        )
        return response.content[0].text.strip()

    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_writeup(
    session_id: int,
    use_ai: bool = True,
) -> WriteupResult:
    """
    Generate a full Markdown writeup for the given session.

    Args:
        session_id: The database ID of the session.
        use_ai:     If True, call Claude to write the Attack Path narrative.
                    Set False for offline / no-cost generation.

    Returns:
        WriteupResult with .markdown and .save() method.
    """
    data = _fetch_session_data(session_id)
    if not data["session"]:
        raise ValueError(f"Session {session_id} not found in database.")

    session_name = data["session"].get("name", str(session_id))

    # Generate AI narrative first (can take a moment)
    narrative   = ""
    ai_enhanced = False
    if use_ai:
        narrative = _generate_ai_narrative(data)
        ai_enhanced = bool(narrative)

    # Assemble the Markdown document
    sections = [
        _build_header(data),
        "---\n",
        _build_target_info(data),
        "---\n",
        _build_enumeration(data),
        "---\n",
        _build_vulnerabilities(data),
        "---\n",
        _build_attack_path(narrative),
        "---\n",
        _build_credentials(data),
        "---\n",
        _build_flags(data),
        "---\n",
        _build_tools_used(data),
        "---\n",
        _build_command_log(data),
        "---\n",
        _build_hints_timeline(data),
        _build_footer(),
    ]

    markdown = "\n".join(sections)

    return WriteupResult(
        session_name=session_name,
        markdown=markdown,
        ai_enhanced=ai_enhanced,
    )
