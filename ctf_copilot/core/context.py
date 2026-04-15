"""
Context Engine — the session's working memory.

Aggregates every piece of discovered intelligence into a single structured
snapshot (SessionContext) that is used by:
  - The AI Reasoning Engine  → format_for_ai() produces the LLM prompt block
  - The Pattern Engine       → raw structured data for rule matching
  - The CLI                  → ctf context command

Key design decisions:
  - Build is always fresh from the DB (no in-process cache that can drift)
  - Observations are synthesised here from raw findings
  - The AI prompt block is compact and prioritised, not a raw data dump
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from ctf_copilot.core.database import get_connection, init_db
from ctf_copilot.core.session import Session, get_session_by_id


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Observation:
    """A single synthesised insight about the session."""
    subject:     str            # e.g. "Port 21 FTP (vsftpd 2.3.4)"
    text:        str            # e.g. "Known backdoor CVE-2011-2523"
    category:    str            # vulnerability | finding | gap | recommendation
    priority:    int = 2        # 1=high, 2=medium, 3=low
    tags:        list[str] = field(default_factory=list)
    cve:         str = ""       # CVE ID if applicable


@dataclass
class SessionContext:
    """Full snapshot of a CTF session's known state."""
    session:        Session
    services:       list[dict]
    web_findings:   list[dict]
    credentials:    list[dict]
    flags:          list[dict]
    command_summary: dict        # {total, tools_used: [{tool, cnt}], recent: [...]}
    observations:   list[Observation] = field(default_factory=list)

    # Derived convenience views (populated by build_context)
    services_by_port:  dict[int, dict]  = field(default_factory=dict)
    tools_used:        set[str]         = field(default_factory=set)

    @property
    def target(self) -> str:
        return self.session.target_ip or self.session.target_host or "unknown"

    @property
    def open_ports(self) -> list[int]:
        return sorted(s["port"] for s in self.services)

    @property
    def high_priority_observations(self) -> list[Observation]:
        return [o for o in self.observations if o.priority == 1]

    @property
    def has_web(self) -> bool:
        return any(s["service"] in ("http", "https", "www", "http-proxy")
                   for s in self.services)

    @property
    def has_smb(self) -> bool:
        return any(s["port"] in (139, 445) for s in self.services)

    @property
    def has_ftp(self) -> bool:
        return any(s["port"] == 21 for s in self.services)

    @property
    def has_sql(self) -> bool:
        return any(s["port"] in (3306, 5432, 1433, 1521)
                   for s in self.services)


# ---------------------------------------------------------------------------
# DB queries
# ---------------------------------------------------------------------------

def _fetch_services(conn, session_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM services WHERE session_id = ? ORDER BY port",
        (session_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        # Deserialise extra JSON blob
        if d.get("extra"):
            try:
                d["extra"] = json.loads(d["extra"])
            except (json.JSONDecodeError, TypeError):
                d["extra"] = {}
        else:
            d["extra"] = {}
        result.append(d)
    return result


def _fetch_web_findings(conn, session_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM web_findings WHERE session_id = ? ORDER BY status_code, endpoint",
        (session_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("parameters"):
            try:
                d["parameters"] = json.loads(d["parameters"])
            except (json.JSONDecodeError, TypeError):
                d["parameters"] = []
        else:
            d["parameters"] = []
        result.append(d)
    return result


def _fetch_command_summary(conn, session_id: int) -> dict:
    total = conn.execute(
        "SELECT COUNT(*) FROM commands WHERE session_id = ?", (session_id,)
    ).fetchone()[0]

    tools = conn.execute(
        """SELECT tool, COUNT(*) as cnt
           FROM commands
           WHERE session_id = ? AND tool IS NOT NULL
           GROUP BY tool ORDER BY cnt DESC""",
        (session_id,),
    ).fetchall()

    recent = conn.execute(
        """SELECT command, tool, exit_code, timestamp
           FROM commands WHERE session_id = ?
           ORDER BY timestamp DESC LIMIT 10""",
        (session_id,),
    ).fetchall()

    return {
        "total":      total,
        "tools_used": [dict(t) for t in tools],
        "recent":     [dict(r) for r in recent],
    }


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def build_context(session_id: int) -> Optional[SessionContext]:
    """
    Build a fresh SessionContext from the DB for the given session.
    Returns None if the session doesn't exist.
    """
    init_db()
    session = get_session_by_id(session_id)
    if not session:
        return None

    with get_connection() as conn:
        services    = _fetch_services(conn, session_id)
        web_findings = _fetch_web_findings(conn, session_id)
        creds       = [dict(r) for r in conn.execute(
            "SELECT * FROM credentials WHERE session_id = ?", (session_id,)
        ).fetchall()]
        flags       = [dict(r) for r in conn.execute(
            "SELECT * FROM flags WHERE session_id = ?", (session_id,)
        ).fetchall()]
        cmd_summary = _fetch_command_summary(conn, session_id)

    # Build derived indexes
    services_by_port = {s["port"]: s for s in services}
    tools_used = {t["tool"] for t in cmd_summary["tools_used"]}

    ctx = SessionContext(
        session=session,
        services=services,
        web_findings=web_findings,
        credentials=creds,
        flags=flags,
        command_summary=cmd_summary,
        services_by_port=services_by_port,
        tools_used=tools_used,
    )

    # Synthesise observations
    from ctf_copilot.core.observations import synthesise
    ctx.observations = synthesise(ctx)

    return ctx


def build_current_context() -> Optional[SessionContext]:
    """Convenience wrapper — builds context for the current active session."""
    from ctf_copilot.core.session import get_current_session
    session = get_current_session()
    if not session:
        return None
    return build_context(session.id)


# ---------------------------------------------------------------------------
# AI prompt formatter
# ---------------------------------------------------------------------------

def format_for_ai(ctx: SessionContext, recent_command: str = "") -> str:
    """
    Produce a compact, structured context block for injection into AI prompts.

    The format is designed to:
      - Fit comfortably within a single prompt section (< 800 tokens)
      - Prioritise actionable information
      - Give the AI enough to make intelligent suggestions
    """
    lines: list[str] = []

    # --- Session header ---
    target_str = ctx.target
    if ctx.session.target_host and ctx.session.target_ip:
        target_str = f"{ctx.session.target_ip} ({ctx.session.target_host})"
    meta_parts = [target_str]
    if ctx.session.platform:   meta_parts.append(ctx.session.platform)
    if ctx.session.difficulty: meta_parts.append(ctx.session.difficulty)
    if ctx.session.os_guess:   meta_parts.append(f"OS: {ctx.session.os_guess}")
    lines.append(f"TARGET: {' | '.join(meta_parts)}")

    # --- Open ports ---
    if ctx.services:
        port_strs = []
        for svc in ctx.services:
            p = str(svc["port"])
            s = svc.get("service") or "?"
            v = svc.get("version") or ""
            port_strs.append(f"{p}/{s}" + (f" ({v[:30]})" if v else ""))
        lines.append(f"OPEN PORTS ({len(ctx.services)}): {', '.join(port_strs)}")
    else:
        lines.append("OPEN PORTS: none discovered yet")

    # --- Web findings ---
    if ctx.web_findings:
        # Group by status code for conciseness
        by_status: dict[str, list[str]] = {}
        for wf in ctx.web_findings:
            code = str(wf.get("status_code") or "?")
            by_status.setdefault(code, []).append(wf["endpoint"])

        web_parts = []
        for code in sorted(by_status.keys()):
            eps = by_status[code]
            if len(eps) <= 3:
                web_parts.append(f"[{code}] {', '.join(eps)}")
            else:
                web_parts.append(f"[{code}] {', '.join(eps[:3])} +{len(eps)-3} more")
        lines.append(f"WEB FINDINGS ({len(ctx.web_findings)}): {' | '.join(web_parts)}")
    else:
        lines.append("WEB FINDINGS: none yet")

    # --- Credentials ---
    if ctx.credentials:
        cred_strs = []
        for c in ctx.credentials[:5]:
            user = c.get("username") or "?"
            src  = c.get("source") or ""
            cred_strs.append(f"{user}" + (f" ({src})" if src else ""))
        lines.append(f"CREDENTIALS ({len(ctx.credentials)}): {', '.join(cred_strs)}")

    # --- Flags ---
    if ctx.flags:
        lines.append(f"FLAGS CAPTURED: {len(ctx.flags)}")

    # --- High-priority observations ---
    high = ctx.high_priority_observations
    if high:
        lines.append("KEY OBSERVATIONS:")
        for obs in high[:6]:  # cap at 6 to keep prompt tight
            cve_note = f" [{obs.cve}]" if obs.cve else ""
            lines.append(f"  - {obs.subject}: {obs.text}{cve_note}")

    # Also include medium-priority if there are no high ones
    if not high:
        medium = [o for o in ctx.observations if o.priority == 2][:4]
        if medium:
            lines.append("OBSERVATIONS:")
            for obs in medium:
                lines.append(f"  - {obs.text}")

    # --- Coverage gaps ---
    gaps = [o for o in ctx.observations if o.category == "gap"]
    if gaps:
        lines.append(f"NOT YET EXPLORED: {', '.join(o.subject for o in gaps[:5])}")

    # --- Tools used ---
    if ctx.tools_used:
        lines.append(f"TOOLS USED: {', '.join(sorted(ctx.tools_used))}")

    # --- Most recent action ---
    if recent_command:
        lines.append(f"LAST ACTION: {recent_command[:100]}")
    elif ctx.command_summary["recent"]:
        last = ctx.command_summary["recent"][0]
        lines.append(f"LAST ACTION: {last['command'][:100]}")

    return "\n".join(lines)
