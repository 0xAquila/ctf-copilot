"""
CTF Copilot TUI Dashboard.

A Rich Live dashboard that auto-refreshes from the session database and
gives a real-time overview of the current CTF session in one terminal view.

Layout:
  +---------------------------------------------------------+
  |  HEADER  - session name, target, platform, status       |
  +------------------+-----------------+-------------------+
  |  SERVICES        |  WEB FINDINGS   |  LATEST HINTS     |
  |  port/svc table  |  endpoint table |  hint list        |
  +------------------+-----------------+-------------------+
  |  FOOTER  - stats bar + last command + key hints         |
  +---------------------------------------------------------+

Usage:
  run_dashboard(session_id)          -- live mode, Ctrl+C to exit
  render_snapshot(session_id)        -- returns a renderable for one-shot print
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ctf_copilot.core.database import get_connection, init_db


# ---------------------------------------------------------------------------
# Data fetcher  (lightweight — called every refresh cycle)
# ---------------------------------------------------------------------------

def _fetch(session_id: int) -> dict:
    """Pull all dashboard data in a single DB round-trip."""
    init_db()
    with get_connection() as conn:
        session = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()

        services = conn.execute(
            "SELECT port, protocol, service, version FROM services "
            "WHERE session_id = ? ORDER BY port LIMIT 30",
            (session_id,),
        ).fetchall()

        web = conn.execute(
            "SELECT status_code, method, endpoint, notes FROM web_findings "
            "WHERE session_id = ? ORDER BY status_code, endpoint LIMIT 30",
            (session_id,),
        ).fetchall()

        creds = conn.execute(
            "SELECT COUNT(*) AS cnt FROM credentials WHERE session_id = ?",
            (session_id,),
        ).fetchone()

        flags = conn.execute(
            "SELECT flag_type, flag_value FROM flags WHERE session_id = ?",
            (session_id,),
        ).fetchall()

        hints = conn.execute(
            "SELECT hint_text, source, confidence, rule_name, timestamp "
            "FROM hints WHERE session_id = ? ORDER BY timestamp DESC LIMIT 6",
            (session_id,),
        ).fetchall()

        # Session notes
        notes_rows = conn.execute(
            "SELECT id, text, tags, pinned, created_at "
            "FROM session_notes "
            "WHERE session_id = ? "
            "ORDER BY pinned DESC, created_at DESC LIMIT 8",
            (session_id,),
        ).fetchall()

        note_count = conn.execute(
            "SELECT COUNT(*) AS cnt FROM session_notes WHERE session_id = ?",
            (session_id,),
        ).fetchone()

        commands = conn.execute(
            "SELECT command, tool, timestamp FROM commands "
            "WHERE session_id = ? ORDER BY timestamp DESC LIMIT 5",
            (session_id,),
        ).fetchall()

        tool_rows = conn.execute(
            "SELECT DISTINCT tool FROM commands "
            "WHERE session_id = ? AND tool IS NOT NULL",
            (session_id,),
        ).fetchall()

        cmd_count = conn.execute(
            "SELECT COUNT(*) AS cnt FROM commands WHERE session_id = ?",
            (session_id,),
        ).fetchone()

    return {
        "session":    dict(session) if session else {},
        "services":   [dict(r) for r in services],
        "web":        [dict(r) for r in web],
        "cred_count": creds["cnt"] if creds else 0,
        "flags":      [dict(r) for r in flags],
        "hints":      [dict(r) for r in hints],
        "notes":      [dict(r) for r in notes_rows],
        "note_count": note_count["cnt"] if note_count else 0,
        "commands":   [dict(r) for r in commands],
        "tools":      sorted(r["tool"] for r in tool_rows if r["tool"]),
        "cmd_count":  cmd_count["cnt"] if cmd_count else 0,
    }


# ---------------------------------------------------------------------------
# Panel builders
# ---------------------------------------------------------------------------

def _header_panel(data: dict) -> Panel:
    s      = data["session"]
    name   = s.get("name", "Unknown")
    target = s.get("target_ip") or s.get("target_host") or "-"
    plat   = s.get("platform") or "-"
    diff   = s.get("difficulty") or "-"
    status = s.get("status", "active")

    status_style = {
        "active":    "[bold green][ACTIVE][/]",
        "paused":    "[bold yellow][PAUSED][/]",
        "completed": "[bold blue][DONE][/]",
    }.get(status, status.upper())

    flags = data["flags"]
    flag_str = ""
    if flags:
        vals = "  ".join(f["flag_value"] for f in flags)
        flag_str = f"  [bold green]  FLAG: {vals}[/]"

    content = Text(justify="center")
    content.append(f"Session: ", style="bold dim")
    content.append(f"{name}", style="bold #8B5CF6")
    content.append(f"   Target: ", style="bold dim")
    content.append(f"{target}", style="bold white")
    content.append(f"   Platform: ", style="bold dim")
    content.append(f"{plat}", style="white")
    content.append(f"   Difficulty: ", style="bold dim")
    content.append(f"{diff}", style="white")
    content.append(f"   Status: ", style="bold dim")
    content.append_text(Text.from_markup(status_style))
    if flag_str:
        content.append_text(Text.from_markup(flag_str))

    return Panel(
        Align.center(content),
        title="[bold #8B5CF6]CTF Copilot[/]",
        border_style="#8B5CF6",
        box=box.HEAVY,
        padding=(0, 1),
    )


def _services_panel(data: dict) -> Panel:
    services = data["services"]

    if not services:
        body = Text("\n  No services yet.\n  Run: nmap -sV <target>", style="dim")
        return Panel(body, title="[bold #F59E0B]Services[/]", border_style="#F59E0B",
                     box=box.ROUNDED)

    t = Table(box=None, show_header=True, header_style="bold #F59E0B",
              padding=(0, 1), expand=True)
    t.add_column("Port",  style="bold #F59E0B", width=6,  no_wrap=True)
    t.add_column("Proto", style="dim",        width=5,  no_wrap=True)
    t.add_column("Service / Version", style="white", ratio=1)

    for svc in services:
        port     = str(svc.get("port", ""))
        proto    = svc.get("protocol", "tcp")
        svc_name = svc.get("service") or ""
        version  = svc.get("version") or ""
        svc_str  = f"{svc_name}  [dim]{version[:30]}[/]" if version else svc_name

        # Highlight interesting ports
        port_style = "bold #F59E0B"
        interesting = {21, 22, 23, 25, 80, 110, 139, 143, 389, 443,
                       445, 1433, 1521, 3306, 3389, 5432, 5985, 6379, 8080, 8443}
        if svc.get("port") in interesting:
            port_style = "bold green"

        t.add_row(
            f"[{port_style}]{port}[/]",
            proto,
            svc_str,
        )

    return Panel(
        t,
        title=f"[bold #F59E0B]Services[/] [dim]({len(services)})[/]",
        border_style="#F59E0B",
        box=box.ROUNDED,
    )


def _web_panel(data: dict) -> Panel:
    web = data["web"]

    if not web:
        body = Text(
            "\n  No web findings yet.\n"
            "  Run: gobuster dir -u http://<target>\n"
            "       ffuf -u http://<target>/FUZZ",
            style="dim",
        )
        return Panel(body, title="[bold magenta]Web Findings[/]",
                     border_style="magenta", box=box.ROUNDED)

    t = Table(box=None, show_header=True, header_style="bold magenta",
              padding=(0, 1), expand=True)
    t.add_column("Code",     width=5,  no_wrap=True)
    t.add_column("Endpoint", ratio=1)
    t.add_column("Notes",    ratio=1,  style="dim")

    for wf in web:
        code = str(wf.get("status_code") or "-")
        if code.startswith("2"):
            code_str = f"[bold green]{code}[/]"
        elif code.startswith("3"):
            code_str = f"[yellow]{code}[/]"
        elif code.startswith("4"):
            code_str = f"[dim]{code}[/]"
        elif code.startswith("5"):
            code_str = f"[bold red]{code}[/]"
        else:
            code_str = code

        endpoint = wf.get("endpoint", "")
        notes    = (wf.get("notes") or "")[:40]

        t.add_row(code_str, endpoint, notes)

    return Panel(
        t,
        title=f"[bold magenta]Web Findings[/] [dim]({len(web)})[/]",
        border_style="magenta",
        box=box.ROUNDED,
    )


def _hints_panel(data: dict) -> Panel:
    hints = data["hints"]

    if not hints:
        body = Text(
            "\n  No hints yet.\n"
            "  Hints appear automatically after\n"
            "  running tools with the shell hook.",
            style="dim",
        )
        return Panel(body, title="[bold #8B5CF6]Latest Hints[/]",
                     border_style="#8B5CF6", box=box.ROUNDED)

    parts: list = []
    for i, h in enumerate(hints):
        source = h.get("source", "ai")
        conf   = h.get("confidence") or 0.0
        rule   = h.get("rule_name") or ""
        ts     = (h.get("timestamp") or "")[:16].replace("T", " ")
        text   = (h.get("hint_text") or "").strip()

        # Badge
        if source == "pattern":
            badge = Text("[Rule] ", style="bold yellow")
            label = rule or "Pattern"
        else:
            badge = Text("[AI]   ", style="bold #8B5CF6")
            label = "Copilot"

        header = Text()
        header.append_text(badge)
        header.append(f"{label}  ", style="dim")
        header.append(f"{conf:.0%}  ", style="dim")
        header.append(ts, style="dim")

        # Truncate hint to 3 lines of ~55 chars
        lines = []
        remaining = text
        while remaining and len(lines) < 3:
            lines.append(remaining[:55])
            remaining = remaining[55:]
        if remaining:
            lines[-1] = lines[-1][:-3] + "..."
        body_text = "\n".join(lines)

        hint_block = Text()
        hint_block.append_text(header)
        hint_block.append("\n")
        hint_block.append(body_text, style="white")

        parts.append(hint_block)
        if i < len(hints) - 1:
            parts.append(Rule(style="dim"))

    return Panel(
        Group(*parts),
        title=f"[bold #8B5CF6]Latest Hints[/] [dim]({len(hints)})[/]",
        border_style="#8B5CF6",
        box=box.ROUNDED,
    )


def _notes_panel(data: dict) -> Panel:
    notes     = data.get("notes", [])
    total_cnt = data.get("note_count", 0)

    if not notes:
        body = Text(
            "\n  No notes yet.\n"
            "  Add one: [bold]ctf note \"your observation\"[/]",
            style="dim",
        )
        return Panel(body, title="[bold blue]Notes[/]",
                     border_style="blue", box=box.ROUNDED)

    parts: list = []
    for i, n in enumerate(notes):
        pin_icon  = "📌 " if n.get("pinned") else ""
        ts        = (n.get("created_at") or "")[:16][5:].replace("T", " ")
        text      = (n.get("text") or "").strip()
        tags      = n.get("tags") or ""

        header = Text()
        header.append(f"{pin_icon}", style="yellow")
        header.append(f"#{n['id']}  ", style=f"bold blue")
        header.append(ts, style="dim")
        if tags:
            header.append(f"  [{tags}]", style="dim blue")

        # Wrap note text to ~52 chars per line
        words, line, wrapped = text.split(), "", []
        for word in words:
            if len(line) + len(word) + 1 > 52:
                if line:
                    wrapped.append(line)
                line = word
            else:
                line = f"{line} {word}".strip()
        if line:
            wrapped.append(line)
        body_text = "\n".join(wrapped[:3])
        if len(wrapped) > 3:
            body_text += " …"

        note_block = Text()
        note_block.append_text(header)
        note_block.append("\n")
        note_block.append(body_text, style="white")

        parts.append(note_block)
        if i < len(notes) - 1:
            parts.append(Rule(style="dim"))

    title_suffix = f" [dim](+{total_cnt - len(notes)} more)[/]" if total_cnt > len(notes) else ""
    return Panel(
        Group(*parts),
        title=f"[bold blue]Notes[/] [dim]({total_cnt})[/]{title_suffix}",
        border_style="blue",
        box=box.ROUNDED,
    )


def _footer_panel(data: dict) -> Panel:
    tools     = data["tools"]
    cmd_count = data["cmd_count"]
    cred_cnt  = data["cred_count"]
    flag_cnt  = len(data["flags"])
    hint_cnt  = data.get("hint_total", len(data["hints"]))
    commands  = data["commands"]

    tools_str = ", ".join(f"[#F59E0B]{t}[/]" for t in tools) if tools else "[dim]none[/]"
    now       = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

    note_cnt  = data.get("note_count", 0)

    stats = Text()
    stats.append_text(Text.from_markup(
        f"Tools: {tools_str}   "
        f"[dim]|[/]   Commands: [bold]{cmd_count}[/]   "
        f"[dim]|[/]   Creds: [bold]{cred_cnt}[/]   "
        f"[dim]|[/]   Flags: [bold green]{flag_cnt}[/]   "
        f"[dim]|[/]   Hints: [bold]{hint_cnt}[/]   "
        f"[dim]|[/]   Notes: [bold blue]{note_cnt}[/]   "
        f"[dim]|[/]   [dim]{now}[/]"
    ))

    parts: list = [stats]

    if commands:
        last = commands[0]
        cmd_ts  = (last.get("timestamp") or "")[:16].replace("T", " ")
        cmd_str = (last.get("command") or "")[:90]
        recent  = Text()
        recent.append("Last:  ", style="bold dim")
        recent.append(f"[{cmd_ts}]  ", style="dim")
        recent.append(cmd_str, style="white")
        parts.append(recent)

    parts.append(Text.from_markup(
        "[dim]  Ctrl+C to exit   r = refresh now   q = quit[/]"
    ))

    return Panel(
        Group(*parts),
        border_style="dim",
        box=box.ROUNDED,
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# Layout assembler
# ---------------------------------------------------------------------------

def _build_layout(data: dict) -> Layout:
    """Assemble the full dashboard layout from fetched data."""
    root = Layout()

    root.split_column(
        Layout(name="header",  size=3),
        Layout(name="body",    ratio=1),
        Layout(name="footer",  size=5),
    )

    root["body"].split_row(
        Layout(name="services", ratio=2),
        Layout(name="web",      ratio=3),
        Layout(name="hints",    ratio=3),
        Layout(name="notes",    ratio=2),
    )

    root["header"].update(_header_panel(data))
    root["services"].update(_services_panel(data))
    root["web"].update(_web_panel(data))
    root["hints"].update(_hints_panel(data))
    root["notes"].update(_notes_panel(data))
    root["footer"].update(_footer_panel(data))

    return root


# ---------------------------------------------------------------------------
# Snapshot renderer (for --once mode)
# ---------------------------------------------------------------------------

def render_snapshot(session_id: int) -> Group:
    """
    Render the full dashboard as a printable Rich renderable.
    Does not use Live / screen mode — safe for piping and logging.
    """
    data = _fetch(session_id)

    header  = _header_panel(data)
    cols    = Columns([
        _services_panel(data),
        _web_panel(data),
        _hints_panel(data),
        _notes_panel(data),
    ], equal=True, expand=True)
    footer  = _footer_panel(data)

    return Group(header, cols, footer)


# ---------------------------------------------------------------------------
# Live dashboard runner
# ---------------------------------------------------------------------------

def run_dashboard(
    session_id: int,
    refresh_seconds: float = 4.0,
) -> None:
    """
    Run the auto-refreshing Live dashboard until Ctrl+C or 'q'.

    Uses Rich's alternate screen mode so the dashboard fills the terminal
    cleanly without scrollback contamination.

    Args:
        session_id:      DB id of the session to display.
        refresh_seconds: How often to query the DB and redraw (default 4s).
    """
    # Non-blocking keyboard reader (Windows: msvcrt, Unix: select+termios)
    def _kbhit() -> bool:
        try:
            import msvcrt
            return msvcrt.kbhit()  # type: ignore[attr-defined]
        except ImportError:
            import select, sys
            return bool(select.select([sys.stdin], [], [], 0)[0])

    def _getch() -> str:
        try:
            import msvcrt
            return msvcrt.getch().decode("utf-8", errors="ignore")  # type: ignore[attr-defined]
        except ImportError:
            import sys
            return sys.stdin.read(1)

    data = _fetch(session_id)

    with Live(
        _build_layout(data),
        screen=True,
        refresh_per_second=2,
        transient=False,
    ) as live:
        last_refresh = time.monotonic()
        try:
            while True:
                time.sleep(0.1)

                # Keyboard check
                if _kbhit():
                    ch = _getch().lower()
                    if ch in ("q", "\x03", "\x1b"):  # q, Ctrl+C, Esc
                        break
                    if ch == "r":
                        data = _fetch(session_id)
                        live.update(_build_layout(data))
                        last_refresh = time.monotonic()

                # Auto-refresh
                if time.monotonic() - last_refresh >= refresh_seconds:
                    data = _fetch(session_id)
                    live.update(_build_layout(data))
                    last_refresh = time.monotonic()

        except KeyboardInterrupt:
            pass
