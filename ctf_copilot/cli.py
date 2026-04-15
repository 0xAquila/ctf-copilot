"""
CTF Copilot CLI — entry point for the `ctf` command.

Commands:
  ctf start <name>     Start a new session
  ctf stop             Pause the current session
  ctf resume <name>    Resume a previous session
  ctf done             Mark current session as completed
  ctf status           Show current session info
  ctf sessions         List all sessions
  ctf history          Show recently logged commands
  ctf findings         Show discovered services, endpoints, credentials
  ctf context          Full session intelligence picture + observations
  ctf hint             Request an on-demand AI hint right now
  ctf hints            Show hint history for the current session
  ctf parsers          List registered tool parsers
  ctf config           Show active configuration
  ctf set-target       Update target details for current session
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ctf_copilot.core.config import config, write_default_config
from ctf_copilot.core.database import init_db
from ctf_copilot.core.logger import get_recent_commands, get_session_summary, detect_tool
from ctf_copilot.core.session import (
    start_session,
    resume_session,
    pause_session,
    complete_session,
    get_current_session,
    list_sessions,
    update_session,
)

import io, sys
console = Console(file=io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace") if hasattr(sys.stdout, "buffer") else sys.stdout)

# ---------------------------------------------------------------------------
# Styling helpers
# ---------------------------------------------------------------------------

STATUS_STYLE = {
    "active":    "[bold green][ACTIVE][/]",
    "paused":    "[bold yellow][PAUSED][/]",
    "completed": "[bold blue][DONE][/]",
}


def _status_badge(status: str) -> str:
    return STATUS_STYLE.get(status, status)


def _print_session_panel(session) -> None:
    lines = [
        f"[bold]Name:[/]       {session.name}",
        f"[bold]Status:[/]     {_status_badge(session.status)}",
        f"[bold]Target:[/]     {session.target_ip or '-'}  {session.target_host or ''}",
        f"[bold]Platform:[/]   {session.platform or '-'}",
        f"[bold]Difficulty:[/] {session.difficulty or '-'}",
        f"[bold]Started:[/]    {session.started_at}",
    ]
    if session.stopped_at:
        lines.append(f"[bold]Stopped:[/]    {session.stopped_at}")
    if session.notes:
        lines.append(f"[bold]Notes:[/]      {session.notes}")

    console.print(Panel(
        "\n".join(lines),
        title="[bold cyan]CTF Copilot — Session[/]",
        border_style="cyan",
        expand=False,
    ))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """CTF Copilot — your AI-assisted penetration testing companion.\n
    Start a session, run your tools as usual, and get real-time hints.
    """
    write_default_config()
    init_db()


# ---------------------------------------------------------------------------
# ctf start
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("name")
@click.option("--ip",         default="", help="Target IP address")
@click.option("--host",       default="", help="Target hostname / domain")
@click.option("--platform",   default="", help="Platform (HackTheBox, TryHackMe, CTF, …)")
@click.option("--difficulty", default="", help="Difficulty (Easy, Medium, Hard, …)")
def start(name, ip, host, platform, difficulty):
    """Start a new CTF session named NAME."""
    try:
        session = start_session(
            name=name,
            target_ip=ip,
            target_host=host,
            platform=platform,
            difficulty=difficulty,
        )
    except ValueError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        sys.exit(1)

    console.print()
    _print_session_panel(session)
    console.print()
    console.print(
        "[bold green]Session started.[/] "
        "Source the shell hook to activate command logging:\n"
        f"  [bold]source ~/.ctf_copilot/ctf-init.sh[/]"
    )
    console.print()


# ---------------------------------------------------------------------------
# ctf stop
# ---------------------------------------------------------------------------

@cli.command()
def stop():
    """Pause the current session (progress is saved)."""
    session = pause_session()
    if not session:
        console.print("[yellow]No active session. Nothing to stop.[/]")
        sys.exit(0)
    console.print(f"[bold yellow]Session '[cyan]{session.name}[/]' paused.[/]")
    console.print(f"  Resume later with: [bold]ctf resume {session.name}[/]")


# ---------------------------------------------------------------------------
# ctf resume
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("name")
def resume(name):
    """Resume a previously paused session named NAME."""
    try:
        session = resume_session(name)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        sys.exit(1)

    console.print()
    _print_session_panel(session)
    console.print()
    console.print("[bold green]Session resumed.[/]")
    console.print()


# ---------------------------------------------------------------------------
# ctf done
# ---------------------------------------------------------------------------

@cli.command()
@click.confirmation_option(prompt="Mark current session as completed?")
def done():
    """Mark the current session as completed (machine rooted / flag captured)."""
    session = complete_session()
    if not session:
        console.print("[yellow]No active session.[/]")
        sys.exit(0)
    console.print(Panel(
        f"[bold green]Session '[cyan]{session.name}[/]' completed! Well done.[/]\n\n"
        f"  Generate your writeup now:\n"
        f"  [bold]ctf writeup[/]                  - AI-enhanced Markdown writeup\n"
        f"  [bold]ctf writeup --no-ai[/]           - Offline writeup (no API cost)\n"
        f"  [bold]ctf writeup --stdout | less[/]   - Preview in terminal",
        title="[bold cyan]Session Complete[/]",
        border_style="green",
        expand=False,
    ))


# ---------------------------------------------------------------------------
# ctf status
# ---------------------------------------------------------------------------

@cli.command()
def status():
    """Show the current active session details."""
    session = get_current_session()
    if not session:
        console.print(
            "[yellow]No active session.[/]\n"
            "  Start one with: [bold]ctf start <name>[/]"
        )
        sys.exit(0)
    console.print()
    _print_session_panel(session)
    console.print()


# ---------------------------------------------------------------------------
# ctf sessions
# ---------------------------------------------------------------------------

@cli.command("sessions")
def sessions_list():
    """List all sessions (all statuses)."""
    sessions = list_sessions()
    if not sessions:
        console.print("[yellow]No sessions found.[/] Start one with: [bold]ctf start <name>[/]")
        return

    current = get_current_session()
    current_id = current.id if current else None

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title="[bold]CTF Sessions[/]",
    )
    table.add_column("ID",         style="dim",   width=4)
    table.add_column("Name",       style="bold",  min_width=16)
    table.add_column("Status",                    min_width=12)
    table.add_column("Target",                    min_width=16)
    table.add_column("Platform",                  min_width=12)
    table.add_column("Started",                   min_width=20)

    for s in sessions:
        marker = " <" if s.id == current_id else ""
        table.add_row(
            str(s.id),
            s.name + marker,
            _status_badge(s.status),
            s.target_ip or s.target_host or "—",
            s.platform or "—",
            s.started_at,
        )

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# ctf set-target
# ---------------------------------------------------------------------------

@cli.command("set-target")
@click.option("--ip",         default=None, help="Target IP address")
@click.option("--host",       default=None, help="Target hostname")
@click.option("--os",         "os_guess", default=None, help="OS guess (Linux, Windows, …)")
@click.option("--platform",   default=None, help="Platform (HackTheBox, TryHackMe, …)")
@click.option("--difficulty", default=None, help="Difficulty")
@click.option("--notes",      default=None, help="Session notes")
def set_target(ip, host, os_guess, platform, difficulty, notes):
    """Update target information for the current session."""
    session = get_current_session()
    if not session:
        console.print("[bold red]Error:[/] No active session. Run [bold]ctf start <name>[/] first.")
        sys.exit(1)

    updates = {}
    if ip is not None:         updates["target_ip"] = ip
    if host is not None:       updates["target_host"] = host
    if os_guess is not None:   updates["os_guess"] = os_guess
    if platform is not None:   updates["platform"] = platform
    if difficulty is not None: updates["difficulty"] = difficulty
    if notes is not None:      updates["notes"] = notes

    if not updates:
        console.print("[yellow]No fields provided. Use --help to see options.[/]")
        return

    update_session(session.id, **updates)
    console.print(f"[bold green]Session '[cyan]{session.name}[/]' updated.[/]")
    for k, v in updates.items():
        console.print(f"  {k}: [cyan]{v}[/]")


# ---------------------------------------------------------------------------
# ctf config
# ---------------------------------------------------------------------------

@cli.command("config")
def show_config():
    """Show the active configuration (keys are masked)."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key",   style="bold cyan")
    table.add_column("Value", style="white")

    masked_key = ("*" * 8 + config.api_key[-4:]) if len(config.api_key) > 4 else "(not set)"
    masked_nvd = ("*" * 4 + config.nvd_api_key[-4:]) if len(config.nvd_api_key) > 4 else ("(set)" if config.nvd_api_key else "(not set)")
    masked_htb = ("*" * 4 + config.htb_api_key[-4:]) if len(config.htb_api_key) > 4 else ("(set)" if config.htb_api_key else "(not set)")
    table.add_row("api_key",               masked_key)
    table.add_row("ai_model",              config.ai_model)
    table.add_row("ai_max_tokens",         str(config.ai_max_tokens))
    table.add_row("ai_rate_limit_seconds", str(config.ai_rate_limit_seconds))
    table.add_row("ai_backend",            config.ai_backend)
    if config.ai_backend == "ollama":
        table.add_row("ollama_endpoint",   config.ollama_endpoint)
        table.add_row("ollama_model",      config.ollama_model)
    table.add_row("hint_mode",             config.hint_mode)
    table.add_row("offline_mode",          str(config.offline_mode))
    table.add_row("confidence_threshold",  str(config.confidence_threshold))
    table.add_row("dedup_hints",           str(config.dedup_hints))
    table.add_row("nvd_api_key",           masked_nvd)
    table.add_row("htb_api_key",           masked_htb)
    table.add_row("db_path",              config.db_path or "(default)")

    console.print()
    console.print(Panel(table, title="[bold cyan]Active Configuration[/]", border_style="cyan", expand=False))
    console.print(f"\n  Config file: [dim]~/.ctf_copilot/config.yaml[/]")
    console.print()


# ---------------------------------------------------------------------------
# ctf history
# ---------------------------------------------------------------------------

@cli.command("history")
@click.option("--limit",   "-n", default=20,   type=int,  help="Number of commands to show (default 20)")
@click.option("--tool",    "-t", default=None,            help="Filter by tool name (e.g. nmap, gobuster)")
@click.option("--with-output", is_flag=True,              help="Show captured output inline")
def history(limit, tool, with_output):
    """Show recently logged commands for the current session."""
    session = get_current_session()
    if not session:
        console.print(
            "[yellow]No active session.[/] Start one with: [bold]ctf start <name>[/]"
        )
        sys.exit(0)

    commands = get_recent_commands(session.id, limit=limit, tool=tool)
    if not commands:
        msg = "No commands logged yet."
        if tool:
            msg = f"No commands logged for tool '[cyan]{tool}[/]' yet."
        console.print(f"[yellow]{msg}[/]")
        return

    # Summary line
    summary = get_session_summary(session.id)
    tools_str = ", ".join(
        f"{r['tool']}({r['cnt']})" for r in summary["tools_used"]
    ) or "none"
    console.print(
        f"\n  Session [bold cyan]{session.name}[/] - "
        f"{summary['total_commands']} commands | Tools: {tools_str}\n"
    )

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title=f"[bold]Command History[/] (last {len(commands)})",
        expand=True,
    )
    table.add_column("Time",    style="dim",        width=20, no_wrap=True)
    table.add_column("Tool",    style="bold yellow", width=12)
    table.add_column("Exit",    style="dim",         width=5)
    table.add_column("Command", style="white",       ratio=1)

    for cmd in reversed(commands):  # oldest first
        exit_style = "green" if cmd["exit_code"] == 0 else "red"
        exit_str   = f"[{exit_style}]{cmd['exit_code']}[/]"
        tool_str   = cmd["tool"] or "[dim]-[/]"
        cmd_text   = cmd["command"]

        # Truncate long commands for the table
        if len(cmd_text) > 80:
            cmd_text = cmd_text[:77] + "..."

        table.add_row(
            cmd["timestamp"][:19].replace("T", " "),
            tool_str,
            exit_str,
            cmd_text,
        )

    console.print(table)

    # Inline output mode
    if with_output:
        console.print()
        for cmd in reversed(commands):
            if cmd.get("output"):
                console.rule(f"[dim]{cmd['command'][:60]}[/]")
                console.print(cmd["output"], highlight=False)
        console.print()


# ---------------------------------------------------------------------------
# ctf findings
# ---------------------------------------------------------------------------

@cli.command("findings")
@click.option("--services",    "show", flag_value="services",    default=True, help="Show open services (default)")
@click.option("--web",         "show", flag_value="web",                       help="Show web findings only")
@click.option("--creds",       "show", flag_value="creds",                     help="Show credentials only")
@click.option("--all",  "-a",  "show", flag_value="all",                       help="Show all finding types")
def findings(show):
    """Show what has been discovered in the current session."""
    from ctf_copilot.core.database import get_connection

    session = get_current_session()
    if not session:
        console.print("[yellow]No active session.[/] Start one with: [bold]ctf start <name>[/]")
        sys.exit(0)

    with get_connection() as conn:
        svcs  = conn.execute("SELECT * FROM services     WHERE session_id = ? ORDER BY port",      (session.id,)).fetchall()
        webs  = conn.execute("SELECT * FROM web_findings WHERE session_id = ? ORDER BY endpoint",  (session.id,)).fetchall()
        creds = conn.execute("SELECT * FROM credentials  WHERE session_id = ? ORDER BY username",  (session.id,)).fetchall()
        flags = conn.execute("SELECT * FROM flags        WHERE session_id = ? ORDER BY found_at",  (session.id,)).fetchall()

    console.print(f"\n  Session: [bold cyan]{session.name}[/]  |  "
                  f"Target: [cyan]{session.target_ip or session.target_host or '-'}[/]\n")

    # --- Services ---
    if show in ("services", "all"):
        if svcs:
            t = Table(box=box.ROUNDED, header_style="bold cyan",
                      title="[bold]Open Services[/]", show_header=True)
            t.add_column("Port",     width=8)
            t.add_column("Proto",    width=6)
            t.add_column("Service",  width=12)
            t.add_column("Version",  ratio=1)
            t.add_column("Banner",   ratio=1)
            for s in svcs:
                t.add_row(
                    str(s["port"]),
                    s["protocol"],
                    s["service"] or "-",
                    (s["version"] or "-")[:50],
                    (s["banner"] or "-")[:50],
                )
            console.print(t)
        else:
            console.print("[dim]  No services discovered yet. Run nmap first.[/]")
        console.print()

    # --- Web Findings ---
    if show in ("web", "all"):
        if webs:
            t = Table(box=box.ROUNDED, header_style="bold cyan",
                      title="[bold]Web Findings[/]", show_header=True)
            t.add_column("Status", width=8)
            t.add_column("Method", width=7)
            t.add_column("Endpoint", ratio=2)
            t.add_column("Notes",    ratio=1)
            for w in webs:
                code = w["status_code"] or "-"
                code_style = (
                    "green"  if str(code).startswith("2") else
                    "yellow" if str(code).startswith("3") else
                    "red"    if str(code).startswith(("4","5")) else "white"
                )
                t.add_row(
                    f"[{code_style}]{code}[/]",
                    w["method"] or "GET",
                    w["endpoint"],
                    (w["notes"] or "-")[:60],
                )
            console.print(t)
        else:
            console.print("[dim]  No web findings yet. Run gobuster or ffuf.[/]")
        console.print()

    # --- Credentials ---
    if show in ("creds", "all"):
        if creds:
            t = Table(box=box.ROUNDED, header_style="bold cyan",
                      title="[bold]Credentials[/]", show_header=True)
            t.add_column("Username")
            t.add_column("Password")
            t.add_column("Hash")
            t.add_column("Source")
            for c in creds:
                t.add_row(
                    c["username"] or "-",
                    c["password"] or "-",
                    (c["hash"] or "-")[:32],
                    c["source"] or "-",
                )
            console.print(t)
        else:
            console.print("[dim]  No credentials found yet.[/]")
        console.print()

    # --- Flags ---
    if flags:
        for f in flags:
            console.print(f"  [bold green]FLAG ({f['flag_type']}):[/] [bold yellow]{f['flag_value']}[/]")
        console.print()


# ---------------------------------------------------------------------------
# ctf context
# ---------------------------------------------------------------------------

@cli.command("context")
@click.option("--ai-format", is_flag=True, help="Print raw AI prompt block (for debugging)")
def show_context(ai_format):
    """Show the full session intelligence picture — findings, observations, gaps."""
    from ctf_copilot.core.context import build_current_context, format_for_ai

    session = get_current_session()
    if not session:
        console.print("[yellow]No active session.[/] Start one with: [bold]ctf start <name>[/]")
        sys.exit(0)

    ctx = build_current_context()
    if not ctx:
        console.print("[red]Failed to build context.[/]")
        sys.exit(1)

    if ai_format:
        console.print(format_for_ai(ctx))
        return

    # --- Header ---
    console.print()
    console.print(Panel(
        f"[bold]Session:[/] {ctx.session.name}  |  "
        f"[bold]Target:[/] [cyan]{ctx.target}[/]  |  "
        f"[bold]Platform:[/] {ctx.session.platform or '-'}  |  "
        f"[bold]Difficulty:[/] {ctx.session.difficulty or '-'}",
        title="[bold cyan]Session Context[/]",
        border_style="cyan",
        expand=True,
    ))

    # --- Stats bar ---
    console.print(
        f"\n  [bold]{len(ctx.services)}[/] services  |  "
        f"[bold]{len(ctx.web_findings)}[/] web findings  |  "
        f"[bold]{len(ctx.credentials)}[/] credentials  |  "
        f"[bold]{len(ctx.flags)}[/] flags  |  "
        f"[bold]{ctx.command_summary['total']}[/] commands run\n"
    )

    # --- Observations by priority ---
    if ctx.observations:
        # Priority 1 — High
        high = [o for o in ctx.observations if o.priority == 1]
        if high:
            console.print("[bold red]  HIGH PRIORITY[/]")
            for obs in high:
                cve = f" [[dim]{obs.cve}[/]]" if obs.cve else ""
                console.print(f"  [red]![/] [bold]{obs.subject}[/]{cve}")
                console.print(f"    [white]{obs.text}[/]")
            console.print()

        # Priority 2 — Medium
        medium = [o for o in ctx.observations if o.priority == 2]
        if medium:
            console.print("[bold yellow]  MEDIUM PRIORITY[/]")
            for obs in medium:
                cat_badge = f"[dim]{obs.category}[/]"
                console.print(f"  [yellow]*[/] [{cat_badge}] [bold]{obs.subject}[/]")
                console.print(f"    {obs.text}")
            console.print()

        # Priority 3 — Low / Gaps
        low = [o for o in ctx.observations if o.priority == 3]
        if low:
            console.print("[bold dim]  NOTES & GAPS[/]")
            for obs in low:
                console.print(f"  [dim]-[/] {obs.text}")
            console.print()
    else:
        console.print("[dim]  No observations yet — run nmap to start.[/]\n")

    # --- Tools used ---
    if ctx.tools_used:
        console.print(f"  [bold]Tools used:[/] {', '.join(sorted(ctx.tools_used))}")

    # --- Last 3 commands ---
    recent = ctx.command_summary.get("recent", [])[:3]
    if recent:
        console.print(f"  [bold]Recent commands:[/]")
        for r in recent:
            console.print(f"    [dim]{r['timestamp'][:19]}[/]  {r['command'][:70]}")
    console.print()


# ---------------------------------------------------------------------------
# ctf dashboard  (live TUI)
# ---------------------------------------------------------------------------

@cli.command("dashboard")
@click.option(
    "--once", is_flag=True,
    help="Print a one-shot snapshot instead of the live dashboard",
)
@click.option(
    "--interval", "-i", default=4, type=float, show_default=True,
    help="Refresh interval in seconds (live mode only)",
)
@click.option(
    "--session-name", "-s", default=None,
    help="Session to display (default: current active session)",
)
def dashboard(once, interval, session_name):
    """Live TUI dashboard — real-time view of the current session."""
    from ctf_copilot.core.database import get_connection as _gc

    # Resolve session
    target_session = None
    if session_name:
        with _gc() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE name = ? ORDER BY id DESC LIMIT 1",
                (session_name,),
            ).fetchone()
        if not row:
            console.print(f"[bold red]Error:[/] Session '[cyan]{session_name}[/]' not found.")
            sys.exit(1)

        class _S:
            pass
        target_session = _S()
        for k in row.keys():
            setattr(target_session, k, row[k])
    else:
        target_session = get_current_session()
        if not target_session:
            console.print(
                "[bold red]Error:[/] No active session.\n"
                "  Start one with [bold]ctf start <name>[/] "
                "or specify [bold]--session-name <name>[/]."
            )
            sys.exit(1)

    if once:
        from ctf_copilot.interface.dashboard import render_snapshot
        snap = render_snapshot(target_session.id)
        console.print(snap)
        return

    # Live mode
    console.print(
        f"\n  Starting live dashboard for [bold cyan]{target_session.name}[/] "
        f"(refresh every {interval}s)  —  press [bold]q[/] or [bold]Ctrl+C[/] to exit\n"
    )
    time.sleep(0.8)   # brief pause so the user reads the note

    from ctf_copilot.interface.dashboard import run_dashboard
    run_dashboard(session_id=target_session.id, refresh_seconds=interval)
    console.print("\n  [dim]Dashboard closed.[/]\n")


# ---------------------------------------------------------------------------
# ctf parsers
# ---------------------------------------------------------------------------

@cli.command("parsers")
def show_parsers():
    """List all registered tool parsers."""
    from ctf_copilot.parsers.registry import list_parsers
    registered = list_parsers()
    console.print("\n  [bold]Registered parsers:[/]")
    for name in registered:
        console.print(f"    [cyan]{name}[/]")
    console.print()


# ---------------------------------------------------------------------------
# ctf rules  (list pattern rules)
# ---------------------------------------------------------------------------

@cli.command("rules")
@click.option("--tag",    "-t", default=None, help="Filter by tag (e.g. sqli, rce, smb)")
@click.option("--detail", "-d", is_flag=True,  help="Show full hint text for each rule")
@click.option("--reload", "do_reload", is_flag=True, help="Force reload of rule files from disk")
def show_rules(tag, detail, do_reload):
    """List all loaded pattern-match rules."""
    from ctf_copilot.engine.pattern import get_all_rules, reload_rules

    if do_reload:
        count = reload_rules()
        console.print(f"[green]Reloaded {count} rules from disk.[/]\n")

    rules = get_all_rules()
    if not rules:
        console.print("[yellow]No rules loaded.[/] Check [dim]ctf_copilot/rules/*.yaml[/]")
        return

    # Optional tag filter
    if tag:
        tag_lower = tag.lower()
        rules = [r for r in rules if tag_lower in [t.lower() for t in r.get("tags", [])]]
        if not rules:
            console.print(f"[yellow]No rules found with tag '[cyan]{tag}[/]'.[/]")
            return

    console.print(
        f"\n  [bold]{len(rules)} rule(s) loaded[/]"
        + (f" (filtered by tag: [cyan]{tag}[/])" if tag else "")
        + "\n"
    )

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        title="[bold]Pattern Rules[/]",
        expand=True,
    )
    table.add_column("ID",         style="dim",         min_width=20)
    table.add_column("Name",       style="bold white",  ratio=2)
    table.add_column("Confidence", style="cyan",        width=10, justify="right")
    table.add_column("Priority",   width=8,             justify="center")
    table.add_column("Tags",       style="dim yellow",  ratio=1)

    for rule in rules:
        conf = rule.get("confidence", 0.0)
        pri  = rule.get("priority", 2)
        tags = ", ".join(rule.get("tags", []))

        pri_badge = (
            "[bold red]HIGH[/]"   if pri == 1 else
            "[bold yellow]MED[/]" if pri == 2 else
            "[dim]LOW[/]"
        )

        table.add_row(
            rule.get("id", ""),
            rule.get("name", ""),
            f"{conf:.0%}",
            pri_badge,
            tags,
        )

    console.print(table)

    if detail:
        console.print()
        for rule in rules:
            hint = (rule.get("hint") or "").strip()
            if hint:
                console.print(Panel(
                    hint,
                    title=f"[bold yellow]{rule.get('id', '')}[/]",
                    border_style="yellow",
                    expand=False,
                ))
                console.print()
    else:
        console.print(
            f"\n  Use [bold]ctf rules --detail[/] to show full hint text for each rule.\n"
        )


# ---------------------------------------------------------------------------
# ctf hint  (on-demand AI hint)
# ---------------------------------------------------------------------------

@cli.command("hint")
@click.option("--context", "show_ctx", is_flag=True, help="Also print the context block sent to the AI")
def request_hint(show_ctx):
    """Request an AI hint right now, bypassing the rate limiter."""
    from ctf_copilot.engine.ai import generate_hint
    from ctf_copilot.interface.display import show_hint

    session = get_current_session()
    if not session:
        console.print("[yellow]No active session.[/] Start one with: [bold]ctf start <name>[/]")
        sys.exit(0)

    if show_ctx:
        from ctf_copilot.core.context import build_context, format_for_ai
        ctx = build_context(session.id)
        if ctx:
            console.print("\n[bold dim]Context block sent to AI:[/]")
            console.print(format_for_ai(ctx))
            console.print()

    console.print("[dim]Asking Claude...[/]")
    hint = generate_hint(
        session_id=session.id,
        trigger_command="",
        force=True,          # bypass rate limit for manual requests
    )

    if hint.skipped:
        if "no API key" in hint.skip_reason:
            console.print(
                f"\n[yellow]No API key configured.[/]\n"
                f"  Add your Anthropic API key to [bold]~/.ctf_copilot/config.yaml[/]:\n"
                f"  [bold]api_key: \"sk-ant-...\"[/]\n"
            )
        elif "no data yet" in hint.skip_reason:
            console.print(
                f"\n[yellow]Not enough data yet.[/] Run nmap first, then try again.\n"
            )
        else:
            console.print(f"\n[yellow]Hint skipped:[/] {hint.skip_reason}\n")
        sys.exit(0)

    show_hint(hint.text, source=hint.source, confidence=hint.confidence)


# ---------------------------------------------------------------------------
# ctf hints  (hint history)
# ---------------------------------------------------------------------------

@cli.command("hints")
@click.option("--limit", "-n", default=10, type=int, help="Number of hints to show")
def hint_history(limit):
    """Show hint history for the current session."""
    from ctf_copilot.engine.hints import get_recent_hints

    session = get_current_session()
    if not session:
        console.print("[yellow]No active session.[/]")
        sys.exit(0)

    hints = get_recent_hints(session.id, limit=limit)
    if not hints:
        console.print(
            "\n[dim]No hints yet.[/] Run a tool or use [bold]ctf hint[/] to generate one.\n"
        )
        return

    console.print(f"\n  [bold]Hint history[/] — session [cyan]{session.name}[/]\n")
    for i, h in enumerate(reversed(hints), 1):
        source_badge = (
            "[cyan][AI][/]" if h["source"] == "ai" else "[yellow][Rule][/]"
        )
        ts = h["timestamp"][:16].replace("T", " ")
        conf = f"  [dim]{h['confidence']:.0%}[/]" if h.get("confidence") else ""
        console.print(f"  [dim]{i:2}.[/] {source_badge} [dim]{ts}[/]{conf}")
        console.print(f"      {h['hint_text']}\n")


# ---------------------------------------------------------------------------
# ctf writeup  (session writeup generator)
# ---------------------------------------------------------------------------

@cli.command("writeup")
@click.option(
    "--session-name", "-s", default=None,
    help="Session name to generate writeup for (default: current session)",
)
@click.option(
    "--output", "-o", default=None,
    help="Output file path (default: ~/ctf_writeups/<name>_writeup.md)",
)
@click.option(
    "--no-ai", "no_ai", is_flag=True,
    help="Skip AI narrative generation (offline / free mode)",
)
@click.option(
    "--stdout", "to_stdout", is_flag=True,
    help="Print Markdown to stdout instead of saving to a file",
)
def writeup(session_name, output, no_ai, to_stdout):
    """Generate a Markdown writeup for a CTF session."""
    from ctf_copilot.engine.writeup import generate_writeup
    from ctf_copilot.core.database import get_connection

    # Resolve which session to use
    target_session = None
    if session_name:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE name = ? ORDER BY id DESC LIMIT 1",
                (session_name,),
            ).fetchone()
        if not row:
            console.print(f"[bold red]Error:[/] Session '[cyan]{session_name}[/]' not found.")
            sys.exit(1)
        # Convert row to a simple namespace for attribute access
        class _S:
            pass
        target_session = _S()
        for k in row.keys():
            setattr(target_session, k, row[k])
    else:
        target_session = get_current_session()
        if not target_session:
            console.print(
                "[bold red]Error:[/] No active session.\n"
                "  Specify one with [bold]--session-name <name>[/] or start a session first."
            )
            sys.exit(1)

    use_ai = not no_ai
    if use_ai and not config.api_key:
        console.print(
            "[yellow]No API key configured — generating offline writeup.[/]\n"
            "  To enable the AI narrative, add your key to [dim]~/.ctf_copilot/config.yaml[/]"
        )
        use_ai = False

    ai_label = "[cyan]AI-enhanced[/]" if use_ai else "[dim]offline[/]"
    console.print(
        f"\n  Generating {ai_label} writeup for session "
        f"[bold cyan]{target_session.name}[/]..."
    )

    try:
        result = generate_writeup(session_id=target_session.id, use_ai=use_ai)
    except Exception as exc:
        console.print(f"[bold red]Error generating writeup:[/] {exc}")
        sys.exit(1)

    if to_stdout:
        # Print raw Markdown to stdout (pipe-friendly)
        sys.stdout.write(result.markdown)
        sys.stdout.flush()
        return

    # Save to file
    try:
        dest = result.save(output_path=output)
    except Exception as exc:
        console.print(f"[bold red]Error saving writeup:[/] {exc}")
        sys.exit(1)

    ai_note = (
        " with AI-generated Attack Path narrative" if result.ai_enhanced
        else " (offline — no AI narrative)"
    )

    console.print(
        Panel(
            f"[bold green]Writeup saved![/]{ai_note}\n\n"
            f"  [bold]File:[/] [cyan]{dest}[/]\n\n"
            f"  Open it in any Markdown viewer, or push it to GitHub Gist:\n"
            f"  [dim]gh gist create {dest} --public[/]",
            title="[bold cyan]CTF Writeup Generated[/]",
            border_style="cyan",
            expand=False,
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# ctf searchsploit  (manual ExploitDB search)
# ---------------------------------------------------------------------------

@cli.command("searchsploit")
@click.argument("query", nargs=-1, required=True)
@click.option("--limit", "-n", default=10, type=int, show_default=True,
              help="Maximum number of results to show")
def run_searchsploit(query, limit):
    """Search ExploitDB via searchsploit for a given query.

    \b
    Examples:
      ctf searchsploit vsftpd 2.3.4
      ctf searchsploit apache 2.4.49
      ctf searchsploit samba smb
    """
    from ctf_copilot.parsers.searchsploit_parser import (
        run_searchsploit as _run, is_searchsploit_available,
    )

    if not is_searchsploit_available():
        console.print(
            "[bold red]searchsploit not found.[/]\n"
            "  Install exploitdb: [dim]sudo apt install exploitdb[/]\n"
            "  Or on Kali it's pre-installed."
        )
        sys.exit(1)

    query_str = " ".join(query)
    console.print(f"\n  Searching ExploitDB for: [bold cyan]{query_str}[/]\n")

    results = _run(query_str)
    if not results:
        console.print(f"[dim]  No results found for '{query_str}'.[/]\n")
        return

    results = results[:limit]
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        title=f"[bold]ExploitDB Results[/] ({len(results)} found)",
        expand=True,
    )
    table.add_column("#",       style="dim",          width=4)
    table.add_column("Entry",   style="bold white",   ratio=1)

    for i, entry in enumerate(results, 1):
        table.add_row(str(i), entry)

    console.print(table)
    console.print()

    # Optionally save to current session hints
    session = get_current_session()
    if session:
        from ctf_copilot.engine.hints import save_hint, is_duplicate
        saved = 0
        for entry in results[:5]:
            hint_text = f"[ExploitDB] {entry}"
            if not is_duplicate(session.id, hint_text):
                save_hint(
                    session_id=session.id,
                    hint_text=hint_text,
                    source="searchsploit",
                    confidence=0.80,
                )
                saved += 1
        if saved:
            console.print(
                f"  [dim]{saved} result(s) saved to session hints.[/]\n"
            )


# ---------------------------------------------------------------------------
# ctf timeline  (attack technique timeline)
# ---------------------------------------------------------------------------

@cli.command("timeline")
@click.option("--session-name", "-s", default=None,
              help="Session to display (default: current active session)")
@click.option("--limit", "-n", default=50, type=int, show_default=True,
              help="Max commands to show")
def timeline(session_name, limit):
    """Show a chronological attack timeline for the current session.

    Displays commands grouped by tool, with timestamps and exit codes,
    interleaved with hints received at each stage.
    """
    from ctf_copilot.core.database import get_connection
    from rich.tree import Tree

    # Resolve session
    target_session = None
    if session_name:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE name = ? ORDER BY id DESC LIMIT 1",
                (session_name,),
            ).fetchone()
        if not row:
            console.print(f"[bold red]Error:[/] Session '[cyan]{session_name}[/]' not found.")
            sys.exit(1)
        class _S: pass
        target_session = _S()
        for k in row.keys():
            setattr(target_session, k, row[k])
    else:
        target_session = get_current_session()
        if not target_session:
            console.print(
                "[bold red]Error:[/] No active session.\n"
                "  Start one with [bold]ctf start <name>[/]."
            )
            sys.exit(1)

    with get_connection() as conn:
        commands = conn.execute(
            """
            SELECT id, command, tool, exit_code, timestamp
            FROM commands
            WHERE session_id = ?
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            (target_session.id, limit),
        ).fetchall()

        hints = conn.execute(
            """
            SELECT command_id, hint_text, source, confidence, timestamp
            FROM hints
            WHERE session_id = ?
            ORDER BY timestamp ASC
            """,
            (target_session.id,),
        ).fetchall()

    if not commands:
        console.print(
            f"\n[dim]  No commands logged yet for session "
            f"'[cyan]{target_session.name}[/]'.[/]\n"
        )
        return

    # Build hint index: command_id -> list of hints
    hint_map: dict[int, list] = {}
    for h in hints:
        cid = h["command_id"]
        if cid not in hint_map:
            hint_map[cid] = []
        hint_map[cid].append(h)

    # Also collect hints not linked to any command (command_id IS NULL)
    unlinked_hints = [h for h in hints if h["command_id"] is None]

    console.print()
    console.print(Panel(
        f"[bold]Session:[/] {target_session.name}  |  "
        f"[bold]Target:[/] [cyan]{getattr(target_session, 'target_ip', '') or '-'}[/]  |  "
        f"[bold]{len(commands)}[/] commands  |  [bold]{len(hints)}[/] hints",
        title="[bold cyan]Attack Timeline[/]",
        border_style="cyan",
        expand=True,
    ))
    console.print()

    tree = Tree(
        f"[bold cyan]{target_session.name}[/]  "
        f"[dim]{getattr(target_session, 'started_at', '')[:19]}[/]"
    )

    for cmd in commands:
        ts        = (cmd["timestamp"] or "")[:19].replace("T", " ")
        tool      = cmd["tool"] or "?"
        cmd_text  = cmd["command"]
        if len(cmd_text) > 70:
            cmd_text = cmd_text[:67] + "..."
        exit_code = cmd["exit_code"]
        exit_style = "green" if exit_code == 0 else "red"

        cmd_node = tree.add(
            f"[dim]{ts}[/]  [bold yellow]{tool}[/]  "
            f"[{exit_style}](exit {exit_code})[/]\n"
            f"       [white]{cmd_text}[/]"
        )

        # Attach hints to this command
        for h in hint_map.get(cmd["id"], []):
            source_badge = {
                "ai":           "[cyan][AI][/]",
                "ollama":       "[cyan][Ollama][/]",
                "pattern":      "[yellow][Rule][/]",
                "nvd":          "[red][NVD][/]",
                "searchsploit": "[magenta][ExploitDB][/]",
            }.get(h["source"], "[dim][?][/]")
            hint_preview = h["hint_text"]
            if len(hint_preview) > 80:
                hint_preview = hint_preview[:77] + "..."
            cmd_node.add(
                f"  {source_badge} [dim]{hint_preview}[/]"
            )

    # Show unlinked hints at the end
    if unlinked_hints:
        unlinked = tree.add("[dim]Hints (unlinked)[/]")
        for h in unlinked_hints:
            source_badge = {
                "ai": "[cyan][AI][/]", "ollama": "[cyan][Ollama][/]",
                "pattern": "[yellow][Rule][/]",
            }.get(h["source"], "[dim][?][/]")
            unlinked.add(f"  {source_badge} [dim]{h['hint_text'][:80]}[/]")

    console.print(tree)
    console.print()
