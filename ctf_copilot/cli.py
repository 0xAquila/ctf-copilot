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
        title="[bold magenta]CTF Copilot — Session[/]",
        border_style="magenta",
        expand=False,
    ))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """CTF Copilot — your AI-assisted penetration testing companion.\n
    Start a session, run your tools as usual, and get real-time hints.
    Run [bold]ctf[/] with no arguments to open the interactive menu.
    """
    write_default_config()
    init_db()

    # Launch interactive REPL when called with no subcommand
    if ctx.invoked_subcommand is None:
        from ctf_copilot.interface.repl import run_repl
        run_repl()
        return

    # First-run nudge: show once when no key is configured for the active backend
    # (skip for `ctf setup` itself so the wizard isn't double-prompted)
    if ctx.invoked_subcommand != "setup":
        backend = config.ai_backend
        missing = False
        if backend == "claude" and not config.api_key:
            missing = True
        elif backend == "groq" and not config.groq_api_key:
            missing = True

        if missing and not config.offline_mode:
            console.print(
                f"\n  [dim]No API key configured for [bold]{backend}[/] backend. "
                "Run [bold magenta]ctf setup[/] to get started.[/]\n"
            )


# ---------------------------------------------------------------------------
# ctf setup
# ---------------------------------------------------------------------------

@cli.command("setup")
def setup():
    """Interactive wizard to configure your AI provider (Claude, Groq, Ollama)."""
    from ctf_copilot.interface.setup_wizard import run_setup_wizard
    run_setup_wizard()


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
    console.print(f"[bold yellow]Session '[yellow]{session.name}[/]' paused.[/]")
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
        f"[bold green]Session '[yellow]{session.name}[/]' completed! Well done.[/]\n\n"
        f"  Generate your writeup now:\n"
        f"  [bold]ctf writeup[/]                  - AI-enhanced Markdown writeup\n"
        f"  [bold]ctf writeup --no-ai[/]           - Offline writeup (no API cost)\n"
        f"  [bold]ctf writeup --stdout | less[/]   - Preview in terminal",
        title="[bold magenta]Session Complete[/]",
        border_style="green",
        expand=False,
    ))


# ---------------------------------------------------------------------------
# ctf status
# ---------------------------------------------------------------------------

@cli.command()
def status():
    """Show the current active session details."""
    from ctf_copilot.core.database import get_connection as _gc
    from ctf_copilot.core.notes import note_count as _note_count

    session = get_current_session()
    if not session:
        console.print(Panel(
            "\n  No active session.\n\n"
            "  [bold]ctf start <name> --ip <target>[/]   — start a new session\n"
            "  [bold]ctf sessions[/]                     — list saved sessions\n"
            "  [bold]ctf resume <name>[/]                — resume a paused session\n",
            title="[bold yellow]No Active Session[/]",
            border_style="yellow",
            box=box.ROUNDED,
            expand=False,
        ))
        sys.exit(0)

    # Fetch session stats
    with _gc() as conn:
        svc_cnt  = conn.execute("SELECT COUNT(*) AS n FROM services  WHERE session_id=?", (session.id,)).fetchone()["n"]
        web_cnt  = conn.execute("SELECT COUNT(*) AS n FROM web_findings WHERE session_id=?", (session.id,)).fetchone()["n"]
        cmd_cnt  = conn.execute("SELECT COUNT(*) AS n FROM commands   WHERE session_id=?", (session.id,)).fetchone()["n"]
        hint_cnt = conn.execute("SELECT COUNT(*) AS n FROM hints      WHERE session_id=?", (session.id,)).fetchone()["n"]
        cred_cnt = conn.execute("SELECT COUNT(*) AS n FROM credentials WHERE session_id=?", (session.id,)).fetchone()["n"]
        flag_cnt = conn.execute("SELECT COUNT(*) AS n FROM flags      WHERE session_id=?", (session.id,)).fetchone()["n"]
    n_cnt = _note_count(session.id)

    status_icon = {"active": "🟢", "paused": "🟡", "completed": "✅"}.get(session.status, "⬜")

    lines = [
        f"  {status_icon}  [bold white]{session.name}[/]   {_status_badge(session.status)}",
        "",
        f"  [bold dim]Target:[/]      [yellow]{session.target_ip or session.target_host or '—'}[/]"
        + (f"  [dim]({session.target_host})[/]" if session.target_ip and session.target_host else ""),
        f"  [bold dim]Platform:[/]    {session.platform or '—'}",
        f"  [bold dim]Difficulty:[/]  {session.difficulty or '—'}",
        f"  [bold dim]OS Guess:[/]    {session.os_guess or '—'}",
        f"  [bold dim]Started:[/]     {(session.started_at or '')[:16].replace('T', ' ')}",
        "",
        "  ──────────────── Intel ─────────────────",
        f"  Services [yellow]{svc_cnt:>4}[/]    Web findings [magenta]{web_cnt:>4}[/]",
        f"  Commands  [dim]{cmd_cnt:>4}[/]    AI hints      [yellow]{hint_cnt:>4}[/]",
        f"  Creds     [dim]{cred_cnt:>4}[/]    Notes         [blue]{n_cnt:>4}[/]",
        f"  Flags   [bold green]{flag_cnt:>6}[/]",
    ]
    if session.notes:
        lines += ["", f"  [bold dim]Notes:[/]  [dim]{session.notes[:80]}[/]"]

    console.print()
    console.print(Panel(
        "\n".join(lines),
        title="[bold magenta]Active Session[/]",
        border_style="magenta",
        box=box.DOUBLE_EDGE,
        expand=False,
    ))
    console.print(
        f"\n  [dim]Dashboard:[/] [bold]ctf dashboard[/]   "
        f"[dim]Notes:[/] [bold]ctf notes[/]   "
        f"[dim]Hint:[/] [bold]ctf hint[/]\n"
    )


# ---------------------------------------------------------------------------
# ctf sessions
# ---------------------------------------------------------------------------

@cli.command("sessions")
def sessions_list():
    """List all CTF sessions with stats."""
    from ctf_copilot.core.database import get_connection as _gc

    sessions = list_sessions()
    if not sessions:
        console.print(Panel(
            "\n  No sessions yet.\n\n"
            "  Start your first session:\n"
            "  [bold magenta]ctf start <machine-name> --ip <target-ip>[/]\n",
            title="[bold magenta]CTF Sessions[/]",
            border_style="magenta",
            box=box.ROUNDED,
            expand=False,
        ))
        return

    current    = get_current_session()
    current_id = current.id if current else None

    # Fetch stats per session in one query
    session_ids = [s.id for s in sessions]
    with _gc() as conn:
        stats_rows = conn.execute(
            f"""
            SELECT session_id,
                   COUNT(DISTINCT c.id)   AS cmd_count,
                   COUNT(DISTINCT sv.id)  AS svc_count,
                   COUNT(DISTINCT h.id)   AS hint_count,
                   COUNT(DISTINCT n.id)   AS note_count,
                   COUNT(DISTINCT f.id)   AS flag_count
            FROM sessions s
            LEFT JOIN commands c     ON c.session_id = s.id
            LEFT JOIN services sv    ON sv.session_id = s.id
            LEFT JOIN hints h        ON h.session_id = s.id
            LEFT JOIN session_notes n ON n.session_id = s.id
            LEFT JOIN flags f        ON f.session_id = s.id
            WHERE s.id IN ({','.join('?' for _ in session_ids)})
            GROUP BY s.id
            """,
            session_ids,
        ).fetchall()
    stats = {r["session_id"]: dict(r) for r in stats_rows}

    _PLATFORM_ICON = {
        "hackthebox": "🟢", "htb": "🟢",
        "tryhackme": "🔴",  "thm": "🔴",
        "ctf": "🏆",
        "vulnhub": "🔷",
    }
    _DIFF_COLOR = {
        "easy":   "green",
        "medium": "yellow",
        "hard":   "red",
        "insane": "bold red",
    }

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        title="[bold magenta]CTF Sessions[/]",
        title_justify="left",
        caption=f"[dim]{len(sessions)} session(s)  •  ctf start <name> to begin[/]",
        caption_justify="right",
        padding=(0, 1),
    )
    table.add_column("",          width=2,  no_wrap=True)   # current marker
    table.add_column("Name",      style="bold white", min_width=18)
    table.add_column("Status",    min_width=10)
    table.add_column("Target",    style="yellow",        min_width=14)
    table.add_column("Platform",  min_width=12)
    table.add_column("Diff",      width=8)
    table.add_column("Cmds",      style="dim",   width=5,  justify="right")
    table.add_column("Svcs",      style="yellow",width=5,  justify="right")
    table.add_column("Hints",     style="yellow",  width=6,  justify="right")
    table.add_column("Notes",     style="blue",  width=6,  justify="right")
    table.add_column("Flags",     style="green", width=6,  justify="right")
    table.add_column("Started",   style="dim",   min_width=11)

    for s in sessions:
        is_active = (s.id == current_id)
        marker    = "[bold green]▶[/]" if is_active else " "

        plat_key  = (s.platform or "").lower()
        plat_icon = _PLATFORM_ICON.get(plat_key, "⬜")
        plat_str  = f"{plat_icon} {s.platform}" if s.platform else "—"

        diff_key  = (s.difficulty or "").lower()
        diff_col  = _DIFF_COLOR.get(diff_key, "white")
        diff_str  = f"[{diff_col}]{s.difficulty}[/]" if s.difficulty else "—"

        target    = s.target_ip or s.target_host or "—"
        date_str  = (s.started_at or "")[:10]

        st = stats.get(s.id, {})
        flags_val = st.get("flag_count", 0)
        flag_disp = f"[bold green]{flags_val}[/]" if flags_val else str(flags_val)

        table.add_row(
            marker,
            s.name,
            _status_badge(s.status),
            target,
            plat_str,
            diff_str,
            str(st.get("cmd_count", 0)),
            str(st.get("svc_count", 0)),
            str(st.get("hint_count", 0)),
            str(st.get("note_count", 0)),
            flag_disp,
            date_str,
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
    console.print(f"[bold green]Session '[yellow]{session.name}[/]' updated.[/]")
    for k, v in updates.items():
        console.print(f"  {k}: [yellow]{v}[/]")


# ---------------------------------------------------------------------------
# ctf config
# ---------------------------------------------------------------------------

@cli.command("config")
def show_config():
    """Show the active configuration (keys are masked)."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key",   style="bold magenta")
    table.add_column("Value", style="white")

    def _mask(key: str, prefix_len: int = 8) -> str:
        return ("*" * prefix_len + key[-4:]) if len(key) > 4 else ("(set)" if key else "(not set)")

    masked_key  = _mask(config.api_key)
    masked_groq = _mask(config.groq_api_key)
    masked_nvd  = _mask(config.nvd_api_key, 4)
    masked_htb  = _mask(config.htb_api_key, 4)

    # Backend badge
    _backend_color = {"claude": "magenta", "groq": "green", "ollama": "yellow"}.get(config.ai_backend, "dim")
    backend_display = f"[bold {_backend_color}]{config.ai_backend}[/]"

    table.add_row("ai_backend",            backend_display)
    table.add_row("", "")   # spacer

    table.add_row("[dim]── Claude ──[/]",  "")
    table.add_row("api_key",               masked_key)
    table.add_row("ai_model",              config.ai_model)

    table.add_row("", "")
    table.add_row("[dim]── Groq ──[/]",    "")
    table.add_row("groq_api_key",          masked_groq)
    table.add_row("groq_model",            config.groq_model)

    table.add_row("", "")
    table.add_row("[dim]── Ollama ──[/]",  "")
    table.add_row("ollama_endpoint",       config.ollama_endpoint)
    table.add_row("ollama_model",          config.ollama_model)

    table.add_row("", "")
    table.add_row("[dim]── General ──[/]", "")
    table.add_row("ai_max_tokens",         str(config.ai_max_tokens))
    table.add_row("ai_rate_limit_seconds", str(config.ai_rate_limit_seconds))
    table.add_row("hint_mode",             config.hint_mode)
    table.add_row("offline_mode",          str(config.offline_mode))
    table.add_row("confidence_threshold",  str(config.confidence_threshold))
    table.add_row("dedup_hints",           str(config.dedup_hints))
    table.add_row("nvd_api_key",           masked_nvd)
    table.add_row("htb_api_key",           masked_htb)
    table.add_row("db_path",               config.db_path or "(default)")

    from ctf_copilot.core.keyring import keyring_exists, keyring_path
    enc_status = (
        f"[bold green]🔐  Enabled[/]  [dim](keyring: {keyring_path()})[/]"
        if keyring_exists()
        else "[yellow]⚠  Not yet active[/]  [dim](run ctf setup to configure)[/]"
    )

    console.print()
    console.print(Panel(
        table,
        title="[bold magenta]Active Configuration[/]",
        border_style="magenta",
        expand=False,
    ))
    console.print(f"\n  Encryption:  {enc_status}")
    console.print(f"  Config file: [dim]~/.ctf_copilot/config.yaml[/]")
    console.print(f"  Reconfigure: [bold magenta]ctf setup[/]")
    console.print()


# ---------------------------------------------------------------------------
# ctf note  / ctf notes
# ---------------------------------------------------------------------------

@cli.command("note")
@click.argument("text", required=False)
@click.option("--list",   "-l", "show_list", is_flag=True,  help="List all notes for the current session")
@click.option("--delete", "-d", "delete_id", type=int, default=None, metavar="ID", help="Delete note by ID")
@click.option("--pin",    "-p", "pin_id",    type=int, default=None, metavar="ID", help="Toggle pin on a note")
@click.option("--tag",    "-t", default="",  help="Comma-separated tags (e.g. web,sqli)")
def note(text, show_list, delete_id, pin_id, tag):
    """Add a tactical note to the current session.

    Notes are shown in the dashboard and injected into AI hints so the
    copilot knows about your observations, dead-ends, and hypotheses.

    \b
    Examples:
      ctf note "Tried anon FTP — Access denied"
      ctf note --tag web,sqli "SQL error on apostrophe at /login"
      ctf note --pin 2
      ctf note --delete 3
      ctf note --list
    """
    from ctf_copilot.core.notes import (
        add_note as _add, get_notes as _get,
        delete_note as _del, pin_note as _pin, note_count as _cnt
    )

    session = get_current_session()
    if not session:
        console.print("[yellow]No active session.[/] Start one with: [bold]ctf start <name>[/]")
        sys.exit(1)

    # ── delete ────────────────────────────────────────────────────────────
    if delete_id is not None:
        if _del(session.id, delete_id):
            console.print(f"  [bold green]✓[/]  Note [bold]#{delete_id}[/] deleted.")
        else:
            console.print(f"  [red]Note #{delete_id} not found in this session.[/]")
        return

    # ── pin toggle ────────────────────────────────────────────────────────
    if pin_id is not None:
        new_state = _pin(session.id, pin_id)
        label = "📌 Pinned" if new_state else "Unpinned"
        console.print(f"  [bold cyan]✓[/]  {label} note [bold]#{pin_id}[/].")
        return

    # ── list mode ─────────────────────────────────────────────────────────
    if show_list or not text:
        _print_notes(session.id)
        return

    # ── add mode ──────────────────────────────────────────────────────────
    note_id = _add(session.id, text.strip(), tags=tag)
    total   = _cnt(session.id)
    console.print(
        f"\n  [bold blue]✓[/]  Note [bold]#{note_id}[/] saved."
        + (f"  [dim]Tags: {tag}[/]" if tag else "")
        + f"  [dim]({total} total)[/]\n"
        + "  [dim]It will be included in the next AI hint context.[/]\n"
    )


def _print_notes(session_id: int) -> None:
    """Render a formatted notes list for a session."""
    from ctf_copilot.core.notes import get_notes as _get

    notes = _get(session_id)
    if not notes:
        console.print(Panel(
            "\n  No notes yet.\n\n"
            "  [bold]ctf note \"your observation\"[/]\n"
            "  [bold]ctf note --tag web,sqli \"SQL error at /login\"[/]\n",
            title="[bold blue]Session Notes[/]",
            border_style="blue",
            box=box.ROUNDED,
            expand=False,
        ))
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold blue",
        title=f"[bold blue]Session Notes[/] [dim]({len(notes)})[/]",
        expand=False,
        padding=(0, 1),
    )
    table.add_column("ID",    style="bold blue",   width=4)
    table.add_column("📌",    width=2)
    table.add_column("Note",  style="white",        ratio=1)
    table.add_column("Tags",  style="dim",          width=18)
    table.add_column("Added", style="dim",          width=14, no_wrap=True)

    for n in notes:
        pin_icon = "📌" if n.get("pinned") else ""
        ts       = (n.get("created_at") or "")[:16].replace("T", " ")[5:]
        tags     = n.get("tags") or ""
        table.add_row(str(n["id"]), pin_icon, n["text"], tags, ts)

    console.print()
    console.print(table)
    console.print(
        "\n  [dim]Delete:[/] [bold]ctf note --delete <id>[/]   "
        "[dim]Pin:[/] [bold]ctf note --pin <id>[/]\n"
    )


@cli.command("notes")
def notes_list():
    """List all tactical notes for the current session."""
    session = get_current_session()
    if not session:
        console.print("[yellow]No active session.[/] Start one with: [bold]ctf start <name>[/]")
        sys.exit(0)
    _print_notes(session.id)


# ---------------------------------------------------------------------------
# ctf vault
# ---------------------------------------------------------------------------

@cli.group("vault")
def vault_group():
    """Manage cross-session knowledge vaults.

    Vaults are named, persistent collections of notes that live outside
    individual CTF sessions.  Build a personal knowledge base over time:
    'Web Techniques', 'Active Directory', 'Buffer Overflow', etc.

    \b
    Commands:
      ctf vault                        List all vaults
      ctf vault new "Web Techniques"   Create a vault
      ctf vault open "Web Techniques"  Enter interactive REPL
      ctf vault show "Web Techniques"  Display entries (non-interactive)
      ctf vault add  "Web Techniques" "SQLi: ' OR 1=1 --"
      ctf vault rm   "Web Techniques"  Delete a vault
    """


@vault_group.command("list")
def vault_list_cmd():
    """List all knowledge vaults."""
    from ctf_copilot.core.vault import list_vaults as _list

    vaults = _list()
    if not vaults:
        console.print(Panel(
            "\n  No vaults yet.\n\n"
            "  Create one:\n"
            "  [bold magenta]ctf vault new \"Web Techniques\"[/]\n"
            "  [bold magenta]ctf vault new \"Active Directory\"[/]\n",
            title="[bold magenta]Knowledge Vaults[/]",
            border_style="magenta",
            box=box.ROUNDED,
            expand=False,
        ))
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        title="[bold magenta]Knowledge Vaults[/]",
        caption="[dim]ctf vault open <name> — enter a vault[/]",
        padding=(0, 1),
    )
    table.add_column("#",           style="dim",        width=4)
    table.add_column("Vault",       style="bold white", min_width=20)
    table.add_column("Description", style="dim",        ratio=1)
    table.add_column("Entries",     style="yellow",       width=8,  justify="right")
    table.add_column("Updated",     style="dim",        width=12, no_wrap=True)

    for v in vaults:
        color    = v.get("color", "cyan")
        updated  = (v.get("updated_at") or "")[:10]
        icon_str = f"[{color}]●[/]  {v['name']}"
        table.add_row(
            str(v["id"]),
            icon_str,
            v.get("description") or "",
            str(v.get("entry_count", 0)),
            updated,
        )

    console.print()
    console.print(table)
    console.print()


@vault_group.command("new")
@click.argument("name")
@click.option("--description", "-d", default="", help="Short description")
def vault_new(name, description):
    """Create a new knowledge vault named NAME."""
    from ctf_copilot.core.vault import create_vault

    try:
        v = create_vault(name, description=description)
    except ValueError as exc:
        console.print(f"  [bold red]Error:[/] {exc}")
        sys.exit(1)

    color = v.get("color", "cyan")
    console.print(Panel(
        f"\n  [{color}]●[/]  [bold]{v['name']}[/]\n"
        + (f"  [dim]{description}[/]\n" if description else "")
        + f"\n  Open it now:  [bold magenta]ctf vault open \"{v['name']}\"[/]\n",
        title=f"[bold {color}]Vault Created[/]",
        border_style=color,
        box=box.ROUNDED,
        expand=False,
    ))


@vault_group.command("open")
@click.argument("name")
def vault_open(name):
    """Enter the interactive REPL for vault NAME."""
    from ctf_copilot.core.vault import run_vault_repl
    run_vault_repl(name)


@vault_group.command("show")
@click.argument("name")
def vault_show(name):
    """Display all entries in vault NAME (non-interactive)."""
    from ctf_copilot.core.vault import get_vault, get_entries, _render_entries

    v = get_vault(name)
    if not v:
        console.print(f"  [red]Vault '[bold]{name}[/]' not found.[/]")
        sys.exit(1)

    entries = get_entries(v["id"])
    color   = v.get("color", "cyan")
    desc    = v.get("description") or ""

    console.print()
    console.print(Panel(
        f"  [bold {color}]📚  {v['name']}[/]"
        + (f"\n  [dim]{desc}[/]" if desc else "")
        + f"\n  [dim]{len(entries)} entries[/]",
        border_style=color,
        box=box.ROUNDED,
        expand=False,
    ))
    console.print()
    _render_entries(entries, color)
    console.print()


@vault_group.command("add")
@click.argument("name")
@click.argument("text")
@click.option("--tag", "-t", default="", help="Comma-separated tags")
def vault_add(name, text, tag):
    """Quick-add an entry to vault NAME."""
    from ctf_copilot.core.vault import get_vault, add_entry

    v = get_vault(name)
    if not v:
        console.print(f"  [red]Vault '[bold]{name}[/]' not found.[/]")
        sys.exit(1)

    eid = add_entry(v["id"], text, tags=tag)
    console.print(
        f"  [bold green]✓[/]  Entry [bold]#{eid}[/] added to vault [bold]{name}[/]."
        + (f"  [dim]Tags: {tag}[/]" if tag else "")
    )


@vault_group.command("rm")
@click.argument("name")
@click.confirmation_option(prompt="Delete this vault and all its entries?")
def vault_rm(name):
    """Delete vault NAME and all its entries."""
    from ctf_copilot.core.vault import delete_vault

    if delete_vault(name):
        console.print(f"  [bold green]✓[/]  Vault [bold]{name}[/] deleted.")
    else:
        console.print(f"  [red]Vault '[bold]{name}[/]' not found.[/]")


# Add `ctf vault` as an alias that shows the list when called bare
@cli.command("vault", hidden=True)
def vault_bare():
    """Alias: list all knowledge vaults (same as `ctf vault list`)."""
    from click import get_current_context
    ctx = get_current_context()
    ctx.invoke(vault_list_cmd)


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
            msg = f"No commands logged for tool '[yellow]{tool}[/]' yet."
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
        header_style="bold magenta",
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
                  f"Target: [yellow]{session.target_ip or session.target_host or '-'}[/]\n")

    # --- Services ---
    if show in ("services", "all"):
        if svcs:
            t = Table(box=box.ROUNDED, header_style="bold magenta",
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
            t = Table(box=box.ROUNDED, header_style="bold magenta",
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
            t = Table(box=box.ROUNDED, header_style="bold magenta",
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
        f"[bold]Target:[/] [yellow]{ctx.target}[/]  |  "
        f"[bold]Platform:[/] {ctx.session.platform or '-'}  |  "
        f"[bold]Difficulty:[/] {ctx.session.difficulty or '-'}",
        title="[bold magenta]Session Context[/]",
        border_style="magenta",
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
            console.print(f"[bold red]Error:[/] Session '[yellow]{session_name}[/]' not found.")
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
        console.print(f"    [yellow]{name}[/]")
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
            console.print(f"[yellow]No rules found with tag '[yellow]{tag}[/]'.[/]")
            return

    console.print(
        f"\n  [bold]{len(rules)} rule(s) loaded[/]"
        + (f" (filtered by tag: [yellow]{tag}[/])" if tag else "")
        + "\n"
    )

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        title="[bold]Pattern Rules[/]",
        expand=True,
    )
    table.add_column("ID",         style="dim",         min_width=20)
    table.add_column("Name",       style="bold white",  ratio=2)
    table.add_column("Confidence", style="yellow",        width=10, justify="right")
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

    console.print(f"\n  [bold]Hint history[/] — session [yellow]{session.name}[/]\n")
    for i, h in enumerate(reversed(hints), 1):
        source_badge = (
            "[yellow][AI][/]" if h["source"] == "ai" else "[yellow][Rule][/]"
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
            console.print(f"[bold red]Error:[/] Session '[yellow]{session_name}[/]' not found.")
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

    ai_label = "[yellow]AI-enhanced[/]" if use_ai else "[dim]offline[/]"
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
            f"  [bold]File:[/] [yellow]{dest}[/]\n\n"
            f"  Open it in any Markdown viewer, or push it to GitHub Gist:\n"
            f"  [dim]gh gist create {dest} --public[/]",
            title="[bold magenta]CTF Writeup Generated[/]",
            border_style="magenta",
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
            console.print(f"[bold red]Error:[/] Session '[yellow]{session_name}[/]' not found.")
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
            f"'[yellow]{target_session.name}[/]'.[/]\n"
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
        f"[bold]Target:[/] [yellow]{getattr(target_session, 'target_ip', '') or '-'}[/]  |  "
        f"[bold]{len(commands)}[/] commands  |  [bold]{len(hints)}[/] hints",
        title="[bold magenta]Attack Timeline[/]",
        border_style="magenta",
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
                "ai":           "[yellow][AI][/]",
                "ollama":       "[yellow][Ollama][/]",
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
                "ai": "[yellow][AI][/]", "ollama": "[yellow][Ollama][/]",
                "pattern": "[yellow][Rule][/]",
            }.get(h["source"], "[dim][?][/]")
            unlinked.add(f"  {source_badge} [dim]{h['hint_text'][:80]}[/]")

    console.print(tree)
    console.print()
