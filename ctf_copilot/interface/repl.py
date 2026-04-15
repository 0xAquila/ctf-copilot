"""
CTF Copilot — Interactive REPL.

Run `ctf` with no arguments to enter this menu-driven interface.
No need to remember any command names or flags — everything is here.

Layout:
  • No active session → Main Menu (start, resume, sessions, vaults, setup)
  • Active session    → Session Menu (hint, notes, findings, dashboard, …)

Color theme: magenta (primary) + yellow (accent) + green/red (status)
"""

from __future__ import annotations

import io
import sys
import time
from typing import Optional

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Use stdout so the user sees everything in their scroll buffer
_console = Console(
    file=io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "buffer") else sys.stdout,
    highlight=False,
)

# ── Color constants ──────────────────────────────────────────────────────────
P  = "magenta"          # primary (borders, titles)
A  = "yellow"           # accent  (numbers, highlights)
OK = "bold green"       # success
ER = "bold red"         # error / critical
DM = "dim"              # secondary text


# ── ASCII banner ─────────────────────────────────────────────────────────────

_LOGO = """\
  ██████╗████████╗███████╗    ██████╗ ██████╗ ██████╗ ██╗██╗      ██████╗ ████████╗
 ██╔════╝╚══██╔══╝██╔════╝   ██╔════╝██╔═══██╗██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
 ██║        ██║   █████╗     ██║     ██║   ██║██████╔╝██║██║     ██║   ██║   ██║
 ██║        ██║   ██╔══╝     ██║     ██║   ██║██╔═══╝ ██║██║     ██║   ██║   ██║
 ╚██████╗   ██║   ██║        ╚██████╗╚██████╔╝██║     ██║███████╗╚██████╔╝   ██║
  ╚═════╝   ╚═╝   ╚═╝         ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝"""


def _banner() -> None:
    _console.print()
    _console.print(Panel(
        Align.center(Text(_LOGO, style=f"bold {P}")),
        subtitle=f"[{DM}]AI-Assisted Penetration Testing  •  Interactive Mode[/]",
        border_style=P,
        box=box.DOUBLE_EDGE,
        padding=(0, 1),
    ))
    _console.print()


def _sep(label: str = "") -> None:
    """Print a section separator."""
    _console.print()
    if label:
        _console.print(Rule(f"[{DM}]{label}[/]", style=DM))
    else:
        _console.print(Rule(style=DM))
    _console.print()


def _prompt(prefix: str = "") -> str:
    """Read a line of input. Returns stripped text or '' on EOF."""
    try:
        raw = input(f"  {prefix}❯ ").strip()
        return raw
    except (EOFError, KeyboardInterrupt):
        _console.print()
        return "q"


def _ask(question: str, default: str = "") -> str:
    """Ask a single question with an optional default."""
    hint = f" [dim](default: {default})[/]" if default else ""
    _console.print(f"  [{A}]?[/]  {question}{hint}")
    try:
        val = input("     ❯ ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        _console.print()
        return default


def _ok(msg: str) -> None:
    _console.print(f"  [{OK}]✓[/]  {msg}")


def _err(msg: str) -> None:
    _console.print(f"  [{ER}]✗[/]  {msg}")


def _info(msg: str) -> None:
    _console.print(f"  [{DM}]{msg}[/]")


# ── Menu renderers ────────────────────────────────────────────────────────────

def _menu_item(key: str, label: str, dim: bool = False) -> str:
    style = DM if dim else "white"
    return f"  [{A}]{key:>5}[/]  [{style}]›  {label}[/]"


def _main_menu() -> None:
    """Render the main menu (no active session)."""
    _console.print(Panel(
        Text("  No active session — start or resume one below", style=DM),
        title=f"[bold {P}]CTF Copilot[/]",
        border_style=P,
        box=box.ROUNDED,
        padding=(0, 1),
        expand=False,
    ))
    _console.print()
    for line in [
        _menu_item("1", "Start new session"),
        _menu_item("2", "Resume a session"),
        _menu_item("3", "All sessions  (list)"),
        "",
        _menu_item("4", "Knowledge vaults"),
        _menu_item("s", "Setup & config"),
        "",
        _menu_item("q", "Quit", dim=True),
    ]:
        _console.print(line)
    _console.print()


def _session_header(session) -> None:
    """Render the active-session status bar."""
    from ctf_copilot.core.database import get_connection
    from ctf_copilot.core.notes import note_count

    with get_connection() as conn:
        svc_n  = conn.execute("SELECT COUNT(*) AS n FROM services    WHERE session_id=?", (session.id,)).fetchone()["n"]
        cmd_n  = conn.execute("SELECT COUNT(*) AS n FROM commands    WHERE session_id=?", (session.id,)).fetchone()["n"]
        flag_n = conn.execute("SELECT COUNT(*) AS n FROM flags       WHERE session_id=?", (session.id,)).fetchone()["n"]
    note_n = note_count(session.id)

    target = session.target_ip or session.target_host or "—"
    plat   = session.platform   or "—"
    diff   = session.difficulty or "—"

    lines = Text(justify="left")
    lines.append("  🟢  ", style="bold green")
    lines.append(f"{session.name}", style=f"bold {P}")
    lines.append(f"   {target}", style="bold white")
    lines.append(f"   {plat}  {diff}", style=DM)
    lines.append("\n")
    lines.append(
        f"     {svc_n} services  •  {cmd_n} commands  •  "
        f"{note_n} notes  •  {flag_n} flags",
        style=DM,
    )

    _console.print(Panel(
        lines,
        title=f"[bold {P}]Active Session[/]",
        border_style=P,
        box=box.ROUNDED,
        padding=(0, 0),
        expand=False,
    ))
    _console.print()


def _session_menu(session_name: str) -> None:
    """Render the in-session action menu."""
    left_items = [
        _menu_item("1", "Get AI hint"),
        _menu_item("2", "Add a note"),
        _menu_item("3", "View notes"),
        _menu_item("4", "Full intel / observations"),
    ]
    right_items = [
        _menu_item("5", "Findings  (services, web, creds)"),
        _menu_item("6", "Live dashboard"),
        _menu_item("7", "Command history"),
        _menu_item("8", "Generate writeup"),
    ]
    for l, r in zip(left_items, right_items):
        _console.print(f"{l}     {r}")
    _console.print()
    _console.print(
        _menu_item("4k", "Knowledge vaults") + "  " +
        _menu_item("s",  "Setup & config")
    )
    _console.print()
    _console.print(
        f"  [{A}] stop[/]  [dim]›  Pause session[/]"
        f"     [{A}] done[/]  [dim]›  Mark completed[/]"
        f"     [{A}]    q[/]  [dim]›  Quit[/]"
    )
    _console.print()


# ── Actions ───────────────────────────────────────────────────────────────────

def _action_start_session() -> None:
    _sep("New Session")
    name  = _ask("Session name  (e.g. lame, blue, vulnversity)")
    if not name:
        _err("Name is required.")
        return
    ip    = _ask("Target IP address", default="")
    host  = _ask("Hostname / domain", default="")
    plat  = _ask("Platform  (HackTheBox / TryHackMe / CTF / …)", default="")
    diff  = _ask("Difficulty  (Easy / Medium / Hard / Insane)", default="")

    from ctf_copilot.core.session import start_session
    try:
        s = start_session(name=name, target_ip=ip, target_host=host,
                          platform=plat, difficulty=diff)
    except ValueError as exc:
        _err(str(exc))
        return

    _console.print()
    _ok(f"Session [bold {P}]{s.name}[/] started!")
    _console.print()
    _show_hook_reminder()


def _action_resume_session() -> None:
    _sep("Resume Session")
    from ctf_copilot.core.session import list_sessions, resume_session

    sessions = [s for s in list_sessions() if s.status != "active"]
    if not sessions:
        _info("No paused sessions found.")
        return

    table = Table(box=box.SIMPLE_HEAD, show_header=True,
                  header_style=f"bold {P}", padding=(0, 1))
    table.add_column("#",        style=A,            width=4)
    table.add_column("Name",     style="bold white",  min_width=16)
    table.add_column("Status",   min_width=10)
    table.add_column("Target",   style="white",       min_width=14)
    table.add_column("Platform", style=DM,            min_width=10)

    _STATUS = {
        "paused":    f"[{A}]paused[/]",
        "completed": "[dim]done[/]",
    }
    for i, s in enumerate(sessions, 1):
        table.add_row(
            str(i),
            s.name,
            _STATUS.get(s.status, s.status),
            s.target_ip or s.target_host or "—",
            s.platform or "—",
        )
    _console.print(table)
    _console.print()

    raw = _ask(f"Choose session  [1–{len(sessions)}]  or name")
    if not raw:
        return
    try:
        idx  = int(raw) - 1
        name = sessions[idx].name if 0 <= idx < len(sessions) else raw
    except ValueError:
        name = raw

    try:
        s = resume_session(name)
        _ok(f"Session [bold {P}]{s.name}[/] resumed.")
        _show_hook_reminder()
    except ValueError as exc:
        _err(str(exc))


def _action_list_sessions() -> None:
    _sep("All Sessions")
    # Reuse the existing CLI command output
    from click.testing import CliRunner
    from ctf_copilot.cli import sessions_list
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(sessions_list, catch_exceptions=False)
    _console.print(result.output)


def _action_get_hint(session_id: int) -> None:
    _sep("AI Hint")
    from ctf_copilot.engine.ai import generate_hint
    from ctf_copilot.interface.display import show_hint

    _info("Asking the AI…")
    hint = generate_hint(session_id=session_id, trigger_command="", force=True)

    if hint.skipped:
        if "no API key" in hint.skip_reason:
            _console.print(Panel(
                f"  No API key configured.\n\n"
                f"  Press [bold {A}]s[/] from the main menu to run [bold]ctf setup[/].",
                border_style=A, box=box.ROUNDED, expand=False,
            ))
        elif "no data yet" in hint.skip_reason:
            _info("Not enough data yet — run nmap or another tool first.")
        else:
            _info(f"Hint skipped: {hint.skip_reason}")
        return
    show_hint(hint.text, source=hint.source, confidence=hint.confidence)


def _action_add_note(session_id: int) -> None:
    _sep("Add Note")
    _info("Type your observation, hypothesis, or dead-end below.")
    text = _ask("Note")
    if not text:
        _info("Nothing saved.")
        return
    tags = _ask("Tags  (optional, comma-separated — e.g. web,sqli)", default="")

    from ctf_copilot.core.notes import add_note, note_count
    nid = add_note(session_id, text, tags=tags)
    total = note_count(session_id)
    _ok(f"Note [bold]#{nid}[/] saved.  [dim]({total} total — included in next AI hint)[/]")


def _action_view_notes(session_id: int) -> None:
    _sep("Session Notes")
    from ctf_copilot.core.notes import get_notes
    notes = get_notes(session_id)
    if not notes:
        _info("No notes yet.  Choose option 2 to add one.")
        return

    table = Table(box=box.ROUNDED, show_header=True,
                  header_style=f"bold {P}", padding=(0, 1), expand=False)
    table.add_column("ID",    style=f"bold {P}", width=4)
    table.add_column("📌",    width=2)
    table.add_column("Note",  style="white",    ratio=1)
    table.add_column("Tags",  style=DM,         width=16)
    table.add_column("Added", style=DM,         width=13, no_wrap=True)

    for n in notes:
        ts = (n.get("created_at") or "")[:16].replace("T", " ")[5:]
        table.add_row(
            str(n["id"]),
            "📌" if n.get("pinned") else "",
            n["text"],
            n.get("tags") or "",
            ts,
        )
    _console.print(table)
    _console.print()
    _info("  [dim]del <id>[/] to delete  •  [dim]pin <id>[/] to pin  •  Enter to continue")
    try:
        cmd = input("     ❯ ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if cmd.startswith("del "):
        from ctf_copilot.core.notes import delete_note
        try:
            nid = int(cmd.split()[1])
            if delete_note(session_id, nid):
                _ok(f"Note #{nid} deleted.")
            else:
                _err(f"Note #{nid} not found.")
        except (ValueError, IndexError):
            _err("Usage: del <id>")
    elif cmd.startswith("pin "):
        from ctf_copilot.core.notes import pin_note
        try:
            nid  = int(cmd.split()[1])
            state = pin_note(session_id, nid)
            _ok(f"Note #{nid} {'📌 pinned' if state else 'unpinned'}.")
        except (ValueError, IndexError):
            _err("Usage: pin <id>")


def _action_intel(session_id: int) -> None:
    _sep("Session Intel")
    from ctf_copilot.core.context import build_context, format_for_ai
    ctx = build_context(session_id)
    if not ctx:
        _err("Could not build context.")
        return
    from ctf_copilot.interface.display import _make_console
    from ctf_copilot.core.observations import Observation
    import ctf_copilot.cli as _cli
    # Reuse cli's show_context output
    from click.testing import CliRunner
    from ctf_copilot.cli import show_context
    result = CliRunner(mix_stderr=False).invoke(show_context, [], catch_exceptions=False)
    _console.print(result.output)


def _action_findings(session_id: int) -> None:
    _sep("Findings")
    from click.testing import CliRunner
    from ctf_copilot.cli import findings
    result = CliRunner(mix_stderr=False).invoke(findings, ["--all"], catch_exceptions=False)
    _console.print(result.output)


def _action_dashboard(session_id: int) -> None:
    _sep("Live Dashboard")
    _info("Launching dashboard… press [bold]q[/] or Ctrl+C to return here.")
    time.sleep(0.6)
    from ctf_copilot.interface.dashboard import run_dashboard
    try:
        run_dashboard(session_id=session_id, refresh_seconds=4.0)
    except Exception:
        pass
    _info("Dashboard closed.")


def _action_history(session_id: int) -> None:
    _sep("Command History")
    from click.testing import CliRunner
    from ctf_copilot.cli import history
    result = CliRunner(mix_stderr=False).invoke(history, ["-n", "20"], catch_exceptions=False)
    _console.print(result.output)


def _action_writeup(session_id: int) -> None:
    _sep("Generate Writeup")
    use_ai = _ask("Include AI narrative?  [y/n]", default="y").lower() in ("y", "yes", "")
    from click.testing import CliRunner
    from ctf_copilot.cli import writeup
    args = [] if use_ai else ["--no-ai"]
    result = CliRunner(mix_stderr=False).invoke(writeup, args, catch_exceptions=False)
    _console.print(result.output)


def _action_vaults() -> None:
    _sep("Knowledge Vaults")
    from ctf_copilot.core.vault import list_vaults, run_vault_repl, create_vault

    vaults = list_vaults()
    if not vaults:
        _info("No vaults yet.")
    else:
        table = Table(box=box.SIMPLE_HEAD, show_header=True,
                      header_style=f"bold {P}", padding=(0, 1), expand=False)
        table.add_column("#",           style=A,             width=4)
        table.add_column("Vault",       style="bold white",  min_width=18)
        table.add_column("Description", style=DM,            ratio=1)
        table.add_column("Entries",     style=A,             width=8, justify="right")
        for i, v in enumerate(vaults, 1):
            color = v.get("color", P)
            table.add_row(
                str(i),
                f"[{color}]●[/]  {v['name']}",
                v.get("description") or "",
                str(v.get("entry_count", 0)),
            )
        _console.print(table)

    _console.print()
    _console.print(
        f"  [{A}]open <name>[/]  [dim]›  Enter vault REPL[/]\n"
        f"  [{A}]new  <name>[/]  [dim]›  Create vault[/]\n"
        f"  [{A}]      Enter[/]  [dim]›  Go back[/]"
    )
    _console.print()

    try:
        cmd = input("  vault ❯ ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if not cmd:
        return
    parts = cmd.split(None, 1)
    verb  = parts[0].lower()
    arg   = parts[1].strip() if len(parts) > 1 else ""

    if verb in ("open", "enter") and arg:
        run_vault_repl(arg)
    elif verb == "new" and arg:
        try:
            v = create_vault(arg)
            _ok(f"Vault '{v['name']}' created.  Opening it now…")
            run_vault_repl(v["name"])
        except ValueError as exc:
            _err(str(exc))
    elif verb in ("open", "new"):
        _err("Please provide a vault name.")


def _action_stop_session() -> None:
    from ctf_copilot.core.session import pause_session
    s = pause_session()
    if s:
        _ok(f"Session [bold {P}]{s.name}[/] paused.  Resume with option 2 from the main menu.")
    else:
        _err("No active session.")


def _action_complete_session() -> None:
    confirm = _ask("Mark session as completed?  [y/N]", default="n").lower()
    if confirm not in ("y", "yes"):
        _info("Cancelled.")
        return
    from ctf_copilot.core.session import complete_session
    s = complete_session()
    if s:
        _ok(f"Session [bold {P}]{s.name}[/] marked complete!  Generate a writeup with option 8.")
    else:
        _err("No active session.")


def _action_setup() -> None:
    _sep("Setup & Config")
    from ctf_copilot.interface.setup_wizard import run_setup_wizard
    run_setup_wizard()


def _show_hook_reminder() -> None:
    """Show the one-line shell hook activation reminder."""
    _console.print(Panel(
        f"  Activate command logging in your shell:\n\n"
        f"  [bold {A}]source ~/.ctf_copilot/ctf-init.sh[/]\n\n"
        f"  [dim]Add this to ~/.bashrc to make it permanent.[/]",
        title=f"[{A}]Shell Hook[/]",
        border_style=A,
        box=box.ROUNDED,
        expand=False,
    ))
    _console.print()


# ── Main REPL loop ────────────────────────────────────────────────────────────

def run_repl() -> None:
    """Entry point — called by `ctf` with no arguments."""
    from ctf_copilot.core.session import get_current_session

    _banner()

    while True:
        try:
            session = get_current_session()

            if session:
                # ── Session mode ──────────────────────────────────────────
                _session_header(session)
                _session_menu(session.name)
                raw = _prompt(f"{session.name} ")

                cmd = raw.lower()
                if   cmd == "1":     _action_get_hint(session.id)
                elif cmd == "2":     _action_add_note(session.id)
                elif cmd == "3":     _action_view_notes(session.id)
                elif cmd == "4":     _action_intel(session.id)
                elif cmd == "5":     _action_findings(session.id)
                elif cmd == "6":     _action_dashboard(session.id)
                elif cmd == "7":     _action_history(session.id)
                elif cmd == "8":     _action_writeup(session.id)
                elif cmd == "4k":    _action_vaults()
                elif cmd in ("s", "setup"):   _action_setup()
                elif cmd == "stop":  _action_stop_session()
                elif cmd in ("done", "complete"): _action_complete_session()
                elif cmd in ("q", "quit", "exit"): break
                elif cmd == "":      pass   # re-draw on empty Enter
                else:
                    _info(f"Unknown option '{raw}' — choose a number from the menu.")

            else:
                # ── Main mode ─────────────────────────────────────────────
                _main_menu()
                raw = _prompt()
                cmd = raw.lower()

                if   cmd == "1":     _action_start_session()
                elif cmd == "2":     _action_resume_session()
                elif cmd == "3":     _action_list_sessions()
                elif cmd == "4":     _action_vaults()
                elif cmd in ("s", "setup"):   _action_setup()
                elif cmd in ("q", "quit", "exit"): break
                elif cmd == "":      pass
                else:
                    _info(f"Unknown option '{raw}' — choose 1–4, s, or q.")

        except KeyboardInterrupt:
            _console.print(f"\n  [{DM}]Ctrl+C — back to menu[/]")
            continue
        except Exception as exc:
            _console.print(f"\n  [{ER}]Error:[/] {exc}\n")
            continue

    _console.print(f"\n  [{DM}]Goodbye.[/]\n")
