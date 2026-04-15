"""
CTF Copilot — Interactive REPL.

Run `ctf` with no arguments to enter this fully interactive menu.
Navigate with arrow keys, press Enter to select, Ctrl+C to go back.

Layout:
  • No active session → Main Menu
  • Active session    → Session Menu

Brand palette: violet (#8B5CF6) primary, amber (#F59E0B) accent.
"""

from __future__ import annotations

import io
import sys
import time
from typing import Optional

import questionary
from questionary import Style as QStyle
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ── Console ───────────────────────────────────────────────────────────────────
_console = Console(
    file=io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "buffer") else sys.stdout,
    highlight=False,
)

# ── Brand palette ─────────────────────────────────────────────────────────────
BRAND  = "#8B5CF6"   # violet   — borders, titles, primary elements
ACCENT = "#F59E0B"   # amber    — selection highlights, numbers, actions
OK     = "#10B981"   # emerald  — success
ERR    = "#EF4444"   # rose     — errors
DIM    = "#6B7280"   # slate    — secondary text
INFO   = "#60A5FA"   # sky blue — informational

# ── Questionary theme ─────────────────────────────────────────────────────────
QSTYLE = QStyle([
    ("qmark",       f"fg:{BRAND} bold"),
    ("question",    "bold"),
    ("answer",      f"fg:{ACCENT} bold"),
    ("pointer",     f"fg:{BRAND} bold"),
    ("highlighted", f"fg:{BRAND} bold"),
    ("selected",    f"fg:{ACCENT}"),
    ("separator",   f"fg:{DIM}"),
    ("instruction", f"fg:{DIM} italic"),
    ("text",        ""),
    ("disabled",    f"fg:{DIM} italic"),
])


# ── ASCII banner ──────────────────────────────────────────────────────────────
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
        Align.center(Text(_LOGO, style=f"bold {BRAND}")),
        subtitle=f"[{DIM}]AI-Assisted Penetration Testing  •  Use ↑↓ arrows to navigate[/]",
        border_style=BRAND,
        box=box.DOUBLE_EDGE,
        padding=(0, 1),
    ))
    _console.print()


def _sep(label: str = "") -> None:
    _console.print()
    if label:
        _console.print(Rule(f"[{DIM}]{label}[/]", style=DIM))
    else:
        _console.print(Rule(style=DIM))
    _console.print()


def _ok(msg: str) -> None:
    _console.print(f"  [bold {OK}]✓[/]  {msg}")


def _err(msg: str) -> None:
    _console.print(f"  [bold {ERR}]✗[/]  {msg}")


def _info(msg: str) -> None:
    _console.print(f"  [{DIM}]{msg}[/]")


def _ask_text(question: str, default: str = "", password: bool = False) -> str:
    """Ask a single text question with optional default. Returns '' on cancel."""
    try:
        if password:
            val = questionary.password(question, style=QSTYLE).ask()
        else:
            val = questionary.text(question, default=default, style=QSTYLE).ask()
        return val.strip() if val else default
    except (EOFError, KeyboardInterrupt):
        return default


def _ask_confirm(question: str, default: bool = False) -> bool:
    try:
        return questionary.confirm(question, default=default, style=QSTYLE).ask() or False
    except (EOFError, KeyboardInterrupt):
        return default


# ── Session header panel ──────────────────────────────────────────────────────

def _session_header(session) -> None:
    from ctf_copilot.core.database import get_connection
    from ctf_copilot.core.notes import note_count

    with get_connection() as conn:
        svc_n  = conn.execute("SELECT COUNT(*) AS n FROM services    WHERE session_id=?", (session.id,)).fetchone()["n"]
        cmd_n  = conn.execute("SELECT COUNT(*) AS n FROM commands    WHERE session_id=?", (session.id,)).fetchone()["n"]
        flag_n = conn.execute("SELECT COUNT(*) AS n FROM flags       WHERE session_id=?", (session.id,)).fetchone()["n"]
        hint_n = conn.execute("SELECT COUNT(*) AS n FROM hints       WHERE session_id=?", (session.id,)).fetchone()["n"]
    note_n = note_count(session.id)

    target = session.target_ip or session.target_host or "—"
    plat   = session.platform   or "—"
    diff   = session.difficulty or "—"

    stats = Text(justify="left")
    stats.append(f"  {session.name}", style=f"bold {BRAND}")
    stats.append(f"  ·  {target}", style="bold white")
    stats.append(f"  ·  {plat}  {diff}", style=DIM)
    stats.append("\n")
    stats.append(
        f"     {svc_n} svc  ·  {cmd_n} cmd  ·  "
        f"{hint_n} hints  ·  {note_n} notes  ·  {flag_n} flags",
        style=DIM,
    )

    _console.print(Panel(
        stats,
        title=f"[bold {BRAND}]Active Session[/]",
        border_style=BRAND,
        box=box.ROUNDED,
        padding=(0, 0),
        expand=False,
    ))
    _console.print()


# ── Menu selectors (arrow-key navigation) ─────────────────────────────────────

def _main_menu_ask() -> str:
    """Show main menu and return the chosen action key. Returns 'q' on cancel."""
    choices = [
        questionary.Choice("  🚀  Start new session",           value="1"),
        questionary.Choice("  ▶   Resume a session",             value="2"),
        questionary.Choice("  📋  All sessions",                 value="3"),
        questionary.Separator("  ─────────────────────────────"),
        questionary.Choice("  🗄   Knowledge vaults",            value="4"),
        questionary.Choice("  ⚙   Settings & config",           value="s"),
        questionary.Separator("  ─────────────────────────────"),
        questionary.Choice("  ✖   Quit",                         value="q"),
    ]
    result = questionary.select(
        "What would you like to do?",
        choices=choices,
        style=QSTYLE,
        use_shortcuts=False,
        use_indicator=True,
    ).ask()
    return result or "q"


def _session_menu_ask(session_name: str) -> str:
    """Show in-session menu and return the chosen action key."""
    choices = [
        questionary.Choice("  ✨  Get AI hint",                  value="1"),
        questionary.Choice("  📝  Add a note",                   value="2"),
        questionary.Choice("  🗒   View notes",                   value="3"),
        questionary.Choice("  🔍  Full intel / observations",    value="4"),
        questionary.Separator("  ─────────────────────────────"),
        questionary.Choice("  🎯  Findings  (services, web, creds)", value="5"),
        questionary.Choice("  📊  Live dashboard",               value="6"),
        questionary.Choice("  📜  Command history",              value="7"),
        questionary.Choice("  📄  Generate writeup",             value="8"),
        questionary.Separator("  ─────────────────────────────"),
        questionary.Choice("  🗄   Knowledge vaults",            value="v"),
        questionary.Choice("  ⚙   Settings & config",           value="s"),
        questionary.Separator("  ─────────────────────────────"),
        questionary.Choice("  ⏸   Pause session",               value="stop"),
        questionary.Choice("  🏁  Mark session complete",        value="done"),
        questionary.Choice("  ✖   Quit",                         value="q"),
    ]
    result = questionary.select(
        f"Session: {session_name}",
        choices=choices,
        style=QSTYLE,
        use_shortcuts=False,
        use_indicator=True,
    ).ask()
    return result or "q"


# ── Action handlers ───────────────────────────────────────────────────────────

def _action_start_session() -> None:
    _sep("New Session")
    name = _ask_text("Session name  (e.g. lame, blue, vulnversity)")
    if not name:
        _info("Cancelled.")
        return
    ip   = _ask_text("Target IP address", default="")
    host = _ask_text("Hostname / domain",  default="")
    plat = _ask_text("Platform  (HackTheBox / TryHackMe / CTF / other)", default="")
    diff = _ask_text("Difficulty  (Easy / Medium / Hard / Insane)", default="")

    from ctf_copilot.core.session import start_session
    try:
        s = start_session(name=name, target_ip=ip, target_host=host,
                          platform=plat, difficulty=diff)
    except ValueError as exc:
        _err(str(exc))
        return

    _console.print()
    _ok(f"Session [bold {BRAND}]{s.name}[/] started!")
    _console.print()
    _show_hook_reminder()


def _action_resume_session() -> None:
    _sep("Resume Session")
    from ctf_copilot.core.session import list_sessions, resume_session

    sessions = [s for s in list_sessions() if s.status != "active"]
    if not sessions:
        _info("No paused sessions found.")
        return

    choices = [
        questionary.Choice(
            f"  {s.name:<20} [{s.status}]  {s.target_ip or s.target_host or '—'}",
            value=s.name,
        )
        for s in sessions
    ]
    choices.append(questionary.Separator())
    choices.append(questionary.Choice("  ← Cancel", value=""))

    name = questionary.select(
        "Choose session to resume:",
        choices=choices,
        style=QSTYLE,
    ).ask()

    if not name:
        return
    try:
        s = resume_session(name)
        _ok(f"Session [bold {BRAND}]{s.name}[/] resumed.")
        _show_hook_reminder()
    except ValueError as exc:
        _err(str(exc))


def _action_list_sessions() -> None:
    _sep("All Sessions")
    from click.testing import CliRunner
    from ctf_copilot.cli import sessions_list
    result = CliRunner(mix_stderr=False).invoke(sessions_list, catch_exceptions=False)
    _console.print(result.output)
    input("  Press Enter to continue…")


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
                f"  Choose [bold {ACCENT}]Settings & config[/] from the menu to run the setup wizard.",
                border_style=ACCENT, box=box.ROUNDED, expand=False,
            ))
        elif "no data yet" in hint.skip_reason:
            _info("Not enough data yet — run nmap or another tool first.")
        else:
            _info(f"Hint skipped: {hint.skip_reason}")
        return
    show_hint(hint.text, source=hint.source, confidence=hint.confidence)
    input("  Press Enter to continue…")


def _action_add_note(session_id: int) -> None:
    _sep("Add Note")
    text = _ask_text("Your observation, hypothesis, or dead-end")
    if not text:
        _info("Nothing saved.")
        return
    tags = _ask_text("Tags  (optional, comma-separated — e.g. web,sqli)", default="")

    from ctf_copilot.core.notes import add_note, note_count
    nid   = add_note(session_id, text, tags=tags)
    total = note_count(session_id)
    _ok(f"Note [bold]#{nid}[/] saved.  [{DIM}]({total} total — fed into next AI hint)[/]")


def _action_view_notes(session_id: int) -> None:
    _sep("Session Notes")
    from ctf_copilot.core.notes import get_notes, delete_note, pin_note

    notes = get_notes(session_id)
    if not notes:
        _info("No notes yet.  Choose 'Add a note' to add one.")
        return

    table = Table(box=box.ROUNDED, show_header=True,
                  header_style=f"bold {BRAND}", padding=(0, 1), expand=False)
    table.add_column("ID",    style=f"bold {BRAND}", width=4)
    table.add_column("📌",    width=2)
    table.add_column("Note",  style="white",    ratio=1)
    table.add_column("Tags",  style=DIM,         width=16)
    table.add_column("Added", style=DIM,         width=13, no_wrap=True)

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

    action_choices = [
        questionary.Choice("  ← Back",                value="back"),
        questionary.Separator(),
        *[questionary.Choice(f"  📌 Pin/unpin #{n['id']}", value=f"pin:{n['id']}") for n in notes],
        *[questionary.Choice(f"  🗑  Delete #{n['id']}",   value=f"del:{n['id']}") for n in notes],
    ]
    choice = questionary.select(
        "Note actions:",
        choices=action_choices,
        style=QSTYLE,
    ).ask()

    if not choice or choice == "back":
        return
    if choice.startswith("del:"):
        nid = int(choice.split(":")[1])
        if delete_note(session_id, nid):
            _ok(f"Note #{nid} deleted.")
        else:
            _err(f"Note #{nid} not found.")
    elif choice.startswith("pin:"):
        nid   = int(choice.split(":")[1])
        state = pin_note(session_id, nid)
        _ok(f"Note #{nid} {'📌 pinned' if state else 'unpinned'}.")


def _action_intel(session_id: int) -> None:
    _sep("Session Intel")
    from click.testing import CliRunner
    from ctf_copilot.cli import show_context
    result = CliRunner(mix_stderr=False).invoke(show_context, [], catch_exceptions=False)
    _console.print(result.output)
    input("  Press Enter to continue…")


def _action_findings(session_id: int) -> None:
    _sep("Findings")
    from click.testing import CliRunner
    from ctf_copilot.cli import findings
    result = CliRunner(mix_stderr=False).invoke(findings, ["--all"], catch_exceptions=False)
    _console.print(result.output)
    input("  Press Enter to continue…")


def _action_dashboard(session_id: int) -> None:
    _sep("Live Dashboard")
    _info("Launching dashboard — press q or Ctrl+C to return.")
    time.sleep(0.4)
    from ctf_copilot.interface.dashboard import run_dashboard
    try:
        run_dashboard(session_id=session_id, refresh_seconds=4.0)
    except Exception:
        pass


def _action_history(session_id: int) -> None:
    _sep("Command History")
    from click.testing import CliRunner
    from ctf_copilot.cli import history
    result = CliRunner(mix_stderr=False).invoke(history, ["-n", "20"], catch_exceptions=False)
    _console.print(result.output)
    input("  Press Enter to continue…")


def _action_writeup(session_id: int) -> None:
    _sep("Generate Writeup")
    use_ai = _ask_confirm("Include AI narrative in writeup?", default=True)
    from click.testing import CliRunner
    from ctf_copilot.cli import writeup
    args   = [] if use_ai else ["--no-ai"]
    result = CliRunner(mix_stderr=False).invoke(writeup, args, catch_exceptions=False)
    _console.print(result.output)
    input("  Press Enter to continue…")


def _action_vaults() -> None:
    _sep("Knowledge Vaults")
    from ctf_copilot.core.vault import list_vaults, run_vault_repl, create_vault

    vaults = list_vaults()

    if vaults:
        table = Table(box=box.SIMPLE_HEAD, show_header=True,
                      header_style=f"bold {BRAND}", padding=(0, 1), expand=False)
        table.add_column("#",           style=ACCENT,         width=4)
        table.add_column("Vault",       style="bold white",   min_width=18)
        table.add_column("Description", style=DIM,            ratio=1)
        table.add_column("Entries",     style=ACCENT,         width=8, justify="right")
        for i, v in enumerate(vaults, 1):
            color = v.get("color", BRAND)
            table.add_row(
                str(i),
                f"[{color}]●[/]  {v['name']}",
                v.get("description") or "",
                str(v.get("entry_count", 0)),
            )
        _console.print(table)
        _console.print()

    # Build choice list: open existing + create new + back
    choices = []
    for v in vaults:
        choices.append(questionary.Choice(f"  📂  Open '{v['name']}'", value=f"open:{v['name']}"))
    choices.append(questionary.Separator())
    choices.append(questionary.Choice("  ➕  Create new vault", value="new"))
    choices.append(questionary.Choice("  ← Back",               value="back"))

    choice = questionary.select(
        "Vault actions:",
        choices=choices,
        style=QSTYLE,
    ).ask()

    if not choice or choice == "back":
        return
    if choice == "new":
        name = _ask_text("Vault name")
        if not name:
            return
        desc = _ask_text("Description  (optional)", default="")
        try:
            v = create_vault(name, description=desc)
            _ok(f"Vault '{v['name']}' created.  Opening it now…")
            run_vault_repl(v["name"])
        except ValueError as exc:
            _err(str(exc))
    elif choice.startswith("open:"):
        vault_name = choice.split(":", 1)[1]
        run_vault_repl(vault_name)


def _action_stop_session() -> None:
    if not _ask_confirm("Pause the current session?", default=True):
        return
    from ctf_copilot.core.session import pause_session
    s = pause_session()
    if s:
        _ok(f"Session [bold {BRAND}]{s.name}[/] paused.  Resume it from the main menu.")
    else:
        _err("No active session.")


def _action_complete_session() -> None:
    if not _ask_confirm("Mark session as completed?", default=False):
        _info("Cancelled.")
        return
    from ctf_copilot.core.session import complete_session
    s = complete_session()
    if s:
        _ok(f"Session [bold {BRAND}]{s.name}[/] marked complete!  Generate a writeup from the menu.")
    else:
        _err("No active session.")


# ── Config editor ─────────────────────────────────────────────────────────────

def _action_edit_config() -> None:
    """Interactive config editor — view and change any setting with arrow keys."""
    _sep("Settings & Config")
    from ctf_copilot.core.config import config, save_config_value, reload_config

    # Fields: (config_key, display_label, input_type, options_or_None)
    # input_type: "text" | "password" | "select" | "bool"
    FIELDS = [
        # ── AI backend ──────────────────────────────────────────────────────
        ("ai_backend",            "AI Backend",         "select",   ["claude", "groq", "ollama"]),
        # ── Claude ──────────────────────────────────────────────────────────
        ("api_key",               "Claude API Key",     "password", None),
        ("ai_model",              "Claude Model",       "select",   [
            "claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"]),
        # ── Groq ────────────────────────────────────────────────────────────
        ("groq_api_key",          "Groq API Key",       "password", None),
        ("groq_model",            "Groq Model",         "select",   [
            "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",      "gemma2-9b-it"]),
        # ── Ollama ──────────────────────────────────────────────────────────
        ("ollama_endpoint",       "Ollama Endpoint",    "text",     None),
        ("ollama_model",          "Ollama Model",       "text",     None),
        # ── General ─────────────────────────────────────────────────────────
        ("ai_max_tokens",         "Max Tokens",         "text",     None),
        ("ai_rate_limit_seconds", "Rate Limit (secs)",  "text",     None),
        ("offline_mode",          "Offline Mode",       "bool",     None),
        ("confidence_threshold",  "Confidence (0-1)",   "text",     None),
        ("dedup_hints",           "Deduplicate Hints",  "bool",     None),
        # ── Integrations ────────────────────────────────────────────────────
        ("nvd_api_key",           "NVD API Key",        "password", None),
        ("htb_api_key",           "HTB API Key",        "password", None),
    ]
    _ENCRYPTED = {"api_key", "groq_api_key", "nvd_api_key", "htb_api_key"}

    while True:
        # Build display choices
        choices = []
        for fkey, label, ftype, _ in FIELDS:
            raw_val = getattr(config, fkey, "")
            if fkey in _ENCRYPTED and raw_val:
                disp = f"[{DIM}]{'•' * 8}  (set)[/{DIM}]"
                disp_plain = "••••••••  (set)"
            elif isinstance(raw_val, bool):
                disp_plain = "yes" if raw_val else "no"
            else:
                disp_plain = str(raw_val) if raw_val else "(not set)"
            choices.append(
                questionary.Choice(
                    f"  {label:<28} {disp_plain}",
                    value=fkey,
                )
            )

        choices.append(questionary.Separator())
        choices.append(questionary.Choice("  ← Back to menu", value="__back__"))

        selected = questionary.select(
            "Select a setting to edit:",
            choices=choices,
            style=QSTYLE,
            use_indicator=True,
        ).ask()

        if selected is None or selected == "__back__":
            break

        # Find field details
        field_info = next((f for f in FIELDS if f[0] == selected), None)
        if not field_info:
            continue
        fkey, label, ftype, options = field_info
        current = str(getattr(config, fkey, ""))

        new_val = None

        if ftype == "bool":
            cur_bool = bool(getattr(config, fkey, False))
            new_val = questionary.select(
                f"{label}:",
                choices=[
                    questionary.Choice("  yes  (enabled)",  value=True),
                    questionary.Choice("  no   (disabled)", value=False),
                ],
                default=questionary.Choice("  yes  (enabled)",  value=True) if cur_bool
                        else questionary.Choice("  no   (disabled)", value=False),
                style=QSTYLE,
            ).ask()

        elif ftype == "select" and options:
            choice_list = [questionary.Choice(f"  {o}", value=o) for o in options]
            choice_list.append(questionary.Separator())
            choice_list.append(questionary.Choice("  ← Cancel", value=None))
            new_val = questionary.select(
                f"New value for {label}:",
                choices=choice_list,
                style=QSTYLE,
            ).ask()

        elif ftype == "password":
            new_val = questionary.password(
                f"New {label}  (leave blank to keep current):",
                style=QSTYLE,
            ).ask()
            if not new_val:
                continue

        else:  # text
            new_val = questionary.text(
                f"New value for {label}:",
                default=current,
                style=QSTYLE,
            ).ask()

        if new_val is None:
            continue

        save_config_value(fkey, new_val)
        reload_config()
        _ok(f"[bold]{label}[/] updated.")

    # Show current config summary after editing
    _console.print()
    _console.print(Panel(
        f"  Backend:  [bold {BRAND}]{config.ai_backend}[/]   "
        f"Model:  [{DIM}]{config.ai_model if config.ai_backend == 'claude' else config.groq_model if config.ai_backend == 'groq' else config.ollama_model}[/]\n"
        f"  Offline:  {'[bold red]yes[/]' if config.offline_mode else '[bold #10B981]no[/]'}   "
        f"Rate limit:  [{DIM}]{config.ai_rate_limit_seconds}s[/]",
        title=f"[bold {BRAND}]Current Settings[/]",
        border_style=BRAND,
        box=box.ROUNDED,
        expand=False,
    ))
    _console.print()


def _action_setup() -> None:
    _sep("Setup Wizard")
    from ctf_copilot.interface.setup_wizard import run_setup_wizard
    run_setup_wizard()


def _show_hook_reminder() -> None:
    _console.print(Panel(
        f"  Activate command logging in your shell:\n\n"
        f"  [bold {ACCENT}]source ~/.ctf_copilot/ctf-init.sh[/]\n\n"
        f"  [{DIM}]Add to ~/.bashrc to make it permanent.[/]",
        title=f"[{ACCENT}]Shell Hook[/]",
        border_style=ACCENT,
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
                choice = _session_menu_ask(session.name)

                if   choice == "1":    _action_get_hint(session.id)
                elif choice == "2":    _action_add_note(session.id)
                elif choice == "3":    _action_view_notes(session.id)
                elif choice == "4":    _action_intel(session.id)
                elif choice == "5":    _action_findings(session.id)
                elif choice == "6":    _action_dashboard(session.id)
                elif choice == "7":    _action_history(session.id)
                elif choice == "8":    _action_writeup(session.id)
                elif choice == "v":    _action_vaults()
                elif choice == "s":    _action_edit_config()
                elif choice == "stop": _action_stop_session()
                elif choice == "done": _action_complete_session()
                elif choice == "q":    break

            else:
                # ── Main mode ─────────────────────────────────────────────
                choice = _main_menu_ask()

                if   choice == "1":  _action_start_session()
                elif choice == "2":  _action_resume_session()
                elif choice == "3":  _action_list_sessions()
                elif choice == "4":  _action_vaults()
                elif choice == "s":  _action_edit_config()
                elif choice == "q":  break

        except KeyboardInterrupt:
            _console.print(f"\n  [{DIM}]Ctrl+C — returning to menu[/]")
            continue
        except Exception as exc:
            _console.print(f"\n  [bold {ERR}]Error:[/] {exc}\n")
            continue

    _console.print(f"\n  [{DIM}]Goodbye.[/]\n")
