"""
CTF Copilot — Interactive REPL.

Run `ctf` with no arguments to enter this fully interactive menu.
Navigate with ↑↓ arrow keys, press Enter to select.
Press Esc or Ctrl+C to go back / return to the previous menu.

The screen is cleared before every menu render — only the relevant
section is ever visible at one time.
"""

from __future__ import annotations

import io
import os
import sys
import time
from typing import Optional

import questionary
from questionary import Style as QStyle
from rich import box
from rich.align import Align
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
BRAND  = "#8B5CF6"   # violet   — primary brand
ACCENT = "#F59E0B"   # amber    — highlights, numbers
OK     = "#10B981"   # emerald  — success
ERR    = "#EF4444"   # rose     — errors
DIM    = "#6B7280"   # slate    — secondary text

# ── Questionary style ─────────────────────────────────────────────────────────
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

# ── Banner ────────────────────────────────────────────────────────────────────
_LOGO = """\
  ██████╗████████╗███████╗    ██████╗ ██████╗ ██████╗ ██╗██╗      ██████╗ ████████╗
 ██╔════╝╚══██╔══╝██╔════╝   ██╔════╝██╔═══██╗██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
 ██║        ██║   █████╗     ██║     ██║   ██║██████╔╝██║██║     ██║   ██║   ██║
 ██║        ██║   ██╔══╝     ██║     ██║   ██║██╔═══╝ ██║██║     ██║   ██║   ██║
 ╚██████╗   ██║   ██║        ╚██████╗╚██████╔╝██║     ██║███████╗╚██████╔╝   ██║
  ╚═════╝   ╚═╝   ╚═╝         ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝"""


def _clear() -> None:
    """Clear the terminal screen."""
    _console.clear()


def _banner() -> None:
    _console.print(Panel(
        Align.center(Text(_LOGO, style=f"bold {BRAND}")),
        subtitle=f"[{DIM}]AI Penetration Testing Copilot  ·  ↑↓ arrows · Enter · Esc/Ctrl+C = back[/]",
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


def _pause() -> None:
    """Hold the output on screen until the user presses Enter."""
    try:
        input(f"\n  [{DIM}]  Press Enter to continue…[/]  ")
    except (EOFError, KeyboardInterrupt):
        pass


def _ask_text(question: str, default: str = "", password: bool = False) -> str:
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
        result = questionary.confirm(question, default=default, style=QSTYLE).ask()
        return result if result is not None else default
    except (EOFError, KeyboardInterrupt):
        return default


# ── Session header ────────────────────────────────────────────────────────────

def _session_header(session) -> None:
    from ctf_copilot.core.database import get_connection
    from ctf_copilot.core.notes import note_count

    with get_connection() as conn:
        svc_n  = conn.execute("SELECT COUNT(*) AS n FROM services WHERE session_id=?", (session.id,)).fetchone()["n"]
        cmd_n  = conn.execute("SELECT COUNT(*) AS n FROM commands WHERE session_id=?", (session.id,)).fetchone()["n"]
        flag_n = conn.execute("SELECT COUNT(*) AS n FROM flags    WHERE session_id=?", (session.id,)).fetchone()["n"]
        hint_n = conn.execute("SELECT COUNT(*) AS n FROM hints    WHERE session_id=?", (session.id,)).fetchone()["n"]
    note_n = note_count(session.id)

    target = session.target_ip or session.target_host or "—"
    plat   = session.platform   or "—"
    diff   = session.difficulty or "—"

    line = Text(justify="left")
    line.append(f"  {session.name}", style=f"bold {BRAND}")
    line.append(f"  ·  {target}", style="bold white")
    line.append(f"  ·  {plat}  {diff}", style=DIM)
    line.append("\n")
    line.append(
        f"     {svc_n} svc  ·  {cmd_n} cmd  ·  "
        f"{hint_n} hints  ·  {note_n} notes  ·  {flag_n} flags",
        style=DIM,
    )

    _console.print(Panel(
        line,
        title=f"[bold {BRAND}]Active Session[/]",
        border_style=BRAND,
        box=box.ROUNDED,
        padding=(0, 0),
        expand=False,
    ))
    _console.print()


# ── Menus ─────────────────────────────────────────────────────────────────────

def _main_menu_ask() -> Optional[str]:
    """Returns the chosen value, or None if cancelled (Esc/Ctrl+C)."""
    choices = [
        questionary.Choice("  🚀  Start new session",        value="1"),
        questionary.Choice("  ▶   Resume a session",          value="2"),
        questionary.Choice("  📋  Manage sessions",           value="3"),
        questionary.Separator("  ─────────────────────────"),
        questionary.Choice("  🗄   Knowledge vaults",         value="4"),
        questionary.Choice("  ⚙   Settings & config",        value="s"),
        questionary.Separator("  ─────────────────────────"),
        questionary.Choice("  ✖   Quit",                      value="q"),
    ]
    try:
        return questionary.select(
            "What would you like to do?",
            choices=choices,
            style=QSTYLE,
            use_indicator=True,
        ).ask()
    except KeyboardInterrupt:
        return None


def _session_menu_ask(session_name: str) -> Optional[str]:
    choices = [
        questionary.Choice("  ✨  Get AI hint",               value="1"),
        questionary.Choice("  📝  Add a note",                value="2"),
        questionary.Choice("  🗒   View notes",                value="3"),
        questionary.Choice("  🔍  Full intel",                 value="4"),
        questionary.Separator("  ─────────────────────────"),
        questionary.Choice("  🎯  Findings  (svcs · web · creds)", value="5"),
        questionary.Choice("  📊  Live dashboard",            value="6"),
        questionary.Choice("  📜  Command history",           value="7"),
        questionary.Choice("  📄  Generate writeup",          value="8"),
        questionary.Separator("  ─────────────────────────"),
        questionary.Choice("  🗄   Knowledge vaults",         value="v"),
        questionary.Choice("  ⚙   Settings & config",        value="s"),
        questionary.Separator("  ─────────────────────────"),
        questionary.Choice("  ⏸   Pause session",            value="stop"),
        questionary.Choice("  🏁  Mark complete",             value="done"),
        questionary.Choice("  ✖   Quit",                      value="q"),
    ]
    try:
        return questionary.select(
            f"Session: {session_name}",
            choices=choices,
            style=QSTYLE,
            use_indicator=True,
        ).ask()
    except KeyboardInterrupt:
        return None


# ── Actions ───────────────────────────────────────────────────────────────────

def _action_start_session() -> None:
    _clear()
    _banner()
    _sep("New Session")
    name = _ask_text("Session name  (e.g. lame, blue, vulnversity)")
    if not name:
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
        _pause()
        return

    _console.print()
    _ok(f"Session [bold {BRAND}]{s.name}[/] started!")
    _console.print()
    _show_hook_reminder()
    _pause()


def _action_resume_session() -> None:
    _clear()
    _banner()
    _sep("Resume Session")
    from ctf_copilot.core.session import list_sessions, resume_session

    sessions = [s for s in list_sessions() if s.status != "active"]
    if not sessions:
        _info("No paused sessions found.")
        _pause()
        return

    choices = [
        questionary.Choice(
            f"  {s.name:<22} [{s.status}]  {s.target_ip or s.target_host or '—'}",
            value=s.name,
        )
        for s in sessions
    ]
    choices.append(questionary.Separator())
    choices.append(questionary.Choice("  ← Cancel", value=""))

    try:
        name = questionary.select(
            "Choose session to resume:",
            choices=choices,
            style=QSTYLE,
        ).ask()
    except KeyboardInterrupt:
        return

    if not name:
        return
    try:
        s = resume_session(name)
        _ok(f"Session [bold {BRAND}]{s.name}[/] resumed.")
        _console.print()
        _show_hook_reminder()
        _pause()
    except ValueError as exc:
        _err(str(exc))
        _pause()


def _action_manage_sessions() -> None:
    """Interactive session manager — view, resume, delete sessions."""
    from ctf_copilot.core.session import list_sessions, resume_session, delete_session, get_current_session

    _STATUS_ICON = {
        "active":    f"[bold {OK}]▶ active[/]",
        "paused":    f"[{ACCENT}]⏸ paused[/]",
        "completed": f"[{DIM}]✓ done[/]",
    }
    _DIFF_COLOR = {"easy": OK, "medium": ACCENT, "hard": ERR, "insane": ERR}

    while True:
        _clear()
        _banner()
        _sep("Manage Sessions")

        sessions = list_sessions()
        current  = get_current_session()

        if not sessions:
            _info("No sessions yet.  Choose 'Start new session' from the main menu.")
            _pause()
            return

        # Build table
        table = Table(box=box.ROUNDED, show_header=True,
                      header_style=f"bold {BRAND}", padding=(0, 1), expand=False)
        table.add_column("",         width=2)
        table.add_column("Name",     style="bold white", min_width=16)
        table.add_column("Status",   min_width=12)
        table.add_column("Target",   style="white",      min_width=14)
        table.add_column("Platform", style=DIM,          min_width=10)
        table.add_column("Diff",     min_width=8)

        for s in sessions:
            is_cur = current and current.id == s.id
            marker = f"[bold {BRAND}]▶[/]" if is_cur else " "
            plat   = s.platform   or "—"
            diff   = s.difficulty or "—"
            diff_c = _DIFF_COLOR.get((s.difficulty or "").lower(), "white")
            table.add_row(
                marker,
                s.name,
                _STATUS_ICON.get(s.status, s.status),
                s.target_ip or s.target_host or "—",
                plat,
                f"[{diff_c}]{diff}[/]",
            )
        _console.print(table)
        _console.print()

        # Build action choices
        choices = [questionary.Choice("  ← Back", value="back")]
        choices.append(questionary.Separator())
        for s in sessions:
            icon = "▶ " if (current and current.id == s.id) else "   "
            choices.append(
                questionary.Choice(f"  {icon}{s.name}  [{s.status}]", value=f"pick:{s.id}:{s.name}:{s.status}")
            )

        try:
            choice = questionary.select(
                "Select a session to manage:",
                choices=choices,
                style=QSTYLE,
                use_indicator=True,
            ).ask()
        except KeyboardInterrupt:
            return

        if not choice or choice == "back":
            return

        _, sid_str, sname, sstatus = choice.split(":", 3)
        sid = int(sid_str)

        # Per-session actions
        session_choices = [questionary.Choice("  ← Back", value="back")]
        session_choices.append(questionary.Separator())
        if sstatus != "active":
            session_choices.append(questionary.Choice("  ▶   Resume this session", value="resume"))
        session_choices.append(questionary.Choice("  🗑  Delete this session (permanent)", value="delete"))

        try:
            action = questionary.select(
                f"Session: {sname}",
                choices=session_choices,
                style=QSTYLE,
            ).ask()
        except KeyboardInterrupt:
            continue

        if not action or action == "back":
            continue

        if action == "resume":
            try:
                s = resume_session(sname)
                _ok(f"Session [bold {BRAND}]{s.name}[/] resumed.")
                _console.print()
                _show_hook_reminder()
                _pause()
            except ValueError as exc:
                _err(str(exc))
                _pause()

        elif action == "delete":
            _console.print()
            confirm = _ask_confirm(
                f"Permanently delete '{sname}' and ALL its data? This cannot be undone.",
                default=False,
            )
            if confirm:
                if delete_session(sid):
                    _ok(f"Session '{sname}' deleted.")
                else:
                    _err("Session not found.")
                time.sleep(0.7)


def _action_get_hint(session_id: int) -> None:
    _clear()
    _banner()
    _sep("AI Hint")
    from ctf_copilot.engine.ai import generate_hint
    from ctf_copilot.interface.display import show_hint

    _info("Asking the AI…")
    hint = generate_hint(session_id=session_id, trigger_command="", force=True)

    if hint.skipped:
        if "no API key" in hint.skip_reason:
            _console.print(Panel(
                f"  No API key configured.\n\n"
                f"  Go to [bold {ACCENT}]Settings & config[/] to run the setup wizard.",
                border_style=ACCENT, box=box.ROUNDED, expand=False,
            ))
        elif "no data yet" in hint.skip_reason:
            _info("Not enough data yet — run nmap or another tool first.")
        else:
            _info(f"Hint skipped: {hint.skip_reason}")
        _pause()
        return

    show_hint(hint.text, source=hint.source, confidence=hint.confidence)
    _pause()


def _action_add_note(session_id: int) -> None:
    _clear()
    _banner()
    _sep("Add Note")
    text = _ask_text("Your observation, hypothesis, or dead-end")
    if not text:
        return
    tags = _ask_text("Tags  (optional, comma-separated — e.g. web,sqli)", default="")

    from ctf_copilot.core.notes import add_note, note_count
    nid   = add_note(session_id, text, tags=tags)
    total = note_count(session_id)
    _console.print()
    _ok(f"Note [bold]#{nid}[/] saved.  [{DIM}]({total} total — fed into next AI hint)[/]")
    _pause()


def _action_view_notes(session_id: int) -> None:
    while True:
        _clear()
        _banner()
        _sep("Session Notes")
        from ctf_copilot.core.notes import get_notes, delete_note, pin_note

        notes = get_notes(session_id)
        if not notes:
            _info("No notes yet.  Choose 'Add a note' to add one.")
            _pause()
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
                str(n["id"]), "📌" if n.get("pinned") else "",
                n["text"], n.get("tags") or "", ts,
            )
        _console.print(table)
        _console.print()

        action_choices = [
            questionary.Choice("  ← Back",                 value="back"),
            questionary.Separator(),
            *[questionary.Choice(f"  📌 Toggle pin on note #{n['id']}", value=f"pin:{n['id']}") for n in notes],
            *[questionary.Choice(f"  🗑  Delete note #{n['id']}",       value=f"del:{n['id']}") for n in notes],
        ]
        try:
            choice = questionary.select(
                "Note actions:",
                choices=action_choices,
                style=QSTYLE,
            ).ask()
        except KeyboardInterrupt:
            return

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
        time.sleep(0.6)  # brief flash so the user sees the confirmation


def _action_intel(session_id: int) -> None:
    _clear()
    _banner()
    _sep("Session Intel")
    from click.testing import CliRunner
    from ctf_copilot.cli import show_context
    result = CliRunner().invoke(show_context, [], catch_exceptions=False)
    _console.print(result.output)
    _pause()


def _action_findings(session_id: int) -> None:
    _clear()
    _banner()
    _sep("Findings")
    from click.testing import CliRunner
    from ctf_copilot.cli import findings
    result = CliRunner().invoke(findings, ["--all"], catch_exceptions=False)
    _console.print(result.output)
    _pause()


def _action_dashboard(session_id: int) -> None:
    _clear()
    _info("Launching dashboard — press q or Ctrl+C to return.")
    time.sleep(0.4)
    from ctf_copilot.interface.dashboard import run_dashboard
    try:
        run_dashboard(session_id=session_id, refresh_seconds=4.0)
    except Exception:
        pass


def _action_history(session_id: int) -> None:
    _clear()
    _banner()
    _sep("Command History")
    from click.testing import CliRunner
    from ctf_copilot.cli import history
    result = CliRunner().invoke(history, ["-n", "20"], catch_exceptions=False)
    _console.print(result.output)
    _pause()


def _action_writeup(session_id: int) -> None:
    _clear()
    _banner()
    _sep("Generate Writeup")
    use_ai = _ask_confirm("Include AI narrative in writeup?", default=True)
    from click.testing import CliRunner
    from ctf_copilot.cli import writeup
    result = CliRunner().invoke(
        writeup, [] if use_ai else ["--no-ai"], catch_exceptions=False
    )
    _console.print(result.output)
    _pause()


def _action_vaults() -> None:
    while True:
        _clear()
        _banner()
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

        choices = [
            *[questionary.Choice(f"  📂  Open '{v['name']}'", value=f"open:{v['name']}") for v in vaults],
            questionary.Separator(),
            questionary.Choice("  ➕  Create new vault", value="new"),
            questionary.Choice("  ← Back",               value="back"),
        ]
        try:
            choice = questionary.select(
                "Vault actions:",
                choices=choices,
                style=QSTYLE,
            ).ask()
        except KeyboardInterrupt:
            return

        if not choice or choice == "back":
            return
        if choice == "new":
            name = _ask_text("Vault name")
            if not name:
                continue
            desc = _ask_text("Description  (optional)", default="")
            try:
                v = create_vault(name, description=desc)
                _ok(f"Vault '{v['name']}' created.  Opening it now…")
                time.sleep(0.5)
                run_vault_repl(v["name"])
            except ValueError as exc:
                _err(str(exc))
                _pause()
        elif choice.startswith("open:"):
            run_vault_repl(choice.split(":", 1)[1])


def _action_stop_session() -> None:
    if not _ask_confirm("Pause the current session?", default=True):
        return
    from ctf_copilot.core.session import pause_session
    s = pause_session()
    if s:
        _ok(f"Session [bold {BRAND}]{s.name}[/] paused.")
    else:
        _err("No active session.")
    _pause()


def _action_complete_session() -> None:
    if not _ask_confirm("Mark session as completed?", default=False):
        return
    from ctf_copilot.core.session import complete_session
    s = complete_session()
    if s:
        _ok(f"Session [bold {BRAND}]{s.name}[/] marked complete!")
    else:
        _err("No active session.")
    _pause()


# ── Config editor ─────────────────────────────────────────────────────────────

def _action_edit_config() -> None:
    from ctf_copilot.core.config import config, save_config_value, reload_config

    FIELDS = [
        ("ai_backend",            "AI Backend",          "select",   ["claude", "groq", "ollama"]),
        ("api_key",               "Claude API Key",       "password", None),
        ("ai_model",              "Claude Model",         "select",   [
            "claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"]),
        ("groq_api_key",          "Groq API Key",         "password", None),
        ("groq_model",            "Groq Model",           "select",   [
            "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",      "gemma2-9b-it"]),
        ("ollama_endpoint",       "Ollama Endpoint",      "text",     None),
        ("ollama_model",          "Ollama Model",         "text",     None),
        ("ai_max_tokens",         "Max Tokens",           "text",     None),
        ("ai_rate_limit_seconds", "Rate Limit (secs)",    "text",     None),
        ("offline_mode",          "Offline Mode",         "bool",     None),
        ("confidence_threshold",  "Confidence (0-1)",     "text",     None),
        ("dedup_hints",           "Deduplicate Hints",    "bool",     None),
        ("nvd_api_key",           "NVD API Key",          "password", None),
        ("htb_api_key",           "HTB API Key",          "password", None),
    ]
    _MASKED = {"api_key", "groq_api_key", "nvd_api_key", "htb_api_key"}

    while True:
        _clear()
        _banner()
        _sep("Settings & Config")

        # Build display choices with current values
        choices = []
        for fkey, label, ftype, _ in FIELDS:
            raw = getattr(config, fkey, "")
            if fkey in _MASKED and raw:
                disp = "••••••••  (set)"
            elif isinstance(raw, bool):
                disp = "yes" if raw else "no"
            else:
                disp = str(raw) if raw else "(not set)"
            choices.append(
                questionary.Choice(f"  {label:<28} {disp}", value=fkey)
            )
        choices.append(questionary.Separator())
        choices.append(questionary.Choice("  ← Back", value="__back__"))

        try:
            selected = questionary.select(
                "Select a setting to edit  (Esc or Ctrl+C = back):",
                choices=choices,
                style=QSTYLE,
                use_indicator=True,
            ).ask()
        except KeyboardInterrupt:
            return

        if selected is None or selected == "__back__":
            return

        field_info = next((f for f in FIELDS if f[0] == selected), None)
        if not field_info:
            continue
        fkey, label, ftype, options = field_info
        current = str(getattr(config, fkey, ""))

        new_val = None

        if ftype == "bool":
            cur_bool = bool(getattr(config, fkey, False))
            try:
                new_val = questionary.select(
                    f"{label}:",
                    choices=[
                        questionary.Choice("  yes  (enabled)",  value=True),
                        questionary.Choice("  no   (disabled)", value=False),
                    ],
                    default=questionary.Choice("  yes  (enabled)", value=True)
                            if cur_bool else questionary.Choice("  no   (disabled)", value=False),
                    style=QSTYLE,
                ).ask()
            except KeyboardInterrupt:
                continue

        elif ftype == "select" and options:
            try:
                new_val = questionary.select(
                    f"New value for {label}:",
                    choices=[questionary.Choice(f"  {o}", value=o) for o in options]
                            + [questionary.Separator(),
                               questionary.Choice("  ← Cancel", value=None)],
                    style=QSTYLE,
                ).ask()
            except KeyboardInterrupt:
                continue

        elif ftype == "password":
            try:
                new_val = questionary.password(
                    f"New {label}  (leave blank to keep current):",
                    style=QSTYLE,
                ).ask()
            except KeyboardInterrupt:
                continue
            if not new_val:
                continue

        else:
            try:
                new_val = questionary.text(
                    f"New value for {label}:",
                    default=current,
                    style=QSTYLE,
                ).ask()
            except KeyboardInterrupt:
                continue

        if new_val is None:
            continue

        save_config_value(fkey, new_val)
        reload_config()
        _ok(f"[bold]{label}[/] updated.")
        time.sleep(0.7)  # brief flash confirmation before redraw


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


# ── Main loop ─────────────────────────────────────────────────────────────────

def run_repl() -> None:
    """Entry point — called by `ctf` with no arguments."""
    from ctf_copilot.core.session import get_current_session

    while True:
        try:
            _clear()
            _banner()

            session = get_current_session()

            if session:
                _session_header(session)
                choice = _session_menu_ask(session.name)

                if choice is None:   continue   # Esc / Ctrl+C → redraw menu
                if choice == "q":    break

                if   choice == "1":   _action_get_hint(session.id)
                elif choice == "2":   _action_add_note(session.id)
                elif choice == "3":   _action_view_notes(session.id)
                elif choice == "4":   _action_intel(session.id)
                elif choice == "5":   _action_findings(session.id)
                elif choice == "6":   _action_dashboard(session.id)
                elif choice == "7":   _action_history(session.id)
                elif choice == "8":   _action_writeup(session.id)
                elif choice == "v":   _action_vaults()
                elif choice == "s":   _action_edit_config()
                elif choice == "stop": _action_stop_session()
                elif choice == "done": _action_complete_session()

            else:
                choice = _main_menu_ask()

                if choice is None:   continue   # Esc / Ctrl+C → redraw menu
                if choice == "q":    break

                if   choice == "1":  _action_start_session()
                elif choice == "2":  _action_resume_session()
                elif choice == "3":  _action_manage_sessions()
                elif choice == "4":  _action_vaults()
                elif choice == "s":  _action_edit_config()

        except KeyboardInterrupt:
            continue
        except Exception as exc:
            _clear()
            _banner()
            _err(str(exc))
            _pause()

    _clear()
    _console.print(f"\n  [{DIM}]Goodbye.[/]\n")
