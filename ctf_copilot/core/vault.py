"""
CTF Copilot — Knowledge Vaults.

Vaults are named, persistent collections of notes that exist OUTSIDE individual
CTF sessions.  Use them to build a personal knowledge base that grows over time:
  "Web Techniques", "Active Directory", "Buffer Overflow", "Privilege Escalation"

Each vault has an interactive REPL (`ctf vault open <name>`) where you can add,
search, and delete entries without leaving the terminal.

CLI:
  ctf vault                        # list all vaults
  ctf vault new "Web Techniques"   # create a vault
  ctf vault open "Web Techniques"  # enter interactive REPL
  ctf vault show "Web Techniques"  # dump entries (non-interactive)
  ctf vault add "Web Techniques" "SQLi: ' OR 1=1 --"
  ctf vault rm "Web Techniques"    # delete a vault
"""

from __future__ import annotations

import io
import sys
from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ctf_copilot.core.database import get_connection

# Console for vault output
_console = Console(
    file=io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "buffer") else sys.stdout,
    highlight=False,
)

# Vault display color palette (rotates for variety) — aesthetic hex colors
_PALETTE = ["#8B5CF6", "#10B981", "#60A5FA", "#F59E0B", "#F472B6"]


# ---------------------------------------------------------------------------
# Vault CRUD
# ---------------------------------------------------------------------------

def create_vault(name: str, description: str = "", color: str = "") -> dict:
    """
    Create a new vault.  Raises ValueError if the name is already taken.
    Returns the new vault as a dict.
    """
    # Auto-assign a color from the palette based on vault count
    if not color:
        with get_connection() as conn:
            cnt = conn.execute("SELECT COUNT(*) AS n FROM vaults").fetchone()["n"]
        color = _PALETTE[cnt % len(_PALETTE)]

    with get_connection() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO vaults (name, description, color) VALUES (?, ?, ?)",
                (name.strip(), description.strip(), color),
            )
            vault_id = cur.lastrowid
        except Exception:
            raise ValueError(f"A vault named '{name}' already exists.")

        row = conn.execute(
            "SELECT * FROM vaults WHERE id = ?", (vault_id,)
        ).fetchone()
    return dict(row)


def list_vaults() -> list[dict]:
    """Return all vaults with entry counts, ordered by updated_at desc."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT v.id, v.name, v.description, v.color, v.created_at, v.updated_at,
                   COUNT(e.id) AS entry_count
            FROM vaults v
            LEFT JOIN vault_entries e ON e.vault_id = v.id
            GROUP BY v.id
            ORDER BY v.updated_at DESC
            """,
        ).fetchall()
    return [dict(r) for r in rows]


def get_vault(name: str) -> Optional[dict]:
    """Return a vault by name, or None if not found."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM vaults WHERE name = ? COLLATE NOCASE", (name,)
        ).fetchone()
    return dict(row) if row else None


def delete_vault(name: str) -> bool:
    """Delete a vault and all its entries.  Returns True if deleted."""
    with get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM vaults WHERE name = ? COLLATE NOCASE", (name,)
        )
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Entry CRUD
# ---------------------------------------------------------------------------

def add_entry(vault_id: int, text: str, tags: str = "") -> int:
    """Add an entry to a vault.  Returns the new entry ID."""
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO vault_entries (vault_id, text, tags) VALUES (?, ?, ?)",
            (vault_id, text.strip(), tags.strip()),
        )
        entry_id = cur.lastrowid
        conn.execute(
            "UPDATE vaults SET updated_at = datetime('now') WHERE id = ?",
            (vault_id,),
        )
    return entry_id  # type: ignore[return-value]


def get_entries(vault_id: int) -> list[dict]:
    """Return all entries in a vault, oldest first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, text, tags, created_at FROM vault_entries "
            "WHERE vault_id = ? ORDER BY created_at ASC",
            (vault_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_entry(vault_id: int, entry_id: int) -> bool:
    """Delete a vault entry.  Returns True if deleted."""
    with get_connection() as conn:
        cur = conn.execute(
            "DELETE FROM vault_entries WHERE id = ? AND vault_id = ?",
            (entry_id, vault_id),
        )
        if cur.rowcount:
            conn.execute(
                "UPDATE vaults SET updated_at = datetime('now') WHERE id = ?",
                (vault_id,),
            )
        return cur.rowcount > 0


def search_entries(vault_id: int, query: str) -> list[dict]:
    """Full-text search within a vault (case-insensitive substring match)."""
    q = f"%{query.lower()}%"
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, text, tags, created_at FROM vault_entries "
            "WHERE vault_id = ? AND (LOWER(text) LIKE ? OR LOWER(tags) LIKE ?) "
            "ORDER BY created_at ASC",
            (vault_id, q, q),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Rich display helpers
# ---------------------------------------------------------------------------

def _render_entries(entries: list[dict], color: str, title: str = "") -> None:
    """Print a formatted entry table to the console."""
    if not entries:
        _console.print("  [dim]No entries yet.  Type a note and press Enter to add one.[/]")
        return

    t = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {color}",
        padding=(0, 1),
        expand=False,
    )
    t.add_column("#",       style=f"bold {color}", width=4, no_wrap=True)
    t.add_column("Entry",   style="white", ratio=1)
    t.add_column("Tags",    style="dim",   width=18, no_wrap=True)
    t.add_column("Added",   style="dim",   width=14, no_wrap=True)

    for e in entries:
        ts = e.get("created_at", "")[:16].replace("T", " ")[5:]  # MM-DD HH:MM
        tags = e.get("tags") or ""
        t.add_row(str(e["id"]), e["text"], tags, ts)

    if title:
        _console.print(Rule(f"[bold {color}]{title}[/]", style=color))
    _console.print(t)


def _vault_banner(vault: dict) -> None:
    """Print the vault header panel."""
    color       = vault.get("color", "cyan")
    name        = vault["name"]
    desc        = vault.get("description") or ""
    created     = (vault.get("created_at") or "")[:10]
    entry_count = vault.get("entry_count", "?")

    lines = Text()
    lines.append(f"  📚  {name}\n", style=f"bold {color}")
    if desc:
        lines.append(f"  {desc}\n", style="dim")
    lines.append(f"\n  {entry_count} entries  •  Created {created}\n", style="dim")
    # Render command hints as proper Rich markup
    lines.append_text(Text.from_markup(
        "  [dim]Just type to add an entry.  "
        "Commands: [/dim][bold]del #[/bold]  [bold]search[/bold]  "
        "[bold]ls[/bold]  [bold]help[/bold]  [bold]exit[/bold]"
    ))

    _console.print()
    _console.print(Panel(
        lines,
        border_style=color,
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))
    _console.print()


# ---------------------------------------------------------------------------
# Interactive REPL
# ---------------------------------------------------------------------------

_HELP_TEXT = """\
  Commands available inside a vault:
  ─────────────────────────────────────────────────
  <text>            Add a new entry (just type it)
  add <text>        Same as above
  del <#>           Delete entry by number
  search <term>     Search entries
  ls  / list        Refresh and show all entries
  clear             Clear the screen
  help  / ?         Show this help
  exit  / quit  / q Leave the vault
  ─────────────────────────────────────────────────
"""


def run_vault_repl(vault_name: str) -> None:
    """
    Enter the interactive vault REPL.

    The REPL loop reads one line at a time.  Bare text is treated as a new
    entry.  Prefixed commands (del, search, etc.) perform their action.
    """
    vault = get_vault(vault_name)
    if not vault:
        _console.print(
            f"\n  [bold red]Vault '[/][red]{vault_name}[/][bold red]' not found.[/]\n"
            f"  Create it first: [bold]ctf vault new \"{vault_name}\"[/]\n"
        )
        return

    color    = vault.get("color", "cyan")
    vault_id = vault["id"]

    # Initial view
    entries  = get_entries(vault_id)
    vault["entry_count"] = len(entries)
    _vault_banner(vault)
    _render_entries(entries, color)
    _console.print()

    # REPL loop
    while True:
        try:
            raw = input(f"  vault:{vault['name']} ❯ ").strip()
        except (EOFError, KeyboardInterrupt):
            _console.print()
            break

        if not raw:
            continue

        parts   = raw.split(None, 1)
        command = parts[0].lower()
        arg     = parts[1].strip() if len(parts) > 1 else ""

        # ── exit ──────────────────────────────────────────────────────────
        if command in ("exit", "quit", "q"):
            break

        # ── help ──────────────────────────────────────────────────────────
        elif command in ("help", "?"):
            _console.print(_HELP_TEXT)

        # ── ls / list ─────────────────────────────────────────────────────
        elif command in ("ls", "list"):
            entries = get_entries(vault_id)
            _console.print()
            _render_entries(entries, color)
            _console.print()

        # ── clear ─────────────────────────────────────────────────────────
        elif command == "clear":
            _console.clear()
            entries = get_entries(vault_id)
            vault["entry_count"] = len(entries)
            _vault_banner(vault)
            _render_entries(entries, color)
            _console.print()

        # ── del <#> ───────────────────────────────────────────────────────
        elif command == "del":
            if not arg:
                _console.print("  [yellow]Usage: del <entry-number>[/]")
                continue
            try:
                entry_id = int(arg)
            except ValueError:
                _console.print("  [red]Please provide a numeric entry ID.[/]")
                continue
            if delete_entry(vault_id, entry_id):
                _console.print(f"  [bold green]✓[/]  Entry [bold]#{entry_id}[/] deleted.")
            else:
                _console.print(f"  [red]Entry #{entry_id} not found.[/]")

        # ── search <term> ─────────────────────────────────────────────────
        elif command == "search":
            if not arg:
                _console.print("  [yellow]Usage: search <term>[/]")
                continue
            results = search_entries(vault_id, arg)
            _console.print()
            if results:
                _render_entries(results, color, title=f"Search: {arg}")
            else:
                _console.print(f"  [dim]No entries matching '[bold]{arg}[/]'[/]")
            _console.print()

        # ── add <text> ────────────────────────────────────────────────────
        elif command == "add":
            text = arg if arg else raw
            if not text:
                _console.print("  [yellow]Usage: add <text>[/]")
                continue
            eid = add_entry(vault_id, text)
            entries = get_entries(vault_id)
            _console.print(
                f"  [bold {color}]✓[/]  Entry [bold]#{eid}[/] added. "
                f"[dim]({len(entries)} total)[/]"
            )

        # ── bare text → add as new entry ──────────────────────────────────
        else:
            eid = add_entry(vault_id, raw)
            entries = get_entries(vault_id)
            _console.print(
                f"  [bold {color}]✓[/]  Entry [bold]#{eid}[/] added. "
                f"[dim]({len(entries)} total)[/]"
            )

    # Exit message
    _console.print(
        f"\n  [dim]Left vault [bold {color}]{vault['name']}[/][dim]. "
        "All entries saved.[/]\n"
    )
