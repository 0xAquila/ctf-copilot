"""
Hint display interface -- Rich terminal renderer.

Formats AI and pattern-engine hints into high-visibility terminal panels
that stand out from normal tool output without being intrusive.

Display modes (from config.hint_mode):
  cli     -- print a Rich panel to stderr immediately (default)
  silent  -- store hint in DB only, no terminal output
"""

from __future__ import annotations

import io
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box


# Write hints to stderr so they don't pollute stdout (tool output goes to stdout)
def _make_console() -> Console:
    if hasattr(sys.stderr, "buffer"):
        stream = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )
    else:
        stream = sys.stderr
    return Console(file=stream, highlight=False)


_console = _make_console()


# ---------------------------------------------------------------------------
# Primary display function
# ---------------------------------------------------------------------------

def show_hint(
    hint_text: str,
    source: str = "ai",
    confidence: Optional[float] = None,
    tool: Optional[str] = None,
    rule_name: Optional[str] = None,
) -> None:
    """
    Render a hint to the terminal.

    Args:
        hint_text:  The hint string to display.
        source:     'ai' or 'pattern' -- affects the panel style.
        confidence: Optional 0.0-1.0 confidence score.
        tool:       The tool that triggered this hint (shown in subtitle).
        rule_name:  Pattern rule name (shown in subtitle for pattern matches).
    """
    if not hint_text or not hint_text.strip():
        return

    # Choose style based on source
    if source in ("ai", "ollama", "groq"):
        if source == "ollama":
            border_style = "bold cyan"
            label        = "Ollama Hint"
        elif source == "groq":
            border_style = "bold green"
            label        = "⚡ Groq Hint"
        else:
            border_style = "bold cyan"
            label        = "Copilot Hint"
        title = f"[{border_style}]{label}[/]"
    elif source == "nvd":
        border_style = "bold red"
        title        = "[bold red]NVD CVE[/]"
    elif source == "searchsploit":
        border_style = "bold magenta"
        title        = "[bold magenta]ExploitDB[/]"
    else:
        border_style = "bold yellow"
        title        = "[bold yellow]Pattern Match[/]"

    # Build subtitle
    subtitle_parts = []
    if rule_name and source in ("pattern", "nvd", "searchsploit"):
        subtitle_parts.append(rule_name)
    elif tool:
        subtitle_parts.append(f"after {tool}")
    if confidence is not None:
        subtitle_parts.append(f"confidence {confidence:.0%}")
    subtitle = "  |  ".join(subtitle_parts) if subtitle_parts else None

    # Build content
    content = Text()
    content.append(f"  {hint_text}", style="white")

    _console.print()
    _console.print(Panel(
        content,
        title=title,
        subtitle=subtitle,
        border_style=border_style,
        box=box.ROUNDED,
        expand=False,
        padding=(0, 1),
    ))
    _console.print()


def show_skip_reason(reason: str, verbose: bool = False) -> None:
    """Print a dim note explaining why a hint was skipped (debug only)."""
    if verbose:
        _console.print(f"[dim][Copilot] Hint skipped: {reason}[/]")


def show_parse_result(tool: str, summary: str) -> None:
    """Print a brief parse confirmation after a tool run."""
    _console.print(
        f"[dim][Copilot] {tool}: {summary}[/]"
    )


def show_flag_alert(flag: str) -> None:
    """High-visibility flag alert."""
    border = "=" * 58
    _console.print(f"\n[bold red]{border}[/]")
    _console.print(f"[bold red]  FLAG DETECTED:[/] [bold yellow]{flag}[/]")
    _console.print(f"[bold red]{border}[/]\n")
