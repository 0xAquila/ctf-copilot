"""
CTF Copilot — Interactive Setup Wizard.

Guides the user through selecting an AI provider, entering their API key,
choosing a model, and validating the configuration — all without any CLI
arguments.  Called via `ctf setup`.

Providers supported:
  [1] Claude API  — Anthropic (paid, best reasoning)
  [2] Groq        — Free-tier cloud (fast, llama / mixtral)
  [3] Ollama      — Local model (offline, private)
  [4] Offline     — Pattern rules only, no AI
"""

from __future__ import annotations

import getpass
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from rich.align import Align
from rich.console import Console
from rich import box
from rich.columns import Columns
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text
from rich.live import Live

# ---------------------------------------------------------------------------
# Console — always stdout so the wizard feels interactive
# ---------------------------------------------------------------------------

import io
_console = Console(
    file=io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "buffer") else sys.stdout,
    highlight=False,
)

# ---------------------------------------------------------------------------
# Provider catalogue
# ---------------------------------------------------------------------------

PROVIDERS = {
    "1": {
        "name":    "Claude API",
        "vendor":  "Anthropic",
        "backend": "claude",
        "color":   "cyan",
        "icon":    "🧠",
        "tier":    "Paid",
        "speed":   "★★★★",
        "models": [
            ("claude-sonnet-4-6",      "Sonnet 4.6   — best balance (recommended)"),
            ("claude-opus-4-6",        "Opus 4.6     — maximum reasoning"),
            ("claude-haiku-4-5-20251001", "Haiku 4.5 — fastest / cheapest"),
        ],
        "key_url":  "https://console.anthropic.com/settings/keys",
        "key_hint": "Starts with  sk-ant-",
        "key_field": "api_key",
    },
    "2": {
        "name":    "Groq",
        "vendor":  "Groq Cloud",
        "backend": "groq",
        "color":   "green",
        "icon":    "⚡",
        "tier":    "Free tier",
        "speed":   "★★★★★",
        "models": [
            ("llama-3.3-70b-versatile", "Llama 3.3 70B  — best accuracy (recommended)"),
            ("llama-3.1-8b-instant",    "Llama 3.1 8B   — ultra-fast"),
            ("mixtral-8x7b-32768",      "Mixtral 8x7B   — 32k context"),
            ("gemma2-9b-it",            "Gemma 2 9B     — lightweight"),
        ],
        "key_url":  "https://console.groq.com/keys",
        "key_hint": "Starts with  gsk_",
        "key_field": "groq_api_key",
    },
    "3": {
        "name":    "Ollama",
        "vendor":  "Local",
        "backend": "ollama",
        "color":   "yellow",
        "icon":    "🏠",
        "tier":    "Free / offline",
        "speed":   "★★★",
        "models": [
            ("llama3.2",   "Llama 3.2   — recommended"),
            ("llama3.1",   "Llama 3.1"),
            ("mistral",    "Mistral 7B"),
            ("codellama",  "Code Llama  — code-focused"),
        ],
        "key_url":  "https://ollama.com",
        "key_hint": "No API key needed",
        "key_field": None,
    },
    "4": {
        "name":    "Offline",
        "vendor":  "No AI",
        "backend": "offline",
        "color":   "dim",
        "icon":    "📴",
        "tier":    "Free",
        "speed":   "N/A",
        "models": [],
        "key_url":  None,
        "key_hint": "No API key needed",
        "key_field": None,
    },
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = """\
  ██████╗████████╗███████╗     ██████╗ ██████╗ ██████╗ ██╗██╗      ██████╗ ████████╗
 ██╔════╝╚══██╔══╝██╔════╝    ██╔════╝██╔═══██╗██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
 ██║        ██║   █████╗      ██║     ██║   ██║██████╔╝██║██║     ██║   ██║   ██║
 ██║        ██║   ██╔══╝      ██║     ██║   ██║██╔═══╝ ██║██║     ██║   ██║   ██║
 ╚██████╗   ██║   ██║         ╚██████╗╚██████╔╝██║     ██║███████╗╚██████╔╝   ██║
  ╚═════╝   ╚═╝   ╚═╝          ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝\
"""


def _print_banner() -> None:
    _console.print()
    _console.print(Panel(
        Align.center(
            Text(_BANNER, style="bold cyan") ,
        ),
        subtitle="[dim cyan]AI-Assisted Penetration Testing Copilot  •  Setup Wizard[/]",
        border_style="cyan",
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))
    _console.print()


# ---------------------------------------------------------------------------
# Provider cards
# ---------------------------------------------------------------------------

def _provider_card(choice: str, info: dict) -> Panel:
    color  = info["color"]
    icon   = info["icon"]
    name   = info["name"]
    vendor = info["vendor"]
    tier   = info["tier"]
    speed  = info["speed"]
    url    = info["key_url"] or "—"

    lines = Text()
    lines.append(f"  {icon}  {name}\n",          style=f"bold {color}")
    lines.append(f"  {vendor}\n",                style="white")
    lines.append(f"\n  Tier:   ", style="dim")
    lines.append(f"{tier}\n",                    style=f"{color}")
    lines.append(f"  Speed:  ", style="dim")
    lines.append(f"{speed}\n",                   style="yellow")
    lines.append(f"\n  {url}\n",                 style=f"dim {color} underline")

    return Panel(
        lines,
        title=f"[bold {color}][{choice}][/]",
        border_style=color,
        box=box.ROUNDED,
        width=36,
        padding=(0, 1),
    )


def _print_provider_menu() -> None:
    cards = [_provider_card(k, v) for k, v in PROVIDERS.items()]
    _console.print(Align.center(Columns(cards, equal=True, expand=False)))
    _console.print()


# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------

def _pick_model(provider: dict) -> str:
    models = provider["models"]
    if not models:
        return ""

    color = provider["color"]
    _console.print(Rule(f"[bold {color}]Select Model[/]", style=color))
    _console.print()
    for i, (mid, desc) in enumerate(models, start=1):
        tag = " [dim](recommended)[/]" if i == 1 else ""
        _console.print(f"  [{color}][{i}][/]  [bold]{mid}[/]  — [dim]{desc}[/]{tag}")
    _console.print()

    while True:
        raw = Prompt.ask(
            f"  [bold {color}]Choose model[/] [dim][1-{len(models)}, default=1][/]",
            default="1",
            console=_console,
        ).strip()
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(models):
                return models[idx][0]
        except ValueError:
            pass
        _console.print("  [red]Please enter a number from the list.[/]")


# ---------------------------------------------------------------------------
# API key input
# ---------------------------------------------------------------------------

def _prompt_key(provider: dict) -> str:
    """Prompt for an API key with masked input. Returns empty string for keyless backends."""
    if provider["key_field"] is None:
        return ""

    color   = provider["color"]
    url     = provider["key_url"]
    hint    = provider["key_hint"]
    name    = provider["name"]

    _console.print(Rule(f"[bold {color}]API Key[/]", style=color))
    _console.print()
    _console.print(f"  [bold {color}]{name}[/] requires an API key.")
    if url:
        _console.print(f"  Generate yours here → [bold {color} underline]{url}[/]")
    _console.print(f"  [dim]{hint}[/]")
    _console.print()

    while True:
        try:
            key = getpass.getpass("  Paste API key (hidden): ").strip()
        except (KeyboardInterrupt, EOFError):
            _console.print("\n  [yellow]Setup cancelled.[/]")
            sys.exit(0)

        if key:
            _console.print(
                f"  [bold green]🔐  Key received.[/] "
                "[dim]Will be AES-128 Fernet encrypted before saving to disk.[/]"
            )
            return key
        _console.print("  [red]Key cannot be empty. Try again (Ctrl-C to cancel).[/]")


# ---------------------------------------------------------------------------
# Key validation via a lightweight test call
# ---------------------------------------------------------------------------

def _validate_claude(key: str, model: str) -> tuple[bool, str]:
    try:
        import anthropic
    except ImportError:
        return False, "anthropic package not installed"

    try:
        client = anthropic.Anthropic(api_key=key)
        resp = client.messages.create(
            model=model,
            max_tokens=16,
            messages=[{"role": "user", "content": "ping"}],
        )
        _ = resp.content[0].text
        return True, ""
    except anthropic.AuthenticationError:
        return False, "Invalid API key — please check and try again."
    except anthropic.RateLimitError:
        return True, "(rate-limited but key is valid)"
    except Exception as exc:
        return False, str(exc)


def _validate_groq(key: str, model: str) -> tuple[bool, str]:
    url = "https://api.groq.com/openai/v1/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 8,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            _ = data["choices"][0]["message"]["content"]
            return True, ""
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            msg = json.loads(body).get("error", {}).get("message", body)
        except Exception:
            msg = body[:120]
        if exc.code == 401:
            return False, f"Invalid API key — {msg}"
        return False, f"HTTP {exc.code}: {msg}"
    except Exception as exc:
        return False, str(exc)


def _validate_ollama(endpoint: str, model: str) -> tuple[bool, str]:
    url = endpoint.rstrip("/") + "/api/generate"
    payload = json.dumps({
        "model": model, "prompt": "ping", "stream": False,
        "options": {"num_predict": 4},
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            _ = data.get("response", "")
            return True, ""
    except Exception as exc:
        return False, str(exc)


def _run_validation(provider: dict, key: str, model: str) -> bool:
    color   = provider["color"]
    backend = provider["backend"]

    _console.print()
    _console.print(f"  [dim]Validating key against {provider['name']} API...[/]")

    # Animated spinner during validation
    ok, err = False, "unknown error"
    with Live(
        Spinner("dots", text=Text(f"  Connecting to {provider['name']}…", style=f"dim {color}")),
        console=_console,
        refresh_per_second=12,
        transient=True,
    ):
        if backend == "claude":
            ok, err = _validate_claude(key, model)
        elif backend == "groq":
            ok, err = _validate_groq(key, model)
        elif backend == "ollama":
            # For Ollama, `key` is actually unused — we validate the endpoint
            from ctf_copilot.core.config import config as _cfg
            ok, err = _validate_ollama(_cfg.ollama_endpoint, model)
        else:
            ok, err = True, ""  # offline — nothing to validate

    if ok:
        _console.print(f"  [bold green]✓  Key validated successfully![/]  {err}")
        return True
    else:
        _console.print(f"  [bold red]✗  Validation failed:[/] {err}")
        return False


# ---------------------------------------------------------------------------
# Ollama endpoint prompt
# ---------------------------------------------------------------------------

def _prompt_ollama_endpoint() -> str:
    _console.print()
    _console.print("  [dim]Default Ollama endpoint: http://localhost:11434[/]")
    endpoint = Prompt.ask(
        "  [bold yellow]Ollama endpoint[/] [dim](press Enter for default)[/]",
        default="http://localhost:11434",
        console=_console,
    ).strip()
    return endpoint or "http://localhost:11434"


# ---------------------------------------------------------------------------
# Save & confirm
# ---------------------------------------------------------------------------

def _save_and_confirm(provider: dict, key: str, model: str, extra: dict) -> None:
    from ctf_copilot.core.config import save_config_value

    color   = provider["color"]
    backend = provider["backend"]

    # Write all changed values
    if backend == "offline":
        save_config_value("offline_mode", "true")
        save_config_value("ai_backend", "claude")   # keep claude as default for future
    else:
        save_config_value("ai_backend", backend)
        save_config_value("offline_mode", "false")

    if provider["key_field"] and key:
        save_config_value(provider["key_field"], key)

    if model:
        model_field = {
            "claude": "ai_model",
            "groq":   "groq_model",
            "ollama": "ollama_model",
        }.get(backend)
        if model_field:
            save_config_value(model_field, model)

    for k, v in extra.items():
        save_config_value(k, v)

    _console.print()
    _console.print(Rule(style=color))
    _console.print()

    # Success panel
    lines = Text()
    lines.append(f"  {provider['icon']}  Provider:  ", style="dim")
    lines.append(f"{provider['name']}\n", style=f"bold {color}")
    if model:
        lines.append("     Model:     ", style="dim")
        lines.append(f"{model}\n", style="white")
    if provider["key_field"] and key:
        masked = ("*" * 8 + key[-4:]) if len(key) > 4 else "****"
        lines.append("     API Key:   ", style="dim")
        lines.append(f"{masked}\n", style="white")
    lines.append("\n")
    if provider["key_field"] and key:
        lines.append("  Security:  ", style="dim")
        lines.append("🔐 Key encrypted (AES-128 Fernet)\n", style="bold green")
        lines.append("  Keyring:   ", style="dim")
        lines.append("~/.ctf_copilot/.keyring  (mode 600)\n", style="dim green")
    lines.append("  Config:    ", style="dim")
    lines.append("~/.ctf_copilot/config.yaml\n", style=f"dim {color}")

    _console.print(Panel(
        lines,
        title="[bold green]✓  Setup Complete[/]",
        border_style="green",
        box=box.DOUBLE_EDGE,
        expand=False,
    ))

    _console.print()
    _console.print("  [bold]Next steps:[/]")
    _console.print("  1. Start a session:  [bold cyan]ctf start <machine-name>[/]")
    _console.print("  2. Activate logging: [bold cyan]source ~/.ctf_copilot/ctf-init.sh[/]")
    _console.print("  3. Run your tools normally — hints appear automatically!")
    _console.print()
    _console.print(f"  [dim]Verify config anytime with:[/] [bold]ctf config[/]")
    _console.print()


# ---------------------------------------------------------------------------
# Main wizard entry point
# ---------------------------------------------------------------------------

def run_setup_wizard() -> None:
    """Run the full interactive setup wizard. No arguments required."""
    _console.print()
    _print_banner()

    # Existing config hint
    cfg_path = Path.home() / ".ctf_copilot" / "config.yaml"
    if cfg_path.exists():
        _console.print(
            "  [dim]Existing config found at [/][dim cyan]~/.ctf_copilot/config.yaml[/][dim]"
            " — only changed values will be updated.[/]\n"
        )

    _console.print(Rule("[bold cyan]Choose Your AI Provider[/]", style="cyan"))
    _console.print()
    _print_provider_menu()

    # --- Provider selection ---
    while True:
        raw = Prompt.ask(
            "  [bold cyan]Your choice[/] [dim][1-4][/]",
            console=_console,
        ).strip()
        if raw in PROVIDERS:
            break
        _console.print("  [red]Please enter 1, 2, 3, or 4.[/]")

    provider = PROVIDERS[raw]
    color    = provider["color"]
    _console.print()
    _console.print(f"  [bold {color}]{provider['icon']}  {provider['name']} selected.[/]")
    _console.print()

    # --- Offline fast-path ---
    if provider["backend"] == "offline":
        _save_and_confirm(provider, "", "", {})
        return

    # --- Ollama: prompt endpoint, no API key ---
    extra: dict = {}
    if provider["backend"] == "ollama":
        endpoint = _prompt_ollama_endpoint()
        extra["ollama_endpoint"] = endpoint

    # --- Model selection ---
    model = _pick_model(provider)

    # --- API key (cloud providers only) ---
    key = ""
    if provider["key_field"]:
        key = _prompt_key(provider)

        # --- Validate ---
        validated = _run_validation(provider, key, model)
        if not validated:
            _console.print()
            retry = Prompt.ask(
                "  [yellow]Save anyway?[/] [dim](key may still work)[/] [dim][y/N][/]",
                default="n",
                console=_console,
            ).strip().lower()
            if retry not in ("y", "yes"):
                _console.print("\n  [yellow]Setup cancelled. Run [bold]ctf setup[/] to try again.[/]\n")
                return
    else:
        # Ollama — validate connectivity
        _run_validation(provider, "", model)

    # --- Save ---
    _save_and_confirm(provider, key, model, extra)
