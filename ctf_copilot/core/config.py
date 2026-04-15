"""
Configuration loader.

Reads from (in priority order):
  1. Environment variables  (CTF_COPILOT_*)
  2. ~/.ctf_copilot/config.yaml
  3. Built-in defaults

Access via:
    from ctf_copilot.core.config import config
    config.api_key
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_CONFIG_DIR = Path.home() / ".ctf_copilot"
_CONFIG_FILE = _CONFIG_DIR / "config.yaml"


@dataclass
class Config:
    # AI backend — Claude (default), Groq (free cloud), or local Ollama
    api_key: str = ""                        # Anthropic API key
    ai_model: str = "claude-sonnet-4-6"      # Claude model to use
    ai_max_tokens: int = 512                  # Max tokens per hint response
    ai_rate_limit_seconds: float = 5.0        # Min seconds between AI calls
    ai_backend: str = "claude"               # "claude" | "groq" | "ollama"
    ollama_endpoint: str = "http://localhost:11434"  # Ollama server URL
    ollama_model: str = "llama3.2"           # Ollama model to use

    # Groq (free-tier cloud LLM — fast, OpenAI-compatible)
    groq_api_key: str = ""                           # Groq API key
    groq_model: str = "llama-3.3-70b-versatile"     # Groq model to use

    # Behaviour
    hint_mode: str = "cli"                    # cli | tui | notify
    offline_mode: bool = False                # Pattern-only; skip AI calls
    confidence_threshold: float = 0.5         # Min confidence to show a hint
    dedup_hints: bool = True                  # Never repeat the same hint

    # External integrations
    nvd_api_key: str = ""                    # NIST NVD API key (raises rate limit)
    htb_api_key: str = ""                    # HackTheBox API key
    thm_api_key: str = ""                    # TryHackMe API key

    # Storage
    db_path: str = ""                         # Override default DB location


def _load_yaml() -> dict:
    if _CONFIG_FILE.exists():
        with open(_CONFIG_FILE) as f:
            return yaml.safe_load(f) or {}
    return {}


def _load_env() -> dict:
    _bool = lambda v: v.lower() in ("1", "true", "yes")
    mapping = {
        "CTF_COPILOT_API_KEY":              ("api_key", str),
        "CTF_COPILOT_AI_MODEL":             ("ai_model", str),
        "CTF_COPILOT_AI_MAX_TOKENS":        ("ai_max_tokens", int),
        "CTF_COPILOT_AI_RATE_LIMIT":        ("ai_rate_limit_seconds", float),
        "CTF_COPILOT_AI_BACKEND":           ("ai_backend", str),
        "CTF_COPILOT_OLLAMA_ENDPOINT":      ("ollama_endpoint", str),
        "CTF_COPILOT_OLLAMA_MODEL":         ("ollama_model", str),
        "CTF_COPILOT_GROQ_API_KEY":         ("groq_api_key", str),
        "CTF_COPILOT_GROQ_MODEL":           ("groq_model", str),
        "CTF_COPILOT_HINT_MODE":            ("hint_mode", str),
        "CTF_COPILOT_OFFLINE":              ("offline_mode", _bool),
        "CTF_COPILOT_CONFIDENCE_THRESHOLD": ("confidence_threshold", float),
        "CTF_COPILOT_NVD_API_KEY":          ("nvd_api_key", str),
        "CTF_COPILOT_HTB_API_KEY":          ("htb_api_key", str),
        "CTF_COPILOT_DB_PATH":              ("db_path", str),
    }
    result = {}
    for env_key, (attr, cast) in mapping.items():
        val = os.environ.get(env_key)
        if val is not None:
            result[attr] = cast(val)
    return result


def load_config() -> Config:
    """Build a Config by merging defaults < YAML file < environment variables."""
    from ctf_copilot.core.keyring import ENCRYPTED_FIELDS, decrypt

    data = _load_yaml()

    # Decrypt any encrypted fields from the YAML file
    for field in ENCRYPTED_FIELDS:
        if field in data and isinstance(data[field], str):
            data[field] = decrypt(data[field])

    data.update(_load_env())  # env vars override file (never encrypted in env)

    # Filter to only known fields
    valid_fields = Config.__dataclass_fields__.keys()
    filtered = {k: v for k, v in data.items() if k in valid_fields}
    return Config(**filtered)


def install_hooks() -> None:
    """
    Write the shell hook files to ~/.ctf_copilot/ so the user can source them.
    Safe to call on every startup — skips files that already exist.
    """
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    _BASH_HOOK = """\
#!/usr/bin/env bash
# CTF Copilot — Bash command logger hook
# This file is sourced by ctf-init.sh. Do NOT execute it directly.

_CTF_LAST_CMD=""
_CTF_LAST_CMD_TS=""

_ctf_preexec() {
    _CTF_LAST_CMD="$BASH_COMMAND"
    _CTF_LAST_CMD_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
trap '_ctf_preexec' DEBUG

_ctf_precmd() {
    local exit_code=$?
    [[ -z "$_CTF_LAST_CMD" ]]          && return
    [[ "$_CTF_LAST_CMD" == "ctf"* ]]   && return
    [[ "$_CTF_LAST_CMD" == "_ctf_"* ]] && return
    ctf-log \\
        --command   "$_CTF_LAST_CMD" \\
        --exit-code "$exit_code"     \\
        --cwd       "$PWD"           \\
        --timestamp "$_CTF_LAST_CMD_TS" \\
        2>/dev/null &
    _CTF_LAST_CMD=""
}

if [[ -z "$PROMPT_COMMAND" ]]; then
    PROMPT_COMMAND="_ctf_precmd"
elif [[ "$PROMPT_COMMAND" != *"_ctf_precmd"* ]]; then
    PROMPT_COMMAND="${PROMPT_COMMAND};_ctf_precmd"
fi
"""

    _ZSH_HOOK = """\
#!/usr/bin/env zsh
# CTF Copilot — Zsh command logger hook
# This file is sourced by ctf-init.sh. Do NOT execute it directly.

_CTF_LAST_CMD=""
_CTF_LAST_CMD_TS=""

_ctf_preexec() {
    _CTF_LAST_CMD="$1"
    _CTF_LAST_CMD_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

_ctf_precmd() {
    local exit_code=$?
    [[ -z "$_CTF_LAST_CMD" ]]          && return
    [[ "$_CTF_LAST_CMD" == "ctf"* ]]   && return
    [[ "$_CTF_LAST_CMD" == "_ctf_"* ]] && return
    ctf-log \\
        --command   "$_CTF_LAST_CMD" \\
        --exit-code "$exit_code"     \\
        --cwd       "$PWD"           \\
        --timestamp "$_CTF_LAST_CMD_TS" \\
        2>/dev/null &
    _CTF_LAST_CMD=""
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec _ctf_preexec
add-zsh-hook precmd  _ctf_precmd
"""

    _INIT_HOOK = """\
#!/usr/bin/env bash
# CTF Copilot — Shell initialisation script
#
# Add to ~/.bashrc for permanent activation:
#   echo 'source ~/.ctf_copilot/ctf-init.sh' >> ~/.bashrc
#
# Or source manually before a CTF session:
#   source ~/.ctf_copilot/ctf-init.sh

_CTF_HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-${(%):-%x}}")" && pwd)"

if [ -n "$ZSH_VERSION" ]; then
    source "$_CTF_HOOKS_DIR/zsh_hook.zsh"
elif [ -n "$BASH_VERSION" ]; then
    source "$_CTF_HOOKS_DIR/bash_hook.sh"
else
    echo "[CTF Copilot] Warning: unsupported shell." >&2
fi

_ctf_wrap() {
    local tool="$1"; shift
    if command -v "ctf-wrap" &>/dev/null; then
        ctf-wrap --tool "$tool" -- "$@"
    else
        command "$tool" "$@"
    fi
}

for _t in nmap gobuster ffuf nikto sqlmap hydra feroxbuster wfuzz enum4linux; do
    alias "$_t"="_ctf_wrap $_t"
done
unset _t

echo "[CTF Copilot] ✓ Shell hooks active — tools are now being tracked."
"""

    hooks = {
        "bash_hook.sh": _BASH_HOOK,
        "zsh_hook.zsh": _ZSH_HOOK,
        "ctf-init.sh":  _INIT_HOOK,
    }
    for filename, content in hooks.items():
        dest = _CONFIG_DIR / filename
        if not dest.exists():
            dest.write_text(content)
            try:
                import os
                os.chmod(dest, 0o755)
            except OSError:
                pass


def write_default_config() -> None:
    """Write a commented default config.yaml on first run."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    install_hooks()   # ensure hook files are always present
    if _CONFIG_FILE.exists():
        return
    template = """\
# CTF Copilot Configuration
# Run `ctf setup` for the interactive setup wizard.

# ── LLM Backend ─────────────────────────────────────────────────────────────
# "claude"  - Anthropic Claude API  (best reasoning, paid)
# "groq"    - Groq cloud API        (free tier, very fast)
# "ollama"  - Local Ollama model    (free, offline, private)
ai_backend: "claude"

# ── Claude API ───────────────────────────────────────────────────────────────
# Get your key at: https://console.anthropic.com/settings/keys
api_key: ""

# Claude model to use for hints
ai_model: "claude-sonnet-4-6"

# ── Groq API (free tier) ─────────────────────────────────────────────────────
# Get your free key at: https://console.groq.com/keys
groq_api_key: ""

# Groq model to use (free tier options):
#   llama-3.3-70b-versatile  — best accuracy  (recommended)
#   llama-3.1-8b-instant     — fastest
#   mixtral-8x7b-32768       — alternative
groq_model: "llama-3.3-70b-versatile"

# ── Ollama (local) ────────────────────────────────────────────────────────────
# Install: https://ollama.com  then: ollama pull llama3.2
ollama_endpoint: "http://localhost:11434"
ollama_model: "llama3.2"

# ── General AI Settings ───────────────────────────────────────────────────────
# Maximum tokens per AI hint response
ai_max_tokens: 512

# Minimum seconds between AI calls (cost/rate control)
ai_rate_limit_seconds: 5.0

# ── Behaviour ────────────────────────────────────────────────────────────────
# Hint display mode: cli | tui | notify
hint_mode: "cli"

# Set true to skip AI calls and use pattern rules only
offline_mode: false

# Minimum confidence score (0.0-1.0) to show a hint
confidence_threshold: 0.5

# Never repeat the same hint text in a session
dedup_hints: true

# ── External Integrations ────────────────────────────────────────────────────
# NIST NVD API key — optional, raises rate limit from 5/30s to 50/30s
# Get a free key at https://nvd.nist.gov/developers/request-an-api-key
nvd_api_key: ""

# HackTheBox API key — for auto-fetching machine metadata on ctf start
# Get yours at https://app.hackthebox.com/profile/settings
htb_api_key: ""

# TryHackMe API key (future integration)
thm_api_key: ""

# ── Storage ──────────────────────────────────────────────────────────────────
# Optional: custom path for the SQLite database
# Defaults to ~/.ctf_copilot/copilot.db
db_path: ""
"""
    _CONFIG_FILE.write_text(template)


def save_config_value(key: str, value: str) -> None:
    """
    Write a single key=value pair into the config YAML, preserving all other
    existing keys and comments.  API key fields are automatically encrypted
    using Fernet (AES-128) before being written to disk.
    """
    from ctf_copilot.core.keyring import ENCRYPTED_FIELDS, encrypt

    write_default_config()          # ensure file exists
    raw = _CONFIG_FILE.read_text(encoding="utf-8")

    # Encrypt API keys before writing to disk
    stored_value: str = value
    if key in ENCRYPTED_FIELDS and isinstance(value, str) and value:
        stored_value = encrypt(value)

    # Replace an existing `key: "..."` or `key: ''` or `key: value` line
    import re
    pattern = re.compile(
        r'^(' + re.escape(key) + r':\s*).*$',
        re.MULTILINE,
    )
    # Wrap strings in double quotes; booleans/numbers are written bare
    if isinstance(stored_value, bool):
        replacement = rf'\g<1>{str(stored_value).lower()}'
    elif isinstance(stored_value, (int, float)):
        replacement = rf'\g<1>{stored_value}'
    else:
        escaped = stored_value.replace('"', '\\"')
        replacement = rf'\g<1>"{escaped}"'

    if pattern.search(raw):
        new_raw = pattern.sub(replacement, raw, count=1)
    else:
        # Key not present — append it
        section_value = f'"{stored_value}"' if not isinstance(stored_value, (bool, int, float)) else str(stored_value).lower()
        new_raw = raw.rstrip("\n") + f"\n{key}: {section_value}\n"

    _CONFIG_FILE.write_text(new_raw, encoding="utf-8")


# Module-level singleton — import and use directly
config: Config = load_config()
