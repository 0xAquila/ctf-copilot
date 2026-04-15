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
    # AI backend — Claude (default) or local Ollama
    api_key: str = ""                        # Anthropic API key
    ai_model: str = "claude-sonnet-4-6"      # Claude model to use
    ai_max_tokens: int = 512                  # Max tokens per hint response
    ai_rate_limit_seconds: float = 5.0        # Min seconds between AI calls
    ai_backend: str = "claude"               # "claude" | "ollama"
    ollama_endpoint: str = "http://localhost:11434"  # Ollama server URL
    ollama_model: str = "llama3.2"           # Ollama model to use

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
    data = _load_yaml()
    data.update(_load_env())  # env vars override file

    # Filter to only known fields
    valid_fields = Config.__dataclass_fields__.keys()
    filtered = {k: v for k, v in data.items() if k in valid_fields}
    return Config(**filtered)


def write_default_config() -> None:
    """Write a commented default config.yaml on first run."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if _CONFIG_FILE.exists():
        return
    template = """\
# CTF Copilot Configuration
# Documentation: https://github.com/your-repo/ctf-copilot

# ── Claude API (default backend) ────────────────────────────────────────────
# Anthropic API key (required when ai_backend is "claude")
# Get yours at https://console.anthropic.com
api_key: ""

# Claude model to use for hints
ai_model: "claude-sonnet-4-6"

# Maximum tokens per AI hint response
ai_max_tokens: 512

# Minimum seconds between AI calls (cost/rate control)
ai_rate_limit_seconds: 5.0

# ── LLM Backend ─────────────────────────────────────────────────────────────
# "claude"  - Use Anthropic Claude API (requires api_key above)
# "ollama"  - Use a local Ollama model (free, offline, no API key needed)
#             Install Ollama: https://ollama.com  then: ollama pull llama3.2
ai_backend: "claude"

# Ollama server endpoint (only used when ai_backend is "ollama")
ollama_endpoint: "http://localhost:11434"

# Ollama model to use (run `ollama list` to see installed models)
ollama_model: "llama3.2"

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


# Module-level singleton — import and use directly
config: Config = load_config()
