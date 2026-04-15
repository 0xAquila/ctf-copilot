"""
AI Reasoning Engine -- Claude API integration.

Responsibilities:
  - Build a structured prompt from the current SessionContext
  - Call the Claude API with prompt caching for efficiency
  - Apply rate limiting so we don't burn tokens on every keystroke
  - Deduplicate hints so the AI never repeats itself
  - Persist the result to the hints table
  - Return a clean HintResult to the caller

The system prompt is injected as a cache-able block (ephemeral cache_control).
The dynamic parts (context + trigger) are in the user turn.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ctf_copilot.core.config import config

# Rate-limit state -- stored in a tiny file so it survives across
# ctf-wrap invocations (each invocation is a separate process).
_RATE_FILE = Path.home() / ".ctf_copilot" / "last_ai_call"

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class HintResult:
    text:       str
    confidence: float = 0.8
    source:     str   = "ai"
    skipped:    bool  = False      # True when rate-limited or deduplicated
    skip_reason: str  = ""         # human-readable reason for skipping


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior penetration tester and CTF mentor with 15+ years of experience.
You are watching a student work through a Capture-The-Flag challenge and providing \
real-time guidance.

YOUR ROLE:
- Observe what they have discovered and what they have tried
- Provide ONE focused, actionable hint for their next logical step
- Push them to think -- do not do the work for them
- Be specific to the actual versions, services, and endpoints in the context

STRICT RULES:
1. ONE hint only. No bullet lists. No preamble like "Great job!" or "I see that...".
2. Be specific: reference the actual service name, version number, endpoint, or CVE ID.
3. Suggest direction, not the full solution. Say "investigate X" not "run: exploit X".
4. If a known CVE directly applies, mention it by ID.
5. If a coverage gap is obvious (e.g. SMB found but not enumerated), point to it.
6. Maximum 3 sentences. Concise and direct.
7. NEVER repeat a hint that is already listed under "HINTS ALREADY GIVEN".
8. If the context is sparse (early recon stage), ask one guiding question instead.
9. Do not suggest running nmap if nmap output is already in the context.
10. Do not output markdown formatting -- plain text only.\
"""

_USER_TEMPLATE = """\
SESSION CONTEXT:
{context_block}

HINTS ALREADY GIVEN IN THIS SESSION (do not repeat or paraphrase these):
{prior_hints}

TRIGGER -- what the user just ran:
{trigger}

Based on the context, what is the single most valuable next step this student \
should investigate? Be specific and concise (max 3 sentences, plain text).\
"""


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

def _is_rate_limited() -> tuple[bool, float]:
    """
    Return (is_limited, seconds_remaining).
    Reads and writes a timestamp file to track the last API call time.
    """
    min_gap = config.ai_rate_limit_seconds
    _RATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    if _RATE_FILE.exists():
        try:
            last = float(_RATE_FILE.read_text().strip())
            elapsed = time.time() - last
            if elapsed < min_gap:
                return True, min_gap - elapsed
        except (ValueError, OSError):
            pass
    return False, 0.0


def _update_rate_stamp() -> None:
    try:
        _RATE_FILE.write_text(str(time.time()))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _build_user_message(
    context_block: str,
    prior_hints: list[str],
    trigger: str,
) -> str:
    if prior_hints:
        hints_section = "\n".join(f"- {h}" for h in prior_hints)
    else:
        hints_section = "(none yet)"

    return _USER_TEMPLATE.format(
        context_block=context_block,
        prior_hints=hints_section,
        trigger=trigger or "(no specific trigger -- general session review)",
    )


# ---------------------------------------------------------------------------
# Claude API call
# ---------------------------------------------------------------------------

def _call_claude(user_message: str) -> Optional[str]:
    """
    Make a single Claude API call. Returns the response text or None on error.
    Uses prompt caching on the system prompt to reduce latency and cost.
    """
    try:
        import anthropic
    except ImportError:
        return None

    api_key = config.api_key
    if not api_key:
        return None

    client = anthropic.Anthropic(api_key=api_key)

    try:
        response = client.messages.create(
            model=config.ai_model,
            max_tokens=config.ai_max_tokens,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},   # prompt caching
                }
            ],
            messages=[
                {"role": "user", "content": user_message}
            ],
        )
        text = response.content[0].text.strip() if response.content else ""
        return text if text else None

    except anthropic.AuthenticationError:
        return None
    except anthropic.RateLimitError:
        return None
    except anthropic.APIConnectionError:
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Groq API call (free-tier cloud LLM — OpenAI-compatible)
# ---------------------------------------------------------------------------

def _call_groq(user_message: str) -> Optional[str]:
    """
    Call Groq's cloud API via the official groq-python SDK.
    Free tier available at https://console.groq.com/keys

    Returns response text or None on any error (error reason printed to stderr).
    """
    import sys

    try:
        from groq import Groq, AuthenticationError, RateLimitError, APIConnectionError
    except ImportError:
        print("[Copilot] Groq: SDK not installed — run: pip install groq", file=sys.stderr)
        return None

    api_key = config.groq_api_key.strip()
    if not api_key:
        return None

    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=config.groq_model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": user_message},
            ],
            max_tokens=config.ai_max_tokens,
            temperature=0.3,
        )
        text = response.choices[0].message.content or ""
        return text.strip() if text.strip() else None

    except AuthenticationError:
        print("[Copilot] Groq: authentication failed — run 'ctf setup' and re-enter your API key", file=sys.stderr)
        return None
    except RateLimitError:
        print("[Copilot] Groq: rate limited — free tier limit reached, wait a minute", file=sys.stderr)
        return None
    except APIConnectionError as e:
        print(f"[Copilot] Groq: connection error — {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Copilot] Groq: error — {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Ollama API call (local LLM backend — free, offline)
# ---------------------------------------------------------------------------

def _call_ollama(user_message: str) -> Optional[str]:
    """
    Call a local Ollama model. Returns response text or None on error.

    Ollama must be running: `ollama serve`
    Model must be pulled:   `ollama pull llama3.2`
    """
    import json
    import urllib.request
    import urllib.error

    endpoint = config.ollama_endpoint.rstrip("/")
    url = f"{endpoint}/api/generate"

    payload = json.dumps({
        "model": config.ollama_model,
        "prompt": f"{_SYSTEM_PROMPT}\n\n{user_message}",
        "stream": False,
        "options": {"num_predict": config.ai_max_tokens},
    }).encode("utf-8")

    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data.get("response", "").strip()
            return text if text else None
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Dispatcher — routes to Claude or Ollama based on config
# ---------------------------------------------------------------------------

def _call_llm(user_message: str) -> Optional[str]:
    """Route the LLM call to the configured backend."""
    if config.ai_backend == "groq":
        return _call_groq(user_message)
    if config.ai_backend == "ollama":
        return _call_ollama(user_message)
    return _call_claude(user_message)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_hint(
    session_id: int,
    trigger_command: str = "",
    command_id: Optional[int] = None,
    force: bool = False,
) -> HintResult:
    """
    Generate an AI hint for the current session state.

    Args:
        session_id:      The active session ID.
        trigger_command: The command that triggered this hint request.
        command_id:      DB ID of the triggering command (for FK linkage).
        force:           If True, bypass rate limiting (used by `ctf hint`).

    Returns:
        A HintResult. Check `.skipped` and `.skip_reason` to understand
        why a hint may not have been generated.
    """
    from ctf_copilot.core.context import build_context, format_for_ai
    from ctf_copilot.engine.hints import (
        get_hints_for_prompt, is_duplicate, save_hint
    )

    # --- Offline mode ---
    if config.offline_mode:
        return HintResult(
            text="", skipped=True, skip_reason="offline mode enabled"
        )

    # --- API key check (not required for Ollama) ---
    _cloud_backends = {"claude", "groq"}
    if config.ai_backend in _cloud_backends:
        _key = config.groq_api_key if config.ai_backend == "groq" else config.api_key
        _cfg_field = "groq_api_key" if config.ai_backend == "groq" else "api_key"
        if not _key:
            return HintResult(
                text="", skipped=True,
                skip_reason=(
                    f"no API key — run `ctf setup` or set {_cfg_field} "
                    f"in ~/.ctf_copilot/config.yaml"
                )
            )

    # --- Rate limit check ---
    if not force:
        limited, remaining = _is_rate_limited()
        if limited:
            return HintResult(
                text="", skipped=True,
                skip_reason=f"rate limited ({remaining:.0f}s remaining)"
            )

    # --- Build context ---
    ctx = build_context(session_id)
    if not ctx:
        return HintResult(
            text="", skipped=True, skip_reason="session not found"
        )

    # Skip if context is completely empty (nothing discovered yet)
    if not ctx.services and not ctx.web_findings and not ctx.command_summary["total"]:
        return HintResult(
            text="", skipped=True, skip_reason="no data yet -- run nmap first"
        )

    context_block  = format_for_ai(ctx, recent_command=trigger_command)
    prior_hints    = get_hints_for_prompt(session_id)
    user_message   = _build_user_message(context_block, prior_hints, trigger_command)

    # --- Call LLM (Claude or Ollama) ---
    raw_text = _call_llm(user_message)
    if not raw_text:
        backend = config.ai_backend
        return HintResult(
            text="", skipped=True,
            skip_reason=f"{backend} API call failed or returned empty"
        )

    # --- Deduplication ---
    if config.dedup_hints and is_duplicate(session_id, raw_text):
        return HintResult(
            text=raw_text, skipped=True, skip_reason="duplicate hint suppressed"
        )

    # --- Persist ---
    _update_rate_stamp()
    _source_map = {"ollama": "ollama", "groq": "groq"}
    ai_source = _source_map.get(config.ai_backend, "ai")
    save_hint(
        session_id=session_id,
        hint_text=raw_text,
        source=ai_source,
        confidence=0.85,
        command_id=command_id,
    )

    return HintResult(text=raw_text, confidence=0.85, source=ai_source)
