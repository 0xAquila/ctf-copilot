"""
Pattern Engine -- YAML-driven offline hint matching.

Rules live in ctf_copilot/rules/*.yaml and are loaded once at startup.
Each rule defines:
  - One or more conditions (ALL must match -- AND logic)
  - A hint text to display when matched
  - Confidence score, priority, MITRE ATT&CK technique IDs, and tags

This engine runs before the AI so that obvious, high-confidence patterns
are caught instantly (no API cost, no latency). The AI is called only when
no high-confidence pattern fires for a given trigger.

Condition types:
  service_version  -- port has service whose version matches a substring
  service_port     -- specific port is open (any version)
  service_name     -- service name contains a string (e.g. "http")
  web_endpoint     -- a web finding matches a regex pattern
  web_status       -- web finding matches regex AND has specific status code
  tool_not_used    -- a tool name has NOT been run yet in the session
  tool_used        -- a tool name HAS been run
  has_credentials  -- at least one credential has been found
  no_flags         -- no flags captured yet (avoid hints after completion)
"""

from __future__ import annotations

import importlib.resources
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from ctf_copilot.core.database import get_connection


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PatternMatch:
    rule_id:    str
    rule_name:  str
    hint:       str
    confidence: float
    priority:   int
    mitre:      list[str] = field(default_factory=list)
    tags:       list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).parent.parent / "rules"

_loaded_rules: list[dict] = []
_rules_loaded  = False


def _load_rules() -> list[dict]:
    global _loaded_rules, _rules_loaded
    if _rules_loaded:
        return _loaded_rules

    rules: list[dict] = []
    if not _RULES_DIR.exists():
        _rules_loaded = True
        return rules

    for yaml_file in sorted(_RULES_DIR.glob("*.yaml")):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            for rule in data.get("rules", []):
                # Validate minimum required fields
                if rule.get("id") and rule.get("hint") and rule.get("conditions"):
                    rules.append(rule)
        except Exception as exc:
            import sys
            print(f"[pattern] Failed to load {yaml_file.name}: {exc}", file=sys.stderr)

    _loaded_rules = rules
    _rules_loaded = True
    return rules


def reload_rules() -> int:
    """Force a reload of all rule files. Returns the count of loaded rules."""
    global _rules_loaded
    _rules_loaded = False
    return len(_load_rules())


def get_all_rules() -> list[dict]:
    return _load_rules()


# ---------------------------------------------------------------------------
# Condition matchers
# ---------------------------------------------------------------------------

def _match_service_version(cond: dict, ctx) -> bool:
    """Port with matching service name AND version substring."""
    service_frag = (cond.get("service") or "").lower()
    version_frag = (cond.get("version_contains") or "").lower()
    port_filter  = cond.get("port")

    for svc in ctx.services:
        if port_filter and svc["port"] != port_filter:
            continue
        svc_name = (svc.get("service") or "").lower()
        version  = (svc.get("version")  or "").lower()
        if service_frag and service_frag not in svc_name:
            continue
        if version_frag and version_frag not in version:
            continue
        return True
    return False


def _match_service_port(cond: dict, ctx) -> bool:
    """Any open port matching the given port number."""
    port = cond.get("port")
    return any(s["port"] == port for s in ctx.services)


def _match_service_name(cond: dict, ctx) -> bool:
    """Any service whose name contains the given fragment."""
    fragment = (cond.get("name") or "").lower()
    return any(
        fragment in (s.get("service") or "").lower()
        for s in ctx.services
    )


def _match_web_endpoint(cond: dict, ctx) -> bool:
    """Any web finding whose endpoint matches the given regex."""
    pattern = cond.get("pattern")
    if not pattern:
        return False
    rx = re.compile(pattern, re.IGNORECASE)
    return any(rx.search(wf.get("endpoint", "")) for wf in ctx.web_findings)


def _match_web_status(cond: dict, ctx) -> bool:
    """Web finding matching regex AND specific status code."""
    pattern    = cond.get("pattern")
    status     = cond.get("status_code")
    if not pattern:
        return False
    rx = re.compile(pattern, re.IGNORECASE)
    for wf in ctx.web_findings:
        if rx.search(wf.get("endpoint", "")):
            if status is None or wf.get("status_code") == status:
                return True
    return False


def _match_tool_not_used(cond: dict, ctx) -> bool:
    """The named tool has NOT been run in this session."""
    tool = (cond.get("tool") or "").lower()
    return tool not in {t.lower() for t in ctx.tools_used}


def _match_tool_used(cond: dict, ctx) -> bool:
    """The named tool HAS been run in this session."""
    tool = (cond.get("tool") or "").lower()
    return tool in {t.lower() for t in ctx.tools_used}


def _match_has_credentials(cond: dict, ctx) -> bool:
    return len(ctx.credentials) > 0


def _match_no_flags(cond: dict, ctx) -> bool:
    return len(ctx.flags) == 0


_MATCHERS = {
    "service_version":  _match_service_version,
    "service_port":     _match_service_port,
    "service_name":     _match_service_name,
    "web_endpoint":     _match_web_endpoint,
    "web_status":       _match_web_status,
    "tool_not_used":    _match_tool_not_used,
    "tool_used":        _match_tool_used,
    "has_credentials":  _match_has_credentials,
    "no_flags":         _match_no_flags,
}


def _evaluate_conditions(conditions: list[dict], ctx) -> bool:
    """Return True only if ALL conditions in the list match (AND logic)."""
    for cond in conditions:
        ctype   = cond.get("type", "")
        matcher = _MATCHERS.get(ctype)
        if matcher is None:
            continue   # unknown condition type -- skip, don't fail
        if not matcher(cond, ctx):
            return False
    return True


# ---------------------------------------------------------------------------
# Deduplication against already-fired rules
# ---------------------------------------------------------------------------

def _get_fired_rule_ids(session_id: int) -> set[str]:
    """Return IDs of rules already saved for this session."""
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT rule_name FROM hints WHERE session_id = ? AND source = 'pattern'",
                (session_id,),
            ).fetchall()
        return {r["rule_name"] for r in rows if r["rule_name"]}
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_pattern_engine(
    ctx,
    trigger_command: str = "",
    max_results: int = 3,
) -> list[PatternMatch]:
    """
    Evaluate all loaded rules against the current session context.

    Returns up to `max_results` matching rules, sorted by priority.
    Already-fired rules (for this session) are excluded.

    Args:
        ctx:             SessionContext built by build_context().
        trigger_command: The command that triggered this evaluation (for logging).
        max_results:     Cap on how many matches to return per call.
    """
    rules = _load_rules()
    if not rules:
        return []

    fired_ids   = _get_fired_rule_ids(ctx.session.id)
    matches: list[PatternMatch] = []

    for rule in rules:
        rule_id = rule.get("id", "")

        # Skip already-fired rules
        if rule_id in fired_ids:
            continue

        # Evaluate all conditions
        conditions = rule.get("conditions", [])
        if not conditions:
            continue

        if not _evaluate_conditions(conditions, ctx):
            continue

        matches.append(PatternMatch(
            rule_id    = rule_id,
            rule_name  = rule.get("name", rule_id),
            hint       = rule.get("hint", ""),
            confidence = float(rule.get("confidence", 0.8)),
            priority   = int(rule.get("priority", 2)),
            mitre      = rule.get("mitre", []),
            tags       = rule.get("tags", []),
        ))

    # Sort: priority ASC (1=high first), then confidence DESC
    matches.sort(key=lambda m: (m.priority, -m.confidence))

    return matches[:max_results]
