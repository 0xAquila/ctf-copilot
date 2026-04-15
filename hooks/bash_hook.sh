#!/usr/bin/env bash
# CTF Copilot — Bash command logger hook
# This file is sourced by ctf-init.sh. Do NOT execute it directly.
#
# How it works:
#   - preexec equivalent via trap DEBUG captures the command text
#   - PROMPT_COMMAND fires after each command completes, captures exit code
#   - Both are sent to `ctf-log` (installed as part of the package)

_CTF_LAST_CMD=""
_CTF_LAST_CMD_TS=""

# Capture command text just before it executes (trap DEBUG fires pre-exec)
_ctf_preexec() {
    _CTF_LAST_CMD="$BASH_COMMAND"
    _CTF_LAST_CMD_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
trap '_ctf_preexec' DEBUG

# Fire after each prompt — exit code is available via $?
_ctf_precmd() {
    local exit_code=$?

    # Skip empty commands, the logger itself, and internal shell ops
    [[ -z "$_CTF_LAST_CMD" ]]             && return
    [[ "$_CTF_LAST_CMD" == "ctf"* ]]      && return
    [[ "$_CTF_LAST_CMD" == "_ctf_"* ]]    && return

    # Log asynchronously so we never block the prompt
    ctf-log \
        --command   "$_CTF_LAST_CMD" \
        --exit-code "$exit_code"     \
        --cwd       "$PWD"           \
        --timestamp "$_CTF_LAST_CMD_TS" \
        2>/dev/null &

    _CTF_LAST_CMD=""
}

# Register with PROMPT_COMMAND (preserve existing entries)
if [[ -z "$PROMPT_COMMAND" ]]; then
    PROMPT_COMMAND="_ctf_precmd"
elif [[ "$PROMPT_COMMAND" != *"_ctf_precmd"* ]]; then
    PROMPT_COMMAND="${PROMPT_COMMAND};_ctf_precmd"
fi
