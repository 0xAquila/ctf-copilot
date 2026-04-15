#!/usr/bin/env zsh
# CTF Copilot — Zsh command logger hook
# This file is sourced by ctf-init.sh. Do NOT execute it directly.

_CTF_LAST_CMD=""
_CTF_LAST_CMD_TS=""

# preexec fires just before the command runs — capture command text + timestamp
_ctf_preexec() {
    _CTF_LAST_CMD="$1"
    _CTF_LAST_CMD_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

# precmd fires just before the next prompt — capture exit code + send log
_ctf_precmd() {
    local exit_code=$?

    [[ -z "$_CTF_LAST_CMD" ]]          && return
    [[ "$_CTF_LAST_CMD" == "ctf"* ]]   && return
    [[ "$_CTF_LAST_CMD" == "_ctf_"* ]] && return

    ctf-log \
        --command   "$_CTF_LAST_CMD" \
        --exit-code "$exit_code"     \
        --cwd       "$PWD"           \
        --timestamp "$_CTF_LAST_CMD_TS" \
        2>/dev/null &

    _CTF_LAST_CMD=""
}

# Attach hooks (safe to call multiple times — zsh deduplicates)
autoload -Uz add-zsh-hook
add-zsh-hook preexec _ctf_preexec
add-zsh-hook precmd  _ctf_precmd
