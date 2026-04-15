#!/usr/bin/env bash
# CTF Copilot — Shell initialisation script
#
# Usage (add to your ~/.bashrc or run manually before a CTF session):
#   source ~/.ctf_copilot/ctf-init.sh
#
# What this does:
#   1. Detects your shell (bash / zsh)
#   2. Sources the appropriate hook file
#   3. Injects transparent aliases so nmap, gobuster, etc.
#      are silently wrapped without changing your workflow

_CTF_HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -- Detect shell and load the right hook ------------------------------------
if [ -n "$ZSH_VERSION" ]; then
    # shellcheck disable=SC1090
    source "$_CTF_HOOKS_DIR/zsh_hook.zsh"
elif [ -n "$BASH_VERSION" ]; then
    # shellcheck disable=SC1090
    source "$_CTF_HOOKS_DIR/bash_hook.sh"
else
    echo "[CTF Copilot] Warning: unsupported shell. Hooks not loaded." >&2
fi

# -- Tool aliases (transparent wrappers) ------------------------------------
# These replace the real command with a wrapper that captures output
# while still behaving identically to the original tool.

_ctf_wrap() {
    local tool="$1"; shift
    if command -v "ctf-wrap" &>/dev/null; then
        ctf-wrap --tool "$tool" -- "$@"
    else
        command "$tool" "$@"
    fi
}

alias nmap='_ctf_wrap nmap'
alias gobuster='_ctf_wrap gobuster'
alias ffuf='_ctf_wrap ffuf'
alias nikto='_ctf_wrap nikto'
alias sqlmap='_ctf_wrap sqlmap'
alias hydra='_ctf_wrap hydra'
alias curl='_ctf_wrap curl'
alias feroxbuster='_ctf_wrap feroxbuster'
alias wfuzz='_ctf_wrap wfuzz'

echo "[CTF Copilot] Shell hooks loaded. Run 'ctf status' to check your session."
