"""
ctf-log — lightweight command logger, called by the shell hook.

This runs in the background after EVERY terminal command. It must be:
  - Fast     (sub-100ms)
  - Silent   (no output unless --verbose)
  - Resilient (never crash the shell)

Called as:
  ctf-log --command "nmap -sV 10.10.10.1" --exit-code 0 --cwd /home/user --timestamp 2026-04-12T09:00:00Z
"""

from __future__ import annotations

import sys

import click

from ctf_copilot.core.logger import save_command


@click.command("ctf-log", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--command",   "-c", required=True,  help="The command string that was executed")
@click.option("--exit-code", "-e", default=0,      type=int, help="Exit code of the command")
@click.option("--cwd",       "-d", default="",     help="Working directory when command ran")
@click.option("--timestamp", "-t", default="",     help="ISO 8601 timestamp of execution")
@click.option("--verbose",   "-v", is_flag=True,   help="Print confirmation (debug use only)")
def log_cmd(command, exit_code, cwd, timestamp, verbose):
    """
    Record a shell command to the active CTF session.

    This command is called automatically by the shell hook — you do not
    need to run it manually.
    """
    try:
        cmd_id = save_command(
            command=command,
            exit_code=exit_code,
            cwd=cwd,
            timestamp=timestamp,
        )
        if verbose:
            if cmd_id:
                click.echo(f"[ctf-log] Saved command #{cmd_id}: {command[:60]}")
            else:
                click.echo("[ctf-log] No active session — command not logged.")
    except Exception as exc:
        # Silently swallow — never interrupt the user's shell
        if verbose:
            click.echo(f"[ctf-log] Error: {exc}", err=True)
        sys.exit(0)


def main():
    log_cmd()


if __name__ == "__main__":
    main()
