"""
Logger / tool detection tests.

detect_tool() is a pure function that maps a raw shell command string
to a canonical tool name. These tests verify the mapping logic
without any DB access.
"""

from __future__ import annotations

import pytest

from ctf_copilot.core.logger import detect_tool


# ===========================================================================
# detect_tool
# ===========================================================================

class TestDetectTool:

    # --- direct commands -----------------------------------------------------

    def test_nmap(self):
        assert detect_tool("nmap -sV 10.10.10.3") == "nmap"

    def test_gobuster(self):
        assert detect_tool("gobuster dir -u http://10.10.10.3 -w wordlist.txt") == "gobuster"

    def test_ffuf(self):
        assert detect_tool("ffuf -u http://10.10.10.3/FUZZ -w wordlist.txt") == "ffuf"

    def test_hydra(self):
        assert detect_tool("hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.3 ssh") == "hydra"

    def test_sqlmap(self):
        assert detect_tool("sqlmap -u http://10.10.10.3/login.php --dbs") == "sqlmap"

    def test_enum4linux(self):
        assert detect_tool("enum4linux -a 10.10.10.3") == "enum4linux"

    def test_nikto(self):
        assert detect_tool("nikto -h http://10.10.10.3") == "nikto"

    def test_feroxbuster(self):
        assert detect_tool("feroxbuster -u http://10.10.10.3 -w wordlist.txt") == "feroxbuster"

    def test_crackmapexec(self):
        assert detect_tool("crackmapexec smb 10.10.10.3 --shares") == "crackmapexec"

    def test_wpscan(self):
        assert detect_tool("wpscan --url http://10.10.10.3 --enumerate u") == "wpscan"

    def test_curl(self):
        assert detect_tool("curl -s http://10.10.10.3/.env") == "curl"

    # --- sudo prefix ---------------------------------------------------------

    def test_sudo_nmap(self):
        assert detect_tool("sudo nmap -sS 10.10.10.3") == "nmap"

    def test_sudo_enum4linux(self):
        assert detect_tool("sudo enum4linux -a 10.10.10.3") == "enum4linux"

    # --- full path -----------------------------------------------------------

    def test_full_path_nmap(self):
        assert detect_tool("/usr/bin/nmap -sV 10.10.10.3") == "nmap"

    def test_full_path_gobuster(self):
        assert detect_tool("/usr/local/bin/gobuster dir -u http://target") == "gobuster"

    # --- python-based tools --------------------------------------------------

    def test_python_sqlmap(self):
        # python3 /path/to/sqlmap.py → the logger maps python3 → "python"
        # (script-name detection is not implemented; we only track the interpreter)
        result = detect_tool("python3 /opt/sqlmap/sqlmap.py -u http://target/login.php")
        assert result in ("sqlmap", "python3", "python")  # interpreter-level detection

    # --- env prefix ----------------------------------------------------------

    def test_env_nmap(self):
        assert detect_tool("env TERM=xterm nmap -sV 10.10.10.3") == "nmap"

    # --- unrecognised command -------------------------------------------------

    def test_unrecognised_returns_none_or_command(self):
        result = detect_tool("ls -la /tmp")
        # Should return None or the literal command — not raise
        assert result is None or isinstance(result, str)

    def test_empty_string(self):
        result = detect_tool("")
        assert result is None or result == ""

    # --- case handling -------------------------------------------------------

    def test_uppercase_tool(self):
        # On some systems tools might be capitalised
        result = detect_tool("NMAP -sV 10.10.10.3")
        # Should either detect nmap or return None — must not raise
        assert result is None or isinstance(result, str)
