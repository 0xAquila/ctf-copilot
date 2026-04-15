"""
Writeup generator tests — section presence and Markdown correctness.

Tests use synthetic session data built directly in a temp DB (no live
AI calls — use_ai=False throughout).
"""

from __future__ import annotations

import pytest

from ctf_copilot.core.database import get_connection
from ctf_copilot.engine.writeup import generate_writeup, WriteupResult


# ---------------------------------------------------------------------------
# Helper: seed a realistic session
# ---------------------------------------------------------------------------

def _seed_session(tmp_db) -> int:
    """Insert a full test session with services, web findings, and hints."""
    with get_connection(tmp_db) as conn:
        conn.execute(
            """INSERT INTO sessions
               (name, target_ip, target_host, platform, difficulty, status)
               VALUES ('lame', '10.10.10.3', 'lame.htb', 'HackTheBox', 'Easy', 'completed')"""
        )
        sid = conn.execute(
            "SELECT id FROM sessions WHERE name='lame'"
        ).fetchone()["id"]

        conn.execute(
            "INSERT INTO services (session_id, port, protocol, service, version) "
            "VALUES (?,21,'tcp','ftp','vsftpd 2.3.4')", (sid,)
        )
        conn.execute(
            "INSERT INTO services (session_id, port, protocol, service, version) "
            "VALUES (?,80,'tcp','http','Apache httpd 2.2.8')", (sid,)
        )
        conn.execute(
            "INSERT INTO services (session_id, port, protocol, service, version) "
            "VALUES (?,445,'tcp','netbios-ssn','Samba smbd 3.0.20-Debian')", (sid,)
        )
        conn.execute(
            "INSERT INTO web_findings (session_id, endpoint, status_code, method) "
            "VALUES (?,'/login.php',200,'GET')", (sid,)
        )
        conn.execute(
            "INSERT INTO credentials (session_id, username, password, source) "
            "VALUES (?,'msfadmin','msfadmin','login form')", (sid,)
        )
        conn.execute(
            "INSERT INTO flags (session_id, flag_type, flag_value) "
            "VALUES (?,'user','HTB{test_flag_value}')", (sid,)
        )
        conn.execute(
            "INSERT INTO commands (session_id, command, tool, exit_code) "
            "VALUES (?,'nmap -sV 10.10.10.3','nmap',0)", (sid,)
        )
        conn.execute(
            "INSERT INTO commands (session_id, command, tool, exit_code) "
            "VALUES (?,'gobuster dir -u http://10.10.10.3','gobuster',0)", (sid,)
        )
        conn.execute(
            "INSERT INTO hints (session_id, hint_text, source, confidence, rule_name) "
            "VALUES (?,'vsftpd 2.3.4 backdoor CVE-2011-2523. Trigger with smiley.','pattern',0.97,'vsftpd-2.3.4-backdoor')",
            (sid,)
        )
        conn.execute(
            "INSERT INTO hints (session_id, hint_text, source, confidence) "
            "VALUES (?,'Try Samba exploit via Metasploit for quick shell.','ai',0.82)",
            (sid,)
        )
    return sid


# ===========================================================================
# WriteupResult
# ===========================================================================

class TestWriteupResult:

    def test_generate_returns_result(self, tmp_db):
        sid = _seed_session(tmp_db)
        result = generate_writeup(sid, use_ai=False)
        assert isinstance(result, WriteupResult)

    def test_session_name_set(self, tmp_db):
        sid = _seed_session(tmp_db)
        result = generate_writeup(sid, use_ai=False)
        assert result.session_name == "lame"

    def test_ai_enhanced_false_without_api(self, tmp_db):
        sid = _seed_session(tmp_db)
        result = generate_writeup(sid, use_ai=False)
        assert result.ai_enhanced is False

    def test_markdown_is_string(self, tmp_db):
        sid = _seed_session(tmp_db)
        result = generate_writeup(sid, use_ai=False)
        assert isinstance(result.markdown, str)
        assert len(result.markdown) > 100

    def test_invalid_session_raises(self, tmp_db):
        with pytest.raises(ValueError, match="not found"):
            generate_writeup(9999, use_ai=False)


# ===========================================================================
# Markdown section presence
# ===========================================================================

class TestMarkdownSections:

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_db):
        sid = _seed_session(tmp_db)
        self.result = generate_writeup(sid, use_ai=False)
        self.md = self.result.markdown

    def test_title_present(self):
        assert "# CTF Writeup: lame" in self.md

    def test_target_section_present(self):
        assert "## Target Information" in self.md

    def test_target_ip_in_table(self):
        assert "10.10.10.3" in self.md

    def test_enumeration_section_present(self):
        assert "## Enumeration" in self.md

    def test_port_scan_table_present(self):
        assert "### Port Scan Results" in self.md

    def test_services_in_table(self):
        assert "21"     in self.md
        assert "ftp"    in self.md
        assert "vsftpd" in self.md

    def test_web_enumeration_present(self):
        assert "### Web Enumeration" in self.md
        assert "/login.php" in self.md

    def test_vulnerabilities_section_present(self):
        assert "## Vulnerabilities Identified" in self.md

    def test_pattern_rule_in_vulnerabilities(self):
        assert "vsftpd-2.3.4-backdoor" in self.md

    def test_attack_path_section_present(self):
        assert "## Attack Path" in self.md

    def test_credentials_section_present(self):
        assert "## Credentials Found" in self.md
        assert "msfadmin" in self.md

    def test_flags_section_present(self):
        assert "## Flags Captured" in self.md
        assert "HTB{test_flag_value}" in self.md

    def test_tools_section_present(self):
        assert "## Tools Used" in self.md
        assert "nmap"      in self.md
        assert "gobuster"  in self.md

    def test_command_log_present(self):
        assert "## Command Log" in self.md
        assert "nmap -sV 10.10.10.3" in self.md
        assert "```bash" in self.md

    def test_hints_timeline_present(self):
        assert "## Hints Timeline" in self.md
        assert "[PATTERN]" in self.md
        assert "[AI]"      in self.md

    def test_footer_present(self):
        assert "CTF Copilot" in self.md

    def test_platform_in_metadata(self):
        assert "HackTheBox" in self.md

    def test_difficulty_in_metadata(self):
        assert "Easy" in self.md


# ===========================================================================
# save() method
# ===========================================================================

class TestWriteupSave:

    def test_save_creates_file(self, tmp_db, tmp_path):
        sid = _seed_session(tmp_db)
        result = generate_writeup(sid, use_ai=False)
        dest = result.save(output_path=str(tmp_path / "lame_writeup.md"))
        assert dest.exists()

    def test_saved_file_is_utf8(self, tmp_db, tmp_path):
        sid = _seed_session(tmp_db)
        result = generate_writeup(sid, use_ai=False)
        dest = result.save(output_path=str(tmp_path / "lame_writeup.md"))
        content = dest.read_text(encoding="utf-8")
        assert "CTF Writeup" in content

    def test_filename_set_after_save(self, tmp_db, tmp_path):
        sid = _seed_session(tmp_db)
        result = generate_writeup(sid, use_ai=False)
        dest = result.save(output_path=str(tmp_path / "lame_writeup.md"))
        assert result.filename != ""

    def test_default_save_path_in_ctf_writeups(self, tmp_db, tmp_path, monkeypatch):
        """Default saves go to ~/ctf_writeups/ — redirect to tmp_path for test."""
        import ctf_copilot.engine.writeup as wmod
        monkeypatch.setattr(
            wmod.Path, "home", staticmethod(lambda: tmp_path)
        )
        sid = _seed_session(tmp_db)
        result = generate_writeup(sid, use_ai=False)
        dest = result.save()
        assert dest.exists()
        assert "lame" in dest.name
