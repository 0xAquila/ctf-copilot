"""
Pattern engine tests — condition matchers and full rule evaluation.

Uses handcrafted SessionContext objects (no DB) so each test is fast and
deterministic. The reload_rules() call ensures a clean rule state.
"""

from __future__ import annotations

import pytest

from ctf_copilot.engine.pattern import (
    _match_service_version,
    _match_service_port,
    _match_service_name,
    _match_web_endpoint,
    _match_tool_not_used,
    _match_tool_used,
    _match_has_credentials,
    _match_no_flags,
    run_pattern_engine,
    reload_rules,
)
from tests.conftest import make_context


# ===========================================================================
# Individual condition matcher tests
# ===========================================================================

class TestServiceVersionMatcher:

    def test_matches_exact_version(self):
        ctx = make_context(services=[
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd 2.3.4"},
        ])
        cond = {"type": "service_version", "service": "ftp", "version_contains": "vsftpd 2.3.4"}
        assert _match_service_version(cond, ctx) is True

    def test_matches_partial_version(self):
        ctx = make_context(services=[
            {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache httpd 2.4.49 (Debian)"},
        ])
        cond = {"type": "service_version", "service": "http", "version_contains": "2.4.49"}
        assert _match_service_version(cond, ctx) is True

    def test_case_insensitive_match(self):
        ctx = make_context(services=[
            {"port": 21, "protocol": "tcp", "service": "FTP", "version": "vsftpd 2.3.4"},
        ])
        cond = {"type": "service_version", "service": "ftp", "version_contains": "VSFTPD"}
        assert _match_service_version(cond, ctx) is True

    def test_no_match_wrong_version(self):
        ctx = make_context(services=[
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd 3.0.5"},
        ])
        cond = {"type": "service_version", "service": "ftp", "version_contains": "vsftpd 2.3.4"}
        assert _match_service_version(cond, ctx) is False

    def test_no_match_empty_services(self):
        ctx = make_context(services=[])
        cond = {"type": "service_version", "service": "ftp", "version_contains": "vsftpd 2.3.4"}
        assert _match_service_version(cond, ctx) is False


class TestServicePortMatcher:

    def test_matches_open_port(self):
        ctx = make_context(services=[{"port": 445, "protocol": "tcp", "service": "smb", "version": ""}])
        assert _match_service_port({"type": "service_port", "port": 445}, ctx) is True

    def test_no_match_closed_port(self):
        ctx = make_context(services=[{"port": 80, "protocol": "tcp", "service": "http", "version": ""}])
        assert _match_service_port({"type": "service_port", "port": 445}, ctx) is False

    def test_matches_multiple_ports(self):
        ctx = make_context(services=[
            {"port": 80,   "protocol": "tcp", "service": "http",  "version": ""},
            {"port": 3306, "protocol": "tcp", "service": "mysql", "version": ""},
        ])
        assert _match_service_port({"port": 80},   ctx) is True
        assert _match_service_port({"port": 3306}, ctx) is True
        assert _match_service_port({"port": 443},  ctx) is False


class TestServiceNameMatcher:

    def test_matches_http(self):
        ctx = make_context(services=[
            {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache"},
        ])
        assert _match_service_name({"name": "http"}, ctx) is True

    def test_partial_name_match(self):
        ctx = make_context(services=[
            {"port": 445, "protocol": "tcp", "service": "netbios-ssn", "version": "Samba"},
        ])
        # 'netbios' is a fragment of 'netbios-ssn'
        assert _match_service_name({"name": "netbios"}, ctx) is True

    def test_no_match(self):
        ctx = make_context(services=[
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd"},
        ])
        assert _match_service_name({"name": "http"}, ctx) is False


class TestWebEndpointMatcher:

    def test_matches_login_path(self):
        ctx = make_context(web_findings=[
            {"endpoint": "/login.php", "status_code": 200, "method": "GET"},
        ])
        cond = {"pattern": r"/(login|signin|auth|logon)"}
        assert _match_web_endpoint(cond, ctx) is True

    def test_matches_git_directory(self):
        ctx = make_context(web_findings=[
            {"endpoint": "/.git", "status_code": 200, "method": "GET"},
        ])
        cond = {"pattern": r"/\.git"}
        assert _match_web_endpoint(cond, ctx) is True

    def test_no_match(self):
        ctx = make_context(web_findings=[
            {"endpoint": "/about.html", "status_code": 200, "method": "GET"},
        ])
        cond = {"pattern": r"/(login|signin)"}
        assert _match_web_endpoint(cond, ctx) is False

    def test_empty_findings(self):
        ctx = make_context(web_findings=[])
        cond = {"pattern": r"/login"}
        assert _match_web_endpoint(cond, ctx) is False

    def test_case_insensitive(self):
        ctx = make_context(web_findings=[
            {"endpoint": "/LOGIN.PHP", "status_code": 200, "method": "GET"},
        ])
        cond = {"pattern": r"/login"}
        assert _match_web_endpoint(cond, ctx) is True


class TestToolMatchers:

    def test_tool_not_used_when_absent(self):
        ctx = make_context(tools_used={"nmap"})
        assert _match_tool_not_used({"tool": "gobuster"}, ctx) is True

    def test_tool_not_used_when_present(self):
        ctx = make_context(tools_used={"gobuster"})
        assert _match_tool_not_used({"tool": "gobuster"}, ctx) is False

    def test_tool_used_when_present(self):
        ctx = make_context(tools_used={"nmap", "gobuster"})
        assert _match_tool_used({"tool": "nmap"}, ctx) is True

    def test_tool_used_case_insensitive(self):
        ctx = make_context(tools_used={"NMAP"})
        assert _match_tool_used({"tool": "nmap"}, ctx) is True

    def test_tool_not_used_case_insensitive(self):
        ctx = make_context(tools_used={"GOBUSTER"})
        assert _match_tool_not_used({"tool": "gobuster"}, ctx) is False


class TestCredentialAndFlagMatchers:

    def test_has_credentials_true(self):
        ctx = make_context(credentials=[
            {"username": "admin", "password": "admin", "source": "login form"},
        ])
        assert _match_has_credentials({}, ctx) is True

    def test_has_credentials_false(self):
        ctx = make_context(credentials=[])
        assert _match_has_credentials({}, ctx) is False

    def test_no_flags_true(self):
        ctx = make_context(flags=[])
        assert _match_no_flags({}, ctx) is True

    def test_no_flags_false(self):
        ctx = make_context(flags=[{"flag_value": "HTB{test}", "flag_type": "user"}])
        assert _match_no_flags({}, ctx) is False


# ===========================================================================
# Full rule engine integration tests
# ===========================================================================

class TestRunPatternEngine:

    def setup_method(self):
        reload_rules()

    def test_vsftpd_backdoor_fires(self):
        ctx = make_context(services=[
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd 2.3.4"},
        ])
        matches = run_pattern_engine(ctx, max_results=10)
        rule_ids = {m.rule_id for m in matches}
        assert "vsftpd-2.3.4-backdoor" in rule_ids

    def test_vsftpd_confidence_is_high(self):
        ctx = make_context(services=[
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd 2.3.4"},
        ])
        matches = run_pattern_engine(ctx, max_results=10)
        vsftpd = next(m for m in matches if m.rule_id == "vsftpd-2.3.4-backdoor")
        assert vsftpd.confidence >= 0.90

    def test_samba_usermap_fires(self):
        ctx = make_context(services=[
            {"port": 445, "protocol": "tcp", "service": "netbios-ssn",
             "version": "Samba smbd 3.0.20-Debian"},
        ])
        matches = run_pattern_engine(ctx, max_results=10)
        assert any(m.rule_id == "samba-usermap-script" for m in matches)

    def test_apache_cve_fires(self):
        ctx = make_context(services=[
            {"port": 80, "protocol": "tcp", "service": "http",
             "version": "Apache httpd 2.4.49"},
        ])
        matches = run_pattern_engine(ctx, max_results=10)
        assert any(m.rule_id == "apache-2.4.49-path-traversal" for m in matches)

    def test_compound_sqli_fires(self):
        """Login page + MySQL port should trigger compound SQLi rule."""
        ctx = make_context(
            services=[
                {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 5"},
            ],
            web_findings=[
                {"endpoint": "/login.php", "status_code": 200, "method": "GET"},
            ],
        )
        matches = run_pattern_engine(ctx, max_results=10)
        assert any(m.rule_id == "compound-login-sqli-opportunity" for m in matches)

    def test_max_results_respected(self):
        ctx = make_context(services=[
            {"port": 21,   "protocol": "tcp", "service": "ftp",         "version": "vsftpd 2.3.4"},
            {"port": 80,   "protocol": "tcp", "service": "http",        "version": "Apache 2.4.49"},
            {"port": 445,  "protocol": "tcp", "service": "netbios-ssn", "version": "Samba smbd 3.0.20"},
            {"port": 3306, "protocol": "tcp", "service": "mysql",       "version": "MySQL 5.0.51a"},
        ])
        matches = run_pattern_engine(ctx, max_results=2)
        assert len(matches) <= 2

    def test_sorted_by_priority_then_confidence(self):
        ctx = make_context(services=[
            {"port": 21,  "protocol": "tcp", "service": "ftp",  "version": "vsftpd 2.3.4"},
            {"port": 445, "protocol": "tcp", "service": "netbios-ssn", "version": "Samba smbd 3.0.20"},
        ])
        matches = run_pattern_engine(ctx, max_results=10)
        # All returned matches should be priority 1 (critical)
        for m in matches:
            assert m.priority <= 2  # no low-priority rules should outrank high ones

    def test_no_services_no_matches(self):
        ctx = make_context(services=[])
        matches = run_pattern_engine(ctx, max_results=10)
        # Web/compound rules won't fire, service rules won't fire
        # Gap rules (like smb-not-enumerated) won't fire either (no port 445)
        service_rule_ids = {"vsftpd-2.3.4-backdoor", "samba-usermap-script",
                            "apache-2.4.49-path-traversal"}
        matched_ids = {m.rule_id for m in matches}
        assert not service_rule_ids & matched_ids

    def test_winrm_with_creds_fires(self):
        ctx = make_context(
            services=[{"port": 5985, "protocol": "tcp", "service": "wsman", "version": ""}],
            credentials=[{"username": "admin", "password": "Password123", "source": "reuse"}],
        )
        matches = run_pattern_engine(ctx, max_results=10)
        assert any(m.rule_id in ("compound-creds-winrm-available", "winrm-with-creds")
                   for m in matches)

    def test_rules_load_nonzero(self):
        from ctf_copilot.engine.pattern import get_all_rules
        rules = get_all_rules()
        assert len(rules) >= 40
