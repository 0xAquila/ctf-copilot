"""
Parser unit tests — feed sample tool output, assert structured results.

Each parser is instantiated directly and tested with realistic sample strings
captured from actual tool runs. No DB access required.
"""

from __future__ import annotations

import pytest

from ctf_copilot.parsers.nmap_parser    import NmapParser
from ctf_copilot.parsers.gobuster_parser import GobusterParser
from ctf_copilot.parsers.ffuf_parser    import FfufParser

from tests.conftest import (
    NMAP_TEXT, NMAP_GREPABLE, NMAP_XML,
    GOBUSTER_DIR_NEW, GOBUSTER_DIR_OLD, GOBUSTER_DNS,
    FFUF_JSON, FFUF_TEXT,
)


# ===========================================================================
# NmapParser
# ===========================================================================

class TestNmapParser:

    def setup_method(self):
        self.parser = NmapParser()

    # --- can_parse -----------------------------------------------------------

    def test_can_parse_text(self):
        assert self.parser.can_parse(NMAP_TEXT) is True

    def test_can_parse_grepable(self):
        assert self.parser.can_parse(NMAP_GREPABLE) is True

    def test_can_parse_xml(self):
        assert self.parser.can_parse(NMAP_XML) is True

    def test_can_parse_rejects_gobuster(self):
        assert self.parser.can_parse(GOBUSTER_DIR_NEW) is False

    def test_can_parse_rejects_empty(self):
        assert self.parser.can_parse("") is False

    # --- text format ---------------------------------------------------------

    def test_text_port_count(self):
        result = self.parser.parse(NMAP_TEXT, "nmap -sV 10.10.10.3")
        assert len(result.services) == 6

    def test_text_port_numbers(self):
        result = self.parser.parse(NMAP_TEXT, "nmap -sV 10.10.10.3")
        ports = {s.port for s in result.services}
        assert ports == {21, 22, 80, 139, 445, 3306}

    def test_text_service_names(self):
        result = self.parser.parse(NMAP_TEXT, "nmap -sV 10.10.10.3")
        by_port = {s.port: s for s in result.services}
        assert by_port[21].service  == "ftp"
        assert by_port[80].service  == "http"
        assert by_port[3306].service == "mysql"

    def test_text_versions_captured(self):
        result = self.parser.parse(NMAP_TEXT, "nmap -sV 10.10.10.3")
        by_port = {s.port: s for s in result.services}
        assert "vsftpd 2.3.4"       in by_port[21].version
        assert "Apache httpd 2.2.8" in by_port[80].version
        assert "MySQL 5.0.51a"      in by_port[3306].version

    def test_text_protocol_default_tcp(self):
        result = self.parser.parse(NMAP_TEXT, "nmap -sV 10.10.10.3")
        assert all(s.protocol == "tcp" for s in result.services)

    def test_text_not_empty(self):
        result = self.parser.parse(NMAP_TEXT, "nmap -sV 10.10.10.3")
        assert not result.is_empty

    # --- grepable format -----------------------------------------------------

    def test_grepable_port_count(self):
        result = self.parser.parse(NMAP_GREPABLE, "nmap -oG - 10.10.10.3")
        assert len(result.services) == 4

    def test_grepable_ports_correct(self):
        result = self.parser.parse(NMAP_GREPABLE, "nmap -oG - 10.10.10.3")
        ports = {s.port for s in result.services}
        assert {21, 22, 80, 3306} == ports

    def test_grepable_version_captured(self):
        result = self.parser.parse(NMAP_GREPABLE, "nmap -oG - 10.10.10.3")
        by_port = {s.port: s for s in result.services}
        assert "vsftpd 2.3.4" in by_port[21].version

    # --- XML format ----------------------------------------------------------

    def test_xml_port_count(self):
        result = self.parser.parse(NMAP_XML, "nmap -oX out.xml 10.10.10.3")
        assert len(result.services) == 2

    def test_xml_ports_correct(self):
        result = self.parser.parse(NMAP_XML, "nmap -oX out.xml 10.10.10.3")
        ports = {s.port for s in result.services}
        assert ports == {21, 80}

    def test_xml_version_captured(self):
        result = self.parser.parse(NMAP_XML, "nmap -oX out.xml 10.10.10.3")
        by_port = {s.port: s for s in result.services}
        assert "2.3.4"  in by_port[21].version
        assert "2.4.49" in by_port[80].version

    # --- edge cases ----------------------------------------------------------

    def test_no_ports_returns_empty(self):
        output = "Nmap scan report for 10.10.10.1\nHost is up.\nNmap done: 0 hosts up"
        result = self.parser.parse(output, "nmap 10.10.10.1")
        assert result.is_empty

    def test_summary_mentions_port_count(self):
        result = self.parser.parse(NMAP_TEXT, "nmap -sV 10.10.10.3")
        assert "6" in result.summary() or "port" in result.summary().lower()


# ===========================================================================
# GobusterParser
# ===========================================================================

class TestGobusterParser:

    def setup_method(self):
        self.parser = GobusterParser()

    # --- can_parse -----------------------------------------------------------

    def test_can_parse_new_format(self):
        assert self.parser.can_parse(GOBUSTER_DIR_NEW) is True

    def test_can_parse_old_format(self):
        assert self.parser.can_parse(GOBUSTER_DIR_OLD) is True

    def test_can_parse_dns(self):
        assert self.parser.can_parse(GOBUSTER_DNS) is True

    def test_rejects_nmap(self):
        assert self.parser.can_parse(NMAP_TEXT) is False

    # --- directory mode (new format) -----------------------------------------

    def test_dir_new_endpoint_count(self):
        result = self.parser.parse(GOBUSTER_DIR_NEW, "gobuster dir -u http://10.10.10.3")
        assert len(result.web_findings) == 4

    def test_dir_new_status_codes(self):
        result = self.parser.parse(GOBUSTER_DIR_NEW, "gobuster dir -u http://10.10.10.3")
        by_ep = {w.endpoint: w for w in result.web_findings}
        assert by_ep["/login.php"].status_code  == 200
        assert by_ep["/admin"].status_code      == 301
        assert by_ep["/.git"].status_code       == 403
        assert by_ep["/backup"].status_code     == 200

    def test_dir_new_endpoints_start_with_slash(self):
        result = self.parser.parse(GOBUSTER_DIR_NEW, "gobuster dir -u http://10.10.10.3")
        assert all(w.endpoint.startswith("/") for w in result.web_findings)

    # --- directory mode (old format) -----------------------------------------

    def test_dir_old_endpoint_count(self):
        result = self.parser.parse(GOBUSTER_DIR_OLD, "gobuster dir -u http://10.10.10.3")
        assert len(result.web_findings) == 3

    def test_dir_old_status_codes(self):
        result = self.parser.parse(GOBUSTER_DIR_OLD, "gobuster dir -u http://10.10.10.3")
        by_ep = {w.endpoint: w for w in result.web_findings}
        assert by_ep["/login.php"].status_code == 200

    # --- DNS mode ------------------------------------------------------------

    def test_dns_subdomain_count(self):
        result = self.parser.parse(GOBUSTER_DNS, "gobuster dns -d example.com")
        # DNS results stored as web findings with subdomain as endpoint
        assert len(result.web_findings) == 3

    def test_dns_endpoints_populated(self):
        result = self.parser.parse(GOBUSTER_DNS, "gobuster dns -d example.com")
        endpoints = {w.endpoint for w in result.web_findings}
        assert "api.example.com"  in endpoints
        assert "mail.example.com" in endpoints

    # --- not_empty / summary -------------------------------------------------

    def test_not_empty(self):
        result = self.parser.parse(GOBUSTER_DIR_NEW, "gobuster dir -u http://10.10.10.3")
        assert not result.is_empty

    def test_summary_contains_count(self):
        result = self.parser.parse(GOBUSTER_DIR_NEW, "gobuster dir -u http://10.10.10.3")
        assert "4" in result.summary() or "endpoint" in result.summary().lower()


# ===========================================================================
# FfufParser
# ===========================================================================

class TestFfufParser:

    def setup_method(self):
        self.parser = FfufParser()

    # --- can_parse -----------------------------------------------------------

    def test_can_parse_json(self):
        assert self.parser.can_parse(FFUF_JSON) is True

    def test_can_parse_text(self):
        assert self.parser.can_parse(FFUF_TEXT) is True

    def test_rejects_nmap(self):
        assert self.parser.can_parse(NMAP_TEXT) is False

    # --- JSON mode -----------------------------------------------------------

    def test_json_finding_count(self):
        result = self.parser.parse(FFUF_JSON, "ffuf -u http://10.10.10.3/FUZZ -w wordlist.txt")
        assert len(result.web_findings) == 3

    def test_json_status_codes(self):
        result = self.parser.parse(FFUF_JSON, "ffuf -u http://10.10.10.3/FUZZ -w wordlist.txt")
        by_ep = {w.endpoint: w for w in result.web_findings}
        assert by_ep["/login.php"].status_code  == 200
        assert by_ep["/admin"].status_code      == 301
        assert by_ep["/phpmyadmin"].status_code == 200

    def test_json_endpoints_are_paths(self):
        result = self.parser.parse(FFUF_JSON, "ffuf -u http://10.10.10.3/FUZZ -w wordlist.txt")
        # Endpoints should be paths (/foo), not full URLs
        assert all(w.endpoint.startswith("/") for w in result.web_findings)

    # --- text mode -----------------------------------------------------------

    def test_text_finding_count(self):
        result = self.parser.parse(FFUF_TEXT, "ffuf -u http://10.10.10.3/FUZZ -w wordlist.txt")
        assert len(result.web_findings) == 3

    def test_text_status_codes(self):
        result = self.parser.parse(FFUF_TEXT, "ffuf -u http://10.10.10.3/FUZZ -w wordlist.txt")
        codes = {w.status_code for w in result.web_findings}
        assert 200 in codes
        assert 301 in codes

    # --- empty output --------------------------------------------------------

    def test_empty_output(self):
        result = self.parser.parse("", "ffuf -u http://example.com/FUZZ")
        assert result.is_empty

    def test_no_results_json(self):
        result = self.parser.parse('{"results": []}', "ffuf -u http://example.com/FUZZ")
        assert result.is_empty
