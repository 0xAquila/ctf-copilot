"""
Nmap output parser.

Handles both text (default) and grepable (-oG) output formats.
XML (-oX) support is also included as it carries the richest data.

Extracts:
  - Open ports with service, version, protocol
  - OS detection results
  - NSE script output (http-title, ssl-cert, smb-security-mode, etc.)
  - Banner text
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Optional

from ctf_copilot.parsers.base import BaseParser, ParseResult, ServiceFinding


# ---------------------------------------------------------------------------
# Regex patterns for nmap text output
# ---------------------------------------------------------------------------

# PORT   STATE  SERVICE   VERSION
# 22/tcp open  ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
_PORT_LINE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?$"
)

# OS detection
_OS_LINE      = re.compile(r"^OS details?:\s+(.+)$", re.IGNORECASE)
_OS_GUESS     = re.compile(r"^Aggressive OS guesses?:\s+(.+)$", re.IGNORECASE)
_RUNNING      = re.compile(r"^Running:\s+(.+)$", re.IGNORECASE)

# Script output (NSE)
_SCRIPT_LINE  = re.compile(r"^\|\s+(\S[\w-]+):\s+(.+)$")
_SCRIPT_LAST  = re.compile(r"^\|_\s+(\S[\w-]+):\s+(.+)$")

# Grepable format
_GREP_HOST    = re.compile(r"^Host:\s+(\S+)")
_GREP_PORTS   = re.compile(r"Ports:\s+(.+)")
_GREP_PORT    = re.compile(r"(\d+)/(open|filtered|closed)/(tcp|udp)//([^/]*)//([^/]*)/")

# XML marker
_XML_HEADER   = re.compile(r"<\?xml|<nmaprun")


class NmapParser(BaseParser):
    tool_name = "nmap"

    def can_parse(self, output: str) -> bool:
        return bool(
            "Nmap scan report" in output
            or "PORT" in output and "STATE" in output
            or _XML_HEADER.search(output[:200])
            or "Host:" in output and "Ports:" in output  # grepable
        )

    def parse(self, output: str, command: str) -> ParseResult:
        output = self._clean(output)

        # Choose format
        if _XML_HEADER.search(output[:200]):
            return self._parse_xml(output, command)
        if output.lstrip().startswith("Host:") or "Ports:" in output:
            return self._parse_grepable(output, command)
        return self._parse_text(output, command)

    # ------------------------------------------------------------------
    # Text parser (default nmap output)
    # ------------------------------------------------------------------

    def _parse_text(self, output: str, command: str) -> ParseResult:
        services: list[ServiceFinding] = []
        notes: list[str] = []
        current_service: Optional[ServiceFinding] = None
        current_scripts: dict[str, str] = {}

        def _flush_service():
            nonlocal current_service, current_scripts
            if current_service:
                if current_scripts:
                    current_service.extra["scripts"] = current_scripts
                    # Extract banner from common script keys
                    for key in ("http-title", "ftp-anon", "smtp-commands",
                                "ssh-hostkey", "ssl-cert"):
                        if key in current_scripts:
                            current_service.banner = current_scripts[key][:200]
                            break
                services.append(current_service)
            current_service = None
            current_scripts = {}

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Port line
            m = _PORT_LINE.match(line)
            if m:
                _flush_service()
                port, proto, state, svc_name, version_info = m.groups()
                if state != "open":
                    continue
                version_str = (version_info or "").strip()
                current_service = ServiceFinding(
                    port=int(port),
                    protocol=proto,
                    service=svc_name,
                    version=version_str,
                )
                continue

            # NSE script output
            ms = _SCRIPT_LINE.match(line) or _SCRIPT_LAST.match(line)
            if ms and current_service:
                script_name, script_val = ms.groups()
                current_scripts[script_name.strip()] = script_val.strip()
                continue

            # OS detection
            mo = _OS_LINE.match(line) or _OS_GUESS.match(line) or _RUNNING.match(line)
            if mo:
                notes.append(f"OS: {mo.group(1).split(',')[0].strip()}")
                continue

        _flush_service()

        return self._make_result(
            services=services,
            notes=notes,
            confidence=0.95,
        )

    # ------------------------------------------------------------------
    # Grepable parser (-oG)
    # ------------------------------------------------------------------

    def _parse_grepable(self, output: str, command: str) -> ParseResult:
        services: list[ServiceFinding] = []

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            m_ports = _GREP_PORTS.search(line)
            if not m_ports:
                continue

            ports_str = m_ports.group(1)
            for pm in _GREP_PORT.finditer(ports_str):
                port_num, state, proto, svc_name, version = pm.groups()
                if state != "open":
                    continue
                services.append(ServiceFinding(
                    port=int(port_num),
                    protocol=proto,
                    service=svc_name.strip(),
                    version=version.strip(),
                ))

        return self._make_result(services=services, confidence=0.90)

    # ------------------------------------------------------------------
    # XML parser (-oX)
    # ------------------------------------------------------------------

    def _parse_xml(self, output: str, command: str) -> ParseResult:
        services: list[ServiceFinding] = []
        notes: list[str] = []

        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            # Fall back to text parser on malformed XML
            return self._parse_text(output, command)

        for host in root.findall("host"):
            # OS detection
            os_el = host.find("os")
            if os_el is not None:
                match = os_el.find("osmatch")
                if match is not None:
                    notes.append(f"OS: {match.get('name', '')} (accuracy {match.get('accuracy', '?')}%)")

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", 0))
                proto    = port_el.get("protocol", "tcp")

                svc_el  = port_el.find("service")
                svc     = svc_el.get("name", "")        if svc_el is not None else ""
                product = svc_el.get("product", "")     if svc_el is not None else ""
                version = svc_el.get("version", "")     if svc_el is not None else ""
                extra   = svc_el.get("extrainfo", "")   if svc_el is not None else ""

                version_str = " ".join(filter(None, [product, version, extra])).strip()

                # NSE scripts
                scripts: dict[str, str] = {}
                for script_el in port_el.findall("script"):
                    scripts[script_el.get("id", "")] = script_el.get("output", "")[:200]

                banner = ""
                for key in ("http-title", "ftp-anon", "ssl-cert", "ssh-hostkey"):
                    if key in scripts:
                        banner = scripts[key][:200]
                        break

                services.append(ServiceFinding(
                    port=port_num,
                    protocol=proto,
                    service=svc,
                    version=version_str,
                    banner=banner,
                    extra={"scripts": scripts} if scripts else {},
                ))

        return self._make_result(
            services=services,
            notes=notes,
            confidence=0.99,  # XML is most reliable
        )
