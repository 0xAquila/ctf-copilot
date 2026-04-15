"""
Gobuster output parser.

Supports three gobuster modes:
  dir   — directory/file brute force
  dns   — subdomain enumeration
  vhost — virtual host enumeration

Extracts:
  - Discovered endpoints with status code, size, redirect target
  - DNS records (subdomains)
  - Virtual hosts
"""

from __future__ import annotations

import re

from ctf_copilot.parsers.base import BaseParser, ParseResult, WebFinding


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Dir mode — matches both old and new gobuster output formats:
#   /admin (Status: 200) [Size: 1234]
#   /admin (Status: 301) [--> /admin/]
#   /admin               [Status: 200, Size: 1234, Words: 50, Lines: 10]
_DIR_OLD = re.compile(
    r"^(\/\S*)\s+\(Status:\s*(\d+)\)"
    r"(?:\s+\[-+>\s*(\S+)\])?"        # optional redirect
    r"(?:\s+\[Size:\s*(\d+)\])?",
    re.IGNORECASE,
)
_DIR_NEW = re.compile(
    r"^(\/\S*)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
    re.IGNORECASE,
)
_DIR_REDIRECT = re.compile(r"\[-+>\s*([^\]]+)\]")

# DNS mode:
#   Found: api.target.com
#   api.target.com
_DNS_FOUND = re.compile(r"^(?:Found:\s*)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+)$")

# Vhost mode:
#   Found: dev.target.com (Status: 200) [Size: 12345]
_VHOST_FOUND = re.compile(
    r"^Found:\s+(\S+)\s+\(Status:\s*(\d+)\)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class GobusterParser(BaseParser):
    tool_name = "gobuster"

    def can_parse(self, output: str) -> bool:
        return (
            "Gobuster" in output
            or "Status:" in output      # covers both (Status: and [Status: formats
            or "Found:" in output
        )

    def parse(self, output: str, command: str) -> ParseResult:
        output = self._clean(output)
        cmd_lower = command.lower()

        if " dns " in cmd_lower or "dns " in cmd_lower:
            return self._parse_dns(output)
        if " vhost " in cmd_lower:
            return self._parse_vhost(output)
        return self._parse_dir(output, command)

    # ------------------------------------------------------------------
    # Dir mode
    # ------------------------------------------------------------------

    def _parse_dir(self, output: str, command: str) -> ParseResult:
        findings: list[WebFinding] = []
        seen: set[str] = set()

        # Extract base URL from command for endpoint normalization
        url_match = re.search(r"-u\s+(\S+)", command)
        base_url = url_match.group(1).rstrip("/") if url_match else ""

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            endpoint = status_code = redirect = size = None

            # New format: /path [Status: 200, Size: 1234, ...]
            m = _DIR_NEW.match(line)
            if m:
                endpoint, status_code, size = m.group(1), int(m.group(2)), m.group(3)
                # Check for redirect in the same line
                rd = _DIR_REDIRECT.search(line)
                if rd:
                    redirect = rd.group(1).strip()

            # Old format: /path (Status: 200) [Size: 1234]
            if not endpoint:
                m = _DIR_OLD.match(line)
                if m:
                    endpoint = m.group(1)
                    status_code = int(m.group(2))
                    redirect = m.group(3)

            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)

            notes = ""
            if redirect:
                notes = f"Redirects to: {redirect}"

            findings.append(WebFinding(
                endpoint=endpoint,
                status_code=status_code,
                notes=notes,
            ))

        return self._make_result(web_findings=findings, confidence=0.92)

    # ------------------------------------------------------------------
    # DNS mode
    # ------------------------------------------------------------------

    def _parse_dns(self, output: str) -> ParseResult:
        findings: list[WebFinding] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("=") or line.startswith("["):
                continue
            # Strip "Found: " prefix
            clean = re.sub(r"^Found:\s*", "", line, flags=re.IGNORECASE)
            m = _DNS_FOUND.match(clean.strip())
            if m and clean not in seen:
                seen.add(clean)
                findings.append(WebFinding(
                    endpoint=clean.strip(),
                    notes="DNS subdomain",
                ))

        return self._make_result(web_findings=findings, confidence=0.88)

    # ------------------------------------------------------------------
    # Vhost mode
    # ------------------------------------------------------------------

    def _parse_vhost(self, output: str) -> ParseResult:
        findings: list[WebFinding] = []
        seen: set[str] = set()

        for line in output.splitlines():
            line = line.strip()
            m = _VHOST_FOUND.match(line)
            if m:
                vhost, status_code = m.group(1), int(m.group(2))
                if vhost not in seen:
                    seen.add(vhost)
                    findings.append(WebFinding(
                        endpoint=vhost,
                        status_code=status_code,
                        notes="Virtual host",
                    ))

        return self._make_result(web_findings=findings, confidence=0.90)
