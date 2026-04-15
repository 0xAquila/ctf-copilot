"""
Dirsearch output parser.

Dirsearch is a web path scanner that prints results in the format:

  [HH:MM:SS] STATUS  -  SIZE  - /path
  [HH:MM:SS] 301  -  319B  - /path  ->  http://target/path/

Extracts discovered endpoints with status codes and redirect targets.
"""

from __future__ import annotations

import re

from ctf_copilot.parsers.base import BaseParser, ParseResult, WebFinding


# Matches the default dirsearch text output line:
#   [12:34:56] 200 -    2KB - /admin/
#   [12:34:56] 301 -  319B - /wp-content  ->  http://target/wp-content/
_LINE_RE = re.compile(
    r"\[\d{2}:\d{2}:\d{2}\]\s+"         # [HH:MM:SS]
    r"(\d{3})\s*-\s*"                    # STATUS_CODE -
    r"[\d.]+\s*\w*\s*-\s*"              # SIZE (e.g. 2KB, 319B, 1.2MB) -
    r"(/\S*)"                            # /path
    r"(?:\s+-+>\s*(\S+))?",             # optional -> redirect
    re.IGNORECASE,
)

# Ignore noise / header lines
_SKIP_RE = re.compile(
    r"^(Target:|Extensions:|Output File:|Threads:|Starting:|"
    r"Task Completed|Error|_\||$|\s*$|\[!]|\[#])",
    re.IGNORECASE,
)


class DirsearchParser(BaseParser):
    tool_name = "dirsearch"

    def can_parse(self, output: str) -> bool:
        return (
            "dirsearch" in output.lower()
            or bool(_LINE_RE.search(output))
        )

    def parse(self, output: str, command: str) -> ParseResult:
        output = self._clean(output)
        findings: list[WebFinding] = []
        seen: set[str] = set()

        for line in output.splitlines():
            m = _LINE_RE.search(line)
            if not m:
                continue

            status_code = int(m.group(1))
            endpoint    = m.group(2).strip()
            redirect    = m.group(3)

            if endpoint in seen:
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

        return self._make_result(web_findings=findings, confidence=0.90)
