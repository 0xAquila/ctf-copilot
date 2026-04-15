"""
ffuf output parser.

Supports two output formats:
  JSON  — when user runs: ffuf ... -o output.json -of json
          OR when the JSON blob appears inline in captured output
  Text  — the default coloured terminal output

Extracts:
  - Discovered endpoints / parameters with status, size, words, lines
  - Technology hints from response headers (when present in JSON)
"""

from __future__ import annotations

import json
import re

from ctf_copilot.parsers.base import BaseParser, ParseResult, WebFinding


# ---------------------------------------------------------------------------
# Regex for text output
# ---------------------------------------------------------------------------

# Default text format (with or without ANSI):
#   [Status: 200, Size: 1234, Words: 50, Lines: 10] :: FUZZ => admin
#   admin                   [Status: 200, Size: 1234, Words: 50, Lines: 10]
_TEXT_RESULT = re.compile(
    r"\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)\]"
    r".*?(?:FUZZ\s*=>\s*(\S+)|^(\S+)\s+\[Status:)",
    re.IGNORECASE,
)

# Simpler line matcher: word [Status: 200, Size: ...]
_TEXT_LINE = re.compile(
    r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
    re.IGNORECASE,
)

# Arrow format: [Status: 200, ...] :: FUZZ => value
_ARROW_LINE = re.compile(
    r"\[Status:\s*(\d+),\s*Size:\s*(\d+).*?\]::\s*\S+\s*=>\s*(\S+)",
    re.IGNORECASE,
)


class FfufParser(BaseParser):
    tool_name = "ffuf"

    def can_parse(self, output: str) -> bool:
        return (
            "ffuf" in output.lower()
            or "[Status:" in output
            or ('"results"' in output and '"url"' in output)
        )

    def parse(self, output: str, command: str) -> ParseResult:
        output_clean = self._clean(output)

        # Try JSON first (most structured)
        result = self._try_parse_json(output_clean, command)
        if result and not result.is_empty:
            return result

        return self._parse_text(output_clean, command)

    # ------------------------------------------------------------------
    # JSON parser
    # ------------------------------------------------------------------

    def _try_parse_json(self, output: str, command: str) -> ParseResult | None:
        """
        Try to find and parse a JSON blob in the output.
        ffuf JSON format has a top-level 'results' key.
        """
        # Find the start of a JSON object
        start = output.find('{"')
        if start == -1:
            start = output.find('[\n{')
        if start == -1:
            return None

        # Try to extract valid JSON from that point
        for end in range(len(output), start, -1):
            candidate = output[start:end].strip()
            try:
                data = json.loads(candidate)
                break
            except json.JSONDecodeError:
                continue
        else:
            return None

        findings: list[WebFinding] = []
        seen: set[str] = set()

        # ffuf JSON: {"results": [{url, status, length, words, lines, ...}]}
        results = data.get("results", []) if isinstance(data, dict) else data

        for entry in results:
            if not isinstance(entry, dict):
                continue
            url        = entry.get("url", entry.get("input", {}).get("FUZZ", ""))
            status     = entry.get("status", entry.get("status_code"))
            length     = entry.get("length", entry.get("content_length", 0))
            content_type = entry.get("content-type", "")

            if not url or url in seen:
                continue
            seen.add(url)

            # Normalise URL → endpoint path
            path_match = re.search(r"https?://[^/]+(/.+)", url)
            endpoint = path_match.group(1) if path_match else url

            findings.append(WebFinding(
                endpoint=endpoint,
                status_code=int(status) if status is not None else None,
                content_type=content_type,
                notes=f"Size: {length}",
            ))

        return self._make_result(web_findings=findings, confidence=0.95)

    # ------------------------------------------------------------------
    # Text parser (default terminal output)
    # ------------------------------------------------------------------

    def _parse_text(self, output: str, command: str) -> ParseResult:
        findings: list[WebFinding] = []
        seen: set[str] = set()

        # Extract URL base from command: -u https://target.com/FUZZ
        url_match = re.search(r"-u\s+(\S+)", command)
        base_url  = url_match.group(1) if url_match else ""

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            endpoint = status_code = None

            # Arrow format: [Status: 200, ...] :: FUZZ => value
            m = _ARROW_LINE.match(line)
            if m:
                status_code = int(m.group(1))
                value = m.group(3)
                endpoint = base_url.replace("FUZZ", value) if "FUZZ" in base_url else f"/{value}"

            # Prefix format: /path [Status: 200, ...]
            if not endpoint:
                m = _TEXT_LINE.match(line)
                if m:
                    endpoint = m.group(1)
                    status_code = int(m.group(2))

            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)

            findings.append(WebFinding(
                endpoint=endpoint,
                status_code=status_code,
            ))

        return self._make_result(web_findings=findings, confidence=0.88)
