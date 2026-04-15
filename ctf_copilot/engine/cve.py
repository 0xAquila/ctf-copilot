"""
CVE Enrichment Engine — NVD API integration with local DB cache.

After nmap discovers versioned services, this module queries the NIST NVD
CVE database for known vulnerabilities. Results are cached locally for 7 days
so repeated scans don't hit the API.

Cache strategy:
  - Table: vulnerabilities (service, version, cve_id, cvss_score, description)
  - TTL:   7 days from cached_at
  - Miss:  query NVD API, store results (or empty marker if no CVEs found)
  - Hit:   return cached rows immediately

Rate limits (NVD API):
  - Without key: 5 requests per 30 seconds
  - With key:    50 requests per 30 seconds (set nvd_api_key in config.yaml)
"""

from __future__ import annotations

import json
import time
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from ctf_copilot.core.database import get_connection, init_db
from ctf_copilot.core.config import config


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CVEResult:
    cve_id:      str
    cvss_score:  Optional[float]
    description: str
    service:     str
    version:     str
    source:      str = "nvd"


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

_CACHE_TTL_DAYS = 7
_EMPTY_MARKER   = "__NO_CVE__"   # stored when NVD returns zero results


def _cache_key_exists(service: str, version: str) -> bool:
    """Return True if a fresh cache entry exists for this service+version."""
    try:
        with get_connection() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) FROM vulnerabilities
                WHERE service = ? AND version = ?
                  AND datetime(cached_at) > datetime('now', ? )
                """,
                (service.lower(), version, f"-{_CACHE_TTL_DAYS} days"),
            ).fetchone()
        return (row[0] > 0) if row else False
    except Exception:
        return False


def _get_cached(service: str, version: str) -> list[CVEResult]:
    """Return cached CVE results for a service+version (empty list = no CVEs)."""
    try:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT cve_id, cvss_score, description FROM vulnerabilities
                WHERE service = ? AND version = ?
                  AND cve_id != ?
                  AND datetime(cached_at) > datetime('now', ?)
                ORDER BY cvss_score DESC NULLS LAST
                """,
                (service.lower(), version, _EMPTY_MARKER,
                 f"-{_CACHE_TTL_DAYS} days"),
            ).fetchall()
        return [
            CVEResult(
                cve_id=r["cve_id"],
                cvss_score=r["cvss_score"],
                description=r["description"] or "",
                service=service,
                version=version,
            )
            for r in rows
        ]
    except Exception:
        return []


def _store_results(
    service: str,
    version: str,
    results: list[CVEResult],
) -> None:
    """Persist CVE results to the local cache (upsert by service+version+cve_id)."""
    try:
        init_db()
        svc_lower = service.lower()
        with get_connection() as conn:
            if not results:
                # Store an empty marker so we don't re-query until TTL expires
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vulnerabilities
                        (service, version, cve_id, cvss_score, description, source)
                    VALUES (?, ?, ?, NULL, NULL, 'nvd')
                    """,
                    (svc_lower, version, _EMPTY_MARKER),
                )
            else:
                for r in results:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO vulnerabilities
                            (service, version, cve_id, cvss_score, description, source)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (svc_lower, version, r.cve_id,
                         r.cvss_score, r.description, r.source),
                    )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# NVD API query
# ---------------------------------------------------------------------------

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_RESULTS_PER_PAGE = 5


def _query_nvd(service: str, version: str) -> list[CVEResult]:
    """
    Query NIST NVD for CVEs matching service+version.
    Returns up to _NVD_RESULTS_PER_PAGE results sorted by CVSS score.
    Returns empty list on any error (network, parse, rate limit).
    """
    keyword = f"{service} {version}".strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(_NVD_RESULTS_PER_PAGE),
    }
    url = f"{_NVD_BASE}?{urllib.parse.urlencode(params)}"

    headers = {"User-Agent": "ctf-copilot/1.0"}
    if config.nvd_api_key:
        headers["apiKey"] = config.nvd_api_key

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, OSError, Exception):
        return []

    results: list[CVEResult] = []
    for item in data.get("vulnerabilities", []):
        cve_node = item.get("cve", {})
        cve_id   = cve_node.get("id", "")
        if not cve_id:
            continue

        # Extract English description
        desc = ""
        for d in cve_node.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:300]
                break

        # Extract CVSS base score (prefer v3.1 > v3.0 > v2)
        cvss: Optional[float] = None
        metrics = cve_node.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                try:
                    cvss = float(
                        metrics[key][0]["cvssData"]["baseScore"]
                    )
                    break
                except (KeyError, IndexError, TypeError, ValueError):
                    pass

        results.append(CVEResult(
            cve_id=cve_id,
            cvss_score=cvss,
            description=desc,
            service=service,
            version=version,
        ))

    # Sort by CVSS descending (None last)
    results.sort(
        key=lambda r: r.cvss_score if r.cvss_score is not None else -1,
        reverse=True,
    )
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_cves(service: str, version: str) -> list[CVEResult]:
    """
    Return CVEs for a service+version.

    Checks the local DB cache first. On a cache miss, queries NVD and stores
    the results. Returns empty list if no CVEs found or on error.

    Args:
        service: Canonical service name (e.g. "ftp", "http", "mysql")
        version: Version string (e.g. "vsftpd 2.3.4", "Apache httpd 2.4.49")
    """
    if not service or not version:
        return []

    # Cache hit
    if _cache_key_exists(service, version):
        return _get_cached(service, version)

    # Cache miss — query NVD
    # Brief delay to respect rate limits (5 req/30s without key = ~6s between calls)
    time.sleep(0.5)
    results = _query_nvd(service, version)
    _store_results(service, version, results)
    return results


def enrich_session_services(session_id: int) -> list[tuple[str, list[CVEResult]]]:
    """
    Query NVD for all versioned services in a session that aren't cached yet.

    Returns a list of (version_string, [CVEResult]) tuples for services
    where CVEs were found.  Silently skips services with no version info.

    This is called from wrap_cmd.py after a successful nmap parse.
    """
    try:
        init_db()
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT service, version FROM services
                WHERE session_id = ? AND version IS NOT NULL AND version != ''
                """,
                (session_id,),
            ).fetchall()
    except Exception:
        return []

    enriched: list[tuple[str, list[CVEResult]]] = []
    for row in rows:
        svc     = (row["service"] or "").lower()
        version = row["version"] or ""
        if not svc or not version:
            continue

        # Skip if already in cache
        if _cache_key_exists(svc, version):
            cached = _get_cached(svc, version)
            if cached:
                enriched.append((version, cached))
            continue

        cves = lookup_cves(svc, version)
        if cves:
            enriched.append((version, cves))

    return enriched


def format_cve_hint(cve: CVEResult) -> str:
    """Format a single CVE as a concise hint string for display."""
    score_str = f" (CVSS {cve.cvss_score:.1f})" if cve.cvss_score else ""
    desc = cve.description
    if len(desc) > 150:
        desc = desc[:147] + "..."
    return f"{cve.cve_id}{score_str}: {desc}"
