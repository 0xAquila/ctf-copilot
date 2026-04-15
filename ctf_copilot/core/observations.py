"""
Observation Synthesiser -- converts raw findings into actionable insights.

This is the intelligence layer between raw data and the AI. It produces
structured Observation objects by applying knowledge about:

  1. Vulnerable versions         -- known CVEs and backdoors for CTF-common software
  2. Endpoint classification     -- what type of page is this? (login, upload, admin...)
  3. Service attack surface      -- what attack vectors does each service expose?
  4. Coverage gaps               -- what's been found but not yet probed?
  5. Compound patterns           -- combinations that suggest specific attack paths

Phase 6 (Pattern Engine) will load these rules from YAML. For now they live
here as plain Python -- same logic, easily extractable later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctf_copilot.core.context import SessionContext, Observation


# ---------------------------------------------------------------------------
# Vulnerable version database
# (version substring -> {cve, description, priority})
# ---------------------------------------------------------------------------

_VULNERABLE_VERSIONS: list[dict] = [
    # FTP
    {"service": "ftp", "version_re": r"vsftpd 2\.3\.4",
     "cve": "CVE-2011-2523", "priority": 1,
     "text": "vsftpd 2.3.4 contains a backdoor triggered by ':)' in username -- opens shell on port 6200"},
    {"service": "ftp", "version_re": r"ProFTPD 1\.3\.3",
     "cve": "CVE-2010-4221", "priority": 1,
     "text": "ProFTPD 1.3.3 is vulnerable to remote code execution via mod_sql"},
    {"service": "ftp", "version_re": r"wu-ftpd",
     "cve": "CVE-2000-0573", "priority": 2,
     "text": "wu-ftpd has multiple known buffer overflow vulnerabilities"},

    # SSH
    {"service": "ssh", "version_re": r"OpenSSH [34]\.",
     "cve": "", "priority": 2,
     "text": "Older OpenSSH -- check for user enumeration and weak key algorithms"},
    {"service": "ssh", "version_re": r"OpenSSH 7\.2",
     "cve": "CVE-2016-6210", "priority": 2,
     "text": "OpenSSH 7.2 is vulnerable to username enumeration via timing attack"},

    # HTTP / Apache
    {"service": "http", "version_re": r"Apache.* 2\.4\.49",
     "cve": "CVE-2021-41773", "priority": 1,
     "text": "Apache 2.4.49 is vulnerable to path traversal and RCE (CVE-2021-41773/41772)"},
    {"service": "http", "version_re": r"Apache.* 2\.4\.50",
     "cve": "CVE-2021-42013", "priority": 1,
     "text": "Apache 2.4.50 path traversal bypass -- try /.%2e/.%2e/etc/passwd"},
    {"service": "http", "version_re": r"Apache.* 2\.[01]\.",
     "cve": "", "priority": 2,
     "text": "Very old Apache version -- likely contains multiple known vulnerabilities"},
    {"service": "http", "version_re": r"Apache.* 2\.2\.",
     "cve": "", "priority": 2,
     "text": "Apache 2.2.x is EOL -- check for ShellShock, mod_cgi vulnerabilities"},
    {"service": "http", "version_re": r"IIS/?6\.",
     "cve": "CVE-2017-7269", "priority": 1,
     "text": "IIS 6.0 is vulnerable to WebDAV buffer overflow -- check for WebDAV"},
    {"service": "http", "version_re": r"IIS/?5\.",
     "cve": "", "priority": 2,
     "text": "IIS 5.x is extremely outdated -- check for WebDAV and Unicode traversal"},

    # SMB / Samba
    {"service": "smb", "version_re": r"Samba 3\.[0-4]\.",
     "cve": "CVE-2007-2447", "priority": 1,
     "text": "Samba 3.0.x–3.4.x is vulnerable to usermap script RCE (MS08-067 equivalent)"},
    {"service": "smb", "version_re": r"Windows.*2008|Windows.*Vista",
     "cve": "MS17-010", "priority": 1,
     "text": "Potentially vulnerable to EternalBlue (MS17-010) -- try with Metasploit or manually"},
    {"service": "smb", "version_re": r"Windows.*XP|Windows.*2003",
     "cve": "MS08-067", "priority": 1,
     "text": "Windows XP/2003 SMB -- vulnerable to MS08-067 (NetAPI) remote code execution"},

    # MySQL
    {"service": "mysql", "version_re": r"MySQL 5\.0\.",
     "cve": "", "priority": 2,
     "text": "MySQL 5.0.x -- try default credentials (root:root, root:'') and UDF privilege escalation"},
    {"service": "mysql", "version_re": r"MySQL 5\.[56]\.",
     "cve": "", "priority": 2,
     "text": "MySQL 5.5/5.6 -- check for root login without password, writable plugin directory"},

    # Telnet
    {"service": "telnet", "version_re": r".*",
     "cve": "", "priority": 2,
     "text": "Telnet transmits credentials in cleartext -- capture with Wireshark or try default creds"},

    # SMTP
    {"service": "smtp", "version_re": r"Postfix",
     "cve": "", "priority": 3,
     "text": "SMTP open -- enumerate users with VRFY/EXPN commands"},
    {"service": "smtp", "version_re": r".*",
     "cve": "", "priority": 3,
     "text": "SMTP found -- check for open relay, user enumeration, and mail injection"},

    # SNMP
    {"service": "snmp", "version_re": r".*",
     "cve": "", "priority": 2,
     "text": "SNMP found -- try community strings 'public'/'private' with snmpwalk"},

    # Redis
    {"service": "redis", "version_re": r".*",
     "cve": "", "priority": 1,
     "text": "Redis often runs unauthenticated -- try redis-cli and write SSH keys or cron jobs"},

    # MongoDB
    {"service": "mongodb", "version_re": r".*",
     "cve": "", "priority": 1,
     "text": "MongoDB may allow unauthenticated access -- try connecting without credentials"},

    # Elasticsearch
    {"service": "elasticsearch", "version_re": r".*",
     "cve": "", "priority": 2,
     "text": "Elasticsearch may expose data without auth -- try /_cat/indices via HTTP"},

    # Tomcat
    {"service": "http", "version_re": r"Apache-Coyote|Tomcat",
     "cve": "", "priority": 2,
     "text": "Apache Tomcat detected -- check /manager/html with default creds (tomcat:tomcat, admin:admin)"},

    # JBoss
    {"service": "http", "version_re": r"JBoss",
     "cve": "CVE-2017-12149", "priority": 1,
     "text": "JBoss detected -- check for exposed JMX console and deserialisation vulnerabilities"},

    # Shellshock
    {"service": "http", "version_re": r"CGI|cgi",
     "cve": "CVE-2014-6271", "priority": 2,
     "text": "CGI detected -- test for ShellShock vulnerability in User-Agent header"},
]


# ---------------------------------------------------------------------------
# Endpoint classifiers
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS: list[dict] = [
    {"pattern": r"/(admin|administrator|wp-admin|cpanel|phpmyadmin)",
     "label": "Admin panel",
     "text": "Admin panel found -- attempt default/weak credentials",
     "priority": 1, "tags": ["admin", "auth"]},

    {"pattern": r"/(login|signin|auth|authenticate|logon)",
     "label": "Login page",
     "text": "Login form -- test for SQLi, default credentials, and brute force",
     "priority": 1, "tags": ["auth", "sqli", "brute"]},

    {"pattern": r"/(upload|uploads|file|files|media|images)/",
     "label": "Upload endpoint",
     "text": "Upload endpoint found -- test for unrestricted file upload (try .php, .php5, .phtml)",
     "priority": 1, "tags": ["upload", "webshell"]},

    {"pattern": r"\.(php|asp|aspx|jsp|cfm)$",
     "label": "Dynamic page",
     "text": "Dynamic page -- check for SQLi, LFI/RFI, command injection",
     "priority": 2, "tags": ["injection"]},

    {"pattern": r"/(backup|bak|old|\.bak|\.old|dump)",
     "label": "Backup file",
     "text": "Backup/old file found -- may contain source code, credentials, or DB dumps",
     "priority": 1, "tags": ["backup", "disclosure"]},

    {"pattern": r"/(api|v1|v2|graphql|rest|swagger|openapi)",
     "label": "API endpoint",
     "text": "API endpoint -- check for authentication bypass, IDOR, and mass assignment",
     "priority": 2, "tags": ["api", "idor"]},

    {"pattern": r"/(.env|\.git|\.svn|config|configuration|settings|web\.config)",
     "label": "Sensitive file",
     "text": "Sensitive file/directory -- may expose credentials, tokens, or source code",
     "priority": 1, "tags": ["disclosure", "secrets"]},

    {"pattern": r"/(register|signup|create.?account)",
     "label": "Registration page",
     "text": "Registration endpoint -- test for account takeover and privilege escalation",
     "priority": 2, "tags": ["auth"]},

    {"pattern": r"/(shell|cmd|exec|command|terminal|console)",
     "label": "Possible shell",
     "text": "Endpoint name suggests command execution -- investigate immediately",
     "priority": 1, "tags": ["rce", "webshell"]},
]


# ---------------------------------------------------------------------------
# Service attack surface hints
# ---------------------------------------------------------------------------

_SERVICE_HINTS: dict[int, dict] = {
    21:   {"text": "FTP found -- try anonymous login: 'ftp {target}' with user 'anonymous'",
           "tags": ["ftp", "anonymous"], "priority": 2},
    23:   {"text": "Telnet found -- try default credentials for the detected service",
           "tags": ["telnet"], "priority": 2},
    25:   {"text": "SMTP found -- enumerate users with: smtp-user-enum -M VRFY -U users.txt",
           "tags": ["smtp"], "priority": 3},
    53:   {"text": "DNS found -- attempt zone transfer: dig axfr @{target} {domain}",
           "tags": ["dns"], "priority": 2},
    111:  {"text": "RPC/portmapper found -- enumerate: rpcinfo -p {target}",
           "tags": ["rpc"], "priority": 2},
    161:  {"text": "SNMP found -- walk with: snmpwalk -c public -v1 {target}",
           "tags": ["snmp"], "priority": 2},
    389:  {"text": "LDAP found -- enumerate: ldapsearch -x -H ldap://{target} -b '' -s base",
           "tags": ["ldap", "ad"], "priority": 2},
    443:  {"text": "HTTPS found -- check SSL cert for domain names, run nikto over HTTPS",
           "tags": ["https", "ssl"], "priority": 3},
    445:  {"text": "SMB found -- enumerate: enum4linux -a {target} or crackmapexec smb {target}",
           "tags": ["smb"], "priority": 2},
    1433: {"text": "MSSQL found -- try: crackmapexec mssql {target} -u sa -p sa",
           "tags": ["mssql"], "priority": 2},
    2049: {"text": "NFS found -- check exports: showmount -e {target}",
           "tags": ["nfs"], "priority": 1},
    3306: {"text": "MySQL found -- try: mysql -h {target} -u root without password",
           "tags": ["mysql"], "priority": 2},
    5432: {"text": "PostgreSQL found -- try: psql -h {target} -U postgres",
           "tags": ["postgresql"], "priority": 2},
    5985: {"text": "WinRM found -- try evil-winrm if you have credentials",
           "tags": ["winrm", "windows"], "priority": 2},
    6379: {"text": "Redis found -- connect unauthenticated: redis-cli -h {target}",
           "tags": ["redis"], "priority": 1},
    8080: {"text": "Alt-HTTP found -- check for Tomcat manager, Jenkins, or other web apps",
           "tags": ["http", "webapp"], "priority": 2},
    8443: {"text": "Alt-HTTPS found -- check for web application on non-standard port",
           "tags": ["https"], "priority": 2},
    27017: {"text": "MongoDB found -- connect without auth: mongosh {target}",
            "tags": ["mongodb"], "priority": 1},
}


# ---------------------------------------------------------------------------
# Coverage gap detection
# ---------------------------------------------------------------------------

def _detect_gaps(ctx: "SessionContext") -> list["Observation"]:
    """Return observations for services found but not yet explored with tools."""
    from ctf_copilot.core.context import Observation

    gaps = []
    tools = ctx.tools_used

    # Web on 80/443 but no directory brute force
    if ctx.has_web and not ({"gobuster", "ffuf", "feroxbuster", "dirb", "wfuzz"} & tools):
        gaps.append(Observation(
            subject="Web server (no dir bruteforce)",
            text="HTTP server found but no directory enumeration has been run yet",
            category="gap", priority=2, tags=["web", "gobuster"],
        ))

    # Web found but nikto not run
    if ctx.has_web and "nikto" not in tools:
        gaps.append(Observation(
            subject="Nikto not run",
            text="Web server not scanned with nikto -- may reveal vulnerabilities and misconfigs",
            category="gap", priority=3, tags=["web", "nikto"],
        ))

    # SMB found but not enumerated
    if ctx.has_smb and not ({"enum4linux", "smbmap", "smbclient", "crackmapexec"} & tools):
        gaps.append(Observation(
            subject="SMB not enumerated",
            text="SMB service found but not enumerated -- run enum4linux or crackmapexec",
            category="gap", priority=2, tags=["smb"],
        ))

    # FTP found but not tried
    if ctx.has_ftp and "ftp" not in str(tools).lower():
        gaps.append(Observation(
            subject="FTP anonymous login not tested",
            text="FTP service found but anonymous login hasn't been attempted",
            category="gap", priority=2, tags=["ftp"],
        ))

    # MySQL/Postgres found but sqlmap not run (and web exists)
    if ctx.has_sql and ctx.has_web and "sqlmap" not in tools:
        gaps.append(Observation(
            subject="Database + web -- SQLi not tested",
            text="Both a database and web server are present -- test for SQL injection",
            category="gap", priority=2, tags=["sqli"],
        ))

    return gaps


# ---------------------------------------------------------------------------
# Main synthesiser
# ---------------------------------------------------------------------------

def synthesise(ctx: "SessionContext") -> list["Observation"]:
    """
    Build the full list of Observations for a SessionContext.
    Called by build_context() after all data is loaded.
    """
    from ctf_copilot.core.context import Observation

    observations: list[Observation] = []
    target = ctx.target

    # 1. Vulnerable version checks
    for svc in ctx.services:
        svc_name = (svc.get("service") or "").lower()
        version  = svc.get("version") or ""
        port     = svc.get("port")

        for rule in _VULNERABLE_VERSIONS:
            # Match by service name OR port-derived service
            rule_svc = rule["service"]
            svc_matches = (
                rule_svc in svc_name
                or (rule_svc == "smb" and port in (139, 445))
                or (rule_svc == "http" and port in (80, 443, 8080, 8443))
            )
            if not svc_matches:
                continue

            if re.search(rule["version_re"], version, re.IGNORECASE):
                observations.append(Observation(
                    subject=f"Port {port} {svc_name} ({version[:40]})",
                    text=rule["text"],
                    category="vulnerability",
                    priority=rule["priority"],
                    cve=rule.get("cve", ""),
                    tags=["version-vuln"],
                ))
                break  # one match per service is enough

    # 2. Service-level attack surface hints
    for svc in ctx.services:
        port = svc.get("port")
        hint = _SERVICE_HINTS.get(port)
        if hint:
            obs_text = hint["text"].replace("{target}", target)
            observations.append(Observation(
                subject=f"Port {port}",
                text=obs_text,
                category="recommendation",
                priority=hint["priority"],
                tags=hint["tags"],
            ))

    # 3. Endpoint classification
    seen_endpoint_labels: set[str] = set()
    for wf in ctx.web_findings:
        endpoint = wf.get("endpoint", "")
        status   = wf.get("status_code")

        # Skip clearly blocked endpoints
        if status == 404:
            continue

        for ep_rule in _ENDPOINT_PATTERNS:
            if re.search(ep_rule["pattern"], endpoint, re.IGNORECASE):
                label = ep_rule["label"]
                if label in seen_endpoint_labels:
                    continue  # Don't repeat the same type of finding
                seen_endpoint_labels.add(label)
                observations.append(Observation(
                    subject=f"{endpoint} ({label})",
                    text=ep_rule["text"],
                    category="finding",
                    priority=ep_rule["priority"],
                    tags=ep_rule["tags"],
                ))
                break

    # 4. Compound patterns
    # Web + login + no SQLi tool
    has_login_page = any(
        re.search(r"/(login|signin|auth)", wf.get("endpoint", ""), re.IGNORECASE)
        for wf in ctx.web_findings
    )
    has_upload_page = any(
        re.search(r"/(upload|files)", wf.get("endpoint", ""), re.IGNORECASE)
        for wf in ctx.web_findings
    )

    if has_login_page and ctx.has_sql and "sqlmap" not in ctx.tools_used:
        observations.append(Observation(
            subject="Login page + DB service",
            text="Login form and database both present -- strong candidate for SQL injection",
            category="vulnerability",
            priority=1,
            tags=["sqli", "compound"],
        ))

    if has_upload_page and ctx.has_web:
        observations.append(Observation(
            subject="File upload endpoint",
            text="Upload endpoint found -- test bypass: rename shell.php -> shell.php5, shell.phtml, shell.pHp",
            category="vulnerability",
            priority=1,
            tags=["upload", "webshell", "compound"],
        ))

    # Samba usermap script (classic HTB Lame)
    if ctx.has_smb:
        for svc in ctx.services:
            if svc.get("port") in (139, 445):
                version = svc.get("version") or ""
                if re.search(r"Samba 3\.[0-4]\.", version):
                    observations.append(Observation(
                        subject="Samba usermap_script",
                        text=(
                            "Samba 3.0.x: exploit usermap_script via username injection -- "
                            "use 'nohup /bin/sh' trick or Metasploit exploit/multi/samba/usermap_script"
                        ),
                        category="vulnerability",
                        priority=1,
                        cve="CVE-2007-2447",
                        tags=["smb", "rce", "compound"],
                    ))
                    break

    # 5. Coverage gaps
    observations.extend(_detect_gaps(ctx))

    # Sort: priority ASC (1=high first), then category
    observations.sort(key=lambda o: (o.priority, o.category))

    return observations
