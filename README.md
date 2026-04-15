<div align="center">

# CTF Copilot

**A real-time AI-assisted penetration testing companion that lives in your terminal.**

Run your tools as normal. CTF Copilot watches, learns, and gives you the next hint — without spoiling the challenge.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-147%20passing-22c55e?style=flat-square&logo=pytest&logoColor=white)](tests/)
[![License](https://img.shields.io/badge/License-MIT-6366f1?style=flat-square)](LICENSE)
[![LLM](https://img.shields.io/badge/LLM-Claude%20%7C%20Ollama-f97316?style=flat-square)](https://anthropic.com)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Parrot%20%7C%20Linux-e11d48?style=flat-square)](https://kali.org)

---

<!-- DEMO VIDEO PLACEHOLDER -->
> **📹 Demo Video**
> 
> *[Insert a short screen recording here — recommended: 60–90 seconds showing a full recon run on an HTB box, with the live dashboard open in a split terminal. Tools: OBS + ffmpeg to gif, or record directly to MP4 and embed with a thumbnail.]*
>
> `![Demo](assets/demo.gif)`

---

</div>

## What Is This?

CTF Copilot is a terminal-native AI assistant for Capture-the-Flag challenges and penetration testing labs. It wraps your existing tools — nmap, gobuster, ffuf, and others — through transparent shell aliases, so your workflow stays exactly the same. In the background, it parses tool output into structured findings, runs an offline pattern engine against 46 hand-crafted rules, queries live vulnerability databases (NVD, ExploitDB), and calls an LLM when it can add something the rules can't.

The result: hints that arrive automatically, timed to what you just discovered, without ever telling you the answer outright.

Built for HTB, TryHackMe, and real-world lab environments. Works fully offline with a local Ollama model.

---

## Screenshots

<!-- SCREENSHOTS PLACEHOLDER -->

> **📸 Screenshots** — *Replace the placeholders below with actual screenshots. Recommended shots:*
> - *The 5-panel live dashboard (`ctf dashboard`) with an active session*
> - *A pattern-match hint panel appearing after an nmap run*
> - *An NVD CVE alert after vsftpd 2.3.4 is detected*
> - *A generated writeup open in a Markdown viewer*
> - *The `ctf timeline` tree view*

```
┌────────────────────────────── CTF Copilot ───────────────────────────────────┐
│  Session: lame  │  Target: 10.10.10.3  │  Platform: HackTheBox  │  [ACTIVE]  │
├──────────────────┬───────────────────────┬─────────────────────────────────────┤
│  Services (6)    │  Web Findings (8)     │  Latest Hints (3)                   │
│  21   ftp        │  200  /login.php      │  [Rule] vsftpd 2.3.4 backdoor       │
│  22   ssh        │  200  /phpmyadmin     │  CVE-2011-2523: trigger ':)' in      │
│  80   http       │  301  /admin          │  username — shell on port 6200       │
│  139  smb        │  403  /.git           │                                     │
│  445  smb        │  200  /backup         │  [NVD] CVE-2011-2523 (CVSS 10.0):   │
│  3306 mysql      │                       │  vsftpd 2.3.4 backdoor RCE          │
│                  │                       │                                     │
│                  │                       │  [AI] Samba 3.0.20 is also          │
│                  │                       │  present — usermap_script is        │
│                  │                       │  likely your primary path in.       │
├──────────────────┴───────────────────────┴─────────────────────────────────────┤
│  Tools: nmap, gobuster  │  Commands: 5  │  Hints: 3  │  Session time: 00:14:32 │
│  Last: gobuster dir -u http://10.10.10.3 -w directory-list-2.3-medium.txt      │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Why I Built This

When I'm working through a CTF box, the mental overhead of context-switching between terminals, browser tabs, and notes breaks my flow. I wanted something that sat *inside* the terminal and thought alongside me — not a cheat sheet, not a walkthrough, but a tool that sees the same output I see and nudges me toward the next logical step.

Everything I built here reflects real frustrations I had during HTB and THM sessions:

- **Pattern engine first, AI second.** Running an API call after every nmap scan is expensive and slow. If vsftpd 2.3.4 is sitting there, a YAML rule can fire in microseconds. The AI gets called only when the rules run out of ideas.
- **Zero workflow change.** I'm not typing `ctf-nmap` instead of `nmap`. Shell aliases handle the interception transparently — muscle memory stays intact.
- **Hints that don't spoil.** The prompt engineering tells the AI to push toward the next step, not give the answer. There's a real difference between "investigate SMB authentication" and "run `exploit/multi/samba/usermap_script`".
- **Offline first.** API keys cost money and networks go down. With Ollama support and 46 offline rules, the core tool works without an internet connection.

---

## Feature Overview

| Feature | Description |
|---------|-------------|
| **Transparent wrapping** | Shell aliases intercept nmap, gobuster, ffuf, etc. — same commands, zero workflow change |
| **Auto-parsing** | Tool output parsed into structured findings (services, endpoints, credentials) automatically |
| **Offline pattern engine** | 46 YAML rules fire instantly — CVE matches, compound paths, coverage gap detection |
| **MITRE ATT&CK tagging** | Every rule tagged with ATT&CK technique IDs for structured reporting |
| **Dual LLM backend** | Claude API *or* local Ollama model — switch with one config line |
| **NVD CVE enrichment** | Live NIST NVD queries after nmap; CVSS-scored CVEs surfaced as alerts |
| **ExploitDB auto-search** | `searchsploit` fires automatically for each versioned service discovered |
| **Live TUI dashboard** | 5-panel auto-refreshing view: services, web findings, hints, stats |
| **Attack timeline** | Tree-view of every command run, with hints attached at each stage |
| **Flag detection** | Scans every tool's output for HTB{}, THM{}, FLAG{}, and MD5-style flags |
| **Writeup generator** | Full Markdown writeup from session data — 10 sections, optional AI narrative |
| **Session management** | Named sessions with full context saved — start, stop, resume |
| **Hint deduplication** | Jaccard similarity (threshold 0.45) ensures you never see the same hint twice |

---

## Architecture

```
[Shell Session]
    │ (alias: nmap → ctf-wrap --tool nmap -- <args>)
    ▼
[ctf-wrap]  ── runs real tool ──► [Tool Output → stdout / terminal]
    │
    ├─► [Command Logger]          ── SQLite DB (commands table)
    │
    ├─► [Parser Registry]         ── auto-discovers *_parser.py files
    │       nmap_parser.py            text / grepable / XML formats
    │       gobuster_parser.py        dir (old+new format), dns, vhost
    │       ffuf_parser.py            JSON (-of json) and terminal text
    │       searchsploit_parser.py    ExploitDB JSON output
    │
    ├─► [CVE Enrichment]          ── fires after nmap parse (nmap only)
    │       engine/cve.py             NVD API → local DB cache (7-day TTL)
    │       engine/cve.py             auto-searchsploit per versioned service
    │
    ├─► [Context Engine]          ── SessionContext rebuilt fresh from DB
    │       core/context.py           5-layer synthesis: CVEs, endpoints,
    │       core/observations.py      services, compound patterns, gaps
    │
    ├─► [Pattern Engine]          ── 46 YAML rules, AND-logic conditions
    │       rules/services.yaml       FTP, SSH, HTTP, SMB, MySQL, Redis...
    │       rules/web.yaml            admin panels, LFI, .git, .env...
    │       rules/compound.yaml       login+DB=SQLi, upload+webshell...
    │
    └─► [AI Reasoning Engine]     ── fires only when patterns are insufficient
            engine/ai.py              Claude API (with prompt caching)
            engine/ai.py              Ollama (local, free, offline)
            engine/hints.py           Jaccard dedup, persistence, retrieval

[ctf dashboard]   ──► Rich Live layout, 5-panel, auto-refresh every 4s
[ctf timeline]    ──► Rich Tree, commands + hints, chronological
[ctf writeup]     ──► 10-section Markdown + optional AI attack narrative
[ctf rules]       ──► browse / filter / reload all 46 pattern rules
[ctf searchsploit]──► manual ExploitDB search, saves to session hints
```

**Storage:** Single SQLite file at `~/.ctf_copilot/copilot.db` — sessions, commands, services, web findings, credentials, flags, hints, CVE cache, all in one place. No server, no Docker, no setup.

**Tech stack:** Python 3.11+ · Click (CLI) · Rich (TUI) · PyYAML (rules) · Anthropic SDK · stdlib only for NVD/Ollama HTTP calls.

---

## Installation

**Requirements:** Python 3.11+, pip, a Linux shell (Kali, Parrot, or any Debian-based distro recommended)

```bash
# Clone the repo
git clone https://github.com/yourusername/ctf-copilot.git
cd ctf-copilot

# Install in editable mode — adds ctf, ctf-log, ctf-wrap to PATH
pip install -e .

# Optional: dev dependencies for running tests
pip install -e ".[dev]"
```

**Configure your API key** (optional — all offline features work without it):

```yaml
# ~/.ctf_copilot/config.yaml  (created automatically on first run)
api_key: "sk-ant-..."
```

**Or use a local Ollama model instead** (free, no API key, works offline):

```bash
# Install Ollama: https://ollama.com
ollama pull llama3.2
ollama serve
```
```yaml
# ~/.ctf_copilot/config.yaml
ai_backend: "ollama"
ollama_model: "llama3.2"
```

---

## Quick Start

```bash
# 1. Start a session
ctf start lame --ip 10.10.10.3 --platform HackTheBox --difficulty Easy

# 2. Activate shell integration (transparent aliases — only needed once per shell session)
source ~/.ctf_copilot/ctf-init.sh

# 3. Run your tools exactly as you normally would — hints appear automatically
nmap -sV -sC 10.10.10.3
gobuster dir -u http://10.10.10.3 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# 4. Open the live dashboard in a second terminal
ctf dashboard

# 5. When you're done, generate a writeup
ctf done
ctf writeup
```

To make shell integration permanent:
```bash
echo 'source ~/.ctf_copilot/ctf-init.sh' >> ~/.bashrc
```

**Wrapped tools:** nmap, gobuster, ffuf, nikto, sqlmap, hydra, curl, feroxbuster, wfuzz, netcat, smbclient, enum4linux, crackmapexec, evil-winrm

---

## Command Reference

### Session Management

| Command | Description |
|---------|-------------|
| `ctf start <name>` | Start a new session |
| `ctf stop` | Pause the current session (progress saved) |
| `ctf resume <name>` | Resume a paused session |
| `ctf done` | Mark session as completed |
| `ctf status` | Show current session details |
| `ctf sessions` | List all sessions |
| `ctf set-target --ip <ip> --host <host> --os Linux` | Update target info |

```bash
# Full start options
ctf start lame --ip 10.10.10.3 --host lame.htb --platform HackTheBox --difficulty Easy
```

---

### Intelligence & Findings

| Command | Description |
|---------|-------------|
| `ctf findings` | Show discovered services (default) |
| `ctf findings --web` | Show web endpoints only |
| `ctf findings --creds` | Show credentials only |
| `ctf findings --all` | Show everything |
| `ctf context` | Full session intelligence: observations, gaps, tools used |
| `ctf context --ai-format` | Print the raw AI prompt block (debug) |
| `ctf history` | Show logged commands |
| `ctf history --tool nmap` | Filter by tool |
| `ctf history --with-output` | Show captured output inline |

---

### Hints

| Command | Description |
|---------|-------------|
| `ctf hint` | Request an AI hint right now (bypasses rate limiter) |
| `ctf hint --context` | Show the context block sent to the AI |
| `ctf hints` | Show hint history for the current session |
| `ctf hints -n 20` | Show last 20 hints |

---

### Vulnerability Research

| Command | Description |
|---------|-------------|
| `ctf searchsploit <query>` | Search ExploitDB via searchsploit |
| `ctf rules` | List all 46 loaded pattern rules |
| `ctf rules --tag rce` | Filter rules by tag |
| `ctf rules --detail` | Show full hint text for each rule |
| `ctf rules --reload` | Force reload YAML files from disk |

```bash
ctf searchsploit vsftpd 2.3.4
ctf searchsploit apache 2.4.49
ctf rules --tag sqli
```

---

### Dashboard & Visualization

| Command | Description |
|---------|-------------|
| `ctf dashboard` | Live auto-refreshing TUI dashboard |
| `ctf dashboard --interval 10` | Refresh every 10 seconds |
| `ctf dashboard --once` | One-shot snapshot (printable/pipeable) |
| `ctf dashboard --session-name lame` | View a specific session |
| `ctf timeline` | Chronological attack timeline with hints attached |
| `ctf timeline --session-name lame` | Timeline for a named session |

**Dashboard controls:** `q` / `Ctrl+C` to exit, `r` to force-refresh.

---

### Writeup Generator

| Command | Description |
|---------|-------------|
| `ctf writeup` | Generate AI-enhanced Markdown writeup |
| `ctf writeup --no-ai` | Offline writeup (no API cost) |
| `ctf writeup --output /tmp/lame.md` | Custom output path |
| `ctf writeup --stdout` | Print to stdout (preview / pipe) |
| `ctf writeup --session-name lame` | Generate for a named session |

Writeups are saved to `~/ctf_writeups/<session>_writeup.md` by default.

**Writeup sections:**
1. Title + metadata (platform, difficulty, date, OS)
2. Target Information
3. Enumeration — port scan table + web findings table
4. Vulnerabilities Identified — from pattern-engine matches
5. Attack Path — AI-generated narrative
6. Credentials Found
7. Flags Captured
8. Tools Used
9. Command Log
10. Hints Timeline

---

### Utilities

| Command | Description |
|---------|-------------|
| `ctf config` | Show active configuration |
| `ctf parsers` | List registered tool parsers |

---

## Configuration

Config file: `~/.ctf_copilot/config.yaml` (created automatically on first run)

```yaml
# ── LLM Backend ─────────────────────────────────────────────────────────────
# "claude"  — Anthropic Claude API (best quality, requires api_key)
# "ollama"  — Local model via Ollama (free, offline, good enough for hints)
ai_backend: "claude"

api_key: "sk-ant-..."          # Anthropic API key
ai_model: "claude-sonnet-4-6"  # Claude model
ai_max_tokens: 300             # Token limit per hint
ai_rate_limit_seconds: 30      # Min gap between auto AI calls

# Ollama settings (only used when ai_backend = "ollama")
ollama_endpoint: "http://localhost:11434"
ollama_model: "llama3.2"

# ── Behaviour ────────────────────────────────────────────────────────────────
hint_mode: "cli"               # "cli" (print) or "silent" (DB only)
offline_mode: false            # Pattern engine only; skip all AI calls
confidence_threshold: 0.70     # Min confidence to show a pattern hint
dedup_hints: true              # Jaccard dedup (threshold 0.45)

# ── External Integrations ────────────────────────────────────────────────────
nvd_api_key: ""                # NIST NVD key — free, raises rate limit 5x
htb_api_key: ""                # HackTheBox API key (future: auto-fetch machine info)
```

**Environment variable overrides:**

| Variable | Config key |
|----------|-----------|
| `CTF_COPILOT_API_KEY` | `api_key` |
| `CTF_COPILOT_AI_BACKEND` | `ai_backend` |
| `CTF_COPILOT_OLLAMA_MODEL` | `ollama_model` |
| `CTF_COPILOT_OFFLINE` | `offline_mode` |
| `CTF_COPILOT_RATE_LIMIT` | `ai_rate_limit_seconds` |
| `CTF_COPILOT_NVD_API_KEY` | `nvd_api_key` |

---

## Pattern Rule Engine

CTF Copilot ships with 46 offline rules in `ctf_copilot/rules/`:

| File | Rules | Coverage |
|------|-------|----------|
| `services.yaml` | 22 | FTP, SSH, HTTP, SMB, MySQL, MSSQL, PostgreSQL, Redis, NFS, SNMP, LDAP, DNS, Telnet |
| `web.yaml` | 15 | Admin panels, phpMyAdmin, login pages, file upload, .git, .env, WordPress, Drupal, LFI |
| `compound.yaml` | 11 | Login+DB=SQLi, upload+webshell, MySQL+web=INTO OUTFILE, privesc chains, credential reuse |

Every rule has: `id`, `name`, `hint`, `confidence` (0–1), `priority` (1=high), `mitre` (ATT&CK IDs), `tags`, `conditions`.

**Adding a custom rule** — drop a YAML file into `ctf_copilot/rules/`:

```yaml
rules:
  - id: my-custom-rule
    name: "Jenkins Default Credentials"
    hint: >
      Jenkins is running. Try default credentials: admin:admin, admin:password.
      Check /script for the Groovy script console — it gives direct OS command execution.
    confidence: 0.88
    priority: 1
    mitre: ["T1078.001", "T1059.001"]
    tags: [jenkins, default-creds, rce]
    conditions:
      - type: service_port
        port: 8080
      - type: tool_not_used
        tool: curl
```

Then reload with: `ctf rules --reload`

**Condition types:**

| Type | Description | Parameters |
|------|-------------|-----------|
| `service_version` | Version string contains substring | `service`, `version_contains` |
| `service_port` | Port is open | `port` |
| `service_name` | Service name contains fragment | `name` |
| `web_endpoint` | Endpoint matches regex | `pattern` |
| `web_status` | Endpoint matches regex + status code | `pattern`, `status_code` |
| `tool_used` | Tool has been run | `tool` |
| `tool_not_used` | Tool has NOT been run | `tool` |
| `has_credentials` | Credentials exist in session | — |
| `no_flags` | No flags captured yet | — |

---

## NVD CVE Enrichment

After every successful nmap scan, CTF Copilot automatically queries the [NIST National Vulnerability Database](https://nvd.nist.gov) for each versioned service discovered. Results are cached locally for 7 days so repeated scans don't hit the API.

CVEs with CVSS score ≥ 7.0 are surfaced as **red NVD alert panels** in the terminal immediately after parsing.

```bash
# Optional: get a free NVD API key to raise rate limits (5 → 50 req/30s)
# https://nvd.nist.gov/developers/request-an-api-key
nvd_api_key: "your-key-here"
```

ExploitDB is queried in parallel via `searchsploit --json` (if installed), and matching exploits appear as **magenta ExploitDB panels**.

---

## Adding a Parser

Drop a new file into `ctf_copilot/parsers/` — the registry auto-discovers it on next startup:

```python
from ctf_copilot.parsers.base import BaseParser, ParseResult, WebFinding

class MyToolParser(BaseParser):
    tool_name = "mytool"   # must match the canonical name in logger._TOOL_NAMES

    def can_parse(self, output: str) -> bool:
        return "mytool signature" in output

    def parse(self, output: str, command: str) -> ParseResult:
        findings = []
        # parse output into WebFinding / ServiceFinding objects
        return self._make_result(web_findings=findings)
```

---

## Flag Detection

CTF Copilot scans every tool's output for common flag formats and alerts immediately:

| Format | Pattern |
|--------|---------|
| HackTheBox | `HTB{...}` |
| TryHackMe | `THM{...}` |
| Generic | `FLAG{...}`, `CTF{...}`, `DUCTF{...}`, `picoCTF{...}` |
| MD5-style | 32-character hex string |

---

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the full test suite (147 tests)
python -m pytest

# With coverage report
python -m pytest --cov=ctf_copilot --cov-report=term-missing

# Run a specific test file
python -m pytest tests/test_parsers.py -v

# Run tests matching a keyword
python -m pytest -k "nmap" -v
```

**Test coverage:**

| File | What's tested |
|------|--------------|
| `test_parsers.py` | nmap (text/grepable/XML), gobuster (dir/dns), ffuf (JSON/text) — 39 tests |
| `test_pattern_engine.py` | All 9 condition matchers + full rule engine integration — 30 tests |
| `test_hints.py` | Jaccard tokenisation, dedup logic, persistence round-trip — 24 tests |
| `test_logger.py` | Tool detection: paths, sudo, env vars, version suffixes — 17 tests |
| `test_writeup.py` | All 10 Markdown sections, file save, UTF-8 correctness — 24 tests |

---

## Supported Tools

| Tool | Parser | Formats handled |
|------|--------|----------------|
| nmap | `nmap_parser.py` | Text (`-oN`), Grepable (`-oG`), XML (`-oX`) |
| gobuster | `gobuster_parser.py` | dir (old + new format), dns, vhost |
| ffuf | `ffuf_parser.py` | JSON (`-of json`), terminal text |
| searchsploit | `searchsploit_parser.py` | JSON (`--json`) |

---

## Roadmap

Things I'm actively working on or planning to add:

- [ ] **Claude tool-use bridge** — give Claude live Shodan + NVD + ExploitDB tools during hint generation, so hints reference real-time data
- [ ] **HTB / THM API integration** — auto-fetch machine OS, tags, and difficulty on `ctf start` to pre-populate context before the first scan
- [ ] **Vector RAG knowledge base** — embed past writeups into a local Chroma DB so the AI can reference "last time I saw vsftpd 2.3.4, the path was..."
- [ ] **More parsers** — nikto, enum4linux, smbmap, hydra output
- [ ] **Playwright web helper** — headless browser for JS-heavy web challenges
- [ ] **Team mode** — shared session context over a local FastAPI server for group CTFs

---

## Project Structure

```
ctf_copilot/
├── cli.py                    # All CLI commands (18 commands via Click)
├── commands/
│   ├── wrap_cmd.py           # ctf-wrap: transparent tool interceptor
│   └── log_cmd.py            # ctf-log: lightweight shell hook (no output capture)
├── core/
│   ├── config.py             # Config loader (YAML + env vars, dataclass)
│   ├── database.py           # SQLite schema + connection management
│   ├── session.py            # Session CRUD + active session tracking
│   ├── context.py            # SessionContext builder (fresh from DB each call)
│   ├── logger.py             # Tool detection + command persistence
│   └── observations.py       # 5-layer intelligence synthesiser
├── parsers/
│   ├── base.py               # BaseParser ABC + ParseResult dataclasses
│   ├── registry.py           # Auto-discovery + persist pipeline
│   ├── nmap_parser.py
│   ├── gobuster_parser.py
│   ├── ffuf_parser.py
│   └── searchsploit_parser.py
├── engine/
│   ├── ai.py                 # LLM backend: Claude + Ollama dispatcher
│   ├── hints.py              # Jaccard dedup, save/retrieve, prompt formatting
│   ├── pattern.py            # YAML rule loader + condition evaluation engine
│   ├── cve.py                # NVD API client + local cache
│   └── writeup.py            # 10-section Markdown writeup generator
├── interface/
│   ├── display.py            # Rich hint panels (5 source types, styled)
│   └── dashboard.py          # Rich Live 5-panel TUI dashboard
└── rules/
    ├── services.yaml         # 22 service-level rules
    ├── web.yaml              # 15 web-focused rules
    └── compound.yaml         # 11 compound/chain detection rules
```

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built from scratch as a self-taught security enthusiast who got tired of alt-tabbing mid-CTF.

*If this tool helped you root a box, star the repo.*

</div>
