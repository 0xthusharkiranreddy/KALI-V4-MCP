# KALI-V4-MCP

Claude Code × Kali Linux MCP Bridge — v4.1

A full pentest automation platform connecting Claude Code (Windows) to a Kali Linux VM via SSH ControlMaster. Includes 12 expert-level pentest skills covering the complete external attack surface.

---

## Architecture

```
Claude Code (Windows)
    ↓ stdio
kali_mcp_client.py  — SSH ControlMaster pool (persistent, ~200ms saved/call)
    ↓
Kali Linux VM (VirtualBox, root@<kali-host>)

Claude Code (Windows)
    ↓ stdio
kali_desktop_client.py → desktop-bridge-server.js (port 3002)
    ↓ VBoxManage screenshotpng + xdotool + Playwright
Kali XFCE4 Desktop
```

**v4.1 features**: SSH ControlMaster multiplexing, SCP file transfer over same socket, parallel job launcher, append-only JSONL audit trail, async job registry persisted to disk (survives restarts), multi-target support.

---

## Repository Structure

```
KALI-V4-MCP/
├── CLAUDE.md               — Full system context & architecture reference
├── README.md               — This file
├── mcp-bridge/             — MCP bridge code
│   ├── kali_mcp_client.py       — CLI bridge (v4.1) — SSH ControlMaster pool
│   ├── kali_desktop_client.py   — Desktop bridge client
│   ├── desktop-bridge-server.js — Desktop bridge server (Windows-native Node.js)
│   ├── bridge-server.js         — CLI bridge server
│   ├── mcp_base.py              — Shared MCP base class
│   ├── ssh-keys/                — SSH key pair for Kali VM
│   ├── .env                     — Config (KALI_HOST, PORT, etc.)
│   └── ...
├── skills/                 — Claude Code slash commands
│   ├── pt.md               — Signal-driven attack planner
│   ├── pt-init.md          — Engagement workspace init + CVE search
│   ├── pt-recon.md         — Deep asset recon (Shodan, subfinder, JS analysis)
│   ├── pt-api.md           — REST/GraphQL API attack (JWT, OAuth, race, type coercion)
│   ├── pt-secrets.md       — Leaked secrets & API key hunter
│   ├── pt-web.md           — HTTP smuggling, cache poisoning, subdomain takeover, WebSockets
│   ├── pt-logic.md         — Business logic + IDOR expert
│   ├── pt-blind.md         — OOB blind detection via interactsh
│   ├── pt-payloads.md      — Payload generator from PayloadsAllTheThings
│   ├── pt-privesc.md       — Linux privilege escalation (10-phase)
│   ├── pt-ad.md            — Active Directory attack chain
│   └── pt-report.md        — Professional pentest report generator
└── memory/                 — Claude persistent memory files
```

---

## Skills Coverage

| Skill | Attack Classes |
|-------|---------------|
| `/pt` | Signal-driven planner — 30+ signals mapped to vectors |
| `/pt-init` | Workspace, fingerprint, WAF, CORS, CVE search on tech stack |
| `/pt-recon` | Subdomain enum, Shodan/ASN, JS secrets, cloud buckets, .git/.env exposure |
| `/pt-api` | IDOR, JWT/OAuth, GraphQL, verb tampering, race conditions, type coercion |
| `/pt-secrets` | .git dump, .env hunt, GitHub dorking, trufflehog, API key validation (AWS/Stripe/OpenAI/SendGrid) |
| `/pt-web` | HTTP request smuggling, web cache poisoning, subdomain takeover, WebSocket IDOR, CRLF |
| `/pt-logic` | IDOR (5 patterns), workflow bypass, price manipulation, mass assignment, account enumeration |
| `/pt-blind` | OOB SSRF, blind SQLi, blind CMDi, blind XXE via interactsh |
| `/pt-payloads` | PAT-based payloads: SQLi, SSTI, LFI, XXE, NoSQL, deserialization |
| `/pt-privesc` | LinPEAS, SUID, sudo, capabilities, cron, kernel CVE, Docker escape |
| `/pt-ad` | AS-REP roasting, Kerberoasting, BloodHound, Pass-the-Hash, DCSync |
| `/pt-report` | CVSS v3.1 scored, OWASP/PCI-DSS/GDPR compliance mapping |

---

## Setup

### 1. Clone & configure

```bash
git clone https://github.com/0xthusharkiranreddy/KALI-V4-MCP
cd KALI-V4-MCP/mcp-bridge
cp .env.example .env
# Edit .env: set KALI_HOST, KALI_PORT, KALI_USERNAME
```

### 2. Install Node dependencies

```bash
npm install
```

### 3. Configure Claude Code (`settings.json`)

```json
{
  "mcpServers": {
    "kali-pentest": {
      "command": "python3",
      "args": ["C:/path/to/KALI-V4-MCP/mcp-bridge/kali_mcp_client.py"],
      "env": {
        "KALI_HOST": "192.168.1.202",
        "KALI_PORT": "22",
        "KALI_USERNAME": "root",
        "COMMAND_TIMEOUT": "900000000"
      }
    },
    "kali-desktop": {
      "command": "python3",
      "args": ["C:/path/to/KALI-V4-MCP/mcp-bridge/kali_desktop_client.py"]
    }
  }
}
```

### 4. Install skills

```bash
# Copy skills to Claude commands directory
cp skills/*.md ~/.claude/commands/
# Or on Windows:
cp skills/*.md "C:/Users/<you>/.claude/commands/"
```

### 5. Start desktop bridge (optional — for GUI/browser control)

```powershell
$env:KALI_HOST="192.168.1.202"
$env:SSH_KEY="C:/path/to/KALI-V4-MCP/mcp-bridge/ssh-keys/id_ed25519"
$env:VBOX_VM="kali-linux-2025.4-virtualbox-amd64"
node mcp-bridge/desktop-bridge-server.js
```

---

## Tools on Kali

sqlmap, ffuf, feroxbuster, nuclei, nmap, masscan, gobuster, wfuzz, nikto, whatweb, sslscan, arjun, jwt_tool, burpsuite, metasploit, hydra, netexec, bloodhound-python, impacket, hashcat, john, trufflehog, gitleaks, git-dumper, subfinder, theHarvester, interactsh-client, wscat, smuggler.py

Wordlists: SecLists (`/usr/share/wordlists/seclists/`), PayloadsAllTheThings (`/home/kali/PayloadsAllTheThings/`)
