# Claude Context — Kali MCP Pentest Bridge

---

## 1. Architecture

### CLI Bridge — Command Execution (v4)
```
Claude Code (Windows)
    ↓ stdio
kali_mcp_client.py  (C:\Users\thiru\Kali-Pentest-MCP\kali_mcp_client.py)
    ↓ SSH ControlMaster pool (one persistent master process per target)
Kali Linux VirtualBox VM  (root@192.168.1.202)
    [+ optional extra targets via KALI_TARGETS env var]
```

**v4.1 improvements:** No Docker, no HTTP bridge. Each target maintains a persistent SSH ControlMaster process — commands reuse the multiplexed socket (~200ms saved per call). Retries 3x on connection errors. Sync output capped at 8MB. Job registry persisted to disk (`%APPDATA%\kali-mcp\jobs.json`) — survives Claude restarts. SCP file transfer via same ControlMaster socket. Parallel job launcher. Append-only JSONL audit trail (`%APPDATA%\kali-mcp\audit.jsonl`).

### Desktop Bridge — GUI Control
```
Claude Code (Windows)
    ↓ stdio
kali_desktop_client.py  (C:\Users\thiru\Kali-Pentest-MCP\kali_desktop_client.py)
    ↓ HTTP POST to localhost:3002
desktop-bridge-server.js  (Windows-native Node.js process, port 3002 — NOT Docker)
    ↓ VBoxManage screenshotpng → screenshots (zero X11, no display freeze)
    ↓ SSH pool → xdotool DISPLAY=:0 XAUTHORITY=/var/run/lightdm/root/:0
    ↓ SSH → su kali -c "DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority ..." (GUI app launch)
Kali XFCE4 Desktop  (1920×955, visible in VirtualBox window)
```

### Playwright Browser Bridge (via Desktop Bridge)
```
desktop-bridge-server.js
    ↓ SSH → auto-starts perception-server.py if not running
perception-server.py  (/home/kali/perception-server.py, venv: /opt/perception-venv/, port 5000)
Playwright Chromium on Kali  (headless — structured page state, network capture, JS eval)
```

**Critical facts:**
- `mcp__kali-pentest__execute_kali_command` — CLI tool execution, text output, runs as `root`
- `mcp__kali-desktop__desktop_*` — full GUI control: see screen, click, type, run apps
- `mcp__kali-desktop__browser_*` — Playwright browser: structured page state, network capture, JS eval, proxy routing
- Desktop bridge runs **natively on Windows** — VBoxManage.exe must be accessible on PATH
- Screenshot method: **VBoxManage screenshotpng** to `%TEMP%\_vbox_shot.png` — never scrot
- xdotool auth: `DISPLAY=:0 XAUTHORITY=/var/run/lightdm/root/:0` (LightDM root auth)
- GUI apps launched as kali user: `su kali -c "DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority nohup bash -c ..."`
- DPMS/screensaver permanently disabled on Kali via autostart — screen never locks
- Kali OS: GNU/Linux Rolling 2025.4, kernel `6.18.9+kali-amd64`
- Transport: stdio (not HTTP) between Claude Code and Python MCP clients

---

## 2. Project Files & Config

| File | Path |
|------|------|
| MCP bridge repo | `C:\Users\thiru\Kali-Pentest-MCP\` |
| CLI MCP client | `C:\Users\thiru\Kali-Pentest-MCP\kali_mcp_client.py` |
| Desktop MCP client | `C:\Users\thiru\Kali-Pentest-MCP\kali_desktop_client.py` |
| Shared MCP base | `C:\Users\thiru\Kali-Pentest-MCP\mcp_base.py` |
| CLI bridge server | `C:\Users\thiru\Kali-Pentest-MCP\bridge-server.js` (port 3001) |
| Desktop bridge server | `C:\Users\thiru\Kali-Pentest-MCP\desktop-bridge-server.js` (port 3002) |
| SSH pool init script | `C:\Users\thiru\Kali-Pentest-MCP\start-bridge.sh` (runs inside mcp-bridge container) |
| SSH key | `C:\Users\thiru\Kali-Pentest-MCP\ssh-keys\id_ed25519` |
| Env config | `C:\Users\thiru\Kali-Pentest-MCP\.env` |
| Perception server | `/home/kali/perception-server.py` (on Kali VM) |
| Slash commands | `C:\Users\thiru\.claude\commands\` |

**.env contents:**
```
KALI_HOST=192.168.1.202
KALI_PORT=22
KALI_USERNAME=root
COMMAND_TIMEOUT=900000000
PORT=3001
```

**Files NOT in git** (copied manually): `.env`, `ssh-keys/`
**Git repo:** https://github.com/0xthusharkiranreddy/MCP-BRIDGE

---

## 3. Startup & Recovery

### Normal Start

**Step 1 — CLI bridge (v4 — no Docker needed):**
The MCP client (`kali_mcp_client.py`) is auto-started by Claude Code via `settings.json`.
Verify it's working: run `check_connection()` → should return `ALIVE`.
First command per session establishes the SSH ControlMaster (~15s); all subsequent calls are instant.

**Step 2 — Desktop bridge (Windows-native):**
```powershell
$env:KALI_HOST="192.168.1.202"
$env:KALI_PORT="22"
$env:KALI_USERNAME="root"
$env:DESKTOP_PORT="3002"
$env:SSH_KEY="C:/Users/thiru/Kali-Pentest-MCP/ssh-keys/id_ed25519"
$env:VBOX_VM="kali-linux-2025.4-virtualbox-amd64"
cd C:\Users\thiru\Kali-Pentest-MCP
node desktop-bridge-server.js
```

**Verify both bridges:**
```powershell
curl http://localhost:3002/health   # desktop bridge → {"status":"ok","service":"desktop-bridge"}
```
For CLI bridge: run `check_connection()` via MCP — should return `ALIVE`.

### CLI Bridge Restart (v4)
No Docker to restart. Just restart Claude Code — the MCP client auto-starts.
If SSH ControlMaster is stale, run `check_connection()` — it will auto-recreate the master.

### VM IP Changed After Reboot
1. Check new IP on VirtualBox console: `ip addr show eth1`
2. Update `settings.json` → `KALI_HOST=<new_ip>` (under mcpServers kali-pentest env)
3. Update desktop bridge env var: `$env:KALI_HOST="<new_ip>"`
4. Restart Claude Code (MCP client restarts with new IP)
5. Restart desktop bridge with new env

### apt Broken After Snapshot Restore
```bash
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
apt-get update
```

### start-bridge.sh CRLF Issue
If `docker logs mcp-bridge` shows `'leep: invalid number '3` or `': not found`:
```powershell
(Get-Content start-bridge.sh -Raw) -replace "`r`n", "`n" | Set-Content start-bridge.sh -NoNewline
docker compose down && docker compose up -d
```

---

## 4. Desktop MCP Tools Reference

### GUI Control Tools (`mcp__kali-desktop__`)

| Tool | Purpose |
|------|---------|
| `desktop_screenshot` | VBoxManage screenshotpng → image Claude sees. Always call before clicking. |
| `desktop_click(x,y)` | Left click at coordinates |
| `desktop_double_click(x,y)` | Double click |
| `desktop_right_click(x,y)` | Right click |
| `desktop_move(x,y)` | Move cursor without clicking |
| `desktop_type(text)` | Type text into focused element |
| `desktop_key(keys)` | Key combos: `ctrl+c`, `Return`, `ctrl+l`, `super` |
| `desktop_scroll(x,y,dir,amount)` | Scroll up/down at position |
| `desktop_drag(x1,y1,x2,y2)` | Click and drag |
| `desktop_run(app_command)` | Launch app as kali user: `firefox`, `burpsuite`, `code /path` |
| `desktop_get_window_list` | List all open windows with IDs |
| `desktop_focus_window(id)` | Bring window to foreground |
| `desktop_get_screen_size` | Returns `1920 955` |
| `desktop_get_cursor_pos` | Current cursor X,Y |

**Coordinate system:** VBoxManage captures at full 1920×955. Claude displays screenshots scaled down in UI. **Multiply displayed/estimated coordinates by ~1.25** to get actual screen coordinates for xdotool.

### Playwright Browser Tools (`mcp__kali-desktop__`)

Playwright runs headless on Kali. The perception server auto-starts on first use. Returns structured page state — no screenshot unless CAPTCHA detected.

| Tool | Purpose |
|------|---------|
| `browser_navigate(url, proxy_port?)` | Navigate to URL, return structured state (url, title, forms, buttons, links, state_hash). Screenshot only on CAPTCHA. |
| `browser_click(selector?, x?, y?)` | Click element by CSS selector or coordinates. Returns updated state. |
| `browser_type(selector?, text)` | Fill form field. Replaces existing content. |
| `browser_get_state` | Current page state without interaction — use after user solves CAPTCHA |
| `browser_screenshot` | Explicit screenshot of current page (use sparingly — prefer browser_get_state) |
| `browser_eval(js)` | Evaluate JS in page context: `document.cookie`, DOM reads, token extraction |
| `browser_get_network` | Last 20 XHR/fetch/document requests: URL, method, status, response body |
| `browser_set_proxy(enabled, host?, port?)` | Route all Playwright traffic through Burp (127.0.0.1:8080) |
| `browser_close` | Close browser; next navigate opens fresh instance |

---

## 5. CLI Bridge — Tools Reference (v4.1)

### Async Job Management

Long-running commands (nmap, sqlmap, nuclei, hydra) run as background jobs:

```python
# Start async — returns jobId immediately
execute_kali_command(command="nmap -T4 -A target.com", async=True)
# → "Job started: abc123def (status: running) [default]"

# Poll output
list_jobs()                              # shows all jobs incl. persisted from prior sessions
get_job_output(job_id="abc123def")       # fetches from Kali, works after Python restart

# Kill if needed
kill_job(job_id="abc123def")
```

Job registry is persisted to `%APPDATA%\kali-mcp\jobs.json` — survives restarts.

### Multi-Target Tools

```python
# Check connectivity + latency
check_connection()                       # → ALIVE, 12ms, uptime...
check_connection(target="kali2")         # → check a named extra target

# List all targets
list_targets()
# → default     root@192.168.1.202:22  [pool ready]
# → kali2       root@192.168.1.203:22  [pool ready]

# Run on a specific target
execute_kali_command(command="hostname", target="kali2")
execute_kali_command(command="nmap ...", target="pivot", async=True)
```

**To register extra targets**, add to `settings.json` env:
```json
"KALI_TARGETS": "kali2=root@192.168.1.203:22,pivot=root@10.10.10.50:22"
```

### File Transfer (v4.1)

```python
# Upload file to Kali (uses existing ControlMaster — no new SSH connection)
transfer_file(direction="to_kali",
              local_path=r"C:\tools\custom_wordlist.txt",
              remote_path="/home/kali/custom_wordlist.txt")

# Download loot from Kali
transfer_file(direction="from_kali",
              local_path=r"C:\Users\thiru\loot\flag.txt",
              remote_path="/home/kali/current/loot/flag.txt")
```

### Parallel Execution (v4.1)

```python
# Launch nmap + ffuf + nuclei simultaneously — returns 3 job IDs immediately
execute_parallel(commands=[
    {"command": "nmap -T4 -p- target.com", "label": "nmap-full"},
    {"command": "ffuf -u target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt", "label": "ffuf"},
    {"command": "nuclei -u target.com -severity critical,high", "label": "nuclei"},
])
# Poll each: get_job_output(job_id="...")
```

### Audit Log (v4.1)

```python
# All tool calls are auto-logged to %APPDATA%\kali-mcp\audit.jsonl

# Add a manual finding
audit_log(action="write",
          message="SQL injection confirmed on /api/search?q= parameter",
          severity="critical",
          tags=["sqli", "target1"])

# Read the trail
audit_log(action="read")                        # last 50 entries
audit_log(action="read", tag="finding")         # only findings
audit_log(action="read", since="2025-01-15")    # from date
```

---

## 6. Desktop Bridge — Cloudflare & CAPTCHA Bypass

Use the Desktop Bridge (Firefox or Playwright) when CLI tools are blocked.

### When to Switch
- CLI tools getting 403/503/Cloudflare challenge pages
- Target returns `cf-ray` headers or `__cf_bm` cookies
- Login has CAPTCHA
- Need to capture authenticated cookies/tokens after human CAPTCHA solve

### Playwright Workflow (preferred — structured output)
```
1. browser_navigate("https://target.com")
2. Check state — if CAPTCHA detected, screenshot is returned automatically
3. Tell user to solve CAPTCHA in VirtualBox window, then:
4. browser_get_state → check state_hash changed (page progressed past CAPTCHA)
5. browser_eval("document.cookie") → extract cookies
6. browser_get_network → inspect XHR requests, capture auth tokens
7. Pass cookies/tokens to CLI tools
```

### Firefox GUI Workflow (for Cloudflare JS challenges)
```
1. desktop_run("firefox https://target.com")
2. desktop_screenshot → confirm Firefox opened
3. If Cloudflare challenge: PAUSE — tell user to solve in VirtualBox window
4. desktop_screenshot → confirm page loaded
5. Extract cookies via Firefox DevTools or sqlite:
```
```bash
python3 -c "
import sqlite3, glob
db = glob.glob('/home/kali/.mozilla/firefox/*.default-esr/cookies.sqlite')[0]
conn = sqlite3.connect(db)
rows = conn.execute('SELECT host, path, isSecure, expiry, name, value FROM moz_cookies WHERE host LIKE \"%target.com%\"').fetchall()
for r in rows:
    print('\t'.join([r[0], 'TRUE', r[1], 'TRUE' if r[2] else 'FALSE', str(r[3]), r[4], r[5]]))"
```

### Burp Suite via Desktop
```
1. desktop_run("burpsuite")
2. desktop_screenshot → wait for Burp to load (~30s)
3. Firefox → Settings → Network → Manual Proxy → 127.0.0.1:8080
   OR: browser_set_proxy(enabled=True, port=8080)
4. Navigate target — all traffic intercepted
5. desktop_screenshot → read requests/responses in Burp UI
```

---

## 7. Engagement Workflow & Skills

### Workflow
```
/pt-init <name> <target>              → workspace setup + thorough initial fingerprint (+ CVE search on detected stack)
/pt-recon [target]                    → deep passive/active asset discovery (+ Shodan/ASN if API key set, + takeover/git/sourcemap check)
/pt <observations>                    → signal-driven attack planner (human-level reasoning)
/pt-api <base-url> [token]            → systematic REST/GraphQL API attack (+ JWT/OAuth/race + type coercion)
/pt-payloads <tech, input, endpoint>  → targeted payload generator from PAT
/pt-blind <target-url>                → OOB blind detection (SSRF, SQLi, CMDi, XXE) via interactsh
/pt-secrets <target-url>              → leaked API keys, .git exposure, .env files, cloud buckets, key validation (AWS/Stripe/GCP/OpenAI)
/pt-web <target-url>                  → HTTP request smuggling, web cache poisoning, subdomain takeover, WebSockets, CRLF
/pt-logic <api-base-url> [token]      → business logic + IDOR expert: data model mapping, price manipulation, workflow bypass, mass assignment
/pt-privesc <user@ip>                 → Linux privilege escalation: linpeas + 10-phase survey
/pt-ad <domain> <dc-ip> [creds]       → Active Directory: AS-REP → Kerberoast → BloodHound → DCSync
/pt-report [engagement-name]          → professional pentest report with CVSS + compliance mapping
```

### `/pt-init <name> <target>`
Creates workspace at `/home/kali/engagements/<name>/` and sets `/home/kali/current` symlink.
Runs: HTTP headers + redirect chain, security headers audit (HSTS/CSP/X-Frame), WAF detection (wafw00f), CORS quick probe, WhatWeb, DNS records, nmap (top 1000 ports + 8080/8443/8888/9200/6379/27017), sslscan + SSL cert alt-names.
Ends with attack surface summary: WAF present? HTTPS enforced? Which headers missing? Interesting ports? CORS signal?

```
/home/kali/engagements/<name>/
├── recon/{nmap,http,dns,screenshots}
├── scans/{ffuf,nikto,nuclei,sqlmap}
├── exploits/
├── loot/
├── poc/{requests,screenshots,videos}
└── notes/engagement.md
```

### `/pt-recon [target]`
Deep passive/active asset discovery. Reads target from argument or active engagement.
Phases: SSL cert alt-names → crt.sh CT → Wayback Machine CDX → subfinder → theHarvester → DNS intel (NS/MX/TXT/DMARC/zone transfer) → live host probing (httpx or parallel curl) → WhatWeb + robots.txt + sitemap → nmap on unique IPs → JS bundle analysis (secrets + API endpoints, with FP filter) → GitHub dorking → cloud bucket check (S3/GCS/Azure Blob/DigitalOcean Spaces).
All output to `/home/kali/current/recon/`.

### `/pt <observations>`
Signal-driven attack planner with human-level reasoning. Reads existing engagement findings first (avoids re-testing confirmed vulns). Maps 30 signals → attack vectors. Justifies every test. Applies impact gate after each result. Recognizes and documents exploit chains (IDOR + JWT = account takeover, SSRF + metadata = cloud compromise).
New vectors added: CORS misconfiguration, prototype pollution, API version abuse, CSRF, rate limit bypass, response manipulation, error disclosure mining, NoSQL injection, SSRF escalation (AWS/GCP/Azure IMDS), XXE via file upload.
SSTI detection bug fixed — uses grep exit code, not shell variable expansion.

### `/pt-api <base-url> [auth-token]`
Systematic REST/GraphQL API attack. Use when you have a target API and want structured enumeration before `/pt`.
Phases: Swagger/OpenAPI/GraphQL endpoint discovery → auth bypass patterns (null token, old API versions) → mass IDOR scan across all numeric ID endpoints → HTTP verb tampering on all discovered endpoints → rate limit baseline + bypass testing → GraphQL deep-dive (introspection, alias batching, mutations, subscription probe) → business logic probes (negative values, integer overflow, coupon abuse).

### `/pt-payloads <tech stack, input type, endpoint>`
Reads actual PayloadsAllTheThings files from Kali first, then generates targeted payload test commands.
Maps tech/input → PAT category → exact curl commands + tool automation.
New categories: NoSQL injection, prototype pollution, LDAP injection, insecure deserialization (ysoserial), CORS misconfiguration.
Engine-specific: Thymeleaf payloads differ from Jinja2 differ from Twig.

### `/pt-blind <target-url>`
OOB (out-of-band) blind vulnerability detection using interactsh as callback server.
Phases: interactsh session setup → blind SSRF (GET/POST params + headers) → blind SQLi (sqlmap with `--dns-domain`) → blind command injection (nslookup/curl payloads into all params) → blind XXE (SVG/XML file upload) → SSTI blind math probes → callback verification.
Confirms exploitability even when target response is identical for all inputs.

### `/pt-privesc <user@ip>`
10-phase Linux privilege escalation from low-privilege foothold to root.
Phases: LinPEAS automated survey → SUID/SGID binaries (GTFOBins cross-reference) → sudo -l analysis → Linux capabilities → cron jobs + writable scripts → writable PATH directories → credential hunting (configs, history, SSH keys) → kernel exploit search (searchsploit + known CVEs) → Docker/LXD escape check → NFS no_root_squash.
Saves report to `/home/kali/current/notes/privesc_TIMESTAMP.md`.

### `/pt-ad <domain> <dc-ip> [creds]`
8-phase Active Directory attack chain from unauthenticated enumeration to DCSync.
Phases: null session SMB + LDAP enum → AS-REP roasting (no creds needed) → password spray → Kerberoasting → BloodHound data collection → Pass-the-Hash across subnet → lateral movement (WinRM/WMI/SMB) → DCSync (full domain credential dump).
Saves all hashes to `/home/kali/current/loot/hashes/` and report to `/home/kali/current/notes/ad_attack_TIMESTAMP.md`.

### `/pt-report [engagement-name]`
Reads all engagement artifacts (engagement.md, PoC files, recon data) and generates a professional penetration test report.
Includes: executive summary (business language), risk summary table, CVSS v3.1 scored findings with vector strings, CWE references, OWASP/PCI-DSS/GDPR compliance mapping table, specific remediation (not generic), attack chain documentation, coverage table (tested-but-not-vulnerable), remediation priority matrix.
Saves to `/home/kali/current/notes/pentest_report_YYYY-MM-DD.md`.

### `/pt-secrets <target-url>`
7-phase leaked secrets and API key hunter for exposed credentials and sensitive files.
Phases: exposed `.git` directory (git-dumper for full source dump) → sensitive file hunt (30+ paths: .env, wp-config, .aws/credentials, backup.zip, source maps) → GitHub API code search (10 dork queries: domain + "api_key", "AKIA", "BEGIN RSA") → trufflehog + gitleaks on git dumps and JS files → API key validation using read-only endpoints (AWS STS GetCallerIdentity, Stripe list charges, OpenAI /models, SendGrid scopes, GitHub /user) → cloud storage bucket enumeration (S3/GCS/Azure with 15 naming patterns) → priority summary and engagement.md update.
Key feature: never makes destructive API calls — all validation is read-only. Saves loot to `/home/kali/current/loot/`.

### `/pt-web <target-url>`
5-phase advanced web attack suite covering attack classes invisible to most automated scanners.
Phases: HTTP Request Smuggling (smuggler.py CL.TE/TE.CL + manual timing probes + h2c upgrade + TE obfuscation variants) → Web Cache Poisoning (unkeyed X-Forwarded-Host injection with canary verification, cache deception via static extensions on account paths, fat GET, parameter cloaking) → Subdomain Takeover (CNAME fingerprint against 12 service signatures: GitHub Pages, S3, Heroku, Netlify, Fastly, Azure, Shopify, Tumblr, Bitbucket, UserVoice) → WebSocket Security (origin bypass, no-auth connection, IDOR via channel subscribe, XSS via message, command injection) → CRLF Injection (8 encoding variants in URL, redirect params, User-Agent; open redirect detection).
Uses smuggler.py from `/opt/smuggler/`, wscat for WebSocket testing.

### `/pt-logic <api-base-url> [auth-token]`
8-phase business logic and IDOR expert with systematic state-machine thinking.
Phases: Data model mapping (enumerate all object types, detect ID format: sequential/UUID v1 time-based/UUID v4/hash-based) → IDOR matrix with 5 patterns (sequential scan ±20 IDs, UUID v1 adjacency prediction, hash reversal with hashlib, indirect via org/team relationships, verb swap) → Workflow bypass (skip email verification, skip payment, forced browse to next step, double-submission replay) → Price manipulation (negative values, integer overflow 2^31, floating point precision, currency confusion JPY/USD, client-supplied price field) → Mass assignment (30 privilege fields injected on registration + profile update, verified with /api/me re-read) → Account enumeration (login timing oracle, password reset response diff, registration response diff) → Coupon/referral abuse (25 common codes, self-referral) → Chain exploitation analysis.
For deep IDOR work, run `/pt-logic` before `/pt-api` to map the data model first.

### Save Evidence
```bash
curl -v -H "Authorization: Bearer <token>" https://target/api/... 2>&1 | \
    tee /home/kali/current/poc/requests/finding_name.txt

cat >> /home/kali/current/notes/engagement.md << EOF
## Finding: <name>
**Severity**: Critical/High/Medium/Low
**Endpoint**: ...
**Impact**: ...
EOF
```

---

## 8. Installed Tools Reference

### Web & API Testing
| Tool | Version | Purpose |
|------|---------|---------|
| nikto | 2.5.0 | Web server scanner |
| sqlmap | 1.10.2 | SQL injection |
| gobuster | 3.8.2 | Directory/DNS/vhost bruteforce |
| ffuf | 2.1.0 | Fast fuzzer — endpoints, params, headers |
| feroxbuster | 2.13.1 | Recursive content discovery |
| wfuzz | 3.1.0 | Web fuzzer |
| commix | 4.1 | OS command injection |
| whatweb | 0.6.3 | Web tech fingerprinting |
| wpscan | latest | WordPress scanner |
| sslscan | latest | SSL/TLS testing |
| zaproxy | latest | OWASP ZAP intercepting proxy |
| nuclei | 3.7.0 | Template-based vuln scanning |
| arjun | 2.2.7 | HTTP parameter discovery |
| jwt_tool | latest | JWT attacks — `/opt/jwt_tool/jwt_tool.py` |
| burpsuite | latest | Full intercepting proxy + manual testing |

### Network
| Tool | Version | Purpose |
|------|---------|---------|
| nmap | 7.98 | Port scan, service/OS detection |
| masscan | 1.3.2 | Fast large-scale port scan |
| metasploit-framework | 6.4.112 | Exploitation framework |
| hydra | 9.6 | Login bruteforce |
| netexec | 1.5.1 | SMB/WinRM/LDAP enum |
| responder | 3.2.2 | LLMNR/NBT-NS poisoning |
| enum4linux | 0.9.1 | Windows/Samba enum |
| python3-impacket | 0.13.0 | Network protocol library |
| netcat-traditional | 1.10 | TCP/IP swiss army knife |

### Password Attacks
| Tool | Purpose |
|------|---------|
| hashcat 7.1.2 | GPU password cracking |
| john | CPU password cracking |

### Wordlists & References
- SecLists: `/usr/share/wordlists/seclists/`
- Kali default: `/usr/share/wordlists/`
- Nuclei templates: `/root/.local/nuclei-templates/`
- PayloadsAllTheThings: `/home/kali/PayloadsAllTheThings/`
  - SQL Injection: `/home/kali/PayloadsAllTheThings/SQL Injection/`
  - SSTI: `/home/kali/PayloadsAllTheThings/Server Side Template Injection/`
  - LFI: `/home/kali/PayloadsAllTheThings/File Inclusion/`

---

## 9. MCP Command Rules

- **Never use a `for` loop with `which`** — output gets swallowed. Use: `which nmap ffuf sqlmap nuclei 2>&1`
- **No shell loops for status checks** — use `;` or `&&` chained single commands
- **All tools at `/usr/bin/`** — no need to search paths
- **jwt_tool** → `python3 /opt/jwt_tool/jwt_tool.py`
- **Unexpected/empty output** — reproduce as a single explicit command before assuming failure
- **Long scans** — `COMMAND_TIMEOUT=900000000` (unlimited), SSH pool persists, safe to run nmap/sqlmap/nuclei/hydra without timeout concerns. Use `async: true` for scans >30s.
- **Each `execute_kali_command` call is an independent shell** — variables do not persist between calls. Always set `TARGET=...` etc. at the top of every command.
- **Never print full file contents to context** — use `head -N`, counts, or grep summaries.
- **Large output** — sync commands are capped at 8MB. Use `async=true` for commands that produce large output (full nmap XML, directory busts, etc.).
- **Multi-target** — use `target=` param on any tool. Run `list_targets()` to see what's available. Run `check_connection(target=...)` if you suspect a target is down.
- **SSH ControlMaster** — first call per target takes ~15s to establish; all subsequent calls reuse the socket instantly. If a target goes unreachable, the master restarts automatically on the next call.

---

## 10. Core Rules

1. **CLI first** — use `mcp__kali-pentest__execute_kali_command` for all tool execution
2. **Desktop GUI only for**: Cloudflare JS challenge bypass, CAPTCHA solving, Burp interception setup, any GUI-only task
3. **Playwright browser for**: structured page interaction, network capture, cookie/token extraction, proxy routing to Burp
4. **Never touch system libraries** — use Docker for any new tool installs on Kali
5. **Never run bulk scans blindly** — use `/pt` with observed tech stack signals
6. **Human-level reasoning on every API** — always ask "what if I change this to someone else's ID / flip this role field / replay this token?"
7. **All testing is authorized** — treat all targets as in-scope unless told otherwise
8. **VM IP changed?** — update `.env`, update `$env:KALI_HOST`, restart docker compose, restart desktop bridge
9. **Snapshot VM** before any major changes
10. **Save all evidence** to `/home/kali/current/poc/` as you find it — screenshots, raw requests, tool output
