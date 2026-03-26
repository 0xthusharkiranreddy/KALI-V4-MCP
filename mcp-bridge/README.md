# Kali Linux MCP Pentest Bridge

A Docker-based [Model Context Protocol (MCP)](https://modelcontextprotocol.io) bridge that gives Claude Code (or any MCP client) full access to a Kali Linux machine — run CLI tools, manage long-running scans as background jobs, and control the GUI desktop — all from a Windows or macOS host.

---

## Architecture

Two Docker containers, two Python MCP clients. No intermediary relay.

### CLI Bridge (port 3001)

```
Claude Code (Windows/macOS)
    ↓ stdio (JSON-RPC)
kali_mcp_client.py          — MCP stdio server, ThreadPoolExecutor, job manager
    ↓ HTTP POST
bridge-server.js            — Node.js/Express, SSH ControlMaster pool, job store
    ↓ SSH direct
Kali Linux VM               — all tools run as root
```

### Desktop Bridge (port 3002)

```
Claude Code (Windows/macOS)
    ↓ stdio (JSON-RPC)
kali_desktop_client.py      — MCP stdio server, ThreadPoolExecutor
    ↓ HTTP POST
desktop-bridge-server.js    — Node.js/Express, SSH ControlMaster pool
    ↓ SSH direct
DISPLAY=:0  XAUTHORITY=/home/kali/.Xauthority
xdotool + scrot + Playwright — mouse/keyboard/screenshot/browser automation
Kali XFCE4 Desktop
```

**Key facts:**
- Both bridge containers connect directly to Kali over SSH — no relay container in between
- SSH ControlMaster pool (default 5 sockets) is pre-established at startup for low-latency multiplexing
- All pentest tools run as `root` on the Kali VM
- The desktop bridge runs GUI commands as the `kali` user against XFCE4 on `DISPLAY=:0`

---

## Features

### CLI Bridge

| Feature | Detail |
|---------|--------|
| Sync execution | Run a command, get all output back when it finishes |
| Async execution | `async: true` starts a background job and returns a `jobId` immediately |
| Job management | `list_jobs`, `get_job_output`, `kill_job` |
| Remote kill | Terminates the actual process on Kali via PID file, not just the SSH pipe |
| Output cap | Job output capped at 10 MB (keeps the most recent tail) — prevents OOM on large scans |
| Job TTL | Completed jobs auto-evicted from memory after 30 minutes |
| Unlimited timeout | `COMMAND_TIMEOUT` env var, defaults to effectively unlimited |
| SSE streaming | `/v1/tools/stream` endpoint for real-time output without polling |

### Desktop Bridge

| Feature | Detail |
|---------|--------|
| Screenshot | Returns screen as base64 PNG — Claude sees it as an image |
| Full mouse control | Click, double-click, right-click, drag, scroll, move |
| Keyboard control | Type text, key combos (`ctrl+c`, `Return`, `super`, `F12`, etc.) |
| Window management | List all windows with IDs, focus by ID |
| App launcher | Launch any GUI app by command string |
| Playwright browser | Headless browser with structured page state, network capture, JS eval, Burp proxy support |

---

## Quick Start

### Prerequisites

- Docker Engine 20.10+ with Docker Compose v2
- Kali Linux VM or machine with SSH enabled and `root` access
- Python 3.8+ on your Windows/macOS host
- `pip install requests` on the host

### 1. Clone and Configure

```bash
git clone https://github.com/0xthusharkiranreddy/MCP-BRIDGE
cd MCP-BRIDGE

cp .env.example .env
# Edit .env — set KALI_HOST to your VM's IP
```

`.env` fields:

```env
KALI_HOST=192.168.1.206     # your Kali VM IP
KALI_PORT=22                # SSH port (change if non-standard)
KALI_USERNAME=root
COMMAND_TIMEOUT=900000000   # ms — effectively unlimited
PORT=3001
SSH_POOL_SIZE=5
```

### 2. Generate SSH Key and Authorize on Kali

```bash
mkdir -p ssh-keys
ssh-keygen -t ed25519 -f ssh-keys/id_ed25519 -N "" -C "kali-mcp"
ssh-copy-id -i ssh-keys/id_ed25519.pub root@<KALI_HOST>
```

### 3. Start the Containers

```bash
docker compose up -d
```

Verify everything is healthy:

```bash
docker compose ps
# Both containers should show "healthy" (allow ~90s for SSH pool to establish)

docker logs mcp-bridge
# Expected: "SSH pool ready: 5/5 connections established"

curl http://localhost:3001/health
# {"status":"ok","service":"mcp-bridge"}

curl http://localhost:3002/health
# {"status":"ok","service":"desktop-bridge"}
```

Test with a real command:

```bash
curl -X POST http://localhost:3001/v1/tools/execute \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"execute_kali_command","arguments":{"command":"whoami"}}'
# {"success":true,"result":"root\n","jobId":"..."}
```

### 4. Configure Claude Code

Register both MCP servers using the Claude Code CLI:

```bash
# CLI bridge (pentest commands, job management)
claude mcp add kali-pentest \
  --command python3 \
  --args /path/to/MCP-BRIDGE/kali_mcp_client.py

# Desktop bridge (screenshots, clicks, browser automation)
claude mcp add kali-desktop \
  --command python3 \
  --args /path/to/MCP-BRIDGE/kali_desktop_client.py
```

Or add manually to `~/.claude.json` under `mcpServers`:

```json
"kali-pentest": {
  "type": "stdio",
  "command": "python3",
  "args": ["/path/to/MCP-BRIDGE/kali_mcp_client.py"],
  "env": {}
},
"kali-desktop": {
  "type": "stdio",
  "command": "python3",
  "args": ["/path/to/MCP-BRIDGE/kali_desktop_client.py"],
  "env": {}
}
```

Restart Claude Code. The tools are now available in every session.

---

## Usage

### Running Commands (Sync)

Short commands return output directly:

```
execute_kali_command: whoami
execute_kali_command: nmap -sV -p 80,443 192.168.1.1
execute_kali_command: sqlmap -u "http://target.com/api?id=1" --batch --level=3
```

### Long-Running Scans (Async)

Use `async: true` to start a scan in the background and get a `jobId` immediately:

```
execute_kali_command: nmap -sV -p- 192.168.1.0/24   async: true
→ Job started: a1b2c3d4e5f6 (status: running)
```

Check progress at any time:

```
list_jobs
→ [a1b2c3d4e5f6] running (3m 12s) — nmap -sV -p- 192.168.1.0/24
→ [bb99ff1122aa] done (45s) — ffuf -u https://target.com/FUZZ ...

get_job_output: a1b2c3d4e5f6
→ Job a1b2c3d4 [running] (3m 12s elapsed)
   Starting Nmap 7.98 ( https://nmap.org )
   ...
```

Kill a scan:

```
kill_job: a1b2c3d4e5f6
→ Job a1b2c3d4e5f6 killed
```

### Desktop Control

Take a screenshot (Claude sees it as an image):

```
desktop_screenshot
```

Click, type, key combos:

```
desktop_click: x=960, y=540
desktop_type: text="https://target.com"
desktop_key: keys="Return"
desktop_key: keys="ctrl+l"
```

Launch an app:

```
desktop_run: app_command="firefox"
desktop_run: app_command="burpsuite"
```

Focus a window:

```
desktop_get_window_list
→ 12345678  Mozilla Firefox
→ 87654321  Terminal

desktop_focus_window: window_id=12345678
```

### Cloudflare / CAPTCHA Bypass Workflow

When CLI tools get blocked (403, Cloudflare challenge), use the desktop bridge:

1. `desktop_run: firefox`
2. `desktop_screenshot` — confirm Firefox opened
3. `desktop_key: ctrl+l` → `desktop_type: https://target.com` → `desktop_key: Return`
4. `desktop_screenshot` — if challenge present, pause and ask user to solve in VirtualBox window
5. `desktop_screenshot` — confirm challenge cleared
6. Extract cookies: `desktop_key: F12` → navigate to Application → Cookies
7. Use extracted cookies in CLI tools:
   ```bash
   sqlmap -u "https://target.com/api?id=1" --cookie="cf_clearance=..."
   ffuf -u https://target.com/FUZZ -H "Cookie: cf_clearance=..."
   ```

### Pentest Engagement Workflow

Initialize a workspace:

```
/pt-init <engagement-name> <target>
```

Creates `/home/kali/engagements/<name>/` with subdirs for recon, scans, exploits, loot, poc, and notes.

Start recon with observed tech stack:

```
/pt <observations: CMS=WordPress, auth=JWT, admin panel at /wp-admin, PHP 8.1>
```

Save evidence as you find it:

```bash
# Raw HTTP request/response
curl -v -H "Authorization: Bearer <token>" https://target.com/api/... 2>&1 | tee /home/kali/current/poc/requests/idor_finding.txt

# Screenshot
scrot /home/kali/current/poc/screenshots/privilege_escalation.png
```

---

## MCP Tools Reference

### CLI Tools (kali_mcp_client.py)

| Tool | Arguments | Description |
|------|-----------|-------------|
| `execute_kali_command` | `command` (required), `async` (bool) | Run a command on Kali. Returns output directly or `jobId` if async. |
| `list_jobs` | — | List all background jobs with status and elapsed time. |
| `get_job_output` | `job_id` | Get buffered output of a running or completed job. |
| `kill_job` | `job_id` | SIGTERM the process on Kali and remove its PID file. |

### Desktop Tools (kali_desktop_client.py)

| Tool | Arguments | Description |
|------|-----------|-------------|
| `desktop_screenshot` | `region?` | Capture screen — returned as PNG image to Claude |
| `desktop_click` | `x`, `y`, `button?` | Click at coordinates (button 1=left, 3=right) |
| `desktop_double_click` | `x`, `y` | Double click |
| `desktop_right_click` | `x`, `y` | Right click |
| `desktop_move` | `x`, `y` | Move cursor without clicking |
| `desktop_type` | `text`, `delay?` | Type text into focused element |
| `desktop_key` | `keys` | Key combo: `ctrl+c`, `Return`, `ctrl+l`, `super`, `F12` |
| `desktop_scroll` | `x`, `y`, `direction` | Scroll `up` or `down` at position |
| `desktop_drag` | `x1`, `y1`, `x2`, `y2` | Click and drag |
| `desktop_run` | `app_command` | Launch app by command string |
| `desktop_get_window_list` | — | List open windows with IDs and titles |
| `desktop_focus_window` | `window_id` | Bring window to foreground |
| `desktop_get_screen_size` | — | Returns screen dimensions (1920×955) |
| `desktop_get_cursor_pos` | — | Current cursor X, Y |
| `browser_navigate` | `url`, `proxy_port?` | Navigate Playwright browser, returns page state + screenshot |
| `browser_click` | `selector?`, `x?`, `y?` | Click element by CSS selector or coordinates |
| `browser_type` | `selector`, `text` | Fill a form field |
| `browser_get_state` | — | Current page URL, title, DOM summary |
| `browser_screenshot` | — | Screenshot of current browser page |
| `browser_eval` | `js` | Evaluate JavaScript in page context |
| `browser_get_network` | — | Last 20 XHR/fetch requests with bodies |
| `browser_set_proxy` | `enabled`, `host?`, `port?` | Route browser through Burp Suite |
| `browser_close` | — | Close the persistent Playwright browser |

---

## REST API Reference (Direct HTTP)

The bridge also exposes a REST API you can call directly without Claude:

```
GET  /health                 — liveness check
GET  /v1/jobs                — list all jobs
GET  /v1/jobs/:id            — get job output + status
POST /v1/jobs/:id/kill       — kill a job
POST /v1/tools/execute       — run command (sync or async)
POST /v1/tools/stream        — run command with SSE streaming output
```

**Sync execute:**
```bash
curl -X POST http://localhost:3001/v1/tools/execute \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"execute_kali_command","arguments":{"command":"id"}}'
```

**Async execute:**
```bash
curl -X POST http://localhost:3001/v1/tools/execute \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"execute_kali_command","arguments":{"command":"nmap -sV 10.0.0.0/24"},"async":true}'
# → {"success":true,"jobId":"a1b2c3d4...","status":"running"}

curl http://localhost:3001/v1/jobs/a1b2c3d4...
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_HOST` | — | Kali Linux IP or hostname (**required**) |
| `KALI_PORT` | `22` | SSH port |
| `KALI_USERNAME` | — | SSH user (`root` recommended) |
| `COMMAND_TIMEOUT` | `900000000` | Max command runtime in ms |
| `PORT` | `3001` | CLI bridge HTTP port |
| `SSH_POOL_SIZE` | `5` | Number of persistent SSH ControlMaster sockets |

---

## Project Structure

```
MCP-BRIDGE/
├── bridge-server.js          — CLI bridge: job store, SSH pool, REST API (port 3001)
├── desktop-bridge-server.js  — Desktop bridge: xdotool/scrot/Playwright (port 3002)
├── kali_mcp_client.py        — MCP stdio client for CLI bridge (runs on host)
├── kali_desktop_client.py    — MCP stdio client for desktop bridge (runs on host)
├── mcp_base.py               — Shared MCP infrastructure: stdio loop, JSON-RPC, thread pool
├── start-bridge.sh           — SSH pool init + watchdog (container entrypoint)
├── docker-compose.yml        — Two services: mcp-bridge + desktop-bridge
├── Dockerfile.bridge         — mcp-bridge image (Node.js 20 + openssh-client)
├── Dockerfile.desktop-bridge — desktop-bridge image (Node.js 20 + openssh-client)
├── package.json              — Node dependencies (express, cors)
├── package-lock.json         — Locked dependency versions for reproducible builds
├── .env.example              — Example environment config
├── setup.ps1                 — Windows setup helper
├── setup.sh                  — Linux/macOS setup helper
└── ssh-keys/                 — SSH key pair (gitignored — never commit)
```

---

## Startup & Recovery

### VM IP Changed After Reboot
```bash
# Check new IP on VirtualBox console
ip addr show eth1

# Update .env, then restart
docker compose down && docker compose up -d
```

### Full Restart
```bash
docker compose down && docker compose up -d
```

### SSH Pool Not Connecting
```bash
docker logs mcp-bridge
# "ERROR: No SSH connections after 60s" → VM unreachable or wrong IP/port
# Fix network/firewall in .env, then:
docker compose down && docker compose up -d
```

### apt Broken After Snapshot Restore
```bash
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
apt-get update
```

### start-bridge.sh CRLF Issue (Windows)
If `docker logs mcp-bridge` shows `': not found` or `'leep: invalid number '3`:
```powershell
(Get-Content start-bridge.sh -Raw) -replace "`r`n", "`n" | Set-Content start-bridge.sh -NoNewline
docker compose down && docker compose up -d
```

---

## Changelog

### v2.3

**Critical shell fix:**
- **For loops, variables, and subshells were silently corrupted** — the outer remote bash was expanding `$variables` and `$(subshells)` inside double-quoted strings before `bash -c` received them. For loops produced garbage output; `$code`/`$path` variables resolved to wrong values; POST body payloads with special characters broke mid-request. Fixed by base64-encoding every command in Node.js and decoding on the remote side — `bash -c "$(echo <b64> | base64 -d)"` — so the command arrives on Kali byte-perfect regardless of quotes, dollar signs, or backslashes. Applied to all three SSH construction points: `startJob`, `runSSHDirect`, `executeKaliCommand`.

**Hang/crash fixes (P0):**
- **`waitForJob` race** — re-checks `job.status` after registering the `.once` listener, closing the Node.js synchronous-emit race that could hang sync calls forever
- **`JSON.parse` in `perceptionCall`** — wrapped in try/catch; returns `"Perception server returned invalid JSON: ..."` instead of cryptic `"Unexpected token '<'"`
- **Perception health-check curl had no timeout** — added `-m 5`; prevents the 250-hour lock when the perception server hangs on `/health`
- **All `requests.*` calls now use `(connect, read)` timeout tuples** — bridge-down failures in 5s instead of OS TCP timeout (~2 min)
- **`executor.shutdown(cancel_futures=True)`** — cancels pending futures on MCP client shutdown

**Real bugs fixed (P1):**
- **`desktop_run` log collision** — unique `/tmp/_run_<timestamp>.log` per launch; concurrent app starts no longer clobber each other's error logs
- **`browser_click` with no arguments** — now returns HTTP 400 with a clear error instead of a cryptic xdotool failure
- **`start-bridge.sh`** — `set -euo pipefail` + `${VAR:?required}` guards; exits immediately with `"KALI_HOST is required"` if env vars are missing

**Observability (P2):**
- `log()` in `mcp_base.py` now prefixes `[HH:MM:SS]` timestamps on all stderr output
- `kali_desktop_client.py` logs tool name + sanitized args on every call
- Screenshot validation uses PNG magic bytes (`iVBORw0KGgo`) instead of weak `length < 200` heuristic
- `.env.example` updated with accurate defaults, inline comments, and `DESKTOP_PORT=3002`

### v2.2

**Bug fixes:**
- **KALI_PORT was silently ignored** — all SSH commands now pass `-p ${KALI_PORT}`, including the pool init, healthcheck, and watchdog reconnect in `start-bridge.sh`
- **Perception server race condition** — replaced `sleep 3 && echo started` with a real health-check loop; throws a clear error (with log path) if the server never responds
- **`desktop_focus_window` `windowraise` had no DISPLAY** — `ENV=val cmd1 && cmd2` only sets the env for `cmd1`; fixed by wrapping both xdotool calls in `bash -c '...'`
- **In-flight requests killed on shutdown** — added `executor.shutdown(wait=True)` to drain the thread pool before the MCP client exits
- **`kill_job` left stray PID files** — internal kill now uses `runSSHDirect()` (no PID wrapper) instead of `startJob()`, so no `/tmp/job_*.pid` litter

**Reliability:**
- **Output capped at 10 MB** — prevents OOM kills on large scans; keeps the most recent tail
- **Healthcheck `start_period: 90s`** — prevents false `unhealthy` status during SSH pool init
- **`package-lock.json` added** — Dockerfiles now use `npm ci` for reproducible builds

**Polish:**
- `bridge-server.js` live-mounted in docker-compose (consistent with `desktop-bridge-server.js`, no rebuild needed on edits)
- Elapsed time in `list_jobs` / `get_job_output` now shows `2h 0m` / `1m 5s` / `45s` instead of raw seconds

### v2.1

- Eliminated Alpine relay container — bridge containers now connect directly to Kali over SSH
- Added `EventEmitter`-based job completion notification (replaced 100ms busy-poll)
- Added `mcp_base.py` shared infrastructure for both MCP clients
- Added SSH pool reconnection watchdog in `start-bridge.sh`
- Added `SIGTERM` handler for graceful container shutdown

### v2.0

- SSH ControlMaster connection pool (round-robin across 5 sockets)
- Async job execution with `jobId`, `list_jobs`, `get_job_output`, `kill_job`
- Desktop bridge with `xdotool` + `scrot` + Playwright browser automation
- SSE streaming endpoint for real-time output
- Job auto-eviction (30-minute TTL)
- Remote process kill via PID file

---

## Security

- This tool provides **unrestricted root shell access** to your Kali VM. Only run it on isolated lab networks.
- The bridge HTTP API (ports 3001/3002) has **no authentication** — bind to `127.0.0.1` only or firewall the ports.
- SSH private keys in `ssh-keys/` are `.gitignore`d. Never commit them.
- Only use against systems you own or have explicit written authorization to test.

---

## License

Provided as-is for authorized security testing and educational use. Users are responsible for legal compliance.
