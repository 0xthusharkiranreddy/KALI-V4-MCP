---
name: Kali MCP Bridge — Actual Architecture (vs CLAUDE.md)
description: Current implementation details from reading the actual code — divergences from CLAUDE.md documented here
type: project
---

## What CLAUDE.md gets wrong / is outdated on

**MCP client files location**: CLAUDE.md says `C:\Users\thiru\kali-mcp-client\`. Reality: they are in `C:\Users\thiru\Kali-Pentest-MCP\` (`kali_mcp_client.py`, `kali_desktop_client.py`, `mcp_base.py`).

**Kali VM IP**: CLAUDE.md says 192.168.1.206. Current `.env` has `KALI_HOST=192.168.1.202`.

**Desktop bridge is Windows-native (NOT Docker)**. The `docker-compose.yml` confirms this with a comment. Only `mcp-bridge` runs in Docker (port 3001). Start desktop bridge with:
```
$env:KALI_HOST="..."; $env:KALI_PORT="22"; $env:KALI_USERNAME="root"
$env:DESKTOP_PORT="3002"; $env:SSH_KEY="C:/Users/thiru/Kali-Pentest-MCP/ssh-keys/id_ed25519"
node desktop-bridge-server.js
```

**Desktop bridge has its own SSH pool** (5 connections to Kali, direct SSH). It does NOT delegate to CLI bridge at 3001 — that was a previous design. Both bridges SSH directly to Kali independently.

**Screenshots use VBoxManage screenshotpng** (not scrot). Config in desktop-bridge-server.js:
- `VBOXMANAGE = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'`
- `VBOX_VM = 'kali-linux-2025.4-virtualbox-amd64'`
- `SHOT_TMP = 'C:\Users\thiru\AppData\Local\Temp\_vbox_shot.png'`

**xdotool auth**: `DISPLAY=:0 XAUTHORITY=/var/run/lightdm/root/:0`

**GUI apps launched via**: `su kali -c "DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority nohup bash -c <cmd> </dev/null ><log> 2>&1 &"`

---

## Perception / Browser tools (new — not in CLAUDE.md at all)

Desktop bridge now has a **Playwright perception server** running on Kali at port 5000.

Venv: `/opt/perception-venv/bin/python3`
Script: `/home/kali/perception-server.py`
Log: `/tmp/perception.log`

The bridge auto-starts it on first use and caches readiness. Browser tools exposed:
- `browser_navigate` — navigate to URL, returns structured state (url, title, forms, buttons, links, state_hash). Screenshot only on CAPTCHA detection.
- `browser_click` — click by CSS selector or x,y coordinates
- `browser_type` — fill form fields by selector
- `browser_get_state` — get current page state without interaction
- `browser_screenshot` — explicit screenshot (use sparingly; prefer browser_get_state)
- `browser_eval` — run arbitrary JS in page context (extract cookies, DOM manipulation)
- `browser_get_network` — last 20 XHR/fetch/document requests with URL, method, status, body
- `browser_set_proxy` — route all Playwright traffic through Burp (127.0.0.1:8080)
- `browser_close` — close browser; next navigate opens fresh one

Optional `proxy_port` on `browser_navigate` routes through Burp for that session.

---

## CLI bridge — job management (not in CLAUDE.md)

CLI bridge (Docker, port 3001) has async job system:
- `execute_kali_command` with `async: true` → returns `jobId` immediately
- `list_jobs` — show all running/completed jobs
- `get_job_output` — poll output of a job by jobId
- `kill_job` — SIGTERM the remote process via PID file

Job store evicts jobs after 30 min. Max output buffered: 10MB.

---

## Startup procedure (correct)

1. Start Docker Desktop
2. `cd C:\Users\thiru\Kali-Pentest-MCP && docker compose up -d` (CLI bridge only — mcp-bridge container)
3. Verify: `docker logs mcp-bridge` → "SSH pool ready: 5/5 connections"
4. Start desktop bridge natively: set env vars, then `node desktop-bridge-server.js`
5. Verify: `curl http://localhost:3001/health` → `{"status":"ok","service":"mcp-bridge"}`
         `curl http://localhost:3002/health` → `{"status":"ok","service":"desktop-bridge"}`

---

## Git repo
https://github.com/0xthusharkiranreddy/MCP-BRIDGE
Files NOT in git: `.env`, `ssh-keys/`

## Coordinate scaling
VBoxManage captures at 1920x955. Claude displays scaled down. Multiply displayed coords by ~1.25 for actual xdotool coords.
