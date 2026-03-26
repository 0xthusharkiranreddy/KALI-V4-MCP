#!/usr/bin/env python3
"""
MCP stdio server for Kali Pentest Bridge — v4.1.0 (SSH ControlMaster pool).
No HTTP bridge. No Docker required. Multiplexed SSH connections to Kali.

Improvements over v4.0:
  - transfer_file: SCP to/from Kali using existing ControlMaster socket
  - execute_parallel: launch multiple async jobs in one call
  - audit_log: append-only JSONL audit trail for engagement post-mortems

v4.0 base:
  - SSHPool: one persistent ControlMaster per target (no handshake per call)
  - Multi-target: KALI_TARGETS env var, optional target= param on every tool
  - Persistent job registry: jobs.json survives Python restarts
  - Retry: 3x exponential backoff on SSH connection errors (exit 255)
  - Output limit: 8MB cap on sync commands with truncation notice
  - Concurrency limit: semaphore(8) per target, prevents sshd saturation
"""

import datetime
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time
import threading
import uuid

from mcp_base import log, send_response, make_base_handler, run_stdio_loop

# ── Config ──────────────────────────────────────────────────────────────────
KALI_HOST        = os.environ.get("KALI_HOST", "192.168.1.202")
KALI_PORT        = os.environ.get("KALI_PORT", "22")
KALI_USER        = os.environ.get("KALI_USER", "root")
SSH_KEY          = os.environ.get("SSH_KEY", r"C:\Users\thiru\Kali-Pentest-MCP\ssh-keys\id_ed25519")
COMMAND_TIMEOUT  = int(os.environ.get("COMMAND_TIMEOUT", str(86400)))
MAX_OUTPUT_BYTES = int(os.environ.get("MCP_MAX_OUTPUT_MB", "8")) * 1024 * 1024
JOB_DIR          = "/tmp/mcp_jobs"  # on Kali

# Persistent store locations (Windows AppData)
_APPDATA   = os.environ.get("APPDATA", str(pathlib.Path.home()))
JOBS_FILE  = pathlib.Path(_APPDATA) / "kali-mcp" / "jobs.json"
AUDIT_FILE = pathlib.Path(_APPDATA) / "kali-mcp" / "audit.jsonl"


# ── SSH / SCP executables ────────────────────────────────────────────────────
def _find_ssh() -> str:
    """
    Prefer Git Bash's OpenSSH (10.x) over Windows OpenSSH (9.x).
    Git's SSH supports ControlMaster via Unix sockets (/tmp paths).
    Windows OpenSSH does NOT support ControlMaster reliably.
    """
    for p in [
        r"C:\Program Files\Git\usr\bin\ssh.exe",       # Git Bash — ControlMaster works
        r"C:\Program Files (x86)\Git\usr\bin\ssh.exe",
        r"C:\Windows\System32\OpenSSH\ssh.exe",         # fallback — no ControlMaster
    ]:
        if os.path.exists(p):
            return p
    return "ssh"

SSH_EXE = _find_ssh()
SCP_EXE = SSH_EXE.replace("ssh.exe", "scp.exe")  # same package, same ControlMaster support


# ── Target registry ──────────────────────────────────────────────────────────
# Format: {"default": {"host": "...", "port": "22", "user": "root", "key": "..."}, ...}
_targets: dict = {}

def _build_target_registry() -> dict:
    """
    Parse KALI_TARGETS env var and combine with default target.
    KALI_TARGETS format: name=user@host:port,name2=user@host2:port2
    Per-target key override: KALI_KEY_<name>=path/to/key
    """
    reg = {
        "default": {
            "host": KALI_HOST,
            "port": KALI_PORT,
            "user": KALI_USER,
            "key":  SSH_KEY,
        }
    }
    raw = os.environ.get("KALI_TARGETS", "").strip()
    if raw:
        for part in raw.split(","):
            part = part.strip()
            if "=" not in part:
                continue
            name, addr = part.split("=", 1)
            name = name.strip()
            addr = addr.strip()
            # addr format: user@host:port  or  host:port  or  host
            user = KALI_USER
            host = addr
            port = "22"
            if "@" in addr:
                user, rest = addr.split("@", 1)
                host = rest
            if ":" in host:
                host, port = host.rsplit(":", 1)
            key = os.environ.get(f"KALI_KEY_{name}", SSH_KEY)
            reg[name] = {"host": host, "port": port, "user": user, "key": key}
    return reg

_targets = _build_target_registry()

def _resolve_target(name_or_addr: str | None) -> dict:
    """
    Resolve a target name or 'user@host:port' string to a config dict.
    Falls back to 'default' if None or empty.
    """
    if not name_or_addr:
        return _targets["default"]
    if name_or_addr in _targets:
        return _targets[name_or_addr]
    # Try to parse as user@host:port inline
    user = KALI_USER
    host = name_or_addr
    port = "22"
    if "@" in host:
        user, host = host.split("@", 1)
    if ":" in host:
        host, port = host.rsplit(":", 1)
    return {"host": host, "port": port, "user": user, "key": SSH_KEY}


# ── SSH ControlMaster pool ───────────────────────────────────────────────────
class SSHPool:
    """
    One persistent ControlMaster SSH process per (user, host, port) target.

    Benefits:
    - Eliminates TCP+handshake overhead per command (~100-300ms on LAN)
    - Transparently restarts dead master processes
    - Limits concurrent commands per target via semaphore (prevents sshd saturation)
    - Retries commands up to 3x on SSH connection failures (exit 255)
    """

    def __init__(self):
        # hkey → {"proc": Popen, "socket": str, "sem": Semaphore}
        self._masters: dict = {}
        self._lock = threading.Lock()

    def _socket_path(self, host: str, port: str, user: str) -> str:
        """
        Use /tmp/ Unix socket path — works with Git Bash's OpenSSH (MSYS2).
        Git's ssh.exe resolves /tmp to the MSYS2 temp directory.
        """
        key = f"{user}_{host}_{port}".replace(".", "_").replace(":", "_").replace("-", "_")
        return f"/tmp/kali_mcp_{key}"

    def _hkey(self, host: str, port: str, user: str) -> str:
        return f"{user}@{host}:{port}"

    def _probe_socket(self, socket_path: str, host: str, port: str,
                      user: str, ssh_key: str) -> bool:
        """
        Verify ControlMaster socket is alive by running 'echo mux_ok' through it.
        More reliable than -O check across all SSH versions.
        """
        try:
            r = subprocess.run(
                [SSH_EXE,
                 "-i", ssh_key,
                 "-o", f"ControlPath={socket_path}",
                 "-o", "ControlMaster=no",
                 "-o", "BatchMode=yes",
                 "-o", "LogLevel=ERROR",
                 "-p", port,
                 f"{user}@{host}",
                 "echo mux_ok"],
                capture_output=True, text=True,
                stdin=subprocess.DEVNULL,
                timeout=6,
            )
            return r.returncode == 0 and "mux_ok" in r.stdout
        except Exception:
            return False

    def ensure_master(self, host: str, port: str, user: str, ssh_key: str) -> tuple:
        """
        Ensure a live ControlMaster exists for this target.
        Uses -f -N (daemonize) with Git OpenSSH 10.x.
        Returns (socket_path, semaphore).
        Raises RuntimeError if the master cannot be established within 20s.
        """
        hkey = self._hkey(host, port, user)
        socket_path = self._socket_path(host, port, user)

        # Fast path: existing registered master — probe it
        with self._lock:
            entry = self._masters.get(hkey)
        if entry:
            if self._probe_socket(socket_path, host, port, user, ssh_key):
                return socket_path, entry["sem"]
            with self._lock:
                self._masters.pop(hkey, None)

        # Slow path: daemonize a new master via -f -N
        log(f"Starting SSH ControlMaster for {hkey}", target=hkey)

        # stdin=DEVNULL is REQUIRED: without it, -f may hang reading from piped stdin
        launcher = subprocess.Popen(
            [
                SSH_EXE,
                "-i", ssh_key,
                "-o", "StrictHostKeyChecking=no",
                "-o", "BatchMode=yes",
                "-o", f"ControlPath={socket_path}",
                "-o", "ControlMaster=yes",
                "-o", "ControlPersist=yes",
                "-o", "ServerAliveInterval=30",
                "-o", "ServerAliveCountMax=6",
                "-o", "LogLevel=ERROR",
                "-p", port,
                f"{user}@{host}",
                "-f", "-N",     # -f: fork after auth, parent exits rc=0
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            launcher.wait(timeout=20)
        except subprocess.TimeoutExpired:
            launcher.kill()
            raise RuntimeError(f"SSH ControlMaster launcher for {hkey} timed out (20s).")

        if launcher.returncode != 0:
            raise RuntimeError(
                f"SSH ControlMaster for {hkey} failed (rc={launcher.returncode}). "
                f"Check SSH key and target reachability."
            )

        # Wait up to 20s for the daemon socket to respond
        deadline = time.time() + 20
        while time.time() < deadline:
            if self._probe_socket(socket_path, host, port, user, ssh_key):
                break
            time.sleep(1)
        else:
            raise RuntimeError(
                f"SSH ControlMaster for {hkey} started but socket did not respond in 20s."
            )

        sem = threading.Semaphore(8)
        with self._lock:
            if hkey not in self._masters:
                self._masters[hkey] = {"socket": socket_path, "sem": sem}
            else:
                sem = self._masters[hkey]["sem"]

        log(f"SSH ControlMaster ready for {hkey}", target=hkey)
        return socket_path, sem

    def run(self, remote_cmd: str, target: dict, timeout: float = None) -> tuple:
        """
        Execute remote_cmd on target via ControlMaster.
        Retries up to 3x on SSH connection errors (exit code 255).
        Truncates output at MAX_OUTPUT_BYTES for sync calls.
        Returns (returncode, output_str).
        """
        host = target["host"]
        port = target["port"]
        user = target["user"]
        key  = target["key"]
        hkey = self._hkey(host, port, user)

        last_rc, last_out = 255, ""
        for attempt in range(3):
            try:
                socket_path, sem = self.ensure_master(host, port, user, key)
                with sem:
                    proc = subprocess.run(
                        [
                            SSH_EXE,
                            "-i", key,                   # identity for fallback auth
                            "-o", f"ControlPath={socket_path}",
                            "-o", "ControlMaster=no",
                            "-o", "BatchMode=yes",
                            "-o", "LogLevel=ERROR",
                            "-p", port,
                            f"{user}@{host}",
                            remote_cmd,
                        ],
                        capture_output=True,
                        text=True,
                        stdin=subprocess.DEVNULL,
                        timeout=timeout,
                    )
                rc  = proc.returncode
                out = proc.stdout
                # Filter out SSH mux noise from stderr (harmless warnings)
                if proc.stderr and proc.stderr.strip():
                    clean_err = "\n".join(
                        l for l in proc.stderr.splitlines()
                        if "mux_client_request_session" not in l
                        and "Connection reset by peer" not in l
                    )
                    if clean_err.strip():
                        out += clean_err

                # Truncate large output
                raw_bytes = out.encode("utf-8", errors="replace")
                if len(raw_bytes) > MAX_OUTPUT_BYTES:
                    out = raw_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
                    out = out.rsplit("\n", 1)[0]
                    mb = MAX_OUTPUT_BYTES // 1024 // 1024
                    out += (
                        f"\n\n[OUTPUT TRUNCATED — exceeded {mb}MB limit. "
                        f"Use async=true for large commands.]"
                    )

                if rc == 255 and attempt < 2:
                    log(
                        f"SSH connection error on {hkey} (attempt {attempt+1}/3), "
                        f"retrying in {2**attempt}s",
                        level="WARN"
                    )
                    # Invalidate ControlMaster so ensure_master recreates it
                    with self._lock:
                        self._masters.pop(hkey, None)
                    time.sleep(2 ** attempt)
                    last_rc, last_out = rc, out
                    continue

                return rc, out

            except subprocess.TimeoutExpired:
                raise
            except RuntimeError:
                raise
            except Exception as e:
                last_rc, last_out = 255, str(e)
                if attempt < 2:
                    time.sleep(2 ** attempt)

        return last_rc, last_out

    def check(self, target: dict) -> tuple:
        """
        Lightweight connection check. Returns (alive: bool, latency_ms: int, info: str).
        """
        t0 = time.time()
        try:
            rc, out = self.run("echo __ok__ && uptime", target, timeout=10)
            latency = int((time.time() - t0) * 1000)
            if rc == 0 and "__ok__" in out:
                info = out.replace("__ok__", "").strip()
                return True, latency, info
            return False, latency, out.strip()
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            return False, latency, str(e)

    def status_of(self, hkey: str) -> str:
        with self._lock:
            entry = self._masters.get(hkey)
        if entry is None:
            return "not connected"
        return "pool ready"  # lightweight — full probe happens on next command


_pool = SSHPool()


# ── Persistent job registry ──────────────────────────────────────────────────
_jobs: dict = {}
_jobs_lock = threading.Lock()


def _load_jobs() -> dict:
    try:
        JOBS_FILE.parent.mkdir(parents=True, exist_ok=True)
        if JOBS_FILE.exists():
            return json.loads(JOBS_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"Could not load jobs from disk: {e}", level="WARN")
    return {}


def _save_jobs(jobs: dict):
    """Atomic write — temp file + rename to avoid corruption."""
    try:
        JOBS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = JOBS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(jobs, indent=2), encoding="utf-8")
        os.replace(tmp, JOBS_FILE)
    except Exception as e:
        log(f"Could not persist jobs to disk: {e}", level="WARN")


# Load on startup
_jobs = _load_jobs()
log(f"Loaded {len(_jobs)} job(s) from disk ({JOBS_FILE})")


# ── Audit log ─────────────────────────────────────────────────────────────────
_audit_lock = threading.Lock()

_SENSITIVE_KEYS = ("key", "pass", "secret", "token", "auth", "credential")


def _audit_append(tool: str, args: dict, target: str = "default",
                  result_summary: str = "", rc: int = 0,
                  job_id: str = None, message: str = None,
                  severity: str = "info", tags: list = None):
    """Append one JSONL entry to the audit log. Sanitises sensitive arg values."""
    safe_args = {}
    for k, v in args.items():
        if any(s in k.lower() for s in _SENSITIVE_KEYS):
            safe_args[k] = "***"
        else:
            safe_args[k] = v

    entry = {
        "ts":             datetime.datetime.utcnow().isoformat() + "Z",
        "tool":           tool,
        "args":           safe_args,
        "target":         target,
        "result_summary": str(result_summary)[:200],
        "rc":             rc,
    }
    if job_id:
        entry["job_id"] = job_id
    if message:
        entry["message"]  = message
        entry["severity"] = severity
    if tags:
        entry["tags"] = tags

    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _audit_lock:
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    except Exception as e:
        log(f"Audit log write failed: {e}", level="WARN")


def _audit_read(since: str = None, tag: str = None, limit: int = 50) -> str:
    """Read audit entries, optionally filtered by timestamp prefix or tag."""
    if not AUDIT_FILE.exists():
        return "Audit log is empty. No entries recorded yet."

    entries = []
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except Exception as ex:
        return f"Error reading audit log: {ex}"

    if since:
        entries = [e for e in entries if e.get("ts", "") >= since]
    if tag:
        entries = [e for e in entries
                   if tag in e.get("tags", [])
                   or tag.lower() in e.get("tool", "").lower()
                   or tag.lower() in e.get("severity", "").lower()]

    entries = entries[-limit:]
    if not entries:
        return "No entries match the specified filter."

    lines = []
    for e in entries:
        ts   = e.get("ts", "")[:19]
        msg  = e.get("message", "")
        if msg:
            sev = e.get("severity", "info").upper()
            tags_str = " [" + ",".join(e.get("tags", [])) + "]" if e.get("tags") else ""
            lines.append(f"{ts} [{sev:8s}]{tags_str} {msg}")
        else:
            tool    = e.get("tool", "?")
            tgt     = e.get("target", "default")
            summary = e.get("result_summary", "")[:80]
            job_str = f" → job:{e['job_id']}" if e.get("job_id") else ""
            rc_str  = f" rc={e.get('rc', '?')}"
            lines.append(f"{ts} [{tool:<22s}] [{tgt}]{job_str}{rc_str} {summary}")

    header = f"Audit log: {len(entries)} entries (of {AUDIT_FILE})\n" + "─" * 60
    return header + "\n" + "\n".join(lines)


# ── Async job management ──────────────────────────────────────────────────────
def _start_job(command: str, target_name: str, target: dict) -> str:
    job_id   = uuid.uuid4().hex[:12]
    out_file = f"{JOB_DIR}/{job_id}.out"
    pid_file = f"{JOB_DIR}/{job_id}.pid"
    hkey     = _pool._hkey(target["host"], target["port"], target["user"])

    launch = (
        f"mkdir -p {JOB_DIR} && "
        f"nohup bash -c {shlex.quote(command)} >{out_file} 2>&1 & "
        f"echo $! >{pid_file} && echo $!"
    )
    rc, out = _pool.run(launch, target, timeout=20)

    status = "running" if rc == 0 else "error"
    entry = {
        "job_id":      job_id,
        "command":     command,
        "status":      status,
        "started_at":  time.time(),
        "out_file":    out_file,
        "pid_file":    pid_file,
        "target_name": target_name,
        "hkey":        hkey,
    }
    with _jobs_lock:
        _jobs[job_id] = entry
        _save_jobs(_jobs)
    return job_id


def _get_output(job_id: str) -> dict:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return {"error": f"Job {job_id} not found"}

    out_file = job["out_file"]
    pid_file = job["pid_file"]
    target   = _resolve_target(job.get("target_name"))

    check = (
        f"cat {out_file} 2>/dev/null ;"
        f" printf '\\n<<<JOB_STATUS>>>' ;"
        f" if [ -f {pid_file} ] && kill -0 \"$(cat {pid_file} 2>/dev/null)\" 2>/dev/null ;"
        f" then echo RUNNING ; else echo DONE ; fi"
    )
    rc, raw = _pool.run(check, target, timeout=15)

    if "<<<JOB_STATUS>>>" in raw:
        output, status_chunk = raw.rsplit("<<<JOB_STATUS>>>", 1)
        status = "running" if "RUNNING" in status_chunk else "done"
    else:
        output = raw
        status = "unknown"

    with _jobs_lock:
        if status in ("done", "unknown"):
            _jobs[job_id]["status"] = "done"
            _save_jobs(_jobs)

    elapsed = int(time.time() - job["started_at"])
    return {
        "job_id":  job_id,
        "status":  status,
        "elapsed": elapsed,
        "output":  output.rstrip("\n"),
        "target":  job.get("target_name", "default"),
    }


def _kill_job(job_id: str) -> str:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return f"Job {job_id} not found"

    pid_file = job["pid_file"]
    target   = _resolve_target(job.get("target_name"))

    kill_cmd = (
        f"if [ -f {pid_file} ]; then"
        f"  PID=$(cat {pid_file});"
        f"  PGID=$(ps -o pgid= -p $PID 2>/dev/null | tr -d ' ');"
        f"  if [ -n \"$PGID\" ]; then kill -- -$PGID 2>/dev/null && echo \"Killed PGID $PGID\";"
        f"  else kill $PID 2>/dev/null && echo \"Killed PID $PID\";"
        f"  fi;"
        f"else echo 'PID file not found (job may have already exited)'; fi"
    )
    rc, out = _pool.run(kill_cmd, target, timeout=10)
    with _jobs_lock:
        _jobs[job_id]["status"] = "killed"
        _save_jobs(_jobs)
    return out.strip() or f"Kill signal sent to job {job_id}"


def _list_jobs() -> str:
    with _jobs_lock:
        snapshot = list(_jobs.values())
    if not snapshot:
        return "No jobs recorded."
    lines = []
    for j in sorted(snapshot, key=lambda x: x.get("started_at", 0), reverse=True):
        elapsed = int(time.time() - j["started_at"])
        e = _fmt_elapsed(elapsed)
        cmd = (j["command"][:80] + "...") if len(j["command"]) > 80 else j["command"]
        tgt = j.get("target_name", "default")
        lines.append(f"[{j['job_id']}] {j['status']:8s} ({e:>8s}) [{tgt}] — {cmd}")
    return "\n".join(lines)


def _fmt_elapsed(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60}m"


# ── File transfer (SCP via ControlMaster) ────────────────────────────────────
def _transfer_file(direction: str, local_path: str, remote_path: str,
                   target: dict) -> str:
    """
    Copy a file to/from Kali using the existing ControlMaster socket.
    direction: "to_kali" | "from_kali"
    Returns human-readable result string.
    """
    host = target["host"]
    port = target["port"]
    user = target["user"]
    key  = target["key"]

    socket_path, sem = _pool.ensure_master(host, port, user, key)

    # SCP uses -P (uppercase) for port; reuses the same ControlPath/ControlMaster options
    scp_cmd = [
        SCP_EXE,
        "-i", key,
        "-o", f"ControlPath={socket_path}",
        "-o", "ControlMaster=no",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",
        "-P", port,
    ]

    if direction == "to_kali":
        scp_cmd += [local_path, f"{user}@{host}:{remote_path}"]
        direction_label = "local → Kali"
    else:
        scp_cmd += [f"{user}@{host}:{remote_path}", local_path]
        direction_label = "Kali → local"

    t0 = time.time()
    with sem:
        proc = subprocess.run(
            scp_cmd,
            capture_output=True, text=True,
            stdin=subprocess.DEVNULL,
            timeout=300,  # 5 minutes for large files
        )
    elapsed_ms = int((time.time() - t0) * 1000)

    if proc.returncode == 0:
        return (
            f"Transfer complete ({direction_label})\n"
            f"Local:   {local_path}\n"
            f"Remote:  {user}@{host}:{remote_path}\n"
            f"Elapsed: {elapsed_ms}ms"
        )
    else:
        err = (proc.stderr or "").strip() or "SCP failed (no error output)"
        raise RuntimeError(f"SCP error (rc={proc.returncode}): {err}")


# ── Tool definitions ──────────────────────────────────────────────────────────
TOOLS = [
    {
        "name": "execute_kali_command",
        "description": (
            "Execute a shell command on a Kali Linux VM as root via SSH ControlMaster pool. "
            "Connection is persistent — no handshake overhead after first call. "
            "For long-running tools (nmap, sqlmap, hydra, nuclei, ffuf) set async=true "
            "to get a jobId immediately and poll with get_job_output. "
            "CRITICAL: Each call is an independent shell — variables do NOT persist between calls. "
            "Always redeclare TARGET=..., WORDLIST=..., etc. at the top of every command. "
            "Sync output is capped at 8MB — use async=true for commands with large output. "
            "Use target= to run on a different VM (see list_targets for available targets)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command(s) to run on Kali as root. May chain with && or ;."
                },
                "async": {
                    "type": "boolean",
                    "description": (
                        "If true, launch in background and return jobId immediately. "
                        "Use for any scan expected to run longer than ~10 seconds."
                    )
                },
                "target": {
                    "type": "string",
                    "description": (
                        "Target name from list_targets, or 'user@host:port'. "
                        "Omit to use the default Kali VM."
                    )
                }
            },
            "required": ["command"]
        }
    },
    {
        "name": "list_jobs",
        "description": (
            "List all background jobs (current session + persisted from prior sessions). "
            "Shows job ID, status, elapsed time, and target."
        ),
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "get_job_output",
        "description": (
            "Fetch current output of a background job via SSH. "
            "Works for running and completed jobs, including jobs from prior Claude Code sessions. "
            "Safe to call repeatedly — each call is a single SSH read."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {
                    "type": "string",
                    "description": "Job ID returned by execute_kali_command(async=true) or list_jobs"
                }
            },
            "required": ["job_id"]
        }
    },
    {
        "name": "kill_job",
        "description": "Kill a running background job and its entire process group on Kali (SIGTERM to PGID).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job ID to kill"}
            },
            "required": ["job_id"]
        }
    },
    {
        "name": "list_targets",
        "description": (
            "List all registered Kali targets with their connection status. "
            "Use to verify available targets before using the target= param on execute_kali_command."
        ),
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "check_connection",
        "description": (
            "Verify SSH connectivity to a target and measure latency. "
            "Returns ALIVE/DEAD, latency in ms, and uptime. "
            "Run this first if you suspect connectivity issues."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target name or 'user@host:port'. Omit for default target."
                }
            }
        }
    },
    {
        "name": "transfer_file",
        "description": (
            "Copy a file to or from Kali using SCP over the existing SSH ControlMaster socket. "
            "No new SSH connection — reuses the multiplexed tunnel. "
            "Use to upload wordlists, custom tools, or exploit scripts to Kali; "
            "or download loot files, scan results, and reports to Windows."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "direction": {
                    "type": "string",
                    "enum": ["to_kali", "from_kali"],
                    "description": "'to_kali' uploads from Windows to Kali. 'from_kali' downloads to Windows."
                },
                "local_path": {
                    "type": "string",
                    "description": "Absolute Windows path (e.g. C:\\\\Users\\\\thiru\\\\wordlist.txt)"
                },
                "remote_path": {
                    "type": "string",
                    "description": "Absolute Kali path (e.g. /home/kali/loot/flag.txt)"
                },
                "target": {
                    "type": "string",
                    "description": "Target name or 'user@host:port'. Omit for default."
                }
            },
            "required": ["direction", "local_path", "remote_path"]
        }
    },
    {
        "name": "execute_parallel",
        "description": (
            "Launch multiple shell commands as async background jobs simultaneously in a single call. "
            "All jobs start at the same time — ideal for running nmap + ffuf + nuclei together, "
            "or scanning multiple targets concurrently. "
            "Returns all job IDs immediately. Poll each with get_job_output."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "commands": {
                    "type": "array",
                    "description": "List of commands to launch in parallel",
                    "items": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Shell command to run on Kali"
                            },
                            "target": {
                                "type": "string",
                                "description": "Target name or 'user@host:port'. Omit for default."
                            },
                            "label": {
                                "type": "string",
                                "description": "Human-readable label for this job (e.g. 'nmap-fullport')"
                            }
                        },
                        "required": ["command"]
                    },
                    "minItems": 1
                }
            },
            "required": ["commands"]
        }
    },
    {
        "name": "audit_log",
        "description": (
            "Append-only JSONL audit trail for the engagement. "
            "Every MCP tool call is auto-logged. Use this tool to: "
            "(1) add a manual finding or note with severity tagging, "
            "(2) read the audit trail filtered by time or tag. "
            "Stored at %APPDATA%\\kali-mcp\\audit.jsonl — survives restarts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["write", "read"],
                    "description": "'write' adds a manual entry. 'read' retrieves entries."
                },
                "message": {
                    "type": "string",
                    "description": "[write] The note or finding to record."
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "finding", "critical"],
                    "description": "[write] Severity level (default: info)."
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "[write] Optional tags e.g. ['sqli', 'critical', 'target1']"
                },
                "since": {
                    "type": "string",
                    "description": "[read] ISO8601 date prefix to filter from (e.g. '2025-01-15')"
                },
                "tag": {
                    "type": "string",
                    "description": "[read] Filter entries by tag or tool name substring."
                },
                "limit": {
                    "type": "integer",
                    "description": "[read] Max entries to return (default: 50)."
                }
            },
            "required": ["action"]
        }
    },
]

SERVER_INFO  = {"name": "kali-pentest-bridge", "version": "4.1.0"}
_handle_base = make_base_handler(SERVER_INFO, TOOLS)


# ── Message dispatcher ────────────────────────────────────────────────────────
def handle_message(line: str):
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        return

    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if _handle_base(req):
        return

    if method != "tools/call":
        if req_id is not None:
            send_response(req_id, error={"code": -32601, "message": f"Method not found: {method}"})
        return

    tool = params.get("name")
    args = params.get("arguments", {})

    try:
        # ── execute_kali_command ───────────────────────────────────────────
        if tool == "execute_kali_command":
            cmd = args.get("command", "").strip()
            if not cmd:
                send_response(req_id, error={"code": -32602, "message": "Missing 'command'"})
                return

            target_name = args.get("target") or "default"
            target      = _resolve_target(target_name)
            is_async    = args.get("async", False)

            if is_async:
                job_id = _start_job(cmd, target_name, target)
                text = (
                    f"Job started: {job_id} (status: running) [{target_name}]\n"
                    f"Poll output: get_job_output(job_id='{job_id}')\n"
                    f"Cancel:      kill_job(job_id='{job_id}')"
                )
                _audit_append(tool, args, target=target_name,
                              result_summary=f"async job {job_id}", rc=0, job_id=job_id)
            else:
                rc, out = _pool.run(cmd, target, timeout=COMMAND_TIMEOUT)
                text = out if out.strip() else f"[Command completed, exit code {rc}, no output]"
                _audit_append(tool, args, target=target_name,
                              result_summary=text[:200], rc=rc)

            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        # ── list_jobs ─────────────────────────────────────────────────────
        elif tool == "list_jobs":
            text = _list_jobs()
            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        # ── get_job_output ────────────────────────────────────────────────
        elif tool == "get_job_output":
            job_id = args.get("job_id", "").strip()
            if not job_id:
                send_response(req_id, error={"code": -32602, "message": "Missing 'job_id'"})
                return
            result = _get_output(job_id)
            if "error" in result:
                send_response(req_id, error={"code": -32000, "message": result["error"]})
                return
            elapsed = _fmt_elapsed(result["elapsed"])
            tgt     = result.get("target", "default")
            text    = (
                f"Job {result['job_id']} [{result['status']}] ({elapsed} elapsed) [{tgt}]\n\n"
                f"{result['output']}"
            )
            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        # ── kill_job ──────────────────────────────────────────────────────
        elif tool == "kill_job":
            job_id = args.get("job_id", "").strip()
            if not job_id:
                send_response(req_id, error={"code": -32602, "message": "Missing 'job_id'"})
                return
            text = _kill_job(job_id)
            _audit_append(tool, args, result_summary=text, rc=0)
            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        # ── list_targets ──────────────────────────────────────────────────
        elif tool == "list_targets":
            lines = []
            for name, cfg in _targets.items():
                hkey   = _pool._hkey(cfg["host"], cfg["port"], cfg["user"])
                status = _pool.status_of(hkey)
                addr   = f"{cfg['user']}@{cfg['host']}:{cfg['port']}"
                lines.append(f"{name:<12} {addr:<28} [{status}]")
            text = "\n".join(lines) if lines else "No targets registered."
            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        # ── check_connection ──────────────────────────────────────────────
        elif tool == "check_connection":
            target_name = args.get("target") or "default"
            target      = _resolve_target(target_name)
            alive, latency, info = _pool.check(target)
            addr = f"{target['user']}@{target['host']}:{target['port']}"
            status_str = "ALIVE" if alive else "DEAD"
            text = (
                f"Target:  {target_name} ({addr})\n"
                f"Status:  {status_str}\n"
                f"Latency: {latency}ms\n"
                f"Info:    {info}"
            )
            _audit_append(tool, args, target=target_name,
                          result_summary=f"{status_str} {latency}ms", rc=0 if alive else 1)
            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        # ── transfer_file ─────────────────────────────────────────────────
        elif tool == "transfer_file":
            direction   = args.get("direction", "").strip()
            local_path  = args.get("local_path", "").strip()
            remote_path = args.get("remote_path", "").strip()
            target_name = args.get("target") or "default"
            target      = _resolve_target(target_name)

            if direction not in ("to_kali", "from_kali"):
                send_response(req_id, error={"code": -32602,
                              "message": "direction must be 'to_kali' or 'from_kali'"})
                return
            if not local_path or not remote_path:
                send_response(req_id, error={"code": -32602,
                              "message": "local_path and remote_path are required"})
                return

            text = _transfer_file(direction, local_path, remote_path, target)
            _audit_append(tool, args, target=target_name, result_summary=text[:200], rc=0)
            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        # ── execute_parallel ──────────────────────────────────────────────
        elif tool == "execute_parallel":
            commands = args.get("commands", [])
            if not commands:
                send_response(req_id, error={"code": -32602, "message": "commands list is empty"})
                return

            results = []
            for item in commands:
                cmd = item.get("command", "").strip()
                if not cmd:
                    continue
                target_name = item.get("target") or "default"
                label       = item.get("label") or (cmd[:40] + "..." if len(cmd) > 40 else cmd)
                tgt         = _resolve_target(target_name)
                try:
                    job_id = _start_job(cmd, target_name, tgt)
                    results.append({
                        "job_id":  job_id,
                        "label":   label,
                        "target":  target_name,
                        "status":  "running",
                    })
                    _audit_append("execute_kali_command",
                                  {"command": cmd, "async": True},
                                  target=target_name,
                                  result_summary=f"parallel job {job_id}",
                                  rc=0, job_id=job_id)
                except Exception as e:
                    results.append({
                        "job_id":  None,
                        "label":   label,
                        "target":  target_name,
                        "status":  f"error: {e}",
                    })

            lines = [f"Launched {len(results)} parallel job(s):\n"]
            for r in results:
                jid = r["job_id"] or "FAILED"
                lines.append(
                    f"  [{jid}] {r['status']:8s} [{r['target']}] {r['label']}"
                )
            lines.append("\nPoll each with: get_job_output(job_id='<id>')")
            text = "\n".join(lines)
            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        # ── audit_log ─────────────────────────────────────────────────────
        elif tool == "audit_log":
            action = args.get("action", "read")

            if action == "write":
                message  = args.get("message", "").strip()
                severity = args.get("severity", "info")
                tags     = args.get("tags", [])
                if not message:
                    send_response(req_id, error={"code": -32602,
                                  "message": "message is required for write"})
                    return
                _audit_append("audit_log", {}, message=message,
                              severity=severity, tags=tags)
                text = f"Audit entry recorded [{severity}]: {message}"

            elif action == "read":
                since = args.get("since")
                tag   = args.get("tag")
                limit = int(args.get("limit", 50))
                text  = _audit_read(since=since, tag=tag, limit=limit)

            else:
                send_response(req_id, error={"code": -32602,
                              "message": f"Unknown action: {action}. Use 'read' or 'write'."})
                return

            send_response(req_id, {"content": [{"type": "text", "text": text}]})

        else:
            send_response(req_id, error={"code": -32601, "message": f"Unknown tool: {tool}"})

    except subprocess.TimeoutExpired:
        send_response(req_id, error={"code": -32000, "message": "SSH command timed out"})
    except RuntimeError as e:
        send_response(req_id, error={"code": -32000, "message": str(e)})
    except Exception as e:
        send_response(req_id, error={"code": -32000, "message": f"Unexpected error: {e}"})


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    log(f"kali-pentest-bridge v4.1.0 — SSH ControlMaster pool + transfer + parallel + audit")
    log(f"Default target : {KALI_USER}@{KALI_HOST}:{KALI_PORT}")
    log(f"SSH key        : {SSH_KEY}")
    log(f"SSH exe        : {SSH_EXE}")
    log(f"SCP exe        : {SCP_EXE}")
    log(f"Job dir        : {JOB_DIR} (on Kali)")
    log(f"Jobs file      : {JOBS_FILE}")
    log(f"Audit file     : {AUDIT_FILE}")
    log(f"Max output     : {MAX_OUTPUT_BYTES // 1024 // 1024}MB (sync commands)")
    if len(_targets) > 1:
        extras = [k for k in _targets if k != "default"]
        log(f"Extra targets  : {', '.join(extras)}")
    run_stdio_loop(handle_message, "kali-pentest-bridge")


if __name__ == "__main__":
    main()
