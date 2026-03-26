---
description: Network discovery & infrastructure signal planner — interface detection, ARP sweep, full port scan, service fingerprinting, vuln correlation, protocol enumeration, attack surface map
argument-hint: <interface|subnet> (e.g. eth0, wlan0, 192.168.1.0/24)
allowed-tools: [mcp__kali-pentest__execute_kali_command, mcp__kali-pentest__execute_parallel]
---

# pt-net — Network Discovery & Infrastructure Attack Planner

You are an expert network penetration tester. Map the full local network attack surface: discover all live hosts, fingerprint every service, correlate versions against known CVEs, enumerate each protocol in depth, and produce a signal-driven attack plan that points to the right sub-skills to execute next.

**This is the `/pt` equivalent for networks. Run it first on any local engagement, then use its output to drive `/pt-exploit`, `/pt-mitm`, `/pt-wifi`, `/pt-iot`, `/pt-ad`.**

---

## Step 0 — Parse Arguments & Setup

`$ARGUMENTS` = `<interface|subnet>`
- If argument looks like an interface name (e.g. `eth0`, `wlan0`, `ens33`) → auto-detect subnet from it
- If argument looks like CIDR (e.g. `192.168.1.0/24`) → use directly; auto-detect local interface
- If argument is a single IP → scan that host only (all phases still apply)
- If no argument → auto-detect primary interface

```bash
ENG=/home/kali/current
mkdir -p $ENG/{recon/network,scans/{nmap,masscan},loot,poc/requests,notes} 2>/dev/null

ARG="<argument>"

# Detect interface and subnet
if echo "$ARG" | grep -qE '^[a-z]'; then
    # It's an interface name
    IFACE="$ARG"
    LOCAL_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)
    CIDR=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+/\d+' | head -1)
    SUBNET=$(echo "$CIDR" | sed 's|\.[0-9]*/|.0/|')
else
    # It's a subnet CIDR or single IP
    SUBNET="$ARG"
    IFACE=$(ip route | grep "$(echo $SUBNET | cut -d/ -f1 | sed 's/\.[0-9]*$//')" | awk '{print $NF}' | head -1)
    [ -z "$IFACE" ] && IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    LOCAL_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)
fi

GATEWAY=$(ip route | grep default | awk '{print $3}' | head -1)

echo "=== Network Engagement Setup ==="
echo "  Interface : $IFACE"
echo "  Local IP  : $LOCAL_IP"
echo "  Subnet    : $SUBNET"
echo "  Gateway   : $GATEWAY"
echo ""
echo "All interfaces:"
ip link show | grep -E "^[0-9]+:" | awk '{print "  "$2}' | tr -d ':'
echo ""
echo "Wireless interfaces:"
iw dev 2>/dev/null | grep "Interface" | awk '{print "  "$2}' || echo "  (none / no wireless)"
```

Read existing engagement context:
```bash
cat /home/kali/current/notes/engagement.md 2>/dev/null | head -40 || echo "[no active engagement — run /pt-init for web targets, or continue with network-only scope]"
```

---

## Phase 1 — ARP Sweep (Live Host Discovery)

ARP is the most reliable discovery method on local networks — it bypasses host-based firewalls.

```bash
IFACE=<interface>
SUBNET=<subnet>
ENG=/home/kali/current

echo "=== [Phase 1] ARP Sweep — Live Host Discovery ==="
echo "Target subnet: $SUBNET"
echo ""

# Primary: arp-scan (fast, reliable, shows vendor OUI)
echo "--- arp-scan (MAC vendor lookup) ---"
arp-scan --interface="$IFACE" --localnet 2>/dev/null | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort -t. -k4 -n | tee $ENG/recon/network/arp_scan.txt

# Count results
LIVE_COUNT=$(cat $ENG/recon/network/arp_scan.txt | grep -c "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null || echo 0)
echo ""
echo "Live hosts detected: $LIVE_COUNT"
echo ""

# Secondary: netdiscover passive (catches hosts arp-scan misses)
echo "--- netdiscover (15s passive ARP monitoring) ---"
timeout 15 netdiscover -i "$IFACE" -r "$SUBNET" -P 2>/dev/null | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | tee -a $ENG/recon/network/arp_scan.txt

# Extract unique IPs for subsequent phases
grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" $ENG/recon/network/arp_scan.txt | sort -u | grep -v "^$LOCAL_IP$" > $ENG/recon/network/live_hosts.txt
echo ""
echo "Unique live hosts (excluding self):"
cat $ENG/recon/network/live_hosts.txt
echo ""
echo "Saved → $ENG/recon/network/live_hosts.txt ($(wc -l < $ENG/recon/network/live_hosts.txt) hosts)"
```

---

## Phase 2 — Fast Port Scan (All 65535 Ports)

```bash
SUBNET=<subnet>
ENG=/home/kali/current

echo "=== [Phase 2] masscan — All Ports (1-65535) ==="
echo "Rate: 1000 pps (adjust if on sensitive network)"
echo ""

# masscan is ~100x faster than nmap for initial port discovery
masscan "$SUBNET" -p1-65535 --rate=1000 --open-only \
    -oL $ENG/scans/masscan/all_ports.txt 2>/dev/null

# Parse masscan output to get host:port pairs
echo "--- Open ports discovered ---"
grep "^open" $ENG/scans/masscan/all_ports.txt 2>/dev/null | \
    awk '{print $4":"$3}' | sort -t: -k1,1V -k2,2n | tee $ENG/scans/masscan/open_ports_parsed.txt

echo ""
echo "Port summary by host:"
grep "^open" $ENG/scans/masscan/all_ports.txt 2>/dev/null | awk '{print $4}' | sort | uniq -c | sort -rn | while read count ip; do
    ports=$(grep "^open.*$ip " $ENG/scans/masscan/all_ports.txt | awk '{print $3}' | sort -n | tr '\n' ',' | sed 's/,$//')
    echo "  $ip ($count ports): $ports"
done
```

---

## Phase 3 — Service + OS Fingerprinting (nmap Deep Scan)

Run nmap on live hosts discovered in Phase 1/2 for full service version detection:

```bash
ENG=/home/kali/current

# Get list of hosts to scan (from masscan results or arp-scan)
HOSTS=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" $ENG/scans/masscan/all_ports.txt 2>/dev/null | sort -u | head -50)
[ -z "$HOSTS" ] && HOSTS=$(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | head -50)

# Get open ports from masscan to tell nmap exactly what to scan (much faster)
PORTS=$(grep "^open" $ENG/scans/masscan/all_ports.txt 2>/dev/null | awk '{print $3}' | sort -un | tr '\n' ',' | sed 's/,$//')
[ -z "$PORTS" ] && PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,3389,5900,8080,8443,8888,9090,37777,554,161"

echo "=== [Phase 3] nmap Service + OS Fingerprinting ==="
echo "Scanning ports: $PORTS"
echo "Hosts: $(echo $HOSTS | wc -w)"
echo ""

nmap -sV -sC -O -T4 --open -Pn \
    -p "$PORTS" \
    --version-intensity 7 \
    -oA $ENG/scans/nmap/service_scan \
    $HOSTS 2>/dev/null | tee $ENG/scans/nmap/service_scan.txt

echo ""
echo "=== Service Summary ==="
grep "^[0-9].*open" $ENG/scans/nmap/service_scan.txt | sort -t/ -k1,1n | \
    awk '{printf "  %-20s %s\n", $1, $3" "$4" "$5" "$6" "$7}' | head -60
```

---

## Phase 4 — Vulnerability Correlation

For each detected service version, find known exploits:

```bash
ENG=/home/kali/current

echo "=== [Phase 4] Vulnerability Correlation ==="
echo ""

# Extract service versions from nmap scan
echo "--- searchsploit — known exploits for detected versions ---"
grep "^[0-9].*open" $ENG/scans/nmap/service_scan.txt 2>/dev/null | while IFS= read -r line; do
    port=$(echo "$line" | awk '{print $1}')
    service=$(echo "$line" | awk '{print $3}')
    version=$(echo "$line" | grep -oP '[\d]+\.[\d]+\.?[\d]*' | head -1)
    [ -z "$version" ] && continue
    RESULT=$(searchsploit --color "$service $version" 2>/dev/null | grep -v "^---\|^Exploit\|^$" | head -5)
    [ -n "$RESULT" ] && echo "  [$port $service $version]" && echo "$RESULT" | sed 's/^/    /'
done

echo ""
echo "--- nmap vuln scripts (top exploited services) ---"
# Run vuln NSE scripts only on interesting ports
VULN_PORTS=$(grep "^[0-9].*open" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -E "smb|ftp|rdp|vnc|telnet|http|apache|nginx|iis|openssh|ms-sql|mysql|postgres" | \
    awk '{print $1}' | tr '\n' ',' | sed 's/,$//')

[ -n "$VULN_PORTS" ] && nmap --script "vuln,auth,default" -p "$VULN_PORTS" \
    --script-timeout 30s -T4 \
    $(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | head -20 | tr '\n' ' ') \
    -oN $ENG/scans/nmap/vuln_scan.txt 2>/dev/null | \
    grep -E "VULNERABLE|CVE-[0-9]|CRITICAL|HIGH|exploitable|risk" | head -30

echo ""
echo "--- nuclei CVE templates on web services ---"
WEB_HOSTS=$(grep "^[0-9]\(80\|443\|8080\|8443\|8888\).*open" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\(.*?\)' | tr -d '()' | head -10)
for host in $(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | head -20); do
    for port in 80 443 8080 8443; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://$host:$port/" 2>/dev/null)
        [ "$code" != "000" ] && echo "http://$host:$port"
    done
done > /tmp/web_targets.txt 2>/dev/null

[ -s /tmp/web_targets.txt ] && nuclei -l /tmp/web_targets.txt \
    -t /root/.local/nuclei-templates/cves/ \
    -t /root/.local/nuclei-templates/network/ \
    -severity critical,high,medium \
    -o $ENG/scans/nuclei/network_cves.txt 2>/dev/null | \
    grep -E "\[critical\]|\[high\]|\[medium\]" | head -30

echo ""
echo "Vuln results → $ENG/scans/nmap/vuln_scan.txt"
echo "Nuclei results → $ENG/scans/nuclei/network_cves.txt"
```

---

## Phase 5 — Admin Portal Discovery

Find web management interfaces on all live hosts:

```bash
ENG=/home/kali/current

echo "=== [Phase 5] Admin Portal Discovery ==="
echo ""

MGMT_PORTS="80 443 8080 8443 8888 9090 9443 2082 2083 2086 2087 10000 8161 6080 3000 8181 7547 8008"

while IFS= read -r host; do
    FOUND=""
    for port in $MGMT_PORTS; do
        result=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}|%{url_effective}" \
            "http://$host:$port/" 2>/dev/null)
        code=$(echo "$result" | cut -d'|' -f1)
        [ "$code" != "000" ] && [ "$code" != "400" ] && {
            title=$(curl -sk --max-time 4 "http://$host:$port/" 2>/dev/null | \
                grep -oP '(?<=<title>)[^<]+' | head -1 | tr -d '\n')
            echo "  $host:$port → HTTP $code | $title"
            FOUND=1
        }
    done
    [ -z "$FOUND" ] && echo "  $host → no web management interface found"
done < $ENG/recon/network/live_hosts.txt

echo ""
echo "Interesting admin portals saved for /pt-exploit and /pt-iot"
```

---

## Phase 6 — Protocol Enumeration (Based on Open Ports)

Run targeted protocol-specific enumeration for each detected service:

```bash
ENG=/home/kali/current

echo "=== [Phase 6] Protocol-Specific Enumeration ==="
echo ""

# Read all hosts and their open ports from nmap
HOST_PORTS=$(grep "Host:\|open" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -A100 "Host:" | grep "open" | head -100)

# --- SMB 445 ---
SMB_HOSTS=$(grep "445.*open\|microsoft-ds" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -10)
if [ -n "$SMB_HOSTS" ]; then
    echo "--- SMB Enumeration (port 445) ---"
    for host in $SMB_HOSTS; do
        echo "  Host: $host"
        netexec smb "$host" 2>/dev/null | tail -3
        netexec smb "$host" --shares 2>/dev/null | grep -v "\[\*\] " | head -10
        echo ""
    done
fi

# --- SNMP 161 ---
SNMP_HOSTS=$(grep "161.*open\|snmp" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -10)
if [ -n "$SNMP_HOSTS" ]; then
    echo "--- SNMP Enumeration (port 161) ---"
    for host in $SNMP_HOSTS; do
        echo "  Host: $host"
        for community in public private community admin snmp cisco; do
            result=$(snmpwalk -v2c -c "$community" -t 2 "$host" sysDescr 2>/dev/null | head -1)
            [ -n "$result" ] && echo "  [SNMP COMMUNITY '$community' WORKS] $result" && \
                snmpwalk -v2c -c "$community" "$host" 2>/dev/null | \
                grep -iE "sysName|sysLocation|sysContact|ifDescr|ipAddrTable" | \
                tee $ENG/loot/snmp_${host}.txt | head -20
        done
        echo ""
    done
fi

# --- FTP 21 ---
FTP_HOSTS=$(grep " 21/tcp.*open\|ftp" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -10)
if [ -n "$FTP_HOSTS" ]; then
    echo "--- FTP Enumeration (port 21) ---"
    for host in $FTP_HOSTS; do
        echo "  Host: $host"
        # Anonymous login check
        timeout 8 bash -c "echo -e 'USER anonymous\nPASS anonymous@test.com\nLIST\nQUIT' | nc -w 5 $host 21 2>/dev/null" | head -10
        echo ""
    done
fi

# --- SMTP 25/587 ---
SMTP_HOSTS=$(grep " 25/tcp.*open\| 587/tcp.*open\|smtp" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -5)
if [ -n "$SMTP_HOSTS" ]; then
    echo "--- SMTP Enumeration ---"
    nmap --script smtp-enum-users,smtp-open-relay \
        -p 25,587 $SMTP_HOSTS 2>/dev/null | grep -v "^$\|^#" | head -20
fi

# --- VNC 5900 ---
VNC_HOSTS=$(grep " 5900.*open\|vnc" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -10)
if [ -n "$VNC_HOSTS" ]; then
    echo "--- VNC Enumeration (port 5900) ---"
    nmap --script vnc-info,vnc-brute --script-args brute.mode=user \
        -p 5900,5901 $VNC_HOSTS 2>/dev/null | grep -E "auth|VNC|Version|Security" | head -20
fi

# --- RDP 3389 ---
RDP_HOSTS=$(grep " 3389.*open\|ms-wbt-server" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -10)
if [ -n "$RDP_HOSTS" ]; then
    echo "--- RDP Enumeration (port 3389) ---"
    nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 \
        -p 3389 $RDP_HOSTS 2>/dev/null | grep -E "encryption|NLA|vuln|CVE|VULNERABLE" | head -15
fi

# --- RTSP 554 (cameras) ---
RTSP_HOSTS=$(grep " 554.*open\|rtsp" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -10)
if [ -n "$RTSP_HOSTS" ]; then
    echo "--- RTSP Detected (IP Cameras likely) → run /pt-iot ---"
    for host in $RTSP_HOSTS; do
        echo "  [CAMERA] $host:554 — RTSP stream present"
    done
fi

# --- Telnet 23 ---
TELNET_HOSTS=$(grep " 23/tcp.*open\|telnet" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -10)
if [ -n "$TELNET_HOSTS" ]; then
    echo "--- Telnet Detected (default creds likely) → run /pt-exploit ---"
    for host in $TELNET_HOSTS; do
        banner=$(timeout 5 bash -c "echo '' | nc -w 3 $host 23 2>/dev/null | strings | head -3")
        echo "  [TELNET] $host — Banner: $banner"
    done
fi

# --- SSH cipher audit ---
SSH_HOSTS=$(grep " 22/tcp.*open\|ssh" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -10)
if [ -n "$SSH_HOSTS" ]; then
    echo "--- SSH Cipher Audit ---"
    nmap --script ssh2-enum-algos,ssh-auth-methods \
        -p 22 $SSH_HOSTS 2>/dev/null | grep -E "auth-methods|kex|compress|encryption|mac" | head -30
fi
```

---

## Phase 7 — Signal Table & Attack Plan

Read all discovered data and produce a prioritized attack surface map:

```bash
ENG=/home/kali/current

echo ""
echo "==========================================="
echo "  pt-net ATTACK SURFACE MAP"
echo "==========================================="
echo ""

echo "=== Live Hosts ==="
cat $ENG/recon/network/live_hosts.txt 2>/dev/null | while read ip; do
    vendor=$(grep "$ip" $ENG/recon/network/arp_scan.txt | awk '{$1=$2=""; print $0}' | xargs)
    echo "  $ip  [$vendor]"
done
echo ""

echo "=== Open Services (from nmap) ==="
grep "^[0-9].*open" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    awk '{printf "  %-8s %-15s %s\n", $1, $(NF-1), $NF}' | head -50
echo ""

echo "=== Known Vulnerabilities Found ==="
[ -f $ENG/scans/nmap/vuln_scan.txt ] && \
    grep -E "VULNERABLE|CVE-[0-9]|exploitable" $ENG/scans/nmap/vuln_scan.txt | head -20 || echo "  (run vuln scan to populate)"
[ -f $ENG/scans/nuclei/network_cves.txt ] && \
    cat $ENG/scans/nuclei/network_cves.txt | grep -E "\[critical\]|\[high\]" | head -20
echo ""

echo "=== Prioritized Attack Recommendations ==="
echo ""

# Signal-driven recommendations based on what was found
grep -q "445.*open\|microsoft-ds" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [CRITICAL] SMB 445 open on Windows hosts"
    echo "    → Check MS17-010 EternalBlue: /pt-exploit <host> smb:445"
    echo "    → ARP spoof + NTLM relay: /pt-mitm <iface> <host> <gateway>"
    echo ""

grep -q "3389.*open\|ms-wbt" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [HIGH] RDP 3389 open"
    echo "    → BlueKeep CVE-2019-0708: /pt-exploit <host> rdp:3389"
    echo "    → Brute force: /pt-exploit <host> credentials"
    echo ""

grep -q "554.*open\|37777\|8000.*camera\|dahua\|hikvision" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [HIGH] IP Camera ports detected (RTSP/Dahua SDK/Hikvision SDK)"
    echo "    → CVE-2021-36260 Hikvision RCE + default creds: /pt-iot <subnet>"
    echo ""

grep -q " 23/tcp.*open\|telnet" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [HIGH] Telnet open — default credentials likely"
    echo "    → /pt-exploit <host> telnet:23"
    echo ""

grep -q "161.*open\|snmp" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [HIGH] SNMP detected — community string public/private often reveals full config"
    echo "    → /pt-exploit <host> snmp:161 (full MIB dump)"
    echo "    → WiFi PSK, VLANs, routing tables accessible via SNMP"
    echo ""

grep -q " 21/tcp.*open\|ftp" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [MEDIUM] FTP detected — check anonymous login"
    echo "    → /pt-exploit <host> ftp:21"
    echo ""

grep -q " 5900.*open\|vnc" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [MEDIUM] VNC detected — check no-auth access"
    echo "    → /pt-exploit <host> vnc:5900"
    echo ""

iw dev 2>/dev/null | grep -q "Interface" && \
    echo "  [HIGH] WiFi interface present on Kali"
    echo "    → Survey all nearby WiFi networks: /pt-wifi <wlan-interface>"
    echo "    → WPA2 handshake capture + PMKID + crack"
    echo ""

echo "  [ALWAYS APPLICABLE] ARP MITM position (any live hosts = MITM possible)"
echo "    → Credential sniffing + responder + NTLM relay: /pt-mitm <iface> <target> <gateway>"
echo ""

echo "=== Credential Spray (if any creds found during this phase) ==="
echo "  → netexec smb $SUBNET -u <user> -p <pass>"
echo "  → netexec ssh $SUBNET -u <user> -p <pass>"
echo ""

echo "=== Evidence saved ==="
echo "  Live hosts:   $ENG/recon/network/live_hosts.txt"
echo "  ARP scan:     $ENG/recon/network/arp_scan.txt"
echo "  Port scan:    $ENG/scans/masscan/all_ports.txt"
echo "  Service scan: $ENG/scans/nmap/service_scan.txt"
echo "  Vuln scan:    $ENG/scans/nmap/vuln_scan.txt"
echo "  SNMP data:    $ENG/loot/snmp_*.txt"
```

After all phases complete, update engagement notes:
```bash
ENG=/home/kali/current
SUBNET=<subnet>
LIVE_COUNT=$(wc -l < $ENG/recon/network/live_hosts.txt 2>/dev/null || echo 0)
PORT_COUNT=$(grep -c "^open" $ENG/scans/masscan/all_ports.txt 2>/dev/null || echo 0)

cat >> $ENG/notes/engagement.md << EOF

---
## Network Scan: $SUBNET
**Date**: $(date)
**Live hosts**: $LIVE_COUNT
**Open ports**: $PORT_COUNT
**Key findings**: (fill in from above output)
**Next steps**: (fill in priority attacks from signal table)
EOF
echo "Engagement notes updated → $ENG/notes/engagement.md"
```

---

## Execution Rules

- **Run Phase 1 + 2 always** — discovery is the foundation of everything
- **Skip protocols in Phase 6** if no hosts have those ports open
- **Phase 7 signal table** — read carefully and select the highest-impact next skill
- **Large subnets** — if `/24` has 100+ hosts, cap nmap deep scan to top 20 hosts by port count; use `--top-hosts` or prioritize by MAC vendor
- **Async for long scans** — masscan and nmap on large subnets can take 10-30 min; run with `async: true`
- **Chain immediately** — don't wait for all phases; if cameras found in Phase 2, run `/pt-iot` in parallel
