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

## Phase 0.5 — Passive Pre-Scan (Listen Before Making Noise)

Before sending a single packet, listen to the network. This reveals Windows machines broadcasting
LLMNR, mDNS services, and SSDP devices — all without alerting any IDS:

```bash
IFACE=<interface>
ENG=/home/kali/current

echo "=== [Phase 0.5] Passive Network Listening (30 seconds) ==="
echo "Listening for broadcasts before any active scanning..."
echo ""

# Listen for LLMNR (Windows name resolution broadcasts — reveals Windows hosts)
echo "--- LLMNR/NBT-NS broadcasts (Windows hosts) ---"
timeout 15 tcpdump -i "$IFACE" -nn 'udp port 5355 or udp port 137' 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | \
    while read ip; do echo "  [LLMNR/NBT-NS] Windows host broadcasting: $ip"; done &

# Listen for mDNS (Bonjour/Avahi — reveals Apple, printers, Linux services)
echo "--- mDNS broadcasts (Apple, printers, Linux) ---"
timeout 15 tcpdump -i "$IFACE" -nn 'udp port 5353' 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | \
    while read ip; do echo "  [mDNS] Device: $ip"; done &

# Listen for SSDP (UPnP devices — IoT, printers, cameras, smart TVs)
echo "--- SSDP/UPnP broadcasts (IoT devices) ---"
timeout 15 tcpdump -i "$IFACE" -nn 'udp port 1900' 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | \
    while read ip; do echo "  [UPnP/SSDP] IoT device: $ip"; done &

# Listen for ARP (reveals hosts communicating right now)
echo "--- ARP traffic (active hosts) ---"
timeout 15 tcpdump -i "$IFACE" -nn 'arp' 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -20 | \
    while read ip; do echo "  [ARP] Active: $ip"; done &

wait
echo ""
echo "Passive phase complete. Proceeding to active scanning."
echo "Key insight: Windows hosts broadcasting LLMNR → strong candidate for /pt-mitm Responder"
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

## Phase 1b — Extended Discovery (UDP + NetBIOS + mDNS + IPv6)

These find hosts and services that ARP + masscan completely miss:

```bash
IFACE=<interface>
SUBNET=<subnet>
ENG=/home/kali/current

echo "=== [Phase 1b] Extended Discovery ==="
echo ""

# UDP scan for critical services (masscan only does TCP)
echo "--- UDP scan for SNMP/DNS/TFTP/NTP/mDNS/SSDP/BACnet ---"
HOSTS=$(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | head -30 | tr '\n' ' ')
[ -n "$HOSTS" ] && nmap -sU -T4 --open \
    -p 53,67,68,69,123,161,162,500,514,1900,5353,47808 \
    --version-intensity 0 \
    -oN $ENG/scans/nmap/udp_scan.txt \
    $HOSTS 2>/dev/null | grep "^[0-9].*open" | tee /tmp/udp_results.txt | head -30
echo "UDP results → $ENG/scans/nmap/udp_scan.txt"
echo ""

# NetBIOS/Windows host enumeration (reveals hostnames + domain without touching SMB)
echo "--- NetBIOS enumeration (nbtscan) ---"
nbtscan -r "$SUBNET" 2>/dev/null | grep -v "^Doing\|^Sending\|^$" | \
    tee $ENG/recon/network/nbtscan.txt | \
    awk '{printf "  %-18s %-20s %-15s %s\n", $1, $2, $3, $4}' | head -30
echo ""

# mDNS/Bonjour service discovery (avahi-browse finds printers, NAS, cameras not in ARP)
echo "--- mDNS service discovery (avahi-browse) ---"
timeout 10 avahi-browse -a -t 2>/dev/null | \
    grep -v "^+\|-\|^$" | sort -u | head -30 \
    || echo "  (avahi-daemon not running — try: systemctl start avahi-daemon)"
echo ""

# Active SSDP M-SEARCH (finds IoT devices, smart TVs, routers)
echo "--- SSDP/UPnP device discovery ---"
python3 << 'EOF'
import socket, time

msg = ('M-SEARCH * HTTP/1.1\r\n'
       'HOST: 239.255.255.250:1900\r\n'
       'MAN: "ssdp:discover"\r\n'
       'MX: 3\r\n'
       'ST: ssdp:all\r\n\r\n')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.settimeout(5)
s.sendto(msg.encode(), ('239.255.255.250', 1900))

seen = set()
while True:
    try:
        data, addr = s.recvfrom(4096)
        ip = addr[0]
        if ip in seen: continue
        seen.add(ip)
        lines = data.decode(errors='replace').split('\r\n')
        server = next((l.replace('SERVER:','').strip() for l in lines if 'SERVER:' in l.upper()), '')
        usn = next((l.replace('USN:','').strip() for l in lines if 'USN:' in l.upper()), '')[:50]
        print(f'  [UPnP] {ip} | {server} | {usn}')
    except socket.timeout:
        break
s.close()
EOF
echo ""

# IPv6 host discovery (modern networks often have entire IPv6 subnets invisible to IPv4 scan)
echo "--- IPv6 host discovery ---"
# Ping all-nodes multicast (instant — gets responses from every IPv6-capable host)
ping6 -c 2 ff02::1%"$IFACE" 2>/dev/null | grep "from" | grep -oP '[0-9a-f:]+(?=%)' | \
    while read ipv6; do echo "  [IPv6] $ipv6"; done
# Also do a quick nmap IPv6 scan of link-local
nmap -6 -sn -T4 'fe80::/10' 2>/dev/null | grep "Nmap scan report" | head -10 || true
echo ""

# Reverse DNS PTR lookup (hostnames reveal roles without port scanning)
echo "--- Reverse DNS lookup (PTR records reveal hostnames) ---"
nmap -sL "$SUBNET" 2>/dev/null | grep "Nmap scan report" | \
    grep -v "not scanned" | awk '{print $5, $6}' | \
    grep -v "^$" | head -30
```

---

## Phase 2 — Port Scan (Tier A: nmap on live hosts | Tier B: optional masscan full)

**Tier A always runs** — nmap on discovered live hosts only, SSH-safe rate.
**Tier B is optional** — masscan full 65535 ports per host at rate=150pps.
⚠ Do NOT run masscan against the full /24 CIDR — it floods the kernel network stack and drops SSH.

```bash
IFACE=<interface>
LOCAL_IP=<local_ip>
ENG=/home/kali/current

LIVE_HOSTS=$(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | head -30 | tr '\n' ' ')
[ -z "$LIVE_HOSTS" ] && echo "[!] No live hosts found — run Phase 1 first" && exit 1

echo "=== [Phase 2 — Tier A] nmap port scan on live hosts (SSH-safe) ==="
echo "Hosts: $LIVE_HOSTS"
echo "Rate: T3 (max-rate=300) — will NOT saturate SSH ControlMaster"
echo ""

# Scan top-1000 ports + all our critical service ports explicitly
# nmap T3 is safe for VirtualBox/shared adapters — unlike masscan at high pps
nmap -sS -T3 --open -Pn \
    --top-ports 1000 \
    -p 21,22,23,25,53,80,110,135,139,143,443,445,554,1433,1521,1883,3306,\
3389,5432,5900,5985,6379,8000,8080,8081,8443,8888,9090,9100,9200,11211,\
27017,37777,8291,2375,6443,5005,4000,5672,15672,4786,8983,515,631,47808 \
    --min-rate=100 --max-rate=300 \
    -oL $ENG/scans/masscan/all_ports.txt \
    $LIVE_HOSTS 2>/dev/null

echo "--- Open ports discovered ---"
grep "^open\|Ports:" $ENG/scans/masscan/all_ports.txt 2>/dev/null | \
    awk '/^open/{print $4":"$3}' | sort -t. -k4 -n

echo ""
echo "Port summary by host:"
grep "^open" $ENG/scans/masscan/all_ports.txt 2>/dev/null | \
    awk '{print $4}' | sort | uniq -c | sort -rn | while read count ip; do
        ports=$(grep "^open.*$ip " $ENG/scans/masscan/all_ports.txt | \
            awk '{print $3}' | sort -n | tr '\n' ',' | sed 's/,$//')
        echo "  $ip ($count ports open): $ports"
    done

echo ""
echo "=== [Phase 2 — Tier B] OPTIONAL: masscan full 65535-port scan ==="
echo "⚠ WARNING: masscan can drop SSH ControlMaster even at 150pps on VMs."
echo "⚠ Only run this if Tier A missed ports you expect to see."
echo "⚠ Run each host individually — NEVER masscan a /24 CIDR."
echo ""
echo "To run full scan on a specific host:"
echo ""
for host in $LIVE_HOSTS; do
    echo "  # Full scan on $host:"
    echo "  masscan $host -p1-65535 --rate=150 --wait=5 --open-only \\"
    echo "      --adapter=$IFACE --adapter-ip=$LOCAL_IP \\"
    echo "      -oL /tmp/masscan_full_${host//./_}.txt"
    echo ""
done
echo "NOTE: After running, append results: cat /tmp/masscan_full_*.txt >> $ENG/scans/masscan/all_ports.txt"
```

---

## Phase 3 — Service + OS Fingerprinting (nmap Deep Scan)

Run nmap on live hosts discovered in Phase 1/2 for full service version detection:

```bash
ENG=/home/kali/current

# Get hosts from Phase 1 live hosts list (primary) or Phase 2 results (secondary)
HOSTS=$(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | head -50 | tr '\n' ' ')
[ -z "$HOSTS" ] && HOSTS=$(grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" $ENG/scans/masscan/all_ports.txt 2>/dev/null | sort -u | head -50 | tr '\n' ' ')

# Get open ports from Phase 2 scan (works with both nmap -oL and masscan -oL format)
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

# --- Active Directory / Domain Controller Detection (LDAP 389 + Kerberos 88) ---
AD_HOSTS=$(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | while read host; do
    ldap=$(nc -zw2 $host 389 2>/dev/null && echo "y")
    krb=$(nc -zw2 $host 88 2>/dev/null && echo "y")
    [ -n "$ldap" ] && [ -n "$krb" ] && echo "$host"
done | head -5)
if [ -n "$AD_HOSTS" ]; then
    echo ""
    echo "--- [CRITICAL] Active Directory Domain Controller(s) Detected ---"
    for dc in $AD_HOSTS; do
        echo "  [DC] $dc — LDAP(389) + Kerberos(88) both open"
        # Get AD domain name from LDAP
        DOMAIN=$(nmap --script ldap-rootdse -p 389 "$dc" 2>/dev/null | \
            grep -oP '(?<=defaultNamingContext: DC=)[^,]+' | head -1)
        [ -n "$DOMAIN" ] && echo "  Domain: $DOMAIN"
        echo "  → IMMEDIATE ACTION: /pt-ad $DOMAIN $dc"
    done
fi

# --- Database Services (commonly unauthenticated on internal networks) ---
echo ""
echo "--- Database Service Detection ---"
for host in $(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | head -30); do
    # Redis
    nc -zw2 $host 6379 2>/dev/null && {
        result=$(echo "PING" | nc -w2 $host 6379 2>/dev/null | head -1)
        echo "  [REDIS] $host:6379 — Response: $result ($(echo "$result" | grep -q 'PONG' && echo 'UNAUTHENTICATED!' || echo 'auth required'))"
    }
    # Elasticsearch
    nc -zw2 $host 9200 2>/dev/null && {
        info=$(curl -sk --max-time 3 "http://$host:9200/" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version',{}).get('number','?'))" 2>/dev/null)
        echo "  [ELASTICSEARCH] $host:9200 — v$info (likely unauthenticated data access)"
    }
    # MongoDB
    nc -zw2 $host 27017 2>/dev/null && echo "  [MONGODB] $host:27017 — open (check for unauthenticated access)"
    # MSSQL
    nc -zw2 $host 1433 2>/dev/null && echo "  [MSSQL] $host:1433 — open (test sa:blank, sa:sa)"
    # MySQL
    nc -zw2 $host 3306 2>/dev/null && echo "  [MYSQL] $host:3306 — open (test root:blank)"
    # PostgreSQL
    nc -zw2 $host 5432 2>/dev/null && echo "  [POSTGRES] $host:5432 — open (test postgres:blank)"
    # memcached
    nc -zw2 $host 11211 2>/dev/null && echo "  [MEMCACHED] $host:11211 — open (unauthenticated cache dump possible)"
done

# --- DevOps / Infrastructure Services ---
echo ""
echo "--- DevOps/Infrastructure Service Detection ---"
for host in $(cat $ENG/recon/network/live_hosts.txt 2>/dev/null | head -30); do
    # Docker API (unauthenticated = instant root on host)
    nc -zw2 $host 2375 2>/dev/null && {
        version=$(curl -sk --max-time 3 "http://$host:2375/version" 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('Version','?'))" 2>/dev/null)
        echo "  [DOCKER API] $host:2375 — v$version UNAUTHENTICATED (container escape to host root!)"
    }
    # Kubernetes API
    nc -zw2 $host 6443 2>/dev/null && echo "  [KUBERNETES] $host:6443 — K8s API (test anon access)"
    nc -zw2 $host 8080 2>/dev/null && {
        title=$(curl -sk --max-time 3 "http://$host:8080/" 2>/dev/null | grep -oP '(?<=<title>)[^<]+' | head -1)
        echo "  [HTTP:8080] $host:8080 — '$title' (check for Jenkins/Kubernetes dashboard)"
    }
    # Jenkins
    nc -zw2 $host 8080 2>/dev/null && \
        curl -sk --max-time 3 "http://$host:8080/login" 2>/dev/null | grep -qi "jenkins" && \
        echo "  [JENKINS] $host:8080 — Jenkins! Test /script console (Groovy RCE if unauthenticated)"
    # Java JDWP (debug wire protocol = instant RCE)
    nc -zw2 $host 5005 2>/dev/null && echo "  [JDWP] $host:5005 — Java debug wire RCE possible"
    nc -zw2 $host 4000 2>/dev/null && echo "  [JDWP] $host:4000 — Java debug wire RCE possible"
    # RabbitMQ management
    nc -zw2 $host 15672 2>/dev/null && echo "  [RABBITMQ] $host:15672 — management UI (default: guest/guest)"
done

# --- Full Windows Enumeration (enum4linux-ng for any Windows host) ---
WIN_HOSTS=$(grep "microsoft-ds\|445.*open" $ENG/scans/nmap/service_scan.txt 2>/dev/null | \
    grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | sort -u | head -5)
if [ -n "$WIN_HOSTS" ]; then
    echo ""
    echo "--- enum4linux-ng (full Windows/Samba enumeration) ---"
    for host in $WIN_HOSTS; do
        echo "  Enumerating $host..."
        enum4linux-ng -A "$host" 2>/dev/null | \
            grep -E "Domain|Workgroup|SID|User|Group|Share|Policy|Password" | \
            head -30 | tee $ENG/recon/network/enum4linux_${host}.txt | sed 's/^/  /'
    done
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

grep -q "6379.*open\|redis" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [CRITICAL] Redis port 6379 open"
    echo "    → Unauthenticated RCE via SSH key or crontab injection: /pt-exploit <host> redis:6379"
    echo ""

grep -q "9200.*open\|elasticsearch" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [HIGH] Elasticsearch port 9200 open"
    echo "    → Full data dump + possible Groovy script RCE: /pt-exploit <host> elasticsearch:9200"
    echo ""

grep -q "27017.*open\|mongodb" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [HIGH] MongoDB port 27017 open"
    echo "    → Unauthenticated database dump: /pt-exploit <host> mongodb:27017"
    echo ""

grep -q "2375.*open" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [CRITICAL] Docker API port 2375 open (UNAUTHENTICATED)"
    echo "    → Container escape → host root access: /pt-exploit <host> docker:2375"
    echo ""

grep -q "6443.*open\|8080.*kubernetes\|kube" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [CRITICAL] Kubernetes API detected"
    echo "    → Cluster takeover + privileged container escape: /pt-exploit <host> kubernetes:6443"
    echo ""

grep -q "8080.*open" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    curl -sk --max-time 3 "http://$(grep "8080.*open" $ENG/scans/nmap/service_scan.txt | grep -oP '\b\d+\.\d+\.\d+\.\d+\b' | head -1):8080/login" 2>/dev/null | grep -qi "jenkins" && \
    echo "  [CRITICAL] Jenkins detected on port 8080"
    echo "    → Groovy script console RCE (if unauthenticated): /pt-exploit <host> jenkins:8080"
    echo ""

grep -q "5005.*open\|4000.*jdwp\|jdwp" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [CRITICAL] Java JDWP debug port open"
    echo "    → Remote class loading = instant RCE: /pt-exploit <host> jdwp:5005"
    echo ""

[ -n "$(cat $ENG/recon/network/live_hosts.txt 2>/dev/null)" ] && \
    grep -q "389.*open\|88.*kerberos" $ENG/scans/nmap/service_scan.txt 2>/dev/null && \
    echo "  [CRITICAL] Active Directory Domain Controller detected (LDAP+Kerberos)"
    echo "    → Full AD attack chain: /pt-ad <domain> <dc-ip>"
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
