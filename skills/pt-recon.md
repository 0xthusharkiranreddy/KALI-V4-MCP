---
description: Deep asset recon — subdomain enum, DNS intel, live host probe, Wayback, JS secret/endpoint extraction, GitHub dorking, cloud bucket check
argument-hint: [target-domain]
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-recon — Deep Reconnaissance Agent

Perform deep passive and active asset discovery. Execute each phase in order using `mcp__kali-pentest__execute_kali_command`. **Each command block is a new SSH session — always set `TARGET` and `RECON` at the top of every call. Never carry variables across calls.**

---

## Step 0 — Target Resolution & Tool Check

Resolve TARGET:
1. If `$ARGUMENTS` is non-empty → `TARGET=$ARGUMENTS` (trim whitespace)
2. Else run: `grep -i "^Target:" /home/kali/current/notes/engagement.md 2>/dev/null | head -1 | awk '{print $2}'`
3. If still empty → stop: *"No target found. Run `/pt-recon <domain>` or run `/pt-init` first."*

Then run this single setup command:

```bash
TARGET=<resolved_target>
RECON=/home/kali/current/recon
mkdir -p $RECON/dns $RECON/http/js

echo "=== pt-recon: $TARGET ==="
echo "Tool availability:"
for t in subfinder theHarvester httpx dnsx gobuster whatweb nmap curl python3 dig; do
    printf "  %-15s %s\n" "$t" "$(command -v $t 2>/dev/null || echo 'NOT FOUND')"
done
echo "Dirs ready: $RECON"
```

Note which tools are available — skip steps that require missing tools.

---

## Phase 0b — Shodan & ASN Intelligence (Optional — requires SHODAN_API_KEY)

Reveals internet-exposed infrastructure before any active probing. Skip gracefully if API key not set.

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon
SHODAN_KEY=${SHODAN_API_KEY:-}
DOMAIN_MAIN=$(echo $TARGET | rev | cut -d. -f1-2 | rev)

echo "[0b] Shodan + ASN intel: $TARGET"

if [ -z "$SHODAN_KEY" ]; then
    echo "  [SKIP] SHODAN_API_KEY not set. Set it in ~/.claude.json env to enable."
    echo "  Manual alternative: https://www.shodan.io/search?query=hostname:$TARGET"
    exit 0
fi

# Resolve IP for target
TARGET_IP=$(dig +short $TARGET 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "  Target IP: $TARGET_IP"

# Shodan host lookup — open ports and banners
echo ""
echo "--- Shodan host lookup ---"
curl -s "https://api.shodan.io/shodan/host/$TARGET_IP?key=$SHODAN_KEY" 2>/dev/null | \
    python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    print(f\"  Organization: {d.get('org','?')}\")
    print(f\"  ASN: {d.get('asn','?')}\")
    print(f\"  Hostnames: {', '.join(d.get('hostnames',[])) or 'none'}\")
    print(f\"  Open ports: {sorted(d.get('ports',[]))}\")
    print(f\"  Vulns: {list(d.get('vulns',{}).keys())[:10]}\")
    for item in d.get('data',[])[:5]:
        print(f\"  [{item.get('port')}] {item.get('product','')} {item.get('version','')}: {str(item.get('banner',''))[:60]}\")
except: print('[no Shodan data]')
" 2>/dev/null

# ASN lookup via BGPView — find all IP ranges belonging to this org
echo ""
echo "--- ASN / IP ranges ---"
ASN=$(curl -s "https://api.shodan.io/shodan/host/$TARGET_IP?key=$SHODAN_KEY" 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('asn','').lstrip('AS'))" 2>/dev/null)

if [ -n "$ASN" ]; then
    curl -s "https://api.bgpview.io/asn/$ASN/prefixes" 2>/dev/null | \
        python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    prefixes = [p['prefix'] for p in d.get('data',{}).get('ipv4_prefixes',[])]
    print(f'  ASN {sys.argv[1] if len(sys.argv)>1 else \"?\"} owns {len(prefixes)} IPv4 prefixes:')
    for p in prefixes[:15]: print(f'    {p}')
except: print('[bgpview error]')
" 2>/dev/null
    echo "  IPv4 prefixes saved to $RECON/dns/asn_prefixes.txt"
    curl -s "https://api.bgpview.io/asn/$ASN/prefixes" 2>/dev/null | \
        python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    for p in d.get('data',{}).get('ipv4_prefixes',[]): print(p['prefix'])
except: pass
" > $RECON/dns/asn_prefixes.txt 2>/dev/null
fi

# Shodan org-wide port facets — what services does this org expose publicly?
ORG=$(curl -s "https://api.shodan.io/shodan/host/$TARGET_IP?key=$SHODAN_KEY" 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('org',''))" 2>/dev/null)

if [ -n "$ORG" ]; then
    echo ""
    echo "--- Org-wide port exposure: $ORG ---"
    curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=org:\"$ORG\"&facets=port:15" 2>/dev/null | \
        python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    total = d.get('total',0)
    print(f'  {total} exposed hosts for org: $ORG')
    for f in d.get('facets',{}).get('port',[]):
        print(f\"  Port {f['value']:6s}: {f['count']} hosts\")
except: print('[org search error]')
" 2>/dev/null
fi
```

---

## Phase 1 — Passive Subdomain Enumeration

All passive sources in one command. Output only counts to context — never full lists.

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

echo "[1/6] Passive subdomain enumeration: $TARGET"

# --- crt.sh certificate transparency ---
echo "  [crt.sh] querying..."
curl -s --max-time 25 "https://crt.sh/?q=%25.${TARGET}&output=json" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
except:
    data = []
names = set()
for r in data:
    for n in r.get('name_value','').split('\n'):
        n = n.strip().lstrip('*.')
        if n and n.endswith('$TARGET') and '.' in n:
            names.add(n.lower())
names.add('$TARGET')
print('\n'.join(sorted(names)))
" > $RECON/dns/subdomains_crt.txt 2>/dev/null
echo "  [crt.sh] $(wc -l < $RECON/dns/subdomains_crt.txt) entries"

# --- Wayback Machine CDX: subdomain extraction + full URL list ---
echo "  [wayback] querying CDX..."
curl -s --max-time 30 "http://web.archive.org/cdx/search/cdx?url=*.${TARGET}&output=text&fl=original&collapse=urlkey&limit=5000" \
    | grep -oE "[a-zA-Z0-9._-]+\.${TARGET}" | sort -u > $RECON/dns/subdomains_wayback.txt 2>/dev/null
# Full historical URLs for Phase 2b interesting-file discovery
curl -s --max-time 30 "http://web.archive.org/cdx/search/cdx?url=${TARGET}/*&output=text&fl=original&collapse=urlkey&limit=5000" \
    | sort -u > $RECON/dns/wayback_urls.txt 2>/dev/null
echo "  [wayback] $(wc -l < $RECON/dns/subdomains_wayback.txt) subdomains, $(wc -l < $RECON/dns/wayback_urls.txt) historical URLs"

# --- subfinder (if installed) ---
if command -v subfinder &>/dev/null; then
    echo "  [subfinder] running (60s timeout)..."
    timeout 60 subfinder -d $TARGET -silent 2>/dev/null > $RECON/dns/subdomains_subfinder.txt
    echo "  [subfinder] $(wc -l < $RECON/dns/subdomains_subfinder.txt) entries"
else
    touch $RECON/dns/subdomains_subfinder.txt
    echo "  [subfinder] not installed — skipped"
fi

# --- Deduplicate all passive sources ---
cat $RECON/dns/subdomains_crt.txt \
    $RECON/dns/subdomains_wayback.txt \
    $RECON/dns/subdomains_subfinder.txt \
    | tr '[:upper:]' '[:lower:]' \
    | grep -E "^[a-z0-9._-]+$" \
    | grep -v '^\.' \
    | sort -u > $RECON/dns/subdomains_all.txt
echo "$TARGET" >> $RECON/dns/subdomains_all.txt
sort -u $RECON/dns/subdomains_all.txt -o $RECON/dns/subdomains_all.txt

echo ""
echo "  [TOTAL passive] $(wc -l < $RECON/dns/subdomains_all.txt) unique subdomains"
```

---

## Phase 1a — SSL Certificate Alt-Names

Extract Subject Alternative Names from the target's TLS certificate — often reveals internal hostnames, staging environments, and wildcard domains not in CT logs.

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

echo "[1a] SSL certificate alt-name extraction..."
{
echo | openssl s_client -connect ${TARGET}:443 -servername $TARGET 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep -A2 "Subject Alternative Name" \
    | grep -oE "DNS:[^ ,]+" | sed 's/DNS://' \
    | grep -vE "^\*\." | grep -v "^$"
# Also try port 8443
echo | openssl s_client -connect ${TARGET}:8443 -servername $TARGET 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep -A2 "Subject Alternative Name" \
    | grep -oE "DNS:[^ ,]+" | sed 's/DNS://' | grep -v "^$"
} | grep -v "^$" | sort -u | tee /tmp/pt_ssl_altnames.txt

count=$(wc -l < /tmp/pt_ssl_altnames.txt 2>/dev/null || echo 0)
echo "  [ssl-altnames] $count names found"
if [ "$count" -gt 0 ]; then
    cat /tmp/pt_ssl_altnames.txt >> $RECON/dns/subdomains_all.txt
    sort -u $RECON/dns/subdomains_all.txt -o $RECON/dns/subdomains_all.txt
    echo "  Added to subdomains_all.txt:"
    cat /tmp/pt_ssl_altnames.txt | head -20
fi
```

---

## Phase 1b — theHarvester OSINT (run only if installed)

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

if command -v theHarvester &>/dev/null; then
    echo "[1b] theHarvester OSINT (90s timeout)..."
    timeout 90 theHarvester -d $TARGET -b google,bing,crtsh -l 200 2>/dev/null \
        | grep -oE "[a-zA-Z0-9._-]+\.${TARGET}" \
        >> $RECON/dns/subdomains_all.txt
    sort -u $RECON/dns/subdomains_all.txt -o $RECON/dns/subdomains_all.txt
    echo "  [total after harvester] $(wc -l < $RECON/dns/subdomains_all.txt) unique subdomains"
else
    echo "[1b] theHarvester not installed — skipped"
fi
```

---

## Phase 1c — DNS Intelligence

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

echo "[1c] DNS intelligence..."
{
echo "=== NS Records ==="
dig NS $TARGET +short 2>/dev/null | head -10

echo ""
echo "=== MX Records (reveals email provider) ==="
dig MX $TARGET +short 2>/dev/null | sort -n | head -10

echo ""
echo "=== TXT Records (SPF / DMARC / verification tokens) ==="
dig TXT $TARGET +short 2>/dev/null | head -20
dig TXT _dmarc.$TARGET +short 2>/dev/null

echo ""
echo "=== Zone Transfer Attempts ==="
for ns in $(dig NS $TARGET +short 2>/dev/null | head -3); do
    echo "  Trying AXFR from $ns..."
    dig @${ns%\.} AXFR $TARGET 2>/dev/null | grep -v "^;" | head -20
done

echo ""
echo "=== Common subdomains (A/CNAME check) ==="
for sub in www mail api dev staging admin vpn ftp uat beta cdn assets static portal; do
    r=$(dig +short "$sub.$TARGET" 2>/dev/null | head -2 | tr '\n' ' ')
    [ -n "$r" ] && echo "  $sub.$TARGET → $r"
done
} | tee $RECON/dns/dns_intel.txt

echo ""
echo "  [dns intel] saved → $RECON/dns/dns_intel.txt"
```

---

## Phase 2 — Live Host Probing

Cap at 150 subdomains. Use `httpx` (parallel, structured output) if available; fall back to parallel curl via `xargs -P20`. Output only first 30 hosts to context.

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

echo "[2/6] Live host probing (cap: 150 hosts)..."
head -150 $RECON/dns/subdomains_all.txt > /tmp/pt_probe_list.txt

if command -v httpx &>/dev/null; then
    httpx -l /tmp/pt_probe_list.txt -silent -status-code -title -tech-detect \
          -timeout 8 -retries 1 -threads 30 \
          -o $RECON/http/live_hosts.txt 2>/dev/null
    echo "  [httpx] $(wc -l < $RECON/http/live_hosts.txt) live hosts"
else
    echo "  [curl xargs -P20] probing..."
    > $RECON/http/live_hosts.txt
    cat /tmp/pt_probe_list.txt | xargs -P20 -I{} bash -c '
        sub="$1"; RECON="$2"
        for scheme in https http; do
            code=$(curl -sk --max-time 6 -o /tmp/_pb_body_$$.html \
                        --write-out "%{http_code}" "${scheme}://${sub}" 2>/dev/null)
            if echo "$code" | grep -qE "^[23456]"; then
                server=$(curl -skI --max-time 4 "${scheme}://${sub}" 2>/dev/null \
                    | grep -i "^server:" | head -1 | cut -d: -f2- | xargs)
                title=$(grep -oi "<title>[^<]*</title>" /tmp/_pb_body_$$.html 2>/dev/null \
                    | head -1 | sed "s/<[^>]*>//g" | xargs)
                echo "$code  ${scheme}://${sub}  [$server]  $title" >> "$RECON/http/live_hosts.txt"
                rm -f /tmp/_pb_body_$$.html
                break
            fi
        done
        rm -f /tmp/_pb_body_$$.html
    ' _ {} "$RECON" 2>/dev/null
    sort -u $RECON/http/live_hosts.txt -o $RECON/http/live_hosts.txt
    echo "  [curl] $(wc -l < $RECON/http/live_hosts.txt) live hosts"
fi

# Output cap: first 30 hosts only — never dump full list to context
echo ""
echo "=== Live hosts (first 30 of $(wc -l < $RECON/http/live_hosts.txt)) ==="
head -30 $RECON/http/live_hosts.txt
total=$(wc -l < $RECON/http/live_hosts.txt)
[ "$total" -gt 30 ] && echo "  ... $((total - 30)) more → $RECON/http/live_hosts.txt"
```

---

## Phase 2b — Tech Fingerprint + Historical File Discovery

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

echo "[2b] Tech fingerprint + historical endpoint discovery..."

# WhatWeb: top 15 live hosts only — log to file, print summary only
live_urls=$(grep -oE "https?://[^ \]]+" $RECON/http/live_hosts.txt | head -15)
if [ -n "$live_urls" ] && command -v whatweb &>/dev/null; then
    echo "$live_urls" | xargs -P5 -I{} \
        whatweb -q --no-errors --log-brief=$RECON/http/whatweb.txt {} 2>/dev/null
    echo "  [whatweb] $(wc -l < $RECON/http/whatweb.txt 2>/dev/null || echo 0) results"
    echo ""
    echo "=== Tech stack summary (top 15 technologies) ==="
    grep -oE "\[[A-Za-z][^\]]{2,30}\]" $RECON/http/whatweb.txt 2>/dev/null \
        | sort | uniq -c | sort -rn | head -15
fi

# robots.txt + sitemap.xml on top 10 live hosts — compact output
echo ""
echo "=== robots.txt & sitemap discovery ==="
grep -oE "https?://[^ \]]+" $RECON/http/live_hosts.txt | head -10 | while read url; do
    base=$(echo "$url" | grep -oE "https?://[^/]+")
    robots=$(curl -sk --max-time 6 "$base/robots.txt" 2>/dev/null)
    if echo "$robots" | grep -qi "^disallow\|^allow\|^sitemap"; then
        echo "  [robots] $base:"
        echo "$robots" | grep -iE "^(Disallow|Allow|Sitemap)" | head -10 | sed 's/^/    /'
    fi
    sm=$(curl -skI --max-time 5 "$base/sitemap.xml" 2>/dev/null | head -1)
    echo "$sm" | grep -q "200" && echo "  [sitemap] $base/sitemap.xml → 200 OK"
done

# Wayback: filter for interesting historical paths
echo ""
echo "=== Interesting historical URLs (Wayback CDX) ==="
grep -iE "\.(bak|old|zip|tar\.gz|gz|sql|dump|config|cfg|env|log|backup|pem|key)\b|/admin|/api/|/debug|/test|/internal|/\.git|/wp-admin|/phpmyadmin|/actuator|/swagger|/v1/|/v2/" \
    $RECON/dns/wayback_urls.txt 2>/dev/null \
    | sort -u | head -30 | tee $RECON/dns/wayback_interesting.txt
echo "  [wayback interesting] $(wc -l < $RECON/dns/wayback_interesting.txt) saved → $RECON/dns/wayback_interesting.txt"
```

---

## Phase 2c — Quick Nmap on Unique IPs

One nmap run against all IPs at once — not per-host. Cap at 10 IPs.

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

echo "[2c] Nmap scan..."

# Resolve hostnames to IPs — deduplicate CDN IPs
grep -oE "https?://[^ \]]+" $RECON/http/live_hosts.txt \
    | sed 's|https\?://||; s|/.*||' | sort -u | head -15 \
    | while read host; do
        ip=$(echo "$host" | grep -qE "^[0-9.]+$" && echo "$host" \
             || dig +short "$host" 2>/dev/null | grep -oE "^[0-9.]+" | head -1)
        [ -n "$ip" ] && echo "$ip"
    done | sort -u | head -10 > /tmp/pt_scan_ips.txt

if [ -s /tmp/pt_scan_ips.txt ]; then
    echo "  Targets: $(cat /tmp/pt_scan_ips.txt | tr '\n' ' ')"
    nmap -T4 -F --open -Pn --reason \
         -oN $RECON/http/nmap_quick.txt \
         $(cat /tmp/pt_scan_ips.txt | tr '\n' ' ') 2>/dev/null
    echo ""
    echo "=== Open ports ==="
    grep -E "^[0-9]+/|Host:" $RECON/http/nmap_quick.txt | head -40
else
    echo "  No IPs resolved — skipping nmap"
fi
```

---

## Phase 2d — Subdomain Takeover Detection + Exposed .git + Source Maps

```bash
TARGET=<resolved_target>
RECON=/home/kali/current/recon
ENG=/home/kali/current
mkdir -p "$ENG/scans/web"

echo "[2d] Subdomain takeover + exposed .git + source maps..."
echo ""

# ── Subdomain Takeover ─────────────────────────────────────────────────────────
echo "=== Subdomain Takeover Check ==="
SUBFILE="$RECON/dns/subdomains_all.txt"
> "$ENG/scans/web/takeover_candidates.txt"

if [ -f "$SUBFILE" ] && [ $(wc -l < "$SUBFILE") -gt 0 ]; then
    echo "Checking $(wc -l < "$SUBFILE") subdomains for dangling CNAMEs..."
    head -150 "$SUBFILE" | while read -r sub; do
        [ -z "$sub" ] && continue
        CNAME=$(dig CNAME +short "$sub" 2>/dev/null | head -1)
        [ -z "$CNAME" ] && continue
        # Only continue if CNAME points to external service
        RESP=$(curl -sk "https://$sub" --max-time 6 2>/dev/null)
        for fp in \
            "There isn't a GitHub Pages site here:GitHub Pages" \
            "NoSuchBucket:AWS S3" \
            "The specified bucket does not exist:AWS S3" \
            "No such app:Heroku" \
            "herokucdn.com/error-pages/no-such-app:Heroku" \
            "doesn't exist:Shopify" \
            "fastly error: unknown domain:Fastly" \
            "Please check that the website address:Azure" \
            "404 Web Site not found:Azure" \
            "Repository not found:Bitbucket" \
            "Unrecognized domain:Netlify" \
            "The thing you were looking for is no longer here:Tumblr"; do
            pattern="${fp%%:*}"; service="${fp##*:}"
            if echo "$RESP" | grep -qi "$pattern"; then
                echo "  [TAKEOVER] $sub → CNAME: $CNAME | Service: $service"
                echo "$sub|$CNAME|$service" >> "$ENG/scans/web/takeover_candidates.txt"
                break
            fi
        done
    done
    HITS=$(wc -l < "$ENG/scans/web/takeover_candidates.txt")
    echo "  Takeover candidates: $HITS"
    [ "$HITS" -gt 0 ] && cat "$ENG/scans/web/takeover_candidates.txt"
else
    echo "  No subdomain list available — run Phase 1 first"
fi

echo ""
echo "=== Exposed .git Directories ==="
# Exposed .git = full source code accessible — Critical finding
LIVE_FILE="$RECON/http/live_hosts.txt"
if [ -f "$LIVE_FILE" ]; then
    while IFS= read -r host; do
        [ -z "$host" ] && continue
        host=$(echo "$host" | grep -oE 'https?://[^/ ]+' | head -1)
        [ -z "$host" ] && continue
        STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$host/.git/HEAD" --max-time 5 2>/dev/null)
        if [ "$STATUS" = "200" ]; then
            CONTENT=$(curl -sk "$host/.git/HEAD" --max-time 5 2>/dev/null | head -1)
            echo "  [GIT EXPOSED] $host/.git/HEAD → HTTP $STATUS | $CONTENT"
            echo "  → Run: git-dumper $host/.git/ $ENG/loot/git_$(echo $host | sed 's|https\?://||' | tr '/' '_')"
        fi
    done < "$LIVE_FILE"
    echo "  .git check complete"
else
    # Check primary target
    DOMAIN=$(echo "$TARGET" | sed 's|https\?://||' | cut -d/ -f1)
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$DOMAIN/.git/HEAD" --max-time 5 2>/dev/null)
    [ "$STATUS" = "200" ] && echo "  [GIT EXPOSED] https://$DOMAIN/.git/HEAD" || echo "  [OK] No .git exposure on primary domain"
fi

echo ""
echo "=== JavaScript Source Maps ==="
# Source maps expose original unminified source — reveals business logic, internal paths, secrets
JS_DIR="$RECON/http/js"
if [ -d "$JS_DIR" ] && [ $(ls "$JS_DIR"/*.js 2>/dev/null | wc -l) -gt 0 ]; then
    echo "Checking $(ls "$JS_DIR"/*.js 2>/dev/null | wc -l) JS files for source maps..."
    for js_file in "$JS_DIR"/*.js; do
        # Check for sourceMappingURL comment in JS file
        MAP_URL=$(grep -o "sourceMappingURL=[^ ]*" "$js_file" 2>/dev/null | head -1 | cut -d= -f2)
        [ -z "$MAP_URL" ] && continue
        # Derive map URL
        echo "  [SOURCE MAP REFERENCE] $(basename $js_file) → $MAP_URL"
    done
    # Check if .map files are accessible on live server
    grep -rh "sourceMappingURL" "$JS_DIR/" 2>/dev/null | \
        grep -oE "https?://[^\"' ]+" | grep "\.map$" | sort -u | head -10 | while read map_url; do
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$map_url" --max-time 5 2>/dev/null)
        [ "$CODE" = "200" ] && echo "  [MAP EXPOSED] $map_url (HTTP $CODE) — contains original source!"
    done
else
    echo "  No JS files in recon dir — run Phase 3 (JS analysis) to populate"
fi

echo ""
echo "[2d] Complete. Check scans/web/takeover_candidates.txt for takeover hits."
```

---

## Phase 3 — JavaScript Bundle Analysis

Single Python script per execution. Caps: 15 hosts, 5 JS files per host, 2MB per file. Strict false-positive filters. Deduplicates across files. Prints only summary + top findings.

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

python3 - << 'PYEOF'
import re, os, subprocess, hashlib, json
from collections import defaultdict
from urllib.parse import urljoin, urlparse

RECON = '/home/kali/current/recon'
JS_DIR = RECON + '/http/js'
os.makedirs(JS_DIR, exist_ok=True)

# ── Load live hosts ───────────────────────────────────────────────────────────
hosts = []
try:
    with open(RECON + '/http/live_hosts.txt') as f:
        for line in f:
            m = re.search(r'https?://[^\s\]]+', line)
            if m:
                hosts.append(m.group().rstrip('/'))
except:
    pass

# ── Download JS: 15 hosts × 5 files each (same-origin only) ─────────────────
downloaded = []
print(f'[3/6] JS analysis — {min(15, len(hosts))} hosts, max 5 JS each')

SKIP_EXT = {'.png','.jpg','.jpeg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.css','.map','.json'}
SKIP_CDN = {'googleapis.com','jquery.com','cloudflare.com','bootstrapcdn.com',
            'amazonaws.com','jsdelivr.net','cdnjs.com','unpkg.com','gstatic.com'}

for base_url in hosts[:15]:
    try:
        html = subprocess.run(
            ['curl','-sk','--max-time','10', base_url],
            capture_output=True, text=True, timeout=12
        ).stdout
    except:
        continue

    base_host = urlparse(base_url).netloc
    srcs = re.findall(r'src=["\']((?:[^"\']*\.js(?:\?[^"\']*)?))["\'"]', html, re.I)
    srcs = list(dict.fromkeys(srcs))  # dedupe order-preserving

    count = 0
    for src in srcs:
        if count >= 5:
            break
        js_url = src if src.startswith('http') else ('https:' + src if src.startswith('//') else urljoin(base_url, src))
        js_host = urlparse(js_url).netloc
        ext = os.path.splitext(urlparse(js_url).path)[1].lower()

        # Skip third-party CDNs and non-JS extensions
        if any(cdn in js_host for cdn in SKIP_CDN): continue
        if js_host and js_host != base_host and base_host.split('.')[-2] not in js_host: continue
        if ext in SKIP_EXT: continue

        fname = hashlib.md5(js_url.encode()).hexdigest()[:8] + '_' + \
                os.path.basename(urlparse(js_url).path)[:50]
        fpath = os.path.join(JS_DIR, fname)
        try:
            subprocess.run(['curl','-sk','--max-time','15', js_url, '-o', fpath],
                           timeout=18, capture_output=True)
            if os.path.exists(fpath) and os.path.getsize(fpath) > 200:
                downloaded.append((js_url, fpath))
                count += 1
        except:
            pass

print(f'  Downloaded {len(downloaded)} JS files')

# ── False positive filter ─────────────────────────────────────────────────────
FP_EXACT = {'null','undefined','false','true','none','example','placeholder',
            'your_key','your_token','your_secret','changeme','replace_me',
            'xxx','yyy','zzz','test','demo','sample','todo','fixme',
            'api_key_here','insert_key_here','your-api-key'}

def is_fp(val):
    v = val.strip().strip('"\'`').lower()
    if v in FP_EXACT: return True
    if len(v) < 8: return True
    if len(set(v)) <= 2: return True          # "aaaaaa" or "ababab"
    if re.match(r'^[0-9.\s]+$', v): return True
    if re.match(r'^[a-z_\-\s]+$', v): return True  # plain English words
    return False

# ── Secret patterns ───────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ('Google API Key',   r'AIza[0-9A-Za-z\-_]{35}'),
    ('Firebase DB',      r'https?://[a-z0-9\-]+\.firebaseio\.com'),
    ('AWS Access Key',   r'AKIA[0-9A-Z]{16}'),
    ('AWS Secret',       r'(?i)aws[_\-]secret[_\-](?:access[_\-])?key["\'`\s]*[:=]["\'`\s]*[A-Za-z0-9+/]{40}'),
    ('Stripe Secret',    r'sk_live_[0-9a-zA-Z]{24,48}'),
    ('Stripe Public',    r'pk_live_[0-9a-zA-Z]{24,48}'),
    ('Slack Token',      r'xox[baprs]-[0-9]{8,12}-[0-9A-Za-z\-]{30,}'),
    ('Twilio SID',       r'AC[0-9a-f]{32}'),
    ('Twilio Key',       r'SK[0-9a-fA-F]{32}'),
    ('SendGrid Key',     r'SG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{40,}'),
    ('GitHub Token',     r'gh[pousr]_[A-Za-z0-9_]{36,}'),
    ('PEM Key',          r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    ('Generic Secret',   r'(?i)(?:^|["\'\s,{(])(?:password|passwd|db_pass(?:word)?|secret_key|client_secret|app_secret|api_secret)\s*[:=]\s*["\'][A-Za-z0-9!@#$%^&*_\-+=/]{12,}["\']'),
    ('Basic Auth URL',   r'https?://[A-Za-z0-9._\-]+:[A-Za-z0-9!@#$%^&*_\-+=/]{8,}@[a-zA-Z0-9\-.]+'),
    ('Internal IP',      r'(?:"|\'|=)((?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3})(?:"|\'|:)'),
]

# ── Endpoint patterns (API paths only) ────────────────────────────────────────
ENDPOINT_RE = [
    r'["\'`](/(?:api|v\d+|graphql|internal|admin|_ah|rpc|ws|webhook|oauth|auth|token|user|account|order|payment|upload|export|download|search|report)[/a-zA-Z0-9_\-\.?=&%#]{0,200})["\'`]',
    r'(?:fetch|axios\.\w+|http(?:Client)?\.\w+)\s*\(\s*["\'`]([^"\'`\s\n]{5,150})["\'`]',
    r'(?i)(?:apiUrl|baseUrl|endpoint|serverUrl|apiEndpoint|API_URL|BASE_URL)\s*[:=]\s*["\'`]([^"\'`\s\n]{5,120})["\'`]',
]

SKIP_EP_EXT = {'.png','.jpg','.jpeg','.gif','.svg','.ico','.woff','.css','.map','.ttf'}

secrets_by_type = defaultdict(list)
seen_secrets = set()
all_endpoints = set()

for js_url, fpath in downloaded:
    try:
        with open(fpath, 'r', errors='ignore') as f:
            content = f.read(2_000_000)  # max 2MB
    except:
        continue

    fname_short = os.path.basename(fpath)[:35]

    for name, pat in SECRET_PATTERNS:
        for m in re.finditer(pat, content, re.MULTILINE):
            val = m.group()
            dedup_key = (name, val[:80])
            if dedup_key in seen_secrets: continue
            if is_fp(val): continue
            seen_secrets.add(dedup_key)
            ctx_start = max(0, m.start()-40)
            ctx_end = min(len(content), m.end()+40)
            ctx = content[ctx_start:ctx_end].replace('\n',' ')[:120]
            secrets_by_type[name].append((fname_short, val[:100], ctx))

    for pat in ENDPOINT_RE:
        for m in re.findall(pat, content, re.MULTILINE):
            val = m if isinstance(m, str) else m[0]
            ext = os.path.splitext(val.split('?')[0])[1].lower()
            if ext in SKIP_EP_EXT: continue
            if len(val) < 4 or val.count('*') > 2: continue
            all_endpoints.add(val[:200])

# ── Write output files ────────────────────────────────────────────────────────
with open(RECON + '/http/js_secrets.txt', 'w') as f:
    for stype, hits in secrets_by_type.items():
        for fname, val, ctx in hits:
            f.write(f'[{stype}] {fname}\n  value:   {val}\n  context: {ctx}\n\n')

with open(RECON + '/http/js_endpoints.txt', 'w') as f:
    for ep in sorted(all_endpoints):
        f.write(ep + '\n')

# ── Context-efficient summary ─────────────────────────────────────────────────
total_secrets = sum(len(v) for v in secrets_by_type.values())
print(f'\n  Secrets: {total_secrets} unique hits ({len(downloaded)} JS files analysed)')
for stype, hits in sorted(secrets_by_type.items(), key=lambda x: -len(x[1])):
    print(f'    [{stype}] {len(hits)} hit(s)  →  {hits[0][1][:70]}')

api_eps = sorted(e for e in all_endpoints if any(
    k in e for k in ['/api/','/v1/','/v2/','/graphql','/admin','/internal','/oauth','/token']))
print(f'\n  Endpoints: {len(all_endpoints)} unique ({len(api_eps)} API paths)')
for ep in api_eps[:25]:
    print(f'    {ep}')
if len(api_eps) > 25:
    print(f'    ... {len(api_eps)-25} more → js_endpoints.txt')
print(f'\n  Files: {RECON}/http/js_secrets.txt | js_endpoints.txt')
PYEOF
```

---

## Phase 4 — GitHub Dorking

Pure Python — no bash quoting issues. Proper rate limit detection and backoff.

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

python3 - << PYEOF
import urllib.request, urllib.parse, urllib.error, json, time, os

RECON = '/home/kali/current/recon'
TARGET = '${TARGET}'
ORG = TARGET.split('.')[0] if TARGET else ''
TOKEN = os.environ.get('GITHUB_TOKEN', '')  # set GITHUB_TOKEN env var for authenticated search (60 req/hr anon, 30/min authed)
OUT = RECON + '/dns/github_dorks.txt'

QUERIES = [
    f'"{TARGET}" password',
    f'"{TARGET}" api_key',
    f'"{TARGET}" secret',
    f'"{TARGET}" token',
    f'"{TARGET}" db_password',
    f'"{TARGET}" private_key',
    f'"{TARGET}" BEGIN RSA PRIVATE',
    f'"{TARGET}" Authorization Bearer',
    f'"{TARGET}" .env',
    f'"{TARGET}" connection_string',
    f'org:{ORG} password',
    f'org:{ORG} secret',
]

def gh_search(query):
    url = 'https://api.github.com/search/code?' + urllib.parse.urlencode({'q': query, 'per_page': 10})
    req = urllib.request.Request(url, headers={
        'Authorization': f'Bearer {TOKEN}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'pt-recon/2.0',
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            remaining = int(resp.headers.get('X-RateLimit-Remaining', 99))
            reset_in = max(0, int(resp.headers.get('X-RateLimit-Reset', 0)) - int(time.time()))
            data = json.loads(resp.read())
            return data.get('total_count', 0), [i['html_url'] for i in data.get('items', [])], remaining, reset_in
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return -1, [], 0, 60
        return 0, [], 99, 0
    except Exception as e:
        return 0, [], 99, 0

print(f'[4/6] GitHub dorking: {TARGET}')
all_results = {}

with open(OUT, 'w') as f:
    f.write(f'=== GitHub Dorks: {TARGET} ===\n\n')
    for i, q in enumerate(QUERIES):
        count, urls, remaining, reset_in = gh_search(q)
        if count == -1:
            wait = min(reset_in + 5, 65)
            print(f'  Rate limited — sleeping {wait}s...')
            time.sleep(wait)
            count, urls, remaining, reset_in = gh_search(q)
        status = f'{count} total' if count >= 0 else 'error'
        print(f'  [{i+1}/{len(QUERIES)}] {q[:55]:<55} → {status}')
        all_results[q] = (count, urls)
        f.write(f'Query: {q}\nTotal: {count}\n')
        for u in urls:
            f.write(f'  {u}\n')
        f.write('\n')
        # Code search: 10 req/min authenticated → 6s min between calls
        time.sleep(7 if remaining > 3 else 30)

total_urls = sum(len(u) for _, u in all_results.values())
print(f'\n  Total GitHub URLs captured: {total_urls}')
print('  Top hits:')
for q, (count, urls) in all_results.items():
    if urls:
        print(f'    [{count}] {q}')
        for u in urls[:2]:
            print(f'      {u}')
print(f'  Full results → {OUT}')
PYEOF
```

---

## Phase 5 — Cloud Bucket Discovery

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

echo "[5/6] Cloud bucket discovery..."
BASE=$(echo $TARGET | sed 's/\..*//')
DASHED=$(echo $TARGET | tr '.' '-')

> $RECON/dns/cloud_buckets.txt

check_s3() {
    local name="$1"
    code=$(curl -skI --max-time 5 "https://${name}.s3.amazonaws.com/" 2>/dev/null \
           | head -1 | grep -oE "[0-9]{3}")
    case "$code" in
        200) echo "  [S3 OPEN]    $name.s3.amazonaws.com  ← public read!" | tee -a $RECON/dns/cloud_buckets.txt ;;
        403) echo "  [S3 EXISTS]  $name.s3.amazonaws.com  (403 — exists but private)" | tee -a $RECON/dns/cloud_buckets.txt ;;
        301) echo "  [S3 REDIR]   $name.s3.amazonaws.com" | tee -a $RECON/dns/cloud_buckets.txt ;;
    esac
}

check_gcs() {
    local name="$1"
    code=$(curl -skI --max-time 5 "https://storage.googleapis.com/${name}/" 2>/dev/null \
           | head -1 | grep -oE "[0-9]{3}")
    case "$code" in
        200) echo "  [GCS OPEN]   storage.googleapis.com/$name  ← public read!" | tee -a $RECON/dns/cloud_buckets.txt ;;
        403) echo "  [GCS EXISTS] storage.googleapis.com/$name  (403 — exists)" | tee -a $RECON/dns/cloud_buckets.txt ;;
    esac
}

echo "=== S3 Bucket Checks ==="
for name in "$BASE" "$BASE-backup" "$BASE-prod" "$BASE-staging" "$BASE-dev" \
            "$BASE-assets" "$BASE-static" "$BASE-media" "$BASE-files" \
            "$BASE-uploads" "$BASE-data" "$BASE-logs" "$DASHED"; do
    check_s3 "$name"
done

echo ""
echo "=== GCS Bucket Checks ==="
for name in "$BASE" "$BASE-backup" "$BASE-assets" "$BASE-static" "$DASHED"; do
    check_gcs "$name"
done

echo ""
echo "=== Azure Blob Storage Checks ==="
check_azure() {
    local name="$1"
    code=$(curl -skI --max-time 5 "https://${name}.blob.core.windows.net/${name}/" 2>/dev/null \
           | head -1 | grep -oE "[0-9]{3}")
    case "$code" in
        200) echo "  [AZURE OPEN]   $name.blob.core.windows.net  ← public read!" | tee -a $RECON/dns/cloud_buckets.txt ;;
        403) echo "  [AZURE EXISTS] $name.blob.core.windows.net  (403 — exists but private)" | tee -a $RECON/dns/cloud_buckets.txt ;;
        400) echo "  [AZURE EXISTS] $name.blob.core.windows.net  (400 — container exists, auth required)" | tee -a $RECON/dns/cloud_buckets.txt ;;
    esac
}
for name in "$BASE" "$BASE-backup" "$BASE-assets" "$BASE-static" "$BASE-media" "$BASE-files" "$BASE-uploads" "$DASHED"; do
    check_azure "$name"
done

echo ""
echo "=== DigitalOcean Spaces Checks ==="
check_do() {
    local name="$1" region="$2"
    code=$(curl -skI --max-time 5 "https://${name}.${region}.digitaloceanspaces.com/" 2>/dev/null \
           | head -1 | grep -oE "[0-9]{3}")
    case "$code" in
        200) echo "  [DO OPEN]   $name.$region.digitaloceanspaces.com  ← public read!" | tee -a $RECON/dns/cloud_buckets.txt ;;
        403) echo "  [DO EXISTS] $name.$region.digitaloceanspaces.com  (403 — private)" | tee -a $RECON/dns/cloud_buckets.txt ;;
    esac
}
for region in nyc3 sfo2 ams3 sgp1 fra1; do
    for name in "$BASE" "$BASE-assets" "$BASE-backup" "$DASHED"; do
        check_do "$name" "$region"
    done
done

hits=$(wc -l < $RECON/dns/cloud_buckets.txt)
echo ""
echo "  [$hits bucket hits] → $RECON/dns/cloud_buckets.txt"
```

---

## Phase 6 — Summary & Handoff

Count-only summary — never dumps file contents to context.

```bash
TARGET=<resolved_target>; RECON=/home/kali/current/recon

sub_count=$(wc -l < $RECON/dns/subdomains_all.txt 2>/dev/null || echo 0)
live_count=$(wc -l < $RECON/http/live_hosts.txt 2>/dev/null || echo 0)
secret_count=$(grep -c '^\[' $RECON/http/js_secrets.txt 2>/dev/null || echo 0)
ep_count=$(wc -l < $RECON/http/js_endpoints.txt 2>/dev/null || echo 0)
gh_count=$(grep -c 'github\.com/' $RECON/dns/github_dorks.txt 2>/dev/null || echo 0)
wb_count=$(wc -l < $RECON/dns/wayback_urls.txt 2>/dev/null || echo 0)
wb_int=$(wc -l < $RECON/dns/wayback_interesting.txt 2>/dev/null || echo 0)
bucket_hits=$(grep -c 'OPEN\|EXISTS' $RECON/dns/cloud_buckets.txt 2>/dev/null || echo 0)

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
printf "║  pt-recon: %-43s ║\n" "$TARGET"
echo "╠═══════════════════════════════════════════════════════╣"
printf "║  %-26s %s\n" "Passive subdomains:"     "$sub_count unique"
printf "║  %-26s %s\n" "Live hosts:"             "$live_count responded"
printf "║  %-26s %s\n" "Wayback URLs:"           "$wb_count total, $wb_int interesting"
printf "║  %-26s %s\n" "JS secrets:"             "$secret_count hits (review!)"
printf "║  %-26s %s\n" "JS endpoints:"           "$ep_count unique paths"
printf "║  %-26s %s\n" "GitHub dork hits:"       "$gh_count code URLs"
printf "║  %-26s %s\n" "Cloud bucket hits:"      "$bucket_hits found"
echo "╠═══════════════════════════════════════════════════════╣"
printf "║  %-26s %s\n" "subdomains_all.txt:"     "$RECON/dns/"
printf "║  %-26s %s\n" "live_hosts.txt:"         "$RECON/http/"
printf "║  %-26s %s\n" "dns_intel.txt:"          "$RECON/dns/"
printf "║  %-26s %s\n" "wayback_interesting.txt:" "$RECON/dns/"
printf "║  %-26s %s\n" "js_secrets.txt:"         "$RECON/http/  ← priority"
printf "║  %-26s %s\n" "js_endpoints.txt:"       "$RECON/http/"
printf "║  %-26s %s\n" "github_dorks.txt:"       "$RECON/dns/"
printf "║  %-26s %s\n" "cloud_buckets.txt:"      "$RECON/dns/"
echo "╚═══════════════════════════════════════════════════════╝"

echo ""
echo "=== Immediate attention ==="
[ "$secret_count" -gt 0 ]  && echo "  [!] JS secrets detected — cat $RECON/http/js_secrets.txt"
[ "$bucket_hits" -gt 0 ]   && echo "  [!] Cloud buckets found   — cat $RECON/dns/cloud_buckets.txt"
[ "$gh_count" -gt 0 ]      && echo "  [!] GitHub code exposure  — cat $RECON/dns/github_dorks.txt"
[ "$wb_int" -gt 0 ]        && echo "  [!] Historical juicy URLs — cat $RECON/dns/wayback_interesting.txt"

# Append counts-only to engagement notes
cat >> /home/kali/current/notes/engagement.md << EOF

---
## Recon ($(date +%Y-%m-%d))
Subdomains: $sub_count | Live: $live_count | JS secrets: $secret_count | JS endpoints: $ep_count | GitHub: $gh_count | Buckets: $bucket_hits
EOF

echo ""
echo "Next step:"
echo "  /pt <tech stack from whatweb, live services, secrets/endpoints found, bucket/github hits>"
```

---

## Execution rules

- **Each phase = one `execute_kali_command` call.** Variables do not persist across calls — always set `TARGET=<resolved>; RECON=/home/kali/current/recon` at the top of every block.
- **Never print full file contents to the conversation.** Use `head -N`, counts, or summaries only.
- **Skip phases that require missing tools** — note it and continue.
- **Phase 4 TARGET injection**: The `${TARGET}` in the Python heredoc is substituted by bash before Python runs — this is intentional and correct.
- **Long phases** (theHarvester, GitHub, nmap): if the target has many hosts, consider `async: true` on the MCP call and poll with `get_job_output`.
- **After Phase 3**: if `js_secrets.txt` has hits, read it with `execute_kali_command("cat /home/kali/current/recon/http/js_secrets.txt")` and present the findings before continuing.
