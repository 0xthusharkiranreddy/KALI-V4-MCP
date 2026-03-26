---
description: Initialize pentest engagement workspace on Kali — creates dirs, symlink, runs thorough initial fingerprinting including WAF, security headers, CORS, redirect chain, and wider port scan
argument-hint: <engagement-name> <target-domain-or-ip>
allowed-tools: [mcp__kali-pentest__execute_kali_command, WebSearch]
---

# pt-init — Engagement Initialization

Set up a new pentest engagement workspace on the Kali VM and run comprehensive initial fingerprinting. The output feeds directly into `/pt` (attack planning) and `/pt-recon` (deep asset discovery).

---

## Step 0 — Parse & Validate Arguments

`$ARGUMENTS` contains `<name> <target>` separated by a space.

Parse:
- `NAME` = first word of `$ARGUMENTS`
- `TARGET` = everything after the first word

If either is missing, stop and tell the user:
> "Usage: `/pt-init <engagement-name> <target-domain-or-ip>`
> Example: `/pt-init acme-corp api.acme.com`"

---

## Step 1 — Create Workspace & Symlink

```bash
NAME=<name>
TARGET=<target>
ENG=/home/kali/engagements/$NAME

mkdir -p \
    $ENG/recon/{nmap,http,dns,screenshots} \
    $ENG/scans/{ffuf,nikto,nuclei,sqlmap} \
    $ENG/exploits \
    $ENG/loot \
    $ENG/poc/{requests,screenshots,videos} \
    $ENG/notes

ln -sfn $ENG /home/kali/current

cat > $ENG/notes/engagement.md << EOF
# Engagement: $NAME
**Date**: $(date +%Y-%m-%d)
**Target**: $TARGET
**Status**: In Progress

## Target
$TARGET

## Scope
- In scope: $TARGET and all subdomains/services unless noted otherwise

## Attack Surface Summary
<!-- Fill in after pt-init completes -->
- WAF: Unknown
- HTTPS: Unknown
- Security Headers: Unknown
- Open Ports: Unknown
- Tech Stack: Unknown

## Findings
<!-- Document confirmed findings here -->

## Timeline
- $(date +%Y-%m-%d): Engagement initialized

## Notes

EOF

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Workspace ready"
echo "║  Path:    $ENG"
echo "║  Symlink: /home/kali/current → $ENG"
echo "║  Target:  $TARGET"
echo "╚══════════════════════════════════════════════════╝"
```

---

## Step 2 — HTTP/HTTPS Headers + Redirect Chain

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== Redirect Chain (HTTP → HTTPS → final) ==="
curl -sIL "http://$TARGET" 2>/dev/null \
    | grep -iE "^HTTP|^Location|^Server|^X-Powered-By" \
    | tee $ENG/recon/http/redirect_chain.txt

echo ""
echo "=== HTTPS Response Headers ==="
curl -skIL --max-time 10 "https://$TARGET" 2>/dev/null \
    | tee $ENG/recon/http/initial_headers.txt \
    | head -35

echo ""
echo "=== HTTP Fallback Headers ==="
curl -sIL --max-time 10 "http://$TARGET" 2>/dev/null | head -20
```

---

## Step 2b — Security Headers Audit

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== Security Headers Present ==="
curl -skI "https://$TARGET" 2>/dev/null \
    | grep -iE "strict-transport|content-security-policy|x-frame-options|x-content-type-options|permissions-policy|referrer-policy|access-control-allow|expect-ct|cross-origin" \
    | tee $ENG/recon/http/security_headers.txt

echo ""
echo "=== Missing Security Headers (attack signals) ==="
for header in \
    "strict-transport-security" \
    "x-frame-options" \
    "x-content-type-options" \
    "content-security-policy" \
    "referrer-policy" \
    "permissions-policy"; do
    grep -qi "$header" $ENG/recon/http/security_headers.txt \
        && echo "  [OK]      $header" \
        || echo "  [MISSING] $header"
done
```

---

## Step 2c — WAF Detection

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== WAF Detection ==="
wafw00f "https://$TARGET" 2>/dev/null \
    | grep -iE "is behind|No WAF|detected|identified|firewall" \
    | tee $ENG/recon/http/waf.txt

# Fallback: manual WAF probe via response headers
echo ""
echo "=== WAF header signals ==="
curl -skI "https://$TARGET/?<script>alert(1)</script>" 2>/dev/null \
    | grep -iE "x-sucuri|x-cache|cf-ray|x-firewall|x-waf|server.*cloudflare|x-iinfo|x-akamai" | head -10
```

---

## Step 2d — CORS Quick Probe

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== CORS probe (evil.com origin) ==="
curl -skI "https://$TARGET/" \
    -H "Origin: https://evil.com" 2>/dev/null \
    | grep -i "access-control" \
    | tee $ENG/recon/http/cors_probe.txt

echo ""
echo "=== CORS probe on /api/ ==="
curl -skI "https://$TARGET/api/" \
    -H "Origin: https://evil.com" 2>/dev/null \
    | grep -i "access-control"

echo ""
# Flag if evil.com is reflected
grep -qi "evil.com" $ENG/recon/http/cors_probe.txt \
    && echo "[CORS SIGNAL] Origin reflected — test further with /pt" \
    || echo "[cors] No reflection on root — check individual API endpoints"
```

---

## Step 2e — WhatWeb Tech Fingerprint

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== WhatWeb Fingerprint ==="
whatweb -q --no-errors "https://$TARGET" "http://$TARGET" 2>/dev/null \
    | tee $ENG/recon/http/whatweb.txt

echo ""
echo "=== Server & framework signals ==="
grep -oE "\[WordPress[^\]]*\]|\[Drupal[^\]]*\]|\[Joomla[^\]]*\]|\[PHP[^\]]*\]|\[Apache[^\]]*\]|\[Nginx[^\]]*\]|\[IIS[^\]]*\]|\[jQuery[^\]]*\]|\[Bootstrap[^\]]*\]|\[React[^\]]*\]" \
    $ENG/recon/http/whatweb.txt 2>/dev/null | sort -u | head -20
```

---

## Step 2f — CVE Search for Detected Tech Stack

After WhatWeb output is saved, parse detected technologies and search for recent critical/high CVEs. This ensures you attack known-vulnerable versions rather than only testing generic attack classes.

**Instructions for Claude**: Read `$ENG/recon/http/whatweb.txt` output from Step 2e. Extract every technology with a version number. For each tech+version combination, use `WebSearch` to find CVEs from the last 2 years. Add any relevant critical/high CVEs to the engagement attack surface summary.

**Parse tech stack from WhatWeb output:**

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== Tech Stack for CVE Research ==="
# Extract name+version pairs
grep -oE "[A-Za-z][A-Za-z0-9._-]+ \[[0-9][^\]]{0,15}\]" \
    "$ENG/recon/http/whatweb.txt" 2>/dev/null | sort -u | head -20

echo ""
echo "=== Server headers (version strings) ==="
cat "$ENG/recon/http/headers.txt" 2>/dev/null | \
    grep -iE "^Server:|^X-Powered-By:|^X-AspNet-Version:|^X-Generator:" | head -10
```

**WebSearch queries to run** (for each technology+version identified):

For each technology with a version number detected (e.g., "Nginx 1.24", "WordPress 6.4", "Apache 2.4.52", "jQuery 3.6.0"), run a WebSearch:
- Query: `"<Technology> <Version> CVE 2024 exploit"` (adjust year to current)
- Query: `"<Technology> <Version> vulnerability RCE 2024 2025"`

**Record CVE findings in engagement notes:**

```bash
ENG=/home/kali/current

cat >> "$ENG/notes/engagement.md" << 'EOF'

## CVE Intelligence (from tech stack fingerprint)
<!-- Claude: fill in any CVEs found via WebSearch above -->
| Technology | Version | CVE | Severity | Impact |
|-----------|---------|-----|----------|--------|
| (example) Nginx | 1.24.0 | CVE-2024-XXXX | High | ... |
EOF
echo "CVE section added to engagement.md"
```

---

## Step 3 — DNS Records

```bash
TARGET=<target>
ENG=/home/kali/current

{
echo "=== A / AAAA Records ==="
dig A $TARGET +short 2>/dev/null
dig AAAA $TARGET +short 2>/dev/null

echo ""
echo "=== NS (nameservers — check for takeover opportunity) ==="
dig NS $TARGET +short 2>/dev/null

echo ""
echo "=== MX (email provider — reveals identity stack) ==="
dig MX $TARGET +short 2>/dev/null | sort -n

echo ""
echo "=== TXT (SPF / DMARC / verification tokens — reveals cloud providers) ==="
dig TXT $TARGET +short 2>/dev/null
dig TXT _dmarc.$TARGET +short 2>/dev/null

echo ""
echo "=== CNAME www / api ==="
dig CNAME www.$TARGET +short 2>/dev/null
dig CNAME api.$TARGET +short 2>/dev/null

} | tee $ENG/recon/dns/initial_dns.txt

echo "[dns] saved → $ENG/recon/dns/initial_dns.txt"
```

---

## Step 4 — Port Scan (wider than default)

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== Nmap: top 1000 ports + common web ports ==="
nmap -T4 -sV --top-ports 1000 -Pn --open --reason \
     -oN $ENG/recon/nmap/initial_scan.txt \
     $TARGET 2>/dev/null

# Also explicitly scan common non-standard web ports often missed
echo ""
echo "=== Additional common web/API ports ==="
nmap -T4 -sV -Pn --open -p 8080,8443,8888,8008,9200,9300,5601,3000,3001,4000,4200,5000,6379,27017,5432,3306 \
     -oN $ENG/recon/nmap/extended_ports.txt \
     $TARGET 2>/dev/null

echo ""
echo "=== Open ports summary ==="
grep -hE "^[0-9]+/|Host:" $ENG/recon/nmap/initial_scan.txt $ENG/recon/nmap/extended_ports.txt 2>/dev/null \
    | grep -v "^$" | sort -u | head -40

echo ""
echo "[nmap] full scan → $ENG/recon/nmap/initial_scan.txt"
echo "[nmap] extra ports → $ENG/recon/nmap/extended_ports.txt"
```

---

## Step 5 — SSL / TLS Check (if port 443 open)

Run only if nmap shows port 443 open:

```bash
TARGET=<target>
ENG=/home/kali/current

echo "=== SSL/TLS Analysis ==="
sslscan --no-colour $TARGET 2>/dev/null \
    | tee $ENG/recon/http/sslscan.txt \
    | grep -iE "TLSv|SSLv|Heartbleed|BEAST|POODLE|Preferred|not supported|EXPIRED|self-signed|Subject:|Issuer:|Alt Names" \
    | head -30

echo ""
echo "=== Certificate Alt Names (additional hosts) ==="
echo | openssl s_client -connect $TARGET:443 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep -A2 "Subject Alternative Name" \
    | grep -oE "DNS:[^ ,]+" | sed 's/DNS://' | head -20

echo "[ssl] full output → $ENG/recon/http/sslscan.txt"
```

---

## Step 6 — Attack Surface Summary

```bash
TARGET=<target>
ENG=/home/kali/current

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  pt-init complete — Attack Surface Assessment"
echo "╠══════════════════════════════════════════════════════╣"
printf "║  %-24s %s\n" "Target:" "$TARGET"
printf "║  %-24s %s\n" "Engagement path:" "$ENG"
printf "║  %-24s %s\n" "Open ports found:" "$(grep -c "^[0-9]" $ENG/recon/nmap/initial_scan.txt 2>/dev/null || echo 0) (top-1000)"
printf "║  %-24s %s\n" "Tech stack:" "$(cat $ENG/recon/http/whatweb.txt 2>/dev/null | head -1 | grep -oE '\[[A-Za-z][^\]]{2,20}\]' | tr '\n' ' ' | head -c 60)"
printf "║  %-24s %s\n" "WAF:" "$(cat $ENG/recon/http/waf.txt 2>/dev/null | grep -oiE 'behind .+|No WAF|not behind' | head -1 || echo 'Unknown')"
printf "║  %-24s %s\n" "HTTPS enforced:" "$(grep -q '301\|302' $ENG/recon/http/redirect_chain.txt 2>/dev/null && echo 'Yes (redirect found)' || echo 'Check manually')"
printf "║  %-24s %s\n" "CORS signal:" "$(grep -qi 'evil.com\|access-control-allow-origin' $ENG/recon/http/cors_probe.txt 2>/dev/null && echo 'YES — probe further' || echo 'No reflection on /')"
printf "║  %-24s %s\n" "Missing sec headers:" "$(grep -c 'MISSING' <(for h in strict-transport-security x-frame-options x-content-type-options content-security-policy; do grep -qi "$h" $ENG/recon/http/security_headers.txt 2>/dev/null || echo "MISSING $h"; done) 2>/dev/null || echo '?') headers"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Attack surface notes:"
# WAF affects payload strategy
grep -qi "behind\|cloudflare\|sucuri\|akamai\|imperva" $ENG/recon/http/waf.txt 2>/dev/null \
    && echo "  [WAF] WAF detected — encode payloads, use time-based blind tests, avoid noisy scanners"
# Interesting ports
grep -qE "9200|9300" $ENG/recon/nmap/extended_ports.txt 2>/dev/null \
    && echo "  [ELASTIC] Port 9200/9300 open — check for unauthenticated Elasticsearch"
grep -qE "6379" $ENG/recon/nmap/extended_ports.txt 2>/dev/null \
    && echo "  [REDIS] Port 6379 open — check for unauthenticated Redis"
grep -qE "27017" $ENG/recon/nmap/extended_ports.txt 2>/dev/null \
    && echo "  [MONGO] Port 27017 open — check for unauthenticated MongoDB"
grep -qE "5601" $ENG/recon/nmap/extended_ports.txt 2>/dev/null \
    && echo "  [KIBANA] Port 5601 open — Kibana dashboard potentially exposed"
# CORS signal
grep -qi "evil.com" $ENG/recon/http/cors_probe.txt 2>/dev/null \
    && echo "  [CORS] Origin reflection detected — run CORS tests in /pt"
echo ""
echo "Next steps:"
echo "  /pt-recon              — deep passive asset discovery (subdomains, JS secrets, GitHub, cloud buckets)"
echo "  /pt <observations>     — start attacking with what you see (tech stack, auth method, endpoint patterns)"
```

After printing the summary, present your own analysis:
- What tech stack signals are most interesting?
- What does the WAF situation mean for payload strategy?
- What ports open are worth immediate attention?
- Any CORS or missing-headers signals to follow up?
