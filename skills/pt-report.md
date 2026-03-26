---
description: Generate a professional penetration test report from engagement artifacts — executive summary, CVSS-scored findings, remediation, attack chains, saved as markdown on Kali
argument-hint: [engagement-name — defaults to active /home/kali/current]
allowed-tools: [mcp__kali-pentest__execute_kali_command]
---

# pt-report — Pentest Report Generator

You are a senior penetration tester writing a professional penetration test report. Read all engagement artifacts from Kali, then generate a structured report with executive summary, CVSS-scored findings, attack chains, and specific remediation advice.

**Report standard**: PTES (Penetration Testing Execution Standard) structure, CVSS v3.1 scoring.

---

## Step 0 — Locate Engagement

```bash
# Resolve engagement path
if [ -n "$ARGUMENTS" ]; then
    ENG=/home/kali/engagements/$ARGUMENTS
    [ -d "$ENG" ] || { echo "ERROR: Engagement '$ARGUMENTS' not found in /home/kali/engagements/"; ls /home/kali/engagements/ 2>/dev/null; exit 1; }
else
    ENG=/home/kali/current
    [ -L "$ENG" ] || { echo "ERROR: No active engagement. Run /pt-init first or pass engagement name."; exit 1; }
fi

echo "=== Engagement: $ENG ==="
echo "Target: $(grep -i '^**Target' $ENG/notes/engagement.md 2>/dev/null | head -1)"
echo "Date: $(grep -i '^**Date' $ENG/notes/engagement.md 2>/dev/null | head -1)"
echo ""
echo "=== Artifacts available ==="
echo "Findings in engagement.md:"
grep -c "^## Finding:" $ENG/notes/engagement.md 2>/dev/null || echo "0"
echo ""
echo "PoC files:"
ls $ENG/poc/requests/ 2>/dev/null || echo "(none)"
echo ""
echo "Recon data:"
[ -f "$ENG/recon/http/live_hosts.txt" ] && echo "  live hosts: $(wc -l < $ENG/recon/http/live_hosts.txt)"
[ -f "$ENG/recon/nmap/initial_scan.txt" ] && echo "  nmap: $(grep -c '^[0-9]' $ENG/recon/nmap/initial_scan.txt 2>/dev/null) open ports"
```

---

## Step 1 — Read All Findings

```bash
ENG=/home/kali/current

echo "=== Full engagement.md ==="
cat $ENG/notes/engagement.md 2>/dev/null

echo ""
echo "=== PoC request files ==="
for f in $ENG/poc/requests/*.txt 2>/dev/null; do
    [ -f "$f" ] || continue
    echo "--- $(basename $f) ---"
    head -30 "$f"
    echo ""
done

echo "=== Nmap findings ==="
grep -E "^[0-9]+/|Host:|open" $ENG/recon/nmap/initial_scan.txt 2>/dev/null | head -30
```

---

## Step 2 — Generate Report

After reading all artifacts above, generate the complete professional report in markdown. Follow this exact structure:

---

### Report Structure to Generate

```markdown
# Penetration Test Report
**Engagement**: [name]
**Target**: [target]
**Date**: [date]
**Tester**: Security Researcher
**Classification**: CONFIDENTIAL

---

## Executive Summary

[2-3 sentences in business language — not technical. Focus on: what was tested, what was found, what is the business risk. Example: "A penetration test of [target] identified [N] security vulnerabilities, including [most critical finding in plain language]. The most severe issue allows [business impact — e.g. 'an attacker to access any user account without authentication']. Immediate remediation is recommended for [critical/high findings]."]

### Risk Summary

| Severity | Count |
|----------|-------|
| Critical | N |
| High | N |
| Medium | N |
| Low | N |
| Informational | N |
| **Total** | **N** |

---

## Scope & Methodology

**In Scope**: [target + subdomains/services as defined]
**Testing Period**: [date range]
**Testing Type**: Grey-box / Black-box / White-box

**Methodology**: OWASP Testing Guide v4.2, PTES, OWASP API Security Top 10 2023

**Tools used**: [list actual tools that were run — from recon/scans directories]

---

## Findings

### Findings Table

| # | Title | Severity | CVSS | Endpoint |
|---|-------|----------|------|----------|
| 1 | [name] | Critical | 9.8 | /api/... |
| 2 | [name] | High | 8.1 | /api/... |
...

---

### Finding 1: [Title]

**Severity**: Critical / High / Medium / Low
**CVSS v3.1 Score**: [score]
**CVSS Vector**: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
**CWE**: CWE-[number]: [name]

**Endpoint**: `[METHOD] https://target/api/endpoint`
**Parameter**: [param name if applicable]

**Description**:
[2-3 sentences: what the vulnerability is, what causes it, how it was identified]

**Impact**:
[Business language: what an attacker can actually do. Not "attacker can execute code" but "attacker can read all customer records including payment information, impersonate any user account, and modify or delete data"]

**Evidence**:
```
[Key lines from the PoC request/response — not full raw dump]
```
Full PoC: `poc/requests/[finding_name].txt`

**Remediation**:
[Specific, actionable fix — not generic "validate input". E.g.: "Add authorization check in the getUserProfile() method to verify the requesting user's ID matches the requested resource ID. Use the authenticated session's user context, not a client-supplied parameter."]

**References**:
- OWASP: [relevant OWASP link]
- CWE: https://cwe.mitre.org/data/definitions/[number].html

---
[Repeat for each finding]

---

## Compliance Impact

Map each confirmed finding to compliance frameworks. Include only frameworks relevant to the engagement (PCI-DSS for payment data, GDPR for EU user data, HIPAA for health data, SOC 2 for SaaS).

| Finding | OWASP Top 10 (2021) | CWE | PCI-DSS v4.0 | GDPR | HIPAA (if applicable) |
|---------|---------------------|-----|--------------|------|-----------------------|
| SQL Injection | A03 — Injection | CWE-89 | Req 6.2.4 | Art. 32 | § 164.312(a)(1) |
| Broken Access Control / IDOR | A01 — Broken Access Control | CWE-639 | Req 7.2 | Art. 25, 32 | § 164.312(a)(2) |
| SSRF | A10 — SSRF | CWE-918 | Req 1.3 | Art. 32 | § 164.312(b) |
| XXE | A05 — Security Misconfiguration | CWE-611 | Req 6.2.4 | Art. 32 | — |
| Insecure Deserialization | A08 — Software/Data Integrity | CWE-502 | Req 6.2.4 | Art. 32 | § 164.312(b) |
| XSS (Stored) | A03 — Injection | CWE-79 | Req 6.2.4 | Art. 32 | § 164.312(a)(1) |
| Authentication Bypass / JWT | A07 — Auth Failures | CWE-287 | Req 8.2 | Art. 32 | § 164.312(d) |
| Race Condition / Business Logic | A04 — Insecure Design | CWE-362 | Req 6.2.3 | Art. 25 | — |
| Command Injection | A03 — Injection | CWE-78 | Req 6.2.4 | Art. 32 | § 164.312(b) |
| Missing Security Headers | A05 — Security Misconfiguration | CWE-693 | Req 6.3 | Art. 32 | — |
| Sensitive Data Exposure | A02 — Cryptographic Failures | CWE-200 | Req 3.3, 4.2 | Art. 32, 34 | § 164.312(a)(2)(iv) |

*Adjust rows to match only confirmed findings. Remove inapplicable frameworks.*

---

## Attack Chains

[Only include if 2+ findings chain into a higher-impact attack]

### Chain: [Name — e.g. "Account Takeover via IDOR + JWT Tampering"]

**Combined Severity**: Critical
**Steps**:
1. [Step 1 — use finding X to achieve Y]
2. [Step 2 — leverage Y to achieve Z]
3. [Step 3 — final impact]

**Impact**: [What the complete chain achieves]

---

## Tested But Not Vulnerable

[Shows testing coverage — important for professional reports]

| Test | Result |
|------|--------|
| SQL Injection | Not vulnerable — parameterized queries used |
| XSS | Not tested (out of scope) |
| Authentication brute force | Rate limiting in place |

---

## Remediation Priority

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| Immediate | [name] | Low | Critical |
| This sprint | [name] | Medium | High |
| Next quarter | [name] | High | Medium |

---

## Appendix: Tool Commands Run

[List the key tool commands executed during the engagement, with brief notes on what was found]
```

---

## Step 3 — Save Report

```bash
ENG=/home/kali/current
DATE=$(date +%Y-%m-%d)
REPORT_FILE="$ENG/notes/pentest_report_$DATE.md"

cat > "$REPORT_FILE" << 'REPORT_EOF'
[paste generated report content here]
REPORT_EOF

echo "Report saved: $REPORT_FILE"
wc -l "$REPORT_FILE"
echo ""
echo "To copy to Windows:"
echo "  cat $REPORT_FILE"
```

---

## CVSS v3.1 Scoring Reference

Use these when scoring each finding. Choose the vector that matches the actual exploit conditions:

| Severity | Score | Example |
|----------|-------|---------|
| Critical | 9.0–10.0 | Unauthenticated RCE, SQLi full DB dump with no auth, account takeover chain |
| High | 7.0–8.9 | Auth IDOR with PII, SSRF to cloud metadata, SQLi with auth, JWT alg:none |
| Medium | 4.0–6.9 | CSRF, stored XSS, CORS misconfiguration, open redirect, mass assignment |
| Low | 0.1–3.9 | Missing security headers, verbose error messages, weak TLS config, info disclosure |
| Informational | 0.0 | Best practice gaps, no direct exploitability |

**CVSS Vector components**:
- `AV:N` = Network exploitable (most web vulns)
- `AC:L` = Low complexity (no special conditions)
- `PR:N` = No privileges required, `PR:L` = Low (authenticated), `PR:H` = Admin
- `UI:N` = No user interaction, `UI:R` = Requires interaction (XSS, CSRF)
- `S:U` = Scope unchanged, `S:C` = Scope changed (affects other components)
- `C/I/A: H/L/N` = Confidentiality/Integrity/Availability impact

---

## Execution Rules

- **Read all artifacts first** (Step 1) before writing a single word of the report
- **Business impact language** — the executive summary is for non-technical stakeholders
- **Specific remediation** — "validate the session user matches the resource owner" not "fix authorization"
- **CVSS vector strings** — include the full vector, not just the score
- **Attack chains** — always check if multiple findings chain to a higher severity
- **Evidence** — include the key lines of PoC, not full raw dumps (save those in poc/ files)
- **CWE numbers** — always include the relevant CWE for each finding
