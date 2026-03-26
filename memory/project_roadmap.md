---
name: Pentesting agents roadmap
description: Existing CLI skills and planned future agents for automated pentest workflow
type: project
---

## Existing skills (all implemented & upgraded 2026-03-26)

- `/pt-init <name> <target>` — workspace setup + thorough fingerprint: WAF detection, security headers audit, CORS probe, redirect chain, nmap top-1000 + common web ports, SSL cert alt-names, attack surface summary
- `/pt <observations>` — human-level attack planner: reads prior findings before selecting vectors, 30-signal table, chain exploitation logic, SSTI bug fixed, new vectors: CORS, prototype pollution, NoSQL injection, API version abuse, CSRF, rate limit bypass, error disclosure, SSRF escalation
- `/pt-payloads <tech, input, endpoint>` — PAT-backed payload generator + new categories: NoSQL injection, prototype pollution, LDAP injection, deserialization (ysoserial probe), CORS misconfiguration
- `/pt-recon <target>` — deep asset discovery: Phase 1a SSL cert alt-names (new), crt.sh, Wayback CDX, subfinder, theHarvester, DNS intel, live host probe, nmap, JS bundle analysis, GitHub dorking, S3/GCS/Azure Blob/DigitalOcean Spaces bucket checks
- `/pt-api <base-url> [token]` — dedicated REST/GraphQL API attack: Swagger/OpenAPI/GraphQL discovery, auth bypass patterns, mass IDOR scan, verb tampering, rate limiting + bypass, GraphQL introspection/alias-batching/mutations, business logic probes
- `/pt-report [name]` — professional pentest report: PTES structure, executive summary, CVSS v3.1 scoring, CWE refs, specific remediation, attack chains, coverage table

## Planned future skills
- `pt-ad` — Active Directory exploitation: BloodHound analysis, Kerberos/NTLM relay, Impacket/evil-winrm, credential harvesting
