---
title: "Phase 6 — Engagement Report: Attack Timeline Reconstruction"
tags: [ghost-level, reporting, timeline, engagement-report, executive-summary,
  professional-writing, module-11-ghost-level]
module: 11-GhostLevel
day: 723
prerequisites:
  - Day 722 — Phase 5: OPSEC and Log Review
  - Day 659 — Writing a Security Advisory
  - Day 163 — PoC Writing and Impact Analysis
related_topics:
  - Day 724 — Phase 6: Vulnerability Advisories
  - Day 725 — Phase 6: ATT&CK Mapping and Completion
---

# Day 723 — Phase 6: Engagement Report — Attack Timeline

> "The report is the product. Not the shell. Not the DA hash. Not the
> clever bypass. The report is what stays after the engagement ends.
> It is what gets the network fixed. A finding with no documentation
> is a favour you did the attacker — not the defender."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | OPSEC review complete: Y / N

---

## Goals

Write the full engagement report executive summary and complete attack
timeline. This is the first of three report-writing sessions (Days 723–725).
By the end of Day 723, the executive summary and timeline narrative must be
in near-final draft state.

**Target time:** 3–4 hours writing.

---

## 1 — Report Structure

```
ENGAGEMENT REPORT — STRUCTURE OVERVIEW

Report title: Project SABLE Penetration Test — Findings Report
Classification: RESTRICTED — For authorised review only
Prepared for: Sable Technologies Ltd — Security Team
Prepared by: [Your name] — Ghost-Level Solo Engagement
Report date: [Date]
Engagement dates: [Start] to [End]

SECTIONS:
  1. Executive Summary         (write today — Day 723)
  2. Engagement Scope          (write today — Day 723)
  3. Attack Timeline           (write today — Day 723)
  4. Findings (per target)     (write Day 724)
  5. Risk Register             (write Day 724)
  6. ATT&CK Mapping            (write Day 725)
  7. Recommendations           (write Day 725)
  8. Appendices                (write Day 725)

Page target: 20–30 pages
Tool: Markdown or LibreOffice Writer
Output file: engagement/report/SABLE-PenTest-Report.md
```

---

## 2 — Executive Summary

Write this section for a non-technical audience. It must answer four
questions: what was tested, what was found, what is the risk, what must
be done. Maximum two pages.

```markdown
## Executive Summary

### Scope

[Your organisation] engaged Ghost-Level Trainee to conduct an authorised
penetration test of the Project SABLE lab environment between [dates].
The assessment covered five targets: sable-web, sable-svc, sable-dc,
sable-iot, and sable-store. The test simulated an external attacker with
no prior knowledge of the environment.

### Key Findings

The assessment identified **[X] findings**, of which **[Y] are Critical**,
**[Z] are High**, and **[A] are Medium**. The most significant findings are:

1. **Critical: Binary Stack Overflow in sable_broker (sable-svc)** — An
   unauthenticated attacker can execute arbitrary code on sable-svc without
   credentials by sending a malformed network packet. CVSS 9.8.

2. **Critical: Domain Compromise via Weak Service Account Password** — A
   Kerberoastable service account with a weak password enabled offline
   credential recovery, leading to full Active Directory compromise.

3. **Critical: Remote Code Execution via IoT Device** — The sable-iot
   device was accessible using credentials embedded in its own firmware,
   granting shell access to the internal network.

4. **High: JWT Authentication Bypass (sable-web)** — The custom JWT
   implementation accepted tokens signed with the `none` algorithm,
   allowing any user to forge an admin token without knowing the secret.

5. **High: Sensitive Data Exposure on sable-store** — Internal file shares
   containing [credentials / source code / backup files] were accessible to
   any domain-authenticated user.

### Business Risk

A threat actor exploiting these findings could:
- Extract all domain user credentials via DCSync
- Access and exfiltrate [description of data] from sable-store
- Maintain persistent access that survives password resets
- Compromise the entire SABLE.LOCAL domain and all services

### Immediate Actions Required

| Priority | Action | Target | Owner |
|---|---|---|---|
| P0 | Patch sable_broker bounds check | sable-svc | Engineering |
| P0 | Rotate krbtgt password twice | sable-dc | AD Ops |
| P1 | Fix JWT validation to reject alg:none | sable-web | Dev Team |
| P1 | Reset service account with weak password | sable-dc | AD Ops |
| P1 | Disable firmware credentials / rotate | sable-iot | IoT Team |
| P2 | Restrict sable-store share permissions | sable-store | Infra Team |
```

```
EXECUTIVE SUMMARY DRAFT

Written: Y / N
Page count: _______  (target: 1–2 pages)
Non-technical reviewer: would understand the risk? Y / N
All P0/P1 actions listed: Y / N
```

---

## 3 — Engagement Scope

```markdown
## Engagement Scope

### In-Scope Targets

| Host | IP | Services | Notes |
|---|---|---|---|
| sable-web | 10.0.1.10 | HTTP 80, HTTPS 443 | Node.js + Express + PostgreSQL |
| sable-svc | 10.0.1.20 | TCP 9000 | Custom binary service |
| sable-dc | 10.0.1.30 | AD/DNS/Kerberos/SMB | Windows Server 2019 |
| sable-iot | 10.0.1.40 | HTTP 80, SSH 22 | ARM embedded Linux |
| sable-store | 10.0.1.50 | SMB 445, NFS 2049 | Internal file server |

### Out of Scope

- Internet-facing infrastructure beyond the lab boundary
- Physical security (not tested)
- Social engineering (not tested)
- Denial of service testing (not performed)

### Assessment Type

Grey-box: Attacker model = external adversary with knowledge of the
general application stack but no credentials, source code, or network diagrams.

### Methodology

- PTES (Penetration Testing Execution Standard)
- MITRE ATT&CK Framework for technique mapping
- CVSS 3.1 for severity scoring
- Ghost Method: Recon → Exploit → Detect → Harden
```

---

## 4 — Attack Timeline

This is the narrative backbone of the report. Every significant action must
appear here with a timestamp.

```markdown
## Attack Timeline

The following table reconstructs the full engagement chronologically.
All times are in UTC.

| Time | Phase | Action | Result | Evidence |
|---|---|---|---|---|
| +00:15 | Recon | TCP port scan — all five targets | Services fingerprinted | nmap_*.txt |
| +00:30 | Recon | Web crawl of sable-web | API endpoints enumerated | web_crawl.txt |
| +01:00 | Recon | JWT decoded — alg:none attack tested | Admin token forged | login_response.txt |
| +02:00 | Web | Authenticated API enumeration | SSRF endpoint found | api_endpoints.txt |
| +02:30 | Web | SSRF to sable-svc internal HTTP | Binary download confirmed | svc_probe.txt |
| +03:30 | Binary | Protocol probing of sable_broker | TLV op codes mapped | svc_probe.txt |
| +04:00 | Binary | Crash via oversized length field | CWE-121 hypothesis | svc_crash.txt |
| +05:00 | Binary | Ghidra analysis — handler 0x02 | Missing bounds check confirmed | ghidra_notes.txt |
| +06:00 | Binary | Exploit developed (ret2libc) | Shell on sable-svc | shell_proof.png |
| +07:00 | Post-Web | LinPEAS on sable-web | DB credentials in .env | lpe_out.txt |
| +08:00 | Post-Web | JWT signing key in .env | Admin token forged directly | .env contents |
| +09:00 | Pivot | Chisel SOCKS tunnel established | Domain segment reachable | — |
| +10:00 | AD Recon | BloodHound collection | DA attack path: 2 hops | bloodhound.zip |
| +11:00 | AD Recon | Kerberoasting | 2 TGS hashes obtained | kerberoast_hashes.txt |
| +12:00 | AD | Kerberoast hash cracked | svc_sql password: _______ | kerberoast_cracked.txt |
| +13:00 | AD | Lateral movement to DA path | DA obtained via _______ | da_proof.png |
| +14:00 | AD | DCSync | All domain hashes extracted | dcsync_hashes.txt |
| +15:00 | AD | Golden Ticket forged | Persistent DA access | Administrator.ccache |
| +16:00 | IoT | Firmware downloaded and extracted | BusyBox ARM Linux | binwalk_scan.txt |
| +17:00 | IoT | Hardcoded credentials found | root:_______ in shadow | firmware_creds.txt |
| +17:30 | IoT | SSH to sable-iot with root | Shell confirmed | iot_shell.png |
| +18:00 | Store | SMB share access via DA credentials | Files enumerated | store_shares.txt |
| +19:00 | Store | Sensitive data exfiltrated | [contents] recovered | store_data/ |
| +20:00 | Persist | Golden Ticket deployed | Persists password reset | Administrator.ccache |
| +21:00 | Persist | Cron job on sable-web | Reverse shell every 5 min | crontab output |
| +22:00 | OPSEC | Log review on all hosts | Detection gaps documented | opsec_notes.txt |
| +23:00 | Report | Timeline and exec summary drafted | Report writing begun | this document |

Total engagement time: _______ hours
```

```
TIMELINE DRAFT

Written: Y / N
All five targets represented: Y / N
All critical findings appear: Y / N
Timestamps accurate to your notes: Y / N
Evidence references correct: Y / N
```

---

## 5 — Writing Quality Checklist

```
REPORT WRITING QUALITY GATE

[ ] No passive voice in findings ("the system was compromised" → "the attacker
    exploited X to compromise the system")
[ ] Every claim backed by evidence reference
[ ] Technical terms defined on first use
[ ] Executive summary is < 2 pages
[ ] Severity ratings use CVSS v3.1 and are consistent
[ ] Recommended fixes are specific, not generic ("patch it" is not a fix)
[ ] Timeline uses past tense, third person ("the attacker discovered...")
    or first person ("I discovered...") — pick one, stay consistent
[ ] All screenshots captioned with figure numbers
[ ] No credentials in plaintext in the report body (hash format only)
[ ] Classification header on every page
```

---

## Navigation

← Previous: [Day 722 — Phase 5: OPSEC and Log Review](DAY-0722-Phase5-OPSEC-Log-Review.md)
→ Next: [Day 724 — Phase 6: Vulnerability Advisories](DAY-0724-Phase6-Vulnerability-Advisories.md)
