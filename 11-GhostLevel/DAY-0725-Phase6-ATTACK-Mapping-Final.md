---
title: "Phase 6 — ATT&CK Mapping, Recommendations, and Report Completion"
tags: [ghost-level, reporting, mitre-attack, recommendations,
  engagement-completion, module-11-ghost-level]
module: 11-GhostLevel
day: 725
prerequisites:
  - Day 724 — Phase 6: Vulnerability Advisories
related_topics:
  - Day 726 — Ghost Level Debrief (preview)
---

# Day 725 — Phase 6: ATT&CK Mapping and Final Report

> "The last ten percent of a report takes twenty percent of the time.
> The ATT&CK mapping, the remediation section, the appendices — they
> look optional. They are not. That is what turns a hack log into a
> security improvement programme."
>
> — Ghost

---

> **ENGAGEMENT CLOCK — CHECK IN**
> Time elapsed: _______ hours | Findings drafted: Y / N

---

## Goals

Complete the MITRE ATT&CK mapping for the full engagement. Write the
remediation roadmap and defence-in-depth recommendations. Finalise and
proofread the complete report. The engagement clock ends when the report
is signed off.

**Target time:** 3–4 hours.

---

## 1 — ATT&CK Navigator Layer

Map every technique used in the engagement to the MITRE ATT&CK matrix.
This gives the blue team a concrete detection checklist.

```
MITRE ATT&CK MAPPING — PROJECT SABLE

RECONNAISSANCE (TA0043)
  T1595.001  Active Scanning — Port Scanning (nmap)
  T1595.002  Active Scanning — Vulnerability Scanning (feroxbuster, probe.py)
  T1592.002  Gather Host Information — Software (whatweb, nmap -sV)

INITIAL ACCESS (TA0001)
  T1190      Exploit Public-Facing Application (JWT alg:none, sable_broker BOF)

EXECUTION (TA0002)
  T1059.004  Command and Scripting Interpreter — Unix Shell (via CGI injection)
  T1059.003  Command and Scripting Interpreter — Windows Shell (smbexec/psexec)
  T1203      Exploitation for Client Execution (sable_broker ret2libc)

PERSISTENCE (TA0003)
  T1053.003  Scheduled Task/Job — Cron (sable-web cron shell)
  T1037.004  Boot or Logon Init Scripts — rc.scripts (sable-iot)
  T1098.001  Account Manipulation — Additional Cloud Credentials (AdminSDHolder)
  T1136.002  Create Account — Domain Account (backup DA account)
  T1558.001  Steal or Forge Kerberos Tickets — Golden Ticket

PRIVILEGE ESCALATION (TA0004)
  T1068      Exploitation for Privilege Escalation
  T1078.002  Valid Accounts — Domain Accounts (post-Kerberoast)
  T1484.001  Domain Policy Modification — Group Policy Object

DEFENSE EVASION (TA0005)
  T1550.002  Use Alternate Authentication Material — Pass-the-Hash
  T1550.003  Use Alternate Authentication Material — Pass-the-Ticket
  T1027      Obfuscated Files or Information (Base64 payloads)

CREDENTIAL ACCESS (TA0006)
  T1558.003  Steal or Forge Kerberos Tickets — Kerberoasting
  T1558.004  Steal or Forge Kerberos Tickets — AS-REP Roasting
  T1003.006  OS Credential Dumping — DCSync
  T1552.001  Unsecured Credentials — Credentials in Files (.env, firmware)

DISCOVERY (TA0007)
  T1082      System Information Discovery (uname, hostname, id)
  T1046      Network Service Discovery (nmap sweeps)
  T1083      File and Directory Discovery (find commands)
  T1069.002  Permission Groups Discovery — Domain Groups (BloodHound)
  T1018      Remote System Discovery (ping sweep)
  T1087.002  Account Discovery — Domain Account (GetADUsers)
  T1135      Network Share Discovery (SMB share enum)
  T1201      Password Policy Discovery (LDAP)

LATERAL MOVEMENT (TA0008)
  T1021.002  Remote Services — SMB/Windows Admin Shares (psexec/smbexec)
  T1021.004  Remote Services — SSH (pivot tunnels)
  T1563.002  Remote Service Session Hijacking — SMB Relay (theoretical)
  T1210      Exploitation of Remote Services (binary exploit from web)

COLLECTION (TA0009)
  T1005      Data from Local System (sable-store share access)
  T1039      Data from Network Shared Drive (NFS/SMB collection)
  T1213      Data from Information Repositories (database backups)

EXFILTRATION (TA0010)
  T1041      Exfiltration over C2 Channel (via reverse shell / Chisel)

IMPACT (TA0040)
  [Not triggered — engagement did not cause damage]

TECHNIQUES USED: _______ out of ~200 Enterprise techniques
TACTICS COVERED: ___ / 14 Enterprise tactics
```

```bash
# ─── Export ATT&CK Navigator layer ───────────────────────────────────
# Use the ATT&CK Navigator online: https://mitre-attack.github.io/attack-navigator/
# Upload this layer JSON or manually colour the techniques used.

# Or generate via atomic-red-team YAML for the report appendix
cat > engagement/report/attack_layer.json << 'EOF'
{
  "name": "Project SABLE — Engagement Coverage",
  "domain": "enterprise-attack",
  "description": "Techniques observed during Project SABLE penetration test",
  "techniques": [
    {"techniqueID": "T1595.001", "color": "#ff6666", "comment": "nmap -p- --min-rate"},
    {"techniqueID": "T1190",     "color": "#ff6666", "comment": "JWT none, sable_broker BOF"},
    {"techniqueID": "T1558.003", "color": "#ff6666", "comment": "Kerberoast → crack → DA"}
  ]
}
EOF
```

---

## 2 — Remediation Roadmap

Present recommendations in a phased, prioritised, actionable format.

```markdown
## Remediation Roadmap

### Priority 0 — Fix Immediately (before next business day)

1. **Patch sable_broker bounds check** [sable-svc]
   - Add `if (len > MAX_ALLOWED_SIZE) { return error; }` before memcpy
   - Rebuild with `-fstack-protector-all -z noexecstack -pie`
   - Impact: eliminates unauthenticated RCE on a network-exposed service

2. **Double-rotate krbtgt password** [sable-dc]
   - Rotate krbtgt password twice (24 hours apart) to invalidate Golden Tickets
   - Invalidates all forged Kerberos tickets immediately after second rotation
   - ATT&CK mitigation: M1015 (Active Directory Configuration)

3. **Fix JWT algorithm validation** [sable-web]
   - Whitelist `HS256` only in JWT library configuration
   - Reject `alg:none` or any algorithm not in the approved list
   - Use a maintained JWT library (jsonwebtoken v9+)

### Priority 1 — Fix Within 72 Hours

4. **Disable hardcoded IoT credentials** [sable-iot]
   - Remove hardcoded credentials from firmware
   - Implement unique credentials per device provisioned at manufacturing
   - Require authentication for all management interfaces

5. **Reset Kerberoastable service account password** [sable-dc]
   - Set a password of ≥ 25 random characters for all service accounts
   - Consider using Managed Service Accounts (MSA) instead

6. **Restrict SSRF in report generator** [sable-web]
   - Implement an allowlist of permitted URL schemes (https only)
   - Block requests to RFC 1918 address ranges
   - Remove `file://`, `gopher://`, `dict://` scheme support

### Priority 2 — Fix Within 30 Days

7. **Restrict sable-store share permissions** [sable-store]
   - Apply minimum-privilege ACLs per department/role group
   - Audit all share permissions with `Get-SmbShareAccess`
   - Remove domain-authenticated blanket read access

8. **Implement network segmentation** [Infrastructure]
   - sable-web should not be able to reach sable-svc TCP 9000
   - IoT devices should be in a separate VLAN with no AD visibility
   - sable-store should be accessible only to specific groups, not the entire domain

9. **Deploy endpoint detection** [Infrastructure]
   - Install EDR on all Windows systems (including sable-dc)
   - Configure Sysmon on domain controllers (Event IDs 1, 3, 7, 11)
   - Enable PowerShell Script Block Logging (Event 4104)

### Priority 3 — Strategic Improvements (90 days)

10. **Implement privileged access workstations (PAW)**
11. **Deploy tiered administration model** (tier 0: DC only, tier 1: servers, tier 2: workstations)
12. **Conduct annual penetration testing + quarterly vulnerability scanning**
13. **Deploy SIEM with alerting for: T1558 (Kerberoasting), T1003.006 (DCSync),
    T1190 (exploit attempts)**
14. **Implement firmware signing for sable-iot update pipeline**
```

---

## 3 — Defence-in-Depth Analysis

```
WHERE DEFENCE-IN-DEPTH FAILED — PROJECT SABLE

LAYER 1 — PERIMETER
  Expected control: firewall blocking non-standard ports
  Actual state: sable-svc port 9000 exposed with no authentication
  Gap: no network-layer authentication before binary

LAYER 2 — APPLICATION
  Expected control: input validation on all network inputs
  Actual state: JWT library accepts alg:none; sable_broker has no bounds check
  Gap: custom implementations with no security review

LAYER 3 — AUTHENTICATION
  Expected control: strong passwords for all accounts
  Actual state: service account password cracked in < 1 hour
  Gap: no password complexity policy enforced for service accounts

LAYER 4 — AUTHORISATION
  Expected control: least-privilege access to file shares
  Actual state: all domain users could read sensitive sable-store shares
  Gap: permissions set to "Domain Users" rather than specific groups

LAYER 5 — DETECTION
  Expected control: SIEM alerting on Kerberoasting, DCSync, abnormal TGS volume
  Actual state: no detection tooling observed during the engagement
  Gap: entire Active Directory attack chain was undetected

LAYER 6 — RESPONSE
  Expected control: IR capability to detect and contain a breach
  Actual state: not tested
  Gap: unknown

SINGLE CONTROL THAT WOULD HAVE MOST REDUCED IMPACT:
  Network segmentation preventing sable-web from reaching sable-svc port 9000
  directly. This would have removed the most severe initial access vector.
  Second: SIEM detection of DCSync (Event 4662) would have triggered a response
  before Golden Ticket persistence was established.
```

---

## 4 — Report Completion Checklist

```
FINAL REPORT CHECKLIST

STRUCTURE:
  [ ] Executive Summary (1–2 pages, non-technical)
  [ ] Engagement Scope (targets, dates, methodology)
  [ ] Attack Timeline (chronological, timestamped)
  [ ] Findings — F-01 through F-0X (all complete with PoC + fix)
  [ ] Risk Register (all findings, CVSS, status)
  [ ] ATT&CK Mapping table
  [ ] Remediation Roadmap (P0/P1/P2/P3)
  [ ] Defence-in-Depth Analysis
  [ ] Appendices (tool outputs, screenshots index)

QUALITY:
  [ ] No finding without evidence reference
  [ ] No generic remediation ("patch it" → specific code change)
  [ ] CVSS vectors correct and consistent
  [ ] All P0 findings have immediate, actionable fixes
  [ ] Executive summary matches findings (no contradiction)
  [ ] Spelling and grammar checked
  [ ] Report version: 1.0 DRAFT → 1.0 FINAL
  [ ] Classification header on every page

FILES:
  [ ] engagement/report/SABLE-PenTest-Report.md (or .docx)
  [ ] engagement/evidence-package/ (all evidence files)
  [ ] engagement/exploits/ (all PoC scripts)
  [ ] engagement/report/attack_layer.json (ATT&CK Navigator)

WORD COUNT TARGET: _______ words (minimum 3,000 for a credible report)
PAGE COUNT: _______ pages (target: 20–30 pages)

REPORT COMPLETE: Y / N
ENGAGEMENT CLOCK STOP TIME: HH:MM (_______ hours total)
```

---

## 5 — Engagement Retrospective

```
48-HOUR ENGAGEMENT — RETROSPECTIVE

TOTAL TIME USED: _______ hours

PHASE BREAKDOWN:
  Phase 1 (Recon):          _______ hours
  Phase 2 (Web exploit):    _______ hours
  Phase 3 (Binary):         _______ hours
  Phase 4 (AD):             _______ hours
  Phase 5 (IoT/Store/Ops):  _______ hours
  Phase 6 (Reporting):      _______ hours

BEST DECISION DURING THE ENGAGEMENT:
  _______________________________________________________________

WORST DECISION (time wasted / wrong rabbit hole):
  _______________________________________________________________

WHAT I WOULD DO DIFFERENTLY:
  1. ____________________________________________________________
  2. ____________________________________________________________
  3. ____________________________________________________________

SKILLS THAT SAVED THE ENGAGEMENT:
  _______________________________________________________________

SKILLS I NEED TO IMPROVE:
  _______________________________________________________________

GOAL COMPLETION:
  [ ] Binary RCE obtained        (sable-svc)
  [ ] Domain Admin obtained      (SABLE.LOCAL)
  [ ] IoT shell obtained         (sable-iot)
  [ ] sable-store data accessed
  [ ] Full report delivered

ENGAGEMENT VERDICT:
  [ ] ALL objectives complete — Ghost Level passed
  [ ] Most objectives complete — strong pass
  [ ] Core objectives complete — conditional pass (debrief required)
  [ ] Significant gaps — extend engagement by 24 hours
```

---

## Navigation

← Previous: [Day 724 — Phase 6: Vulnerability Advisories](DAY-0724-Phase6-Vulnerability-Advisories.md)
→ Next: [Day 726 — Ghost Level Debrief](DAY-0726-Ghost-Level-Debrief.md)
