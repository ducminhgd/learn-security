---
title: "Red Team Report Writing Sprint"
tags: [red-team, report-writing, executive-summary, findings, remediation,
  CVSS, attack-narrative, ATT&CK-mapping, deliverable, professional-output,
  pentest-report, kill-chain, remediation-matrix]
module: 08-RedTeam-03
day: 549
related_topics:
  - Full Engagement Simulation (Day 548)
  - Full Engagement Simulation Alternate (Day 548)
  - Milestone 550 Retrospective (Day 550)
  - Red Team CTF Sprint Introduction (Day 551)
  - Offshore Lab Episode 4 (Day 538)
---

# Day 549 — Red Team Report Writing Sprint

> "The engagement is not done when you get the flag. It is done when the
> client understands what you found, why it matters, and exactly what to
> do about it. A pentest without a report is a break-in. A pentest with
> a good report is a service. You are in the service business. Learn to
> write."
>
> — Ghost

---

## Goals

Write a complete red team engagement report using the findings from the
engagement simulations (Days 535–548).
Structure an executive summary that a non-technical reader can act on.
Write technical findings with reproducible evidence and unambiguous remediation.
Build a remediation priority matrix.
Map every finding to MITRE ATT&CK.

**Prerequisites:** Days 535–548 (Offshore lab episodes and alternate scenario).
The report should be based on findings from those engagements.
**Time budget:** 6 hours (full writing sprint — treat it like a real deadline).

---

## Part 1 — Report Architecture

```
A professional red team report has exactly these sections.
Do not add sections. Do not remove sections. Adapt the content — not the
structure.

COVER PAGE
  Client: [Name]
  Engagement: [Type — Internal Pentest / Red Team / Assumed Breach]
  Assessment Period: [Start Date] – [End Date]
  Report Date: [Delivery Date]
  Prepared By: [Your Operator Name]
  Classification: CONFIDENTIAL — FOR CLIENT USE ONLY

TABLE OF CONTENTS (auto-generated or hand-built)

1. EXECUTIVE SUMMARY (1–2 pages)
2. ENGAGEMENT SCOPE AND RULES OF ENGAGEMENT (1 page)
3. ATTACK NARRATIVE (3–5 pages)
4. FINDINGS (1 page per finding, as many as needed)
5. REMEDIATION PRIORITY MATRIX (1 page)
6. APPENDICES
   A. Tools Used
   B. Credentials Captured
   C. Hosts Compromised
   D. MITRE ATT&CK Mapping Table
   E. Engagement Timeline (from your engagement log)

Target total length: 20–40 pages for a full engagement.
This is a sprint — produce a draft-quality version of each section.
```

---

## Part 2 — Executive Summary

```
Audience: the CISO, CEO, or Board. They have 5 minutes. They need to know:
  1. What did the red team achieve? (Highest impact, in plain English)
  2. How did they get in? (One sentence — the initial access)
  3. What is the business risk? (In dollars, data, or regulatory terms)
  4. What must be fixed first? (The top 3 remediation items)

Rules for the executive summary:
  → No acronyms without definition (spell out "Active Directory" — not "AD")
  → No tool names (no "Mimikatz", "BloodHound", "Metasploit")
  → No technical jargon (no "DCSync", "Kerberoasting", "NTLM hash")
  → Every claim needs a "so what" — "we accessed the VPN using a weak
    password" → "this means any person with a corporate email and one hour
    of patience could have done the same"
  → Finish with a single forward-looking sentence: what this assessment
    enables the organisation to do next
```

### Executive Summary Template

```markdown
## Executive Summary

During a [X]-day simulated adversary engagement, the [Company Name]
red team operated against the full CorpCo International environment without
any prior knowledge of the internal systems.

**Engagement Result**

The assessment team achieved the highest level of access possible within the
organisation's environment:

- Full administrative control of the corporate Windows domain
  (approximately [N] users and [N] systems)
- Administrative access to the organisation's cloud environment
- Access to [Crown Jewel Name] — the organisation's [describe asset plainly]

**How Access Was Achieved**

Initial access was obtained using a valid employee username and password,
discovered by sending a single password to a list of corporate email addresses.
No technical vulnerability or hacking tool was required to gain initial access
— only a weak, commonly used password.

From this initial access, the assessment team escalated to full administrative
control using a series of configuration weaknesses in the corporate
authentication infrastructure.

**Business Risk**

The findings in this report demonstrate that an external attacker who obtains
or guesses one employee credential — through phishing, data breaches, or
password guessing — could:

- Access all corporate systems and user data within [X] hours
- Extract [Crown Jewel description] with no additional barrier
- Maintain undetected access for an extended period (the assessment team
  operated undetected for [X] hours during the simulated engagement)

**Immediate Actions Required**

Three actions would prevent the primary attack chain demonstrated:

1. Require multi-factor authentication on all systems reachable from the
   internet (VPN, email, remote access portals)
2. Remove the ADCS misconfiguration that allows any employee to impersonate
   any other user for authentication purposes
3. Rotate the credentials of the synchronisation account connecting the
   on-premises environment to the cloud, and restrict its permissions

These three controls, implemented together, would block every attack path
demonstrated during this assessment.

**Conclusion**

This assessment provides CorpCo International with a clear, evidenced
picture of the risks in its current environment. The findings are
actionable. The remediation items in this report, prioritised by risk and
implementation effort, form the basis of a roadmap to a materially more
resilient security posture.
```

---

## Part 3 — Engagement Scope and Rules of Engagement

```
This section is factual. It documents what was in and out of scope.
It protects both the client and the assessor legally.

Contents:
  → Scope definition (networks, domains, applications in scope)
  → Out-of-scope items (production DBs, DR systems, specific users)
  → Rules of Engagement (no DoS, no destructive attacks, no exfiltration
    of real customer data, immediate stop-work conditions)
  → Assessment window (dates and times)
  → Emergency contact chain (who to call if something goes wrong)
  → Authorisation statement (reference to the engagement contract)

Example scope entry:
  IN SCOPE:
    External: *.corpcointl.com, VPN gateway (vpn.corpcointl.com)
    Internal: corp.local domain, 10.10.10.0/24, 192.168.10.0/24
    Cloud: tenant.onmicrosoft.com (read-only cloud actions)
  OUT OF SCOPE:
    Production databases containing customer PII
    DR site (dr.corpcointl.com)
    Physical security testing
    Social engineering of non-IT staff
```

---

## Part 4 — Attack Narrative

```
Audience: technical staff — senior engineers, SOC leads, IR team.
Purpose: tell the story of the engagement so defenders can walk the path
  themselves and understand the attack chain end-to-end.

Rules for the attack narrative:
  → Chronological order — follow the engagement timeline from your log
  → Tool names ARE appropriate here (this is the technical section)
  → Every step must have evidence (screenshot reference or log excerpt)
  → Write in past tense: "The assessment team conducted..." not "We found..."
  → Include dead ends — places where techniques failed and why
  → Include the defender's perspective where possible ("no alert fired
    because...")
```

### Attack Narrative Template

```markdown
## Attack Narrative

### Phase 1 — External Reconnaissance (Day 1, Hours 0–1)

The assessment team began with passive reconnaissance of the target domain
`corpcointl.com`. Using the theHarvester tool and publicly available data
from LinkedIn and GitHub, the team constructed a list of [N] employee
email addresses in the format `firstname.lastname@corpcointl.com`.

Email validity was confirmed using the `o365spray` tool's enumeration mode,
which identifies existing accounts by analysing error code differences in
Microsoft's authentication API without triggering a failed login event.

**Result:** [N] valid accounts confirmed. No alerts generated.
**Evidence:** Appendix E, Timeline entries 09:00–09:45.

---

### Phase 2 — Initial Access via Credential Spray (Day 1, Hours 1–4)

Using the validated account list and a single password — `Summer2024!` —
sent to all accounts at a rate of one attempt per account per hour, the
assessment team obtained valid VPN credentials for one account after
[N] hours.

The password was identified as a probable target using seasonal password
patterns common in corporate environments. The VPN system did not enforce
multi-factor authentication on this account.

**Credentials obtained:** john.smith@corpcointl.com / Summer2024!
**Result:** Direct VPN access to the corp.local network segment (10.10.10.0/24).
**Evidence:** Appendix B — Credentials Captured, Entry 1.
**Note:** The active directory lockout policy was set to lock after 5 failed
attempts within 30 minutes. The spray rate of 1 attempt per account per hour
stayed entirely below this threshold. No lockouts occurred.

---

### Phase 3 — Internal Reconnaissance and Privilege Escalation

[Continue for each phase: C2 deployment, BloodHound enumeration, DA path
chosen, DA achieved, DCSync, Azure pivot, crown jewel access]

---

### Phase 4 — Domain Compromise

[...]

---

### Phase 5 — Cloud Pivot

[...]

---

### Phase 6 — Crown Jewel Access and Cleanup

[...]
```

---

## Part 5 — Technical Findings

```
Each finding is one page. This is the core of the report.
Format is fixed — do not deviate from it.

Findings are ordered by severity: Critical → High → Medium → Low → Info.

A finding is NOT a technique. A finding is a vulnerability or misconfiguration
that enabled the technique.

Wrong: "Finding: DCSync Attack"
  → DCSync is what you did. Not a finding.

Right: "Finding: Domain Admin credentials obtainable by standard domain user
  via misconfigured Active Directory Certificate Services"
  → This is the vulnerability. DCSync is the impact.
```

### Finding Card Format

```markdown
---

## Finding — [Short Title]

**Finding ID:** F-01
**Severity:** [Critical | High | Medium | Low | Informational]
**CVSS Score:** [e.g. 9.8 — use CVSS 3.1 Base Score]
**ATT&CK Technique:** [e.g. T1649 — Steal or Forge Authentication Certificates]
**CWE:** [e.g. CWE-284 — Improper Access Control]

### Summary

[One paragraph. What is vulnerable, what can an attacker do, why it matters.
Write for a technical reader who has not read the narrative.]

### Evidence

[Screenshot reference, log excerpt, or command output that proves the
vulnerability exists. Never include full credential dumps in the body —
reference the appendix. Example below.]

    [Evidence: command output from certipy showing ESC1 vulnerability]
    $ certipy find -u john.smith@corp.local -p 'Summer2024!' -dc-ip 10.10.10.5 -vulnerable -stdout
    Certificate Templates
      Template Name: UserCertificate
      ...
      [!] Vulnerabilities
        ESC1: 'CORP\Domain Users' can enroll, enrollee supplies subject

### Steps to Reproduce

1. Obtain any valid domain user credential (demonstrated in Finding F-01).
2. Run certipy to identify vulnerable certificate templates:
   `certipy find -u <user> -p <pass> -dc-ip <DC_IP> -vulnerable`
3. Request a certificate with administrator UPN as Subject Alternative Name:
   `certipy req -u <user> -p <pass> -ca corp-CA -template UserCertificate
   -upn administrator@corp.local`
4. Authenticate using the issued certificate:
   `certipy auth -pfx administrator.pfx -dc-ip <DC_IP>`
5. The domain administrator's NTLM hash is returned by the domain controller,
   allowing full administrative access.

### Impact

An attacker with any valid domain user credential can obtain domain
administrator privileges within minutes. This requires no elevated
permissions, no software exploitation, and no interaction from any user.
All corporate systems joined to the corp.local domain are then compromised.

### Remediation

1. **Immediate (< 24 hours):** Remove the "Enrollee Supplies Subject" flag
   from the `UserCertificate` template. In the Certificate Authority console:
   Certificate Templates → UserCertificate → Properties → Subject Name →
   uncheck "Supply in the request". Restart the Certificate Authority service.

2. **Short-term (< 1 week):** Audit all certificate templates for
   ESC1–ESC8 vulnerabilities using `certipy find -vulnerable`. Remediate
   all flagged templates.

3. **Long-term (< 1 month):** Implement Event ID 4886/4887 alerting on the
   Certificate Authority to detect certificate requests with unexpected
   Subject Alternative Names.

### References

- SpecterOps: Certified Pre-Owned (Will Schroeder, Lee Christensen, 2021)
- CVE-2022-26923 (related Certificate Services elevation of privilege)
- MITRE ATT&CK T1649: Steal or Forge Authentication Certificates

---
```

### Severity Definitions and CVSS Guidance

```
For a red team finding — CVSS Base Score:

  Critical (9.0–10.0):
    → No authentication required to reach the vulnerable component
    → Remote exploitation possible
    → Direct path to full system or domain compromise
    Example: unauthenticated RCE on an internet-facing application

  High (7.0–8.9):
    → Low-privilege user can escalate to admin or DA
    → Credential theft possible from standard user position
    → ADCS ESC1, unconstrained delegation + printer bug, shadow credentials
    Example: domain user → domain admin via ADCS ESC1

  Medium (4.0–6.9):
    → Requires specific configuration or access beyond standard user
    → Increases attack surface but not directly exploitable alone
    Example: overly permissive file share accessible to domain users

  Low (0.1–3.9):
    → Defence-in-depth weakness; does not enable direct exploitation
    → Missing logging, weak password policy, information disclosure
    Example: verbose error messages revealing internal paths

  Informational (N/A):
    → Observation; not directly exploitable
    → Best practice deviation
    Example: absence of a security header on an internal application
```

---

## Part 6 — Remediation Priority Matrix

```
Purpose: answer the client's question — "where do we spend our first dollar?"
Format: a ranked table of remediations sorted by (Risk Reduction × Implementation Effort)

Axes:
  Risk Reduction: how much does fixing this reduce attacker capability?
    High: blocks a critical or high finding entirely
    Medium: raises the bar for a medium finding or removes one step from a high chain
    Low: addresses an informational or best-practice gap

  Implementation Effort:
    Quick Win (< 1 day): a configuration change, a policy update
    Short Term (1–2 weeks): a patch cycle, a one-time audit
    Long Term (> 1 month): an architecture change, a new tool deployment
```

### Remediation Matrix Template

```markdown
## Remediation Priority Matrix

| Priority | Finding | Remediation Action | Risk Reduction | Effort |
|----------|---------|-------------------|----------------|--------|
| P1 | F-01: MFA not enforced on VPN | Enable MFA on VPN gateway for all accounts | High | Quick Win |
| P2 | F-02: ADCS ESC1 — SAN injection | Remove Enrollee Supplies Subject from UserCertificate | High | Quick Win |
| P3 | F-03: AAD Connect MSOL account exposed | Rotate MSOL account password; audit replication rights | High | Quick Win |
| P4 | F-04: Weak password policy | Enforce minimum 14-character passwords; ban seasonal patterns | High | Short Term |
| P5 | F-05: BloodHound ACL paths to DA | Audit and remove excessive GenericWrite ACLs from standard user groups | Medium | Short Term |
| P6 | F-06: No LSASS protection | Enable RunAsPPL for LSASS on all domain-joined hosts | Medium | Short Term |
| P7 | F-07: No Sysmon deployment | Deploy Sysmon v15 with a hardened configuration (e.g. SwiftOnSecurity) | Medium | Short Term |
| P8 | F-08: ADCS audit logging disabled | Enable Event ID 4886/4887/4899 alerting on Certificate Authority | Medium | Quick Win |
| P9 | F-09: Printer spooler service on DCs | Disable Print Spooler on all Domain Controllers | High | Quick Win |
| P10 | F-10: No network segmentation between zones | Implement host-based firewall rules blocking lateral movement protocols | Medium | Long Term |

Quick Wins (implement this week):
  P1, P2, P3, P8, P9 — five configuration changes that sever the primary
  attack chain demonstrated in this assessment. Combined implementation time:
  estimated 4–6 hours for a senior systems administrator.
```

---

## Part 7 — Appendix D: MITRE ATT&CK Mapping Table

```markdown
## Appendix D — MITRE ATT&CK Mapping

| Phase | Technique | ATT&CK ID | Finding |
|-------|-----------|-----------|---------|
| Reconnaissance | Gather Victim Identity Information: Email Addresses | T1589.002 | — |
| Initial Access | Valid Accounts: Domain Accounts | T1078.002 | F-01 (weak password + no MFA) |
| Execution | Windows Management Instrumentation | T1047 | — |
| Persistence | Scheduled Task/Job | T1053.005 | — |
| Privilege Escalation | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | F-04 |
| Privilege Escalation | Steal or Forge Authentication Certificates | T1649 | F-02 |
| Defence Evasion | Use Alternate Authentication Material: Pass the Hash | T1550.002 | — |
| Credential Access | OS Credential Dumping: DCSync | T1003.006 | F-03 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | — |
| Collection | Data from Local System | T1005 | — |
| Command and Control | Protocol Tunnelling | T1572 | — |
| Exfiltration | (No data exfiltration in scope) | — | — |
| Impact | (Not demonstrated — engagement stopped at objective completion) | — | — |
```

---

## Writing Sprint Exercise

```
Using your engagement log from Days 539–548:

1. Write a full executive summary (30 min)
   → One page maximum
   → Read it aloud — if you stumble on a sentence, rewrite it
   → Ask: would a non-technical executive understand this and know what to do?

2. Write three technical findings using the finding card format (90 min)
   → One Critical: the ADCS or credential spray finding
   → One High: the MSOL / Azure pivot finding
   → One Medium: a lateral movement enabler (e.g. BloodHound ACL path)

3. Build the remediation priority matrix (30 min)
   → Include every finding from your three cards plus any additional
     observations from the engagement
   → Rank them honestly by risk reduction × effort

4. Write the attack narrative for Phases 1–3 (90 min)
   → Chronological; reference your engagement log timestamps
   → Each paragraph answers: what happened, what did it enable, was it detected?

5. Complete the ATT&CK mapping table (30 min)
   → Map every technique used to an ATT&CK technique ID
   → The table should have at least 10 entries

Total sprint time: ~5 hours of writing
Deliverable: a draft report document (Word, Markdown, or PDF)
Review: swap reports with a peer if possible; review for clarity, completeness,
  and whether the findings would enable the client to actually remediate
```

---

## Key Takeaways

1. The executive summary determines whether anything gets fixed. A technically
   perfect finding section paired with an incomprehensible executive summary
   means the CISO presents nothing to the board and the remediation budget goes
   to something else. Write for the decision-maker, not for yourself.
2. A finding is a vulnerability — not a technique. The technique is evidence.
   The finding is the root cause. "The assessment team used credential spraying"
   is a technique. "The organisation does not enforce MFA on externally
   accessible authentication endpoints" is a finding. Findings are what get
   fixed; techniques are how you found them.
3. CVSS scores are a communication tool, not a perfect risk measurement. Use
   them consistently and be prepared to explain why you scored a finding the
   way you did. A client who disputes a score is a client who has not yet
   understood the impact — your job is to explain it, not to defend the number.
4. The remediation priority matrix is the most actionable deliverable in the
   report. Findings tell the client what is broken. The matrix tells them where
   to start. A senior engineer who reads only the matrix should be able to
   spend a week on the top five items and meaningfully reduce the risk the
   report describes.
5. Time your report writing. A pentest that takes 3 days to execute should not
   take 3 weeks to report. Professional red team reports are delivered within
   5 business days of the engagement end. The writing sprint (this lesson)
   simulates that pressure — you do not get unlimited time on a real engagement,
   and your next client is already scheduled.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q549.1, Q549.2 …).

---

## Navigation

← Previous: [Day 548 — Full Engagement Simulation: Alternate Scenario](DAY-0548-Full-Engagement-Simulation-Alternate.md)
→ Next: [Day 550 — Milestone 550: Red Team Retrospective](DAY-0550-Milestone-550-Red-Team-Retrospective.md)
