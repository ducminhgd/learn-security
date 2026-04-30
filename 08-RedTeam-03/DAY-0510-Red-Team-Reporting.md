---
title: "Red Team Reporting — Narrative Report, Executive Summary, Remediation Priority"
tags: [red-team, reporting, executive-summary, findings, remediation, CVSS,
  risk-rating, communication, purple-team]
module: 08-RedTeam-03
day: 510
related_topics:
  - Atomic Red Team Lab (Day 509)
  - Full Kill-Chain Lab Day 2 (Day 507)
  - Purple Team Concepts (Day 508)
  - Bug Bounty Report Writing (Days 161–165)
---

# Day 510 — Red Team Reporting

> "The best engagement in the world means nothing if the report does not
> change behaviour. Executives do not read 80-page technical appendices.
> They read the first two pages and make decisions. Write for the person
> who signs the budget — not for the person who runs the SIEM. Then give
> the person who runs the SIEM a technical appendix they can actually use.
> Two audiences. One report."
>
> — Ghost

---

## Goals

Understand the structure of a professional red team engagement report.
Write a compelling executive summary that communicates business risk.
Format technical findings with evidence, impact, and remediation.
Apply a remediation prioritisation framework.

**Prerequisites:** Day 507 (kill-chain lab day 2), Days 161–165 (report
writing), any completed red team exercise.
**Time budget:** 4–5 hours.

---

## Part 1 — Report Structure

A professional red team report has two audiences and two sections:

```
Section 1: Executive Summary (2–4 pages)
  Audience: C-level, board, CISO
  Language: Business risk, impact, decisions needed
  No technical jargon. No acronyms without definition.
  Answers: What did you find? How bad is it? What do we do?

Section 2: Technical Findings (main body)
  Audience: Security engineers, IT team, incident response
  Language: Technical specifics, evidence, steps to reproduce
  Each finding: description, CVSS, evidence, remediation
  Answers: What exactly happened? Where? How do we fix it?

Section 3: Appendices
  Audience: Blue team, detection engineers
  Content: ATT&CK Navigator heatmap, Sigma rules, full log evidence,
           tool output, timeline of all actions
```

---

## Part 2 — Executive Summary

### What the Executive Summary Must Answer

```
1. What was tested?
   "A simulated adversary attack against CorpLab's Active Directory
   environment, conducted from the perspective of an external attacker
   who successfully delivered a phishing email."

2. What was the outcome?
   "Full domain compromise was achieved within 4 hours. Every Windows
   system in the environment was accessible, and the equivalent of all
   domain passwords was extracted."

3. What could a real attacker have done?
   Translate technical findings into business impact:
   → "An attacker could have encrypted all 500 servers (ransomware)"
   → "An attacker could have read all employee payroll data"
   → "An attacker could have accessed the M&A document repository"
   → "An attacker could have maintained access for months undetected"

4. What is the risk level?
   One clear sentence: "The current posture presents a critical risk of
   full business disruption from a ransomware attack or data breach."

5. What should leadership prioritise?
   3–5 action items, numbered, with a timeframe:
   1. Immediately: enforce MFA on all accounts (removes the phishing risk)
   2. Within 30 days: deploy LSASS protection (RunAsPPL)
   3. Within 90 days: rotate krbtgt password twice (invalidates stolen tickets)
```

### Executive Summary Template

```
Executive Summary

Engagement: [Client Name] Red Team Assessment
Period:     [Date range]
Conducted by: [Team/Operator]

Objective
[One paragraph: why this test was conducted, what it simulates.]

Outcome
[Two to three sentences: the bottom line. Domain compromised? Data accessible?
How long did it take? Was detection successful?]

Key Findings
[Bullet list — 4–6 findings, one sentence each, business language only.]
  • An attacker who delivers a phishing email can access all domain systems.
  • Credential theft from a single workstation enables full domain control.
  • No alerts fired during 4 hours of active attack activity.
  • Customer financial records were accessible from any compromised account.

Business Risk
[What is the worst-case scenario? Ransomware, data breach, regulatory fine?
Attach a probability × impact assessment if the client uses one.]

Recommended Actions
Priority 1 (Immediate):
  [Action] — [Owner] — [Deadline]
Priority 2 (30 days):
  ...
Priority 3 (90 days):
  ...

Positive Observations
[What did the client do well? A good report acknowledges strengths.
Comfortable executives are more likely to fund remediation.]
  • Endpoint protection was deployed on all workstations.
  • Network segmentation prevented direct access to production databases.
```

---

## Part 3 — Technical Finding Format

Each finding follows a consistent format. Every section is required.

```
Finding: [F-01] Phishing Email Bypasses Email Gateway Controls

Severity:     Critical
CVSS Score:   9.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H)
ATT&CK:       T1566.001 (Phishing: Spearphishing Attachment)
Status:       Open

Description
A phishing email containing an ISO attachment was delivered to a target
mailbox without interception by the email security gateway. The ISO contained
a malicious LNK file that executed a remote access tool upon opening.

Evidence
  Timestamp:  2026-05-01 10:15 UTC
  Target:     jsmith@corplab.local (WORKSTATION01)
  Tool used:  GoPhish with custom ISO+LNK payload
  Result:     Sliver beacon established; command execution confirmed as corp\jsmith

  [Screenshot: GoPhish results showing email opened and payload executed]
  [Sysmon Event 1: WORKSTATION01, cmd.exe parent=explorer.exe,
   CommandLine: runner.exe started from ISO mount]

Impact
  An unauthenticated external attacker who can send an email to any corporate
  mailbox can gain persistent access to domain-joined systems. No prior knowledge
  of the target organisation is required beyond a valid email address.

  This finding was the entry point for all subsequent compromise in this
  engagement, including full domain administrator access (F-04).

Steps to Reproduce
  1. Register a lookalike domain (e.g. corp-secure.com) with valid DKIM/SPF.
  2. Craft a spearphishing email referencing a legitimate internal system
     (Workday, O365, ServiceNow).
  3. Attach an ISO file containing an LNK payload pointing to a remote access tool.
  4. Send to any corporate email address.
  5. The email gateway delivers the message without quarantine or warning.
  6. Upon target opening the ISO and clicking the LNK, the payload executes.

Remediation
  Short term (immediate):
    Configure email gateway to quarantine or reject ISO, IMG, and VHD
    attachments from external senders.
    Enable Microsoft Defender for Office 365 Safe Attachments with a
    detonation policy.

  Medium term (30 days):
    Enforce multi-factor authentication on all mailboxes to reduce the
    impact of credential phishing.
    Deploy user security awareness training with simulated phishing testing.

  Long term (90 days):
    Implement an email gateway policy that blocks all archive and disk image
    formats from external senders unless explicitly allowlisted.

References
  MITRE ATT&CK T1566.001
  CVE examples: N/A (configuration issue, not a CVE)
  Related findings: F-02 (Credential Theft), F-04 (Domain Compromise)
```

---

## Part 4 — Remediation Prioritisation

Not all findings can be fixed immediately. Use a risk matrix to prioritise.

### Risk Rating Matrix

```
Likelihood × Impact:

               Impact
               Low    Medium  High    Critical
Likelihood
High:          Medium  High   Critical Critical
Medium:        Low     Medium High    Critical
Low:           Low     Low    Medium  High
Very Low:      Info    Info   Low     Medium

Definitions:
  Critical: Immediate action required — stop operations to fix if needed
  High:     Fix within 30 days — compensating controls required immediately
  Medium:   Fix within 90 days — no immediate compensating control needed
  Low:      Fix at next scheduled change window
  Info:     Noted, no action required
```

### Remediation Dependency Map

```
Some findings depend on others. Fix the root cause first.

Example from the CorpLab engagement:

  F-01 (Phishing delivery) → enables → F-02 (Initial access beacon)
    Fix F-01 first: block ISO/LNK in email gateway

  F-02 (Beacon established) → enables → F-03 (LSASS credential dump)
    Fix F-02 partially with: AV tuning, AMSI enhancement

  F-03 (LSASS dump) → enables → F-04 (Lateral movement)
    Fix F-03 with: RunAsPPL for LSASS

  F-04 (Lateral movement) → enables → F-05 (Domain Admin)
    Fix F-04 with: WMI restriction GPO, DCOM hardening

  F-05 (Domain Admin via DCSync) → enables → F-06 (Golden Ticket)
    Fix F-05 with: DCSync rights audit, remove from non-DC accounts

Fixing F-01 prevents the entire chain.
Fixing F-03 prevents F-04, F-05, F-06 even if F-01 and F-02 are not fixed.
Show this dependency map to help the client prioritise effectively.
```

---

## Part 5 — Sample Finding: Golden Ticket

```
Finding: [F-06] Domain Kerberos Trust Compromise (Golden Ticket)

Severity:     Critical
CVSS Score:   10.0 (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H)
ATT&CK:       T1558.001 (Steal or Forge Kerberos Tickets: Golden Ticket)

Description
The krbtgt account password hash was extracted from the Domain Controller
using the DCSync technique. This hash was used to forge a Kerberos Ticket
Granting Ticket (Golden Ticket) that grants unrestricted access to any
domain resource as any domain user — including non-existent users.

A Golden Ticket forged with the current krbtgt hash remains valid until
the krbtgt password is rotated twice. This means that even after the red
team engagement concluded, the attacker could theoretically maintain access
if the credential is not rotated.

Evidence
  Timestamp:  2026-05-01 11:00 UTC
  Command:    secretsdump.py / mimikatz lsadump::dcsync
  Result:     krbtgt NTLM hash: [REDACTED IN CLIENT COPY — provided separately]
              krbtgt AES-256 key: [REDACTED]
  Verification: Golden Ticket forged for non-existent user "ghost_test_9999"
               Accessed \\DC01.corplab.local\C$ successfully as this user.
  [Screenshot: klist showing forged TGT; dir command output on DC01 C$]

Impact
  An attacker who completes this attack chain has permanent, cryptographic
  access to every resource in the domain. Resetting Domain Admin passwords
  does not remove this access. The only remediation is rotating the krbtgt
  password twice, which invalidates all existing Kerberos tickets —
  including legitimate user sessions (plan for a service disruption window).

Remediation
  Immediate:
    Rotate the krbtgt account password twice, at least 10 hours apart.
    Monitor for Event 4768 (TGT requests) with RC4 encryption type
    (0x17) from non-DC sources — indicates Golden Ticket use.

  30 days:
    Deploy Microsoft Defender for Identity (MDI). MDI has specific
    analytics for Golden Ticket detection (anomalous ticket properties,
    accounts without a prior AS-REQ).

  90 days:
    Implement Privileged Access Workstations (PAWs) for all Domain
    Admin operations. Limit DCSync-capable accounts to DCs only via
    quarterly ACL audits.

References
  MITRE ATT&CK T1558.001
  Mimikatz documentation: kerberos::golden
  MSFT blog: How to reset the krbtgt account password
  NotPetya incident report: Golden Ticket used for persistence post-breach
```

---

## Key Takeaways

1. Write the executive summary last, after all findings are documented.
   The summary distills the findings into business language — you cannot
   do that accurately until you know what you found.
2. Every finding needs evidence. Screenshots, log entries, timestamps. "We
   accessed the DC" with no evidence is an assertion. "We accessed the DC
   at 11:00 UTC, screenshot attached, Event 4624 from beacon IP" is a finding.
3. Remediation must be specific and actionable. "Improve security posture" is
   not remediation. "Enable RunAsPPL for LSASS via registry key X on every
   domain-joined system within 30 days" is remediation.
4. Dependency mapping saves client resources. Fixing the root cause (phishing
   delivery, MFA gaps, LSASS protection) prevents entire attack chains. Help
   the client understand which fix has the highest return on investment.
5. A red team report that does not result in defensive changes is a waste of
   the client's money. Follow up at 30 and 90 days to verify remediation
   progress. The engagement is not over when the report is delivered.

---

## Exercises

1. Write an executive summary for the CorpLab two-day engagement (Days 506–507).
   Keep it to two pages. Use only business language — no ATT&CK IDs, no tool
   names, no jargon. Have a non-technical colleague read it and verify they
   understand the risk.
2. Write three complete technical findings using the format from Part 3:
   one for LSASS credential theft (F-03), one for WMI lateral movement (F-04),
   and one for the Golden Ticket (F-06). Include all required sections.
3. Build a remediation dependency map for the CorpLab findings. Identify which
   single remediation action would prevent the most subsequent attack phases.
4. Convert the ATT&CK Navigator layer from the Day 509 purple team session into
   an appendix for the report. Include a legend that explains the colour coding
   and a written summary of detection coverage percentage by tactic.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q510.1, Q510.2 …).

---

## Navigation

← Previous: [Day 509 — Atomic Red Team Lab](DAY-0509-Atomic-Red-Team-Lab.md)
→ Next: Day 511 — Red Team Practice: AD Offshore Labs
