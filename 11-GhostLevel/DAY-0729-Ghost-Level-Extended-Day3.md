---
title: "Ghost Level Extended — Day 3: Report Polish and Oral Defence Preparation"
tags: [ghost-level, report-writing, oral-defence, presentation,
  professional-skills, module-11-ghost-level]
module: 11-GhostLevel
day: 729
prerequisites:
  - Day 728 — Ghost Level Extended Day 2: Purple Team Exercise
related_topics:
  - Day 730 — Ghost Level Competency Gate
---

# Day 729 — Ghost Level Extended Day 3: Report Polish and Oral Defence Preparation

> "The best technical work in the world is worthless if you cannot communicate
> it. Reports are not paperwork — they are the product. The executive who
> signs the remediation budget reads your report. The developer who patches
> the vulnerability reads your advisory. Write accordingly."
>
> — Ghost

---

## Goals

1. Conduct a final quality review of the Project SABLE report using the
   Ghost Report Review Checklist.
2. Verify all technical claims with evidence.
3. Prepare answers for the Ghost Level oral defence (30-minute live exam
   in Day 730).
4. Practise explaining each finding to a non-technical executive audience
   in under 2 minutes.

---

## Prerequisites

- Full report from Days 723–725 with purple team addendum from Day 728.
- Engagement notes from Days 707–728.

---

## 1 — Ghost Report Review Checklist

Run through this checklist for every section of your report:

```
GHOST REPORT REVIEW CHECKLIST

EXECUTIVE SUMMARY
  [ ] One paragraph. Max 300 words.
  [ ] States the scope, the date range, and the highest-severity finding.
  [ ] States the single most impactful remediation.
  [ ] No technical jargon. No acronyms unexplained.
  [ ] A CEO who reads this knows: what happened, how bad, what to do first.

SCOPE AND METHODOLOGY
  [ ] Lists every target (IP, hostname, service).
  [ ] States what was explicitly OUT of scope.
  [ ] Documents the methodology (e.g., "We used the Ghost Method: Recon →
      Exploit → Detect → Harden").
  [ ] States the engagement window (start and end date/time).

FINDINGS SECTION (per finding)
  [ ] Title: ≤ 10 words, describes the vulnerability and location.
  [ ] Severity: Critical / High / Medium / Low with CVSS base score.
  [ ] Affected component: specific system name and service.
  [ ] Description: 1–2 paragraphs. Root cause, exploitation path, impact.
  [ ] Evidence: screenshot, log extract, or command output. Not just words.
  [ ] MITRE ATT&CK technique: at least one T-ID mapped.
  [ ] Remediation: specific, actionable, technically correct.
    [ ] Not "patch your systems." Specific: "Rotate the KRBTGT password
        twice within 24 hours using the procedure in Microsoft KB2919721."
  [ ] CVSS vector string: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (example)

ATTACK TIMELINE
  [ ] Every major action logged with a timestamp.
  [ ] Each timestamp maps to a specific finding or lateral movement step.
  [ ] The timeline reads as a coherent narrative.
  [ ] External reviewer can reconstruct the engagement from the timeline alone.

DETECTION AND HARDENING (added in Day 728)
  [ ] Detection rules provided (Sigma, Suricata, or KQL).
  [ ] Detection gap analysis present.
  [ ] Remediation roadmap with priority order.
  [ ] Estimated effort for each remediation (quick win vs. project).

APPENDICES
  [ ] All tool commands used (with flags explained).
  [ ] All Sigma/Suricata rules from Day 728.
  [ ] MITRE ATT&CK Navigator layer (JSON) or screenshot.
  [ ] Raw tool output for each critical finding.
```

---

## 2 — Evidence Verification

For each finding, verify that your evidence is sufficient:

```
EVIDENCE SUFFICIENCY STANDARD

Critical findings: Require at least TWO independent pieces of evidence.
  Example for F-02 (Stack Overflow):
    Evidence 1: Ghidra screenshot showing parse_record() with no bounds check
    Evidence 2: Terminal screenshot showing pwntools script + reverse shell

High findings: Require at least ONE definitive piece of evidence.
  Example for F-03 (Kerberoasting):
    Evidence 1: Impacket output showing TGS tickets for SVC_BACKUP
    Evidence 2 (optional): hashcat output showing cracked password

Medium findings: Screenshot or command output is sufficient.

EVIDENCE CHECKLIST (complete per finding):
  F-01 JWT:       Evidence 1: _______  Evidence 2: _______  Sufficient: Y/N
  F-02 Overflow:  Evidence 1: _______  Evidence 2: _______  Sufficient: Y/N
  F-03 Kerberoast:Evidence 1: _______  Evidence 2: _______  Sufficient: Y/N
  F-04 ADCS:      Evidence 1: _______  Evidence 2: _______  Sufficient: Y/N
  F-05 CGI:       Evidence 1: _______  Evidence 2: _______  Sufficient: Y/N
  F-06 SMB:       Evidence 1: _______  Evidence 2: _______  Sufficient: Y/N
```

---

## 3 — Executive Communication Drill

For the oral defence, you must explain any finding to a non-technical audience
in under 2 minutes. Practise these explanations:

### Finding F-02 (Stack Overflow) — Non-technical version

Practise this out loud, timed:

```
"The network service that handles internal data requests — sable-svc —
contains a programming error in how it reads incoming messages. If we
send a message that is slightly too long, the program writes data past
the end of its allocated memory. This corrupts a specific area of memory
that controls where the program will execute its next instruction.
We were able to redirect that execution to code we control, giving us
the same level of access as the service account running the program.
In practical terms: we got a remote command line on that server with
no valid credentials. A real attacker would use this to install malware,
steal data, or use the server as a stepping stone to the rest of the
network."

Time yourself: _____ seconds (target: under 90 seconds)
```

### Finding F-04 (ADCS ESC1) — Non-technical version

```
"Your organisation runs a certificate authority — a system that issues
digital identity cards to users and computers on your network. The
certificate template called 'SableUser' is misconfigured: it allows
any user to request a certificate that claims to be someone else — in
this case, the domain administrator. We used this to request a
certificate that identifies us as your most powerful user, and with
that certificate we had complete administrative access to your entire
Active Directory domain — every computer, every account, every database."

Time yourself: _____ seconds (target: under 90 seconds)
```

---

## 4 — Oral Defence Preparation

Day 730 includes a 30-minute oral defence. Six questions will be drawn from
the following bank. Prepare a 60–90 second answer for each:

```
ORAL DEFENCE QUESTION BANK

TECHNICAL QUESTIONS:
  Q1: Walk me through the exact sequence of actions that gave you Domain
      Admin access. Start from the first packet you sent to sable-web.

  Q2: For Finding F-02 (stack overflow), explain why the vulnerability
      exists at the source code level. What would a correct implementation
      look like?

  Q3: What is the difference between the ADCS ESC1 technique you used and
      the ESC4 technique? Why did ESC1 apply here and not ESC4?

  Q4: Describe three things that, if implemented on the sable-dc host,
      would have prevented your successful Domain Admin compromise.

  Q5: A defender sees Event ID 4769 with TicketEncryptionType 0x17.
      Is this always malicious? What false-positive scenarios exist?

METHODOLOGY QUESTIONS:
  Q6: You had 48 hours. Describe your time allocation decision at Hour 12.
      What had you found? What had you not yet looked at? What did you
      prioritise and why?

  Q7: Which finding would a basic SOC (with standard Windows event logging,
      no SIEM, no EDR) have detected while the attack was in progress?
      Which ones would they have missed entirely?

  Q8: If the client could only fix one finding in the next 24 hours,
      which would you recommend and why?

PROFESSIONAL QUESTIONS:
  Q9: A client's CTO asks: "Our security vendor told us we passed our
      last security audit three months ago. How did you find all this?"
      How do you respond?

  Q10: During this engagement, you found credentials stored in plaintext
       in the sable-store backup share. Those credentials belong to
       real employees. How do you handle this in your report and in your
       communication with the client?
```

---

## 5 — Day 730 Pre-Gate Checklist

Complete before attending the Day 730 gate:

```
PRE-GATE CHECKLIST — DAY 729

REPORT:
  [ ] Executive summary reviewed and timed (under 5 minutes to read)
  [ ] All 6 findings documented with CVSS scores
  [ ] All findings have at least 1 piece of evidence
  [ ] Attack timeline complete
  [ ] Detection rules from Day 728 appended
  [ ] Remediation roadmap complete
  [ ] ATT&CK mapping complete

ORAL DEFENCE:
  [ ] Practised non-technical explanation of all Critical/High findings
  [ ] Can answer all 10 questions in the bank within 90 seconds each
  [ ] Can walk through the kill chain timeline without notes
  [ ] Can name the CVSS score and ATT&CK technique for each finding

MENTAL:
  [ ] Reviewed debrief notes from Day 726
  [ ] Know your 3 biggest mistakes and the lessons you drew from them
  [ ] Rested. The gate is tomorrow. Stop working at a reasonable hour.

"The report is done. The oral is prepared. Get some sleep.
 Tomorrow you find out whether 730 days made a Ghost." — Ghost
```

---

## Key Takeaways

1. **The report is the product.** The client does not keep your reverse shell.
   They keep the report. A technically perfect engagement with a mediocre
   report is a mediocre engagement. A solid engagement with a professional
   report is a professional engagement.
2. **Evidence is not optional.** "I found a SQL injection" is an allegation.
   A screenshot of `'OR 1=1--` in a URL bar returning all database records is
   evidence. Every finding must be reproducible from the evidence you provide.
   If you deleted your notes, you can no longer prove the finding.
3. **Executive communication is a technical skill.** Translating a stack
   buffer overflow into a 90-second business-impact explanation requires as
   much practice as writing the exploit. Security professionals who can do
   both have careers. Those who can only do one have jobs.
4. **The oral defence tests reasoning, not memory.** The questions are not
   "recite CVE-2023-XXXX's CVSS score." They are "explain why this attack
   worked and what would have prevented it." Reasoning from first principles
   beats memorisation every time.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q729.1, Q729.2 …).

---

## Navigation

← Previous: [Day 728 — Ghost Level Extended Day 2: Purple Team](DAY-0728-Ghost-Level-Extended-Day2.md)
→ Next: [Day 730 — Ghost Level Competency Gate](DAY-0730-Ghost-Level-Competency-Gate.md)
