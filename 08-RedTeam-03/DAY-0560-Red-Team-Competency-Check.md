---
title: "Red Team Operations — Competency Check (Day 560)"
tags: [red-team, competency-check, gate, self-assessment, ATT&CK, kill-chain,
  AD, evasion, cloud, reporting, module-complete]
module: 08-RedTeam-03
day: 560
related_topics:
  - Red Team CTF Sprint Day 9 (Day 559)
  - Red Team Report Writing Sprint (Day 549)
  - Milestone 550 (Day 550)
  - Cryptographic Attacks — Padding Oracle (Day 561)
---

# Day 560 — Red Team Operations: Competency Check

> "Competency is not a moment — it is a pattern of demonstrated, repeatable
> performance. Today you prove the pattern. If you cannot, you know exactly
> what to go back and drill. There is no shame in that. Shame is running an
> engagement you are not ready for."
>
> — Ghost

---

## Goals

Verify mastery of the entire Red Team Operations module (Days 491–559) before
advancing to the Cryptographic Attacks module. This check has three parts:
a technique confidence matrix, a timed lab challenge, and a written report
review. All three must pass.

**Prerequisites:** Days 491–559 — all of Red Team Operations.
**Time budget:** 4 hours (self-paced across the day).

---

## Part 1 — Technique Confidence Matrix (30 minutes)

Rate yourself honestly on each technique. 1 = theoretical knowledge only;
3 = can perform reliably in a lab; 5 = can perform reliably under time
pressure with variant conditions.

For any row rated below 3, note the specific gap and the day to revisit.

```
Technique                          | Self-Score (1–5) | Gap Note | Revisit Day
-----------------------------------|-----------------|----------|------------
C2 infrastructure setup (Sliver)   |                 |          | 492–493
Payload development (shellcode)    |                 |          | 496
AMSI bypass (AmsiScanBuffer patch) |                 |          | 519, 541
ETW patching                       |                 |          | 541
Process injection (hollowing)      |                 |          | 542
BloodHound shortest path analysis  |                 |          | 501–502
Kerberoasting (targeted)           |                 |          | 515, 557
AS-REP roasting                    |                 |          | 515
ADCS ESC1 (SAN injection)          |                 |          | 511–512
ADCS ESC8 (PetitPotam relay)       |                 |          | 513
RBCD attack (full chain)           |                 |          | 514, 559
Shadow Credentials (msDS-KCL)      |                 |          | 544
DCSync                             |                 |          | 499, 557
Golden Ticket forge                |                 |          | 499
PTH / PTK (overpass-the-hash)      |                 |          | 498, 559
AWS IMDS exploitation (IMDSv1)     |                 |          | 523–524, 556
Azure PRT theft                    |                 |          | 525–526
Kubernetes SA token abuse          |                 |          | 527–528
Container escape (cgroup)          |                 |          | 528
Persistence: WMI subscription      |                 |          | 531, 555
Persistence: COM HKCU hijack       |                 |          | 532, 555
Multi-forest trust abuse (SID Hist)|                 |          | 516, 538
Red team report writing            |                 |          | 510, 549
```

**Pass criterion for Part 1:** No more than 4 rows below 3.
If more than 4 rows are below 3, revisit the flagged days before proceeding.

---

## Part 2 — Timed Lab Challenge (2 hours hard stop)

### Setup

Use the same lab environment from Day 559 (Acme Manufacturing Ltd.) but with
one changed condition: **the local admin password on WS02 is different from
alice's domain password** (LAPS has been deployed on WS02 only).

Find a different lateral movement path from WS01 to WS02 that does not rely
on the local admin password reuse.

### Objectives

```
[ ] 1. Establish C2 beacon on WS01 (alice's machine, initial access by any method)
[ ] 2. Move laterally to WS02 without using alice's credentials directly
        Hint: there are at least two valid paths:
          a) DCOM execution (MMC20.Application or ShellWindows)
          b) Scheduled task creation via RPC (impacket/atexec)
          c) WMI exec (wmic or impacket/wmiexec)
[ ] 3. Escalate to domain admin via svc-sql Kerberoasting + RBCD (same as Day 559)
[ ] 4. Retrieve the flag from DC01:\SecretDocuments\crown_jewels.txt
[ ] 5. Stay under 2 alerts from the detection manifest
```

### Scoring

| Objective | Points | Notes |
|---|---|---|
| C2 beacon on WS01 | 10 | Any method |
| Lateral to WS02 (no PTH) | 25 | Must use non-credential lateral movement |
| Domain Admin achieved | 35 | Via any valid path |
| Flag retrieved | 20 | Binary — yes or no |
| ≤2 alerts triggered | 10 bonus | Deducted for each alert above 2 |

**Pass criterion for Part 2:** ≥ 70 points within 2 hours.

### Time Log

```
Start time: ___________
[ ] WS01 beacon:  ___________  (+10)
[ ] WS02 access:  ___________  (+25)
[ ] Domain Admin: ___________  (+35)
[ ] Flag:         ___________  (+20)
End time:   ___________
Total time: ___________
Score:      ___________  / 90
Alerts triggered: ___________
```

---

## Part 3 — Report Review (1 hour)

Take the engagement summary you wrote during Day 559 (or write a fresh one
from today's Part 2 run) and evaluate it against these criteria.

### Report Quality Rubric

```
Criteria                                              | Score (0–5)
------------------------------------------------------|------------
Executive Summary: clear, jargon-free, one page max  |
Attack path: every technique listed with ATT&CK ID   |
Evidence: screenshot or command output for each stage |
Impact: "what could an attacker do with this?" clear  |
Recommendations: specific, actionable, prioritised   |
CVSS scores: present and reasonable for each finding  |
Total:                                               | _____ / 30
```

**Pass criterion for Part 3:** ≥ 20 / 30.

### Sample Report Debrief

Review one real-world red team report (linked below) and compare its structure
to yours. Note three things your report does better and three things it does
worse.

```
Compare against: Mandiant M-Trends (public edition — available free at
mandiant.com/resources/m-trends) or any HackerOne public disclosure that
includes an attack narrative.

Better than reference:
  1. _______________________________________________________________
  2. _______________________________________________________________
  3. _______________________________________________________________

Worse than reference:
  1. _______________________________________________________________
  2. _______________________________________________________________
  3. _______________________________________________________________
```

---

## Overall Pass Criteria

| Part | Minimum to Pass |
|---|---|
| Part 1 — Confidence Matrix | ≤ 4 rows below 3 |
| Part 2 — Timed Lab | ≥ 70 points in 2 hours |
| Part 3 — Report Review | ≥ 20 / 30 |
| **All three parts pass** | **Advance to Module 09: Cryptographic Attacks** |

If any part fails: revisit the specific days identified, re-run the Part 2
lab, re-score the report. There is no time limit on retries — only on
advancement.

---

## Module 08 Summary

You have completed the Red Team Operations module. The techniques you now know:

**Operations tradecraft:**
C2 infrastructure with redirectors → malleable profiles → OPSEC discipline

**Windows AD attack paths:**
BloodHound → Kerberoasting → RBCD → ADCS ESC chains → DCSync → Golden Ticket

**Evasion:**
AMSI bypass → ETW patching → process injection → LOLBins → alert-aware execution

**Cloud:**
AWS IMDS → IAM escalation → Azure PRT → Kubernetes SA → container escape

**Full kill chains:**
Phishing → initial access → lateral movement → domain compromise under detection

The next module is **Cryptographic Attacks** (Days 561–610). You will shift
from operational tradecraft to mathematical exploitation: padding oracles,
timing side-channels, length extension, ECDSA nonce reuse, and lattice attacks.
The prerequisite knowledge is Day 29–38 (crypto foundations).

Before you start Day 561: re-read Day 029 (symmetric encryption) and Day 030
(hashing + length extension) to refresh the mathematical foundations.

---

## Key Takeaways

1. Red team operations is a craft, not a checklist. The difference between a
   mediocre red team and an excellent one is not the technique list — it is
   the ability to chain techniques cleanly, adapt when a path is blocked, and
   communicate findings with clarity.
2. Detection evasion is a conversation with the blue team, not a permanent win.
   Every technique you use today will be detected tomorrow. The goal is to
   raise the cost of detection high enough to matter for the duration of an
   engagement.
3. Reporting is half the job. A compromise no one understands cannot be fixed.
   If your written report does not convey the impact clearly enough for a
   non-technical executive to approve budget for remediation, you have not
   finished the engagement.

---

## Questions

> Add your questions here. Each question gets a Global ID (Q560.1, Q560.2 …).

---

## Navigation

← Previous: [Day 559 — Red Team CTF Sprint: Day 9](DAY-0559-Red-Team-CTF-Sprint-Day-9.md)
→ Next: [Day 561 — Padding Oracle Attack](../09-Crypto-01/DAY-0561-Padding-Oracle-Attack.md)
