---
title: "Gate Preparation Day 2 — Live Target Speed Run"
tags: [gate-prep, Year-1, live-target, speed, practice, exploit]
module: 05-BugBountyOps-03
day: 362
related_topics:
  - Gate Preparation Day 1 (Day 361)
  - CTF Web Competition Day 5 (Day 315)
  - Bug Bounty Hunter Gate (Day 365)
---

# Day 362 — Gate Preparation Day 2: Live Target Speed Run

---

## Goals

Run a timed, reference-free exploitation session on a live target.
Simulate the 3-hour live engagement portion of the Day 365 gate.
Focus on decision speed and methodical coverage under pressure.

**Time budget:** 5–6 hours.

---

## Session Setup

```
Target: ___  (use a FRESH HTB/TryHackMe machine or reset Juice Shop)
  Rule: must not have completed this exact machine before.

Session type: Timed sprint — 3 hours hard limit on live testing.
              30 min allowed for report writing after.

Start time: ___
End time (hard): Start + 3:00
```

---

## Pre-Engagement Plan (10 min)

```
Tech stack (from description / initial HTTP response): ___
Initial hypotheses (ranked by probability):
  1. ___  — reason: ___
  2. ___  — reason: ___
  3. ___  — reason: ___

First tool I will run: ___
First manual check: ___
```

---

## Time-Boxed Engagement Log

```
00:00–00:15 — Recon:
  Subdomains / ports: ___
  Login: Y/N  |  API: Y/N  |  Upload: Y/N
  Interesting endpoint: ___

00:15–00:45 — First hypothesis test:
  Technique: ___
  Payload: ___
  Result: ___  → Continue: Y/N

00:45–01:30 — Second hypothesis / pivot:
  Technique: ___
  Result: ___

01:30–02:15 — Exploitation attempt:
  Finding confirmed: Y/N
  Payload: ___
  Evidence captured: Y/N

02:15–02:45 — Escalation / chaining:
  Chain attempt: ___
  Result: ___

02:45–03:00 — Documentation cleanup:
  Finding type: ___  Severity: ___
  Evidence: ___
```

---

## 30-Minute Report

```
Title: ___
Severity: ___   CVSS: ___

Summary (3 sentences max):
  ___

Impact:
  ___

Steps to Reproduce:
  1. ___
  2. ___
  3. ___

HTTP Request / Evidence:
  ___

Remediation:
  ___

Report complete in: ___ min
```

---

## Speed Run Assessment

```
Finding quality: P1 / P2 / P3 / P4 / no finding
Time to first finding: ___ min
Time to complete report: ___ min

vs Day 360 simulation:
  Better: ___
  Worse: ___

Key improvement since simulation: ___
Remaining concern for Day 365: ___
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q362.1, Q362.2 …).

---

## Navigation

← Previous: [Day 361 — Gate Preparation Day 1](DAY-0361-Gate-Preparation-Day-01.md)
→ Next: [Day 363 — Gate Preparation Day 3](DAY-0363-Gate-Preparation-Day-03.md)
