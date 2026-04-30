---
title: "Year-1 Review Day 5 — Gate Simulation"
tags: [Year-1, review, gate-simulation, dry-run, gate-prep]
module: 05-BugBountyOps-03
day: 360
related_topics:
  - Year-1 Review Day 4 (Day 359)
  - Bug Bounty Hunter Gate (Day 365)
  - Web Exploitation Competency Gate (Day 165)
---

# Day 360 — Year-1 Review Day 5: Gate Simulation

> "You don't want your first experience of the gate format to be the gate
> itself. Run the simulation. Find out what breaks. Fix it before Day 365."
>
> — Ghost

---

## Goals

Run a full dry-run of the Year-1 Bug Bounty Hunter Gate format.
Under timed, reference-free conditions — as close to the real gate as possible.

**Time budget:** 6–7 hours (full gate simulation).

---

## Simulation Setup

```
Start time: ___
Rules:
  - Part 1 (oral): no reference material. Write answers only.
  - Part 2 (live target): one unknown HTB or DVWA/Juice Shop instance.
    Choose something you have NOT done before.
    3 hours. Find at least one exploitable vulnerability.
  - Part 3 (report): write a complete report from your Part 2 finding.
    90 minutes. Professional quality.
  - Part 4 (blue): explain how to detect and fix your own finding.
    20 minutes.

Target environment: ___  (fresh HTB machine / reset Juice Shop / custom VM)
```

---

## Part 1 — Oral Concept Questions (30 min)

Answer without looking anything up:

```
Q1: What is the OWASP API Top 10 item #1? Define it and give a one-line example.
A: ___

Q2: What CVSS component determines whether a vulnerability can be exploited
    without any user interaction?
A: ___

Q3: A JWT header contains "alg": "RS256". The server has an HMAC-HS256
    verification path. Describe the attack.
A: ___

Q4: An HTTP response contains "Access-Control-Allow-Origin: *" and
    "Access-Control-Allow-Credentials: true". Is this exploitable?
A: ___

Q5: Name three AWS IAM privilege escalation paths that do NOT require
    iam:CreateRole.
A: ___

Q6: What is the difference between reflected, stored, and DOM-based XSS?
    Which is the hardest to detect with a WAF and why?
A: ___

Q7: A bug bounty programme marks your SSRF finding as "informational".
    They say "the server cannot reach 169.254.169.254". What do you do?
A: ___

Q8: The CFAA prohibits accessing a computer "without authorisation".
    Does a valid bug bounty safe harbour clause constitute authorisation?
    What risk remains?
A: ___
```

---

## Part 2 — Live 3-Hour Engagement Log

```
Target: ___
Start: ___

00:00–00:30 — Recon:
  ___

00:30–01:30 — Primary testing:
  Techniques attempted: ___
  Anomalies noticed: ___

01:30–02:30 — Exploitation attempt:
  Finding: ___
  Payload/technique: ___
  Evidence: ___

02:30–03:00 — Documentation:
  Finding confirmed: Y/N
  Severity: ___
  Impact: ___

End time: ___
Total time: ___
```

---

## Part 3 — Report (90 min)

```
Title: ___
Severity: ___   CVSS: ___

Summary: ___

Impact: ___

Steps:
  1. ___
  2. ___
  3. ___

Evidence: ___
Root Cause (CWE ___): ___
Remediation: ___

Self-review checklist:
  [ ] Title: verb + asset + technique
  [ ] Impact in business terms
  [ ] CVSS justified per component
  [ ] Reproducible steps
  [ ] Evidence attached
```

---

## Part 4 — Defensive Translation (20 min)

```
For the finding in Part 2:

Detection rule:
  Log source: ___
  Alert condition: ___
  Alert signature: ___

Fix:
  Root cause: ___
  Code / config change: ___
  CWE addressed: ___
```

---

## Simulation Debrief

```
Total score (self-assessed):
  Part 1 (8 questions): ___/8
  Part 2 (finding quality): P1/P2/P3/none
  Part 3 (report quality): Excellent / Good / Needs work
  Part 4 (detection/fix): Correct / Partial / Incorrect

Areas to polish before Day 365: ___

Confidence level for Day 365: ___/10
```

---

## Questions

> Add your questions here. Each question gets a Global ID (Q360.1, Q360.2 …).

---

## Navigation

← Previous: [Day 359 — Year-1 Review Day 4](DAY-0359-Year-1-Review-Day-04.md)
→ Next: [Day 361 — Gate Preparation Day 1](DAY-0361-Gate-Preparation-Day-01.md)
